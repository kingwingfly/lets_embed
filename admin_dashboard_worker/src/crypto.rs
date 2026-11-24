//! Dedicated AES-256-GCM encrypted secret storage for D1 `provider_secrets` (Fixes M3).
//!
//! Security properties:
//! - Resolves the active 32-byte AES-256-GCM key from explicit `PROVIDER_SECRETS_KEY`
//!   (or legacy `SETTINGS_ENCRYPTION_KEY`), falling back to RFC 5869 HKDF-SHA256
//!   derivation from `SITE_SECRET` (`KeyDomain::ProviderSecrets`) via
//!   [`site_access::resolve_provider_aes_key`].
//! - Supports zero-downtime key rotation via `PROVIDER_SECRETS_KEY_PREV`,
//!   `SETTINGS_ENCRYPTION_KEY_PREV`, or `SITE_SECRET_PREV`.
//! - Generates a fresh CSPRNG 96-bit nonce (`getrandom`) on every encryption write.
//! - Binds explicit AAD = `"{deployment_id}|{provider_id}|{field_name}"` so ciphertext
//!   cannot be transplanted across deployments, providers, or fields.
//! - Zeroizes key bytes on drop and redacts all key material from `Debug` output.

use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use sha2::{Digest, Sha256};
use site_access::resolve_provider_aes_key;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyFormat(&'static str),
    InvalidAadComponent(&'static str),
    RngFailure(String),
    EncryptionFailed,
    DecryptionFailed,
    InvalidBlobFormat(&'static str),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyFormat(m) => write!(f, "invalid encryption key: {m}"),
            Self::InvalidAadComponent(m) => write!(f, "invalid AAD component: {m}"),
            Self::RngFailure(m) => write!(f, "CSPRNG failure: {m}"),
            Self::EncryptionFailed => write!(f, "AES-256-GCM encryption failed"),
            Self::DecryptionFailed => write!(f, "AES-256-GCM decryption failed"),
            Self::InvalidBlobFormat(m) => write!(f, "invalid encrypted blob: {m}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Single 256-bit AES-GCM key with deterministic fingerprint `kid` (`k1:<16-hex>`).
/// Key bytes are zeroized on drop and redacted from `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]
    kid: String,
    bytes: [u8; KEY_LEN],
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("kid", &self.kid)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl SecretKey {
    /// Parses a dedicated 32-byte key from `"<kid>:<material>"` or plain `<material>`.
    /// `<material>` may be 64 hex chars OR base64/base64url (padded or unpadded).
    pub fn parse(raw: &str) -> Result<Self, CryptoError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::InvalidKeyFormat("key cannot be empty"));
        }

        let (explicit_kid, material) = match trimmed.split_once(':') {
            Some((kid, rest))
                if !kid.is_empty()
                    && kid.len() <= 32
                    && kid
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) =>
            {
                (Some(kid.to_string()), rest.trim())
            }
            _ => (None, trimmed),
        };

        let mut decoded = if material.len() == 64 && material.bytes().all(|b| b.is_ascii_hexdigit())
        {
            hex::decode(material).map_err(|_| CryptoError::InvalidKeyFormat("invalid hex key"))?
        } else {
            STANDARD
                .decode(material)
                .or_else(|_| STANDARD_NO_PAD.decode(material))
                .or_else(|_| URL_SAFE.decode(material))
                .or_else(|_| URL_SAFE_NO_PAD.decode(material))
                .map_err(|_| {
                    CryptoError::InvalidKeyFormat(
                        "must be 64-char hex or base64/base64url encoding of 32 bytes",
                    )
                })?
        };

        if decoded.len() != KEY_LEN {
            decoded.zeroize();
            return Err(CryptoError::InvalidKeyFormat(
                "decoded key must be exactly 32 bytes (256 bits)",
            ));
        }

        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(&decoded);
        decoded.zeroize();

        if bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidKeyFormat("all-zero key rejected"));
        }

        let mut key = Self::from_bytes(bytes);
        if let Some(kid) = explicit_kid {
            key.kid = kid;
        }
        Ok(key)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let digest = Sha256::digest(bytes);
        let kid = format!("k1:{}", hex::encode(&digest[..8]));
        Self { kid, bytes }
    }

    /// Resolves a key from an optional explicit key override (`PROVIDER_SECRETS_KEY` /
    /// `SETTINGS_ENCRYPTION_KEY`) or HKDF derivation from `SITE_SECRET`.
    pub fn resolve(
        explicit_key: Option<&str>,
        site_secret: Option<&str>,
    ) -> Result<Self, CryptoError> {
        if let Some(raw) = explicit_key.map(str::trim).filter(|s| !s.is_empty()) {
            return Self::parse(raw);
        }
        let bytes = resolve_provider_aes_key(None, site_secret)
            .map_err(CryptoError::InvalidKeyFormat)?;
        Ok(Self::from_bytes(bytes))
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.bytes).expect("AES-256-GCM accepts 32-byte key")
    }
}

/// Active key + optional previous key for zero-downtime secret rotation.
#[derive(Clone)]
pub struct KeyRing {
    pub current: SecretKey,
    pub previous: Option<SecretKey>,
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRing")
            .field("current_kid", &self.current.kid())
            .field(
                "previous_kid",
                &self.previous.as_ref().map(SecretKey::kid),
            )
            .finish()
    }
}

/// Output of encrypting one secret field for storage in D1 `provider_secrets`.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSecret {
    pub kid: String,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("kid", &self.kid)
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Builds strict canonical AAD: `"{deployment_id}|{provider_id}|{field_name}"`.
pub fn build_aad(
    deployment_id: &str,
    provider_id: &str,
    field_name: &str,
) -> Result<Vec<u8>, CryptoError> {
    for (label, part) in [
        ("deployment_id", deployment_id),
        ("provider_id", provider_id),
        ("field_name", field_name),
    ] {
        let t = part.trim();
        if t.is_empty() || t != part || part.contains('|') || part.chars().any(char::is_control) {
            return Err(CryptoError::InvalidAadComponent(label));
        }
    }
    Ok(format!("{deployment_id}|{provider_id}|{field_name}").into_bytes())
}

fn non_empty(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|s| !s.is_empty())
}

impl KeyRing {
    pub fn from_env_strings(
        current_raw: &str,
        previous_raw: Option<&str>,
    ) -> Result<Self, CryptoError> {
        let current = SecretKey::parse(current_raw)?;
        let previous = match non_empty(previous_raw) {
            Some(prev) => {
                let key = SecretKey::parse(prev)?;
                if key.bytes == current.bytes {
                    None
                } else {
                    Some(key)
                }
            }
            None => None,
        };
        Ok(Self { current, previous })
    }

    /// Resolves active & optional previous provider encryption keys with precedence:
    /// - Current: `PROVIDER_SECRETS_KEY` > `SETTINGS_ENCRYPTION_KEY` > HKDF(`SITE_SECRET`)
    /// - Previous: `PROVIDER_SECRETS_KEY_PREV` > `SETTINGS_ENCRYPTION_KEY_PREV` > HKDF(`SITE_SECRET_PREV`)
    pub fn from_resolved_env(
        provider_secrets_key: Option<&str>,
        legacy_settings_key: Option<&str>,
        site_secret: Option<&str>,
        prev_provider_key: Option<&str>,
        prev_legacy_key: Option<&str>,
        prev_site_secret: Option<&str>,
    ) -> Result<Self, CryptoError> {
        let explicit_current = non_empty(provider_secrets_key).or_else(|| non_empty(legacy_settings_key));
        let current = SecretKey::resolve(explicit_current, site_secret)?;

        let explicit_prev = non_empty(prev_provider_key).or_else(|| non_empty(prev_legacy_key));
        let previous = if explicit_prev.is_some() || non_empty(prev_site_secret).is_some() {
            let key = SecretKey::resolve(explicit_prev, prev_site_secret)?;
            if key.bytes == current.bytes {
                None
            } else {
                Some(key)
            }
        } else {
            None
        };

        Ok(Self { current, previous })
    }

    pub fn has_previous(&self) -> bool {
        self.previous.is_some()
    }

    /// Encrypts `plaintext` with `self.current`, a fresh CSPRNG 96-bit nonce, and
    /// AAD = `"{deployment_id}|{provider_id}|{field_name}"`.
    pub fn encrypt(
        &self,
        deployment_id: &str,
        provider_id: &str,
        field_name: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedSecret, CryptoError> {
        let aad = build_aad(deployment_id, provider_id, field_name)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|e| CryptoError::RngFailure(e.to_string()))?;
        self.encrypt_with_nonce(&aad, nonce_bytes, plaintext)
    }

    fn encrypt_with_nonce(
        &self,
        aad: &[u8],
        nonce_bytes: [u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<EncryptedSecret, CryptoError> {
        let cipher = self.current.cipher();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(EncryptedSecret {
            kid: self.current.kid().to_string(),
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypts a stored `provider_secrets` row, verifying the exact AAD and trying
    /// the key matching `kid` first, then falling back to the alternate key in the ring.
    pub fn decrypt(
        &self,
        deployment_id: &str,
        provider_id: &str,
        field_name: &str,
        kid: &str,
        nonce_bytes: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce_bytes.len() != NONCE_LEN {
            return Err(CryptoError::InvalidBlobFormat(
                "nonce must be exactly 12 bytes",
            ));
        }
        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::InvalidBlobFormat(
                "ciphertext shorter than GCM auth tag",
            ));
        }
        let aad = build_aad(deployment_id, provider_id, field_name)?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let mut candidates: Vec<&SecretKey> = Vec::with_capacity(2);
        if self.current.kid() == kid {
            candidates.push(&self.current);
            if let Some(prev) = &self.previous {
                candidates.push(prev);
            }
        } else if let Some(prev) = &self.previous
            && prev.kid() == kid
        {
            candidates.push(prev);
            candidates.push(&self.current);
        } else {
            candidates.push(&self.current);
            if let Some(prev) = &self.previous {
                candidates.push(prev);
            }
        }

        for key in candidates {
            let cipher = key.cipher();
            if let Ok(pt) = cipher.decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            ) {
                return Ok(pt);
            }
        }
        Err(CryptoError::DecryptionFailed)
    }

    /// Re-encrypts a secret row using `self.current` and a fresh CSPRNG 96-bit nonce.
    pub fn reencrypt(
        &self,
        deployment_id: &str,
        provider_id: &str,
        field_name: &str,
        old_kid: &str,
        old_nonce: &[u8],
        old_ciphertext: &[u8],
    ) -> Result<EncryptedSecret, CryptoError> {
        let mut plaintext = self.decrypt(
            deployment_id,
            provider_id,
            field_name,
            old_kid,
            old_nonce,
            old_ciphertext,
        )?;
        let encrypted = self.encrypt(deployment_id, provider_id, field_name, &plaintext);
        plaintext.zeroize();
        encrypted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_parser_supports_optional_kid_prefix_and_raw_encodings() {
        let raw_bytes = [0x5au8; 32];
        let hex_mat = hex::encode(raw_bytes);
        let b64_mat = STANDARD.encode(raw_bytes);
        let b64_url_mat = URL_SAFE_NO_PAD.encode(raw_bytes);

        let k_raw_hex = SecretKey::parse(&hex_mat).expect("raw hex");
        let k_raw_b64 = SecretKey::parse(&b64_mat).expect("raw b64");
        let k_raw_url = SecretKey::parse(&b64_url_mat).expect("raw b64url");
        assert!(k_raw_hex.kid().starts_with("k1:"));
        assert_eq!(k_raw_hex.kid(), k_raw_b64.kid());
        assert_eq!(k_raw_hex.kid(), k_raw_url.kid());

        let k_pref_hex = SecretKey::parse(&format!("v1:{hex_mat}")).expect("prefixed hex");
        let k_pref_b64 = SecretKey::parse(&format!("rot-2026_01.a:{b64_url_mat}"))
            .expect("prefixed base64url");
        assert_eq!(k_pref_hex.kid(), "v1");
        assert_eq!(k_pref_b64.kid(), "rot-2026_01.a");

        let ring_pref = KeyRing::from_env_strings(&format!("v1:{hex_mat}"), None).unwrap();
        let ring_raw = KeyRing::from_env_strings(&b64_mat, None).unwrap();
        let enc = ring_pref
            .encrypt("prod-1", "google", "client_secret", b"secret-value")
            .unwrap();
        assert_eq!(enc.kid, "v1");
        let pt = ring_raw
            .decrypt(
                "prod-1",
                "google",
                "client_secret",
                &enc.kid,
                &enc.nonce,
                &enc.ciphertext,
            )
            .unwrap();
        assert_eq!(pt, b"secret-value");

        let hex_v2 = hex::encode([0x7bu8; 32]);
        let ring_rot =
            KeyRing::from_env_strings(&format!("v2:{hex_v2}"), Some(&format!("v1:{hex_mat}")))
                .unwrap();
        assert!(ring_rot.has_previous());
        assert_eq!(ring_rot.current.kid(), "v2");
        assert_eq!(ring_rot.previous.as_ref().unwrap().kid(), "v1");
        assert_eq!(
            ring_rot
                .decrypt(
                    "prod-1",
                    "google",
                    "client_secret",
                    &enc.kid,
                    &enc.nonce,
                    &enc.ciphertext
                )
                .unwrap(),
            b"secret-value"
        );

        assert!(SecretKey::parse(&format!(":{hex_mat}")).is_err());
        assert!(SecretKey::parse(&format!("bad kid:{hex_mat}")).is_err());
        assert!(SecretKey::parse(&format!("{}:{hex_mat}", "k".repeat(33))).is_err());
        assert!(SecretKey::parse(&"00".repeat(32)).is_err());
        assert!(SecretKey::parse(&format!("v1:{}", "00".repeat(32))).is_err());
    }
}
