//! Dedicated AES-256-GCM encrypted secret storage for D1 `provider_secrets` (Fixes M3).
//!
//! Security properties:
//! - Uses dedicated `SETTINGS_ENCRYPTION_KEY` (and optional `SETTINGS_ENCRYPTION_KEY_PREV`
//!   for zero-downtime key rotation). NEVER derived from `JWT_SECRET`.
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
    /// Parses a 32-byte key encoded as 64 hex chars OR base64/base64url (padded or unpadded).
    pub fn parse(raw: &str) -> Result<Self, CryptoError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::InvalidKeyFormat("key cannot be empty"));
        }

        let decoded = if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(trimmed).map_err(|_| CryptoError::InvalidKeyFormat("invalid hex key"))?
        } else {
            STANDARD
                .decode(trimmed)
                .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
                .or_else(|_| URL_SAFE.decode(trimmed))
                .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
                .map_err(|_| {
                    CryptoError::InvalidKeyFormat(
                        "must be 64-char hex or base64/base64url encoding of 32 bytes",
                    )
                })?
        };

        if decoded.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyFormat(
                "decoded key must be exactly 32 bytes (256 bits)",
            ));
        }

        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(&decoded);
        Ok(Self::from_bytes(bytes))
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let digest = Sha256::digest(bytes);
        let kid = format!("k1:{}", hex::encode(&digest[..8]));
        Self { kid, bytes }
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

impl KeyRing {
    pub fn from_env_strings(
        current_raw: &str,
        previous_raw: Option<&str>,
    ) -> Result<Self, CryptoError> {
        let current = SecretKey::parse(current_raw)?;
        let previous = match previous_raw.map(str::trim).filter(|s| !s.is_empty()) {
            Some(prev) => {
                let key = SecretKey::parse(prev)?;
                if key.kid() == current.kid() {
                    None
                } else {
                    Some(key)
                }
            }
            None => None,
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
