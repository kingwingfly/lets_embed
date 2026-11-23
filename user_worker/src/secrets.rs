//! Dedicated AES-256-GCM secret store for `provider_secrets` (fixes M3).
//!
//! Resolves the 32-byte AES-256-GCM key via `site_access::resolve_provider_aes_key`:
//! 1. RFC 5869 HKDF-SHA256 derivation from `SITE_SECRET` (`KeyDomain::ProviderSecrets`)
//! 2. Optional explicit override `PROVIDER_SECRETS_KEY` (takes precedence when set)
//! 3. Optional `PROVIDER_SECRETS_KEY_PREV` for zero-downtime key rotation.
//!
//! NEVER derived from `JWT_SECRET` or `SESSION_SECRET`. Every decryption validates
//! exact AAD = `"{deployment_id}|{provider_id}|{field_name}"` and fails closed.

use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use site_access::resolve_provider_aes_key;
use worker::Env;

pub const SITE_SECRET_ENV: &str = "SITE_SECRET";
pub const PROVIDER_SECRETS_KEY_ENV: &str = "PROVIDER_SECRETS_KEY";
pub const PROVIDER_SECRETS_KEY_PREV_ENV: &str = "PROVIDER_SECRETS_KEY_PREV";
pub const ENCRYPTION_KEY_SECRET: &str = "SETTINGS_ENCRYPTION_KEY";
pub const ENCRYPTION_KEY_PREV_SECRET: &str = "SETTINGS_ENCRYPTION_KEY_PREV";
pub const NONCE_LEN: usize = 12;

/// Redacted secret wrapper so plaintext credentials are never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    MissingEncryptionKey,
    InvalidEncryptionKey(&'static str),
    InvalidNonceLength,
    EmptyCiphertext,
    DecryptFailed,
    EncryptFailed,
    DatabaseError(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEncryptionKey => write!(
                f,
                "missing provider encryption key (configure SITE_SECRET or optional PROVIDER_SECRETS_KEY)"
            ),
            Self::InvalidEncryptionKey(msg) => write!(f, "invalid encryption key: {msg}"),
            Self::InvalidNonceLength => write!(f, "invalid AES-GCM nonce length"),
            Self::EmptyCiphertext => write!(f, "empty ciphertext"),
            Self::DecryptFailed => write!(f, "failed to decrypt provider secret"),
            Self::EncryptFailed => write!(f, "failed to encrypt provider secret"),
            Self::DatabaseError(msg) => write!(f, "provider secret lookup failed: {msg}"),
        }
    }
}

impl std::error::Error for SecretError {}

#[derive(Clone)]
pub struct EncryptionKey {
    pub kid: String,
    key: [u8; 32],
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("kid", &self.kid)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl EncryptionKey {
    /// Construct an encryption key from raw 32-byte key material using its deterministic kid.
    pub fn from_bytes(key: [u8; 32]) -> Result<Self, SecretError> {
        if key.iter().all(|&b| b == 0) {
            return Err(SecretError::InvalidEncryptionKey("all-zero key rejected"));
        }
        let kid = derive_default_kid(&key);
        Ok(Self { kid, key })
    }

    /// Parse a dedicated 32-byte key from `"<kid>:<material>"` or plain `<material>`.
    /// `<material>` may be 64-char hex or standard/URL-safe base64 (padded or unpadded).
    pub fn parse(raw: &str) -> Result<Self, SecretError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(SecretError::InvalidEncryptionKey("empty key"));
        }

        let explicit_kid = match trimmed.split_once(':') {
            Some((kid, _rest))
                if !kid.is_empty()
                    && kid.len() <= 32
                    && kid
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) =>
            {
                Some(kid.to_string())
            }
            _ => None,
        };

        let decoded = resolve_provider_aes_key(Some(trimmed), None)
            .map_err(SecretError::InvalidEncryptionKey)?;
        let kid = explicit_kid.unwrap_or_else(|| derive_default_kid(&decoded));
        Ok(Self { kid, key: decoded })
    }

    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

fn derive_default_kid(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    format!("k1:{}", hex::encode(&digest[..8]))
}

#[derive(Debug, Clone)]
pub struct KeyRing {
    pub current: EncryptionKey,
    pub prev: Option<EncryptionKey>,
}

fn first_non_empty<'a>(candidates: &[Option<&'a str>]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
}

fn read_env_secret_or_var(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .map(|s| s.to_string())
        .or_else(|_| env.var(name).map(|v| v.to_string()))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

impl KeyRing {
    pub fn from_raw(current_raw: &str, prev_raw: Option<&str>) -> Result<Self, SecretError> {
        let current = EncryptionKey::parse(current_raw)?;
        let prev = match prev_raw.map(str::trim).filter(|s| !s.is_empty()) {
            Some(p) => Some(EncryptionKey::parse(p)?),
            None => None,
        };
        Ok(Self { current, prev })
    }

    /// Resolve the active provider-secrets AES-256-GCM keyring via `site_access::kdf`:
    /// - Defaults to `SITE_SECRET` (HKDF `KeyDomain::ProviderSecrets`), with optional
    ///   explicit `PROVIDER_SECRETS_KEY` override (and silent legacy alias compatibility).
    /// - Optional `PROVIDER_SECRETS_KEY_PREV` or `SITE_SECRET_PREV` rotation key.
    pub fn resolve(
        provider_secrets_key: Option<&str>,
        settings_encryption_key: Option<&str>,
        site_secret: Option<&str>,
        provider_secrets_key_prev: Option<&str>,
        settings_encryption_key_prev: Option<&str>,
    ) -> Result<Self, SecretError> {
        Self::resolve_with_site_prev(
            provider_secrets_key,
            settings_encryption_key,
            site_secret,
            provider_secrets_key_prev,
            settings_encryption_key_prev,
            None,
        )
    }

    pub fn resolve_with_site_prev(
        provider_secrets_key: Option<&str>,
        settings_encryption_key: Option<&str>,
        site_secret: Option<&str>,
        provider_secrets_key_prev: Option<&str>,
        settings_encryption_key_prev: Option<&str>,
        site_secret_prev: Option<&str>,
    ) -> Result<Self, SecretError> {
        let current = if let Some(explicit) =
            first_non_empty(&[provider_secrets_key, settings_encryption_key])
        {
            EncryptionKey::parse(explicit)?
        } else if let Some(master) = first_non_empty(&[site_secret]) {
            let derived = resolve_provider_aes_key(None, Some(master))
                .map_err(SecretError::InvalidEncryptionKey)?;
            EncryptionKey::from_bytes(derived)?
        } else {
            return Err(SecretError::MissingEncryptionKey);
        };

        let prev = if let Some(raw) =
            first_non_empty(&[provider_secrets_key_prev, settings_encryption_key_prev])
        {
            Some(EncryptionKey::parse(raw)?)
        } else if let Some(prev_master) = first_non_empty(&[site_secret_prev]) {
            let derived = resolve_provider_aes_key(None, Some(prev_master))
                .map_err(SecretError::InvalidEncryptionKey)?;
            Some(EncryptionKey::from_bytes(derived)?)
        } else {
            None
        };
        Ok(Self { current, prev })
    }

    pub fn from_env(env: &Env) -> Result<Self, SecretError> {
        let provider_key = read_env_secret_or_var(env, PROVIDER_SECRETS_KEY_ENV);
        let legacy_key = read_env_secret_or_var(env, ENCRYPTION_KEY_SECRET);
        let site_secret = read_env_secret_or_var(env, SITE_SECRET_ENV);
        let provider_prev = read_env_secret_or_var(env, PROVIDER_SECRETS_KEY_PREV_ENV);
        let legacy_prev = read_env_secret_or_var(env, ENCRYPTION_KEY_PREV_SECRET);
        let site_prev = read_env_secret_or_var(env, "SITE_SECRET_PREV");
        Self::resolve_with_site_prev(
            provider_key.as_deref(),
            legacy_key.as_deref(),
            site_secret.as_deref(),
            provider_prev.as_deref(),
            legacy_prev.as_deref(),
            site_prev.as_deref(),
        )
    }
}

/// Encrypted row stored in D1 `provider_secrets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedSecret {
    pub kid: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Canonical AAD format shared between `admin_dashboard_worker` and `user_worker`.
pub fn build_aad(deployment_id: &str, provider_id: &str, field_name: &str) -> Vec<u8> {
    format!("{deployment_id}|{provider_id}|{field_name}").into_bytes()
}

/// Encrypt a provider secret using the current key in `ring` and a fresh CSPRNG 96-bit nonce.
pub fn encrypt_secret(
    ring: &KeyRing,
    deployment_id: &str,
    provider_id: &str,
    field_name: &str,
    plaintext: &str,
) -> Result<EncryptedSecret, SecretError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| SecretError::EncryptFailed)?;
    encrypt_secret_with_nonce(
        &ring.current,
        deployment_id,
        provider_id,
        field_name,
        plaintext,
        nonce_bytes,
    )
}

fn encrypt_secret_with_nonce(
    key: &EncryptionKey,
    deployment_id: &str,
    provider_id: &str,
    field_name: &str,
    plaintext: &str,
    nonce_bytes: [u8; NONCE_LEN],
) -> Result<EncryptedSecret, SecretError> {
    let cipher = Aes256Gcm::new_from_slice(&key.key).map_err(|_| SecretError::EncryptFailed)?;
    let aad = build_aad(deployment_id, provider_id, field_name);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| SecretError::EncryptFailed)?;
    Ok(EncryptedSecret {
        kid: key.kid.clone(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt a `provider_secrets` row validating AES-256-GCM tag and exact AAD.
/// Supports zero-downtime key rotation via `PROVIDER_SECRETS_KEY_PREV` and
/// ALWAYS fails closed on tag/AAD mismatch.
pub fn decrypt_secret(
    ring: &KeyRing,
    deployment_id: &str,
    provider_id: &str,
    field_name: &str,
    row: &EncryptedSecret,
) -> Result<SecretString, SecretError> {
    if row.nonce.len() != NONCE_LEN {
        return Err(SecretError::InvalidNonceLength);
    }
    if row.ciphertext.is_empty() {
        return Err(SecretError::EmptyCiphertext);
    }

    let aad = build_aad(deployment_id, provider_id, field_name);
    let nonce = Nonce::from_slice(&row.nonce);

    // Order candidate keys with matching kid first, then fallback key during rotation.
    let candidates: Vec<&EncryptionKey> = match &ring.prev {
        Some(prev) if row.kid == prev.kid && row.kid != ring.current.kid => {
            vec![prev, &ring.current]
        }
        Some(prev) => vec![&ring.current, prev],
        None => vec![&ring.current],
    };

    for key in candidates {
        let Ok(cipher) = Aes256Gcm::new_from_slice(&key.key) else {
            continue;
        };
        if let Ok(plain_bytes) = cipher.decrypt(
            nonce,
            Payload {
                msg: row.ciphertext.as_slice(),
                aad: &aad,
            },
        ) {
            let text = String::from_utf8(plain_bytes).map_err(|_| SecretError::DecryptFailed)?;
            return Ok(SecretString::new(text));
        }
    }

    Err(SecretError::DecryptFailed)
}

/// Load a provider secret from D1 `provider_secrets` (decrypting via the
/// `SITE_SECRET` / `PROVIDER_SECRETS_KEY` keyring and validating AAD).
///
/// If a row exists in D1 and decryption fails, this FAILS CLOSED (`Err`) and
/// NEVER silently falls back to env vars. Only when no D1 row exists does it
/// consult `fallback_env_vars` (`wrangler secret`).
pub async fn load_provider_secret(
    env: &Env,
    deployment_id: &str,
    provider_id: &str,
    field_name: &str,
    fallback_env_vars: &[&str],
) -> Result<Option<SecretString>, SecretError> {
    #[derive(Deserialize)]
    struct Row {
        kid: String,
        nonce_hex: String,
        ciphertext_hex: String,
    }

    let db = env
        .d1(crate::D1_BINDING)
        .map_err(|e| SecretError::DatabaseError(e.to_string()))?;

    let row = db
        .prepare(
            "SELECT kid, hex(nonce) AS nonce_hex, hex(ciphertext) AS ciphertext_hex \
             FROM provider_secrets WHERE provider_id = ?1 AND field_name = ?2",
        )
        .bind(&[provider_id.into(), field_name.into()])
        .map_err(|e| SecretError::DatabaseError(e.to_string()))?
        .first::<Row>(None)
        .await
        .map_err(|e| SecretError::DatabaseError(e.to_string()))?;

    if let Some(row) = row {
        let nonce = hex::decode(&row.nonce_hex).map_err(|_| SecretError::InvalidNonceLength)?;
        let ciphertext =
            hex::decode(&row.ciphertext_hex).map_err(|_| SecretError::DecryptFailed)?;
        let ring = KeyRing::from_env(env)?;
        let secret = decrypt_secret(
            &ring,
            deployment_id,
            provider_id,
            field_name,
            &EncryptedSecret {
                kid: row.kid,
                nonce,
                ciphertext,
            },
        )?;
        return Ok(Some(secret));
    }

    for &var_name in fallback_env_vars {
        if let Ok(sec) = env.secret(var_name) {
            let val = sec.to_string().trim().to_string();
            if !val.is_empty() {
                return Ok(Some(SecretString::new(val)));
            }
        }
        if let Ok(var) = env.var(var_name) {
            let val = var.to_string().trim().to_string();
            if !val.is_empty() {
                return Ok(Some(SecretString::new(val)));
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD},
    };
    use site_access::{KeyDomain, derive_domain_key_bytes};

    use super::*;

    const KEY_V1_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const KEY_V2_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn aes_gcm_roundtrip_and_aad_binding() {
        let ring = KeyRing::from_raw(&format!("v1:{KEY_V1_HEX}"), None).expect("keyring");
        let enc = encrypt_secret(&ring, "prod-1", "google", "client_secret", "super-secret-val")
            .expect("encrypt");
        assert_eq!(enc.kid, "v1");
        assert_eq!(enc.nonce.len(), NONCE_LEN);
        assert_ne!(enc.ciphertext, b"super-secret-val");

        let plain = decrypt_secret(&ring, "prod-1", "google", "client_secret", &enc)
            .expect("decrypt");
        assert_eq!(plain.expose(), "super-secret-val");
        assert_eq!(format!("{plain:?}"), "[REDACTED]");

        // AAD mismatch on deployment_id, provider_id, or field_name MUST fail closed.
        assert_eq!(
            decrypt_secret(&ring, "prod-2", "google", "client_secret", &enc),
            Err(SecretError::DecryptFailed)
        );
        assert_eq!(
            decrypt_secret(&ring, "prod-1", "github", "client_secret", &enc),
            Err(SecretError::DecryptFailed)
        );
        assert_eq!(
            decrypt_secret(&ring, "prod-1", "google", "api_key", &enc),
            Err(SecretError::DecryptFailed)
        );

        // Tampered ciphertext MUST fail closed.
        let mut tampered = enc.clone();
        tampered.ciphertext[0] ^= 0xff;
        assert_eq!(
            decrypt_secret(&ring, "prod-1", "google", "client_secret", &tampered),
            Err(SecretError::DecryptFailed)
        );

        // Wrong nonce length MUST fail closed.
        let mut bad_nonce = enc.clone();
        bad_nonce.nonce.pop();
        assert_eq!(
            decrypt_secret(&ring, "prod-1", "google", "client_secret", &bad_nonce),
            Err(SecretError::InvalidNonceLength)
        );
    }

    #[test]
    fn key_rotation_supports_prev_key_and_fails_closed_after_removal() {
        let ring_v1 = KeyRing::from_raw(&format!("v1:{KEY_V1_HEX}"), None).unwrap();
        let enc_v1 = encrypt_secret(&ring_v1, "dep", "telegram", "bot_token", "12345:ABC")
            .expect("encrypt v1");

        // During rotation: current = v2, prev = v1 -> decrypts v1 rows cleanly!
        let ring_rotating = KeyRing::from_raw(
            &format!("v2:{KEY_V2_HEX}"),
            Some(&format!("v1:{KEY_V1_HEX}")),
        )
        .unwrap();
        let plain = decrypt_secret(&ring_rotating, "dep", "telegram", "bot_token", &enc_v1)
            .expect("decrypt via prev key");
        assert_eq!(plain.expose(), "12345:ABC");

        // Even if stored kid differs (e.g. written by admin worker with different kid naming),
        // AES-GCM authentication with prev key still succeeds cleanly.
        let mut alt_kid = enc_v1.clone();
        alt_kid.kid = "admin-k1".to_string();
        assert_eq!(
            decrypt_secret(&ring_rotating, "dep", "telegram", "bot_token", &alt_kid)
                .unwrap()
                .expose(),
            "12345:ABC"
        );

        // New encryptions use v2.
        let enc_v2 = encrypt_secret(&ring_rotating, "dep", "telegram", "bot_token", "99999:XYZ")
            .expect("encrypt v2");
        assert_eq!(enc_v2.kid, "v2");

        // Once v1 is dropped from keyring, v1 ciphertext fails closed while v2 still decrypts.
        let ring_v2_only = KeyRing::from_raw(&format!("v2:{KEY_V2_HEX}"), None).unwrap();
        assert_eq!(
            decrypt_secret(&ring_v2_only, "dep", "telegram", "bot_token", &enc_v1),
            Err(SecretError::DecryptFailed)
        );
        assert_eq!(
            decrypt_secret(&ring_v2_only, "dep", "telegram", "bot_token", &enc_v2)
                .unwrap()
                .expose(),
            "99999:XYZ"
        );
    }

    #[test]
    fn key_parser_supports_base64_and_rejects_weak_or_wrong_size_keys() {
        let b64 = B64_STD.encode([0x5au8; 32]);
        let parsed = EncryptionKey::parse(&b64).expect("base64 key");
        assert!(parsed.kid.starts_with("k1:"));

        let b64_url = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
        assert!(EncryptionKey::parse(&b64_url).is_ok());

        // Reject all-zero key
        assert!(EncryptionKey::parse(&"00".repeat(32)).is_err());
        // Reject short key
        assert!(EncryptionKey::parse("abcd").is_err());
        assert!(EncryptionKey::parse("").is_err());
    }

    #[test]
    fn keyring_resolves_from_site_secret_hkdf_and_honors_explicit_overrides() {
        let master = "0123456789abcdef0123456789abcdef0123456789abcdef";

        // 1. SITE_SECRET-only derives KeyDomain::ProviderSecrets via HKDF-SHA256
        let ring_hkdf = KeyRing::resolve(None, None, Some(master), None, None).expect("hkdf ring");
        assert_eq!(
            ring_hkdf.current.key_bytes(),
            &derive_domain_key_bytes(master.as_bytes(), KeyDomain::ProviderSecrets)
        );
        let enc = encrypt_secret(&ring_hkdf, "prod", "google", "client_secret", "hkdf-secret")
            .expect("encrypt with hkdf");
        assert_eq!(
            decrypt_secret(&ring_hkdf, "prod", "google", "client_secret", &enc)
                .unwrap()
                .expose(),
            "hkdf-secret"
        );

        // 2. Explicit PROVIDER_SECRETS_KEY overrides both SETTINGS_ENCRYPTION_KEY and SITE_SECRET
        let ring_explicit = KeyRing::resolve(
            Some(&format!("p1:{KEY_V1_HEX}")),
            Some(&format!("s1:{KEY_V2_HEX}")),
            Some(master),
            None,
            Some(&format!("old:{KEY_V2_HEX}")),
        )
        .expect("explicit override");
        assert_eq!(ring_explicit.current.kid, "p1");
        assert_eq!(ring_explicit.prev.as_ref().unwrap().kid, "old");

        // 3. Legacy SETTINGS_ENCRYPTION_KEY overrides SITE_SECRET when PROVIDER_SECRETS_KEY unset
        let ring_legacy = KeyRing::resolve(
            None,
            Some(&format!("s1:{KEY_V2_HEX}")),
            Some(master),
            None,
            None,
        )
        .expect("legacy override");
        assert_eq!(ring_legacy.current.kid, "s1");

        // 4. Rotation from legacy SETTINGS_ENCRYPTION_KEY -> SITE_SECRET via *_PREV succeeds
        let enc_legacy = encrypt_secret(&ring_legacy, "prod", "github", "client_secret", "gh-tok")
            .expect("encrypt legacy");
        let ring_migrated = KeyRing::resolve(
            None,
            None,
            Some(master),
            None,
            Some(&format!("s1:{KEY_V2_HEX}")),
        )
        .expect("migrated ring");
        assert_eq!(
            decrypt_secret(&ring_migrated, "prod", "github", "client_secret", &enc_legacy)
                .unwrap()
                .expose(),
            "gh-tok"
        );

        // 5. Zero-downtime SITE_SECRET -> SITE_SECRET_PREV rotation succeeds
        let master_new = "new-master-site-secret-0123456789abcdef0123456789abcdef";
        let ring_old_master =
            KeyRing::resolve_with_site_prev(None, None, Some(master), None, None, None)
                .expect("old master ring");
        let enc_old = encrypt_secret(&ring_old_master, "prod", "discord", "client_secret", "dc-s")
            .expect("encrypt with old master");
        let ring_rotated = KeyRing::resolve_with_site_prev(
            None,
            None,
            Some(master_new),
            None,
            None,
            Some(master),
        )
        .expect("rotated master ring");
        assert_eq!(
            decrypt_secret(&ring_rotated, "prod", "discord", "client_secret", &enc_old)
                .unwrap()
                .expose(),
            "dc-s"
        );

        // 6. Missing all keys fails closed
        assert_eq!(
            KeyRing::resolve(None, None, None, None, None).unwrap_err(),
            SecretError::MissingEncryptionKey
        );
        assert_eq!(
            KeyRing::resolve(Some("  "), Some(""), Some(" "), None, None).unwrap_err(),
            SecretError::MissingEncryptionKey
        );
        let err_msg = SecretError::MissingEncryptionKey.to_string();
        assert!(err_msg.contains("SITE_SECRET"));
        assert!(!err_msg.contains("SETTINGS_ENCRYPTION_KEY"));
    }
}
