//! RFC 5869 HKDF-SHA256 Master Secret (`SITE_SECRET`) key derivation.
//!
//! Allows deployers to configure a single high-entropy `SITE_SECRET` instead of
//! 6–7 separate random secrets while maintaining strict cryptographic domain
//! separation across every subsystem and preserving optional per-purpose
//! overrides for independent secret rotation.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit as _, Mac};
use sha2::Sha256;

use crate::legal::hex_lower;

type HmacSha256 = Hmac<Sha256>;

/// Fixed protocol salt for `SITE_SECRET` HKDF-SHA256 extraction.
pub const HKDF_SALT: &[u8] = b"lets-embed-hkdf-v1";

/// Recommended minimum byte length for production `SITE_SECRET` values (256 bits).
pub const MIN_MASTER_SECRET_BYTES: usize = 32;

/// Cryptographically isolated key derivation domains under `SITE_SECRET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyDomain {
    Session,
    MediaCap,
    GatewayAssertion,
    InternalApi,
    AdminAssertion,
    ProviderSecrets,
    GuestSession,
}

impl KeyDomain {
    pub const ALL: [Self; 7] = [
        Self::Session,
        Self::MediaCap,
        Self::GatewayAssertion,
        Self::InternalApi,
        Self::AdminAssertion,
        Self::ProviderSecrets,
        Self::GuestSession,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::MediaCap => "media-cap",
            Self::GatewayAssertion => "gateway-assertion",
            Self::InternalApi => "internal-api",
            Self::AdminAssertion => "admin-assertion",
            Self::ProviderSecrets => "provider-secrets",
            Self::GuestSession => "guest-session",
        }
    }

    pub const fn info(self) -> &'static [u8] {
        match self {
            Self::Session => b"lets-embed:session:v1",
            Self::MediaCap => b"lets-embed:media-cap:v1",
            Self::GatewayAssertion => b"lets-embed:gateway-assertion:v1",
            Self::InternalApi => b"lets-embed:internal-api:v1",
            Self::AdminAssertion => b"lets-embed:admin-assertion:v1",
            Self::ProviderSecrets => b"lets-embed:provider-secrets:v1",
            Self::GuestSession => b"lets-embed:guest-session:v1",
        }
    }
}

/// Validates a production master secret (`SITE_SECRET`), requiring non-empty,
/// control-char-free material of at least [`MIN_MASTER_SECRET_BYTES`] (32) bytes.
pub fn validate_master_secret(master_secret: &str) -> Result<&str, &'static str> {
    let trimmed = master_secret.trim();
    if trimmed.is_empty() {
        return Err("SITE_SECRET must not be empty");
    }
    if trimmed.chars().any(char::is_control) {
        return Err("SITE_SECRET must not contain control characters");
    }
    if trimmed.len() < MIN_MASTER_SECRET_BYTES {
        return Err("SITE_SECRET must be at least 32 bytes");
    }
    Ok(trimmed)
}

/// RFC 5869 Section 2.2: `HKDF-Extract(salt, IKM) -> PRK` (SHA-256).
///
/// If `salt` is empty, a 32-byte zero salt (`HashLen` zeros) is used per RFC 5869.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let zero_salt = [0u8; 32];
    let effective_salt = if salt.is_empty() { &zero_salt } else { salt };
    let mut mac =
        HmacSha256::new_from_slice(effective_salt).expect("HMAC accepts variable length keys");
    mac.update(ikm);
    let bytes = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&bytes);
    prk
}

/// RFC 5869 Section 2.3: `HKDF-Expand(PRK, info, L) -> OKM` (SHA-256).
///
/// Rejects output lengths exceeding `255 * 32` bytes (8160 bytes).
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), &'static str> {
    const HASH_LEN: usize = 32;
    const MAX_LEN: usize = 255 * HASH_LEN;

    if out.len() > MAX_LEN {
        return Err("HKDF-Expand output length exceeds 255 * HashLen");
    }
    if out.is_empty() {
        return Ok(());
    }

    let mut prev = [0u8; HASH_LEN];
    let mut has_prev = false;
    let mut counter: u8 = 1;
    let mut offset = 0usize;

    while offset < out.len() {
        let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC accepts 32-byte PRK");
        if has_prev {
            mac.update(&prev);
        }
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        prev.copy_from_slice(&block);
        has_prev = true;

        let take = (out.len() - offset).min(HASH_LEN);
        out[offset..offset + take].copy_from_slice(&prev[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }

    Ok(())
}

/// Derives an isolated 32-byte domain key from `master_secret` via RFC 5869
/// HKDF-SHA256 using [`HKDF_SALT`] and `domain.info()`.
pub fn derive_domain_key_bytes(master_secret: &[u8], domain: KeyDomain) -> [u8; 32] {
    let prk = hkdf_extract(HKDF_SALT, master_secret);
    let mut okm = [0u8; 32];
    hkdf_expand(&prk, domain.info(), &mut okm).expect("32 bytes <= 255 * 32");
    okm
}

/// Derives a 64-char lowercase hex domain secret from `master_secret` for
/// `&str` / `&[u8]` HMAC sign/verify APIs.
pub fn derive_domain_secret(master_secret: &str, domain: KeyDomain) -> String {
    let bytes = derive_domain_key_bytes(master_secret.as_bytes(), domain);
    hex_lower(&bytes)
}

/// Resolves the active secret for `domain`:
/// 1. If `explicit_override` is present and non-empty (trimmed), returns it
///    directly for backwards-compatible per-purpose rotation.
/// 2. Else if `master_secret` (`SITE_SECRET`) is present and non-empty
///    (trimmed), derives an isolated 64-char hex key via [`derive_domain_secret`].
/// 3. Else fails closed with `Err`.
pub fn resolve_domain_secret(
    explicit_override: Option<&str>,
    master_secret: Option<&str>,
    domain: KeyDomain,
) -> Result<String, &'static str> {
    if let Some(override_val) = explicit_override.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(override_val.to_string());
    }
    if let Some(master) = master_secret.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(derive_domain_secret(master, domain));
    }
    Err("missing secret: configure explicit override or SITE_SECRET")
}

fn decode_hex_32(raw: &str) -> Result<[u8; 32], &'static str> {
    if raw.len() != 64 {
        return Err("hex key must be 64 characters");
    }
    let bytes = raw.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex character"),
    }
}

/// Resolves the 32-byte AES-256-GCM key for encrypted `provider_secrets`:
/// 1. If `explicit_base64` (`SETTINGS_ENCRYPTION_KEY` / `PROVIDER_SECRETS_KEY`)
///    is present and non-empty, decodes `<optional_kid:><base64|base64url|64-hex>`
///    into 32 non-zero bytes.
/// 2. Else if `master_secret` (`SITE_SECRET`) is present and non-empty, derives
///    `[u8; 32]` directly with [`KeyDomain::ProviderSecrets`].
/// 3. Else fails closed with `Err`.
pub fn resolve_provider_aes_key(
    explicit_base64: Option<&str>,
    master_secret: Option<&str>,
) -> Result<[u8; 32], &'static str> {
    if let Some(raw) = explicit_base64.map(str::trim).filter(|s| !s.is_empty()) {
        let material = match raw.split_once(':') {
            Some((kid, rest))
                if !kid.is_empty()
                    && kid.len() <= 32
                    && kid
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) =>
            {
                rest.trim()
            }
            _ => raw,
        };

        let key = if material.len() == 64 && material.bytes().all(|b| b.is_ascii_hexdigit()) {
            decode_hex_32(material)?
        } else {
            let decoded = STANDARD
                .decode(material)
                .or_else(|_| STANDARD_NO_PAD.decode(material))
                .or_else(|_| URL_SAFE.decode(material))
                .or_else(|_| URL_SAFE_NO_PAD.decode(material))
                .map_err(|_| "explicit provider AES key must be valid base64/base64url or 64-char hex")?;
            if decoded.len() != 32 {
                return Err("explicit provider AES key must decode to exactly 32 bytes");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            arr
        };

        if key.iter().all(|&b| b == 0) {
            return Err("all-zero provider AES key rejected");
        }
        return Ok(key);
    }

    if let Some(master) = master_secret.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(derive_domain_key_bytes(
            master.as_bytes(),
            KeyDomain::ProviderSecrets,
        ));
    }

    Err("missing provider AES key: configure explicit key or SITE_SECRET")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        assert_eq!(b.len() % 2, 0);
        (0..b.len() / 2)
            .map(|i| (hex_nibble(b[i * 2]).unwrap() << 4) | hex_nibble(b[i * 2 + 1]).unwrap())
            .collect()
    }

    #[test]
    fn rfc_5869_appendix_a_test_vectors_match_exactly() {
        // Test Case 1 (Basic test case with SHA-256)
        let ikm = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = from_hex("000102030405060708090a0b0c");
        let info = from_hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex_lower(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm).unwrap();
        assert_eq!(
            hex_lower(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        // Test Case 2 (Longer inputs/outputs)
        let ikm2 = from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt2 = from_hex(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info2 = from_hex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let prk2 = hkdf_extract(&salt2, &ikm2);
        assert_eq!(
            hex_lower(&prk2),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
        );
        let mut okm2 = [0u8; 82];
        hkdf_expand(&prk2, &info2, &mut okm2).unwrap();
        assert_eq!(
            hex_lower(&okm2),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );

        // Test Case 3 (Zero-length salt and info)
        let prk3 = hkdf_extract(&[], &ikm);
        assert_eq!(
            hex_lower(&prk3),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );
        let mut okm3 = [0u8; 42];
        hkdf_expand(&prk3, &[], &mut okm3).unwrap();
        assert_eq!(
            hex_lower(&okm3),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn all_key_domains_derive_distinct_keys_and_overrides_win() {
        let master = "0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(validate_master_secret(master).is_ok());
        assert!(validate_master_secret("too-short").is_err());
        assert!(validate_master_secret("   ").is_err());

        let mut seen_bytes = HashSet::new();
        let mut seen_hex = HashSet::new();
        for domain in KeyDomain::ALL {
            let bytes = derive_domain_key_bytes(master.as_bytes(), domain);
            let hex = derive_domain_secret(master, domain);
            assert_eq!(hex.len(), 64);
            assert!(seen_bytes.insert(bytes), "duplicate bytes for {domain:?}");
            assert!(seen_hex.insert(hex.clone()), "duplicate hex for {domain:?}");

            // Resolution via master secret matches derive_domain_secret
            assert_eq!(
                resolve_domain_secret(None, Some(master), domain).unwrap(),
                hex
            );
            assert_eq!(
                resolve_domain_secret(Some("  "), Some(master), domain).unwrap(),
                hex
            );
            // Explicit override takes precedence
            assert_eq!(
                resolve_domain_secret(Some(" explicit-secret "), Some(master), domain).unwrap(),
                "explicit-secret"
            );
            // Both missing/empty fails closed
            assert!(resolve_domain_secret(None, None, domain).is_err());
            assert!(resolve_domain_secret(Some(""), Some("   "), domain).is_err());
        }
    }

    #[test]
    fn provider_aes_key_supports_explicit_override_and_master_derivation() {
        let master = "master-secret-at-least-32-bytes-long!!";
        let derived = resolve_provider_aes_key(None, Some(master)).unwrap();
        assert_eq!(
            derived,
            derive_domain_key_bytes(master.as_bytes(), KeyDomain::ProviderSecrets)
        );

        let raw_key = [0x42u8; 32];
        let b64 = STANDARD.encode(raw_key);
        let b64_url = URL_SAFE_NO_PAD.encode(raw_key);
        let hex_key = hex_lower(&raw_key);
        let with_kid = format!("k1:{b64}");

        assert_eq!(
            resolve_provider_aes_key(Some(&b64), Some(master)).unwrap(),
            raw_key
        );
        assert_eq!(
            resolve_provider_aes_key(Some(&b64_url), Some(master)).unwrap(),
            raw_key
        );
        assert_eq!(
            resolve_provider_aes_key(Some(&hex_key), Some(master)).unwrap(),
            raw_key
        );
        assert_eq!(
            resolve_provider_aes_key(Some(&with_kid), Some(master)).unwrap(),
            raw_key
        );

        // Reject all-zero, wrong-length, invalid base64, or missing both
        let zeros = STANDARD.encode([0u8; 32]);
        assert!(resolve_provider_aes_key(Some(&zeros), Some(master)).is_err());
        assert!(resolve_provider_aes_key(Some("c2hvcnQ="), Some(master)).is_err());
        assert!(resolve_provider_aes_key(Some("!!!not-b64!!!"), Some(master)).is_err());
        assert!(resolve_provider_aes_key(None, None).is_err());
        assert!(resolve_provider_aes_key(Some(" "), Some("")).is_err());
    }
}
