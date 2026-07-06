//! FROZEN SCAFFOLD (fully implemented): HS256 session tokens + cookie helpers.
//!
//! Same 2-part token format (`base64url(payload).base64url(hmac)`) and same
//! `lets-embed-jwt-secret` as gateway_worker; `sub` is a session **principal** —
//! either a lowercase 0x eth address (SIWE) or a base58 Solana pubkey (SIWS).
//! The `is_valid_principal` check on `sub` rejects legacy `gw_token` values
//! (UUID subs) signed with the same secret.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tower_cookies::{
    Cookie, Cookies,
    cookie::{SameSite, time::Duration as CookieDuration},
};

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_COOKIE: &str = "ue_session";

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Session principal: a lowercase 0x eth address (SIWE) or a base58 Solana
    /// pubkey (SIWS).
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
}

pub fn now_secs() -> u64 {
    worker::Date::now().as_millis() / 1000
}

pub fn jwt_sign(c: &SessionClaims, secret: &[u8]) -> String {
    let payload = B64.encode(serde_json::to_vec(c).unwrap());
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(payload.as_bytes());
    let sig = B64.encode(mac.finalize().into_bytes());
    format!("{payload}.{sig}")
}

pub fn jwt_verify(token: &str, secret: &[u8], now: u64) -> Option<SessionClaims> {
    let (payload, sig) = token.split_once('.')?;
    let sig = B64.decode(sig).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig).ok()?;
    let c: SessionClaims = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
    (c.exp >= now && is_valid_principal(&c.sub)).then_some(c)
}

/// Lowercase 0x-prefixed 20-byte hex address.
pub fn is_eth_address(s: &str) -> bool {
    s.len() == 42
        && s.starts_with("0x")
        && s[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A base58-encoded 32-byte Solana ed25519 public key. Format-disjoint from
/// [`is_eth_address`] — eth is `0x`+hex, and the base58 alphabet excludes `0`,
/// so `0x…` can never decode as base58 — letting eth and Solana principals share
/// one namespace (session `sub`, `users.address`, DO id) without collision.
pub fn is_sol_principal(s: &str) -> bool {
    // base58 of 32 bytes is 32–44 chars; bound the work before decoding.
    (32..=44).contains(&s.len())
        && matches!(bs58::decode(s).into_vec(), Ok(v) if v.len() == 32)
}

/// A valid session principal: an Ethereum address (SIWE) or a Solana pubkey (SIWS).
pub fn is_valid_principal(s: &str) -> bool {
    is_eth_address(s) || is_sol_principal(s)
}

/// Verified session address from the request cookies, or None.
pub fn session_address(cookies: &Cookies, secret: &[u8]) -> Option<String> {
    let token = cookies.get(SESSION_COOKIE)?;
    Some(jwt_verify(token.value(), secret, now_secs())?.sub)
}

pub fn make_session_cookie(token: String, max_age_secs: i64) -> Cookie<'static> {
    let mut c = Cookie::new(SESSION_COOKIE, token);
    c.set_http_only(true);
    c.set_secure(true);
    c.set_same_site(SameSite::Lax);
    c.set_path("/");
    c.set_max_age(CookieDuration::seconds(max_age_secs));
    c
}

pub fn clear_session_cookie() -> Cookie<'static> {
    make_session_cookie(String::new(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eth_address_check() {
        assert!(is_eth_address(
            "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
        ));
        // uppercase rejected (must be lowercase)
        assert!(!is_eth_address(
            "0xD8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        ));
        // legacy gw_token UUID sub rejected
        assert!(!is_eth_address("2f4d0c9e-9f5a-4a2c-8f2e-2d3b4c5d6e7f"));
        assert!(!is_eth_address("0x123"));
    }

    #[test]
    fn sol_and_valid_principal() {
        // a real 32-byte base58 ed25519 pubkey
        let sol = "7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2";
        assert!(is_sol_principal(sol));
        assert!(is_valid_principal(sol));
        // eth is not a sol principal (base58 excludes '0', so "0x…" can't decode)
        let eth = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        assert!(!is_sol_principal(eth));
        assert!(is_valid_principal(eth));
        // legacy UUID sub is neither
        assert!(!is_sol_principal("2f4d0c9e-9f5a-4a2c-8f2e-2d3b4c5d6e7f"));
        assert!(!is_valid_principal("2f4d0c9e-9f5a-4a2c-8f2e-2d3b4c5d6e7f"));
        // base58 but wrong length (not 32 bytes) rejected
        assert!(!is_sol_principal(&bs58::encode([0u8; 16]).into_string()));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let secret = b"test-secret";
        let claims = SessionClaims {
            sub: "0xd8da6bf26964af9d7eed9e03e53415d37aa96045".into(),
            iat: 1000,
            exp: 2000,
        };
        let tok = jwt_sign(&claims, secret);
        let back = jwt_verify(&tok, secret, 1500).expect("valid");
        assert_eq!(back.sub, claims.sub);
        // expired
        assert!(jwt_verify(&tok, secret, 2001).is_none());
        // wrong key
        assert!(jwt_verify(&tok, b"other", 1500).is_none());
        // non-address sub rejected
        let bad = SessionClaims {
            sub: "some-uuid".into(),
            iat: 1000,
            exp: 2000,
        };
        assert!(jwt_verify(&jwt_sign(&bad, secret), secret, 1500).is_none());
    }
}
