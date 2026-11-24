//! Pluggable multi-provider authentication subsystem.

pub mod email;
pub mod oauth;
pub mod oidc;
pub mod ssrf;
pub mod telegram;

use std::net::IpAddr;

use axum::{http::HeaderMap, response::Response};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use sha2::{Digest, Sha256};

use crate::auth;

pub fn random_b64url(num_bytes: usize) -> Result<String, Response> {
    let mut buf = vec![0u8; num_bytes];
    getrandom::fill(&mut buf).map_err(|e| {
        worker::console_error!("getrandom failed: {e:?}");
        auth::internal_error()
    })?;
    Ok(B64.encode(buf))
}

pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub fn pkce_s256_challenge(verifier: &str) -> String {
    B64.encode(Sha256::digest(verifier.as_bytes()))
}

/// Sanitize a post-login `next` redirect target so open redirects are impossible.
pub fn sanitize_next_url(raw: Option<&str>) -> String {
    let Some(s) = raw.map(str::trim) else {
        return "/".to_string();
    };
    if !s.starts_with('/')
        || s.starts_with("//")
        || s.contains('\\')
        || s.chars().any(char::is_control)
        || s.len() > 512
    {
        return "/".to_string();
    }
    s.to_string()
}

pub fn ip_rate_key(headers: &HeaderMap, secret: &[u8]) -> String {
    let raw = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let norm = match raw.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Err(_) => "unknown".to_string(),
    };
    let mut h = Sha256::new();
    h.update(secret);
    h.update(b":auth-ip:");
    h.update(norm.as_bytes());
    hex::encode(&h.finalize()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_next_url_blocks_open_redirects() {
        assert_eq!(sanitize_next_url(Some("/user/account")), "/user/account");
        assert_eq!(sanitize_next_url(Some("/details/42?a=1")), "/details/42?a=1");
        assert_eq!(sanitize_next_url(Some("https://evil.com")), "/");
        assert_eq!(sanitize_next_url(Some("//evil.com/x")), "/");
        assert_eq!(sanitize_next_url(Some("/\\evil.com")), "/");
        assert_eq!(sanitize_next_url(Some("/ok\r\nSet-Cookie: x")), "/");
    }

    #[test]
    fn pkce_s256_matches_rfc_7636_vector() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_s256_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
