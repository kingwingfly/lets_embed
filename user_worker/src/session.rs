//! Session token helpers wrapping `site_access` revocable `v2` sessions and
//! legacy wallet session cutover verification, plus `__Host-auth_tx` cookie helpers.

use tower_cookies::{
    Cookie, Cookies,
    cookie::{SameSite, time::Duration as CookieDuration},
};

pub use site_access::{
    AUTH_TX_COOKIE, LegacySessionClaims, SESSION_COOKIE, SESSION_V2_VERSION, SessionV2Claims,
    VerifiedSession, is_eth_address, is_sol_principal, is_valid_do_key, is_valid_legacy_principal,
    sign_legacy_session, sign_session_v2, verify_legacy_session, verify_session_any,
    verify_session_v2,
};

pub fn now_secs() -> u64 {
    worker::Date::now().as_millis() / 1000
}

/// A valid legacy wallet principal: Ethereum address (SIWE) or Solana pubkey (SIWS).
pub fn is_valid_principal(s: &str) -> bool {
    is_valid_legacy_principal(s)
}

/// Verify the `ue_session` cookie (supporting both revocable `v2.` sessions and
/// legacy wallet sessions during cutover).
pub fn verify_cookie_session(
    cookies: &Cookies,
    v2_secret: &[u8],
    legacy_secret: Option<&[u8]>,
) -> Option<VerifiedSession> {
    let token = cookies.get(SESSION_COOKIE)?;
    verify_session_any(token.value(), v2_secret, legacy_secret, now_secs()).ok()
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

/// Browser-bound `__Host-auth_tx` cookie for OAuth/OIDC transactions.
/// Per RFC 6265bis, `__Host-` cookies MUST set `Secure`, `Path=/`, and NO `Domain`.
pub fn make_auth_tx_cookie(value: String, max_age_secs: i64) -> Cookie<'static> {
    let mut c = Cookie::new(AUTH_TX_COOKIE, value);
    c.set_http_only(true);
    c.set_secure(true);
    c.set_same_site(SameSite::Lax);
    c.set_path("/");
    c.set_max_age(CookieDuration::seconds(max_age_secs));
    c
}

pub fn clear_auth_tx_cookie() -> Cookie<'static> {
    make_auth_tx_cookie(String::new(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_session_cookie_sign_and_verify_roundtrip() {
        let v2_secret = b"v2-session-secret";
        let legacy_secret = b"legacy-jwt-secret";
        let claims = SessionV2Claims {
            v: SESSION_V2_VERSION,
            sub: "user-uuid-12345".into(),
            do_key: "usr:550e8400-e29b-41d4-a716-446655440000".into(),
            sid: "sid-abc-999".into(),
            iat: 1000,
            exp: 2000,
        };
        let tok = sign_session_v2(&claims, v2_secret).expect("sign v2");
        assert!(tok.starts_with("v2."));

        let verified = verify_session_any(&tok, v2_secret, Some(legacy_secret), 1500)
            .expect("verify v2");
        assert!(verified.is_v2());
        assert_eq!(verified.user_id(), "user-uuid-12345");
        assert_eq!(verified.do_key(), "usr:550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(verified.sid(), Some("sid-abc-999"));

        // Expired token rejected
        assert!(verify_session_any(&tok, v2_secret, Some(legacy_secret), 2001).is_err());

        // Host cookie attributes conform to __Host- prefix rules
        let c = make_auth_tx_cookie("tx.secret".into(), 600);
        assert_eq!(c.name(), AUTH_TX_COOKIE);
        assert_eq!(c.path(), Some("/"));
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.domain(), None);
    }
}
