//! UNIT 2: SIWE auth handlers.
//!
//! - GET  /user/api/nonce  -> 200 Json(NonceResp); nonce stored in KV
//!   (`NONCE_BINDING`) under "nonce:{nonce}" with `NONCE_TTL_SECS`.
//! - POST /user/api/verify Json(VerifyReq) -> 200 Json(VerifyResp) + session
//!   cookie | 400/401 Json(ApiError) | 403 banned.
//! - POST /user/api/verify_solana Json(SiwsReq) -> 200 Json(VerifyResp) + session
//!   cookie | 400/401 | 403 banned | 409 (address linked elsewhere). SIWS login:
//!   the principal is the base58 Solana pubkey (standalone account).
//! - POST /user/api/logout -> clears the cookie.
//! - GET  /user/api/me     -> 200 Json(StatusResp) | 401.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::types::{ApiError, NonceResp, SiwsReq, VerifyReq, VerifyResp};
use crate::{AppState, config, do_client, session, siwe, solana_link};

pub(crate) fn api_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ApiError { error: msg.into() })).into_response()
}

pub(crate) fn internal_error() -> Response {
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

pub(crate) fn display_address(addr: &str) -> String {
    if session::is_eth_address(addr) {
        siwe::to_checksum(addr)
    } else {
        addr.to_string()
    }
}

pub(crate) async fn ensure_not_banned(st: &AppState, addr: &str) -> Result<(), Response> {
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return Err(internal_error());
        }
    };
    #[derive(Deserialize)]
    struct BanRow {
        banned: i64,
    }
    let banned = match db
        .prepare("SELECT banned FROM users WHERE address = ?")
        .bind(&[addr.into()])
    {
        Ok(stmt) => match stmt.first::<BanRow>(None).await {
            Ok(row) => row.is_some_and(|r| r.banned != 0),
            Err(e) => {
                worker::console_error!("ban check failed: {e:?}");
                return Err(internal_error());
            }
        },
        Err(e) => {
            worker::console_error!("ban check bind failed: {e:?}");
            return Err(internal_error());
        }
    };
    if banned {
        return Err(api_error(StatusCode::FORBIDDEN, "account banned"));
    }
    Ok(())
}

pub(crate) async fn touch_user_login(st: &AppState, addr: &str, now: u64) -> Result<(), Response> {
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return Err(internal_error());
        }
    };
    let upsert = db
        .prepare(
            "INSERT INTO users (address, created_at, last_login) VALUES (?, ?, ?) \
             ON CONFLICT(address) DO UPDATE SET last_login = excluded.last_login",
        )
        .bind(&[addr.into(), (now as f64).into(), (now as f64).into()]);
    match upsert {
        Ok(stmt) => {
            if let Err(e) = stmt.run().await {
                worker::console_error!("user upsert failed: {e:?}");
                return Err(internal_error());
            }
        }
        Err(e) => {
            worker::console_error!("user upsert bind failed: {e:?}");
            return Err(internal_error());
        }
    }
    Ok(())
}

pub(crate) fn issue_session(st: &AppState, cookies: &Cookies, addr: &str) -> VerifyResp {
    let now = session::now_secs();
    let claims = session::SessionClaims {
        sub: addr.to_string(),
        iat: now,
        exp: now + config::SESSION_TTL_SECS,
    };
    let token = session::jwt_sign(&claims, &st.jwt_secret);
    cookies.add(session::make_session_cookie(
        token,
        config::SESSION_TTL_SECS as i64,
    ));
    VerifyResp {
        address: display_address(addr),
    }
}

/// Verify an `Origin` (or `Sec-Fetch-Site: same-origin` when `Origin` is absent)
/// header against `siwe_domain` to block cross-site / sibling-subdomain POST CSRF.
pub(crate) fn same_origin(headers: &HeaderMap, domain: &str) -> bool {
    if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok()) {
        return origin == format!("https://{domain}")
            || (domain
                .split(':')
                .next()
                .is_some_and(|h| matches!(h, "localhost" | "127.0.0.1"))
                && origin == format!("http://{domain}"));
    }
    headers
        .get("sec-fetch-site")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("same-origin"))
}

pub(crate) fn require_same_origin(st: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if !same_origin(headers, &st.siwe_domain) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "cross-origin request rejected",
        ));
    }
    Ok(())
}

/// Ensure a verified principal is upserted in D1, not banned, and initialized in its DO.
pub(crate) async fn finalize_eth_principal(st: &AppState, addr: &str) -> Result<(), Response> {
    let now = session::now_secs();
    touch_user_login(st, addr, now).await?;
    ensure_not_banned(st, addr).await?;
    if let Err(e) = do_client::do_init(&st.env, addr).await {
        worker::console_error!("do init failed: {e:?}");
        return Err(internal_error());
    }
    Ok(())
}

/// Check linked-wallet coexistence, upsert D1, check ban, and init DO for a Solana principal.
pub(crate) async fn finalize_sol_principal(st: &AppState, addr: &str) -> Result<(), Response> {
    let db = st.env.d1(crate::D1_BINDING).map_err(|e| {
        worker::console_error!("d1 binding failed: {e:?}");
        internal_error()
    })?;
    #[derive(Deserialize)]
    struct AddrRow {
        #[allow(dead_code)]
        address: String,
    }
    let linked = match db
        .prepare("SELECT address FROM users WHERE solana_address = ?")
        .bind(&[addr.into()])
    {
        Ok(stmt) => match stmt.first::<AddrRow>(None).await {
            Ok(row) => row,
            Err(e) => {
                worker::console_error!("linked lookup failed: {e:?}");
                return Err(internal_error());
            }
        },
        Err(e) => {
            worker::console_error!("linked lookup bind failed: {e:?}");
            return Err(internal_error());
        }
    };
    if linked.is_some() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "this wallet is linked to another account — unlink it there first",
        ));
    }
    let now = session::now_secs();
    touch_user_login(st, addr, now).await?;
    ensure_not_banned(st, addr).await?;
    if let Err(e) = do_client::do_init(&st.env, addr).await {
        worker::console_error!("do init failed: {e:?}");
        return Err(internal_error());
    }
    Ok(())
}

/// Verify an EIP-4361 SIWE direct-login payload, consume its single-use nonce,
/// upsert the user row, enforce the ban check, and ensure the Durable Object exists.
pub(crate) async fn verify_siwe_and_ensure_user(
    st: &AppState,
    req: &VerifyReq,
) -> Result<String, Response> {
    // 1) Parse the EIP-4361 message.
    let msg = siwe::parse_siwe(&req.message)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e.to_string()))?;

    // 2) Domain / version / chain / direct-login URI binding (blocks cross-flow replay).
    if msg.domain != *st.siwe_domain {
        return Err(api_error(StatusCode::UNAUTHORIZED, "domain mismatch"));
    }
    if msg.version != "1" {
        return Err(api_error(StatusCode::UNAUTHORIZED, "unsupported version"));
    }
    if msg.chain_id != st.chain_id {
        return Err(api_error(StatusCode::UNAUTHORIZED, "chain id mismatch"));
    }
    if msg.uri.contains("/user/login/approve")
        || msg
            .statement
            .as_deref()
            .is_some_and(|s| s.starts_with("Approve sign-in for another browser"))
    {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "handoff approval signature cannot be used for direct sign-in",
        ));
    }

    // 3) Timestamps: issued-at freshness + optional expiration.
    let now = session::now_secs();
    let Some(iat) = siwe::parse_rfc3339_epoch(&msg.issued_at) else {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid issued-at timestamp",
        ));
    };
    if now.abs_diff(iat) > config::SIWE_MAX_AGE_SECS {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "message issued-at out of range",
        ));
    }
    if let Some(exp_str) = &msg.expiration_time {
        let Some(exp) = siwe::parse_rfc3339_epoch(exp_str) else {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "invalid expiration timestamp",
            ));
        };
        if exp <= now {
            return Err(api_error(StatusCode::UNAUTHORIZED, "message expired"));
        }
    }

    // 4) Single-use nonce: must exist in KV, then delete it.
    let kv = st.env.kv(crate::NONCE_BINDING).map_err(|e| {
        worker::console_error!("kv binding failed: {e:?}");
        internal_error()
    })?;
    let nonce_key = format!("nonce:{}", msg.nonce);
    match kv.get(&nonce_key).text().await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "unknown or expired nonce",
            ));
        }
        Err(e) => {
            worker::console_error!("nonce get failed: {e:?}");
            return Err(internal_error());
        }
    }
    if let Err(e) = kv.delete(&nonce_key).await {
        worker::console_error!("nonce delete failed: {e:?}");
        return Err(internal_error());
    }

    // 5) Recover the signer and compare against the claimed address.
    let addr = siwe::recover_address(&req.message, &req.signature)
        .map_err(|e| api_error(StatusCode::UNAUTHORIZED, e.to_string()))?;
    if addr != msg.address.to_lowercase() {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "signature does not match address",
        ));
    }

    finalize_eth_principal(st, &addr).await?;
    Ok(addr)
}

/// Verify a SIWS login payload, consume its single-use nonce, enforce linked
/// wallet coexistence and ban checks, upsert the user row, and ensure the DO.
pub(crate) async fn verify_siws_and_ensure_user(
    st: &AppState,
    req: &SiwsReq,
) -> Result<String, Response> {
    // 1) The address must be a well-formed Solana principal.
    if !session::is_sol_principal(&req.solana_address) {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid solana address"));
    }

    // 2) Single-use nonce: must exist in KV, then delete it.
    let kv = st.env.kv(crate::NONCE_BINDING).map_err(|e| {
        worker::console_error!("kv binding failed: {e:?}");
        internal_error()
    })?;
    let nonce_key = format!("nonce:{}", req.nonce);
    match kv.get(&nonce_key).text().await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "unknown or expired nonce",
            ));
        }
        Err(e) => {
            worker::console_error!("nonce get failed: {e:?}");
            return Err(internal_error());
        }
    }
    if let Err(e) = kv.delete(&nonce_key).await {
        worker::console_error!("nonce delete failed: {e:?}");
        return Err(internal_error());
    }

    // 3) Verify the ed25519 signature over the SIWS challenge.
    let msg = siws_challenge(st.siwe_domain.as_str(), &req.nonce);
    if !solana_link::verify_ed25519_challenge(
        &req.solana_address,
        &req.signature,
        &msg,
        req.signed_message.as_deref(),
    ) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "signature verification failed",
        ));
    }

    let addr = req.solana_address.clone();
    finalize_sol_principal(st, &addr).await?;
    Ok(addr)
}

#[worker::send]
pub async fn nonce(State(st): State<AppState>) -> Response {
    let nonce = uuid::Uuid::new_v4().simple().to_string();

    let kv = match st.env.kv(crate::NONCE_BINDING) {
        Ok(kv) => kv,
        Err(e) => {
            worker::console_error!("kv binding failed: {e:?}");
            return internal_error();
        }
    };
    let put = match kv.put(&format!("nonce:{nonce}"), "1") {
        Ok(p) => p,
        Err(e) => {
            worker::console_error!("nonce put failed: {e:?}");
            return internal_error();
        }
    };
    if let Err(e) = put.expiration_ttl(config::NONCE_TTL_SECS).execute().await {
        worker::console_error!("nonce store failed: {e:?}");
        return internal_error();
    }

    Json(NonceResp { nonce }).into_response()
}

#[worker::send]
pub async fn verify(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(req): Json<VerifyReq>,
) -> Response {
    match verify_siwe_and_ensure_user(&st, &req).await {
        Ok(addr) => Json(issue_session(&st, &cookies, &addr)).into_response(),
        Err(resp) => resp,
    }
}

/// The exact challenge a Solana wallet signs to log in (SIWS). Domain-bound and
/// nonce-bound; MUST match the login-page JS byte for byte.
pub fn siws_challenge(domain: &str, nonce: &str) -> String {
    format!("Sign in to lets_embed with Solana\nDomain: {domain}\nNonce: {nonce}")
}

/// Sign-In-With-Solana: authenticate with a Solana wallet as a standalone
/// account whose principal is the base58 pubkey. Mirrors [`verify`] (the SIWE
/// path) but proves control with an ed25519 signature over [`siws_challenge`].
#[worker::send]
pub async fn verify_solana(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(req): Json<SiwsReq>,
) -> Response {
    match verify_siws_and_ensure_user(&st, &req).await {
        Ok(addr) => Json(issue_session(&st, &cookies, &addr)).into_response(),
        Err(resp) => resp,
    }
}

#[worker::send]
pub async fn logout(State(st): State<AppState>, headers: HeaderMap, cookies: Cookies) -> Response {
    if let Err(r) = require_same_origin(&st, &headers) {
        return r;
    }
    cookies.add(session::clear_session_cookie());
    StatusCode::OK.into_response()
}

#[worker::send]
pub async fn me(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_error(StatusCode::UNAUTHORIZED, "not signed in");
    };
    match do_client::do_status(&st.env, &addr).await {
        Ok(status) => Json(status).into_response(),
        Err(e) => {
            worker::console_error!("do status failed: {e:?}");
            internal_error()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn siws_challenge_is_deterministic() {
        assert_eq!(
            siws_challenge("app.example.com", "n1"),
            "Sign in to lets_embed with Solana\nDomain: app.example.com\nNonce: n1"
        );
    }

    #[test]
    fn siws_signature_roundtrip_verifies() {
        // A wallet signs the exact challenge; the shared verifier must accept it,
        // and the signing key's base58 pubkey is a valid Solana principal.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk_b58 = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        assert!(session::is_sol_principal(&pk_b58));

        let msg = siws_challenge("app.example.com", "nonce-xyz");
        let sig_b58 = bs58::encode(sk.sign(msg.as_bytes()).to_bytes()).into_string();
        assert!(solana_link::verify_ed25519_b58(&pk_b58, &sig_b58, &msg));

        // wrong domain in the rebuilt challenge must fail
        let other = siws_challenge("evil.example.com", "nonce-xyz");
        assert!(!solana_link::verify_ed25519_b58(&pk_b58, &sig_b58, &other));
    }
}
