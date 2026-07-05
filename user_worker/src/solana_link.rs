//! UNIT 5: link/unlink a Solana wallet to the (ETH) session.
//!
//! A Solana top-up tx has no on-chain link to the SIWE (Ethereum) session, so
//! the user proves control of a Solana wallet once by signing a challenge; the
//! linked address is then required to originate their SOL/SPL top-ups.
//!
//! - POST   /user/api/link_solana  LinkSolReq -> 200 LinkSolResp | 400 | 401 | 409
//! - DELETE /user/api/link_solana             -> 200 (idempotent)
//!
//! SCAFFOLD STATE: the challenge format is implemented (shared with the account
//! page JS); ed25519 verification + D1 writes are stubs — UNIT 5 fills them in.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tower_cookies::Cookies;

use crate::types::{ApiError, LinkSolReq};
use crate::{AppState, session};

/// The exact message the wallet signs. MUST match the account-page JS byte for
/// byte. `eth_addr` is the lowercase session address; `nonce` is single-use.
pub fn challenge_message(eth_addr: &str, nonce: &str) -> String {
    format!("Link Solana wallet to {eth_addr}\nNonce: {nonce}")
}

fn api_err(code: StatusCode, msg: &str) -> Response {
    (code, Json(ApiError { error: msg.into() })).into_response()
}

#[worker::send]
pub async fn link(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(_req): Json<LinkSolReq>,
) -> Response {
    let Some(_addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };
    // UNIT 5: consume nonce from KV, rebuild challenge, verify ed25519 signature
    // (bs58 pubkey + signature), then UPSERT users.solana_address (409 if the
    // address is already linked to a different account).
    api_err(StatusCode::NOT_IMPLEMENTED, "link_solana not implemented")
}

#[worker::send]
pub async fn unlink(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(_addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };
    // UNIT 5: clear users.solana_address for this account (idempotent).
    api_err(StatusCode::NOT_IMPLEMENTED, "link_solana not implemented")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_deterministic() {
        let m = challenge_message("0xabc", "n1");
        assert_eq!(m, "Link Solana wallet to 0xabc\nNonce: n1");
    }
}
