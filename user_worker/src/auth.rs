//! UNIT 2: SIWE auth handlers.
//!
//! STUB: implement nonce / verify / logout / me. Contracts:
//! - GET  /user/api/nonce  -> 200 Json(NonceResp); nonce stored in KV
//!   (`NONCE_BINDING`) under "nonce:{nonce}" with `NONCE_TTL_SECS`.
//! - POST /user/api/verify Json(VerifyReq) -> 200 Json(VerifyResp) + session
//!   cookie | 401 Json(ApiError) | 403 banned. Checks: parse, domain,
//!   version "1", chain_id, issued-at freshness (SIWE_MAX_AGE_SECS),
//!   expiration_time, single-use nonce, recovered signer == claimed address;
//!   then D1 upsert into users, `do_client::do_init`, set `ue_session`.
//! - POST /user/api/logout -> clears the cookie.
//! - GET  /user/api/me     -> 200 Json(StatusResp) | 401.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tower_cookies::Cookies;

use crate::AppState;
use crate::types::VerifyReq;

#[worker::send]
pub async fn nonce(State(_st): State<AppState>) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn verify(
    State(_st): State<AppState>,
    _cookies: Cookies,
    Json(_req): Json<VerifyReq>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn logout(_cookies: Cookies) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn me(State(_st): State<AppState>, _cookies: Cookies) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}
