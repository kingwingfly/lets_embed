//! UNIT 6: HTML pages (inline HTML + JS, gateway_worker aesthetic).
//!
//! STUB: implement login_page / account_page / favorites_page. Contracts:
//! - GET /user/login: wallet sign-in page. Inline JS: eth_requestAccounts ->
//!   GET /user/api/nonce -> build EIP-4361 message (domain = location.host,
//!   URI = location.origin + "/user/login", Version 1, Chain ID from page,
//!   Issued At = new Date().toISOString()) -> personal_sign -> POST
//!   /user/api/verify -> redirect to sanitized ?next= (reject non-"/" starts
//!   and "//").
//! - GET /user/account: balance/plan/status via GET /user/api/me; top-up form
//!   (shows deposit address + tx-hash submit -> POST /user/api/topup);
//!   subscribe/unsubscribe buttons for config::PLANS; payment history via
//!   GET /user/api/payments; logout button.
//! - GET /user/favorites: static shell; JS fetches GET /user/api/likes and
//!   renders links to /details/{id} for post/image likes. No thumbnail
//!   fetches (they would consume points).
//! Copy the STYLE/page()/html_escape pattern from gateway_worker/src/lib.rs.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tower_cookies::Cookies;

use crate::AppState;

#[worker::send]
pub async fn login_page(State(_st): State<AppState>) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn account_page(State(_st): State<AppState>, _cookies: Cookies) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn favorites_page(State(_st): State<AppState>, _cookies: Cookies) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}
