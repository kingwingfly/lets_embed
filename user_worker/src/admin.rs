//! UNIT 7: admin user management, protected by Cloudflare Access.
//!
//! STUB: implement admin_page / credit / ban. Contracts:
//! - All handlers first verify the `Cf-Access-Jwt-Assertion` header (RS256,
//!   JWKS from https://{team_domain}/cdn-cgi/access/certs cached in KV
//!   `JWKS_BINDING` under `JWKS_KEY` with `JWKS_TTL`; check alg/exp/nbf/iss/
//!   aud) — copy the `require_approver` implementation from
//!   gateway_worker/src/lib.rs (it is being deleted there by the gateway
//!   unit). 403 on failure.
//! - GET /user/admin[?q=0xprefix][&address=0x..]: list users from D1 (newest
//!   last_login first, LIMIT 200, optional address-prefix filter); when
//!   ?address= is given also show DO status (do_client::do_status) with
//!   credit/ban forms.
//! - POST /user/admin/credit (form): validate user exists; do_credit with key
//!   "admin:{uuid}"; mirror nothing (balance lives in DO); redirect back.
//! - POST /user/admin/ban (form): DO /ban + UPDATE users SET banned=?;
//!   redirect back.

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct AdminQuery {
    /// Optional address-prefix filter for the user list.
    pub q: Option<String>,
    /// Show DO status + actions for this user.
    pub address: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreditForm {
    pub address: String,
    /// May be negative to deduct.
    pub points: i64,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct BanForm {
    pub address: String,
    /// 1 = ban, 0 = unban.
    pub banned: i64,
}

#[worker::send]
pub async fn admin_page(
    State(_st): State<AppState>,
    _headers: HeaderMap,
    Query(_q): Query<AdminQuery>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn credit(
    State(_st): State<AppState>,
    _headers: HeaderMap,
    Form(_form): Form<CreditForm>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn ban(
    State(_st): State<AppState>,
    _headers: HeaderMap,
    Form(_form): Form<BanForm>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}
