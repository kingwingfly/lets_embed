pub mod accounts;
pub mod overview;
pub mod providers;
pub mod reports;
pub mod safety;

use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::{
    AppState,
    security::{forbidden, json_error, require_admin_identity, verify_admin_mutation},
};

/// Enforces `gallery_admin == true` + `ADMIN_HEADER` on read handlers.
pub fn guard_read<'a>(st: &AppState, headers: &'a HeaderMap) -> Result<&'a str, Response> {
    require_admin_identity(st.admin_binding, headers)
        .ok_or_else(|| forbidden("Administrator access required"))
}

/// Enforces `gallery_admin == true` + `ADMIN_HEADER` + exact `Origin` +
/// `Sec-Fetch-Site` + `X-Admin-CSRF: 1` on mutation handlers.
pub fn guard_mutation<'a>(st: &AppState, headers: &'a HeaderMap) -> Result<&'a str, Response> {
    verify_admin_mutation(
        st.admin_binding,
        headers,
        st.public_url.as_deref().map(String::as_str),
        &st.siwe_domain,
    )
    .map_err(forbidden)
}

pub fn internal_error() -> Response {
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

pub fn bad_request(msg: impl Into<String>) -> Response {
    json_error(StatusCode::BAD_REQUEST, msg)
}

pub fn conflict(msg: impl Into<String>) -> Response {
    json_error(StatusCode::CONFLICT, msg)
}

pub fn not_found(msg: impl Into<String>) -> Response {
    json_error(StatusCode::NOT_FOUND, msg)
}
