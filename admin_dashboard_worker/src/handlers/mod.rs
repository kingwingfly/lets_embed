pub mod accounts;
pub mod overview;
pub mod providers;
pub mod reports;
pub mod safety;

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    AppState,
    api::{ActivationStatus, FieldValidationError, PendingActivationResp},
    security::{
        AdminIdentity, apply_security_headers, forbidden, json_error, json_validation_error,
        verify_csrf_headers,
    },
};

/// Enforces `gallery_admin == true` + verified `AdminIdentity` on read handlers.
pub fn guard_read<'a>(st: &AppState, admin: &'a AdminIdentity) -> Result<&'a str, Response> {
    if !st.admin_binding || admin.email.trim().is_empty() {
        return Err(forbidden("Administrator access required"));
    }
    Ok(admin.email.as_str())
}

/// Enforces `gallery_admin == true` + verified `AdminIdentity` + exact `Origin` +
/// `Sec-Fetch-Site` + `X-Admin-CSRF: 1` on mutation handlers.
pub fn guard_mutation<'a>(
    st: &AppState,
    admin: &'a AdminIdentity,
    headers: &HeaderMap,
) -> Result<&'a str, Response> {
    if !st.admin_binding || admin.email.trim().is_empty() {
        return Err(forbidden("Administrator access required"));
    }
    verify_csrf_headers(
        headers,
        st.admin_domain.as_deref().map(String::as_str),
        st.public_url.as_deref().map(String::as_str),
        &st.siwe_domain,
    )
    .map_err(forbidden)?;
    Ok(admin.email.as_str())
}

pub fn pending_activation_response(
    revision: u64,
    min_enforce_rev: u64,
    policy_digest: String,
    error: String,
) -> Response {
    let mut resp = (
        StatusCode::BAD_GATEWAY,
        Json(PendingActivationResp {
            ok: false,
            pending_activation: true,
            activation_status: ActivationStatus::PendingDoAck.as_str().to_string(),
            revision,
            min_enforce_rev,
            policy_digest,
            error,
        }),
    )
        .into_response();
    apply_security_headers(resp.headers_mut());
    resp
}

pub fn internal_error() -> Response {
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

pub fn bad_gateway(msg: impl Into<String>) -> Response {
    json_error(StatusCode::BAD_GATEWAY, msg)
}

pub fn bad_request(msg: impl Into<String>) -> Response {
    json_error(StatusCode::BAD_REQUEST, msg)
}

pub fn bad_request_fields(
    msg: impl Into<String>,
    field_errors: Vec<FieldValidationError>,
) -> Response {
    json_validation_error(StatusCode::BAD_REQUEST, msg, field_errors)
}

pub fn conflict(msg: impl Into<String>) -> Response {
    json_error(StatusCode::CONFLICT, msg)
}

pub fn not_found(msg: impl Into<String>) -> Response {
    json_error(StatusCode::NOT_FOUND, msg)
}
