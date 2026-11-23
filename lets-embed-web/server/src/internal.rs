//! Policy v3 internal origin endpoints, click-to-reveal endpoint, and Standalone Media Guard:
//!
//! - `GET /internal/facts-rev/{kind}/{id}` — authoritative single-snapshot `facts_rev` lookup
//!   used by `gateway_worker` on every `/media/*` redemption when `safety_enabled == true`.
//! - `POST /internal/validate-safety-catalog` — exact Postgres existence check for
//!   `post_tag:<name>` and `author:<name>` used by `admin_dashboard_worker` on Policy v3 publish.
//! - `POST /api/safety/reveal` — same-origin + CSRF-protected click-to-reveal endpoint minting
//!   a short-lived (15 min) single-asset clear `MediaCapability` v3 bound to the live actor.
//! - Standalone Media Guard (`/images/{*path}` and `/videos/{*path}`) — active in Standalone Mode
//!   when a local Policy v3 file has `safety_enabled == true`, checking DB authorization BEFORE
//!   streaming bytes from disk.

use app::{
    state::{AppState, MediaSigner, RequestSafetyContext},
    util::{normalize_public_origin, resolve_origin_for_request},
};
use axum::{
    Extension, Json,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use search_engine::{
    RevealCheckResult,
    safety::mint_reveal_cap_url_v3,
};
use search_types::{MediaKind, RevealRequest, RevealResponse};
use serde::{Deserialize, Serialize};
use tower_http::services::ServeFile;

const MAX_CATALOG_VALIDATE_ITEMS: usize = 256;

fn no_store_json<T: Serialize>(status: StatusCode, payload: &T) -> Response {
    let mut resp = (status, Json(payload)).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    resp
}

fn no_store_text(status: StatusCode, msg: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "private, no-store")],
        msg,
    )
        .into_response()
}

fn extract_single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut all = headers.get_all(name).iter();
    let first = all.next()?.to_str().ok()?.trim();
    if all.next().is_some() || first.is_empty() {
        return None;
    }
    Some(first)
}

fn parse_media_kind(raw: &str) -> Option<MediaKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "image" => Some(MediaKind::Image),
        "video" => Some(MediaKind::Video),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// GET /internal/facts-rev/{kind}/{id}
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct FactsRevResponse {
    pub facts_rev: u64,
}

/// Authoritative single-snapshot `facts_rev` lookup (`image` | `video`).
pub async fn facts_rev(
    State(state): State<AppState>,
    Path((raw_kind, asset_id)): Path<(String, i64)>,
) -> Response {
    let Some(kind) = parse_media_kind(&raw_kind) else {
        return no_store_text(StatusCode::BAD_REQUEST, "Invalid media kind");
    };
    if asset_id <= 0 {
        return no_store_text(StatusCode::NOT_FOUND, "Not Found");
    }
    match state.engine.lookup_facts_rev(kind, asset_id).await {
        Ok(Some(rev)) => no_store_json(StatusCode::OK, &FactsRevResponse { facts_rev: rev }),
        Ok(None) => no_store_text(StatusCode::NOT_FOUND, "Not Found"),
        Err(err) => {
            tracing::error!(?kind, asset_id, %err, "facts_rev lookup failed");
            no_store_text(StatusCode::SERVICE_UNAVAILABLE, "Facts lookup unavailable")
        }
    }
}

// ---------------------------------------------------------------------------
// POST /internal/validate-safety-catalog
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct ValidateSafetyCatalogRequest {
    #[serde(default)]
    pub post_tags: Vec<String>,
    #[serde(default)]
    pub authors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ValidateSafetyCatalogResponse {
    pub unknown_post_tags: Vec<String>,
    pub unknown_authors: Vec<String>,
}

/// Validates exact existence of `post_tag:<name>` and `author:<name>` references in Postgres.
pub async fn validate_safety_catalog(
    State(state): State<AppState>,
    Json(body): Json<ValidateSafetyCatalogRequest>,
) -> Response {
    if body.post_tags.len() > MAX_CATALOG_VALIDATE_ITEMS
        || body.authors.len() > MAX_CATALOG_VALIDATE_ITEMS
    {
        return no_store_text(
            StatusCode::BAD_REQUEST,
            "Too many catalog items in validation request",
        );
    }

    match state
        .engine
        .validate_safety_catalog(&body.post_tags, &body.authors)
        .await
    {
        Ok(res) => no_store_json(
            StatusCode::OK,
            &ValidateSafetyCatalogResponse {
                unknown_post_tags: res.unknown_post_tags,
                unknown_authors: res.unknown_authors,
            },
        ),
        Err(err) => {
            tracing::error!(%err, "validate_safety_catalog failed");
            no_store_text(
                StatusCode::SERVICE_UNAVAILABLE,
                "Catalog validation unavailable",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/safety/reveal
// ---------------------------------------------------------------------------

/// Verify same-origin + CSRF headers on `POST /api/safety/reveal`:
/// 1. `X-Requested-With: fetch` (case-insensitive, single value).
/// 2. If `Sec-Fetch-Site` is present, it MUST equal `same-origin`.
/// 3. If `Origin` is present, it MUST match the request's canonical origin.
/// 4. At least one of `Origin` or `Sec-Fetch-Site` MUST be present.
pub(crate) fn verify_reveal_csrf(state: &AppState, headers: &HeaderMap) -> Result<(), &'static str> {
    let xrw = extract_single_header(headers, "x-requested-with")
        .ok_or("missing X-Requested-With header")?;
    if !xrw.eq_ignore_ascii_case("fetch") {
        return Err("invalid X-Requested-With header");
    }

    let sec_fetch_site = extract_single_header(headers, "sec-fetch-site");
    let origin_header = extract_single_header(headers, "origin");
    if sec_fetch_site.is_none() && origin_header.is_none() {
        return Err("missing same-origin browser headers");
    }

    if let Some(sfs) = sec_fetch_site
        && !sfs.eq_ignore_ascii_case("same-origin")
    {
        return Err("cross-site reveal request blocked");
    }

    if let Some(raw_origin) = origin_header {
        let req_origin =
            normalize_public_origin(raw_origin).ok_or("malformed Origin header")?;
        let expected_origin = resolve_origin_for_request(state, headers)
            .ok_or("unable to determine canonical origin")?;
        if !req_origin.eq_ignore_ascii_case(&expected_origin) {
            return Err("origin mismatch on reveal request");
        }
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct RevealErrorBody {
    error: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_rev: Option<u64>,
}

/// Same-origin, CSRF-protected object-bound click-to-reveal endpoint.
pub async fn safety_reveal(
    State(state): State<AppState>,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    headers: HeaderMap,
    Json(body): Json<RevealRequest>,
) -> Response {
    if let Err(reason) = verify_reveal_csrf(&state, &headers) {
        return no_store_json(
            StatusCode::FORBIDDEN,
            &RevealErrorBody {
                error: "csrf_rejected",
                message: reason.to_string(),
                active_rev: None,
            },
        );
    }

    let ctx = match ctx_ext {
        Some(Extension(c)) => c,
        None if state.mode.is_managed() => {
            return no_store_text(StatusCode::FORBIDDEN, "Missing verified safety context");
        }
        None => RequestSafetyContext::standalone(
            state.policy_store.current_standalone(),
            state.trust_proxy,
        ),
    };

    if body.asset_id <= 0 {
        return no_store_text(StatusCode::NOT_FOUND, "Not Found");
    }

    let active_rev = ctx.policy.policy.revision;
    if body.policy_rev != active_rev {
        return no_store_json(
            StatusCode::CONFLICT,
            &RevealErrorBody {
                error: "policy_revision_mismatch",
                message: "Policy has updated; please refresh the page.".to_string(),
                active_rev: Some(active_rev),
            },
        );
    }

    // Click-to-reveal MUST be bound to a non-Anon actor (User, LiveAdmin, or GuestSession).
    if ctx.caller.actor.is_anon() {
        return no_store_json(
            StatusCode::FORBIDDEN,
            &RevealErrorBody {
                error: "actor_required",
                message: "Reveal requires an active user or guest session.".to_string(),
                active_rev: None,
            },
        );
    }

    let MediaSigner::Managed { secret, now_secs } = &ctx.signer else {
        return no_store_json(
            StatusCode::FORBIDDEN,
            &RevealErrorBody {
                error: "reveal_unavailable",
                message: "Click-to-reveal capabilities require managed media signing.".to_string(),
                active_rev: None,
            },
        );
    };

    match state
        .engine
        .evaluate_single_asset_for_reveal(body.kind, body.asset_id, &ctx.policy, &ctx.caller)
        .await
    {
        Ok(RevealCheckResult::NotFound) => no_store_text(StatusCode::NOT_FOUND, "Not Found"),
        Ok(RevealCheckResult::Denied) => no_store_json(
            StatusCode::FORBIDDEN,
            &RevealErrorBody {
                error: "reveal_denied",
                message: "You are not permitted to reveal this item.".to_string(),
                active_rev: None,
            },
        ),
        Ok(RevealCheckResult::Allowed {
            immutable_locator,
            facts_rev,
            matched_blocks,
            matched_blurs,
            revealed_refs,
        }) => match mint_reveal_cap_url_v3(
            secret,
            *now_secs,
            active_rev,
            facts_rev,
            body.kind,
            body.asset_id,
            immutable_locator,
            &matched_blocks,
            &matched_blurs,
            &revealed_refs,
            &ctx.caller,
        ) {
            Ok((clear_url, expires_at)) => no_store_json(
                StatusCode::OK,
                &RevealResponse {
                    kind: body.kind,
                    asset_id: body.asset_id,
                    policy_rev: active_rev,
                    clear_url,
                    expires_at,
                },
            ),
            Err(err) => {
                tracing::warn!(asset_id = body.asset_id, %err, "failed minting reveal capability");
                no_store_json(
                    StatusCode::FORBIDDEN,
                    &RevealErrorBody {
                        error: "reveal_sign_denied",
                        message: "Unable to mint reveal capability.".to_string(),
                        active_rev: None,
                    },
                )
            }
        },
        Err(err) => {
            tracing::error!(asset_id = body.asset_id, %err, "safety reveal evaluation failed");
            no_store_text(
                StatusCode::SERVICE_UNAVAILABLE,
                "Reveal verification unavailable",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone Media Guard (`/images/{*path}` and `/videos/{*path}`)
// ---------------------------------------------------------------------------

/// Validate a relative media path from `/images/{*path}` or `/videos/{*path}`,
/// rejecting empty paths, leading slashes, traversal segments, backslashes, and control bytes.
pub(crate) fn sanitize_media_rel_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start_matches('/');
    if trimmed.is_empty()
        || raw.starts_with('/')
        || trimmed.contains('\\')
        || trimmed.contains('%')
        || trimmed.len() > 1024
        || trimmed.bytes().any(|b| b <= 0x1f || b == 0x7f)
    {
        return None;
    }
    let mut clean_segments = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        clean_segments.push(seg);
    }
    Some(clean_segments.join("/"))
}

async fn serve_standalone_guarded_media(
    state: AppState,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    raw_path: String,
    kind: MediaKind,
    req: Request,
) -> Response {
    if state.mode.is_managed() {
        return no_store_text(StatusCode::NOT_FOUND, "Not Found");
    }
    let Some(rel_path) = sanitize_media_rel_path(&raw_path) else {
        return no_store_text(StatusCode::NOT_FOUND, "Not Found");
    };
    let canonical_db_name = match kind {
        MediaKind::Image => match rel_path.strip_suffix(".webp") {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => return no_store_text(StatusCode::NOT_FOUND, "Not Found"),
        },
        MediaKind::Video => rel_path.clone(),
    };

    let ctx = match ctx_ext {
        Some(Extension(c)) => c,
        None => RequestSafetyContext::standalone(
            state.policy_store.current_standalone(),
            state.trust_proxy,
        ),
    };

    match state
        .engine
        .evaluate_asset_by_name(kind, &canonical_db_name, &ctx.policy, &ctx.caller)
        .await
    {
        Ok(None) => return no_store_text(StatusCode::NOT_FOUND, "Not Found"),
        Ok(Some((_id, outcome))) if !outcome.is_clear() => {
            return no_store_text(
                StatusCode::FORBIDDEN,
                "Media blocked by active standalone safety policy",
            );
        }
        Ok(Some((_id, _clear))) => {}
        Err(err) => {
            tracing::error!(?kind, %canonical_db_name, %err, "standalone media guard DB check failed");
            return no_store_text(
                StatusCode::SERVICE_UNAVAILABLE,
                "Media authorization unavailable",
            );
        }
    }

    let Some(prefix) = state.prefix.as_ref().as_ref() else {
        return no_store_text(StatusCode::NOT_FOUND, "Not Found");
    };
    let Ok(canonical_root) = tokio::fs::canonicalize(prefix).await else {
        return no_store_text(StatusCode::NOT_FOUND, "Not Found");
    };
    let candidate = prefix.join(&rel_path);
    let Ok(canonical_file) = tokio::fs::canonicalize(&candidate).await else {
        return no_store_text(StatusCode::NOT_FOUND, "Not Found");
    };
    if !canonical_file.starts_with(&canonical_root) {
        return no_store_text(StatusCode::FORBIDDEN, "Forbidden");
    }

    match ServeFile::new(canonical_file).try_call(req).await {
        Ok(resp) => {
            let mut resp = resp.into_response();
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
            resp
        }
        Err(_) => no_store_text(StatusCode::INTERNAL_SERVER_ERROR, "Failed serving media"),
    }
}

pub async fn standalone_guarded_image(
    State(state): State<AppState>,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    Path(raw_path): Path<String>,
    req: Request,
) -> Response {
    serve_standalone_guarded_media(state, ctx_ext, raw_path, MediaKind::Image, req).await
}

pub async fn standalone_guarded_video(
    State(state): State<AppState>,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    Path(raw_path): Path<String>,
    req: Request,
) -> Response {
    serve_standalone_guarded_media(state, ctx_ext, raw_path, MediaKind::Video, req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use app::{
        policy_sync::PolicyStore,
        state::{CompiledPolicy, DeploymentMode},
    };
    use leptos::config::LeptosOptions;
    use std::sync::Arc;

    fn sample_state(public_url: Option<&str>, mode: DeploymentMode) -> AppState {
        AppState {
            leptos_options: LeptosOptions::builder().output_name("test").build(),
            engine: Arc::new(
                search_engine::Engine::connect_lazy_without_models(
                    "postgres://127.0.0.1:5432/unused",
                )
                .unwrap(),
            ),
            prefix: Arc::new(None),
            public_url: Arc::new(public_url.map(ToOwned::to_owned)),
            mode,
            trust_proxy: false,
            policy_store: Arc::new(PolicyStore::standalone(CompiledPolicy::disabled())),
            gateway_assertion_secret: None,
            media_cap_secret: None,
            internal_api_secret: None,
        }
    }

    #[tokio::test]
    async fn verify_reveal_csrf_enforces_x_requested_with_and_same_origin() {
        let state = sample_state(Some("https://gallery.example.com"), DeploymentMode::Managed);

        // Missing X-Requested-With -> rejected.
        let mut h = HeaderMap::new();
        h.insert("origin", HeaderValue::from_static("https://gallery.example.com"));
        h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(verify_reveal_csrf(&state, &h).is_err());

        // Missing Origin and Sec-Fetch-Site -> rejected.
        let mut h = HeaderMap::new();
        h.insert("x-requested-with", HeaderValue::from_static("fetch"));
        assert!(verify_reveal_csrf(&state, &h).is_err());

        // Cross-site Sec-Fetch-Site -> rejected.
        let mut h = HeaderMap::new();
        h.insert("x-requested-with", HeaderValue::from_static("fetch"));
        h.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        h.insert("origin", HeaderValue::from_static("https://gallery.example.com"));
        assert!(verify_reveal_csrf(&state, &h).is_err());

        // Mismatched Origin -> rejected.
        let mut h = HeaderMap::new();
        h.insert("x-requested-with", HeaderValue::from_static("fetch"));
        h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        h.insert("origin", HeaderValue::from_static("https://evil.example.com"));
        assert!(verify_reveal_csrf(&state, &h).is_err());

        // Valid same-origin + fetch -> accepted!
        let mut h = HeaderMap::new();
        h.insert("x-requested-with", HeaderValue::from_static("fetch"));
        h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        h.insert("origin", HeaderValue::from_static("https://gallery.example.com"));
        assert!(verify_reveal_csrf(&state, &h).is_ok());
    }

    #[test]
    fn sanitize_media_rel_path_rejects_traversal_and_special_chars() {
        assert_eq!(
            sanitize_media_rel_path("dir/sub/img_01.webp").as_deref(),
            Some("dir/sub/img_01.webp")
        );
        assert!(sanitize_media_rel_path("").is_none());
        assert!(sanitize_media_rel_path("/etc/passwd").is_none());
        assert!(sanitize_media_rel_path("../secret.webp").is_none());
        assert!(sanitize_media_rel_path("a/../b.webp").is_none());
        assert!(sanitize_media_rel_path("a/./b.webp").is_none());
        assert!(sanitize_media_rel_path("a\\b.webp").is_none());
        assert!(sanitize_media_rel_path("a%2fb.webp").is_none());
        assert!(sanitize_media_rel_path("a//b.webp").is_none());
    }
}
