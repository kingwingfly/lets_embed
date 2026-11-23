//! Deployment-mode safety & gateway assertion middleware for `lets-embed-web`.
//!
//! - **Standalone Mode**:
//!   - Unconditionally strips & ignores privileged gateway headers (`X-Gateway-Assertion`,
//!     `X-Policy-Revision`, `X-Gallery-Switchers`, `CF-IPCountry`, etc.).
//!   - Pins `RequestSafetyContext::standalone(...)` onto request extensions.
//! - **Managed Mode**:
//!   - Exempts ONLY `/healthz` from assertion authentication.
//!   - Verifies `X-Gateway-Assertion` via `site_access::verify_gateway_assertion` on EVERY
//!     other route, rejecting missing/invalid/expired assertions with `403 Forbidden`
//!     (`Cache-Control: private, no-store`).
//!   - Pins ONE immutable digest-verified `Arc<CompiledPolicy>` snapshot per request via
//!     `AppState.policy_store`, failing closed (`503 Service Unavailable`) on any sync,
//!     digest, revision, or compile error — NEVER falling back to `CompiledPolicy::disabled()`.
//!   - Sets `Cache-Control: private, no-store` at origin on all Managed Mode responses except
//!     `/pkg/*` (200, no `Set-Cookie`), `/robots.txt` (200), and anonymous `/sitemap*.xml` (200).

use std::time::{SystemTime, UNIX_EPOCH};

use app::state::{AppState, CallerContext, DeploymentMode, MediaSigner, RequestSafetyContext};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use site_access::{
    GATEWAY_ASSERTION_AUDIENCE, GATEWAY_ASSERTION_DEFAULT_MAX_SKEW, GATEWAY_ASSERTION_HEADER,
    GATEWAY_ASSERTION_TTL, is_privileged_request_header, verify_gateway_assertion,
};

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn strip_privileged_headers(headers: &mut HeaderMap) {
    let to_remove: Vec<_> = headers
        .keys()
        .filter(|name| {
            let s = name.as_str();
            is_privileged_request_header(s) || s.eq_ignore_ascii_case("cf-ipcountry")
        })
        .cloned()
        .collect();
    for key in to_remove {
        headers.remove(&key);
    }
}

fn extract_single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut all = headers.get_all(name).iter();
    let first = all.next()?.to_str().ok()?.trim();
    if all.next().is_some() || first.is_empty() {
        return None;
    }
    Some(first)
}

fn is_safe_pkg_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/pkg/") else {
        return false;
    };
    if rest.is_empty()
        || rest.contains('%')
        || rest.contains('\\')
        || rest.contains('?')
        || rest.contains('#')
        || rest.bytes().any(|b| b <= 0x1f || b == 0x7f)
    {
        return false;
    }
    rest.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn is_sitemap_path(path: &str) -> bool {
    path == "/sitemap.xml" || (path.starts_with("/sitemap/") && path.ends_with(".xml"))
}

fn no_store_error(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "private, no-store")],
        body,
    )
        .into_response()
}

pub async fn safety_and_auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    if state.mode == DeploymentMode::Standalone {
        // Standalone Mode unconditionally ignores privileged gateway/CF headers.
        strip_privileged_headers(req.headers_mut());
        let ctx = RequestSafetyContext::standalone(
            state.policy_store.current_standalone(),
            state.trust_proxy,
        );
        req.extensions_mut().insert(ctx);
        return next.run(req).await;
    }

    // Managed Mode: ONLY `/healthz` is exempted from X-Gateway-Assertion verification.
    if path == "/healthz" {
        strip_privileged_headers(req.headers_mut());
        let mut resp = next.run(req).await;
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        return resp;
    }

    let Some(assertion_secret) = state
        .gateway_assertion_secret
        .as_deref()
        .filter(|s| !s.is_empty())
    else {
        tracing::error!("managed mode missing GATEWAY_ASSERTION_SECRET");
        return no_store_error(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable");
    };
    let Some(media_cap_secret) = state
        .media_cap_secret
        .as_ref()
        .filter(|s| !s.is_empty())
        .cloned()
    else {
        tracing::error!("managed mode missing MEDIA_CAP_SECRET");
        return no_store_error(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable");
    };

    let Some(raw_token) = extract_single_header(req.headers(), GATEWAY_ASSERTION_HEADER) else {
        return no_store_error(StatusCode::FORBIDDEN, "Missing gateway assertion");
    };

    let now = unix_now_secs();
    let assertion = match verify_gateway_assertion(
        raw_token,
        assertion_secret,
        GATEWAY_ASSERTION_AUDIENCE,
        now,
        GATEWAY_ASSERTION_DEFAULT_MAX_SKEW,
    ) {
        Ok(a) => a,
        Err(err) => {
            tracing::warn!(%path, ?err, "rejected invalid gateway assertion");
            return no_store_error(StatusCode::FORBIDDEN, "Invalid gateway assertion");
        }
    };

    // Defense-in-depth checks on expiry upper bound and safe_mode invariant.
    let max_exp = now.saturating_add(GATEWAY_ASSERTION_TTL + GATEWAY_ASSERTION_DEFAULT_MAX_SKEW);
    if assertion.exp > max_exp || (assertion.safe_mode && !assertion.switchers.is_empty()) {
        tracing::warn!(%path, "rejected gateway assertion violating invariants");
        return no_store_error(StatusCode::FORBIDDEN, "Invalid gateway assertion");
    }

    // Strip all privileged headers before forwarding to handlers.
    strip_privileged_headers(req.headers_mut());

    // Pin ONE immutable digest-verified compiled policy snapshot for this request.
    let policy = match state
        .policy_store
        .resolve_for_assertion(&assertion, &state.engine)
        .await
    {
        Ok(p) => p,
        Err(err) => {
            tracing::error!(%path, %err, "managed policy sync failed closed");
            return no_store_error(StatusCode::SERVICE_UNAVAILABLE, "Policy sync unavailable");
        }
    };

    let is_anonymous = assertion.sub.is_none();
    let ctx = RequestSafetyContext {
        mode: DeploymentMode::Managed,
        policy,
        caller: CallerContext::from_assertion(&assertion),
        signer: MediaSigner::Managed {
            secret: media_cap_secret,
            now_secs: now,
        },
        trust_proxy: false,
    };
    req.extensions_mut().insert(ctx);

    let mut resp = next.run(req).await;

    let ok = resp.status() == StatusCode::OK;
    let has_set_cookie = resp.headers().contains_key(header::SET_COOKIE);
    let allow_public_cache = ok
        && !has_set_cookie
        && ((is_safe_pkg_path(&path))
            || path == "/robots.txt"
            || (is_sitemap_path(&path) && is_anonymous));

    if !allow_public_cache {
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }

    resp
}
