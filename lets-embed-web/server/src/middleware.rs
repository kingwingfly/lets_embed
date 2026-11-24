//! Deployment-mode safety, gateway assertion, and metadata rate-limit middleware for `lets-embed-web`.
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
//!   - Enforces bounded per-subject + global rate limits (`429 Too Many Requests`,
//!     `Cache-Control: private, no-store`) on unmetered metadata routes (M2).
//!   - Pins ONE immutable digest-verified `Arc<CompiledPolicy>` snapshot per request via
//!     `AppState.policy_store`, failing closed (`503 Service Unavailable`) on any sync,
//!     digest, revision, or compile error — NEVER falling back to `CompiledPolicy::disabled()`.
//!   - Sets `Cache-Control: private, no-store` at origin on all Managed Mode responses except
//!     `/pkg/*` (200, no `Set-Cookie`), `/robots.txt` (200), and anonymous `/sitemap*.xml` (200).

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use app::state::{AppState, CallerContext, DeploymentMode, MediaSigner, RequestSafetyContext};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use site_access::{
    ActorBinding, GATEWAY_ASSERTION_AUDIENCE, GATEWAY_ASSERTION_DEFAULT_MAX_SKEW,
    GATEWAY_ASSERTION_HEADER, GATEWAY_ASSERTION_TTL, is_privileged_request_header,
    normalize_ip_bucket, verify_gateway_assertion,
};

/// Maximum distinct subject buckets kept in memory by [`MetadataRateLimiter`].
const MAX_SUBJECT_BUCKETS: usize = 4_096;

#[derive(Debug, Clone, Copy)]
pub struct MetadataRateLimitConfig {
    pub per_subject_limit: u32,
    pub global_limit: u32,
    pub window: Duration,
}

impl Default for MetadataRateLimitConfig {
    fn default() -> Self {
        Self {
            per_subject_limit: 120,
            global_limit: 1_000,
            window: Duration::from_secs(60),
        }
    }
}

#[derive(Debug)]
struct RateState {
    global_window_start: Instant,
    global_count: u32,
    subjects: HashMap<String, (Instant, u32)>,
}

/// Bounded in-memory per-subject + global rate limiter protecting unmetered
/// Postgres metadata routes (`/api/fetch_post_meta`, `/api/suggest_search`,
/// `/api/like_previews`, `/api/fetch_image_details`, `/api/post_images`,
/// `/api/list_post_images`, `/api/list_post_videos`).
#[derive(Debug)]
pub struct MetadataRateLimiter {
    cfg: MetadataRateLimitConfig,
    state: Mutex<RateState>,
}

impl MetadataRateLimiter {
    pub fn new(cfg: MetadataRateLimitConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(RateState {
                global_window_start: Instant::now(),
                global_count: 0,
                subjects: HashMap::new(),
            }),
        }
    }

    /// Check & record one request for `subject`. Returns `Err(retry_after_secs)` on limit exceeded.
    pub fn check_and_record(&self, subject: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Reset global window if elapsed.
        if now.duration_since(guard.global_window_start) >= self.cfg.window {
            guard.global_window_start = now;
            guard.global_count = 0;
        }
        if guard.global_count >= self.cfg.global_limit {
            let rem = self
                .cfg
                .window
                .saturating_sub(now.duration_since(guard.global_window_start))
                .as_secs()
                .max(1);
            return Err(rem);
        }

        // Check existing subject bucket (or evict expired/oldest before inserting).
        if let Some((start, count)) = guard.subjects.get_mut(subject) {
            if now.duration_since(*start) >= self.cfg.window {
                *start = now;
                *count = 0;
            }
            if *count >= self.cfg.per_subject_limit {
                let rem = self
                    .cfg
                    .window
                    .saturating_sub(now.duration_since(*start))
                    .as_secs()
                    .max(1);
                return Err(rem);
            }
            *count += 1;
            guard.global_count += 1;
            return Ok(());
        }

        if guard.subjects.len() >= MAX_SUBJECT_BUCKETS {
            let window = self.cfg.window;
            guard
                .subjects
                .retain(|_, (start, _)| now.duration_since(*start) < window);
            if guard.subjects.len() >= MAX_SUBJECT_BUCKETS
                && let Some(oldest_key) = guard
                    .subjects
                    .iter()
                    .min_by_key(|(_, (start, _))| *start)
                    .map(|(k, _)| k.clone())
            {
                guard.subjects.remove(&oldest_key);
            }
        }

        if self.cfg.per_subject_limit == 0 {
            return Err(self.cfg.window.as_secs().max(1));
        }

        guard.subjects.insert(subject.to_string(), (now, 1));
        guard.global_count += 1;
        Ok(())
    }
}

impl Default for MetadataRateLimiter {
    fn default() -> Self {
        Self::new(MetadataRateLimitConfig::default())
    }
}

#[derive(Debug, Clone)]
pub struct MiddlewareState {
    pub app: AppState,
    pub rate_limiter: Arc<MetadataRateLimiter>,
}

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

pub(crate) fn is_rate_limited_metadata_route(path: &str) -> bool {
    if matches!(
        path,
        "/api/fetch_post_meta"
            | "/api/suggest_search"
            | "/api/like_previews"
            | "/api/fetch_image_details"
            | "/api/post_images"
            | "/api/list_post_images"
            | "/api/list_post_videos"
            | "/api/safety/reveal"
            | "/api/search_advanced"
            | "/api/search_query"
    ) {
        return true;
    }
    // Also cover Leptos hash-suffixed server function endpoints.
    let Some(name) = path.strip_prefix("/api/") else {
        return false;
    };
    [
        "search_query",
        "list_post_images",
        "list_post_videos",
        "fetch_image_details",
    ]
    .iter()
    .any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 20
                && suffix.bytes().all(|b| b.is_ascii_digit())
        })
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn has_valid_internal_secret(headers: &HeaderMap, expected: &[u8]) -> bool {
    if expected.is_empty() {
        return false;
    }
    if let Some(auth) = extract_single_header(headers, "authorization")
        && let Some(token) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        && constant_time_eq(token.trim().as_bytes(), expected)
    {
        return true;
    }
    if let Some(tok) = extract_single_header(headers, "x-internal-api-secret")
        && constant_time_eq(tok.as_bytes(), expected)
    {
        return true;
    }
    if let Some(tok) = extract_single_header(headers, "x-internal-secret")
        && constant_time_eq(tok.as_bytes(), expected)
    {
        return true;
    }
    false
}

fn extract_client_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trust_cf_ip: bool,
    trust_proxy: bool,
) -> Option<IpAddr> {
    if trust_cf_ip
        && let Some(raw) = extract_single_header(headers, "cf-connecting-ip")
        && let Ok(ip) = raw.parse::<IpAddr>()
    {
        return Some(ip);
    }
    if trust_proxy {
        for hdr in ["cf-connecting-ip", "x-real-ip"] {
            if let Some(raw) = extract_single_header(headers, hdr)
                && let Ok(ip) = raw.parse::<IpAddr>()
            {
                return Some(ip);
            }
        }
        if let Some(xff) = extract_single_header(headers, "x-forwarded-for")
            && let Some(first) = xff.split(',').next().map(str::trim)
            && let Ok(ip) = first.parse::<IpAddr>()
        {
            return Some(ip);
        }
    }
    peer_ip
}

fn rate_limit_subject_for_request(
    actor: Option<&ActorBinding>,
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trust_cf_ip: bool,
    trust_proxy: bool,
) -> String {
    match actor {
        Some(ActorBinding::User { sub, .. }) => format!("u:{sub}"),
        Some(ActorBinding::LiveAdmin { email }) => format!("a:{email}"),
        Some(ActorBinding::GuestSession { gid }) => format!("g:{gid}"),
        Some(ActorBinding::Anon) | None => {
            if let Some(ip) = extract_client_ip(headers, peer_ip, trust_cf_ip, trust_proxy) {
                format!("ip:{}", normalize_ip_bucket(ip))
            } else {
                "anon".to_string()
            }
        }
    }
}

fn no_store_error(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "private, no-store")],
        body,
    )
        .into_response()
}

fn rate_limited_response(retry_after_secs: u64) -> Response {
    let mut resp = no_store_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded");
    if let Ok(val) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, val);
    }
    resp
}

pub async fn safety_and_auth_middleware(
    State(mw): State<MiddlewareState>,
    mut req: Request,
    next: Next,
) -> Response {
    let state = &mw.app;
    let path = req.uri().path().to_string();
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    if state.mode == DeploymentMode::Standalone {
        if path.starts_with("/internal/") {
            return no_store_error(StatusCode::FORBIDDEN, "Internal endpoint unavailable");
        }
        // Standalone Mode unconditionally ignores privileged gateway/CF headers.
        strip_privileged_headers(req.headers_mut());
        if is_rate_limited_metadata_route(&path) {
            let subject =
                rate_limit_subject_for_request(None, req.headers(), peer_ip, false, state.trust_proxy);
            if let Err(retry_after) = mw.rate_limiter.check_and_record(&subject) {
                return rate_limited_response(retry_after);
            }
        }
        let ctx = RequestSafetyContext::standalone(
            state.policy_store.current_standalone(),
            state.trust_proxy,
        );
        req.extensions_mut().insert(ctx);
        return next.run(req).await;
    }

    // Managed Mode: ONLY `/healthz` is exempted from authentication.
    if path == "/healthz" {
        strip_privileged_headers(req.headers_mut());
        let mut resp = next.run(req).await;
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        return resp;
    }

    let now = unix_now_secs();

    // Managed Mode `/internal/*` endpoints require `INTERNAL_API_SECRET` exclusively
    // (user `X-Gateway-Assertion` alone NEVER unlocks `/internal/*`).
    if path.starts_with("/internal/") {
        let internal_token_ok = state
            .internal_api_secret
            .as_deref()
            .is_some_and(|secret| has_valid_internal_secret(req.headers(), secret));

        if !internal_token_ok {
            return no_store_error(StatusCode::FORBIDDEN, "Invalid internal credentials");
        }

        strip_privileged_headers(req.headers_mut());
        req.headers_mut().remove(header::AUTHORIZATION);
        req.headers_mut().remove("x-internal-api-secret");
        req.headers_mut().remove("x-internal-secret");

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

    // Defense-in-depth check on expiry upper bound.
    let max_exp = now.saturating_add(GATEWAY_ASSERTION_TTL + GATEWAY_ASSERTION_DEFAULT_MAX_SKEW);
    if assertion.exp > max_exp {
        tracing::warn!(%path, "rejected gateway assertion exceeding max TTL");
        return no_store_error(StatusCode::FORBIDDEN, "Invalid gateway assertion");
    }

    // Strip all privileged headers before forwarding to handlers.
    strip_privileged_headers(req.headers_mut());

    // Enforce per-subject + global rate limits on unmetered metadata, search & reveal routes.
    if is_rate_limited_metadata_route(&path) {
        let subject = rate_limit_subject_for_request(
            Some(&assertion.actor),
            req.headers(),
            peer_ip,
            true,
            false,
        );
        if let Err(retry_after) = mw.rate_limiter.check_and_record(&subject) {
            return rate_limited_response(retry_after);
        }
    }

    // Pin ONE immutable exact-aligned Policy v3 snapshot for this request.
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

    let is_anonymous = assertion.actor.is_anon();
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

    let status = resp.status();
    let ok = status == StatusCode::OK;
    let cacheable_status = matches!(status, StatusCode::OK | StatusCode::NOT_MODIFIED);
    let has_set_cookie = resp.headers().contains_key(header::SET_COOKIE);
    let is_pkg = is_safe_pkg_path(&path);
    let allow_public_cache = cacheable_status
        && !has_set_cookie
        && (is_pkg
            || path == "/robots.txt"
            || (is_sitemap_path(&path) && is_anonymous));

    if is_pkg && ok && !has_set_cookie && !resp.headers().contains_key(header::CACHE_CONTROL) {
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    } else if !allow_public_cache {
        let headers = resp.headers_mut();
        headers.remove("cdn-cache-control");
        headers.remove("cloudflare-cdn-cache-control");
        headers.remove("surrogate-control");
        headers.remove(header::EXPIRES);
        headers.remove(header::PRAGMA);
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }

    resp
}
