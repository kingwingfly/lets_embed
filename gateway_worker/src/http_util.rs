//! Pure HTTP routing, canonicalization, header/cookie sanitization, CSRF,
//! metering validation, and response helpers.

use axum::{
    body::Bytes,
    http::{
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
        header::{
            ACCEPT, CACHE_CONTROL, CONTENT_TYPE, IF_NONE_MATCH, RETRY_AFTER, SET_COOKIE,
            USER_AGENT, X_CONTENT_TYPE_OPTIONS,
        },
    },
    response::{IntoResponse, Redirect, Response},
};
use site_access::{
    ADMIN_VIEW_COOKIE, ChargeKind, ChargeReq, GUEST_SESSION_COOKIE, LEGACY_GUEST_SESSION_COOKIE,
    LEGACY_SESSION_COOKIE, STRIPPED_ORIGIN_COOKIES, UPGRADE_PATH, is_privileged_request_header,
};
use worker::{Env, Result};

pub(crate) const USER_ALLOWED_METHODS: &str = "GET, HEAD, POST, DELETE, PUT, PATCH, OPTIONS";
pub(crate) const GALLERY_ALLOWED_METHODS: &str = "GET, HEAD, POST";
pub(crate) const MEDIA_ALLOWED_METHODS: &str = "GET, HEAD";
pub(crate) const MAX_GATEWAY_BODY_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_ADMIN_BODY_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_IMAGE_SEARCH_BODY_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_TEXT_SEARCH_BODY_BYTES: usize = 32 * 1024;
pub(crate) const MAX_REVEAL_BODY_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub(crate) struct Upstreams {
    pub(crate) api: String,
    pub(crate) image: String,
    pub(crate) video: String,
}

pub(crate) fn parse_upstream_origin(raw: &str) -> std::result::Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty upstream URL");
    }
    let url = worker::Url::parse(trimmed).map_err(|_| "malformed upstream URL")?;
    let without_trailing_slash = trimmed.strip_suffix('/').unwrap_or(trimmed);
    let authority_clean = without_trailing_slash
        .get(8..)
        .is_some_and(|rest| !rest.contains('/') && !rest.contains('\\'));
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !authority_clean
    {
        return Err("upstream must be an https origin without userinfo, path, query, or fragment");
    }
    Ok(url.origin().ascii_serialization())
}

impl Upstreams {
    pub(crate) fn from_env(env: &Env) -> Result<Self> {
        let var = |name: &str| -> Result<String> {
            let raw = env.var(name)?.to_string();
            parse_upstream_origin(&raw)
                .map_err(|reason| worker::Error::RustError(format!("invalid {name}: {reason}")))
        };
        let api = match env.var("API_UPSTREAM") {
            Ok(v) => {
                let raw = v.to_string();
                parse_upstream_origin(&raw).map_err(|reason| {
                    worker::Error::RustError(format!("invalid API_UPSTREAM: {reason}"))
                })?
            }
            Err(_) => var("APP_ORIGIN")?,
        };
        Ok(Self {
            api,
            image: var("IMAGE_UPSTREAM")?,
            video: var("VIDEO_UPSTREAM")?,
        })
    }
}

pub(crate) fn private_no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    // Strip CDN-specific override headers that take precedence over `Cache-Control`
    // at Cloudflare / downstream CDNs so private responses can never be edge-cached.
    headers.remove("cdn-cache-control");
    headers.remove("cloudflare-cdn-cache-control");
    headers.remove("surrogate-control");
    headers.remove("expires");
    headers.remove("pragma");
    headers.insert(CACHE_CONTROL, "private, no-store".parse().unwrap());
    response
}

pub(crate) fn checked_user_method(method: &Method) -> Option<worker::Method> {
    match *method {
        Method::GET => Some(worker::Method::Get),
        Method::HEAD => Some(worker::Method::Head),
        Method::POST => Some(worker::Method::Post),
        Method::DELETE => Some(worker::Method::Delete),
        Method::PUT => Some(worker::Method::Put),
        Method::PATCH => Some(worker::Method::Patch),
        Method::OPTIONS => Some(worker::Method::Options),
        _ => None,
    }
}

pub(crate) fn checked_gallery_method(method: &Method) -> Option<worker::Method> {
    match *method {
        Method::GET => Some(worker::Method::Get),
        Method::HEAD => Some(worker::Method::Head),
        Method::POST => Some(worker::Method::Post),
        _ => None,
    }
}

pub(crate) fn checked_media_method(method: &Method) -> Option<worker::Method> {
    match *method {
        Method::GET => Some(worker::Method::Get),
        Method::HEAD => Some(worker::Method::Head),
        _ => None,
    }
}

pub(crate) fn method_not_allowed(allow: &'static str) -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [("allow", allow), ("cache-control", "private, no-store")],
        "Method Not Allowed",
    )
        .into_response()
}

pub(crate) fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> std::result::Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

fn host_without_port(host: &str) -> &str {
    if let Some((h, port)) = host.rsplit_once(':')
        && !h.contains(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return h;
    }
    host
}

pub(crate) fn request_host<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> Option<&'a str> {
    let raw = uri
        .authority()
        .map(|a| a.as_str())
        .or_else(|| single_header(headers, "host").ok().flatten())?;
    let host = raw.trim();
    if host.is_empty() || host.contains('/') || host.contains('@') {
        return None;
    }
    Some(host)
}

/// Returns `true` unless the request URI explicitly uses `http://`.
///
/// SECURITY: Derives strictly from `uri.scheme_str()` and NEVER reads the
/// untrusted client `X-Forwarded-Proto` header.
pub(crate) fn is_https_request(uri: &Uri) -> bool {
    !uri.scheme_str()
        .is_some_and(|s| s.eq_ignore_ascii_case("http"))
}

pub(crate) fn is_same_origin(uri: &Uri, headers: &HeaderMap) -> bool {
    let Ok(sec_fetch_site) = single_header(headers, "sec-fetch-site") else {
        return false;
    };
    if let Some(site) = sec_fetch_site
        && !site.trim().eq_ignore_ascii_case("same-origin")
    {
        return false;
    }
    let Ok(origin) = single_header(headers, "origin") else {
        return false;
    };
    let Some(origin) = origin else {
        return sec_fetch_site.is_some();
    };
    let Some(host) = request_host(uri, headers) else {
        return false;
    };
    let origin = origin.trim();
    let bare_host = host_without_port(host);
    let allow_http = bare_host.eq_ignore_ascii_case("localhost") || bare_host == "127.0.0.1";
    if let Some(rest) = origin.strip_prefix("https://") {
        rest.eq_ignore_ascii_case(host)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        allow_http && rest.eq_ignore_ascii_case(host)
    } else {
        false
    }
}

/// Validates the required `X-Requested-With: fetch` anti-CSRF header on
/// `POST /api/safety/reveal`.
pub(crate) fn has_reveal_csrf_header(headers: &HeaderMap) -> bool {
    single_header(headers, "x-requested-with")
        .ok()
        .flatten()
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("fetch"))
}

pub(crate) fn is_rfc3986_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

pub(crate) fn is_segment_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub(crate) fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

/// Strips sensitive gateway/auth cookies across ALL incoming `Cookie` headers
/// before forwarding requests to `API_UPSTREAM` (`lets-embed-web`).
pub(crate) fn sanitize_origin_cookie(headers: &HeaderMap) -> Option<String> {
    let mut kept = Vec::new();
    for raw in headers.get_all("cookie").iter().filter_map(|v| v.to_str().ok()) {
        for cookie in raw.split(';').map(str::trim).filter(|c| !c.is_empty()) {
            let name = cookie.split('=').next().unwrap_or("").trim();
            if !STRIPPED_ORIGIN_COOKIES.contains(&name) {
                kept.push(cookie);
            }
        }
    }
    (!kept.is_empty()).then(|| kept.join("; "))
}

/// Strict single-occurrence cookie extractor: detects duplicate cookie names across
/// all `Cookie` headers so subdomain cookie tossing cannot silently shadow a host cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CookieLookup<'a> {
    Missing,
    Single(&'a str),
    Duplicate,
}

pub(crate) fn extract_single_cookie<'a>(headers: &'a HeaderMap, target: &str) -> CookieLookup<'a> {
    let mut found: Option<&'a str> = None;
    for raw in headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| std::str::from_utf8(v.as_bytes()).ok())
    {
        for pair in raw.split(';').map(str::trim).filter(|c| !c.is_empty()) {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.trim() == target {
                if found.is_some() {
                    return CookieLookup::Duplicate;
                }
                found = Some(value.trim());
            }
        }
    }
    match found {
        Some(v) => CookieLookup::Single(v),
        None => CookieLookup::Missing,
    }
}

/// Percent-decodes RFC 3986 `%XX` escapes in a cookie name (without translating `+`)
/// to match `cookie::Cookie::parse_encoded` used by `tower-cookies` in `user_worker`.
fn percent_decode_cookie_name(raw: &str) -> String {
    if !raw.contains('%') {
        return raw.to_string();
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Strips admin, Cloudflare Access, and guest-reveal cookies before forwarding to
/// `USER_WORKER` while preserving single-occurrence literal `__Host-ue_session` and
/// `__Host-auth_tx`. Percent-encoded spoofs (e.g. `%5F_Host-ue_session`) are dropped
/// unconditionally and literal duplicate occurrences of auth cookies are dropped
/// fail-closed to prevent parser differentials against `tower-cookies` (Cycle 3 H5 / Cycle 4 I1).
pub(crate) fn sanitize_user_worker_cookie(headers: &HeaderMap) -> Option<String> {
    let dup_session = matches!(
        extract_single_cookie(headers, site_access::SESSION_COOKIE),
        CookieLookup::Duplicate
    );
    let dup_auth_tx = matches!(
        extract_single_cookie(headers, site_access::AUTH_TX_COOKIE),
        CookieLookup::Duplicate
    );
    let mut kept = Vec::new();
    for raw in headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| std::str::from_utf8(v.as_bytes()).ok())
    {
        for cookie in raw.split(';').map(str::trim).filter(|c| !c.is_empty()) {
            let Some((raw_name, _)) = cookie.split_once('=') else {
                continue;
            };
            let name = raw_name.trim();
            if name.is_empty() {
                continue;
            }
            let decoded = percent_decode_cookie_name(name);
            let is_encoded = decoded != name;
            let is_stripped_sensitive = matches!(
                decoded.as_str(),
                ADMIN_VIEW_COOKIE
                    | GUEST_SESSION_COOKIE
                    | LEGACY_GUEST_SESSION_COOKIE
                    | LEGACY_SESSION_COOKIE
                    | "CF_Authorization"
            );
            let is_encoded_auth_spoof = is_encoded
                && matches!(
                    decoded.as_str(),
                    site_access::SESSION_COOKIE | site_access::AUTH_TX_COOKIE
                );
            if !is_stripped_sensitive
                && !is_encoded_auth_spoof
                && !(dup_session && name == site_access::SESSION_COOKIE)
                && !(dup_auth_tx && name == site_access::AUTH_TX_COOKIE)
            {
                kept.push(cookie);
            }
        }
    }
    (!kept.is_empty()).then(|| kept.join("; "))
}

/// Returns `true` for headers that must NEVER be copied verbatim from client
/// requests onto `API_UPSTREAM`.
pub(crate) fn should_strip_api_request_header(name: &str) -> bool {
    is_hop_by_hop(name)
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-forwarded-proto")
        || name.eq_ignore_ascii_case("forwarded")
        || name.eq_ignore_ascii_case("cf-ipcountry")
        || name.eq_ignore_ascii_case("x-internal-api-secret")
        || name.eq_ignore_ascii_case("x-internal-secret")
        || is_privileged_request_header(name)
}

/// Percent-decode a single RFC 3986 path segment into raw bytes (preserving `+`
/// literally). Rejects malformed `%` escapes, lowercase hex digits, double-encoding
/// (`%25`), control/NUL bytes, path delimiters, and percent-encoded RFC 3986 unreserved
/// ASCII characters (so proxies normalizing `/%61pi/...` -> `/api/...` can never bypass
/// gateway route guards or metering).
pub(crate) fn percent_decode_segment_bytes(seg: &str) -> Option<Vec<u8>> {
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let b1 = bytes[i + 1];
                let b2 = bytes[i + 2];
                // Require canonical uppercase hex digits (`0-9A-F`).
                if !(b1.is_ascii_digit() || (b'A'..=b'F').contains(&b1))
                    || !(b2.is_ascii_digit() || (b'A'..=b'F').contains(&b2))
                {
                    return None;
                }
                let hi = (b1 as char).to_digit(16)?;
                let lo = (b2 as char).to_digit(16)?;
                let decoded = (hi * 16 + lo) as u8;
                if is_rfc3986_unreserved(decoded)
                    || decoded <= 0x1f
                    || decoded == 0x7f
                    || matches!(decoded, b'/' | b'\\' | b'?' | b'#' | b'%')
                {
                    return None;
                }
                out.push(decoded);
                i += 3;
            }
            b'%' => return None,
            b if b <= 0x1f || b == 0x7f => return None,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Reject any non-canonical or traversal-bearing request path before route
/// matching, geo exemption, metering, or proxying so gateway checks and upstream
/// URL parsing always see the exact same path.
pub(crate) fn is_canonical_path(path: &str) -> bool {
    if !path.starts_with('/') || path.contains("//") || path.contains('\\') {
        return false;
    }
    for seg in path.split('/') {
        if seg == "." || seg == ".." {
            return false;
        }
        let Some(decoded) = percent_decode_segment_bytes(seg) else {
            return false;
        };
        if decoded == b"."
            || decoded == b".."
            || decoded.contains(&b'/')
            || decoded.contains(&b'\\')
        {
            return false;
        }
    }
    let Ok(parsed) = worker::Url::parse(&format!("https://invalid.local{path}")) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.host_str() == Some("invalid.local")
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.path() == path
}

/// Builds and validates a target URL strictly pinned to `API_UPSTREAM`.
pub(crate) fn build_api_upstream_target(
    uri: &Uri,
    upstreams: &Upstreams,
) -> std::result::Result<worker::Url, ()> {
    let path = uri.path();
    if !is_canonical_path(path) {
        return Err(());
    }
    let upstream = parse_upstream_origin(upstreams.api.as_str()).map_err(|_| ())?;
    let expected_path = if path.is_empty() { "/" } else { path };

    let mut target = format!("{upstream}{expected_path}");
    if let Some(q) = uri.query() {
        target.push('?');
        target.push_str(q);
    }

    let base_url = worker::Url::parse(&upstream).map_err(|_| ())?;
    let target_url = worker::Url::parse(&target).map_err(|_| ())?;
    if target_url.scheme() != base_url.scheme()
        || target_url.host_str() != base_url.host_str()
        || target_url.port_or_known_default() != base_url.port_or_known_default()
        || !target_url.username().is_empty()
        || target_url.password().is_some()
        || target_url.path() != expected_path
        || target_url.fragment().is_some()
    {
        return Err(());
    }
    Ok(target_url)
}

/// Builds and validates `{API_UPSTREAM}/healthz` strictly pinned to `API_UPSTREAM`.
pub(crate) fn build_api_healthz_target(
    upstreams: &Upstreams,
) -> std::result::Result<worker::Url, ()> {
    let upstream = parse_upstream_origin(upstreams.api.as_str()).map_err(|_| ())?;
    let base_url = worker::Url::parse(&upstream).map_err(|_| ())?;
    let target_url = worker::Url::parse(&format!("{upstream}/healthz")).map_err(|_| ())?;
    if target_url.scheme() != base_url.scheme()
        || target_url.host_str() != base_url.host_str()
        || target_url.port_or_known_default() != base_url.port_or_known_default()
        || !target_url.username().is_empty()
        || target_url.password().is_some()
        || target_url.path() != "/healthz"
        || target_url.query().is_some()
        || target_url.fragment().is_some()
    {
        return Err(());
    }
    Ok(target_url)
}

/// Known search/social crawler User-Agent tokens (lowercase) that should wait for
/// the real HTML response instead of receiving the interactive cold-start waking screen.
const CRAWLER_UA_TOKENS: &[&str] = &[
    "googlebot",
    "bingbot",
    "slurp",
    "duckduckbot",
    "baiduspider",
    "yandexbot",
    "twitterbot",
    "facebookexternalhit",
    "discordbot",
    "slackbot",
];

pub(crate) fn is_crawler_user_agent(headers: &HeaderMap) -> bool {
    headers.get_all(USER_AGENT).iter().any(|val| {
        val.to_str().ok().is_some_and(|ua| {
            let lower = ua.to_ascii_lowercase();
            CRAWLER_UA_TOKENS.iter().any(|tok| lower.contains(tok))
        })
    })
}

/// Interactive gallery/legal HTML routes eligible for the cold-start waking screen.
/// Explicitly excludes `/api/*`, `/media/*`, `/pkg/*`, `/robots.txt`, `/favicon.ico`,
/// `/sitemap*.xml`, `/user/*`, `/admin*`, and `/_gw/*`.
pub(crate) fn is_waking_interstitial_path(path: &str) -> bool {
    matches!(
        path,
        "/" | "/terms" | "/privacy" | "/dmca" | "/content-policy"
    ) || path
        .strip_prefix("/details/")
        .is_some_and(|rest| !rest.is_empty())
}

/// Returns `true` iff this request is an interactive browser HTML `GET` navigation
/// to a gallery/legal page (not a bot, API call, subresource, `HEAD`, or `POST`).
pub(crate) fn should_serve_waking_interstitial(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> bool {
    *method == Method::GET
        && is_waking_interstitial_path(path)
        && is_html_navigation(headers)
        && !is_crawler_user_agent(headers)
}

/// Upstream statuses that indicate a transient cold-start / boot-race failure
/// where the waking interstitial + readiness poll should take over.
pub(crate) fn is_transient_cold_start_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
}

/// Paths always accessible on `GET`/`HEAD` (after Step 0 geo check), even when
/// `login_required=yes` or a site-wide age splash is active.
pub(crate) fn is_always_public_path(path: &str) -> bool {
    matches!(
        path,
        "/robots.txt"
            | "/favicon.ico"
            | "/terms"
            | "/privacy"
            | "/dmca"
            | "/content-policy"
    ) || is_segment_prefix(path, "/pkg")
}

pub(crate) fn is_sitemap_path(path: &str) -> bool {
    path == "/sitemap.xml" || is_segment_prefix(path, "/sitemap")
}

/// Paths that may preserve upstream public `Cache-Control` headers (instead of
/// forcing `private, no-store`) when no session cookie is being cleared and
/// (for sitemaps) the request was served anonymously.
pub(crate) fn is_public_cacheable_path(path: &str, anonymous_guest: bool) -> bool {
    if is_segment_prefix(path, "/pkg") || path == "/robots.txt" {
        return true;
    }
    anonymous_guest && is_sitemap_path(path)
}

pub(crate) fn browse_route(method: &Method, path: &str) -> bool {
    if matches!(*method, Method::GET | Method::HEAD) {
        return matches!(
            path,
            "/" | "/favicon.ico"
                | "/robots.txt"
                | "/sitemap.xml"
                | "/terms"
                | "/privacy"
                | "/dmca"
                | "/content-policy"
        ) || ["/pkg", "/details", "/sitemap"]
            .iter()
            .any(|p| is_segment_prefix(path, p));
    }
    if method != Method::POST {
        return false;
    }
    if matches!(
        path,
        "/api/search_similar"
            | "/api/search_by_image"
            | "/api/search_by_desc"
            | "/api/search_advanced"
            | "/api/search_advanced_embed"
            | "/api/search_advanced_clip"
            | "/api/search_advanced_image"
            | "/api/fetch_post_meta"
            | "/api/suggest_search"
            | "/api/site_config"
            | "/api/safety/reveal"
    ) {
        return true;
    }
    // Leptos appends a decimal u64 build hash to its unnamed server functions.
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
    .any(|p| {
        name.strip_prefix(p).is_some_and(|suffix| {
            suffix.is_empty() || (suffix.len() <= 20 && suffix.bytes().all(|b| b.is_ascii_digit()))
        })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MeterError {
    BadRequest,
    PayloadTooLarge,
}

impl MeterError {
    pub(crate) fn into_response(self) -> Response {
        match self {
            Self::BadRequest => {
                private_no_store((StatusCode::BAD_REQUEST, "Invalid search request").into_response())
            }
            Self::PayloadTooLarge => private_no_store(
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Search request body too large",
                )
                    .into_response(),
            ),
        }
    }
}

/// Validate `images` has 1..=4 non-empty comma-separated slots, scanning at most 5 entries.
fn valid_advanced_image_slots(images: &str) -> bool {
    let mut count = 0usize;
    for slot in images.split(',') {
        count += 1;
        if count > 4 || slot.trim().is_empty() {
            return false;
        }
    }
    count >= 1
}

pub(crate) fn require_form_urlencoded(headers: &HeaderMap) -> std::result::Result<(), MeterError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(first) = values.next() else {
        return Err(MeterError::BadRequest);
    };
    if values.next().is_some() {
        return Err(MeterError::BadRequest);
    }
    let ok = first.to_str().ok().is_some_and(|v| {
        v.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    });
    if ok {
        Ok(())
    } else {
        Err(MeterError::BadRequest)
    }
}

/// Defense-in-depth validation of optional pagination/threshold search params so
/// malformed query parameters fail `400` at the edge before reserving a billing hold.
fn validate_optional_search_params(body: &Bytes) -> std::result::Result<(), MeterError> {
    let s = std::str::from_utf8(body).map_err(|_| MeterError::BadRequest)?;
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').ok_or(MeterError::BadRequest)?;
        let key = percent_decode(k).ok_or(MeterError::BadRequest)?;
        if matches!(key.as_str(), "limit" | "offset" | "min_similarity") {
            let val = percent_decode(v).ok_or(MeterError::BadRequest)?;
            let trimmed = val.trim();
            if trimmed.is_empty() {
                continue;
            }
            match key.as_str() {
                "limit" | "offset" => {
                    if trimmed.parse::<i64>().is_err() {
                        return Err(MeterError::BadRequest);
                    }
                }
                "min_similarity" => {
                    let Ok(f) = trimmed.parse::<f32>() else {
                        return Err(MeterError::BadRequest);
                    };
                    if !f.is_finite() || !(0.0..=1.0).contains(&f) {
                        return Err(MeterError::BadRequest);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Computes the metered search [`ChargeReq`] for `POST` search routes.
///
/// Media billing is handled exclusively by the capability-gated `/media/*`
/// handler using [`site_access::MediaBillingKey`]; raw `/images/*` and `/videos/*`
/// are blocked before this function is ever called.
pub(crate) fn metered_item(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> std::result::Result<Option<ChargeReq>, MeterError> {
    if method != Method::POST {
        return Ok(None);
    }
    match path {
        "/api/search_similar" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            validate_optional_search_params(body)?;
            let q = form_field(body, "q").ok_or(MeterError::BadRequest)?;
            let trimmed = q.trim();
            let id: i64 = trimmed.parse().map_err(|_| MeterError::BadRequest)?;
            if id <= 0 {
                return Err(MeterError::BadRequest);
            }
            Ok(Some(ChargeReq {
                kind: ChargeKind::EmbedSearch,
                path: format!("search:sim:{}", &sha256_hex(trimmed)[..32]),
                media_path: None,
            }))
        }
        "/api/search_by_image" => {
            if body.len() > MAX_IMAGE_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            validate_optional_search_params(body)?;
            let image = form_field(body, "image")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::Search,
                path: format!("search:img:{}", &sha256_hex(&image)[..32]),
                media_path: None,
            }))
        }
        "/api/search_by_desc" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            validate_optional_search_params(body)?;
            let q = form_field(body, "q").ok_or(MeterError::BadRequest)?;
            let trimmed = q.trim();
            if trimmed.is_empty() || q.len() > 2000 {
                return Err(MeterError::BadRequest);
            }
            Ok(Some(ChargeReq {
                kind: ChargeKind::Description,
                path: format!("search:desc:{}", &sha256_hex(trimmed)[..32]),
                media_path: None,
            }))
        }
        "/api/search_advanced" => Ok(None),
        "/api/search_advanced_embed" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            validate_optional_search_params(body)?;
            let q = form_field(body, "q")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::EmbedSearch,
                path: format!("search:adv_embed:{}", &sha256_hex(&q)[..32]),
                media_path: None,
            }))
        }
        "/api/search_advanced_clip" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            validate_optional_search_params(body)?;
            let q = form_field(body, "q")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::Description,
                path: format!("search:adv_clip:{}", &sha256_hex(&q)[..32]),
                media_path: None,
            }))
        }
        "/api/search_advanced_image" => {
            if body.len() > MAX_GATEWAY_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            validate_optional_search_params(body)?;
            let q = form_field(body, "q")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            let images = form_field(body, "images")
                .filter(|s| valid_advanced_image_slots(s))
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::Search,
                path: format!(
                    "search:adv_img:{}",
                    &sha256_hex(&format!("{q}\0{images}"))[..32]
                ),
                media_path: None,
            }))
        }
        _ => Ok(None),
    }
}

pub(crate) fn login_response(uri: &Uri, method: &Method) -> Response {
    let path = uri.path();
    if is_segment_prefix(path, "/api")
        || is_segment_prefix(path, "/media")
        || is_segment_prefix(path, "/images")
        || is_segment_prefix(path, "/videos")
        || !matches!(*method, Method::GET | Method::HEAD)
    {
        return private_no_store((StatusCode::UNAUTHORIZED, "Login required").into_response());
    }
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    private_no_store(
        Redirect::to(&format!(
            "/user/login?next={}&reason=login_required",
            encode_next(pq)
        ))
        .into_response(),
    )
}

pub(crate) fn is_html_navigation(headers: &HeaderMap) -> bool {
    let mode = headers.get("sec-fetch-mode");
    let dest = headers.get("sec-fetch-dest");
    if mode.is_some() || dest.is_some() {
        mode.is_some_and(|value| value == "navigate")
            || dest.is_some_and(|value| value == "document")
    } else {
        headers
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',').any(|item| {
                    let mut parts = item.split(';').map(str::trim);
                    parts
                        .next()
                        .is_some_and(|mime| mime.eq_ignore_ascii_case("text/html"))
                        && parts
                            .filter_map(|param| param.split_once('='))
                            .filter(|(key, _)| key.trim().eq_ignore_ascii_case("q"))
                            .all(|(_, value)| {
                                value
                                    .trim()
                                    .parse::<f32>()
                                    .is_ok_and(|q| q > 0.0 && q <= 1.0)
                            })
                })
            })
    }
}

const WAKING_INTERSTITIAL_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Waking up · Let&#39;s Embed</title>
<noscript><meta http-equiv="refresh" content="6"></noscript>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: linear-gradient(180deg, #f0f9ff 0%, #ffffff 48%, #e0f2fe 100%);
    color: #334155;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  main {
    width: 100%;
    max-width: 460px;
    background: rgba(255, 255, 255, 0.94);
    border: 1px solid #bae6fd;
    border-radius: 22px;
    padding: 32px 28px;
    box-shadow: 0 12px 36px rgba(14, 165, 233, 0.12);
    text-align: center;
  }
  .brand {
    font-weight: 700;
    font-size: 0.95rem;
    letter-spacing: 0.01em;
    color: #0284c7;
    margin-bottom: 18px;
  }
  .spinner-wrap {
    display: flex;
    justify-content: center;
    margin-bottom: 18px;
  }
  .spinner {
    width: 46px;
    height: 46px;
    border-radius: 50%;
    border: 4px solid #e0f2fe;
    border-top-color: #0284c7;
    border-right-color: #38bdf8;
    animation: le-spin 0.9s linear infinite;
  }
  @keyframes le-spin {
    to { transform: rotate(360deg); }
  }
  h1 {
    margin: 0 0 10px;
    font-size: 1.25rem;
    line-height: 1.3;
    color: #0f172a;
  }
  p.desc {
    margin: 0 0 20px;
    font-size: 0.93rem;
    line-height: 1.55;
    color: #475569;
  }
  .progress-track {
    width: 100%;
    height: 8px;
    border-radius: 999px;
    background: #e0f2fe;
    overflow: hidden;
    margin-bottom: 14px;
  }
  .progress-fill {
    height: 100%;
    width: 12%;
    border-radius: 999px;
    background: linear-gradient(90deg, #38bdf8 0%, #0284c7 100%);
    transition: width 0.6s ease;
  }
  .status-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    font-size: 0.84rem;
    color: #64748b;
    margin-bottom: 20px;
  }
  .status-text {
    text-align: left;
    color: #0369a1;
    font-weight: 500;
  }
  .elapsed {
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .actions {
    display: flex;
    justify-content: center;
  }
  button.retry-btn {
    appearance: none;
    border: 1px solid #7dd3fc;
    background: #f0f9ff;
    color: #0369a1;
    font-weight: 600;
    font-size: 0.88rem;
    padding: 9px 18px;
    border-radius: 999px;
    cursor: pointer;
    transition: background-color 0.15s ease, border-color 0.15s ease, transform 0.1s ease;
  }
  button.retry-btn:hover {
    background: #e0f2fe;
    border-color: #38bdf8;
  }
  button.retry-btn:active {
    transform: translateY(1px);
  }
  .noscript-note {
    margin-top: 14px;
    font-size: 0.82rem;
    color: #64748b;
  }
</style>
</head>
<body>
<main role="status" aria-live="polite">
  <div class="brand">Let&#39;s Embed</div>
  <div class="spinner-wrap" aria-hidden="true"><div class="spinner"></div></div>
  <h1>Waking up the gallery server&#8230;</h1>
  <p class="desc">
    Our serverless backend is starting up from sleep. Cold starts usually take
    15&#8211;25 seconds &#8212; this page will reload automatically as soon as it&#39;s ready.
  </p>
  <div class="progress-track" aria-hidden="true">
    <div id="le-progress" class="progress-fill"></div>
  </div>
  <div class="status-row">
    <span id="le-status" class="status-text">Starting backend instance&#8230;</span>
    <span id="le-elapsed" class="elapsed">0s</span>
  </div>
  <div class="actions">
    <button id="le-retry" class="retry-btn" type="button">Retry now</button>
  </div>
  <noscript>
    <p class="noscript-note">JavaScript is disabled; this page will automatically refresh every 6 seconds.</p>
  </noscript>
</main>
<script>
(function () {
  var startedAt = Date.now();
  var statusEl = document.getElementById('le-status');
  var elapsedEl = document.getElementById('le-elapsed');
  var progressEl = document.getElementById('le-progress');
  var retryBtn = document.getElementById('le-retry');
  var inFlight = false;
  var reloading = false;
  var pollTimer = null;

  function readRetryState() {
    try {
      var raw = sessionStorage.getItem('le_wake_retries');
      if (!raw) return { ts: 0, count: 0 };
      var parsed = JSON.parse(raw);
      if (!parsed || Date.now() - parsed.ts > 60000) return { ts: 0, count: 0 };
      return parsed;
    } catch (_) {
      return { ts: 0, count: 0 };
    }
  }

  function recordReloadAttempt() {
    try {
      var st = readRetryState();
      sessionStorage.setItem('le_wake_retries', JSON.stringify({
        ts: st.ts || Date.now(),
        count: (st.count || 0) + 1
      }));
    } catch (_) {}
  }

  function clearReloadAttempts() {
    try { sessionStorage.removeItem('le_wake_retries'); } catch (_) {}
  }

  function updateClock() {
    if (reloading) return;
    var secs = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    if (elapsedEl) elapsedEl.textContent = secs + 's';
    var pct = Math.min(92, Math.round(12 + 80 * (1 - Math.exp(-secs / 14))));
    if (progressEl) progressEl.style.width = pct + '%';
    if (statusEl) {
      if (secs >= 35) {
        statusEl.textContent = 'Still starting up\u2014hang tight or click Retry now.';
      } else if (secs >= 15) {
        statusEl.textContent = 'Almost ready\u2014finishing initialization\u2026';
      }
    }
  }

  function schedulePoll(ms) {
    if (reloading) return;
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(pollReady, ms);
  }

  function triggerReload() {
    if (reloading) return;
    reloading = true;
    if (pollTimer) clearTimeout(pollTimer);
    if (progressEl) progressEl.style.width = '100%';
    if (statusEl) statusEl.textContent = 'Server is ready! Loading gallery\u2026';
    recordReloadAttempt();
    window.location.reload();
  }

  function pollReady() {
    if (inFlight || reloading) return;
    inFlight = true;
    fetch('/_gw/ready', {
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { 'accept': 'application/json' }
    })
      .then(function (res) {
        if (!res.ok) return null;
        return res.json().catch(function () { return null; });
      })
      .then(function (data) {
        if (data && data.ready === true) {
          var st = readRetryState();
          if (st.count >= 3) {
            if (statusEl) statusEl.textContent = 'Backend is recovering\u2014retrying shortly\u2026';
            schedulePoll(8000);
            return;
          }
          triggerReload();
          return;
        }
        var secs = Math.floor((Date.now() - startedAt) / 1000);
        schedulePoll(secs >= 90 ? 5000 : 2000);
      })
      .catch(function () {
        var secs = Math.floor((Date.now() - startedAt) / 1000);
        schedulePoll(secs >= 90 ? 5000 : 2000);
      })
      .finally(function () {
        inFlight = false;
      });
  }

  if (retryBtn) {
    retryBtn.addEventListener('click', function () {
      clearReloadAttempts();
      triggerReload();
    });
  }

  setInterval(updateClock, 1000);
  updateClock();
  schedulePoll(1500);
})();
</script>
</body>
</html>"#;

/// Self-contained 503 waking interstitial for interactive browser HTML navigations
/// while the serverless GCP Cloud Run backend is cold-starting.
pub(crate) fn waking_interstitial_response() -> Response {
    let mut resp = (StatusCode::SERVICE_UNAVAILABLE, WAKING_INTERSTITIAL_HTML).into_response();
    let h = resp.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(RETRY_AFTER, HeaderValue::from_static("3"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert("x-robots-tag", HeaderValue::from_static("noindex, nofollow"));
    private_no_store(resp)
}

pub(crate) fn payment_required(headers: &HeaderMap, guest: bool) -> Response {
    let navigation = is_html_navigation(headers);
    let response = if navigation {
        let target = if guest {
            format!("{UPGRADE_PATH}?reason=free_limit")
        } else {
            format!("{UPGRADE_PATH}?reason=quota")
        };
        Redirect::to(&target).into_response()
    } else {
        let reason = if guest {
            "Daily free allowance reached — sign in to continue"
        } else {
            "Out of points or quota — top up or wait for window reset"
        };
        (
            StatusCode::PAYMENT_REQUIRED,
            [
                ("location", UPGRADE_PATH),
                ("server-timing", "gallery-allowance"),
            ],
            axum::Json(serde_json::json!({"error": reason, "redirect_to": UPGRADE_PATH})),
        )
            .into_response()
    };
    private_no_store(response)
}

/// Minimal percent-encoding for the `next` query value.
pub(crate) fn encode_next(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '+' => out.push_str("%2B"),
            '?' => out.push_str("%3F"),
            '#' => out.push_str("%23"),
            '&' => out.push_str("%26"),
            _ => out.push(ch),
        }
    }
    out
}

/// Lowercase hex SHA-256 of `s`.
pub(crate) fn sha256_hex(s: &str) -> String {
    site_access::sha256_hex(s.as_bytes())
}

/// Read one `application/x-www-form-urlencoded` field value from a raw body,
/// decoding both field names and values (`+` -> space, `%XX` -> byte).
/// Rejects non-UTF-8 or duplicate matching keys so gateway metering stays
/// aligned with `serde_urlencoded`.
pub(crate) fn form_field(body: &Bytes, key: &str) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    let mut found: Option<String> = None;
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=')?;
        let decoded_k = percent_decode(k)?;
        if decoded_k == key {
            if found.is_some() {
                return None;
            }
            found = Some(percent_decode(v)?);
        }
    }
    found
}

/// Strict `application/x-www-form-urlencoded` component decoder (UTF-8).
pub(crate) fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16)?;
                let lo = (bytes[i + 2] as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b'%' => return None,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Derives the guest Durable Object key from Cloudflare's `CF-Connecting-IP`
/// and `jwt_secret`. Missing IPs share a single fallback key.
pub(crate) fn guest_id(jwt_secret: &[u8], headers: &HeaderMap) -> String {
    let ip = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    ip.map(|ip| site_access::guest_account(jwt_secret, ip))
        .unwrap_or_else(|| "guest:unknown".into())
}

fn is_cf_access_set_cookie_value(val: &HeaderValue) -> bool {
    let Ok(raw) = val.to_str() else {
        return false;
    };
    let Some((name, _)) = raw.split_once('=') else {
        return false;
    };
    let name = name.trim();
    name.eq_ignore_ascii_case("cf_authorization") || name.eq_ignore_ascii_case("cf_appsession")
}

/// Strips Cloudflare Access infrastructure cookies (`CF_Authorization`, `CF_AppSession`)
/// injected by Cloudflare Access on responses from private origins (e.g. `API_UPSTREAM`).
///
/// Prevents leaking the gateway's service-token Access JWT to end users and prevents
/// Cloudflare Access `Set-Cookie` headers from downgrading public-cacheable responses
/// (`/pkg/*`, `/robots.txt`, anonymous `/sitemap*.xml`) to `private, no-store`, while
/// keeping any other unexpected origin `Set-Cookie` headers so the fail-closed cache
/// guard remains active.
pub(crate) fn strip_cf_access_set_cookies(headers: &mut HeaderMap) {
    if !headers.contains_key(SET_COOKIE) {
        return;
    }
    let kept: Vec<HeaderValue> = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter(|val| !is_cf_access_set_cookie_value(val))
        .cloned()
        .collect();
    headers.remove(SET_COOKIE);
    for val in kept {
        headers.append(SET_COOKIE, val);
    }
}

/// Builds a canonical, policy-digest-scoped cache key URL for anonymous XML sitemaps
/// stored in Cloudflare Workers' `caches.default`.
///
/// Keying on canonical path (ignoring arbitrary query strings) and `policy_digest`
/// prevents query-string cache-busting DoS while guaranteeing zero stale-policy windows
/// whenever `SITE_POLICY` changes.
pub(crate) fn build_sitemap_cache_key(
    uri: &Uri,
    headers: &HeaderMap,
    upstreams: &Upstreams,
    policy_digest: &str,
) -> Option<String> {
    let path = uri.path();
    if !is_canonical_path(path)
        || !is_sitemap_path(path)
        || policy_digest.is_empty()
        || !policy_digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let origin = if let Some(host) = request_host(uri, headers) {
        format!("https://{}", host.to_ascii_lowercase())
    } else {
        parse_upstream_origin(upstreams.api.as_str()).ok()?
    };
    let raw = format!("{origin}/__gw_sitemap_cache{path}?pd={policy_digest}");
    let parsed = worker::Url::parse(&raw).ok()?;
    (parsed.scheme() == "https" && parsed.fragment().is_none()).then(|| parsed.to_string())
}

/// Returns `true` iff any `Cache-Control` directive marks the response `public`
/// and no `Cache-Control` header is non-UTF-8 or carries `private` / `no-store`.
pub(crate) fn cache_control_allows_edge_cache(headers: &HeaderMap) -> bool {
    let mut has_public = false;
    for raw in headers.get_all(CACHE_CONTROL) {
        let Ok(val) = raw.to_str() else {
            return false;
        };
        for part in val.split(',') {
            let directive = part.split('=').next().unwrap_or("").trim();
            if directive.eq_ignore_ascii_case("private")
                || directive.eq_ignore_ascii_case("no-store")
            {
                return false;
            }
            if directive.eq_ignore_ascii_case("public") {
                has_public = true;
            }
        }
    }
    has_public
}

/// RFC 9110 weak-comparison `If-None-Match` evaluator matching `lets-embed-web`'s `seo.rs`.
pub(crate) fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    let target = etag.trim().strip_prefix("W/").unwrap_or(etag.trim());
    if target.is_empty() {
        return false;
    }
    headers
        .get_all(IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|inm| {
            inm.split(',').any(|part| {
                let trimmed = part.trim();
                trimmed == "*" || trimmed.strip_prefix("W/").unwrap_or(trimmed) == target
            })
        })
}
