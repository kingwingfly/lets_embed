//! Pure HTTP routing, canonicalization, header/cookie sanitization, CSRF,
//! metering validation, and response helpers.

use axum::{
    body::Bytes,
    http::{
        HeaderMap, Method, StatusCode, Uri,
        header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE},
    },
    response::{IntoResponse, Redirect, Response},
};
use site_access::{
    ADMIN_VIEW_COOKIE, ChargeKind, ChargeReq, GUEST_SESSION_COOKIE, STRIPPED_ORIGIN_COOKIES,
    UPGRADE_PATH, is_privileged_request_header,
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
    response
        .headers_mut()
        .insert(CACHE_CONTROL, "private, no-store".parse().unwrap());
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

/// Strips admin, Cloudflare Access, and guest-reveal cookies before forwarding to
/// `USER_WORKER` while preserving `ue_session` and `__Host-auth_tx`.
pub(crate) fn sanitize_user_worker_cookie(headers: &HeaderMap) -> Option<String> {
    let mut kept = Vec::new();
    for raw in headers.get_all("cookie").iter().filter_map(|v| v.to_str().ok()) {
        for cookie in raw.split(';').map(str::trim).filter(|c| !c.is_empty()) {
            let name = cookie.split('=').next().unwrap_or("").trim();
            if name != ADMIN_VIEW_COOKIE
                && name != GUEST_SESSION_COOKIE
                && name != "CF_Authorization"
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
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-forwarded-proto")
        || name.eq_ignore_ascii_case("forwarded")
        || name.eq_ignore_ascii_case("cf-ipcountry")
        || name.eq_ignore_ascii_case("x-internal-api-secret")
        || is_privileged_request_header(name)
}

/// Percent-decode a single RFC 3986 path segment into raw bytes (preserving `+`
/// literally). Malformed `%` escapes return `None`.
pub(crate) fn percent_decode_segment_bytes(seg: &str) -> Option<Vec<u8>> {
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
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
            let q = form_field(body, "q").ok_or(MeterError::BadRequest)?;
            let trimmed = q.trim();
            let id: i64 = trimmed.parse().map_err(|_| MeterError::BadRequest)?;
            if id <= 0 {
                return Err(MeterError::BadRequest);
            }
            Ok(Some(ChargeReq {
                kind: ChargeKind::EmbedSearch,
                path: format!("search:sim:{}", &sha256_hex(trimmed)[..32]),
            }))
        }
        "/api/search_by_image" => {
            if body.len() > MAX_IMAGE_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let image = form_field(body, "image")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::Search,
                path: format!("search:img:{}", &sha256_hex(&image)[..32]),
            }))
        }
        "/api/search_by_desc" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let q = form_field(body, "q").ok_or(MeterError::BadRequest)?;
            let trimmed = q.trim();
            if trimmed.is_empty() || q.len() > 2000 {
                return Err(MeterError::BadRequest);
            }
            Ok(Some(ChargeReq {
                kind: ChargeKind::Description,
                path: format!("search:desc:{}", &sha256_hex(trimmed)[..32]),
            }))
        }
        "/api/search_advanced" => Ok(None),
        "/api/search_advanced_embed" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let q = form_field(body, "q")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::EmbedSearch,
                path: format!("search:adv_embed:{}", &sha256_hex(&q)[..32]),
            }))
        }
        "/api/search_advanced_clip" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let q = form_field(body, "q")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::Description,
                path: format!("search:adv_clip:{}", &sha256_hex(&q)[..32]),
            }))
        }
        "/api/search_advanced_image" => {
            if body.len() > MAX_GATEWAY_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
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
    private_no_store(Redirect::to(&format!("/user/login?next={}", encode_next(pq))).into_response())
}

pub(crate) fn payment_required(headers: &HeaderMap, guest: bool) -> Response {
    let mode = headers.get("sec-fetch-mode");
    let dest = headers.get("sec-fetch-dest");
    let navigation = if mode.is_some() || dest.is_some() {
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
    };
    let response = if navigation {
        Redirect::to(UPGRADE_PATH).into_response()
    } else {
        let reason = if guest {
            "Free access does not cover this item"
        } else {
            "out of points"
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
