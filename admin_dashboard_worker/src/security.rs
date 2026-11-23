//! Zero-bypass admin authentication guard, strict CSRF validation, security headers,
//! OIDC SSRF URL defense, and ISO-3166 geo code validation.
//!
//! All logic here is pure Rust so it is exhaustively tested on the host.

use axum::{
    Json,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use site_access::{
    ADMIN_ASSERTION_AUDIENCE, ADMIN_ASSERTION_HEADER, ADMIN_CSRF_HEADER, ADMIN_HEADER,
    GATEWAY_ASSERTION_DEFAULT_MAX_SKEW, GeoPolicy, verify_admin_assertion,
};
use url::{Host, Url};

use crate::api::ApiError;

/// Strict CSP for the `/admin` SPA and API responses:
/// - No inline scripts (`script-src 'self' 'wasm-unsafe-eval'` for WASM instantiation only)
/// - No framing (`frame-ancestors 'none'`)
/// - No external origins (`default-src 'self'`, `connect-src 'self'`)
pub const ADMIN_CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

pub const ADMIN_CACHE_CONTROL: &str = "private, no-store";
pub const ADMIN_ROBOTS_TAG: &str = "noindex, nofollow";

/// Applies mandatory zero-cache, noindex, framing, MIME-sniffing, and CSP headers
/// to every response emitted by `admin_dashboard_worker`.
pub fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(ADMIN_CACHE_CONTROL),
    );
    headers.insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static(ADMIN_ROBOTS_TAG),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(ADMIN_CSP),
    );
}

/// Constructs a hardened JSON error response with all admin security headers applied.
pub fn json_error(status: StatusCode, msg: impl Into<String>) -> Response {
    let mut resp = (status, Json(ApiError { error: msg.into() })).into_response();
    apply_security_headers(resp.headers_mut());
    resp
}

pub fn forbidden(msg: impl Into<String>) -> Response {
    json_error(StatusCode::FORBIDDEN, msg)
}

/// Returns the single header value for `name`, rejecting duplicate headers to
/// prevent header-smuggling ambiguity.
fn single_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut iter = headers.get_all(name).iter();
    let Some(first) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

/// Verifies the privileged `gallery_admin == true` binding prop AND non-empty
/// `x-gallery-admin-email` forwarded by `gateway_worker` after Cloudflare Access checks.
pub fn require_admin_identity(admin_binding: bool, headers: &HeaderMap) -> Option<&str> {
    if !admin_binding {
        return None;
    }
    let raw = single_header_str(headers, ADMIN_HEADER).ok()??;
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 320
        || trimmed.chars().any(char::is_control)
        || trimmed != raw
    {
        return None;
    }
    Some(trimmed)
}

/// Verifies an incoming request to `admin_dashboard_worker` at Step 0 (BEFORE routing or
/// `ASSETS.fetch`).
///
/// Cloudflare Workers with `[assets]` route service bindings through an internal assets
/// router hop that drops `ctx.props`. When `admin_assertion_secret` is configured (required
/// in production `wrangler.toml`), authorization is proven cryptographically via the
/// short-lived HMAC-signed `X-Gallery-Admin-Assertion` header matching `X-Gallery-Admin-Email`.
/// When `admin_assertion_secret` is `None` (host unit tests), falls back to the privileged
/// `admin_binding` prop check.
pub fn verify_admin_request<'a>(
    admin_binding: bool,
    admin_assertion_secret: Option<&[u8]>,
    headers: &'a HeaderMap,
    now_secs: u64,
) -> Option<&'a str> {
    let email = single_header_str(headers, ADMIN_HEADER).ok()??;
    let trimmed = email.trim();
    if trimmed.is_empty()
        || trimmed.len() > 320
        || trimmed.chars().any(char::is_control)
        || trimmed != email
    {
        return None;
    }
    if let Some(secret) = admin_assertion_secret {
        let token = single_header_str(headers, ADMIN_ASSERTION_HEADER).ok()??;
        let claims = verify_admin_assertion(
            token,
            secret,
            ADMIN_ASSERTION_AUDIENCE,
            now_secs,
            GATEWAY_ASSERTION_DEFAULT_MAX_SKEW,
        )
        .ok()?;
        if claims.email != trimmed {
            return None;
        }
        return Some(trimmed);
    }
    admin_binding.then_some(trimmed)
}

/// Returns `true` for HTTP methods that mutate state and require full CSRF verification.
pub fn is_mutation_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Derives allowed canonical origins for `/admin/api/*` CSRF validation.
///
/// - When `admin_domain` (`ADMIN_DOMAIN`) is configured and non-empty (split-host
///   deployments), ONLY `https://{ADMIN_DOMAIN}` (plus `http://{ADMIN_DOMAIN}` when
///   targeting `localhost` or `127.0.0.1`) is trusted; `PUBLIC_URL` and `SIWE_DOMAIN`
///   are intentionally NOT trusted as admin mutation origins.
/// - Otherwise (single-host deployments), falls back to `PUBLIC_URL` and `SIWE_DOMAIN`.
pub fn allowed_origins(
    admin_domain: Option<&str>,
    public_url: Option<&str>,
    siwe_domain: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_unique = |origin: String| {
        if !out
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(&origin))
        {
            out.push(origin);
        }
    };

    if let Some(domain) = admin_domain.map(str::trim).filter(|s| !s.is_empty()) {
        push_unique(format!("https://{domain}"));
        let host_only = domain.split(':').next().unwrap_or("");
        if is_local_dev_host(host_only) {
            push_unique(format!("http://{domain}"));
        }
        return out;
    }

    if let Some(raw_url) = public_url.map(str::trim).filter(|s| !s.is_empty())
        && let Ok(parsed) = Url::parse(raw_url)
        && let Some(host) = parsed.host_str()
    {
        let scheme = parsed.scheme();
        let is_local = is_local_dev_host(host);
        if scheme.eq_ignore_ascii_case("https")
            || (scheme.eq_ignore_ascii_case("http") && is_local)
        {
            let origin = format_origin(scheme, host, parsed.port());
            push_unique(origin);
        }
    }

    let domain = siwe_domain.trim();
    if !domain.is_empty() {
        push_unique(format!("https://{domain}"));
        let host_only = domain.split(':').next().unwrap_or("");
        if is_local_dev_host(host_only) {
            push_unique(format!("http://{domain}"));
        }
    }

    out
}

fn is_local_dev_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1"
}

fn format_origin(scheme: &str, host: &str, port: Option<u16>) -> String {
    let default_port = match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };
    match port {
        Some(p) if Some(p) != default_port => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    }
}

/// Validates every CSRF invariant required on admin mutations (`POST`/`PUT`/`PATCH`/`DELETE`):
/// 1. `gallery_admin == true` binding prop + non-empty `ADMIN_HEADER`
/// 2. Exact `Origin` matching configured `ADMIN_DOMAIN` (when set) or `PUBLIC_URL` / `https://{SIWE_DOMAIN}` (plus local dev `http://localhost` / `http://127.0.0.1` when configured)
/// 3. `Sec-Fetch-Site: same-origin` (if the header is present)
/// 4. Custom header `X-Admin-CSRF: 1` (`site_access::ADMIN_CSRF_HEADER`)
pub fn verify_admin_mutation<'a>(
    admin_binding: bool,
    headers: &'a HeaderMap,
    admin_domain: Option<&str>,
    public_url: Option<&str>,
    siwe_domain: &str,
) -> Result<&'a str, &'static str> {
    let admin = require_admin_identity(admin_binding, headers)
        .ok_or("Administrator access required")?;

    let csrf_val = single_header_str(headers, ADMIN_CSRF_HEADER)
        .map_err(|()| "Invalid or duplicate X-Admin-CSRF header")?
        .map(str::trim);
    if csrf_val != Some("1") {
        return Err("Missing or invalid X-Admin-CSRF header");
    }

    if let Some(val) = single_header_str(headers, "sec-fetch-site")
        .map_err(|()| "Invalid or duplicate Sec-Fetch-Site header")?
        && !val.trim().eq_ignore_ascii_case("same-origin")
    {
        return Err("Cross-site Sec-Fetch-Site rejected");
    }

    let origin = single_header_str(headers, header::ORIGIN.as_str())
        .map_err(|()| "Invalid or duplicate Origin header")?
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("null"))
        .ok_or("Missing Origin header")?;

    let allowed = allowed_origins(admin_domain, public_url, siwe_domain);
    if allowed.is_empty() || !allowed.iter().any(|a| a.eq_ignore_ascii_case(origin)) {
        return Err("Cross-origin request rejected");
    }

    Ok(admin)
}

/// Validates an OIDC issuer / discovery / endpoint URL against SSRF rules:
/// - Strict `https://` scheme only
/// - No userinfo (`user:pass@`), no query string, no fragment
/// - Rejects all IPv4 and IPv6 literals (including hex/decimal/mapped forms)
/// - Rejects localhost, loopback, single-label internal hostnames, and private/internal TLDs
/// - Allows standard HTTPS port (`443` / implicit) only
/// - Rejects control characters and path traversal segments (`..`)
pub fn validate_oidc_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("OIDC URL cannot be empty".into());
    }
    if trimmed.len() > 512 {
        return Err("OIDC URL exceeds maximum length of 512 characters".into());
    }
    if trimmed.chars().any(char::is_control) {
        return Err("OIDC URL contains control characters".into());
    }
    if trimmed.contains('\\') || trimmed.contains('%') {
        return Err("OIDC URL must not contain backslashes or percent-encoding".into());
    }
    if trimmed
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
        && let Some((_, raw_path)) = trimmed[8..].split_once('/')
        && raw_path.split('/').any(|seg| seg == "." || seg == "..")
    {
        return Err("OIDC URL path contains invalid traversal segments".into());
    }

    let parsed = Url::parse(trimmed).map_err(|e| format!("Invalid OIDC URL: {e}"))?;

    if parsed.scheme() != "https" {
        return Err("OIDC URL must use https://".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("OIDC URL must not contain userinfo credentials".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("OIDC URL must not contain query parameters or fragments".into());
    }
    if let Some(port) = parsed.port()
        && port != 443
    {
        return Err("OIDC URL must use standard HTTPS port 443".into());
    }

    let host = match parsed.host() {
        Some(Host::Domain(domain)) => domain,
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => {
            return Err("OIDC URL must use a public hostname, not an IP literal".into());
        }
        None => return Err("OIDC URL is missing a host".into()),
    };

    let host_clean = host.trim_end_matches('.').to_ascii_lowercase();
    if host_clean.is_empty() || !host_clean.contains('.') {
        return Err("OIDC URL host must be a fully-qualified public domain".into());
    }
    if is_disallowed_internal_host(&host_clean) {
        return Err(format!(
            "OIDC URL host '{host_clean}' is a private/local domain and is not allowed"
        ));
    }

    // Reject path traversal segments or backslashes.
    if parsed.path().contains('\\')
        || parsed
            .path()
            .split('/')
            .any(|seg| seg == "." || seg == "..")
    {
        return Err("OIDC URL path contains invalid traversal segments".into());
    }

    // Normalize by trimming trailing slash when path is non-root, or keep clean canonical form.
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn is_disallowed_internal_host(host: &str) -> bool {
    const EXACT: &[&str] = &[
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
        "instance-data",
    ];
    const SUFFIXES: &[&str] = &[
        ".localhost",
        ".local",
        ".localdomain",
        ".internal",
        ".home.arpa",
        ".lan",
        ".corp",
        ".intranet",
        ".private",
        ".test",
        ".invalid",
    ];
    EXACT.contains(&host) || SUFFIXES.iter().any(|s| host.ends_with(s))
}

/// Validates and canonically normalizes a [`GeoPolicy`] (uppercase deduplicated
/// ISO-3166 alpha-2 country codes, rejecting `"XX"` and `"T1"` inside `blocked_countries`).
pub fn validate_and_normalize_geo(geo: &GeoPolicy) -> Result<GeoPolicy, String> {
    let mut normalized: Vec<String> = Vec::with_capacity(geo.blocked_countries.len());
    for raw in &geo.blocked_countries {
        let code = raw.trim().to_ascii_uppercase();
        if code.is_empty() {
            continue;
        }
        if code == "XX" {
            return Err("Use the 'Block unknown country (XX)' toggle instead of listing XX".into());
        }
        if code == "T1" {
            return Err("Use the 'Block Tor exit nodes (T1)' toggle instead of listing T1".into());
        }
        if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(format!(
                "Invalid ISO-3166 alpha-2 country code '{raw}' (expected 2 letters like US, GB, JP)"
            ));
        }
        if !normalized.contains(&code) {
            normalized.push(code);
        }
    }
    if normalized.len() > 260 {
        return Err("Too many blocked country codes".into());
    }
    normalized.sort();
    Ok(GeoPolicy {
        blocked_countries: normalized,
        block_unknown: geo.block_unknown,
        block_tor: geo.block_tor,
    })
}

/// Validates that a static asset request path under `/admin` is clean and safe to map
/// to the `ASSETS` binding. Returns the normalized asset path starting with `/`.
pub fn map_admin_asset_path(req_path: &str) -> Option<String> {
    if req_path.contains('\\')
        || req_path.contains('%')
        || req_path.contains('?')
        || req_path.contains('#')
        || req_path.chars().any(char::is_control)
    {
        return None;
    }
    let rest = if req_path == "/admin" || req_path == "/admin/" {
        ""
    } else {
        req_path.strip_prefix("/admin/")?
    };

    if rest.is_empty() {
        return Some("/index.html".to_string());
    }
    if rest.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
        return None;
    }
    // Serve known static files directly; SPA sub-routes without file extensions map to index.html.
    if rest.contains('.') {
        Some(format!("/{rest}"))
    } else {
        Some("/index.html".to_string())
    }
}
