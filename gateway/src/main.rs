#![cfg_attr(
    feature = "validate-jwt",
    feature(iterator_try_collect, duration_constructors)
)]

#[cfg(feature = "validate-jwt")]
mod jwt;

use std::process::ExitCode;

use async_trait::async_trait;
use pingora::prelude::*;
use tracing_subscriber::EnvFilter;

const ADDR: &str = "0.0.0.0:8080";
const IMMUTABLE_PUBLIC_CACHE: &str = "public, max-age=31536000, immutable";
const REVALIDATED_PKG_CACHE: &str =
    "public, max-age=0, s-maxage=300, stale-while-revalidate=60, must-revalidate";

struct Ingress {
    upstream: HttpPeer,
    #[cfg(feature = "validate-jwt")]
    policy_aud: String,
}

#[async_trait]
impl ProxyHttp for Ingress {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(self.upstream.clone()))
    }

    #[cfg(feature = "validate-jwt")]
    #[tracing::instrument(skip_all)]
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let Some(jwt) = session
            .get_header("Cf-Access-Jwt-Assertion")
            .map(|value| value.as_bytes())
        else {
            tracing::info!(reason = "no token", "reject");
            return Ok(true);
        };

        jwt::verify(jwt, &self.policy_aud)
            .map_err(|e| Error::because(ErrorType::HTTPStatus(403), "forbidden", e))?;

        Ok(false)
    }

    #[tracing::instrument(skip_all)]
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let existing_cache_controls: Vec<std::result::Result<&str, ()>> = upstream_response
            .headers
            .get_all(http::header::CACHE_CONTROL)
            .iter()
            .map(|v| v.to_str().map_err(|_| ()))
            .collect();

        let has_set_cookie = upstream_response
            .headers
            .contains_key(http::header::SET_COOKIE);

        let content_type = upstream_response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        let method = &session.req_header().method;
        let status = upstream_response.status;
        let path = session.req_header().uri.path();

        if let Some(value) = decide_cache_control_for_response(
            method,
            status,
            path,
            content_type,
            has_set_cookie,
            &existing_cache_controls,
        ) {
            upstream_response.insert_header(http::header::CACHE_CONTROL, value)?;
        }

        Ok(())
    }
}

/// Returns `true` if any existing `Cache-Control` header is non-UTF-8 (fail closed)
/// or carries any non-empty directive (preserving `private`, `no-store`, `no-cache`,
/// and any explicit upstream `max-age` untouched).
fn should_preserve_existing_cache_control(
    existing: &[std::result::Result<&str, ()>],
) -> bool {
    existing.iter().any(|header| match header {
        Err(()) => true,
        Ok(val) => !val.trim().is_empty(),
    })
}

fn is_sensitive_path(path: &str) -> bool {
    path == "/api"
        || path.starts_with("/api/")
        || path == "/media"
        || path.starts_with("/media/")
        || path == "/user"
        || path.starts_with("/user/")
        || path == "/admin"
        || path.starts_with("/admin/")
        || path == "/images"
        || path.starts_with("/images/")
        || path == "/videos"
        || path.starts_with("/videos/")
}

fn is_pkg_asset_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/pkg/") else {
        return false;
    };
    if rest.is_empty()
        || path
            .chars()
            .any(|c| c.is_control() || matches!(c, '%' | '\\' | '?' | '#'))
    {
        return false;
    }
    !rest
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
}

fn is_allowlisted_pkg_asset_mime(normalized_ct: &str, hashed: bool) -> bool {
    match normalized_ct {
        "application/javascript" | "text/javascript" | "text/css" | "application/wasm" => true,
        t if t.starts_with("font/") => true,
        t if hashed && t.starts_with("image/") => true,
        _ => false,
    }
}

/// Full response-level cache decision helper.
///
/// Security invariants (H2):
/// 1. Only `GET` / `HEAD` requests returning `200 OK` with zero `Set-Cookie` headers
///    are eligible for proxy-injected `Cache-Control`.
/// 2. Any non-UTF-8 or non-empty upstream `Cache-Control` (`private`, `no-store`,
///    `no-cache`, or explicit `max-age`) is ALWAYS preserved untouched.
/// 3. `text/html`, `application/xhtml+xml`, `/api/*`, `/media/*`, `/user/*`,
///    `/admin*`, `/images/*`, and `/videos/*` NEVER receive `public` or `s-maxage`.
/// 4. `public, max-age=31536000, immutable` is applied ONLY to content-hashed
///    allowlisted static assets (`js`/`css`/`wasm`/`font/*`/`image/*`) strictly
///    under `/pkg/*` (rejecting `%`, control chars, `//`, `.`, `..`).
fn decide_cache_control_for_response(
    method: &http::Method,
    status: http::StatusCode,
    path: &str,
    content_type: Option<&str>,
    has_set_cookie: bool,
    existing_cache_controls: &[std::result::Result<&str, ()>],
) -> Option<&'static str> {
    if !matches!(*method, http::Method::GET | http::Method::HEAD) {
        return None;
    }
    if status != http::StatusCode::OK || has_set_cookie {
        return None;
    }
    if should_preserve_existing_cache_control(existing_cache_controls) {
        return None;
    }
    if is_sensitive_path(path) {
        return None;
    }

    let normalized_ct = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    if normalized_ct.is_empty()
        || matches!(normalized_ct.as_str(), "text/html" | "application/xhtml+xml")
    {
        return None;
    }

    if !is_pkg_asset_path(path) {
        return None;
    }

    let hashed = is_content_hashed(path);
    if !is_allowlisted_pkg_asset_mime(&normalized_ct, hashed) {
        return None;
    }

    if hashed {
        Some(IMMUTABLE_PUBLIC_CACHE)
    } else {
        Some(REVALIDATED_PKG_CACHE)
    }
}

fn is_content_hashed(path: &str) -> bool {
    let Some(file) = path.rsplit('/').next() else {
        return false;
    };
    let parts: Vec<&str> = file.split('.').collect();
    parts.len() >= 3
        && parts[parts.len() - 2].len() >= 8
        && parts[parts.len() - 2]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gateway=info,pingora=info".parse().unwrap()),
        )
        .init();

    #[cfg(feature = "validate-jwt")]
    if jwt::keys().is_none() {
        tracing::error!("Failed to get pub keys");
        return ExitCode::FAILURE;
    }

    #[cfg(feature = "validate-jwt")]
    let Ok(policy_aud) = std::env::var("POLICY_AUD") else {
        tracing::error!(env_var = "POLICY_AUD", "Not presented");
        return ExitCode::FAILURE;
    };

    let mut my_server = Server::new(None).unwrap();

    my_server.bootstrap();

    let mut ingress = http_proxy_service(
        &my_server.configuration,
        Ingress {
            upstream: HttpPeer::new("127.0.0.1:3000", false, "".to_string()),
            #[cfg(feature = "validate-jwt")]
            policy_aud,
        },
    );
    ingress.add_tcp(ADDR);
    my_server.add_service(ingress);

    tracing::info!("listening on {ADDR}");
    my_server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decide_ok_get(
        path: &str,
        content_type: Option<&str>,
        existing_cache_controls: &[&str],
    ) -> Option<&'static str> {
        let existing: Vec<std::result::Result<&str, ()>> =
            existing_cache_controls.iter().copied().map(Ok).collect();
        decide_cache_control_for_response(
            &http::Method::GET,
            http::StatusCode::OK,
            path,
            content_type,
            false,
            &existing,
        )
    }

    #[test]
    fn preserves_existing_and_non_utf8_cache_control_untouched() {
        assert_eq!(
            decide_ok_get("/", Some("text/html; charset=utf-8"), &["private, no-store"]),
            None
        );
        assert_eq!(
            decide_ok_get(
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                &["private, no-store"]
            ),
            None
        );
        assert_eq!(
            decide_ok_get(
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                &["no-cache, must-revalidate"]
            ),
            None
        );
        assert_eq!(
            decide_ok_get(
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                &["max-age=60"]
            ),
            None
        );
        // Non-UTF-8 Cache-Control fails closed
        assert_eq!(
            decide_cache_control_for_response(
                &http::Method::GET,
                http::StatusCode::OK,
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                false,
                &[Err(())],
            ),
            None
        );
    }

    #[test]
    fn gates_on_method_status_and_set_cookie() {
        // Non-200 error responses under /pkg/* must never be cached as immutable
        for status in [
            http::StatusCode::FORBIDDEN,
            http::StatusCode::NOT_FOUND,
            http::StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert_eq!(
                decide_cache_control_for_response(
                    &http::Method::GET,
                    status,
                    "/pkg/app.deadbeef01.js",
                    Some("application/javascript"),
                    false,
                    &[],
                ),
                None
            );
        }

        // POST / PUT must never get public cache headers
        assert_eq!(
            decide_cache_control_for_response(
                &http::Method::POST,
                http::StatusCode::OK,
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                false,
                &[],
            ),
            None
        );

        // Set-Cookie must never be publicly cached
        assert_eq!(
            decide_cache_control_for_response(
                &http::Method::GET,
                http::StatusCode::OK,
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                true,
                &[],
            ),
            None
        );

        // HEAD 200 without Set-Cookie IS eligible for hashed /pkg/* static asset
        assert_eq!(
            decide_cache_control_for_response(
                &http::Method::HEAD,
                http::StatusCode::OK,
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                false,
                &[],
            ),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
    }

    #[test]
    fn never_injects_public_or_s_maxage_on_html_xhtml_api_media_non_allowlisted_or_traversals() {
        // HTML and XHTML
        assert_eq!(decide_ok_get("/", Some("text/html"), &[]), None);
        assert_eq!(
            decide_ok_get("/details/42", Some("text/html; charset=utf-8"), &[]),
            None
        );
        assert_eq!(
            decide_ok_get("/pkg/index.deadbeef01.html", Some("text/html"), &[]),
            None
        );
        assert_eq!(
            decide_ok_get(
                "/pkg/index.deadbeef01.xhtml",
                Some("application/xhtml+xml"),
                &[]
            ),
            None
        );

        // Arbitrary MIME types on hashed /pkg/* paths are NOT allowlisted
        assert_eq!(
            decide_ok_get(
                "/pkg/data.deadbeef01.json",
                Some("application/json"),
                &[]
            ),
            None
        );
        assert_eq!(
            decide_ok_get("/pkg/info.deadbeef01.txt", Some("text/plain"), &[]),
            None
        );

        // API & media paths
        assert_eq!(
            decide_ok_get("/api/fetch_posts", Some("application/json"), &[]),
            None
        );
        assert_eq!(
            decide_ok_get("/media/image/42", Some("image/webp"), &[]),
            None
        );
        assert_eq!(
            decide_ok_get("/media/preview/42", Some("image/webp"), &[]),
            None
        );

        // Non-hashed images & images outside /pkg/
        assert_eq!(
            decide_ok_get("/images/album/pic.webp", Some("image/webp"), &[]),
            None
        );
        assert_eq!(
            decide_ok_get("/images/pic.12345678.webp", Some("image/webp"), &[]),
            None
        );
        assert_eq!(decide_ok_get("/avatar.png", Some("image/png"), &[]), None);
        assert_eq!(decide_ok_get("/pkg/logo.png", Some("image/png"), &[]), None);

        // Percent-encoding, traversal, empty segment, and control-char tricks under /pkg/
        assert_eq!(
            decide_ok_get(
                "/pkg/%2e%2e/images/pic.12345678.webp",
                Some("image/webp"),
                &[]
            ),
            None
        );
        assert_eq!(
            decide_ok_get(
                "/pkg/../images/pic.a1b2c3d4.webp",
                Some("image/webp"),
                &[]
            ),
            None
        );
        assert_eq!(
            decide_ok_get("/pkg//app.a1b2c3d4.js", Some("application/javascript"), &[]),
            None
        );
        assert_eq!(
            decide_ok_get(
                "/pkg/app\x00.a1b2c3d4.js",
                Some("application/javascript"),
                &[]
            ),
            None
        );
    }

    #[test]
    fn applies_immutable_public_cache_only_to_content_hashed_pkg_assets() {
        assert_eq!(
            decide_ok_get(
                "/pkg/lets-embed-web.a1b2c3d4.js",
                Some("application/javascript; charset=utf-8"),
                &[]
            ),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
        assert_eq!(
            decide_ok_get(
                "/pkg/lets-embed-web.a1b2c3d4.wasm",
                Some("application/wasm"),
                &[]
            ),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
        assert_eq!(
            decide_ok_get("/pkg/lets-embed-web.a1b2c3d4.css", Some("text/css"), &[]),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
        assert_eq!(
            decide_ok_get(
                "/pkg/placeholder.a1b2c3d4.svg",
                Some("image/svg+xml"),
                &[]
            ),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
        assert_eq!(
            decide_ok_get("/pkg/inter.a1b2c3d4.woff2", Some("font/woff2"), &[]),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
    }
}
