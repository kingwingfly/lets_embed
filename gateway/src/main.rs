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
        let existing_cache_controls: Vec<&str> = upstream_response
            .headers
            .get_all(http::header::CACHE_CONTROL)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();

        let content_type = upstream_response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        let path = session.req_header().uri.path();

        if let Some(value) = decide_cache_control(path, content_type, &existing_cache_controls) {
            upstream_response.insert_header(http::header::CACHE_CONTROL, value)?;
        }

        Ok(())
    }
}

/// Returns `true` if any existing `Cache-Control` directive marks the response
/// as `private`, `no-store`, or `no-cache`.
fn has_protective_cache_control(existing: &[&str]) -> bool {
    existing.iter().any(|header| {
        header.split(',').any(|raw| {
            let directive = raw
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            matches!(directive.as_str(), "private" | "no-store" | "no-cache")
        })
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
    path.starts_with("/pkg/")
        && !path.contains('\\')
        && !path.split('/').any(|seg| seg == "." || seg == "..")
}

/// Decides whether Pingora should inject a `Cache-Control` header, or return
/// `None` to leave the upstream response's caching semantics untouched.
///
/// Security invariants (H2):
/// 1. Any upstream `Cache-Control` carrying `private`, `no-store`, or `no-cache`
///    is ALWAYS preserved untouched.
/// 2. `text/html`, `/api/*`, `/media/*`, `/user/*`, `/admin*`, `/images/*`, and
///    `/videos/*` NEVER receive `public` or `s-maxage`.
/// 3. `public, max-age=31536000, immutable` is applied ONLY to content-hashed
///    non-HTML assets under `/pkg/*` (never blindly to all `image/*`).
fn decide_cache_control(
    path: &str,
    content_type: Option<&str>,
    existing_cache_controls: &[&str],
) -> Option<&'static str> {
    if has_protective_cache_control(existing_cache_controls) {
        return None;
    }

    if is_sensitive_path(path) {
        return None;
    }

    let normalized_ct = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    if normalized_ct.is_empty() || normalized_ct == "text/html" {
        return None;
    }

    if !is_pkg_asset_path(path) {
        return None;
    }

    if is_content_hashed(path) {
        return Some(IMMUTABLE_PUBLIC_CACHE);
    }

    if existing_cache_controls.is_empty() {
        match normalized_ct.as_str() {
            "application/javascript" | "text/javascript" | "text/css" | "application/wasm" => {
                Some(REVALIDATED_PKG_CACHE)
            }
            t if t.starts_with("font/") => Some(REVALIDATED_PKG_CACHE),
            _ => None,
        }
    } else {
        None
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

    #[test]
    fn preserves_private_no_store_and_no_cache_responses_untouched() {
        // Private/no-store HTML is never overwritten
        assert_eq!(
            decide_cache_control("/", Some("text/html; charset=utf-8"), &["private, no-store"]),
            None
        );
        // Even a hashed /pkg/* path with protective upstream headers is never overwritten
        assert_eq!(
            decide_cache_control(
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                &["private, no-store"]
            ),
            None
        );
        assert_eq!(
            decide_cache_control(
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                &["no-cache, must-revalidate"]
            ),
            None
        );
        assert_eq!(
            decide_cache_control(
                "/pkg/app.deadbeef01.js",
                Some("application/javascript"),
                &["max-age=60", "Private=\"Set-Cookie\""]
            ),
            None
        );
    }

    #[test]
    fn never_injects_public_or_s_maxage_on_html_api_media_or_non_hashed_images() {
        // Unlabelled HTML
        assert_eq!(decide_cache_control("/", Some("text/html"), &[]), None);
        assert_eq!(
            decide_cache_control("/details/42", Some("text/html; charset=utf-8"), &[]),
            None
        );
        // Hashed-looking HTML even under /pkg/
        assert_eq!(
            decide_cache_control("/pkg/index.deadbeef01.html", Some("text/html"), &[]),
            None
        );

        // API & media paths
        assert_eq!(
            decide_cache_control("/api/fetch_posts", Some("application/json"), &[]),
            None
        );
        assert_eq!(
            decide_cache_control("/media/image/42", Some("image/webp"), &[]),
            None
        );
        assert_eq!(
            decide_cache_control("/media/preview/42", Some("image/webp"), &[]),
            None
        );

        // Non-hashed images & images outside /pkg/ (even if filename looks hashed)
        assert_eq!(
            decide_cache_control("/images/album/pic.webp", Some("image/webp"), &[]),
            None
        );
        assert_eq!(
            decide_cache_control("/images/pic.12345678.webp", Some("image/webp"), &[]),
            None
        );
        assert_eq!(
            decide_cache_control("/avatar.png", Some("image/png"), &[]),
            None
        );
        assert_eq!(
            decide_cache_control("/pkg/logo.png", Some("image/png"), &[]),
            None
        );
    }

    #[test]
    fn applies_immutable_public_cache_only_to_content_hashed_pkg_assets() {
        assert_eq!(
            decide_cache_control(
                "/pkg/lets-embed-web.a1b2c3d4.js",
                Some("application/javascript; charset=utf-8"),
                &[]
            ),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
        assert_eq!(
            decide_cache_control(
                "/pkg/lets-embed-web.a1b2c3d4.wasm",
                Some("application/wasm"),
                &[]
            ),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
        assert_eq!(
            decide_cache_control(
                "/pkg/lets-embed-web.a1b2c3d4.css",
                Some("text/css"),
                &[]
            ),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
        assert_eq!(
            decide_cache_control(
                "/pkg/placeholder.a1b2c3d4.svg",
                Some("image/svg+xml"),
                &[]
            ),
            Some(IMMUTABLE_PUBLIC_CACHE)
        );
        // Traversal out of /pkg/ must be rejected
        assert_eq!(
            decide_cache_control(
                "/pkg/../images/pic.a1b2c3d4.webp",
                Some("image/webp"),
                &[]
            ),
            None
        );
    }
}
