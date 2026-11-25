//! Leptos CSR SPA shell & static asset serving for `/user/*` (plus retired
//! `/user/admin*` 404 handler per H13).
//!
//! All `/user/*` HTML views are rendered client-side by the Leptos CSR SPA
//! (`user_worker/web/`, built into `user_worker/assets/` and served via
//! Cloudflare Workers Static Assets `[assets]` binding `ASSETS` with
//! `run_worker_first = true`).

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use tower_cookies::Cookies;

use crate::{AppState, identity};

const ROBOTS_HEADER: HeaderName = HeaderName::from_static("x-robots-tag");
const NO_STORE: &str = "private, no-store";
const NO_INDEX: &str = "noindex, nofollow";

/// Strict CSP allowing same-origin ES modules, Leptos CSR WASM instantiation
/// (`'wasm-unsafe-eval'`), and optional Telegram Login Widget frames/scripts.
const SPA_CSP: &str = concat!(
    "default-src 'self'; ",
    "script-src 'self' 'wasm-unsafe-eval' https://telegram.org; ",
    "style-src 'self' 'unsafe-inline'; ",
    "img-src 'self' data: blob: https:; ",
    "media-src 'self' blob:; ",
    "connect-src 'self' https:; ",
    "frame-src https://oauth.telegram.org; ",
    "frame-ancestors 'none'; ",
    "base-uri 'self'; ",
    "object-src 'none'"
);

/// Minimal SPA HTML shell fallback if the `ASSETS` binding is unavailable.
const FALLBACK_SPA_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <meta name="robots" content="noindex, nofollow">
  <title>Account — Let’s Embed</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>💠</text></svg>">
  <script src="/user/assets/wallet-bridge.js" defer></script>
  <script type="module" src="/user/assets/boot.js"></script>
</head>
<body>
  <div id="user-app-root"><noscript>JavaScript is required for account management.</noscript></div>
</body>
</html>
"#;

fn apply_html_security_headers(resp: &mut Response) {
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    h.insert(ROBOTS_HEADER, HeaderValue::from_static(NO_INDEX));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(SPA_CSP),
    );
}

fn redirect_no_store(location: &str) -> Response {
    let mut resp = (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response();
    apply_html_security_headers(&mut resp);
    resp
}

/// Sanitize a relative static asset path under `/user/assets/{*path}`.
/// Enforces an explicit non-HTML static extension allowlist so `index.html` can
/// NEVER be served via `/user/assets/index.html` without CSP / `X-Frame-Options`
/// / `Referrer-Policy` headers (Cycle 3 H6).
pub fn sanitize_asset_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start_matches('/');
    if trimmed.is_empty()
        || trimmed.len() > 256
        || trimmed.contains('\\')
        || trimmed.contains('%')
        || trimmed.contains('\0')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.chars().any(char::is_control)
    {
        return None;
    }
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
    }
    let lower = trimmed.to_ascii_lowercase();
    let allowed_ext = [
        ".js", ".mjs", ".wasm", ".css", ".svg", ".png", ".ico", ".webp", ".woff2",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext));
    if !allowed_ext {
        return None;
    }
    Some(trimmed.to_string())
}

async fn serve_spa_shell(st: &AppState) -> Response {
    if let Ok(assets) = st.env.assets(crate::ASSETS_BINDING)
        && let Ok(http_resp) = assets.fetch("https://assets.local/index.html", None).await
        && http_resp.status() == StatusCode::OK
    {
        let mut resp: Response = http_resp.map(Body::new);
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        apply_html_security_headers(&mut resp);
        return resp;
    }
    let mut resp = Html(FALLBACK_SPA_HTML).into_response();
    apply_html_security_headers(&mut resp);
    resp
}

/// Retired `/user/admin*` handler (H13): admin lives exclusively in `admin_dashboard_worker`.
#[worker::send]
pub async fn admin_retired() -> Response {
    let mut resp = (StatusCode::NOT_FOUND, "Not Found").into_response();
    apply_html_security_headers(&mut resp);
    resp
}

#[worker::send]
pub async fn login_page(State(st): State<AppState>) -> Response {
    serve_spa_shell(&st).await
}

#[worker::send]
pub async fn approve_page(State(st): State<AppState>) -> Response {
    serve_spa_shell(&st).await
}

#[worker::send]
pub async fn upgrade_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    if identity::optional_active_session(&st, &cookies)
        .await
        .is_some()
    {
        return redirect_no_store("/user/account#topup");
    }
    serve_spa_shell(&st).await
}

#[worker::send]
pub async fn account_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    if identity::optional_active_session(&st, &cookies)
        .await
        .is_none()
    {
        return redirect_no_store("/user/login?next=/user/account");
    }
    serve_spa_shell(&st).await
}

#[worker::send]
pub async fn favorites_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    if identity::optional_active_session(&st, &cookies)
        .await
        .is_none()
    {
        return redirect_no_store("/user/login?next=/user/favorites");
    }
    serve_spa_shell(&st).await
}

/// Serve compiled Leptos CSR SPA assets (`/user/assets/pkg/*`, `/user/assets/wallet-bridge.js`, etc.)
/// via the Workers Static Assets `ASSETS` binding.
#[worker::send]
pub async fn serve_asset(
    State(st): State<AppState>,
    Path(rel_path): Path<String>,
) -> Response {
    let Some(clean) = sanitize_asset_path(&rel_path) else {
        let mut resp = (StatusCode::BAD_REQUEST, "Invalid asset path").into_response();
        apply_html_security_headers(&mut resp);
        return resp;
    };
    let Ok(assets) = st.env.assets(crate::ASSETS_BINDING) else {
        let mut resp = (StatusCode::NOT_FOUND, "Assets unavailable").into_response();
        apply_html_security_headers(&mut resp);
        return resp;
    };
    let url = format!("https://assets.local/{clean}");
    match assets.fetch(url, None).await {
        Ok(http_resp) => {
            if http_resp.status().is_redirection() {
                let mut resp = (StatusCode::BAD_GATEWAY, "Unexpected asset redirect").into_response();
                apply_html_security_headers(&mut resp);
                return resp;
            }
            let mut resp: Response = http_resp.map(Body::new);
            let is_ok = resp.status() == StatusCode::OK;
            let h = resp.headers_mut();
            h.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            h.insert(ROBOTS_HEADER, HeaderValue::from_static(NO_INDEX));
            if is_ok {
                h.insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=300"),
                );
                if clean.ends_with(".wasm") {
                    h.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/wasm"),
                    );
                } else if clean.ends_with(".js") || clean.ends_with(".mjs") {
                    h.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/javascript; charset=utf-8"),
                    );
                } else if clean.ends_with(".css") {
                    h.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("text/css; charset=utf-8"),
                    );
                }
            } else {
                h.insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
            }
            resp
        }
        Err(e) => {
            worker::console_error!("ASSETS fetch failed for {clean}: {e:?}");
            let mut resp = (StatusCode::NOT_FOUND, "Not Found").into_response();
            apply_html_security_headers(&mut resp);
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_asset_path_rejects_traversal_and_accepts_bundle_files() {
        assert_eq!(
            sanitize_asset_path("pkg/user_worker_web.js").as_deref(),
            Some("pkg/user_worker_web.js")
        );
        assert_eq!(
            sanitize_asset_path("/pkg/user_worker_web_bg.wasm").as_deref(),
            Some("pkg/user_worker_web_bg.wasm")
        );
        assert_eq!(
            sanitize_asset_path("wallet-bridge.js").as_deref(),
            Some("wallet-bridge.js")
        );
        assert_eq!(
            sanitize_asset_path("boot.js").as_deref(),
            Some("boot.js")
        );
        for bad in [
            "",
            "/",
            "../secret",
            "pkg/../../etc/passwd",
            "pkg/%2e%2e/index.html",
            "pkg/a%20b.js",
            "pkg\\foo.js",
            "pkg/a?b=1",
            "pkg/a\0.js",
            "index.html",
            "/index.html",
            "foo/bar.htm",
            "INDEX.HTML",
        ] {
            assert!(sanitize_asset_path(bad).is_none(), "expected rejection for {bad}");
        }
        // SPA shell must use external module boot script (no inline script blocked by CSP)
        assert!(FALLBACK_SPA_HTML.contains(r#"src="/user/assets/boot.js""#));
        assert!(!FALLBACK_SPA_HTML.contains("<script type=\"module\">\n"));
    }

    #[test]
    fn admin_retired_returns_404_no_store_and_noindex() {
        let rt = futures::executor::block_on(admin_retired());
        assert_eq!(rt.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            rt.headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("private, no-store")
        );
        assert_eq!(
            rt.headers()
                .get("x-robots-tag")
                .and_then(|v| v.to_str().ok()),
            Some("noindex, nofollow")
        );
    }
}
