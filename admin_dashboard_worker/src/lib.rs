#![allow(clippy::result_large_err)]

//! Standalone `admin_dashboard_worker` (`/admin` SPA + `/admin/api/*`).
//!
//! Security boundary (H13):
//! - `wrangler.toml` enforces `workers_dev = false`, `preview_urls = false`, and
//!   `[assets] run_worker_first = true`.
//! - EVERY incoming request (static assets AND API endpoints) MUST pass the
//!   privileged `gallery_admin == true` binding prop check + non-empty
//!   `site_access::ADMIN_HEADER` BEFORE static assets or handlers execute.
//! - EVERY mutating request (`POST`/`PUT`/`PATCH`/`DELETE`) under `/admin/api/*`
//!   MUST pass exact `Origin`, `Sec-Fetch-Site: same-origin` (if present), and
//!   `X-Admin-CSRF: 1`.
//! - EVERY response carries `Cache-Control: private, no-store`,
//!   `X-Robots-Tag: noindex, nofollow`, `X-Content-Type-Options: nosniff`,
//!   `X-Frame-Options: DENY`, and strict `Content-Security-Policy`.

pub mod api;
pub mod crypto;
pub mod do_client;
pub mod handlers;
pub mod security;
pub mod settings;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use axum::{
    Router,
    http::{Method, StatusCode},
    response::Response,
    routing::{get, post},
};
use tower_service::Service;
use worker::{Context, Env, Error, HttpRequest, RequestInit, Result, event};

use crate::{
    crypto::KeyRing,
    security::{
        apply_security_headers, forbidden, is_mutation_method, json_error, map_admin_asset_path,
        verify_admin_mutation, verify_admin_request,
    },
};

pub const D1_BINDING: &str = "DB";
pub const ASSETS_BINDING: &str = "ASSETS";

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct BindingProps {
    gallery_admin: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub env: Arc<Env>,
    pub admin_binding: bool,
    pub admin_domain: Option<Arc<String>>,
    pub siwe_domain: Arc<String>,
    pub public_url: Option<Arc<String>>,
    pub deployment_id: Arc<String>,
    pub keyring: Arc<KeyRing>,
}

fn build_state(env: Env, admin_binding: bool) -> Result<AppState> {
    let admin_domain = env
        .var("ADMIN_DOMAIN")
        .ok()
        .map(|v| v.to_string().trim().to_string())
        .filter(|s| !s.is_empty())
        .map(Arc::new);
    let siwe_domain = env
        .var("SIWE_DOMAIN")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let public_url = env
        .var("PUBLIC_URL")
        .ok()
        .map(|v| v.to_string().trim().to_string())
        .filter(|s| !s.is_empty())
        .map(Arc::new);
    let deployment_id = env
        .var("DEPLOYMENT_ID")
        .ok()
        .map(|v| v.to_string().trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let d = siwe_domain.trim();
            (!d.is_empty()).then(|| d.to_string())
        })
        .unwrap_or_else(|| "default".to_string());

    let enc_key_raw = env
        .secret("SETTINGS_ENCRYPTION_KEY")
        .map_err(|_| Error::RustError("SETTINGS_ENCRYPTION_KEY secret is required".into()))?
        .to_string();
    let prev_key_raw = env
        .secret("SETTINGS_ENCRYPTION_KEY_PREV")
        .ok()
        .map(|s| s.to_string());

    let keyring = KeyRing::from_env_strings(&enc_key_raw, prev_key_raw.as_deref())
        .map_err(|e| Error::RustError(format!("invalid SETTINGS_ENCRYPTION_KEY: {e}")))?;

    Ok(AppState {
        env: Arc::new(env),
        admin_binding,
        admin_domain,
        siwe_domain: Arc::new(siwe_domain),
        public_url,
        deployment_id: Arc::new(deployment_id),
        keyring: Arc::new(keyring),
    })
}

fn api_router(state: AppState) -> Router {
    Router::new()
        .route("/admin/api/overview", get(handlers::overview::get_overview))
        .route(
            "/admin/api/settings/access",
            post(handlers::overview::save_access_settings),
        )
        .route("/admin/api/accounts", get(handlers::accounts::list_accounts))
        .route(
            "/admin/api/accounts/plan",
            post(handlers::accounts::set_account_plan),
        )
        .route(
            "/admin/api/accounts/credit",
            post(handlers::accounts::credit_account),
        )
        .route(
            "/admin/api/accounts/ban",
            post(handlers::accounts::ban_account),
        )
        .route("/admin/api/payments", get(handlers::accounts::list_payments))
        .route(
            "/admin/api/safety",
            get(handlers::safety::get_safety).post(handlers::safety::save_safety),
        )
        .route(
            "/admin/api/providers",
            get(handlers::providers::get_providers).post(handlers::providers::save_providers),
        )
        .route(
            "/admin/api/secrets/rotate",
            post(handlers::providers::rotate_secrets),
        )
        .route("/admin/api/reports", get(handlers::reports::list_reports))
        .route(
            "/admin/api/reports/{id}/resolve",
            post(handlers::reports::resolve_report),
        )
        .with_state(state)
}

async fn serve_static_asset(env: &Env, method: &Method, req_path: &str) -> Response {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return json_error(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed");
    }

    let Some(asset_path) = map_admin_asset_path(req_path) else {
        return json_error(StatusCode::NOT_FOUND, "Not found");
    };

    let assets = match env.assets(ASSETS_BINDING) {
        Ok(a) => a,
        Err(e) => {
            worker::console_error!("ASSETS binding missing: {e:?}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Admin assets unavailable");
        }
    };

    let mut init = RequestInit::new();
    init.with_method(if *method == Method::HEAD {
        worker::Method::Head
    } else {
        worker::Method::Get
    });

    let url = format!("https://assets.invalid{asset_path}");
    let asset_http_resp = match assets.fetch(url, Some(init)).await {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("ASSETS fetch failed for {asset_path}: {e:?}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load admin asset");
        }
    };

    let worker_resp: worker::Response = match asset_http_resp.try_into() {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("ASSETS response conversion failed: {e:?}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to serve admin asset");
        }
    };

    let mut resp: Response = worker_resp.into();
    if resp.status().is_redirection() {
        worker::console_error!(
            "ASSETS binding returned unexpected redirect {} for {asset_path} (ensure html_handling = \"none\")",
            resp.status()
        );
        return json_error(StatusCode::BAD_GATEWAY, "Unexpected static asset redirect");
    }
    apply_security_headers(resp.headers_mut());
    resp
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, ctx: Context) -> Result<Response> {
    // STEP 0 — ZERO-BYPASS AUTH GUARD BEFORE ANY ROUTING OR STATIC ASSET ACCESS (H13).
    // Verify HMAC-signed `X-Gallery-Admin-Assertion` using dedicated `ADMIN_ASSERTION_SECRET`
    // (survives Cloudflare's `[assets]` router hop where `ctx.props` is dropped).
    let admin_assertion_secret = match env.secret("ADMIN_ASSERTION_SECRET") {
        Ok(s) => {
            let bytes = s.to_string().into_bytes();
            if bytes.is_empty() {
                worker::console_error!("ADMIN_ASSERTION_SECRET is empty");
                return Ok(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Admin dashboard misconfigured",
                ));
            }
            bytes
        }
        Err(_) => {
            worker::console_error!("ADMIN_ASSERTION_SECRET secret is missing");
            return Ok(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Admin dashboard misconfigured",
            ));
        }
    };
    let admin_binding_prop = ctx
        .props::<BindingProps>()
        .unwrap_or_default()
        .gallery_admin;
    let now_secs = worker::Date::now().as_millis() / 1000;
    if verify_admin_request(
        admin_binding_prop,
        Some(&admin_assertion_secret),
        req.headers(),
        now_secs,
    )
    .is_none()
    {
        return Ok(forbidden("Administrator access required"));
    }
    // Cryptographic gateway assertion verified above.
    let admin_binding = true;

    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // API routes under /admin/api/*
    if path == "/admin/api" || path.starts_with("/admin/api/") {
        let state = match build_state(env, admin_binding) {
            Ok(s) => s,
            Err(e) => {
                worker::console_error!("admin worker init failed: {e:?}");
                return Ok(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Admin dashboard misconfigured",
                ));
            }
        };

        // Defense-in-depth CSRF check at router boundary for EVERY mutation method.
        if is_mutation_method(&method)
            && let Err(msg) = verify_admin_mutation(
                state.admin_binding,
                req.headers(),
                state.admin_domain.as_deref().map(String::as_str),
                state.public_url.as_deref().map(String::as_str),
                &state.siwe_domain,
            )
        {
            return Ok(forbidden(msg));
        }

        let mut resp = api_router(state)
            .call(req)
            .await
            .map_err(|e| Error::RustError(format!("router error: {e}")))?;
        apply_security_headers(resp.headers_mut());
        return Ok(resp);
    }

    // Protected static SPA assets under /admin and /admin/*
    if path == "/admin" || path.starts_with("/admin/") {
        return Ok(serve_static_asset(&env, &method, &path).await);
    }

    Ok(json_error(StatusCode::NOT_FOUND, "Not found"))
}
