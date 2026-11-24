#![allow(clippy::result_large_err)]

//! Standalone `admin_dashboard_worker` (`/admin` SPA + `/admin/api/*`).
//!
//! Security boundary (H13 + Policy v3 AdminAssertion v2):
//! - `wrangler.toml` enforces `workers_dev = false`, `preview_urls = false`, and
//!   `[assets] run_worker_first = true`.
//! - EVERY incoming request (static assets AND API endpoints) MUST pass Step-0
//!   `AdminAssertion` v2 (`aa2.`) verification binding `{ v: 2, aud, email, m, p, bh, jti, exp }`
//!   via `ADMIN_ASSERTION_SECRET` or HKDF(`SITE_SECRET`, `KeyDomain::AdminAssertion`).
//! - EVERY mutating request (`POST`/`PUT`/`PATCH`/`DELETE`) atomically consumes `jti`
//!   in D1 `admin_assertion_nonces` (rejecting replays) AND verifies exact `Origin`,
//!   `Sec-Fetch-Site: same-origin` (if present), and `X-Admin-CSRF: 1`.
//! - Verified [`AdminIdentity`] is passed explicitly into every API handler via Axum `Extension`.
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
    body::{Body, to_bytes},
    http::{Method, Request as AxumRequest, StatusCode},
    response::Response,
    routing::{get, post},
};
use site_access::{GATEWAY_ASSERTION_DEFAULT_MAX_SKEW, sha256_hex};
use tower_service::Service;
use worker::{Context, Env, Error, HttpRequest, RequestInit, Result, event};

use crate::{
    crypto::KeyRing,
    security::{
        MAX_ADMIN_BODY_BYTES, apply_security_headers, canonical_request_target, forbidden,
        is_mutation_method, json_error, map_admin_asset_path, resolve_admin_assertion_secret,
        verify_admin_mutation, verify_admin_request_with_body_hash,
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

impl AppState {
    /// Returns the canonical public origin used for OAuth callbacks and email links
    /// (`PUBLIC_URL` if configured, else `https://{SIWE_DOMAIN}`, else empty).
    pub fn public_origin(&self) -> String {
        if let Some(url) = self.public_url.as_deref() {
            let trimmed = url.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        let domain = self.siwe_domain.trim();
        if !domain.is_empty() {
            return format!("https://{domain}");
        }
        String::new()
    }
}

fn optional_secret(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|s| s.to_string())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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

    let provider_key = optional_secret(&env, "PROVIDER_SECRETS_KEY");
    let legacy_key = optional_secret(&env, "SETTINGS_ENCRYPTION_KEY");
    let site_secret = optional_secret(&env, "SITE_SECRET");
    let prev_provider_key = optional_secret(&env, "PROVIDER_SECRETS_KEY_PREV");
    let prev_legacy_key = optional_secret(&env, "SETTINGS_ENCRYPTION_KEY_PREV");
    let prev_site_secret = optional_secret(&env, "SITE_SECRET_PREV");

    let keyring = KeyRing::from_resolved_env(
        provider_key.as_deref(),
        legacy_key.as_deref(),
        site_secret.as_deref(),
        prev_provider_key.as_deref(),
        prev_legacy_key.as_deref(),
        prev_site_secret.as_deref(),
    )
    .map_err(|e| Error::RustError(format!("invalid provider encryption key: {e}")))?;

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
            "/admin/api/policy/retry-activation",
            post(handlers::safety::retry_policy_activation),
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

/// Atomically consumes a single-use `AdminAssertion` v2 `jti` nonce in D1
/// `admin_assertion_nonces` and opportunistically prunes expired rows.
///
/// Returns `Ok(true)` if the nonce was newly inserted (`changes == 1`),
/// `Ok(false)` if this `jti` was already consumed (replay!).
async fn consume_admin_assertion_nonce(
    env: &Env,
    jti: &str,
    expires_at: u64,
    now_secs: u64,
) -> Result<bool> {
    let db = env.d1(D1_BINDING)?;
    let insert_stmt = db
        .prepare("INSERT OR IGNORE INTO admin_assertion_nonces (jti, expires_at) VALUES (?, ?)")
        .bind(&[jti.into(), (expires_at as f64).into()])?;
    let prune_before = now_secs.saturating_sub(5);
    let prune_stmt = db
        .prepare("DELETE FROM admin_assertion_nonces WHERE expires_at < ?")
        .bind(&[(prune_before as f64).into()])?;

    let results = db.batch(vec![insert_stmt, prune_stmt]).await?;
    let inserted = results
        .first()
        .and_then(|r| r.meta().ok().flatten())
        .and_then(|m| m.changes)
        == Some(1);
    Ok(inserted)
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
    // STEP 0 — ZERO-BYPASS ADMIN ASSERTION v2 (`aa2.`) GUARD BEFORE ROUTING OR ASSETS.
    // Resolve AdminAssertion key via explicit `ADMIN_ASSERTION_SECRET` or HKDF(`SITE_SECRET`).
    let explicit_admin_secret = optional_secret(&env, "ADMIN_ASSERTION_SECRET");
    let site_secret = optional_secret(&env, "SITE_SECRET");
    let admin_assertion_secret = match resolve_admin_assertion_secret(
        explicit_admin_secret.as_deref(),
        site_secret.as_deref(),
    ) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) | Err(_) => {
            worker::console_error!(
                "AdminAssertion secret missing: configure SITE_SECRET or ADMIN_ASSERTION_SECRET"
            );
            return Ok(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Admin dashboard misconfigured",
            ));
        }
    };

    // Read request body within bounded limit so we can verify exact `bh` SHA-256 digest.
    let (mut parts, body) = req.into_parts();
    let body_bytes = match to_bytes(Body::new(body), MAX_ADMIN_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(e) => {
            worker::console_error!("Failed to read admin request body within limit: {e:?}");
            return Ok(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request body exceeds maximum allowed size",
            ));
        }
    };

    let admin_binding_prop = ctx
        .props::<BindingProps>()
        .unwrap_or_default()
        .gallery_admin;
    let now_secs = worker::Date::now().as_millis() / 1000;
    let method = parts.method.clone();
    let canonical_target = canonical_request_target(&parts.uri);
    let body_sha256 = sha256_hex(&body_bytes);

    let Some(verified) = verify_admin_request_with_body_hash(
        admin_binding_prop,
        Some(&admin_assertion_secret),
        &parts.headers,
        method.as_str(),
        &canonical_target,
        &body_sha256,
        now_secs,
    ) else {
        return Ok(forbidden("Administrator access required"));
    };

    // Single-use D1 `jti` replay protection on ALL mutating methods.
    if is_mutation_method(&method) {
        let (Some(jti), Some(exp)) = (verified.jti.as_deref(), verified.exp) else {
            return Ok(forbidden("Admin assertion replay nonce missing"));
        };
        let expires_at = exp.saturating_add(GATEWAY_ASSERTION_DEFAULT_MAX_SKEW);
        match consume_admin_assertion_nonce(&env, jti, expires_at, now_secs).await {
            Ok(true) => {}
            Ok(false) => {
                worker::console_warn!(
                    "Rejected replayed AdminAssertion jti for {}",
                    verified.identity.email
                );
                return Ok(forbidden("Replayed admin assertion rejected"));
            }
            Err(e) => {
                worker::console_error!("admin_assertion_nonces replay check failed: {e:?}");
                return Ok(json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Replay protection unavailable",
                ));
            }
        }
    }

    // Cryptographic gateway assertion verified above.
    let admin_binding = true;
    let path = parts.uri.path().to_string();

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
                &parts.headers,
                state.admin_domain.as_deref().map(String::as_str),
                state.public_url.as_deref().map(String::as_str),
                &state.siwe_domain,
            )
        {
            return Ok(forbidden(msg));
        }

        // Explicitly pass verified AdminIdentity into every handler.
        parts.extensions.insert(verified.identity);
        let axum_req = AxumRequest::from_parts(parts, Body::from(body_bytes));

        let mut resp = api_router(state)
            .call(axum_req)
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
