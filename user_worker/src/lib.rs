#![allow(clippy::result_large_err)]

//! `user_worker` — Unified multi-provider auth, revocable `v2` sessions,
//! safety preferences, Terms acceptance, content reports, crypto billing,
//! Durable Objects (`UserAccount`, `AuthChallengeDO`, `SitePolicyDO`), and
//! Leptos CSR SPA shell for `/user/*`.

pub mod account_do;
pub mod auth;
pub mod challenge_do;
pub mod config;
pub mod do_client;
pub mod handoff;
pub mod identity;
pub mod likes;
pub mod pages;
pub mod payments;
pub mod policy_do;
pub mod providers;
pub mod qr;
pub mod rates;
pub mod safety_api;
pub mod secrets;
pub mod session;
pub mod settings;
pub mod siwe;
pub mod solana;
pub mod solana_link;
pub mod types;

pub use account_do::UserAccount;
pub use challenge_do::AuthChallengeDO;
pub use policy_do::SitePolicyDO;

use std::sync::Arc;

use axum::{
    Router,
    routing::{any, delete, get, post},
};
use tower_cookies::CookieManagerLayer;
use tower_service::Service;
use worker::{Context, Env, Error, HttpRequest, Result, event};

pub const D1_BINDING: &str = "DB";
pub const ASSETS_BINDING: &str = "ASSETS";

#[derive(Clone)]
pub struct AppState {
    pub env: Arc<Env>,
    pub jwt_secret: Arc<Vec<u8>>,
    pub session_v2_secret: Arc<Vec<u8>>,
    pub siwe_domain: Arc<String>,
    pub public_url: Arc<String>,
    pub deployment_id: Arc<String>,
    pub chain_id: u64,
    pub rpc_url: Arc<String>,
    pub sol_rpc_url: Arc<String>,
}

impl AppState {
    /// Pinned canonical external origin (e.g. `https://gallery.example.com`)
    /// derived strictly from `PUBLIC_URL` (fallback `https://{SIWE_DOMAIN}`) — never
    /// from untrusted `Host` / `X-Forwarded-Host` request headers (L2).
    pub fn public_origin(&self) -> &str {
        self.public_url.trim_end_matches('/')
    }
}

fn normalize_public_url(raw: Option<String>, siwe_domain: &str) -> String {
    if let Some(u) = raw.map(|s| s.trim().trim_end_matches('/').to_string())
        && !u.is_empty()
    {
        return u;
    }
    if siwe_domain.starts_with("http://") || siwe_domain.starts_with("https://") {
        siwe_domain.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", siwe_domain.trim_end_matches('/'))
    }
}

async fn router(env: Env, _ctx: Context) -> Result<Router> {
    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    if jwt_secret.trim().is_empty() {
        return Err(Error::RustError("JWT_SECRET must not be empty".into()));
    }
    let session_v2_secret = env
        .secret("SESSION_V2_SECRET")
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| jwt_secret.clone());
    let siwe_domain = env.var("SIWE_DOMAIN")?.to_string();
    let public_url = normalize_public_url(
        env.var("PUBLIC_URL").ok().map(|v| v.to_string()),
        &siwe_domain,
    );
    let deployment_id = env
        .var("DEPLOYMENT_ID")
        .ok()
        .map(|v| v.to_string())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| siwe_domain.clone());
    let chain_id = env
        .var("CHAIN_ID")?
        .to_string()
        .parse::<u64>()
        .map_err(|e| Error::RustError(format!("bad CHAIN_ID: {e}")))?;
    let rpc_url = env.var("RPC_URL")?.to_string();
    let sol_rpc_url = env.var("SOL_RPC_URL")?.to_string();

    let state = AppState {
        env: Arc::new(env),
        jwt_secret: Arc::new(jwt_secret.into_bytes()),
        session_v2_secret: Arc::new(session_v2_secret.into_bytes()),
        siwe_domain: Arc::new(siwe_domain),
        public_url: Arc::new(public_url),
        deployment_id: Arc::new(deployment_id),
        chain_id,
        rpc_url: Arc::new(rpc_url),
        sol_rpc_url: Arc::new(sol_rpc_url),
    };

    Ok(Router::new()
        // Retired Admin routes (H13): admin lives exclusively in `admin_dashboard_worker`.
        .route("/user/admin", any(pages::admin_retired))
        .route("/user/admin/{*rest}", any(pages::admin_retired))
        // Leptos CSR SPA routes & Static Assets
        .route("/user/login", get(pages::login_page))
        .route("/user/login/approve", get(pages::approve_page))
        .route(site_access::UPGRADE_PATH, get(pages::upgrade_page))
        .route("/user/account", get(pages::account_page))
        .route("/user/favorites", get(pages::favorites_page))
        .route("/user/assets/{*path}", get(pages::serve_asset))
        // Pluggable Multi-Provider Auth (OAuth2, OIDC Age Assurance, Email OTP, Telegram)
        .route("/user/auth/email/start", post(providers::email::start))
        .route("/user/auth/email/verify", post(providers::email::verify))
        .route("/user/auth/telegram/verify", post(providers::telegram::verify))
        .route("/user/auth/{provider}/start", get(providers::oauth::start))
        .route(
            "/user/auth/{provider}/callback",
            get(providers::oauth::callback),
        )
        // Wallet Auth (SIWE / SIWS / cross-device QR & wallet handoff / transfer)
        .route("/user/api/nonce", get(auth::nonce))
        .route("/user/api/verify", post(auth::verify))
        .route("/user/api/verify_solana", post(auth::verify_solana))
        .route("/user/api/handoff/start", post(handoff::start))
        .route("/user/api/handoff/info", get(handoff::info))
        .route("/user/api/handoff/approve_eth", post(handoff::approve_eth))
        .route("/user/api/handoff/approve_sol", post(handoff::approve_sol))
        .route("/user/api/handoff/poll", post(handoff::poll))
        .route("/user/api/transfer/create", post(handoff::transfer_create))
        .route("/user/api/transfer/claim", post(handoff::transfer_claim))
        .route("/user/api/transfer/revoke", post(handoff::transfer_revoke))
        .route("/user/api/logout", post(auth::logout))
        .route("/user/api/me", get(auth::me))
        // Public Policy, Safety Preferences, Terms, Content Reports & Identity Linking
        .route("/user/api/policy", get(safety_api::get_policy))
        .route("/user/api/bootstrap", get(safety_api::bootstrap))
        .route("/user/api/preferences", post(safety_api::update_preferences))
        .route("/user/api/accept_terms", post(safety_api::accept_terms))
        .route("/user/api/reports", post(safety_api::create_report))
        .route("/user/api/report", post(safety_api::create_report))
        .route("/user/api/identities", delete(safety_api::identity_unlink))
        .route(
            "/user/api/identities/link/start",
            post(safety_api::identity_link_start),
        )
        .route(
            "/user/api/identities/link/wallet",
            post(safety_api::identity_link_wallet),
        )
        .route(
            "/user/api/sessions/revoke_all",
            post(safety_api::revoke_all_sessions),
        )
        // Payments / subscriptions / wallet linking
        .route("/user/api/topup", post(payments::topup))
        .route("/user/api/topup/prepare", post(payments::prepare))
        .route("/user/api/payments", get(payments::list_payments))
        .route("/user/api/subscribe", post(payments::subscribe))
        .route("/user/api/unsubscribe", post(payments::unsubscribe))
        .route("/user/api/rates", get(rates::rates))
        .route(
            "/user/api/link_solana",
            get(solana_link::link_status)
                .post(solana_link::link)
                .delete(solana_link::unlink),
        )
        // Likes
        .route(
            "/user/api/like",
            get(likes::liked).post(likes::like).delete(likes::unlike),
        )
        .route("/user/api/likes", get(likes::list))
        .route("/user/api/likes/status", get(likes::status_batch))
        .layer(CookieManagerLayer::new())
        .with_state(state))
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, ctx: Context) -> Result<axum::response::Response> {
    Ok(router(env, ctx).await?.call(req).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_public_url_prefers_explicit_var_and_trims_trailing_slash() {
        assert_eq!(
            normalize_public_url(Some("https://gallery.example.com/".into()), "ignored.com"),
            "https://gallery.example.com"
        );
        assert_eq!(
            normalize_public_url(None, "gallery.example.com"),
            "https://gallery.example.com"
        );
        assert_eq!(
            normalize_public_url(Some("   ".into()), "http://localhost:8787/"),
            "http://localhost:8787"
        );
    }
}
