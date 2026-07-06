#![allow(clippy::result_large_err)]

//! user_worker — SIWE user system for lets_embed.
//!
//! FROZEN SCAFFOLD: this file (plus `config.rs`, `types.rs`, `session.rs`,
//! `do_client.rs`) is the shared contract between the parallel work units.
//! Do not change routes, `AppState`, or module boundaries — implement the
//! stub handlers inside the module files instead.

pub mod account_do;
pub mod admin;
pub mod auth;
pub mod config;
pub mod do_client;
pub mod likes;
pub mod pages;
pub mod payments;
pub mod rates;
pub mod session;
pub mod siwe;
pub mod solana;
pub mod solana_link;
pub mod types;

pub use account_do::UserAccount;

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use tower_cookies::CookieManagerLayer;
use tower_service::Service;
use worker::{Context, Env, Error, HttpRequest, Result, event};

pub const D1_BINDING: &str = "DB";
pub const NONCE_BINDING: &str = "NONCES";
pub const JWKS_BINDING: &str = "JWKS_CACHE";
pub const JWKS_KEY: &str = "cf-access-jwks";
pub const JWKS_TTL: u64 = 3600;

#[derive(Clone)]
pub struct AppState {
    pub env: Arc<Env>,
    pub jwt_secret: Arc<Vec<u8>>,
    pub siwe_domain: Arc<String>,
    pub chain_id: u64,
    pub rpc_url: Arc<String>,
    /// lowercase 0x-prefixed Ethereum deposit address for top-ups
    pub deposit_address: Arc<String>,
    /// Solana JSON-RPC endpoint used to verify SOL / SPL top-ups
    pub sol_rpc_url: Arc<String>,
    /// base58 Solana deposit address for top-ups
    pub sol_deposit_address: Arc<String>,
    pub team_domain: Arc<String>,
    pub access_aud: Arc<String>,
}

async fn secret(env: &Env, name: &str) -> Result<String> {
    env.secret_store(name)?
        .get()
        .await?
        .ok_or_else(|| Error::BindingError(format!("`{name}` not provided")))
}

async fn router(env: Env, _ctx: Context) -> Result<Router> {
    let jwt_secret = secret(&env, "lets-embed-jwt-secret").await?;
    let siwe_domain = env.var("SIWE_DOMAIN")?.to_string();
    let chain_id = env
        .var("CHAIN_ID")?
        .to_string()
        .parse::<u64>()
        .map_err(|e| Error::RustError(format!("bad CHAIN_ID: {e}")))?;
    let rpc_url = env.var("RPC_URL")?.to_string();
    let deposit_address = env.var("DEPOSIT_ADDRESS")?.to_string().to_lowercase();
    let sol_rpc_url = env.var("SOL_RPC_URL")?.to_string();
    let sol_deposit_address = env.var("SOL_DEPOSIT_ADDRESS")?.to_string();
    let team_domain = env.var("CF_ACCESS_TEAM_DOMAIN")?.to_string();
    let access_aud = env.var("CF_ACCESS_AUD")?.to_string();

    let state = AppState {
        env: Arc::new(env),
        jwt_secret: Arc::new(jwt_secret.into_bytes()),
        siwe_domain: Arc::new(siwe_domain),
        chain_id,
        rpc_url: Arc::new(rpc_url),
        deposit_address: Arc::new(deposit_address),
        sol_rpc_url: Arc::new(sol_rpc_url),
        sol_deposit_address: Arc::new(sol_deposit_address),
        team_domain: Arc::new(team_domain),
        access_aud: Arc::new(access_aud),
    };

    Ok(Router::new()
        // Pages
        .route("/user/login", get(pages::login_page))
        .route("/user/account", get(pages::account_page))
        .route("/user/favorites", get(pages::favorites_page))
        // Auth (SIWE)
        .route("/user/api/nonce", get(auth::nonce))
        .route("/user/api/verify", post(auth::verify))
        .route("/user/api/logout", post(auth::logout))
        .route("/user/api/me", get(auth::me))
        // Payments / subscription
        .route("/user/api/topup", post(payments::topup))
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
        // Admin (Cloudflare Access protected)
        .route("/user/admin", get(admin::admin_page))
        .route("/user/admin/credit", post(admin::credit))
        .route("/user/admin/ban", post(admin::ban))
        .layer(CookieManagerLayer::new())
        .with_state(state))
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, ctx: Context) -> Result<axum::response::Response> {
    Ok(router(env, ctx).await?.call(req).await?)
}
