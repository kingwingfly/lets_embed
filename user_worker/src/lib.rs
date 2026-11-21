#![allow(clippy::result_large_err)]

//! user_worker — SIWE user system for lets_embed.

pub mod account_do;
pub mod admin;
pub mod auth;
pub mod config;
mod dashboard;
pub mod do_client;
pub mod likes;
pub mod pages;
pub mod payments;
pub mod rates;
pub mod session;
pub mod settings;
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
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct BindingProps {
    gallery_admin: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub env: Arc<Env>,
    pub jwt_secret: Arc<Vec<u8>>,
    pub siwe_domain: Arc<String>,
    pub chain_id: u64,
    pub rpc_url: Arc<String>,
    pub sol_rpc_url: Arc<String>,
    pub admin_binding: bool,
}

async fn router(env: Env, ctx: Context) -> Result<Router> {
    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let siwe_domain = env.var("SIWE_DOMAIN")?.to_string();
    let chain_id = env
        .var("CHAIN_ID")?
        .to_string()
        .parse::<u64>()
        .map_err(|e| Error::RustError(format!("bad CHAIN_ID: {e}")))?;
    let rpc_url = env.var("RPC_URL")?.to_string();
    let sol_rpc_url = env.var("SOL_RPC_URL")?.to_string();

    let state = AppState {
        admin_binding: ctx
            .props::<BindingProps>()
            .unwrap_or_default()
            .gallery_admin,
        env: Arc::new(env),
        jwt_secret: Arc::new(jwt_secret.into_bytes()),
        siwe_domain: Arc::new(siwe_domain),
        chain_id,
        rpc_url: Arc::new(rpc_url),
        sol_rpc_url: Arc::new(sol_rpc_url),
    };

    Ok(Router::new()
        // Pages
        .route("/user/login", get(pages::login_page))
        .route(site_access::UPGRADE_PATH, get(pages::upgrade_page))
        .route("/user/account", get(pages::account_page))
        .route("/user/favorites", get(pages::favorites_page))
        // Auth (SIWE)
        .route("/user/api/nonce", get(auth::nonce))
        .route("/user/api/verify", post(auth::verify))
        .route("/user/api/verify_solana", post(auth::verify_solana))
        .route("/user/api/logout", post(auth::logout))
        .route("/user/api/me", get(auth::me))
        // Payments / subscription
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
        // Admin (Cloudflare Access protected)
        .route("/user/admin", get(admin::admin_page))
        .route("/user/admin/settings", post(admin::save_settings))
        .route("/user/admin/plan", post(admin::set_plan))
        .route("/user/admin/credit", post(admin::credit))
        .route("/user/admin/ban", post(admin::ban))
        .layer(CookieManagerLayer::new())
        .with_state(state))
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, ctx: Context) -> Result<axum::response::Response> {
    Ok(router(env, ctx).await?.call(req).await?)
}
