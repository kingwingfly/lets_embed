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
use site_access::{KeyDomain, resolve_domain_secret};
use subtle::ConstantTimeEq;
use tower_cookies::CookieManagerLayer;
use tower_service::Service;
use worker::{Context, Env, Error, HttpRequest, Result, event};

pub const D1_BINDING: &str = "DB";
pub const ASSETS_BINDING: &str = "ASSETS";

#[derive(Clone)]
pub struct AppState {
    pub env: Arc<Env>,
    /// Optional legacy HS256 wallet session secret (for backwards-compatible cookie cutover only).
    pub legacy_jwt_secret: Option<Arc<Vec<u8>>>,
    /// Active revocable `v2.` session & auth-HMAC secret (resolved via `SESSION_SECRET` /
    /// `SESSION_V2_SECRET` override or `SITE_SECRET` HKDF `KeyDomain::Session`).
    pub session_v2_secret: Arc<Vec<u8>>,
    /// Internal worker-to-worker API secret (resolved via `INTERNAL_API_SECRET` override or
    /// `SITE_SECRET` HKDF `KeyDomain::InternalApi`).
    pub internal_api_secret: Option<Arc<Vec<u8>>>,
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

/// Pure, host-testable secret resolution for `user_worker` via `site_access::kdf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUserSecrets {
    pub session_secret: String,
    pub internal_api_secret: Option<String>,
    pub legacy_jwt_secret: Option<String>,
}

fn non_empty(val: Option<&str>) -> Option<&str> {
    val.map(str::trim).filter(|s| !s.is_empty())
}

/// Resolves `user_worker` runtime secrets from `SITE_SECRET` via RFC 5869 HKDF-SHA256
/// while honoring explicit overrides (`SESSION_SECRET`, `SESSION_V2_SECRET`,
/// `INTERNAL_API_SECRET`, and legacy `JWT_SECRET`).
pub fn resolve_user_secrets(
    site_secret: Option<&str>,
    session_secret_override: Option<&str>,
    legacy_session_v2_override: Option<&str>,
    legacy_jwt_secret: Option<&str>,
    internal_api_override: Option<&str>,
) -> std::result::Result<ResolvedUserSecrets, &'static str> {
    let explicit_session =
        non_empty(session_secret_override).or_else(|| non_empty(legacy_session_v2_override));
    let master = non_empty(site_secret);
    let legacy_jwt = non_empty(legacy_jwt_secret).map(str::to_string);

    let session_secret = match resolve_domain_secret(explicit_session, master, KeyDomain::Session) {
        Ok(s) => s,
        Err(_) => match legacy_jwt.clone() {
            Some(jwt) => jwt,
            None => {
                return Err(
                    "missing session secret: configure SITE_SECRET or SESSION_SECRET (or legacy JWT_SECRET)",
                );
            }
        },
    };

    let internal_api_secret =
        resolve_domain_secret(non_empty(internal_api_override), master, KeyDomain::InternalApi)
            .ok();

    Ok(ResolvedUserSecrets {
        session_secret,
        internal_api_secret,
        legacy_jwt_secret: legacy_jwt,
    })
}

/// Constant-time verification of internal worker-to-worker API authentication
/// (`Authorization: Bearer <secret>` or `X-Internal-Api-Secret: <secret>`).
pub fn verify_internal_api_auth(
    headers: &axum::http::HeaderMap,
    expected_secret: Option<&[u8]>,
) -> bool {
    let Some(expected) = expected_secret.filter(|s| !s.is_empty()) else {
        return false;
    };
    let supplied = headers
        .get("x-internal-api-secret")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
                .map(str::trim)
                .filter(|s| !s.is_empty())
        });
    let Some(provided) = supplied else {
        return false;
    };
    provided.len() == expected.len() && bool::from(provided.as_bytes().ct_eq(expected))
}

fn read_optional_secret(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|s| s.to_string())
        .or_else(|| env.var(name).ok().map(|v| v.to_string()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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
    let resolved = resolve_user_secrets(
        read_optional_secret(&env, "SITE_SECRET").as_deref(),
        read_optional_secret(&env, "SESSION_SECRET").as_deref(),
        read_optional_secret(&env, "SESSION_V2_SECRET").as_deref(),
        read_optional_secret(&env, "JWT_SECRET").as_deref(),
        read_optional_secret(&env, "INTERNAL_API_SECRET").as_deref(),
    )
    .map_err(|msg| Error::RustError(msg.to_string()))?;
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
        legacy_jwt_secret: resolved
            .legacy_jwt_secret
            .map(|s| Arc::new(s.into_bytes())),
        session_v2_secret: Arc::new(resolved.session_secret.into_bytes()),
        internal_api_secret: resolved
            .internal_api_secret
            .map(|s| Arc::new(s.into_bytes())),
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
        // Internal Policy v3 two-phase activation endpoints (authenticated via InternalApi secret)
        .route(
            "/internal/policy/activate",
            post(safety_api::internal_policy_activate),
        )
        .route(
            "/internal/policy/refresh",
            post(safety_api::internal_policy_refresh),
        )
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
        .route("/user/api/age-confirm", post(safety_api::confirm_age))
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

    #[test]
    fn resolve_user_secrets_derives_from_site_secret_and_honors_overrides() {
        let master = "0123456789abcdef0123456789abcdef0123456789abcdef";

        // 1. SITE_SECRET-only derives isolated Session & InternalApi secrets
        let derived = resolve_user_secrets(Some(master), None, None, None, None).unwrap();
        assert_eq!(
            derived.session_secret,
            site_access::derive_domain_secret(master, KeyDomain::Session)
        );
        assert_eq!(
            derived.internal_api_secret.as_deref(),
            Some(site_access::derive_domain_secret(master, KeyDomain::InternalApi).as_str())
        );
        assert_ne!(
            derived.session_secret,
            derived.internal_api_secret.as_deref().unwrap()
        );
        assert_eq!(derived.legacy_jwt_secret, None);

        // 2. Explicit SESSION_SECRET and INTERNAL_API_SECRET override SITE_SECRET
        let overridden = resolve_user_secrets(
            Some(master),
            Some(" explicit-session "),
            Some("legacy-v2"),
            Some("legacy-jwt"),
            Some(" explicit-internal "),
        )
        .unwrap();
        assert_eq!(overridden.session_secret, "explicit-session");
        assert_eq!(
            overridden.internal_api_secret.as_deref(),
            Some("explicit-internal")
        );
        assert_eq!(overridden.legacy_jwt_secret.as_deref(), Some("legacy-jwt"));

        // 3. Legacy SESSION_V2_SECRET overrides SITE_SECRET when SESSION_SECRET absent
        let legacy_v2 =
            resolve_user_secrets(Some(master), None, Some("legacy-v2"), None, None).unwrap();
        assert_eq!(legacy_v2.session_secret, "legacy-v2");

        // 4. Legacy JWT_SECRET-only cutover still succeeds when SITE_SECRET absent
        let legacy_only =
            resolve_user_secrets(None, None, None, Some("jwt-cutover"), None).unwrap();
        assert_eq!(legacy_only.session_secret, "jwt-cutover");
        assert_eq!(legacy_only.internal_api_secret, None);

        // 5. Missing everything fails closed
        assert!(resolve_user_secrets(None, None, None, None, None).is_err());
        assert!(resolve_user_secrets(Some("  "), Some(""), None, Some(" "), None).is_err());
    }

    #[test]
    fn internal_api_auth_verifies_bearer_and_header_and_fails_closed() {
        use axum::http::{HeaderMap, HeaderValue};

        let secret = b"derived-internal-secret";
        let mut h_bearer = HeaderMap::new();
        h_bearer.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer derived-internal-secret"),
        );
        assert!(verify_internal_api_auth(&h_bearer, Some(secret)));
        assert!(!verify_internal_api_auth(&h_bearer, None));
        assert!(!verify_internal_api_auth(&h_bearer, Some(b"wrong")));

        let mut h_hdr = HeaderMap::new();
        h_hdr.insert(
            "x-internal-api-secret",
            HeaderValue::from_static("derived-internal-secret"),
        );
        assert!(verify_internal_api_auth(&h_hdr, Some(secret)));

        let empty = HeaderMap::new();
        assert!(!verify_internal_api_auth(&empty, Some(secret)));
    }
}
