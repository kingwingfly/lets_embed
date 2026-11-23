#![recursion_limit = "256"]

mod cli;
mod legal_routes;
mod middleware;
mod previews;
mod seo;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context as _;
use app::{
    App,
    policy_sync::PolicyStore,
    shell,
    state::{AppState, CompiledPolicy, DeploymentMode},
};
use axum::{
    Router,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use clap::Parser;
use leptos::prelude::*;
use leptos_axum::{AxumRouteListing, LeptosRoutes, generate_route_list};
use site_access::PublicSitePolicy;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{
    EnvFilter, Registry, layer::SubscriberExt as _, util::SubscriberInitExt as _,
};

async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "private, no-store")],
        "ok",
    )
}

/// Build the core non-Leptos HTTP router (healthz, optional Standalone media ServeDir,
/// SEO, legal Markdown routes, and `/api/like_previews`) wrapped in the deployment-mode
/// safety & assertion middleware.
fn build_core_router(app_state: &AppState, serve_media_prefix: Option<PathBuf>) -> Router<AppState> {
    let mut router = Router::new().route("/healthz", get(healthz));

    // HARD INVARIANT (C2): raw ServeDir on `/images` and `/videos` is mounted ONLY
    // in Standalone Mode. Managed Mode unconditionally refuses raw media file mounts
    // even if `--prefix` was passed on the command line.
    if app_state.mode == DeploymentMode::Standalone
        && let Some(prefix) = serve_media_prefix
    {
        router = router
            .nest_service("/images", ServeDir::new(&prefix))
            .nest_service("/videos", ServeDir::new(&prefix));
    }

    router
        .route("/robots.txt", get(seo::robots_txt))
        .route("/sitemap.xml", get(seo::sitemap_root))
        .route("/sitemap/{page}", get(seo::sitemap_page))
        .route("/terms", get(legal_routes::terms))
        .route("/privacy", get(legal_routes::privacy))
        .route("/dmca", get(legal_routes::dmca))
        .route("/content-policy", get(legal_routes::content_policy))
        .route("/api/like_previews", get(previews::like_previews))
}

fn build_app_router(
    app_state: AppState,
    serve_media_prefix: Option<PathBuf>,
    routes: Vec<AxumRouteListing>,
    leptos_options: LeptosOptions,
) -> Router {
    let state_for_ctx = app_state.clone();
    let state_for_mw = app_state.clone();
    build_core_router(&app_state, serve_media_prefix)
        .leptos_routes_with_context(
            &app_state,
            routes,
            move || provide_context(state_for_ctx.clone()),
            move || shell(leptos_options.clone()),
        )
        .fallback(leptos_axum::file_and_error_handler::<AppState, _>(shell))
        .layer(axum::middleware::from_fn_with_state(
            state_for_mw,
            middleware::safety_and_auth_middleware,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Registry::default()
        .with(tracing_subscriber::fmt::layer())
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or("lets_embed_web=info,search_engine=info".into()),
        )
        .init();

    let args = cli::Cli::parse();
    // Validate deployment mode and all required Managed Mode secrets/URLs BEFORE touching DB or sockets.
    let runtime = cli::resolve_runtime_config(&args, |k| std::env::var(k).ok())?;
    if runtime.mode == DeploymentMode::Managed && args.prefix.is_some() {
        tracing::warn!(
            "ignoring positional `prefix` argument in managed mode: raw /images and /videos mounts are disabled"
        );
    }

    let conf = get_configuration(None)?;
    let mut leptos_options = conf.leptos_options;
    leptos_options.site_addr = format!("{}:{}", args.host, args.port).parse()?;

    let engine = Arc::new(
        search_engine::Engine::new(
            args.clip_text_model.as_ref(),
            args.tokenizer.as_ref(),
            args.dinov3_model.as_ref(),
            args.idle_timeout.map(Duration::from_secs),
        )
        .await?,
    );
    tracing::info!(mode = runtime.mode.as_str(), "search engine loaded");

    let policy_store = match runtime.mode {
        DeploymentMode::Standalone => {
            let compiled = if let Some(path) = runtime.standalone_policy_file.as_ref() {
                let raw = std::fs::read_to_string(path).with_context(|| {
                    format!("failed reading --policy-file {}", path.display())
                })?;
                let parsed: PublicSitePolicy = serde_json::from_str(&raw).with_context(|| {
                    format!("failed parsing PublicSitePolicy JSON in {}", path.display())
                })?;
                tracing::info!(
                    path = %path.display(),
                    rev = parsed.revision,
                    safety_enabled = parsed.safety_enabled,
                    "loaded standalone safety policy"
                );
                engine.compile_policy(parsed).await?
            } else {
                CompiledPolicy::disabled()
            };
            Arc::new(PolicyStore::standalone(compiled))
        }
        DeploymentMode::Managed => {
            let sync_cfg = runtime
                .managed_policy_sync
                .clone()
                .expect("managed mode requires policy sync config");
            Arc::new(PolicyStore::managed(sync_cfg)?)
        }
    };

    let app_state = AppState {
        leptos_options: leptos_options.clone(),
        engine,
        prefix: Arc::new(runtime.serve_media_prefix.clone()),
        public_url: Arc::new(runtime.public_url.clone()),
        mode: runtime.mode,
        trust_proxy: runtime.trust_proxy,
        policy_store,
        gateway_assertion_secret: runtime.gateway_assertion_secret.map(Arc::new),
        media_cap_secret: runtime.media_cap_secret.map(Arc::new),
    };

    let routes = generate_route_list(App);
    let app = build_app_router(
        app_state,
        runtime.serve_media_prefix,
        routes,
        leptos_options.clone(),
    );

    let addr = leptos_options.site_addr;
    tracing::info!(mode = runtime.mode.as_str(), "listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use app::policy_sync::PolicySyncConfig;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use site_access::{
        GATEWAY_ASSERTION_AUDIENCE, GATEWAY_ASSERTION_HEADER, GATEWAY_ASSERTION_VERSION,
        GatewayAssertion, compute_policy_digest, sign_gateway_assertion,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt as _;

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn test_engine() -> Arc<search_engine::Engine> {
        Arc::new(
            search_engine::Engine::connect_lazy_without_models(
                "postgres://127.0.0.1:5432/unused_unit_test",
            )
            .expect("lazy engine"),
        )
    }

    fn test_leptos_opts() -> LeptosOptions {
        LeptosOptions::builder()
            .output_name("lets-embed-web")
            .build()
    }

    fn test_router(state: AppState, serve_prefix: Option<PathBuf>) -> Router {
        let state_for_mw = state.clone();
        build_core_router(&state, serve_prefix)
            .layer(axum::middleware::from_fn_with_state(
                state_for_mw,
                middleware::safety_and_auth_middleware,
            ))
            .with_state(state)
    }

    async fn spawn_policy_server(policy: &PublicSitePolicy) -> String {
        let body = serde_json::json!({
            "policy": policy,
            "digest": compute_policy_digest(policy),
        })
        .to_string();
        let router = Router::new().route(
            "/policy",
            get(move || {
                let body = body.clone();
                async move { ([("content-type", "application/json")], body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}/policy")
    }

    fn signed_assertion(
        secret: &[u8],
        policy: &PublicSitePolicy,
        sub: Option<&str>,
        exp: u64,
    ) -> String {
        let a = GatewayAssertion {
            v: GATEWAY_ASSERTION_VERSION,
            aud: GATEWAY_ASSERTION_AUDIENCE.to_string(),
            rev: policy.revision,
            min_enforce_rev: policy.min_enforce_rev,
            policy_digest: compute_policy_digest(policy),
            sub: sub.map(ToOwned::to_owned),
            sid: sub.map(|_| "sid-test".to_string()),
            switchers: vec![],
            safe_mode: false,
            is_admin_view: false,
            exp,
        };
        sign_gateway_assertion(&a, secret).unwrap()
    }

    #[tokio::test]
    async fn standalone_serves_prefix_media_ignores_spoofed_headers_and_respects_trust_proxy() {
        let tmp = std::env::temp_dir().join(format!(
            "lets-embed-standalone-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("hello.webp"), b"webp-bytes").unwrap();

        let state = AppState {
            leptos_options: test_leptos_opts(),
            engine: test_engine(),
            prefix: Arc::new(Some(tmp.clone())),
            public_url: Arc::new(None),
            mode: DeploymentMode::Standalone,
            trust_proxy: false,
            policy_store: Arc::new(PolicyStore::standalone(CompiledPolicy::disabled())),
            gateway_assertion_secret: None,
            media_cap_secret: None,
        };

        let app = test_router(state.clone(), Some(tmp.clone()));

        // 1. Raw `/images/*` works in Standalone Mode even without X-Gateway-Assertion,
        // and spoofed privileged headers are ignored rather than causing 403/503.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/images/hello.webp")
                    .header(GATEWAY_ASSERTION_HEADER, "garbage-spoofed")
                    .header("x-policy-revision", "999")
                    .header("x-gallery-switchers", "r18")
                    .header("cf-ipcountry", "KP")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"webp-bytes");

        // 2. Without `--trust-proxy`, `/robots.txt` ignores spoofed `X-Forwarded-Host` and uses `Host`.
        let robots_no_proxy = app
            .oneshot(
                Request::builder()
                    .uri("/robots.txt")
                    .header("host", "127.0.0.1:3000")
                    .header("x-forwarded-host", "evil.example.com")
                    .header("x-forwarded-proto", "https")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(robots_no_proxy.status(), StatusCode::OK);
        let robots_txt = String::from_utf8(
            to_bytes(robots_no_proxy.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(robots_txt.contains("Sitemap: http://127.0.0.1:3000/sitemap.xml"));
        assert!(!robots_txt.contains("evil.example.com"));

        // 3. With explicit `--trust-proxy`, Standalone honors `X-Forwarded-Host`.
        let mut trust_state = state;
        trust_state.trust_proxy = true;
        let trust_app = test_router(trust_state, None);
        let robots_proxy = trust_app
            .oneshot(
                Request::builder()
                    .uri("/robots.txt")
                    .header("host", "127.0.0.1:3000")
                    .header("x-forwarded-host", "proxy.example.com")
                    .header("x-forwarded-proto", "https")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let robots_proxy_txt = String::from_utf8(
            to_bytes(robots_proxy.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(robots_proxy_txt.contains("Sitemap: https://proxy.example.com/sitemap.xml"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn managed_mode_enforces_assertions_refuses_raw_media_syncs_policy_and_sanitizes_legal() {
        let tmp = std::env::temp_dir().join(format!(
            "lets-embed-managed-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("secret.webp"), b"secret-bytes").unwrap();

        let mut policy = PublicSitePolicy {
            revision: 5,
            min_enforce_rev: 3,
            safety_enabled: false,
            ..PublicSitePolicy::default()
        };
        policy.legal.rta_meta_enabled = true;
        policy.legal.terms_md = "# Terms\n\n<script>alert('xss')</script>\n\n<img src=x onerror=alert(1)>\n\n[bad](javascript:alert(2))\n\nSafe **text**.".to_string();

        let policy_url = spawn_policy_server(&policy).await;
        let assert_secret = b"managed-assertion-secret-0123456789";
        let cap_secret = b"managed-media-cap-secret-0123456789";

        let store = PolicyStore::managed(PolicySyncConfig {
            policy_url,
            cf_access_client_id: None,
            cf_access_client_secret: None,
            max_staleness: Duration::from_secs(60),
        })
        .unwrap();

        let state = AppState {
            leptos_options: test_leptos_opts(),
            engine: test_engine(),
            prefix: Arc::new(None),
            public_url: Arc::new(Some("https://gallery.example.com".to_string())),
            mode: DeploymentMode::Managed,
            trust_proxy: false,
            policy_store: Arc::new(store),
            gateway_assertion_secret: Some(Arc::new(assert_secret.to_vec())),
            media_cap_secret: Some(Arc::new(cap_secret.to_vec())),
        };

        // Even if someone passes `Some(tmp)` to `build_core_router`, Managed Mode MUST refuse `/images` mount!
        let app = test_router(state, Some(tmp.clone()));

        // 1. `/healthz` works WITHOUT X-Gateway-Assertion and returns `private, no-store`.
        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(
            health.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );

        // 2. Missing assertion -> 403 Forbidden + `Cache-Control: private, no-store`.
        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/terms")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            missing.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );

        // 3. Forged or expired assertion -> 403 Forbidden.
        let expired_tok = signed_assertion(assert_secret, &policy, None, now_secs() - 60);
        let expired = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/terms")
                    .header(GATEWAY_ASSERTION_HEADER, expired_tok)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired.status(), StatusCode::FORBIDDEN);

        let wrong_secret_tok = signed_assertion(b"wrong-secret", &policy, None, now_secs() + 20);
        let forged = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/terms")
                    .header(GATEWAY_ASSERTION_HEADER, wrong_secret_tok)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forged.status(), StatusCode::FORBIDDEN);

        // 4. Digest mismatch between signed assertion and upstream POLICY_URL -> fail closed 503!
        let mut wrong_pol = policy.clone();
        wrong_pol.legal.terms_md = "tampered".into();
        let mismatch_tok = signed_assertion(assert_secret, &wrong_pol, None, now_secs() + 20);
        let mismatch = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/terms")
                    .header(GATEWAY_ASSERTION_HEADER, mismatch_tok)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatch.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            mismatch.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );

        // 5. Valid assertion -> syncs policy, renders sanitized `/terms` with strict CSP,
        // RTA meta, pinned canonical PUBLIC_URL (ignoring spoofed Host/X-Forwarded-Host), and `private, no-store`.
        let valid_tok = signed_assertion(assert_secret, &policy, Some("usr-1"), now_secs() + 20);
        let terms_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/terms")
                    .header(GATEWAY_ASSERTION_HEADER, &valid_tok)
                    .header("host", "spoofed.evil")
                    .header("x-forwarded-host", "also-spoofed.evil")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(terms_resp.status(), StatusCode::OK);
        assert_eq!(
            terms_resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        let csp = terms_resp
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        let html = String::from_utf8(
            to_bytes(terms_resp.into_body(), 32_768)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("<h1>Terms</h1>"));
        assert!(html.contains("<strong>text</strong>"));
        assert!(!html.to_ascii_lowercase().contains("<script"));
        assert!(!html.to_ascii_lowercase().contains("onerror"));
        assert!(!html.to_ascii_lowercase().contains("javascript:"));
        assert!(html.contains("RTA-5042-1996-1400-1577-RTA"));
        assert!(html.contains(r#"href="https://gallery.example.com/terms""#));
        assert!(!html.contains("spoofed.evil"));

        // 6. Managed Mode REFUSES raw `/images/*` mount -> 404 (with `private, no-store`) even with valid assertion!
        let raw_img = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/images/secret.webp")
                    .header(GATEWAY_ASSERTION_HEADER, &valid_tok)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(raw_img.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            raw_img.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );

        // 7. `/robots.txt` uses ONLY pinned `PUBLIC_URL` and retains public caching.
        let robots = app
            .oneshot(
                Request::builder()
                    .uri("/robots.txt")
                    .header(GATEWAY_ASSERTION_HEADER, &valid_tok)
                    .header("host", "spoofed.evil")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(robots.status(), StatusCode::OK);
        assert_eq!(
            robots.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=3600"
        );
        let robots_body = String::from_utf8(
            to_bytes(robots.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(robots_body.contains("Sitemap: https://gallery.example.com/sitemap.xml"));
        assert!(!robots_body.contains("spoofed.evil"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
