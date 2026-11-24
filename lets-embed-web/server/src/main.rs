#![recursion_limit = "256"]

mod cli;
mod internal;
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
    routing::{get, post},
};
use clap::Parser;
use leptos::prelude::*;
use leptos_axum::{AxumRouteListing, LeptosRoutes, generate_route_list};
use middleware::{MetadataRateLimiter, MiddlewareState};
use site_access::decode_active_policy_v3;
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
/// SEO, legal Markdown routes, `/api/like_previews`, and `/api/post_images`).
fn build_core_router(app_state: &AppState, serve_media_prefix: Option<PathBuf>) -> Router<AppState> {
    let mut router = Router::new().route("/healthz", get(healthz));

    // HARD INVARIANT:
    // - Managed Mode unconditionally refuses raw media mounts on `/images` and `/videos`.
    // - Standalone Mode mounts standard `ServeDir` ONLY when `safety_enabled == false`.
    //   When a local Policy v3 file enables safety (`safety_enabled == true`), `/images/*`
    //   and `/videos/*` route through the DB-authorizing Standalone Media Guard!
    if app_state.mode == DeploymentMode::Standalone
        && let Some(prefix) = serve_media_prefix
    {
        if app_state
            .policy_store
            .current_standalone()
            .policy
            .safety_enabled
        {
            router = router
                .route("/images/{*path}", get(internal::standalone_guarded_image))
                .route("/videos/{*path}", get(internal::standalone_guarded_video));
        } else {
            router = router
                .nest_service("/images", ServeDir::new(&prefix))
                .nest_service("/videos", ServeDir::new(&prefix));
        }
    }

    router
        .route("/internal/facts-rev/{kind}/{id}", get(internal::facts_rev))
        .route(
            "/internal/validate-safety-catalog",
            post(internal::validate_safety_catalog),
        )
        .route("/api/safety/reveal", post(internal::safety_reveal))
        .route("/robots.txt", get(seo::robots_txt))
        .route("/sitemap.xml", get(seo::sitemap_root))
        .route("/sitemap/{page}", get(seo::sitemap_page))
        .route("/terms", get(legal_routes::terms))
        .route("/privacy", get(legal_routes::privacy))
        .route("/dmca", get(legal_routes::dmca))
        .route("/content-policy", get(legal_routes::content_policy))
        .route(
            "/api/like_previews",
            get(previews::like_previews).post(previews::like_previews_post),
        )
        .route("/api/post_images", get(previews::post_images))
}

fn build_app_router(
    app_state: AppState,
    serve_media_prefix: Option<PathBuf>,
    routes: Vec<AxumRouteListing>,
    leptos_options: LeptosOptions,
) -> Router {
    let state_for_ctx = app_state.clone();
    let mw_state = MiddlewareState {
        app: app_state.clone(),
        rate_limiter: Arc::new(MetadataRateLimiter::default()),
    };
    build_core_router(&app_state, serve_media_prefix)
        .leptos_routes_with_context(
            &app_state,
            routes,
            move || provide_context(state_for_ctx.clone()),
            move || shell(leptos_options.clone()),
        )
        .fallback(leptos_axum::file_and_error_handler::<AppState, _>(shell))
        .layer(axum::middleware::from_fn_with_state(
            mw_state,
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
                let parsed = decode_active_policy_v3(&raw).map_err(|err| {
                    anyhow::anyhow!(
                        "failed decoding Policy v3 JSON in {}: {err}",
                        path.display()
                    )
                })?;
                tracing::info!(
                    path = %path.display(),
                    rev = parsed.revision,
                    safety_enabled = parsed.safety_enabled,
                    "loaded standalone Policy v3 safety policy"
                );
                engine.compile_policy(parsed)?
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
        internal_api_secret: runtime.internal_api_secret.map(Arc::new),
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
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
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
    use middleware::MetadataRateLimitConfig;
    use site_access::{
        ActorBinding, GATEWAY_ASSERTION_AUDIENCE, GATEWAY_ASSERTION_HEADER,
        GATEWAY_ASSERTION_VERSION, GatewayAssertion, PublicSitePolicy, compute_policy_digest,
        sign_gateway_assertion,
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

    fn test_router_with_limits(
        state: AppState,
        serve_prefix: Option<PathBuf>,
        limits: MetadataRateLimitConfig,
    ) -> Router {
        let mw_state = MiddlewareState {
            app: state.clone(),
            rate_limiter: Arc::new(MetadataRateLimiter::new(limits)),
        };
        build_core_router(&state, serve_prefix)
            .layer(axum::middleware::from_fn_with_state(
                mw_state,
                middleware::safety_and_auth_middleware,
            ))
            .with_state(state)
    }

    fn test_router(state: AppState, serve_prefix: Option<PathBuf>) -> Router {
        test_router_with_limits(state, serve_prefix, MetadataRateLimitConfig::default())
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
        let actor = match sub {
            Some(s) => ActorBinding::User {
                sub: s.to_string(),
                sid: "sid-test".to_string(),
            },
            None => ActorBinding::Anon,
        };
        let a = GatewayAssertion {
            v: GATEWAY_ASSERTION_VERSION,
            aud: GATEWAY_ASSERTION_AUDIENCE.to_string(),
            actor,
            rev: policy.revision,
            min_enforce_rev: policy.min_enforce_rev,
            digest: compute_policy_digest(policy),
            direct_grants: vec![],
            click_eligible: vec![],
            is_billing_waived: false,
            caller_age_verified: false,
            caller_terms_accepted: false,
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
            internal_api_secret: None,
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
        policy.refresh_policy_digest();

        let policy_url = spawn_policy_server(&policy).await;
        let assert_secret = b"managed-assertion-secret-0123456789";
        let cap_secret = b"managed-media-cap-secret-0123456789";
        let internal_secret = b"managed-internal-api-secret-012345";

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
            internal_api_secret: Some(Arc::new(internal_secret.to_vec())),
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
            .clone()
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

        // 8. `POST /api/like_previews` and `GET /api/post_images` enforce Managed auth + `private, no-store`.
        let post_previews_unauth = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/like_previews")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"posts":[],"images":[],"videos":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_previews_unauth.status(), StatusCode::FORBIDDEN);

        let post_previews_ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/like_previews")
                    .header(GATEWAY_ASSERTION_HEADER, &valid_tok)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"posts":[],"images":[],"videos":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_previews_ok.status(), StatusCode::OK);
        assert_eq!(
            post_previews_ok.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        let previews_json: serde_json::Value = serde_json::from_slice(
            &to_bytes(post_previews_ok.into_body(), 4096).await.unwrap(),
        )
        .unwrap();
        assert_eq!(
            previews_json,
            serde_json::json!({ "posts": [], "images": [], "videos": [] })
        );

        let post_images_unauth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/post_images?post_id=12")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_images_unauth.status(), StatusCode::FORBIDDEN);

        let post_images_bad_query = app
            .oneshot(
                Request::builder()
                    .uri("/api/post_images?post_id=not_a_number")
                    .header(GATEWAY_ASSERTION_HEADER, &valid_tok)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_images_bad_query.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn metadata_rate_limiter_enforces_per_subject_and_global_429_limits() {
        let mut policy = PublicSitePolicy {
            revision: 2,
            min_enforce_rev: 2,
            safety_enabled: false,
            ..PublicSitePolicy::default()
        };
        policy.refresh_policy_digest();
        let policy_url = spawn_policy_server(&policy).await;
        let assert_secret = b"rate-limit-assertion-secret-012345";
        let cap_secret = b"rate-limit-cap-secret-0123456789";

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
            internal_api_secret: None,
        };

        let app = test_router_with_limits(
            state,
            None,
            MetadataRateLimitConfig {
                per_subject_limit: 2,
                global_limit: 3,
                window: Duration::from_secs(60),
            },
        );

        let tok_a = signed_assertion(assert_secret, &policy, Some("user-a"), now_secs() + 20);
        let tok_b = signed_assertion(assert_secret, &policy, Some("user-b"), now_secs() + 20);
        let tok_c = signed_assertion(assert_secret, &policy, Some("user-c"), now_secs() + 20);

        let make_req = |tok: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/like_previews")
                .header(GATEWAY_ASSERTION_HEADER, tok)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"posts":[],"images":[],"videos":[]}"#))
                .unwrap()
        };

        // user-a: requests 1 and 2 pass; request 3 hits per-subject 429!
        assert_eq!(app.clone().oneshot(make_req(&tok_a)).await.unwrap().status(), StatusCode::OK);
        assert_eq!(app.clone().oneshot(make_req(&tok_a)).await.unwrap().status(), StatusCode::OK);
        let r3 = app.clone().oneshot(make_req(&tok_a)).await.unwrap();
        assert_eq!(r3.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r3.headers().get(header::CACHE_CONTROL).unwrap(), "private, no-store");
        assert!(r3.headers().contains_key(header::RETRY_AFTER));

        // user-b: request 1 passes (global count reaches 3).
        assert_eq!(app.clone().oneshot(make_req(&tok_b)).await.unwrap().status(), StatusCode::OK);

        // user-c: hits global 429 limit immediately!
        let rc = app.oneshot(make_req(&tok_c)).await.unwrap();
        assert_eq!(rc.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rc.headers().get(header::CACHE_CONTROL).unwrap(), "private, no-store");
    }

    #[tokio::test]
    async fn internal_endpoints_and_reveal_and_standalone_media_guard_enforce_policy_v3_invariants() {
        let mut policy = PublicSitePolicy {
            revision: 7,
            min_enforce_rev: 5,
            safety_enabled: true,
            fixed_blur_enabled: true,
            ..PublicSitePolicy::default()
        };
        policy.refresh_policy_digest();
        let policy_url = spawn_policy_server(&policy).await;
        let assert_secret = b"v3-assertion-secret-0123456789abcdef";
        let cap_secret = b"v3-media-cap-secret-0123456789abcdef";
        let internal_secret = b"v3-internal-secret-0123456789abcdef";

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
            internal_api_secret: Some(Arc::new(internal_secret.to_vec())),
        };
        let app = test_router(state, None);

        // 1. `/internal/facts-rev` rejects unauthenticated calls with 403.
        let unauth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/facts-rev/image/42")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::FORBIDDEN);

        // 2. `/internal/facts-rev` accepts `X-Internal-Api-Secret` (sent by gateway_worker/admin)
        // as well as `Authorization: Bearer <internal_api_secret>` and validates kind.
        let bad_kind = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/facts-rev/audio/42")
                    .header(
                        "x-internal-api-secret",
                        std::str::from_utf8(internal_secret).unwrap(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_kind.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            bad_kind.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );

        // 3a. `/internal/validate-safety-catalog` MUST REJECT user `X-Gateway-Assertion` alone (403, Cycle 2 D-2).
        let valid_anon = signed_assertion(assert_secret, &policy, None, now_secs() + 20);
        let assertion_only_catalog = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/validate-safety-catalog")
                    .header(GATEWAY_ASSERTION_HEADER, &valid_anon)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"post_tags":[],"authors":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(assertion_only_catalog.status(), StatusCode::FORBIDDEN);

        // 3b. `/internal/validate-safety-catalog` accepts `X-Internal-Api-Secret` without DB for empty arrays!
        let empty_catalog = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/validate-safety-catalog")
                    .header(
                        "x-internal-api-secret",
                        std::str::from_utf8(internal_secret).unwrap(),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"post_tags":[],"authors":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(empty_catalog.status(), StatusCode::OK);
        let cat_json: serde_json::Value = serde_json::from_slice(
            &to_bytes(empty_catalog.into_body(), 4096).await.unwrap(),
        )
        .unwrap();
        assert_eq!(
            cat_json,
            serde_json::json!({ "unknown_post_tags": [], "unknown_authors": [] })
        );

        // 4. `POST /api/safety/reveal`: rejects missing CSRF header (403).
        let valid_user = signed_assertion(assert_secret, &policy, Some("usr:12345678"), now_secs() + 20);
        let no_csrf = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/safety/reveal")
                    .header(GATEWAY_ASSERTION_HEADER, &valid_user)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("origin", "https://gallery.example.com")
                    .body(Body::from(
                        r#"{"kind":"image","asset_id":42,"policy_rev":7}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);

        // 5. `POST /api/safety/reveal`: rejects stale policy_rev with 409 Conflict.
        let stale_rev = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/safety/reveal")
                    .header(GATEWAY_ASSERTION_HEADER, &valid_user)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("origin", "https://gallery.example.com")
                    .header("sec-fetch-site", "same-origin")
                    .header("x-requested-with", "fetch")
                    .body(Body::from(
                        r#"{"kind":"image","asset_id":42,"policy_rev":6}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale_rev.status(), StatusCode::CONFLICT);

        // 6. `POST /api/safety/reveal`: rejects Anon actor with 403 Forbidden.
        let anon_reveal = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/safety/reveal")
                    .header(GATEWAY_ASSERTION_HEADER, &valid_anon)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("origin", "https://gallery.example.com")
                    .header("sec-fetch-site", "same-origin")
                    .header("x-requested-with", "fetch")
                    .body(Body::from(
                        r#"{"kind":"image","asset_id":42,"policy_rev":7}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(anon_reveal.status(), StatusCode::FORBIDDEN);

        // 7. Standalone Media Guard: when `safety_enabled == true`, raw files on disk are NOT
        // served by `ServeDir` — requests pass through the DB-authorizing guard (which fails closed
        // with 404/503 instead of leaking raw bytes from disk!).
        let tmp = std::env::temp_dir().join(format!(
            "lets-embed-standalone-guard-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("restricted.webp"), b"secret-standalone-bytes").unwrap();
        let guarded_compiled = CompiledPolicy::compile(policy).unwrap();
        let standalone_guarded_state = AppState {
            leptos_options: test_leptos_opts(),
            engine: test_engine(),
            prefix: Arc::new(Some(tmp.clone())),
            public_url: Arc::new(None),
            mode: DeploymentMode::Standalone,
            trust_proxy: false,
            policy_store: Arc::new(PolicyStore::standalone(guarded_compiled)),
            gateway_assertion_secret: None,
            media_cap_secret: None,
            internal_api_secret: None,
        };
        let guarded_app = test_router(standalone_guarded_state, Some(tmp.clone()));
        let guarded_resp = guarded_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/images/restricted.webp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            guarded_resp.status(),
            StatusCode::OK,
            "guarded standalone media MUST NOT serve raw bytes without DB authorization"
        );
        // Non-.webp path rejected immediately with 404.
        let non_webp = guarded_app
            .oneshot(
                Request::builder()
                    .uri("/images/restricted.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(non_webp.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
