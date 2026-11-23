#![recursion_limit = "256"]

mod cli;
mod previews;
mod seo;

use app::*;
use axum::Router;
use clap::Parser;
use leptos::prelude::*;
use leptos_axum::{LeptosRoutes, generate_route_list};
use std::{sync::Arc, time::Duration};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{
    EnvFilter, Registry, layer::SubscriberExt as _, util::SubscriberInitExt as _,
};

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

    let conf = get_configuration(None)?;
    let mut leptos_options = conf.leptos_options;
    leptos_options.site_addr = format!("{}:{}", args.host, args.port).parse()?;

    let engine = search_engine::Engine::new(
        args.clip_text_model.as_ref(),
        args.tokenizer.as_ref(),
        args.dinov3_model.as_ref(),
        args.idle_timeout.map(Duration::from_secs),
    )
    .await?;
    tracing::info!("search engine loaded");

    let public_url = args
        .public_url
        .or_else(|| std::env::var("PUBLIC_URL").ok())
        .as_deref()
        .and_then(app::util::normalize_public_origin);
    let app_state = state::AppState {
        leptos_options: leptos_options.clone(),
        engine: Arc::new(engine),
        prefix: Arc::new(args.prefix.clone()),
        public_url: Arc::new(public_url),
    };

    let routes = generate_route_list(App);

    // Search is served by Leptos server functions (auto-registered under /api),
    // so no manual routes are needed here beyond static assets, SEO, and leptos routes.
    let mut app = Router::new();
    if let Some(prefix) = args.prefix {
        app = app
            .nest_service("/images", ServeDir::new(&prefix))
            .nest_service("/videos", ServeDir::new(&prefix))
    }
    let app = app
        .route("/robots.txt", axum::routing::get(seo::robots_txt))
        .route("/sitemap.xml", axum::routing::get(seo::sitemap_root))
        .route("/sitemap/{page}", axum::routing::get(seo::sitemap_page))
        .route(
            "/api/like_previews",
            axum::routing::get(previews::like_previews),
        )
        .leptos_routes_with_context(
            &app_state,
            routes,
            {
                let app_state = app_state.clone();
                move || provide_context(app_state.clone())
            },
            {
                let opts = leptos_options.clone();
                move || shell(opts.clone())
            },
        )
        .fallback(leptos_axum::file_and_error_handler::<state::AppState, _>(
            shell,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr = leptos_options.site_addr;
    tracing::info!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
