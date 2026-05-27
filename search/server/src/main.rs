mod api;
mod cli;
mod state;

use app::*;
use axum::{Router, routing::get};
use clap::Parser;
use leptos::prelude::*;
use leptos_axum::{LeptosRoutes, generate_route_list};
use std::sync::Arc;
use tower_http::{services::ServeDir, trace::TraceLayer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = cli::Cli::parse();

    let conf = get_configuration(None)?;
    let mut leptos_options = conf.leptos_options;
    leptos_options.site_addr = format!("{}:{}", args.host, args.port).parse()?;

    let engine = Arc::new(
        search_engine::Engine::new(&args.clip_text_model, &args.tokenizer, &args.dinov3_model)
            .await?,
    );

    let app_state = state::AppState {
        leptos_options: leptos_options.clone(),
        engine,
        prefix: Arc::new(args.prefix.clone()),
    };

    let routes = generate_route_list(App);

    let app = Router::new()
        .route("/api/search", get(api::search_sse))
        .nest_service("/images", ServeDir::new(&args.prefix))
        .leptos_routes(&app_state, routes, {
            let opts = leptos_options.clone();
            move || shell(opts.clone())
        })
        .fallback(leptos_axum::file_and_error_handler::<state::AppState, _>(
            shell,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr = leptos_options.site_addr;
    tracing::info!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
