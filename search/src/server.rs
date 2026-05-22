use crate::{ServeArgs, handlers};
use askama::Template;
use axum::{
    Router,
    response::Html,
    routing::{get, post},
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::{compression::CompressionLayer, services::ServeDir, trace::TraceLayer};

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<search_engine::Engine>,
    pub _prefix: Arc<PathBuf>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTpl;

pub async fn run(args: ServeArgs) -> anyhow::Result<()> {
    let engine = search_engine::Engine::new(args.model.clip_model, args.model.tokenizer).await?;
    let state = AppState {
        engine: Arc::new(engine),
        _prefix: Arc::new(args.prefix.clone()),
    };

    // Compression must NOT wrap SSE (it would break streaming),
    // so we split routers and apply compression only to static/HTML.
    let api = Router::new()
        .route("/api/search/tag", post(handlers::search_tag))
        .route("/api/search/clip", post(handlers::search_clip));

    let statics = Router::new()
        .route("/", get(index))
        .nest_service("/files", ServeDir::new(&args.prefix)) // range support 内建
        .nest_service("/dist", ServeDir::new("dist"))
        .layer(CompressionLayer::new());

    let app = Router::new()
        .merge(api)
        .merge(statics)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    tracing::info!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<String> {
    Html(IndexTpl.render().expect("template render"))
}
