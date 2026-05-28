use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use std::{path::PathBuf, sync::Arc};

pub use search_engine::Engine;

#[derive(Debug, Clone, FromRef)]
pub struct AppState {
    pub leptos_options: LeptosOptions,
    pub engine: Arc<Engine>,
    pub prefix: Arc<PathBuf>,
}
