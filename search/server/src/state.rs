use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use search_engine::Engine;
use std::{path::PathBuf, sync::Arc};

#[derive(Clone, FromRef)]
pub struct AppState {
    pub leptos_options: LeptosOptions,
    pub engine: Arc<Engine>,
    pub prefix: Arc<PathBuf>,
}
