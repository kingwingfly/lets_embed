mod error;
mod handlers;
mod payload;
mod server;

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ssearch", about = "Image semantic search server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run HTTP server
    Serve(ServeArgs),
    /// Local tag search (prints JSON to stdout)
    Tag {
        #[arg(long)]
        include: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
        #[command(flatten)]
        model: ModelArgs,
    },
    /// Local CLIP search (prints JSON to stdout)
    Clip {
        #[arg(long)]
        query: Vec<String>,
        #[arg(long, default_value_t = 20)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
        #[command(flatten)]
        model: ModelArgs,
    },
}

#[derive(Args, Clone)]
pub struct ModelArgs {
    #[arg(long, default_value = "models/cn_clip_text.onnx")]
    pub clip_model: PathBuf,
    #[arg(long, default_value = "models/tokenizer.json")]
    pub tokenizer: PathBuf,
}

#[derive(Args)]
pub struct ServeArgs {
    #[arg(long, default_value_t = 3000)]
    pub port: u16,
    #[arg(long, default_value = "./images")]
    pub prefix: PathBuf,
    #[command(flatten)]
    pub model: ModelArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or("search=info,tower_http=info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Serve(args) => server::run(args).await,
        Cmd::Tag {
            include,
            exclude,
            limit,
            offset,
            model,
        } => {
            let engine = search_engine::Engine::new(model.clip_model, model.tokenizer).await?;
            let (posts, images) = engine.search_tag(include, exclude, limit, offset).await?;
            let out = serde_json::json!({
                "posts":  posts,
                "images": images
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        Cmd::Clip {
            query,
            limit,
            offset,
            model,
        } => {
            let engine = search_engine::Engine::new(model.clip_model, model.tokenizer).await?;
            let groups = engine
                .search_clip(query.iter().map(|s| s.as_str()), limit, offset)
                .await?;
            let merged = payload::merge_clip(groups);
            let out = serde_json::json!({
                "images": merged
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
    }
}
