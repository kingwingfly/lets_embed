use std::path::PathBuf;

use clap::Parser;
use img2webp::{operator, walk_convert};
use opendal::{Operator, services::Fs};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(short, long)]
    delete_origin: bool,
    /// If presented, walk throgh this path
    src_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "img2webp=info".parse().unwrap()),
        )
        .init();

    let s3 = operator().await?;
    let metas = match cli.src_path {
        None => walk_convert(s3.clone(), s3, cli.delete_origin).await?,
        Some(path) => {
            walk_convert(
                Operator::new(Fs::default().root(&path.to_string_lossy()))?.finish(),
                s3,
                cli.delete_origin,
            )
            .await?
        }
    };
    println!("{}", serde_json::to_string(&metas)?);
    Ok(())
}
