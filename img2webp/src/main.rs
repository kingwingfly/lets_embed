use std::{path::PathBuf, time::Duration};

use clap::Parser;
use img2webp::{QueueConfig, operator, pull_convert, walk_convert_prefix};
use opendal::{Operator, services::Fs};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(short, long)]
    delete_origin: bool,
    /// Walk only this R2/FS prefix instead of pulling from Cloudflare Queue
    #[clap(long)]
    prefix: Option<String>,
    /// Walk the entire R2 bucket ("/") instead of pulling from Cloudflare Queue
    #[clap(long, conflicts_with = "prefix")]
    full_scan: bool,
    /// Keep polling the Cloudflare Queue when empty
    #[clap(long)]
    daemon: bool,
    /// Seconds to wait between empty polls in --daemon mode
    #[clap(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    poll_interval_secs: u64,
    /// Max messages to pull per Cloudflare Queue batch (1..=100)
    #[clap(long, default_value_t = 32, value_parser = clap::value_parser!(u8).range(1..=100))]
    batch_size: u8,
    /// Lease visibility timeout in seconds for pulled queue messages
    #[clap(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..=43200))]
    visibility_timeout_secs: u64,
    /// If presented, walk through this local filesystem path
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
        Some(path) => {
            let prefix = cli.prefix.as_deref().unwrap_or("/");
            walk_convert_prefix(
                Operator::new(Fs::default().root(&path.to_string_lossy()))?,
                s3,
                prefix,
                cli.delete_origin,
            )
            .await?
        }
        None if cli.full_scan => walk_convert_prefix(s3.clone(), s3, "/", cli.delete_origin).await?,
        None => {
            if let Some(prefix) = cli.prefix.as_deref() {
                walk_convert_prefix(s3.clone(), s3, prefix, cli.delete_origin).await?
            } else {
                let cfg = QueueConfig::from_env(
                    cli.batch_size,
                    cli.visibility_timeout_secs,
                    cli.daemon,
                    Duration::from_secs(cli.poll_interval_secs),
                )?;
                pull_convert(s3.clone(), s3, cfg, cli.delete_origin).await?
            }
        }
    };
    println!("{}", serde_json::to_string(&metas)?);
    Ok(())
}
