use std::{io::Write, path::PathBuf, time::Duration};

use clap::Parser;
use img2webp::{
    QueueConfig, default_io_concurrency, operator, pull_convert_and_then,
    walk_convert_prefix_with_concurrency,
};
use opendal::{Operator, services::Fs};
use tracing_subscriber::EnvFilter;

fn parse_concurrency(s: &str) -> Result<usize, String> {
    let val: usize = s.parse().map_err(|e| format!("{e}"))?;
    if !(1..=256).contains(&val) {
        return Err("concurrency must be in 1..=256".to_string());
    }
    Ok(val)
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(short, long)]
    delete_origin: bool,
    /// Walk only this R2/FS prefix instead of pulling from Cloudflare Queue
    #[clap(long)]
    prefix: Option<String>,
    /// Walk the entire R2 bucket ("/") instead of pulling from Cloudflare Queue
    #[clap(long, conflicts_with_all = ["prefix", "src_path"])]
    full_scan: bool,
    /// Keep polling the Cloudflare Queue when empty
    #[clap(long, conflicts_with_all = ["prefix", "full_scan", "src_path"])]
    daemon: bool,
    /// Seconds to wait between empty polls in --daemon mode
    #[clap(
        long,
        default_value_t = 10,
        value_parser = clap::value_parser!(u64).range(1..),
        conflicts_with_all = ["prefix", "full_scan", "src_path"]
    )]
    poll_interval_secs: u64,
    /// Max messages to pull per Cloudflare Queue batch (1..=100)
    #[clap(
        long,
        default_value_t = 32,
        value_parser = clap::value_parser!(u8).range(1..=100),
        conflicts_with_all = ["prefix", "full_scan", "src_path"]
    )]
    batch_size: u8,
    /// Lease visibility timeout in seconds for pulled queue messages
    #[clap(
        long,
        default_value_t = 600,
        value_parser = clap::value_parser!(u64).range(1..=43200),
        conflicts_with_all = ["prefix", "full_scan", "src_path"]
    )]
    visibility_timeout_secs: u64,
    /// Max concurrent storage I/O tasks (defaults to 2x logical CPUs, clamped to 4..=32)
    #[clap(long, value_parser = parse_concurrency)]
    concurrency: Option<usize>,
    /// If presented, walk through this local filesystem path
    src_path: Option<PathBuf>,
}

fn print_metadata(metas: impl serde::Serialize) -> anyhow::Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &metas)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "img2webp=info,opendal::layers::retry=warn".parse().unwrap()),
        )
        .init();

    let concurrency = cli.concurrency.unwrap_or_else(default_io_concurrency);
    let s3 = operator().await?;
    let metas = match cli.src_path {
        Some(path) => {
            let prefix = match cli.prefix.as_deref() {
                Some("") => anyhow::bail!("--prefix cannot be empty"),
                Some(p) => p,
                None => "/",
            };
            walk_convert_prefix_with_concurrency(
                Operator::new(Fs::default().root(&path.to_string_lossy()))?,
                s3,
                prefix,
                cli.delete_origin,
                concurrency,
            )
            .await?
        }
        None if cli.full_scan => {
            walk_convert_prefix_with_concurrency(
                s3.clone(),
                s3,
                "/",
                cli.delete_origin,
                concurrency,
            )
            .await?
        }
        None => {
            if let Some(prefix) = cli.prefix.as_deref() {
                if prefix.is_empty() {
                    anyhow::bail!("--prefix cannot be empty (use --full-scan for \"/\")");
                }
                walk_convert_prefix_with_concurrency(
                    s3.clone(),
                    s3,
                    prefix,
                    cli.delete_origin,
                    concurrency,
                )
                .await?
            } else {
                let cfg = QueueConfig::from_env(
                    cli.batch_size,
                    cli.visibility_timeout_secs,
                    cli.daemon,
                    Duration::from_secs(cli.poll_interval_secs),
                )?
                .with_concurrency(concurrency);
                return pull_convert_and_then(
                    s3.clone(),
                    s3,
                    cfg,
                    cli.delete_origin,
                    print_metadata,
                )
                .await;
            }
        }
    };
    print_metadata(metas)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_rejects_queue_flags_with_scan_modes_and_validates_concurrency() {
        assert!(Cli::try_parse_from(["img2webp", "--prefix", "album", "--batch-size", "16"]).is_err());
        assert!(Cli::try_parse_from(["img2webp", "--full-scan", "--poll-interval-secs", "5"]).is_err());
        assert!(
            Cli::try_parse_from(["img2webp", "/tmp/local", "--visibility-timeout-secs", "60"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["img2webp", "--concurrency", "0"]).is_err());
        assert!(Cli::try_parse_from(["img2webp", "--concurrency", "257"]).is_err());

        let parsed =
            Cli::try_parse_from(["img2webp", "--prefix", "album", "--concurrency", "12"]).unwrap();
        assert_eq!(parsed.concurrency, Some(12));
        assert_eq!(parsed.prefix.as_deref(), Some("album"));
    }
}
