use std::{path::PathBuf, time::Duration};

use clap::Parser;
use img2webp::walk_convert;
use opendal::{
    Operator,
    layers::{RetryLayer, TimeoutLayer},
    services::{Fs, S3},
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
struct Cli {
    path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "img2webp:info".parse().unwrap()),
        )
        .init();

    let op = match cli.path {
        None => operator().await?,
        Some(path) => Operator::new(Fs::default().root(&path.to_string_lossy()))?.finish(),
    };
    walk_convert(op).await?;
    Ok(())
}

#[derive(Debug)]
struct Config {
    endpoint: String,
    bucket: String,
    key_id: String,
    secret: String,
    region: String,
}

impl Config {
    fn new() -> Result<Self, dotenvy::Error> {
        dotenvy::dotenv().ok();
        Ok(Self {
            endpoint: dotenvy::var("R2_ENDPOINT").or_else(|_| dotenvy::var("S3_ENDPOINT"))?,
            bucket: dotenvy::var("R2_BUCKET").or_else(|_| dotenvy::var("S3_BUCKET"))?,
            key_id: dotenvy::var("R2_KEY_ID").or_else(|_| dotenvy::var("S3_KEY_ID"))?,
            secret: dotenvy::var("R2_SECRET_KEY").or_else(|_| dotenvy::var("S3_SECRET_KEY"))?,
            region: dotenvy::var("R2_REGION")
                .or_else(|_| dotenvy::var("S3_REGION"))
                .unwrap_or("auto".to_string()),
        })
    }
}

pub async fn operator() -> anyhow::Result<Operator> {
    let config = Config::new()?;
    let op = Operator::new(
        S3::default()
            .endpoint(&config.endpoint)
            .bucket(&config.bucket)
            .region(&config.region)
            .access_key_id(&config.key_id)
            .secret_access_key(&config.secret),
    )?
    .layer(
        RetryLayer::new()
            .with_max_times(3)
            .with_min_delay(Duration::from_millis(200))
            .with_max_delay(Duration::from_secs(10))
            .with_jitter(),
    )
    .layer(
        TimeoutLayer::new()
            .with_timeout(Duration::from_secs(600))
            .with_io_timeout(Duration::from_secs(300)),
    )
    .finish();
    Ok(op)
}
