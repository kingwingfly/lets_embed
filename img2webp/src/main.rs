use std::{
    future::ready,
    sync::{
        LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, available_parallelism},
    time::Duration,
};

use futures::{StreamExt as _, TryStreamExt};
use libvips::{
    VipsApp, VipsImage,
    ops::{ForeignKeep, ForeignWebpPreset, WebpsaveBufferOptions, webpsave_buffer_with_opts},
};
use opendal::Operator;
use tokio_util::sync::CancellationToken;

static FINISHED: AtomicU64 = AtomicU64::new(0);

static CONCURRENT: LazyLock<usize> = LazyLock::new(|| {
    available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
});

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let op = operator().await?;

    let app = VipsApp::new("img2webp", false).expect("Cannot initialize libvips");
    app.concurrency_set(1);

    let entries = op.lister_with("/").recursive(true).await?;

    thread::spawn(move || {
        loop {
            println!("Finished: {}", FINISHED.load(Ordering::Relaxed));
            thread::sleep(Duration::from_secs(5));
        }
    });

    let cancel = CancellationToken::new();

    let finished_paths = entries
        .take_until(cancel.cancelled())
        .filter_map(|e| ready(e.ok()))
        .filter(|e| {
            ready(
                e.metadata().is_file()
                    && [".webp", ".mp4", ".mov", ".mkv", ".avi"]
                        .into_iter()
                        .all(|s| !e.path().ends_with(s)),
            )
        })
        .map(|e| e.into_parts().0)
        .map(async |path| Ok::<_, opendal::Error>((op.read(&path).await?, path)))
        .buffer_unordered(*CONCURRENT)
        .inspect_err(|e| eprintln!("{e}"))
        .filter_map(async |res| res.ok())
        .map(async |(bytes, path)| {
            tokio::task::spawn_blocking(move || {
                let bytes = bytes.to_bytes();
                convert(&bytes)
            })
            .await
            .unwrap()
            .map(|bytes| (path, bytes))
        })
        .buffer_unordered(*CONCURRENT)
        .inspect_err(|e| {
            eprintln!("{e} {:?}", app.error_buffer());
            app.error_clear();
        })
        .filter_map(async |res| res.ok())
        .map(async |(path, bytes)| {
            op.write(&format!("{}.webp", path), bytes).await?;
            #[cfg(not(debug_assertions))]
            op.delete(&path).await?;
            Ok::<_, opendal::Error>(path)
        })
        .buffer_unordered(*CONCURRENT)
        .inspect_err(|e| eprintln!("{e}"))
        .filter_map(async |res| res.ok());

    let task = async {
        tokio::pin!(finished_paths);
        while finished_paths.next().await.is_some() {
            FINISHED.fetch_add(1, Ordering::Relaxed);
        }
    };

    tokio::pin!(task);
    tokio::select! {
        _ = &mut task => {},
        _ = tokio::signal::ctrl_c() => {
            cancel.cancel();
            task.await
        }
    }

    Ok(())
}

#[cfg(not(debug_assertions))]
#[derive(Debug)]
struct Config {
    endpoint: String,
    bucket: String,
    key_id: String,
    secret: String,
    region: String,
}

#[cfg(not(debug_assertions))]
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

#[cfg(debug_assertions)]
pub async fn operator() -> anyhow::Result<Operator> {
    use opendal::services::Fs;

    let op = Operator::new(Fs::default().root("assets"))?.finish();
    Ok(op)
}

#[cfg(not(debug_assertions))]
pub async fn operator() -> anyhow::Result<Operator> {
    use opendal::{
        layers::{RetryLayer, TimeoutLayer},
        services::S3,
    };

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

pub fn convert(bytes: &[u8]) -> Result<Vec<u8>, libvips::error::Error> {
    let inp = VipsImage::new_from_buffer(bytes, "")?;
    webpsave_buffer_with_opts(
        &inp,
        &WebpsaveBufferOptions {
            q: 80,
            preset: ForeignWebpPreset::Photo,
            // lossless: true,
            // near_lossless: true,
            // exact: true,
            alpha_q: 100,
            smart_subsample: true,
            keep: ForeignKeep::Icc,
            ..Default::default()
        },
    )
}
