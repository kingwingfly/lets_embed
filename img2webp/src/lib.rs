use std::{
    collections::{HashMap, HashSet},
    future::ready,
    path::Path,
    sync::LazyLock,
    thread::available_parallelism,
    time::Duration,
};

use db::{Image, Meta};
use futures::{StreamExt as _, TryStreamExt};
use libvips::{
    VipsApp, VipsImage,
    ops::{ForeignKeep, ForeignWebpPreset, WebpsaveBufferOptions, webpsave_buffer_with_opts},
};
use mime_guess::{MimeGuess, mime::IMAGE};
use opendal::{
    Operator,
    layers::{RetryLayer, TimeoutLayer},
    services::S3,
};
use tokio_util::sync::CancellationToken;

static CONCURRENT: LazyLock<usize> = LazyLock::new(|| {
    available_parallelism()
        .map(|count| (count.get() / 2).max(1))
        .unwrap_or(1)
});

pub async fn walk_convert(
    src_op: Operator,
    dst_op: Operator,
    delete_origin: bool,
) -> anyhow::Result<HashSet<Meta>> {
    let app = VipsApp::new("img2webp", false).expect("Cannot initialize libvips");
    app.concurrency_set(1);

    let entries = src_op.lister_with("/").recursive(true).await?;

    let mut metas: HashMap<String, Meta> = HashMap::new();
    let cancel = CancellationToken::new();

    let finished_paths = entries
        .take_until(cancel.cancelled())
        .inspect_err(|e| tracing::error!("{e}"))
        .filter_map(|e| ready(e.ok()))
        .filter(|e| {
            let mimes = MimeGuess::from_path(e.path());
            ready(
                e.metadata().is_file()
                    && !e.path().ends_with(".webp")
                    && (mimes.is_empty() || mimes.into_iter().any(|m| m.type_() == IMAGE)),
            )
        })
        .map(|e| e.into_parts().0)
        .map(async |path| Ok::<_, opendal::Error>((src_op.read(&path).await?, path)))
        .buffer_unordered(*CONCURRENT)
        .inspect_err(|e| tracing::error!("{e}"))
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
            tracing::error!("{e} {:?}", app.error_buffer());
            app.error_clear();
        })
        .filter_map(async |res| res.ok())
        .map(async |(path, bytes)| {
            let (new_path, key) = match path.rsplit_once(".") {
                Some((pre, ext))
                    if [
                        "jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "svg", "ico", "heic",
                    ]
                    .contains(&ext) =>
                {
                    (format!("{}.webp", pre), pre.to_string())
                }
                _ => (format!("{}.webp", path), path.to_owned()),
            };

            let imagesize::ImageSize { width, height } = imagesize::blob_size(&bytes)?;
            dst_op.write(&new_path, bytes).await?;
            if delete_origin {
                src_op.delete(&path).await?;
            }
            anyhow::Ok((path, new_path, key, (width, height)))
        })
        .buffer_unordered(*CONCURRENT)
        .inspect_err(|e| tracing::error!("{e}"))
        .filter_map(async |res| res.ok());

    let task = async {
        tokio::pin!(finished_paths);
        while let Some((path, new_path, key, (width, height))) = finished_paths.next().await {
            tracing::info!(path, new_path, "converted");
            let (title, author) = {
                let p = Path::new(&new_path);
                let title = p
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or("Unknown".to_string());
                let author = title
                    .split_whitespace()
                    .next()
                    .unwrap_or("Unknown")
                    .to_string();
                (title, author)
            };
            let meta = metas.entry(title.clone()).or_insert(Meta {
                title,
                ..Default::default()
            });
            if !meta.authors.contains(&author) {
                meta.authors.push(author);
            }
            let new_image = Image {
                name: key,
                width: width as i32,
                height: height as i32,
            };
            if !meta.images.contains(&new_image) {
                meta.images.push(new_image);
            }
        }
        metas.into_values().collect()
    };

    tokio::pin!(task);
    let metas = tokio::select! {
        res = &mut task => res,
        _ = tokio::signal::ctrl_c() => {
            cancel.cancel();
            task.await
        }
    };
    Ok(metas)
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
