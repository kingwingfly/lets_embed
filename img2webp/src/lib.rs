use std::{
    collections::{HashMap, HashSet},
    future::ready,
    path::Path,
    sync::LazyLock,
    thread::available_parallelism,
    time::Duration,
};

use anyhow::Context as _;
use db::{Image, Meta};
use futures::{StreamExt as _, TryStreamExt};
use libvips::{
    VipsApp, VipsImage,
    ops::{ForeignKeep, ForeignWebpPreset, WebpsaveBufferOptions, webpsave_buffer_with_opts},
};
use mime_guess::{MimeGuess, mime::IMAGE};
use opendal::{
    ErrorKind, Operator,
    layers::{RetryLayer, TimeoutLayer},
    services::S3,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

static CONCURRENT: LazyLock<usize> = LazyLock::new(|| {
    available_parallelism()
        .map(|count| (count.get() / 2).max(1))
        .unwrap_or(1)
});

const KNOWN_IMAGE_EXTS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "svg", "ico", "heic", "avif",
];

#[derive(Debug, Clone)]
pub struct QueueConfig {
    pub account_id: String,
    pub queue_id: String,
    pub api_token: String,
    pub batch_size: u8,
    pub visibility_timeout_ms: u64,
    pub daemon: bool,
    pub poll_interval: Duration,
}

impl QueueConfig {
    pub fn from_env(
        batch_size: u8,
        visibility_timeout_secs: u64,
        daemon: bool,
        poll_interval: Duration,
    ) -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        Ok(Self {
            account_id: dotenvy::var("CF_ACCOUNT_ID")
                .context("CF_ACCOUNT_ID is required in queue mode (or pass --prefix / --full-scan)")?,
            queue_id: dotenvy::var("CF_QUEUE_ID")
                .context("CF_QUEUE_ID is required in queue mode (or pass --prefix / --full-scan)")?,
            api_token: dotenvy::var("CF_API_TOKEN")
                .context("CF_API_TOKEN is required in queue mode (or pass --prefix / --full-scan)")?,
            batch_size: batch_size.clamp(1, 100),
            visibility_timeout_ms: visibility_timeout_secs.saturating_mul(1000).max(1000),
            daemon,
            poll_interval,
        })
    }
}

#[derive(Debug, Deserialize)]
struct PullEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
    result: Option<PullResult>,
}

#[derive(Debug, Deserialize)]
struct PullResult {
    #[serde(default)]
    messages: Vec<QueueMessage>,
}

#[derive(Debug, Deserialize)]
struct QueueMessage {
    id: String,
    lease_id: String,
    body: serde_json::Value,
    #[serde(default)]
    attempts: u32,
}

#[derive(Debug, Serialize)]
struct PullRequest {
    batch_size: u8,
    visibility_timeout_ms: u64,
}

#[derive(Debug, Serialize)]
struct AckRequest {
    acks: Vec<AckLease>,
    retries: Vec<RetryLease>,
}

#[derive(Debug, Serialize)]
struct AckLease {
    lease_id: String,
}

#[derive(Debug, Serialize)]
struct RetryLease {
    lease_id: String,
    delay_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct AckEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

pub async fn walk_convert(
    src_op: Operator,
    dst_op: Operator,
    delete_origin: bool,
) -> anyhow::Result<HashSet<Meta>> {
    walk_convert_prefix(src_op, dst_op, "/", delete_origin).await
}

pub async fn walk_convert_prefix(
    src_op: Operator,
    dst_op: Operator,
    prefix: &str,
    delete_origin: bool,
) -> anyhow::Result<HashSet<Meta>> {
    let app = VipsApp::new("img2webp", false).expect("Cannot initialize libvips");
    app.concurrency_set(1);

    let entries = src_op.lister_with(prefix).recursive(true).await?;

    let mut metas: HashMap<String, Meta> = HashMap::new();
    let cancel = CancellationToken::new();

    let finished_paths = entries
        .take_until(cancel.cancelled())
        .inspect_err(|e| tracing::error!("{e}"))
        .filter_map(|e| ready(e.ok()))
        .filter(|e| ready(e.metadata().is_file() && should_convert_path(e.path())))
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
            let (new_path, key) = target_paths(&path);
            let imagesize::ImageSize { width, height } = imagesize::blob_size(&bytes)?;
            dst_op.write(&new_path, bytes).await?;
            if delete_origin && path != new_path {
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
            record_meta(&mut metas, &new_path, key, width, height);
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

pub async fn pull_convert(
    src_op: Operator,
    dst_op: Operator,
    cfg: QueueConfig,
    delete_origin: bool,
) -> anyhow::Result<HashSet<Meta>> {
    let app = VipsApp::new("img2webp", false).expect("Cannot initialize libvips");
    app.concurrency_set(1);

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", cfg.api_token))
            .context("invalid CF_API_TOKEN header value")?,
    );
    let http = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()?;

    let base_url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/queues/{}/messages",
        cfg.account_id, cfg.queue_id
    );
    let pull_url = format!("{base_url}/pull");
    let ack_url = format!("{base_url}/ack");

    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    let ctrl_c_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("SIGINT received, draining current batch");
            signal_cancel.cancel();
        }
    });

    let mut metas: HashMap<String, Meta> = HashMap::new();

    while !cancel.is_cancelled() {
        let messages = tokio::select! {
            _ = cancel.cancelled() => break,
            res = pull_messages(&http, &pull_url, cfg.batch_size, cfg.visibility_timeout_ms) => res?,
        };

        if messages.is_empty() {
            if !cfg.daemon {
                break;
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(cfg.poll_interval) => continue,
            }
        }

        tracing::info!(count = messages.len(), "pulled queue batch");

        let mut acks = Vec::with_capacity(messages.len());
        let mut retries = Vec::new();
        let mut work_items = Vec::new();

        for msg in messages {
            let Some(key) = extract_message_key(&msg.body) else {
                tracing::debug!(id = %msg.id, "ignoring non-upload queue message");
                acks.push(AckLease {
                    lease_id: msg.lease_id,
                });
                continue;
            };
            if !should_convert_path(&key) {
                tracing::debug!(id = %msg.id, %key, "skipping non-image or already-webp key");
                acks.push(AckLease {
                    lease_id: msg.lease_id,
                });
                continue;
            }
            work_items.push((msg.id, msg.lease_id, msg.attempts, key));
        }

        let results: Vec<_> = futures::stream::iter(work_items)
            .map(|(id, lease_id, attempts, key)| {
                let src_op = src_op.clone();
                let dst_op = dst_op.clone();
                let app = &app;
                async move {
                    let res = convert_one(&src_op, &dst_op, &key, delete_origin, app).await;
                    (id, lease_id, attempts, key, res)
                }
            })
            .buffer_unordered(*CONCURRENT)
            .collect()
            .await;

        for (id, lease_id, attempts, key, res) in results {
            match res {
                Ok(Some((new_path, meta_key, (width, height)))) => {
                    tracing::info!(path = %key, %new_path, "converted");
                    record_meta(&mut metas, &new_path, meta_key, width, height);
                    acks.push(AckLease { lease_id });
                }
                Ok(None) => {
                    acks.push(AckLease { lease_id });
                }
                Err(e) => {
                    tracing::error!(id = %id, %key, attempts, error = %e, "conversion failed; scheduling retry");
                    retries.push(RetryLease {
                        lease_id,
                        delay_seconds: 30,
                    });
                }
            }
        }

        if !acks.is_empty() || !retries.is_empty() {
            ack_messages(&http, &ack_url, AckRequest { acks, retries }).await?;
        }
    }

    ctrl_c_task.abort();
    Ok(metas.into_values().collect())
}

async fn pull_messages(
    http: &reqwest::Client,
    pull_url: &str,
    batch_size: u8,
    visibility_timeout_ms: u64,
) -> anyhow::Result<Vec<QueueMessage>> {
    let resp: PullEnvelope = http
        .post(pull_url)
        .json(&PullRequest {
            batch_size,
            visibility_timeout_ms,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if !resp.success {
        anyhow::bail!("cloudflare queue pull failed: {:?}", resp.errors);
    }
    Ok(resp.result.map(|r| r.messages).unwrap_or_default())
}

async fn ack_messages(
    http: &reqwest::Client,
    ack_url: &str,
    req: AckRequest,
) -> anyhow::Result<()> {
    let mut last_err = None;
    for attempt in 0..3 {
        match async {
            let resp: AckEnvelope = http
                .post(ack_url)
                .json(&req)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if !resp.success {
                anyhow::bail!("cloudflare queue ack failed: {:?}", resp.errors);
            }
            anyhow::Ok(())
        }
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(attempt = attempt + 1, error = %e, "queue ack failed, retrying");
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(200 * (1 << attempt))).await;
            }
        }
    }
    Err(last_err.unwrap())
}

async fn convert_one(
    src_op: &Operator,
    dst_op: &Operator,
    path: &str,
    delete_origin: bool,
    app: &VipsApp,
) -> anyhow::Result<Option<(String, String, (usize, usize))>> {
    let (new_path, meta_key) = target_paths(path);

    let buf = match src_op.read(path).await {
        Ok(buf) => buf,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if dst_op.exists(&new_path).await? {
                tracing::debug!(path, %new_path, "already converted, skipping");
            } else {
                tracing::warn!(path, "source object missing in storage, skipping");
            }
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };

    let webp_bytes = tokio::task::spawn_blocking(move || {
        let raw = buf.to_bytes();
        convert(&raw)
    })
    .await?
    .map_err(|e| {
        tracing::error!("{e} {:?}", app.error_buffer());
        app.error_clear();
        anyhow::anyhow!("libvips convert failed for {path}: {e}")
    })?;

    let imagesize::ImageSize { width, height } = imagesize::blob_size(&webp_bytes)?;
    dst_op.write(&new_path, webp_bytes).await?;
    if delete_origin && path != new_path {
        src_op.delete(path).await?;
    }
    Ok(Some((new_path, meta_key, (width, height))))
}

fn extract_message_key(body: &serde_json::Value) -> Option<String> {
    match body {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.starts_with('{')
                && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed)
            {
                return extract_message_key(&parsed);
            }
            (!trimmed.is_empty()).then(|| s.clone())
        }
        serde_json::Value::Object(map) => {
            if let Some(action) = map.get("action").and_then(|v| v.as_str())
                && action.starts_with("Delete")
            {
                return None;
            }
            if let Some(key) = map.get("key").and_then(|v| v.as_str()) {
                return (!key.is_empty()).then(|| key.to_owned());
            }
            map.get("object")
                .and_then(|obj| obj.get("key"))
                .and_then(|v| v.as_str())
                .filter(|k| !k.is_empty())
                .map(ToOwned::to_owned)
        }
        _ => None,
    }
}

fn should_convert_path(path: &str) -> bool {
    if path.is_empty() || path.ends_with('/') {
        return false;
    }
    if path.to_ascii_lowercase().ends_with(".webp") {
        return false;
    }
    let mimes = MimeGuess::from_path(path);
    mimes.is_empty() || mimes.into_iter().any(|m| m.type_() == IMAGE)
}

fn target_paths(path: &str) -> (String, String) {
    match path.rsplit_once('.') {
        Some((pre, ext))
            if KNOWN_IMAGE_EXTS.contains(&ext.to_ascii_lowercase().as_str()) =>
        {
            (format!("{pre}.webp"), pre.to_owned())
        }
        _ => (format!("{path}.webp"), path.to_owned()),
    }
}

fn record_meta(
    metas: &mut HashMap<String, Meta>,
    new_path: &str,
    key: String,
    width: usize,
    height: usize,
) {
    let (title, author) = {
        let p = Path::new(new_path);
        let title = p
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string());
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
    );
    Ok(op)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_key_formats() {
        assert_eq!(
            extract_message_key(&serde_json::json!({ "key": "post/photo 1" })),
            Some("post/photo 1".to_string())
        );
        assert_eq!(
            extract_message_key(&serde_json::json!({
                "action": "PutObject",
                "object": { "key": "post/photo 2", "size": 123 }
            })),
            Some("post/photo 2".to_string())
        );
        assert_eq!(
            extract_message_key(&serde_json::json!({
                "action": "DeleteObject",
                "object": { "key": "post/photo 2" }
            })),
            None
        );
        assert_eq!(
            extract_message_key(&serde_json::json!(r#"{"key":"post/photo 3"}"#)),
            Some("post/photo 3".to_string())
        );
    }

    #[test]
    fn filter_and_target_paths() {
        assert!(should_convert_path("foo/bar - photo 1"));
        assert!(should_convert_path("foo/bar.jpg"));
        assert!(!should_convert_path("foo/bar.webp"));
        assert!(!should_convert_path("foo/bar.WEBP"));
        assert!(!should_convert_path("foo/video.mp4"));
        assert!(!should_convert_path("foo/"));

        assert_eq!(
            target_paths("foo/bar - photo 1"),
            ("foo/bar - photo 1.webp".to_string(), "foo/bar - photo 1".to_string())
        );
        assert_eq!(
            target_paths("foo/bar.PNG"),
            ("foo/bar.webp".to_string(), "foo/bar".to_string())
        );
    }
}
