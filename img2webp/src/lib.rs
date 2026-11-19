use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::ready,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    thread::available_parallelism,
    time::{Duration, SystemTime},
};

use anyhow::{Context as _, bail};
use base64::Engine as _;
use db::{Image, Meta};
use futures::{StreamExt as _, TryStreamExt, stream::FuturesUnordered};
use libvips::{
    VipsApp, VipsImage,
    ops::{ForeignKeep, ForeignWebpPreset, WebpsaveBufferOptions, webpsave_buffer_with_opts},
};
use mime_guess::{MimeGuess, mime::IMAGE};
use opendal::{
    ErrorKind, Metadata, Operator,
    layers::{RetryLayer, TimeoutLayer},
    services::S3,
};
use reqwest::{
    StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue, RETRY_AFTER},
};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::{
    sync::Semaphore,
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;

static VIPS: LazyLock<Result<VipsApp, String>> = LazyLock::new(|| {
    let app = VipsApp::new("img2webp", false).map_err(|e| e.to_string())?;
    app.concurrency_set(1);
    Ok(app)
});

fn ensure_vips() -> anyhow::Result<()> {
    match &*VIPS {
        Ok(_) => Ok(()),
        Err(msg) => bail!("Cannot initialize libvips: {msg}"),
    }
}

pub fn default_io_concurrency() -> usize {
    available_parallelism()
        .map(|count| count.get().saturating_mul(2).clamp(4, 32))
        .unwrap_or(4)
}

fn cpu_concurrency() -> usize {
    available_parallelism()
        .map(|count| count.get().max(1))
        .unwrap_or(1)
}

const KNOWN_IMAGE_EXTS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "svg", "ico", "heic", "avif", "bin",
];

const MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const SOURCE_BYTE_BUDGET: usize = 256 * 1024 * 1024;
const MAX_IMAGE_PIXELS: usize = 100_000_000;
const MAX_RETRY_AFTER_SECS: u64 = 900;
const RETRY_DELAY_SECS: u64 = 15;
const ONE_SHOT_MAX_SETTLE_ROUNDS: u8 = 2;
const DEFAULT_CF_API_BASE_URL: &str = "https://api.cloudflare.com";

#[derive(Clone)]
pub struct QueueConfig {
    pub account_id: String,
    pub queue_id: String,
    pub api_token: String,
    pub batch_size: u8,
    pub visibility_timeout_ms: u64,
    pub daemon: bool,
    pub poll_interval: Duration,
    pub concurrency: usize,
}

impl fmt::Debug for QueueConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueueConfig")
            .field("account_id", &self.account_id)
            .field("queue_id", &self.queue_id)
            .field("api_token", &"[REDACTED]")
            .field("batch_size", &self.batch_size)
            .field("visibility_timeout_ms", &self.visibility_timeout_ms)
            .field("daemon", &self.daemon)
            .field("poll_interval", &self.poll_interval)
            .field("concurrency", &self.concurrency)
            .finish()
    }
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
            visibility_timeout_ms: visibility_timeout_secs
                .clamp(1, 43_200)
                .saturating_mul(1000),
            daemon,
            poll_interval: poll_interval.max(Duration::from_secs(1)),
            concurrency: default_io_concurrency(),
        })
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.account_id.trim().is_empty() {
            bail!("CF_ACCOUNT_ID cannot be empty");
        }
        if self.queue_id.trim().is_empty() {
            bail!("CF_QUEUE_ID cannot be empty");
        }
        if self.api_token.trim().is_empty() {
            bail!("CF_API_TOKEN cannot be empty");
        }
        if !(1..=100).contains(&self.batch_size) {
            bail!("batch_size must be in 1..=100");
        }
        if !(1_000..=43_200_000).contains(&self.visibility_timeout_ms) {
            bail!("visibility_timeout_ms must be in 1000..=43200000");
        }
        if self.daemon && self.poll_interval < Duration::from_secs(1) {
            bail!("poll_interval must be >= 1s in daemon mode");
        }
        if !(1..=256).contains(&self.concurrency) {
            bail!("concurrency must be in 1..=256");
        }
        Ok(())
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug, Deserialize)]
struct PullEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
    result: Option<PullResultRaw>,
}

#[derive(Debug, Deserialize)]
struct PullResultRaw {
    #[serde(default)]
    messages: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct QueueMessage {
    #[serde(default)]
    id: Option<String>,
    lease_id: String,
    body: serde_json::Value,
    #[serde(default)]
    metadata: HashMap<String, serde_json::Value>,
    #[serde(default)]
    attempts: u32,
}

#[derive(Debug, Serialize)]
struct PullRequest {
    batch_size: u8,
    visibility_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct AckRequest {
    acks: Vec<AckLease>,
    retries: Vec<RetryLease>,
}

#[derive(Debug, Clone, Serialize)]
struct AckLease {
    lease_id: String,
}

#[derive(Debug, Clone, Serialize)]
struct RetryLease {
    lease_id: String,
    delay_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct AckEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
    result: Option<AckResult>,
}

fn deserialize_warnings<'de, D>(deserializer: D) -> Result<HashMap<String, serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WarningsShape {
        Map(HashMap<String, serde_json::Value>),
        List(Vec<serde_json::Value>),
        Null,
    }
    match WarningsShape::deserialize(deserializer)? {
        WarningsShape::Map(m) => Ok(m),
        WarningsShape::List(v) => Ok(v
            .into_iter()
            .enumerate()
            .map(|(i, val)| (format!("item_{i}"), val))
            .collect()),
        WarningsShape::Null => Ok(HashMap::new()),
    }
}

#[derive(Debug, Default, Deserialize)]
struct AckResult {
    #[serde(default, alias = "ackCount")]
    ack_count: Option<usize>,
    #[serde(default, alias = "retryCount")]
    retry_count: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_warnings")]
    warnings: HashMap<String, serde_json::Value>,
}

#[derive(Debug)]
struct AckOutcome {
    complete: bool,
    exhausted_retries: usize,
    max_retry_delay_secs: Option<u64>,
}

impl AckResult {
    fn outcome(&self, req: &AckRequest) -> AckOutcome {
        let mut exhausted_retries = 0;
        let mut max_retry_delay_secs = None;
        for retry in &req.retries {
            let warning = self.warnings.get(&retry.lease_id).and_then(|v| v.as_str());
            if warning == Some("Message has exhausted maxRetries") {
                exhausted_retries += 1;
            } else {
                max_retry_delay_secs =
                    Some(retry.delay_seconds.max(max_retry_delay_secs.unwrap_or(0)));
            }
        }

        if exhausted_retries > 0 {
            tracing::warn!(
                exhausted_retries,
                "Cloudflare queue messages reached the retry limit"
            );
        }
        // Each exhausted lease can explain one missing retry in the response counts.
        let complete = self.warnings.len() == exhausted_retries
            && self.ack_count.is_none_or(|n| n >= req.acks.len())
            && self
                .retry_count
                .is_none_or(|n| n >= req.retries.len() - exhausted_retries);
        if !complete {
            tracing::warn!(
                sent_acks = req.acks.len(),
                ack_count = ?self.ack_count,
                sent_retries = req.retries.len(),
                retry_count = ?self.retry_count,
                warning_count = self.warnings.len(),
                exhausted_retries,
                "cloudflare queue ack had warnings or short counts"
            );
        }
        AckOutcome {
            complete,
            exhausted_retries,
            max_retry_delay_secs,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum MessageAction {
    Convert(String),
    Ignore(&'static str),
    Malformed,
}

enum ApiError {
    Transient(anyhow::Error, Option<Duration>),
    Fatal(anyhow::Error),
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => tracing::info!("SIGINT received, draining current work"),
                    _ = sigterm.recv() => tracing::info!("SIGTERM received, draining current work"),
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler, listening for SIGINT only");
                let _ = ctrl_c.await;
                tracing::info!("SIGINT received, draining current work");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
        tracing::info!("SIGINT received, draining current work");
    }
}

fn normalize_scan_prefix(prefix: &str) -> anyhow::Result<String> {
    if prefix.is_empty() {
        bail!("prefix cannot be empty (use \"/\" for root)");
    }
    if prefix == "/" {
        return Ok("/".to_string());
    }
    if prefix.ends_with('/') {
        Ok(prefix.to_string())
    } else {
        Ok(format!("{prefix}/"))
    }
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
    walk_convert_prefix_with_concurrency(
        src_op,
        dst_op,
        prefix,
        delete_origin,
        default_io_concurrency(),
    )
    .await
}

pub async fn walk_convert_prefix_with_concurrency(
    src_op: Operator,
    dst_op: Operator,
    prefix: &str,
    delete_origin: bool,
    concurrency: usize,
) -> anyhow::Result<HashSet<Meta>> {
    if !(1..=256).contains(&concurrency) {
        bail!("concurrency must be in 1..=256");
    }
    let prefix = normalize_scan_prefix(prefix)?;
    ensure_vips()?;

    let entries = src_op.lister_with(&prefix).recursive(true).await?;

    let mut metas: HashMap<String, Meta> = HashMap::new();
    let cancel = CancellationToken::new();
    let _signal_guard = AbortOnDrop(tokio::spawn({
        let cancel = cancel.clone();
        async move {
            shutdown_signal().await;
            cancel.cancel();
        }
    }));

    let byte_sem = Arc::new(Semaphore::new(SOURCE_BYTE_BUDGET));
    let cpu_sem = Arc::new(Semaphore::new(cpu_concurrency()));
    let finished_paths = entries
        .take_until(cancel.cancelled())
        .try_filter(|e| ready(e.metadata().is_file() && should_convert_path(e.path())))
        .map(async |entry| {
            let (path, entry_meta) = entry?.into_parts();
            let outcome = convert_object(
                &src_op,
                &dst_op,
                &path,
                Some(&entry_meta),
                delete_origin,
                true,
                1,
                &byte_sem,
                &cpu_sem,
            )
            .await;
            Ok::<_, opendal::Error>((path, outcome))
        })
        .buffer_unordered(concurrency);

    let mut first_list_error = None;
    let mut item_errors = 0usize;
    let mut examples = Vec::new();
    tokio::pin!(finished_paths);
    while let Some(entry) = finished_paths.next().await {
        let (path, outcome) = match entry {
            Ok(item) => item,
            Err(e) => {
                tracing::error!(error = %e, "storage list failed");
                first_list_error.get_or_insert(e);
                continue;
            }
        };
        match outcome {
            Ok(ConvertOutcome::Converted {
                new_path,
                meta_key,
                size: (width, height),
            }) => {
                tracing::info!(path, new_path, "converted");
                record_meta(&mut metas, &new_path, meta_key, width, height);
            }
            Ok(ConvertOutcome::SkippedWithMeta {
                new_path,
                meta_key,
                size: (width, height),
            }) => {
                tracing::debug!(path, new_path, "unchanged, skipping conversion");
                record_meta(&mut metas, &new_path, meta_key, width, height);
            }
            Ok(ConvertOutcome::SkippedNoMeta) => {}
            Err(e) => {
                tracing::error!(key = ?path, error = %format_args!("{e:#}"), "scan item conversion failed");
                item_errors += 1;
                if examples.len() < 3 {
                    examples.push(format!("  {path:?}: {e:#}"));
                }
            }
        }
    }

    let list_failed = first_list_error.is_some();
    let summary = if cancel.is_cancelled() {
        format!(
            "walk interrupted by signal after converting {} image(s) (errors={item_errors})",
            metas.values().map(|m| m.images.len()).sum::<usize>()
        )
    } else if list_failed || item_errors > 0 {
        format!("walk completed with errors (list_failed={list_failed}, item_errors={item_errors})")
    } else {
        return Ok(metas.into_values().collect());
    };
    if let Some(error) = first_list_error {
        examples.insert(0, format!("  listing {prefix:?}: {error}"));
    }
    examples.insert(0, summary);
    bail!("{}", examples.join("\n"))
}

fn one_shot_journal_path(cfg: &QueueConfig) -> PathBuf {
    if let Ok(path) = std::env::var("IMG2WEBP_META_JOURNAL")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
    }
    let sanitize_id = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    std::env::temp_dir().join(format!(
        "img2webp-meta-{}-{}.json",
        sanitize_id(&cfg.account_id),
        sanitize_id(&cfg.queue_id),
    ))
}

fn load_journal(path: &Path) -> anyhow::Result<HashMap<String, Meta>> {
    match std::fs::File::open(path) {
        Ok(file) => serde_json::from_reader(file)
            .with_context(|| format!("failed to parse metadata journal {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(anyhow::Error::from(e))
            .with_context(|| format!("failed to open metadata journal {}", path.display())),
    }
}

fn persist_journal(path: &Path, metas: &HashMap<String, Meta>) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec(metas)?;
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub async fn pull_convert(
    src_op: Operator,
    dst_op: Operator,
    cfg: QueueConfig,
    delete_origin: bool,
) -> anyhow::Result<HashSet<Meta>> {
    let cancel = CancellationToken::new();
    let _signal_guard = AbortOnDrop(tokio::spawn({
        let cancel = cancel.clone();
        async move {
            shutdown_signal().await;
            cancel.cancel();
        }
    }));
    pull_convert_inner(
        src_op,
        dst_op,
        cfg,
        delete_origin,
        DEFAULT_CF_API_BASE_URL,
        None,
        cancel,
    )
    .await
}

async fn pull_convert_inner(
    src_op: Operator,
    dst_op: Operator,
    cfg: QueueConfig,
    delete_origin: bool,
    api_base_url: &str,
    journal_override: Option<&Path>,
    cancel: CancellationToken,
) -> anyhow::Result<HashSet<Meta>> {
    cfg.validate()?;
    ensure_vips()?;

    let expected_bucket = (src_op.info().scheme() == "s3" && !src_op.info().name().is_empty())
        .then(|| src_op.info().name().to_string());

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", cfg.api_token))
            .context("invalid CF_API_TOKEN header value")?,
    );
    let http = reqwest::Client::builder()
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;

    let base_url = format!(
        "{}/client/v4/accounts/{}/queues/{}/messages",
        api_base_url.trim_end_matches('/'),
        cfg.account_id,
        cfg.queue_id
    );
    let pull_url = format!("{base_url}/pull");
    let ack_url = format!("{base_url}/ack");

    let collect_meta = !cfg.daemon;
    let journal_path = collect_meta.then(|| {
        journal_override
            .map(Path::to_path_buf)
            .unwrap_or_else(|| one_shot_journal_path(&cfg))
    });
    let mut metas: HashMap<String, Meta> = match &journal_path {
        Some(p) => load_journal(p)?,
        None => HashMap::new(),
    };
    let mut journal_dirty = false;
    let mut retry_wait_until: Option<Instant> = None;
    let mut retry_not_before: Option<Instant> = None;
    let mut settle_rounds: u8 = 0;
    let mut exhausted_retries = 0usize;

    let io_concurrency = cfg.concurrency;
    let byte_sem = Arc::new(Semaphore::new(SOURCE_BYTE_BUDGET));
    let cpu_sem = Arc::new(Semaphore::new(cpu_concurrency()));

    let visibility_timeout = Duration::from_millis(cfg.visibility_timeout_ms);
    let reserve = (visibility_timeout / 4).min(Duration::from_secs(30));
    let flush_interval =
        (visibility_timeout / 4).clamp(Duration::from_secs(1), Duration::from_secs(15));
    let flush_threshold = (io_concurrency * 2).max(8);

    while !cancel.is_cancelled() {
        let Some((batch_started, messages, parse_err_count)) = pull_with_retry(
            &http,
            &pull_url,
            cfg.batch_size,
            cfg.visibility_timeout_ms,
            cfg.daemon,
            cfg.poll_interval,
            &cancel,
            &mut retry_not_before,
            &mut retry_wait_until,
        )
        .await?
        else {
            break;
        };

        if cancel.is_cancelled() {
            if !messages.is_empty() {
                let retries: Vec<RetryLease> = messages
                    .into_iter()
                    .map(|m| RetryLease {
                        lease_id: m.lease_id,
                        delay_seconds: 0,
                    })
                    .collect();
                let _ = ack_messages(
                    &http,
                    &ack_url,
                    &AckRequest {
                        acks: Vec::new(),
                        retries,
                    },
                    &mut retry_not_before,
                )
                .await;
            }
            break;
        }

        if messages.is_empty() && parse_err_count == 0 {
            if !cfg.daemon {
                if let Some(until) = retry_wait_until.take() {
                    if settle_rounds < ONE_SHOT_MAX_SETTLE_ROUNDS {
                        settle_rounds += 1;
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep_until(until) => continue,
                        }
                    } else {
                        bail!(
                            "one-shot settle budget exhausted with retries/uncertain pulls still pending"
                        );
                    }
                }
                break;
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(cfg.poll_interval) => continue,
            }
        }

        tracing::info!(
            count = messages.len(),
            parse_errors = parse_err_count,
            "pulled queue batch"
        );

        if !cfg.daemon && parse_err_count > 0 {
            let until = batch_started + visibility_timeout + Duration::from_secs(2);
            update_max_deadline(&mut retry_wait_until, until);
        }

        let deadline = batch_started + visibility_timeout.saturating_sub(reserve);

        let mut acks: Vec<AckLease> = Vec::with_capacity(messages.len());
        let mut retries: Vec<RetryLease> = Vec::new();
        let mut work_items = Vec::new();

        for msg in messages {
            let msg_id = msg.id.as_deref().unwrap_or("<none>");
            match decode_and_classify_message(&msg, expected_bucket.as_deref()) {
                MessageAction::Ignore(reason) => {
                    tracing::debug!(id = %msg_id, reason, "ignoring non-upload queue message");
                    acks.push(AckLease {
                        lease_id: msg.lease_id,
                    });
                }
                MessageAction::Malformed => {
                    tracing::warn!(
                        id = %msg_id,
                        attempts = msg.attempts,
                        content_type = message_content_type(&msg).unwrap_or("<none>"),
                        meta_keys = ?msg.metadata.keys().collect::<Vec<_>>(),
                        body_preview = %body_preview(&msg.body),
                        "unrecognized or unsafe queue message payload; scheduling retry"
                    );
                    retries.push(RetryLease {
                        lease_id: msg.lease_id,
                        delay_seconds: RETRY_DELAY_SECS,
                    });
                }
                MessageAction::Convert(key) => {
                    if !should_convert_path(&key) {
                        tracing::debug!(id = %msg_id, %key, "skipping non-image or already-webp key");
                        acks.push(AckLease {
                            lease_id: msg.lease_id,
                        });
                    } else {
                        work_items.push((
                            msg.id.unwrap_or_default(),
                            msg.lease_id,
                            msg.attempts,
                            key,
                        ));
                    }
                }
            }
        }

        let mut flush_tick = tokio::time::interval(flush_interval);
        flush_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        flush_tick.tick().await;

        let mut pending = work_items.into_iter();
        let mut in_flight = FuturesUnordered::new();
        let mut stopping = false;
        let mut periodic_flush_due = false;
        let mut ack_disabled = false;
        let mut journal_err: Option<anyhow::Error> = None;
        let mut ack_fatal_err: Option<anyhow::Error> = None;
        let mut ack_transient_err: Option<anyhow::Error> = None;
        let mut incomplete_batch = false;
        let mut transient_ack_abort = false;
        let mut active_ack: Option<tokio::task::JoinHandle<AckTaskResult>> = None;

        let spawn_item = |(id, lease_id, attempts, key): (String, String, u32, String)| {
            let src_op = src_op.clone();
            let dst_op = dst_op.clone();
            let byte_sem = Arc::clone(&byte_sem);
            let cpu_sem = Arc::clone(&cpu_sem);
            async move {
                let res = convert_object(
                    &src_op,
                    &dst_op,
                    &key,
                    None,
                    delete_origin,
                    collect_meta,
                    attempts,
                    &byte_sem,
                    &cpu_sem,
                )
                .await;
                (id, lease_id, attempts, key, res)
            }
        };

        loop {
            if !stopping && (cancel.is_cancelled() || Instant::now() >= deadline) {
                stopping = true;
                requeue_unstarted(&mut pending, &mut retries);
            }

            if !stopping {
                while in_flight.len() < io_concurrency
                    && !cancel.is_cancelled()
                    && Instant::now() < deadline
                {
                    let Some(item) = pending.next() else {
                        break;
                    };
                    in_flight.push(spawn_item(item));
                }
                if cancel.is_cancelled() || Instant::now() >= deadline {
                    stopping = true;
                    requeue_unstarted(&mut pending, &mut retries);
                }
            }

            let all_work_done = in_flight.is_empty() && pending.as_slice().is_empty();
            let should_flush = active_ack.is_none()
                && !ack_disabled
                && (!acks.is_empty() || !retries.is_empty())
                && (all_work_done
                    || stopping
                    || periodic_flush_due
                    || acks.len() + retries.len() >= flush_threshold);
            periodic_flush_due = false;

            if should_flush {
                if collect_meta && journal_dirty && let Some(jp) = &journal_path {
                    if let Err(e) = persist_journal(jp, &metas) {
                        tracing::error!(
                            error = %e,
                            "failed to persist metadata journal; withholding unpersisted acks"
                        );
                        if journal_err.is_none() {
                            journal_err = Some(e);
                        }
                        stopping = true;
                        requeue_unstarted(&mut pending, &mut retries);
                        for a in acks.drain(..) {
                            retries.push(RetryLease {
                                lease_id: a.lease_id,
                                delay_seconds: RETRY_DELAY_SECS,
                            });
                        }
                    } else {
                        journal_dirty = false;
                    }
                } else if journal_err.is_some() && !acks.is_empty() {
                    for a in acks.drain(..) {
                        retries.push(RetryLease {
                            lease_id: a.lease_id,
                            delay_seconds: RETRY_DELAY_SECS,
                        });
                    }
                }

                if !acks.is_empty() || !retries.is_empty() {
                    active_ack = Some(spawn_ack_task(
                        &http,
                        &ack_url,
                        std::mem::take(&mut acks),
                        std::mem::take(&mut retries),
                    ));
                }
            }

            // Every exit path waits until all in-flight conversions and active_ack finish.
            if in_flight.is_empty() && active_ack.is_none() {
                debug_assert!(pending.as_slice().is_empty());
                break;
            }

            tokio::select! {
                Some((id, lease_id, attempts, key, res)) = in_flight.next(), if !in_flight.is_empty() => {
                    match res {
                        Ok(ConvertOutcome::Converted {
                            new_path,
                            meta_key,
                            size: (width, height),
                        }) => {
                            tracing::info!(path = %key, %new_path, "converted");
                            if collect_meta {
                                record_meta(&mut metas, &new_path, meta_key, width, height);
                                journal_dirty = true;
                            }
                            if journal_err.is_some() {
                                retries.push(RetryLease {
                                    lease_id,
                                    delay_seconds: RETRY_DELAY_SECS,
                                });
                            } else {
                                acks.push(AckLease { lease_id });
                            }
                        }
                        Ok(ConvertOutcome::SkippedWithMeta {
                            new_path,
                            meta_key,
                            size: (width, height),
                        }) => {
                            if collect_meta {
                                record_meta(&mut metas, &new_path, meta_key, width, height);
                                journal_dirty = true;
                            }
                            if journal_err.is_some() {
                                retries.push(RetryLease {
                                    lease_id,
                                    delay_seconds: RETRY_DELAY_SECS,
                                });
                            } else {
                                acks.push(AckLease { lease_id });
                            }
                        }
                        Ok(ConvertOutcome::SkippedNoMeta) => {
                            acks.push(AckLease { lease_id });
                        }
                        Err(e) => {
                            tracing::error!(
                                cause = %e.root_cause(),
                                id = %id,
                                attempts,
                                error = %format_args!("{e:#}"),
                                %key,
                                "conversion failed; scheduling retry"
                            );
                            retries.push(RetryLease {
                                lease_id,
                                delay_seconds: RETRY_DELAY_SECS,
                            });
                        }
                    }
                }
                join_res = async { active_ack.as_mut().unwrap().await }, if active_ack.is_some() => {
                    active_ack = None;
                    match join_res {
                        Ok((task_rnb, Ok(outcome))) => {
                            if let Some(rnb) = task_rnb {
                                update_max_deadline(&mut retry_not_before, rnb);
                            }
                            if !cfg.daemon {
                                exhausted_retries += outcome.exhausted_retries;
                                if let Some(delay) = outcome.max_retry_delay_secs {
                                    update_max_deadline(
                                        &mut retry_wait_until,
                                        Instant::now() + Duration::from_secs(delay + 2),
                                    );
                                }
                                if !outcome.complete {
                                    incomplete_batch = true;
                                    stopping = true;
                                    requeue_unstarted(&mut pending, &mut retries);
                                }
                            }
                        }
                        Ok((task_rnb, Err(ApiError::Transient(err, maybe_rnb)))) => {
                            if let Some(rnb) = task_rnb {
                                update_max_deadline(&mut retry_not_before, rnb);
                            }
                            if let Some(rnb) = maybe_rnb {
                                update_max_deadline(&mut retry_not_before, Instant::now() + rnb);
                            }
                            if cfg.daemon {
                                tracing::warn!(
                                    error = %err,
                                    "transient ack failure in daemon mode; stopping new work for this batch"
                                );
                                transient_ack_abort = true;
                            } else if ack_transient_err.is_none() {
                                ack_transient_err = Some(err);
                            }
                            ack_disabled = true;
                            stopping = true;
                            requeue_unstarted(&mut pending, &mut retries);
                        }
                        Ok((task_rnb, Err(ApiError::Fatal(err)))) => {
                            if let Some(rnb) = task_rnb {
                                update_max_deadline(&mut retry_not_before, rnb);
                            }
                            if ack_fatal_err.is_none() {
                                ack_fatal_err = Some(err);
                            }
                            ack_disabled = true;
                            stopping = true;
                            requeue_unstarted(&mut pending, &mut retries);
                        }
                        Err(e) => {
                            if ack_fatal_err.is_none() {
                                ack_fatal_err = Some(anyhow::anyhow!("ack task panicked: {e}"));
                            }
                            ack_disabled = true;
                            stopping = true;
                            requeue_unstarted(&mut pending, &mut retries);
                        }
                    }
                }
                _ = flush_tick.tick(), if active_ack.is_none() && !ack_disabled && (!acks.is_empty() || !retries.is_empty()) => {
                    periodic_flush_due = true;
                }
                _ = cancel.cancelled(), if !stopping => {}
                _ = tokio::time::sleep_until(deadline), if !stopping => {
                    tracing::warn!("batch approaching visibility timeout, requeuing unstarted leases");
                    stopping = true;
                    requeue_unstarted(&mut pending, &mut retries);
                }
            }
        }

        if collect_meta
            && journal_dirty
            && journal_err.is_none()
            && let Some(jp) = &journal_path
            && let Err(e) = persist_journal(jp, &metas)
        {
            journal_err = Some(e);
        }

        // Best-effort release of unstarted/failed leases if an earlier ack failed transiently.
        if (transient_ack_abort || ack_transient_err.is_some())
            && ack_fatal_err.is_none()
            && !retries.is_empty()
        {
            let release_req = AckRequest {
                acks: Vec::new(),
                retries: std::mem::take(&mut retries),
            };
            if let Err(ApiError::Transient(_, Some(ra))) =
                ack_once(&http, &ack_url, &release_req).await
            {
                update_max_deadline(&mut retry_not_before, Instant::now() + ra);
            }
        }

        if let Some(err) = journal_err {
            return Err(err);
        }
        if let Some(err) = ack_fatal_err {
            return Err(err);
        }
        if let Some(err) = ack_transient_err {
            return Err(err);
        }
        if transient_ack_abort {
            if cfg.daemon && !cancel.is_cancelled() {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(cfg.poll_interval) => continue,
                }
            }
            bail!("transient ack failure aborted queue batch");
        }
        if incomplete_batch {
            bail!("cloudflare queue ack had warnings or short counts");
        }
    }

    if collect_meta && journal_dirty && let Some(jp) = &journal_path {
        persist_journal(jp, &metas)?;
    }

    if !cfg.daemon && cancel.is_cancelled() {
        bail!("queue pull interrupted by signal");
    }
    if exhausted_retries > 0 {
        bail!("queue drained with failed messages (exhausted_retries={exhausted_retries})");
    }

    if let Some(jp) = &journal_path {
        let _ = std::fs::remove_file(jp);
    }

    Ok(metas.into_values().collect())
}

fn update_max_deadline(slot: &mut Option<Instant>, candidate: Instant) {
    *slot = Some(slot.map_or(candidate, |prev| prev.max(candidate)));
}

fn requeue_unstarted(
    pending: &mut std::vec::IntoIter<(String, String, u32, String)>,
    retries: &mut Vec<RetryLease>,
) {
    let count = pending.len();
    if count > 0 {
        tracing::info!(count, "releasing unstarted leases with zero delay");
        for (_, lease_id, _, _) in pending.by_ref() {
            retries.push(RetryLease {
                lease_id,
                delay_seconds: 0,
            });
        }
    }
}

type AckTaskResult = (Option<Instant>, Result<AckOutcome, ApiError>);

fn spawn_ack_task(
    http: &reqwest::Client,
    ack_url: &str,
    acks: Vec<AckLease>,
    retries: Vec<RetryLease>,
) -> tokio::task::JoinHandle<AckTaskResult> {
    let http = http.clone();
    let ack_url = ack_url.to_string();
    let req = AckRequest { acks, retries };
    tokio::spawn(async move {
        let mut rnb: Option<Instant> = None;
        let outcome = ack_messages(&http, &ack_url, &req, &mut rnb).await;
        (rnb, outcome)
    })
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    parse_retry_after_at(headers, SystemTime::now())
}

fn parse_retry_after_at(headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let raw = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs.clamp(1, MAX_RETRY_AFTER_SECS)));
    }
    let dt = httpdate::parse_http_date(raw).ok()?;
    let secs = dt
        .duration_since(now)
        .unwrap_or_default()
        .as_secs()
        .clamp(1, MAX_RETRY_AFTER_SECS);
    Some(Duration::from_secs(secs))
}

#[allow(clippy::too_many_arguments)]
async fn pull_with_retry(
    http: &reqwest::Client,
    pull_url: &str,
    batch_size: u8,
    visibility_timeout_ms: u64,
    daemon: bool,
    poll_interval: Duration,
    cancel: &CancellationToken,
    retry_not_before: &mut Option<Instant>,
    retry_wait_until: &mut Option<Instant>,
) -> anyhow::Result<Option<(Instant, Vec<QueueMessage>, usize)>> {
    let mut attempt: u32 = 0;
    loop {
        if let Some(rnb) = retry_not_before.take()
            && Instant::now() < rnb
        {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(None),
                _ = tokio::time::sleep_until(rnb) => {}
            }
        }

        let attempt_started = Instant::now();
        match pull_messages(http, pull_url, batch_size, visibility_timeout_ms).await {
            Ok((msgs, parse_errs)) => return Ok(Some((attempt_started, msgs, parse_errs))),
            Err(ApiError::Fatal(e)) => return Err(e),
            Err(ApiError::Transient(e, retry_after)) => {
                // An in-flight pull timeout/reset could have leased messages server-side
                let uncertain_deadline =
                    attempt_started + Duration::from_millis(visibility_timeout_ms) + Duration::from_secs(2);
                update_max_deadline(retry_wait_until, uncertain_deadline);

                if !daemon && attempt >= 4 {
                    return Err(e);
                }
                let backoff = Duration::from_secs(1 << attempt.min(4));
                let mut delay = retry_after.unwrap_or(backoff);
                if daemon && attempt >= 4 {
                    delay = delay.max(poll_interval);
                }
                update_max_deadline(retry_not_before, Instant::now() + delay);
                attempt = attempt.saturating_add(1);
                tracing::warn!(
                    attempt,
                    delay_secs = delay.as_secs_f32(),
                    error = %e,
                    "queue pull failed transiently, retrying"
                );
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(None),
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

async fn pull_messages(
    http: &reqwest::Client,
    pull_url: &str,
    batch_size: u8,
    visibility_timeout_ms: u64,
) -> Result<(Vec<QueueMessage>, usize), ApiError> {
    let resp = http
        .post(pull_url)
        .json(&PullRequest {
            batch_size,
            visibility_timeout_ms,
        })
        .send()
        .await
        .map_err(|e| ApiError::Transient(e.into(), None))?;

    let status = resp.status();
    if !status.is_success() {
        let retry_after = parse_retry_after(resp.headers());
        let body = resp.text().await.unwrap_or_default();
        let err = anyhow::anyhow!("cloudflare queue pull HTTP {status}: {body}");
        return Err(if is_retryable_status(status) {
            ApiError::Transient(err, retry_after)
        } else {
            ApiError::Fatal(err)
        });
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ApiError::Transient(e.into(), None))?;
    let env: PullEnvelope = serde_json::from_slice(&bytes).map_err(|e| ApiError::Fatal(e.into()))?;
    if !env.success {
        return Err(ApiError::Fatal(anyhow::anyhow!(
            "cloudflare queue pull failed: {:?}",
            env.errors
        )));
    }

    let raw_msgs = env.result.map(|r| r.messages).unwrap_or_default();
    let mut parsed = Vec::with_capacity(raw_msgs.len());
    let mut parse_errors = 0usize;
    for raw in raw_msgs {
        match serde_json::from_value::<QueueMessage>(raw) {
            Ok(m) => parsed.push(m),
            Err(e) => {
                parse_errors += 1;
                tracing::error!(error = %e, "failed to deserialize individual queue message");
            }
        }
    }
    Ok((parsed, parse_errors))
}

async fn ack_messages(
    http: &reqwest::Client,
    ack_url: &str,
    req: &AckRequest,
    retry_not_before: &mut Option<Instant>,
) -> Result<AckOutcome, ApiError> {
    let max_attempts = 3usize;
    let mut last_err: Option<ApiError> = None;

    for attempt in 0..max_attempts {
        match ack_once(http, ack_url, req).await {
            Ok(outcome) => return Ok(outcome),
            Err(ApiError::Fatal(e)) => return Err(ApiError::Fatal(e)),
            Err(ApiError::Transient(e, retry_after)) => {
                if let Some(ra) = retry_after {
                    update_max_deadline(retry_not_before, Instant::now() + ra);
                }
                tracing::warn!(attempt = attempt + 1, error = %e, "queue ack failed transiently");
                last_err = Some(ApiError::Transient(e, retry_after));
                if attempt + 1 < max_attempts {
                    let delay =
                        retry_after.unwrap_or_else(|| Duration::from_millis(200 * (1 << attempt)));
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    Err(last_err.expect("loop ran at least once"))
}

async fn ack_once(
    http: &reqwest::Client,
    ack_url: &str,
    req: &AckRequest,
) -> Result<AckOutcome, ApiError> {
    let resp = http
        .post(ack_url)
        .json(req)
        .send()
        .await
        .map_err(|e| ApiError::Transient(e.into(), None))?;

    let status = resp.status();
    if !status.is_success() {
        let retry_after = parse_retry_after(resp.headers());
        let body = resp.text().await.unwrap_or_default();
        let err = anyhow::anyhow!("cloudflare queue ack HTTP {status}: {body}");
        return Err(if is_retryable_status(status) {
            ApiError::Transient(err, retry_after)
        } else {
            ApiError::Fatal(err)
        });
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ApiError::Transient(e.into(), None))?;
    let env: AckEnvelope = serde_json::from_slice(&bytes).map_err(|e| ApiError::Fatal(e.into()))?;
    if !env.success {
        return Err(ApiError::Fatal(anyhow::anyhow!(
            "cloudflare queue ack failed: {:?}",
            env.errors
        )));
    }

    Ok(env.result.unwrap_or_default().outcome(req))
}

#[derive(Clone, Debug)]
struct SourceIdentity {
    etag: Option<String>,
    last_modified: Option<opendal::raw::Timestamp>,
    content_length: u64,
}

impl SourceIdentity {
    fn from_meta(m: &Metadata) -> Self {
        Self {
            etag: m.etag().map(str::to_owned),
            last_modified: m.last_modified(),
            content_length: m.content_length(),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        if self.content_length != other.content_length {
            return false;
        }
        match (&self.etag, &other.etag) {
            (Some(a), Some(b)) => a == b,
            (None, None) => {
                self.last_modified.is_some() && self.last_modified == other.last_modified
            }
            _ => false,
        }
    }

    fn has_version_token(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

enum ConvertOutcome {
    Converted {
        new_path: String,
        meta_key: String,
        size: (usize, usize),
    },
    SkippedWithMeta {
        new_path: String,
        meta_key: String,
        size: (usize, usize),
    },
    SkippedNoMeta,
}

/// A destination's source ETag is usable only after checking which key owns it.
fn destination_source_etag<'a>(
    dst_meta: &'a Metadata,
    path: &str,
    new_path: &str,
) -> anyhow::Result<Option<&'a str>> {
    let Some(um) = dst_meta.user_metadata() else {
        return Ok(None);
    };
    let matches = match (um.get("source-key"), um.get("source-key-encoding")) {
        (None, None) => return Ok(None),
        (Some(key), None) => key == path,
        (Some(key), Some("base64")) => {
            key == base64::engine::general_purpose::STANDARD.encode(path)
        }
        _ => bail!("invalid source-key metadata for {new_path}"),
    };
    if !matches {
        bail!("destination collision for {new_path}: source key metadata does not match {path}");
    }
    Ok(um.get("source-etag"))
}

enum ReadSourceOutcome {
    Loaded(opendal::Buffer, tokio::sync::OwnedSemaphorePermit),
    NotFound,
}

async fn read_source_bytes(
    src_op: &Operator,
    path: &str,
    src_id: &mut SourceIdentity,
    byte_sem: &Arc<Semaphore>,
) -> anyhow::Result<ReadSourceOutcome> {
    if src_id.content_length > MAX_SOURCE_BYTES {
        bail!(
            "source object {path} too large ({} bytes > {MAX_SOURCE_BYTES})",
            src_id.content_length
        );
    }

    let acquire_budget = |len: u64| {
        let permits = len.clamp(1, MAX_SOURCE_BYTES) as u32;
        Arc::clone(byte_sem).acquire_many_owned(permits)
    };

    let permit = acquire_budget(src_id.content_length)
        .await
        .context("source byte budget semaphore closed")?;

    let can_if_match = src_op.info().capability().read_with_if_match;
    let res = if can_if_match && let Some(etag) = src_id.etag.clone() {
        match src_op.read_with(path).if_match(&etag).await {
            Ok(buf) => Ok((buf, permit)),
            Err(e) if e.kind() == ErrorKind::ConditionNotMatch => {
                drop(permit);
                let fresh = match src_op.stat(path).await {
                    Ok(stat) => stat,
                    Err(se) if se.kind() == ErrorKind::NotFound => {
                        return Ok(ReadSourceOutcome::NotFound);
                    }
                    Err(se) => return Err(se.into()),
                };
                *src_id = SourceIdentity::from_meta(&fresh);
                if src_id.content_length > MAX_SOURCE_BYTES {
                    bail!(
                        "source object {path} too large ({} bytes > {MAX_SOURCE_BYTES})",
                        src_id.content_length
                    );
                }
                let fresh_permit = acquire_budget(src_id.content_length)
                    .await
                    .context("source byte budget semaphore closed")?;
                let retry_res = if let Some(fresh_etag) = src_id.etag.as_deref() {
                    src_op.read_with(path).if_match(fresh_etag).await
                } else {
                    src_op.read(path).await
                };
                retry_res.map(|buf| (buf, fresh_permit))
            }
            Err(e) => Err(e),
        }
    } else {
        src_op.read(path).await.map(|buf| (buf, permit))
    };

    match res {
        Ok((buf, permit)) => {
            if buf.len() as u64 > MAX_SOURCE_BYTES {
                bail!(
                    "source object {path} exceeded max bytes ({} > {MAX_SOURCE_BYTES})",
                    buf.len()
                );
            }
            Ok(ReadSourceOutcome::Loaded(buf, permit))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(ReadSourceOutcome::NotFound),
        Err(e) => Err(e.into()),
    }
}

async fn delete_source_verified(
    src_op: &Operator,
    path: &str,
    src_id: &SourceIdentity,
) -> anyhow::Result<()> {
    if !src_id.has_version_token() {
        bail!(
            "refusing --delete-origin on {path}: storage backend returned no version token/timestamp"
        );
    }
    if src_op.info().capability().delete_with_if_match
        && let Some(etag) = src_id.etag.as_deref()
    {
        match src_op.delete_with(path).if_match(etag).await {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) if e.kind() == ErrorKind::Unsupported => {}
            Err(e) => return Err(e.into()),
        }
    }
    match src_op.stat(path).await {
        Ok(current_stat) => {
            let current_id = SourceIdentity::from_meta(&current_stat);
            if !src_id.matches(&current_id) {
                bail!(
                    "source object {path} changed during conversion; refusing to delete newer upload"
                );
            }
            src_op.delete(path).await?;
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_and_cleanup(
    src_op: &Operator,
    dst_op: &Operator,
    path: &str,
    new_path: &str,
    src_id: &SourceIdentity,
    pre_dst: Option<Metadata>,
    webp_bytes: Vec<u8>,
    dimensions: (usize, usize),
    delete_origin: bool,
) -> anyhow::Result<()> {
    let caps = dst_op.info().capability();
    let buf_webp = opendal::Buffer::from(webp_bytes);
    let make_user_meta = || {
        let mut um = Vec::with_capacity(5);
        // Keep the legacy header when signing and HTTP whitespace normalization preserve it.
        let header_safe = path
            .split(' ')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_graphic()));
        let source_key = if header_safe {
            path.to_owned()
        } else {
            um.push(("source-key-encoding".to_string(), "base64".to_string()));
            base64::engine::general_purpose::STANDARD.encode(path)
        };
        um.push(("source-key".to_string(), source_key));
        if let Some(etag) = &src_id.etag {
            um.push(("source-etag".to_string(), etag.clone()));
        }
        um.push(("webp-width".to_string(), dimensions.0.to_string()));
        um.push(("webp-height".to_string(), dimensions.1.to_string()));
        um
    };

    let mut existing_dst = match pre_dst {
        Some(m) => Some(m),
        None if !caps.write_with_if_not_exists => match dst_op.stat(new_path).await {
            Ok(m) => Some(m),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        },
        None => None,
    };

    let mut published = false;
    if existing_dst.is_none() {
        if caps.write_with_if_not_exists {
            let mut writer = dst_op.write_with(new_path, buf_webp.clone());
            if caps.write_with_user_metadata {
                writer = writer.user_metadata(make_user_meta());
            }
            writer = writer.if_not_exists(true);
            match writer.await {
                Ok(_) => published = true,
                Err(e) if e.kind() == ErrorKind::ConditionNotMatch => {
                    let m = dst_op.stat(new_path).await?;
                    existing_dst = Some(m);
                }
                Err(e) => return Err(e.into()),
            }
        } else {
            let current_src = src_op.stat(path).await.with_context(|| {
                format!("source object {path} disappeared before publishing {new_path}")
            })?;
            let current_id = SourceIdentity::from_meta(&current_src);
            if !src_id.matches(&current_id) {
                bail!(
                    "source object {path} changed during conversion; refusing to publish stale version"
                );
            }
            let mut writer = dst_op.write_with(new_path, buf_webp.clone());
            if caps.write_with_user_metadata {
                writer = writer.user_metadata(make_user_meta());
            }
            writer.await?;
            published = true;
        }
    }

    if !published
        && let Some(ref dst_meta) = existing_dst
    {
        let stored_etag = destination_source_etag(dst_meta, path, new_path)?;
        if stored_etag.is_none() || stored_etag != src_id.etag.as_deref() {
            let current_src = src_op.stat(path).await.with_context(|| {
                format!("source object {path} disappeared before overwriting {new_path}")
            })?;
            let current_id = SourceIdentity::from_meta(&current_src);
            if !src_id.matches(&current_id) {
                bail!(
                    "source object {path} changed during conversion; refusing to overwrite {new_path} with stale version"
                );
            }
            let mut writer = dst_op.write_with(new_path, buf_webp);
            if caps.write_with_user_metadata {
                writer = writer.user_metadata(make_user_meta());
            }
            if caps.write_with_if_match
                && let Some(etag) = dst_meta.etag()
            {
                writer = writer.if_match(etag);
            }
            writer.await?;
        }
    }

    if delete_origin && path != new_path {
        delete_source_verified(src_op, path, src_id).await?;
    }
    Ok(())
}

fn convert_checked(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure_vips()?;
    let size = imagesize::blob_size(raw)?;
    if size.width == 0 || size.height == 0 {
        bail!("zero image dimensions");
    }
    if size.width.saturating_mul(size.height) > MAX_IMAGE_PIXELS {
        bail!(
            "image pixel count {}x{} exceeds limit",
            size.width,
            size.height
        );
    }
    convert(raw).map_err(Into::into)
}

async fn read_webp_dimensions(
    dst_op: &Operator,
    new_path: &str,
) -> anyhow::Result<(usize, usize)> {
    let head = dst_op.read_with(new_path).range(0..4096).await;
    if let Ok(buf) = head {
        let bytes = buf.to_bytes();
        if let Ok(sz) = imagesize::blob_size(&bytes) {
            return Ok((sz.width, sz.height));
        }
    }
    let full = dst_op.read(new_path).await?;
    let sz = imagesize::blob_size(&full.to_bytes())?;
    Ok((sz.width, sz.height))
}

async fn recover_webp_dimensions(
    dst_op: &Operator,
    new_path: &str,
    dst_meta: &Metadata,
) -> anyhow::Result<(usize, usize)> {
    if let Some(um) = dst_meta.user_metadata()
        && let (Some(w), Some(h)) = (
            um.get("webp-width").and_then(|s| s.parse::<usize>().ok()),
            um.get("webp-height").and_then(|s| s.parse::<usize>().ok()),
        )
        && w > 0
        && h > 0
    {
        return Ok((w, h));
    }
    read_webp_dimensions(dst_op, new_path).await
}

async fn recover_missing_source(
    dst_op: &Operator,
    path: &str,
    new_path: String,
    meta_key: String,
    collect_meta: bool,
    attempts: u32,
) -> anyhow::Result<ConvertOutcome> {
    // Another converter may have published the WebP and deleted the source since our first HEAD.
    let dst_meta = match dst_op.stat(&new_path).await {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            bail!("source object missing in storage (attempt {attempts}): {path}");
        }
        Err(e) => return Err(e.into()),
    };
    destination_source_etag(&dst_meta, path, &new_path)?;
    if collect_meta {
        let size = recover_webp_dimensions(dst_op, &new_path, &dst_meta).await?;
        Ok(ConvertOutcome::SkippedWithMeta {
            new_path,
            meta_key,
            size,
        })
    } else {
        Ok(ConvertOutcome::SkippedNoMeta)
    }
}

#[allow(clippy::too_many_arguments)]
async fn convert_object(
    src_op: &Operator,
    dst_op: &Operator,
    path: &str,
    list_meta: Option<&Metadata>,
    delete_origin: bool,
    collect_meta: bool,
    attempts: u32,
    byte_sem: &Arc<Semaphore>,
    cpu_sem: &Arc<Semaphore>,
) -> anyhow::Result<ConvertOutcome> {
    if !is_exact_opendal_key(path) {
        bail!("refusing non-canonical object key: {path:?}");
    }
    let (new_path, meta_key) = target_paths(path);

    let existing_dst = match dst_op.stat(&new_path).await {
        Ok(m) => Some(m),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let stored_etag = match &existing_dst {
        Some(m) => destination_source_etag(m, path, &new_path)?,
        None => None,
    };

    let mut src_id = if let Some(m) = list_meta.filter(|m| m.etag().is_some()) {
        SourceIdentity::from_meta(m)
    } else {
        match src_op.stat(path).await {
            Ok(stat) => SourceIdentity::from_meta(&stat),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return recover_missing_source(dst_op, path, new_path, meta_key, collect_meta, attempts)
                    .await;
            }
            Err(e) => return Err(e.into()),
        }
    };

    if let (Some(dst_meta), Some(etag)) = (&existing_dst, stored_etag)
        && Some(etag) == src_id.etag.as_deref()
    {
        let size = if collect_meta {
            Some(recover_webp_dimensions(dst_op, &new_path, dst_meta).await?)
        } else {
            None
        };
        if delete_origin && path != new_path {
            delete_source_verified(src_op, path, &src_id).await?;
        }
        return Ok(match size {
            Some(size) => ConvertOutcome::SkippedWithMeta {
                new_path,
                meta_key,
                size,
            },
            None => ConvertOutcome::SkippedNoMeta,
        });
    }

    let (buf, byte_permit) = match read_source_bytes(src_op, path, &mut src_id, byte_sem).await? {
        ReadSourceOutcome::Loaded(buf, permit) => (buf, permit),
        ReadSourceOutcome::NotFound => {
            return recover_missing_source(dst_op, path, new_path, meta_key, collect_meta, attempts)
                .await;
        }
    };

    let cpu_permit = Arc::clone(cpu_sem)
        .acquire_owned()
        .await
        .context("cpu semaphore closed")?;

    let webp_bytes = tokio::task::spawn_blocking(move || {
        let _cpu_permit = cpu_permit;
        let _byte_permit = byte_permit;
        let raw = buf.to_bytes();
        let out = convert_checked(&raw);
        drop(raw);
        drop(buf);
        out
    })
    .await?
    .with_context(|| format!("libvips convert failed for {path}"))?;

    let imagesize::ImageSize { width, height } = imagesize::blob_size(&webp_bytes)?;
    publish_and_cleanup(
        src_op,
        dst_op,
        path,
        &new_path,
        &src_id,
        existing_dst,
        webp_bytes,
        (width, height),
        delete_origin,
    )
    .await?;
    Ok(ConvertOutcome::Converted {
        new_path,
        meta_key,
        size: (width, height),
    })
}

fn is_exact_opendal_key(key: &str) -> bool {
    !key.is_empty()
        && key.trim() == key
        && !key.starts_with('/')
        && !key.ends_with('/')
        && !key.contains("//")
        && !key.contains('\0')
        && !key.split('/').any(|seg| seg == "." || seg == "..")
}

fn message_content_type(msg: &QueueMessage) -> Option<&str> {
    msg.metadata
        .iter()
        .find(|(k, _)| {
            ["CF-Content-Type", "contentType", "content_type"]
                .iter()
                .any(|name| k.eq_ignore_ascii_case(name))
        })
        .and_then(|(_, v)| v.as_str())
}

/// Standard base64, falling back to unpadded.
fn decode_base64_flex(s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(t.trim_end_matches('=')))
        .ok()
}

/// Char-safe preview of at most `max` chars.
fn preview(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Diagnostic preview of a message body (plus decoded text if it is base64 UTF-8).
fn body_preview(body: &serde_json::Value) -> String {
    let text = match body {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let mut out = preview(&text, 120);
    if let serde_json::Value::String(s) = body
        && let Some(raw) = decode_base64_flex(s)
    {
        match std::str::from_utf8(&raw) {
            Ok(t) => out.push_str(&format!(" | decoded_utf8={}", preview(t, 120))),
            Err(_) => out.push_str(&format!(" | decoded_bytes={}", raw.len())),
        }
    }
    out
}

/// Classifies a string body that may be raw JSON, base64 JSON, or a plain key.
fn classify_string_body(s: &str, expected_bucket: Option<&str>) -> MessageAction {
    if !s.trim_start().starts_with('{')
        && let Some(raw) = decode_base64_flex(s)
        && let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(&raw)
        && (map.contains_key("key") || map.contains_key("object") || map.contains_key("action"))
    {
        return classify_object_map(&map, expected_bucket);
    }
    classify_text_payload(s, expected_bucket)
}

fn decode_and_classify_message(
    msg: &QueueMessage,
    expected_bucket: Option<&str>,
) -> MessageAction {
    let content_type = message_content_type(msg);

    match content_type {
        Some(ct) if ct.eq_ignore_ascii_case("json") => match &msg.body {
            serde_json::Value::String(s) => {
                if matches!(s.trim_start().chars().next(), Some('{' | '"')) {
                    let Ok(val) = serde_json::from_str::<serde_json::Value>(s) else {
                        return MessageAction::Malformed;
                    };
                    return classify_decoded_value(&val, expected_bucket);
                }
                let Some(raw) = decode_base64_flex(s) else {
                    return MessageAction::Malformed;
                };
                match serde_json::from_slice::<serde_json::Value>(&raw) {
                    Ok(val) => classify_decoded_value(&val, expected_bucket),
                    Err(_) if raw.first() == Some(&0xFF) => {
                        classify_v8_payload(&raw, expected_bucket)
                    }
                    Err(_) => MessageAction::Malformed,
                }
            }
            other => classify_decoded_value(other, expected_bucket),
        },
        Some(ct) if ct.eq_ignore_ascii_case("bytes") => match &msg.body {
            serde_json::Value::String(b64) => {
                let Some(raw) = decode_base64_flex(b64) else {
                    return MessageAction::Malformed;
                };
                let Ok(text) = String::from_utf8(raw) else {
                    return MessageAction::Malformed;
                };
                classify_text_payload(&text, expected_bucket)
            }
            _ => MessageAction::Malformed,
        },
        Some(ct) if ct.eq_ignore_ascii_case("v8") => match &msg.body {
            serde_json::Value::String(b64) => {
                let Some(raw) = decode_base64_flex(b64) else {
                    return MessageAction::Malformed;
                };
                classify_v8_payload(&raw, expected_bucket)
            }
            _ => MessageAction::Malformed,
        },
        Some(ct) if !ct.eq_ignore_ascii_case("text") => MessageAction::Malformed,
        _ => match &msg.body {
            serde_json::Value::String(s) => classify_string_body(s, expected_bucket),
            other => classify_decoded_value(other, expected_bucket),
        },
    }
}

/// Upper bound on nesting when skipping unrelated V8 values inside a task object.
const V8_MAX_DEPTH: usize = 4;
/// Upper bound on a single V8 header version varint (Blink and V8 versions are small).
const V8_MAX_VERSION: u64 = 64;

/// Result of decoding a `CF-Content-Type: v8` queue payload.
#[derive(Debug, PartialEq, Eq)]
enum V8TaskKey {
    /// `"key"` property of a JS `Object` / `Map` (e.g. `WebpTask { key }` via `serde_wasm_bindgen`).
    Field(String),
    /// A bare JS string at the root (`queue.send(key)`).
    Bare(String),
}

/// Bounds-checked cursor over a V8 `ValueSerializer` buffer.
struct V8Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> V8Reader<'a> {
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn byte(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// Base-128 little-endian varint (max 10 bytes, overflow rejected).
    fn varint(&mut self) -> Option<u64> {
        let mut value: u64 = 0;
        for i in 0..10u32 {
            let b = self.byte()?;
            let chunk = u64::from(b & 0x7F);
            let shift = 7 * i;
            if shift == 63 && chunk > 1 {
                return None;
            }
            value |= chunk << shift;
            if b & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn len(&mut self) -> Option<usize> {
        usize::try_from(self.varint()?).ok()
    }

    /// Next tag, skipping `kPadding` (0x00) and `kVerifyObjectCount` ('?' + varint).
    fn tag(&mut self) -> Option<u8> {
        loop {
            match self.byte()? {
                0x00 => {}
                b'?' => {
                    self.varint()?;
                }
                t => return Some(t),
            }
        }
    }

    /// Reads a string body for a string tag; `None` for non-string tags or invalid data.
    fn string(&mut self, tag: u8) -> Option<String> {
        match tag {
            // kOneByteString: Latin-1
            b'"' => {
                let n = self.len()?;
                Some(self.take(n)?.iter().map(|&b| char::from(b)).collect())
            }
            // kUtf8String
            b'S' => {
                let n = self.len()?;
                String::from_utf8(self.take(n)?.to_vec()).ok()
            }
            // kTwoByteString: UTF-16LE
            b'c' => {
                let n = self.len()?;
                if n % 2 != 0 {
                    return None;
                }
                let units: Vec<u16> = self
                    .take(n)?
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&c| u16::from_le_bytes(c))
                    .collect();
                String::from_utf16(&units).ok()
            }
            _ => None,
        }
    }

    /// Skips one value of a small, safe subset of V8 tags.
    fn skip_value(&mut self, tag: u8, depth: usize) -> Option<()> {
        match tag {
            b'"' | b'S' | b'c' => self.string(tag).map(drop),
            b'_' | b'0' | b'T' | b'F' => Some(()),
            b'I' | b'U' => self.varint().map(drop),
            b'N' => self.take(8).map(drop),
            b'o' | b';' => {
                if depth >= V8_MAX_DEPTH {
                    return None;
                }
                self.container_key(tag, depth + 1).map(drop)
            }
            _ => None,
        }
    }

    /// Reads a JS `Object` (`o` … `{` n) or `Map` (`;` … `:` 2n) and returns its `"key"` string
    /// property, if any. Rejects non-string `"key"` values, duplicate `"key"`s and bad counts.
    fn container_key(&mut self, open: u8, depth: usize) -> Option<Option<String>> {
        let (close, per_entry) = match open {
            b'o' => (b'{', 1u64),
            b';' => (b':', 2u64),
            _ => return None,
        };
        let mut found: Option<String> = None;
        let mut entries: u64 = 0;
        loop {
            let tag = self.tag()?;
            if tag == close {
                let count = self.varint()?;
                return (count == entries.checked_mul(per_entry)?).then_some(found);
            }
            let name = match tag {
                b'"' | b'S' | b'c' => Some(self.string(tag)?),
                b'I' | b'U' => {
                    self.varint()?;
                    None
                }
                b'N' => {
                    self.take(8)?;
                    None
                }
                _ => return None,
            };
            let value_tag = self.tag()?;
            if name.as_deref() == Some("key") {
                if found.is_some() {
                    return None;
                }
                found = Some(self.string(value_tag)?);
            } else {
                self.skip_value(value_tag, depth)?;
            }
            entries = entries.checked_add(1)?;
        }
    }
}

/// Decodes a `CF-Content-Type: v8` (V8 `ValueSerializer`, optionally wrapped in a Blink/Workers
/// envelope) queue payload produced by e.g. `workers-rs` `QueueContentType::V8`.
///
/// Accepts one or two `0xFF <varint version>` headers (Blink + V8), an optional Blink trailer
/// offset record (`0xFE` + 12 bytes), then a root JS `Object`/`Map` carrying a string `"key"`, or
/// a bare root string. Everything is bounds-checked; anything else yields `None`.
fn decode_v8_webp_task_key(raw: &[u8]) -> Option<V8TaskKey> {
    let mut r = V8Reader { buf: raw, pos: 0 };
    let mut headers = 0;
    while r.peek() == Some(0xFF) {
        if headers == 2 {
            return None;
        }
        r.pos += 1;
        let version = r.varint()?;
        if version == 0 || version > V8_MAX_VERSION {
            return None;
        }
        headers += 1;
        if r.peek() == Some(0xFE) {
            r.pos += 1;
            r.take(12)?;
        }
    }
    if headers == 0 {
        return None;
    }
    let tag = r.tag()?;
    match tag {
        b'"' | b'S' | b'c' => r.string(tag).map(V8TaskKey::Bare),
        b'o' | b';' => r.container_key(tag, 0)?.map(V8TaskKey::Field),
        _ => None,
    }
}

fn classify_v8_payload(raw: &[u8], expected_bucket: Option<&str>) -> MessageAction {
    match decode_v8_webp_task_key(raw) {
        Some(V8TaskKey::Bare(s)) => classify_text_payload(&s, expected_bucket),
        Some(V8TaskKey::Field(key)) if !key.trim().is_empty() && is_exact_opendal_key(&key) => {
            MessageAction::Convert(key)
        }
        _ => MessageAction::Malformed,
    }
}

fn classify_text_payload(s: &str, expected_bucket: Option<&str>) -> MessageAction {
    if s.trim().is_empty() {
        return MessageAction::Malformed;
    }
    if s.trim_start().starts_with('{') {
        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(s) {
            return classify_object_map(&map, expected_bucket);
        }
        return MessageAction::Malformed;
    }
    if is_exact_opendal_key(s) {
        MessageAction::Convert(s.to_owned())
    } else {
        MessageAction::Malformed
    }
}

fn classify_decoded_value(
    body: &serde_json::Value,
    expected_bucket: Option<&str>,
) -> MessageAction {
    match body {
        serde_json::Value::String(s) => classify_text_payload(s, expected_bucket),
        serde_json::Value::Object(map) => classify_object_map(map, expected_bucket),
        _ => MessageAction::Malformed,
    }
}

fn classify_object_map(
    map: &serde_json::Map<String, serde_json::Value>,
    expected_bucket: Option<&str>,
) -> MessageAction {
    let is_r2_event = map.contains_key("object") || map.contains_key("action");
    if is_r2_event {
        if let Some(bucket_val) = map.get("bucket") {
            let Some(bucket) = bucket_val.as_str() else {
                return MessageAction::Malformed;
            };
            if let Some(expected) = expected_bucket
                && bucket != expected
            {
                return MessageAction::Ignore("r2_bucket_mismatch");
            }
        }
        match map.get("action") {
            Some(serde_json::Value::String(action)) => match action.as_str() {
                "PutObject" | "CopyObject" | "CompleteMultipartUpload" => {}
                a if a.starts_with("Delete")
                    || a == "LifecycleDeletion"
                    || a == "AbortMultipartUpload" =>
                {
                    return MessageAction::Ignore("r2_non_create_action");
                }
                _ => return MessageAction::Malformed,
            },
            Some(_) => return MessageAction::Malformed,
            None => {}
        }
        if let Some(key) = map
            .get("object")
            .and_then(|obj| obj.get("key"))
            .and_then(|v| v.as_str())
        {
            return if !key.trim().is_empty() && is_exact_opendal_key(key) {
                MessageAction::Convert(key.to_owned())
            } else {
                MessageAction::Malformed
            };
        }
        return MessageAction::Malformed;
    }

    if let Some(key) = map.get("key").and_then(|v| v.as_str()) {
        return if !key.trim().is_empty() && is_exact_opendal_key(key) {
            MessageAction::Convert(key.to_owned())
        } else {
            MessageAction::Malformed
        };
    }

    MessageAction::Malformed
}

fn should_convert_path(path: &str) -> bool {
    if path.is_empty() || path.ends_with('/') {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".webp") {
        return false;
    }
    if lower.ends_with(".bin") {
        return true;
    }
    let mimes = MimeGuess::from_path(path);
    mimes.is_empty() || mimes.into_iter().any(|m| m.type_() == IMAGE)
}

fn target_paths(path: &str) -> (String, String) {
    match path.rsplit_once('.') {
        Some((pre, ext)) if KNOWN_IMAGE_EXTS.contains(&ext.to_ascii_lowercase().as_str()) => {
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
        match p
            .parent()
            .map(|p| p.to_string_lossy())
            .map(|s| s.trim_matches('/').to_owned())
            .filter(|s| !s.is_empty())
        {
            Some(dir_title) => {
                let author = dir_title
                    .split_whitespace()
                    .next()
                    .unwrap_or("Unknown")
                    .to_string();
                (dir_title, author)
            }
            None => ("/".to_string(), "Unknown".to_string()),
        }
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
    if let Some(existing) = meta.images.iter_mut().find(|i| i.name == new_image.name) {
        existing.width = new_image.width;
        existing.height = new_image.height;
    } else {
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
                .unwrap_or_else(|_| "auto".to_string()),
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
        TimeoutLayer::new()
            .with_timeout(Duration::from_secs(600))
            .with_io_timeout(Duration::from_secs(300)),
    )
    .layer(
        RetryLayer::new()
            .with_max_times(3)
            .with_min_delay(Duration::from_millis(200))
            .with_max_delay(Duration::from_secs(10))
            .with_jitter(),
    );
    Ok(op)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn extract_key_formats() {
        assert_eq!(
            classify_decoded_value(&serde_json::json!({ "key": "post/photo 1" }), None),
            MessageAction::Convert("post/photo 1".to_string())
        );
        assert_eq!(
            classify_decoded_value(
                &serde_json::json!({
                    "bucket": "my-bucket",
                    "action": "PutObject",
                    "object": { "key": "post/photo 2", "size": 123 }
                }),
                Some("my-bucket")
            ),
            MessageAction::Convert("post/photo 2".to_string())
        );
        assert_eq!(
            classify_decoded_value(
                &serde_json::json!({
                    "bucket": "other-bucket",
                    "action": "PutObject",
                    "object": { "key": "post/photo 2", "size": 123 }
                }),
                Some("my-bucket")
            ),
            MessageAction::Ignore("r2_bucket_mismatch")
        );
        assert_eq!(
            classify_decoded_value(
                &serde_json::json!({
                    "action": "DeleteObject",
                    "object": { "key": "post/photo 2" }
                }),
                None
            ),
            MessageAction::Ignore("r2_non_create_action")
        );
        assert_eq!(
            classify_decoded_value(
                &serde_json::json!({
                    "action": "LifecycleDeletion",
                    "object": { "key": "post/photo 2" }
                }),
                None
            ),
            MessageAction::Ignore("r2_non_create_action")
        );
        assert_eq!(
            classify_decoded_value(
                &serde_json::json!({
                    "action": "UnknownFutureAction",
                    "object": { "key": "post/photo 2" }
                }),
                None
            ),
            MessageAction::Malformed
        );
        assert_eq!(
            classify_decoded_value(&serde_json::json!(r#"{"key":"post/photo 3"}"#), None),
            MessageAction::Convert("post/photo 3".to_string())
        );
        assert_eq!(
            classify_decoded_value(&serde_json::json!("post/photo 4"), None),
            MessageAction::Convert("post/photo 4".to_string())
        );
        // OpenDAL trims outer whitespace before every operation, including deletion.
        for key in ["post/photo 4 ", "\u{3000}相册/照片"] {
            assert_eq!(
                classify_decoded_value(&serde_json::json!(key), None),
                MessageAction::Malformed
            );
        }
        assert_eq!(
            classify_decoded_value(&serde_json::json!("post//photo.jpg"), None),
            MessageAction::Malformed
        );
        assert_eq!(
            classify_decoded_value(&serde_json::json!("/post/photo.jpg"), None),
            MessageAction::Malformed
        );
        assert_eq!(
            classify_decoded_value(&serde_json::json!({ "foo": "bar" }), None),
            MessageAction::Malformed
        );
        assert_eq!(
            classify_decoded_value(&serde_json::json!(""), None),
            MessageAction::Malformed
        );
        assert_eq!(
            classify_decoded_value(&serde_json::json!(123), None),
            MessageAction::Malformed
        );
    }

    #[test]
    fn http_pull_decodes_base64_json_and_bytes_messages() {
        let json_b64 =
            base64::engine::general_purpose::STANDARD.encode(br#"{"key":"album/photo 1"}"#);
        let msg: QueueMessage = serde_json::from_value(serde_json::json!({
            "lease_id": "lease-1",
            "attempts": 1,
            "metadata": { "CF-Content-Type": "json" },
            "body": json_b64
        }))
        .unwrap();
        assert_eq!(
            decode_and_classify_message(&msg, None),
            MessageAction::Convert("album/photo 1".to_string())
        );

        let bytes_b64 = base64::engine::general_purpose::STANDARD.encode(b"album/photo 2");
        let msg_bytes: QueueMessage = serde_json::from_value(serde_json::json!({
            "id": "m2",
            "lease_id": "lease-2",
            "metadata": { "CF-Content-Type": "bytes" },
            "body": bytes_b64
        }))
        .unwrap();
        assert_eq!(
            decode_and_classify_message(&msg_bytes, None),
            MessageAction::Convert("album/photo 2".to_string())
        );

        let msg_v8: QueueMessage = serde_json::from_value(serde_json::json!({
            "lease_id": "lease-3",
            "metadata": { "CF-Content-Type": "v8" },
            "body": "AAAA"
        }))
        .unwrap();
        assert_eq!(
            decode_and_classify_message(&msg_v8, None),
            MessageAction::Malformed
        );
    }

    fn v8_one_byte(s: &[u8]) -> Vec<u8> {
        let mut out = vec![b'"', u8::try_from(s.len()).unwrap()];
        out.extend_from_slice(s);
        out
    }

    fn v8_two_byte(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut out = vec![b'c', u8::try_from(units.len() * 2).unwrap()];
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    fn v8_msg(raw: &[u8]) -> QueueMessage {
        serde_json::from_value(serde_json::json!({
            "lease_id": "lease-v8",
            "metadata": { "CF-Content-Type": "v8" },
            "body": base64::engine::general_purpose::STANDARD.encode(raw)
        }))
        .unwrap()
    }

    #[test]
    fn v8_blink_envelope_map_with_utf16_cjk_key_and_padding() {
        let key = "コスプレ 写真集 Vol.1/photo 1";
        // Blink header (0xFF 0x14) + V8 header (0xFF 0x0F) + JS Map.
        let mut raw = vec![0xFF, 0x14, 0xFF, 0x0F, b';'];
        raw.extend(v8_one_byte(b"key"));
        raw.push(0x00); // kPadding aligning the two-byte string
        raw.extend(v8_two_byte(key));
        raw.extend([b':', 2]);
        assert_eq!(
            decode_v8_webp_task_key(&raw),
            Some(V8TaskKey::Field(key.to_string()))
        );
        assert_eq!(
            decode_and_classify_message(&v8_msg(&raw), None),
            MessageAction::Convert(key.to_string())
        );

        // Blink trailer-offset record (0xFE + 12 bytes) and a padded, unrelated entry are tolerated.
        let mut raw = vec![0xFF, 0x15, 0xFE];
        raw.extend([0u8; 12]);
        raw.extend([0xFF, 0x0F, b';']);
        raw.extend(v8_one_byte(b"n"));
        raw.extend([b'I', 0x04]);
        raw.extend([0x00, 0x00]);
        raw.extend(v8_one_byte(b"key"));
        raw.extend(v8_two_byte(key));
        raw.extend([b':', 4]);
        assert_eq!(
            decode_and_classify_message(&v8_msg(&raw), None),
            MessageAction::Convert(key.to_string())
        );
    }

    #[test]
    fn v8_single_header_object_with_latin1_key() {
        let mut raw = vec![0xFF, 0x0F, b'o'];
        raw.extend(v8_one_byte(b"key"));
        raw.extend(v8_one_byte(b"caf\xe9 album/photo 2"));
        raw.extend([b'{', 1]);
        assert_eq!(
            decode_v8_webp_task_key(&raw),
            Some(V8TaskKey::Field("café album/photo 2".to_string()))
        );
        assert_eq!(
            decode_and_classify_message(&v8_msg(&raw), None),
            MessageAction::Convert("café album/photo 2".to_string())
        );
    }

    #[test]
    fn v8_bare_root_string() {
        let mut raw = vec![0xFF, 0x0F, b'S', 13];
        raw.extend_from_slice(b"album/photo 3");
        assert_eq!(
            decode_v8_webp_task_key(&raw),
            Some(V8TaskKey::Bare("album/photo 3".to_string()))
        );
        assert_eq!(
            decode_and_classify_message(&v8_msg(&raw), None),
            MessageAction::Convert("album/photo 3".to_string())
        );

        let mut raw = vec![0xFF, 0x14, 0xFF, 0x0F];
        raw.extend(v8_one_byte(b"album/photo 4"));
        assert_eq!(
            decode_and_classify_message(&v8_msg(&raw), None),
            MessageAction::Convert("album/photo 4".to_string())
        );
    }

    #[test]
    fn json_body_variants_raw_unpadded_and_missing_content_type() {
        let mk = |meta: serde_json::Value, body: &str| -> QueueMessage {
            serde_json::from_value(serde_json::json!({
                "lease_id": "l", "metadata": meta, "body": body
            }))
            .unwrap()
        };
        let want = MessageAction::Convert("album/photo 8".to_string());

        // Raw JSON string under json content type (not base64).
        let m = mk(
            serde_json::json!({"CF-Content-Type": "json"}),
            r#"{"key":"album/photo 8"}"#,
        );
        assert_eq!(decode_and_classify_message(&m, None), want);

        // Unpadded base64 JSON ({"key":"album/photo 8"} is 23 bytes → padding needed).
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(br#"{"key":"album/photo 8"}"#);
        assert!(!b64.ends_with('='));
        let m = mk(serde_json::json!({"CF-Content-Type": "json"}), &b64);
        assert_eq!(decode_and_classify_message(&m, None), want);

        // Base64 JSON with no content-type metadata at all.
        let b64 = base64::engine::general_purpose::STANDARD.encode(br#"{"key":"album/photo 8"}"#);
        let m = mk(serde_json::json!({}), &b64);
        assert_eq!(decode_and_classify_message(&m, None), want);

        // Alternate metadata key spelling.
        let m = mk(serde_json::json!({"contentType": "JSON"}), &b64);
        assert_eq!(decode_and_classify_message(&m, None), want);

        // Plain key without metadata still works; random non-JSON base64-looking name stays a key.
        let m = mk(serde_json::json!({}), "album/photo 9");
        assert_eq!(
            decode_and_classify_message(&m, None),
            MessageAction::Convert("album/photo 9".to_string())
        );
        let m = mk(serde_json::json!({}), "abcd");
        assert_eq!(
            decode_and_classify_message(&m, None),
            MessageAction::Convert("abcd".to_string())
        );

        // v8 bytes delivered under json content type are still recovered.
        let mut raw = vec![0xFF, 0x0F, b'o'];
        raw.extend(v8_one_byte(b"key"));
        raw.extend(v8_one_byte(b"album/photo 8"));
        raw.extend([b'{', 1]);
        let m = mk(
            serde_json::json!({"CF-Content-Type": "json"}),
            &base64::engine::general_purpose::STANDARD.encode(&raw),
        );
        assert_eq!(decode_and_classify_message(&m, None), want);

        assert!(body_preview(&serde_json::json!("日本語")).starts_with("日本語"));
    }

    #[test]
    fn v8_malformed_or_unsafe_payloads_are_rejected() {
        let mut good = vec![0xFF, 0x0F, b'o'];
        good.extend(v8_one_byte(b"key"));
        good.extend(v8_one_byte(b"album/photo 5"));
        good.extend([b'{', 1]);
        assert!(decode_v8_webp_task_key(&good).is_some());

        // Every strict truncation is rejected.
        for n in 0..good.len() {
            assert_eq!(decode_v8_webp_task_key(&good[..n]), None, "prefix {n}");
        }

        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00, 0x00, 0x00],             // padding only, no header
            vec![b'o', b'{', 0],                // missing version header
            vec![0xFF, 0x0F, 0xFF, 0x0F, 0xFF, 0x0F, b'_'], // too many headers
            vec![0xFF, 0x00, b'S', 1, b'a'],    // zero version
            vec![0xFF, 0x0F, b'S', 0x7F, b'a'], // length past end of buffer
            vec![0xFF, 0x0F, b'S', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
            vec![0xFF, 0x0F, b'c', 3, b'a', 0, b'b'], // odd two-byte length
            vec![0xFF, 0x0F, b'c', 2, 0x00, 0xD8],    // lone surrogate
            vec![0xFF, 0x0F, b'S', 2, 0xC3, 0x28],    // invalid UTF-8
            vec![0xFF, 0x0F, b'o', b'{', 0],          // object without key
            vec![0xFF, 0x0F, b'I', 0x02],             // non-string root
        ];
        for raw in &cases {
            assert_eq!(decode_v8_webp_task_key(raw), None, "{raw:?}");
        }

        // Wrong property count, non-string key value, duplicate key.
        let mut bad_count = good.clone();
        *bad_count.last_mut().unwrap() = 2;
        assert_eq!(decode_v8_webp_task_key(&bad_count), None);

        let mut non_string = vec![0xFF, 0x0F, b'o'];
        non_string.extend(v8_one_byte(b"key"));
        non_string.extend([b'I', 0x02, b'{', 1]);
        assert_eq!(decode_v8_webp_task_key(&non_string), None);

        let mut dup = vec![0xFF, 0x0F, b';'];
        for _ in 0..2 {
            dup.extend(v8_one_byte(b"key"));
            dup.extend(v8_one_byte(b"album/photo 6"));
        }
        dup.extend([b':', 4]);
        assert_eq!(decode_v8_webp_task_key(&dup), None);

        // Structurally valid but unsafe keys are Malformed, as is non-base64 / non-string body.
        for unsafe_key in [&b"../etc/passwd"[..], b"/abs/photo", b"a//b", b"  "] {
            let mut raw = vec![0xFF, 0x0F, b'o'];
            raw.extend(v8_one_byte(b"key"));
            raw.extend(v8_one_byte(unsafe_key));
            raw.extend([b'{', 1]);
            assert_eq!(
                decode_and_classify_message(&v8_msg(&raw), None),
                MessageAction::Malformed
            );
        }
        let not_b64: QueueMessage = serde_json::from_value(serde_json::json!({
            "lease_id": "lease-v8",
            "metadata": { "CF-Content-Type": "v8" },
            "body": "!!not base64!!"
        }))
        .unwrap();
        assert_eq!(
            decode_and_classify_message(&not_b64, None),
            MessageAction::Malformed
        );
        let not_string: QueueMessage = serde_json::from_value(serde_json::json!({
            "lease_id": "lease-v8",
            "metadata": { "CF-Content-Type": "v8" },
            "body": { "key": "album/photo 7" }
        }))
        .unwrap();
        assert_eq!(
            decode_and_classify_message(&not_string, None),
            MessageAction::Malformed
        );
    }

    #[test]
    fn filter_and_target_paths() {
        assert!(should_convert_path("foo/bar - photo 1"));
        assert!(should_convert_path("v1.0/by A - site.com v1.0 - photo 1"));
        assert!(should_convert_path("foo/bar.jpg"));
        assert!(should_convert_path("foo/legacy.bin"));
        assert!(!should_convert_path("foo/bar.webp"));
        assert!(!should_convert_path("foo/bar.WEBP"));
        assert!(!should_convert_path("foo/video.mp4"));
        assert!(!should_convert_path("foo/"));

        assert_eq!(
            target_paths("foo/bar - photo 1"),
            (
                "foo/bar - photo 1.webp".to_string(),
                "foo/bar - photo 1".to_string()
            )
        );
        assert_eq!(
            target_paths("foo/legacy.bin"),
            ("foo/legacy.webp".to_string(), "foo/legacy".to_string())
        );
        assert_eq!(
            target_paths("foo/bar.PNG"),
            ("foo/bar.webp".to_string(), "foo/bar".to_string())
        );
    }

    #[test]
    fn record_meta_updates_replaced_image_dimensions() {
        let mut metas = HashMap::new();
        record_meta(&mut metas, "root.webp", "root".to_string(), 100, 200);
        assert!(metas.contains_key("/"));
        assert_eq!(metas["/"].authors, vec!["Unknown".to_string()]);
        record_meta(
            &mut metas,
            "Unknown/photo.webp",
            "Unknown/photo".to_string(),
            300,
            400,
        );
        assert!(metas.contains_key("Unknown"));
        assert_eq!(metas["/"].images.len(), 1);
        assert_eq!(metas["Unknown"].images.len(), 1);

        record_meta(
            &mut metas,
            "Title A/by Author - Title A - photo 1.webp",
            "Title A/by Author - Title A - photo 1".to_string(),
            800,
            600,
        );
        record_meta(
            &mut metas,
            "Title A/by Author - Title A - photo 1.webp",
            "Title A/by Author - Title A - photo 1".to_string(),
            1200,
            900,
        );
        let m = &metas["Title A"];
        assert_eq!(m.images.len(), 1);
        assert_eq!(m.images[0].width, 1200);
        assert_eq!(m.images[0].height, 900);
    }

    #[test]
    fn ack_envelope_deserializes_map_warnings_and_redacts_debug() {
        let camel: AckEnvelope = serde_json::from_str(
            r#"{"success":true,"errors":[],"result":{"ackCount":3,"retryCount":1,"warnings":{"lease-x":"expired"}}}"#,
        )
        .unwrap();
        assert!(camel.success);
        let r = camel.result.unwrap();
        assert_eq!(r.ack_count, Some(3));
        assert_eq!(r.retry_count, Some(1));
        assert_eq!(r.warnings.get("lease-x"), Some(&serde_json::json!("expired")));

        let snake: AckEnvelope = serde_json::from_str(
            r#"{"success":true,"result":{"ack_count":2,"retry_count":0,"warnings":{}}}"#,
        )
        .unwrap();
        let r = snake.result.unwrap();
        assert_eq!(r.ack_count, Some(2));
        assert_eq!(r.retry_count, Some(0));
        assert!(r.warnings.is_empty());

        let cfg = QueueConfig {
            account_id: "acct".into(),
            queue_id: "q1".into(),
            api_token: "super-secret-token".into(),
            batch_size: 32,
            visibility_timeout_ms: 600_000,
            daemon: false,
            poll_interval: Duration::from_secs(10),
            concurrency: 8,
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("super-secret-token"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn exhausted_warning_only_accounts_for_its_retry_lease() {
        let req = AckRequest {
            acks: vec![AckLease {
                lease_id: "ok".into(),
            }],
            retries: vec![
                RetryLease {
                    lease_id: "failed".into(),
                    delay_seconds: 15,
                },
                RetryLease {
                    lease_id: "pending".into(),
                    delay_seconds: 0,
                },
            ],
        };
        let mut result: AckResult = serde_json::from_value(serde_json::json!({
            "ackCount": 1, "retryCount": 1,
            "warnings": { "failed": "Message has exhausted maxRetries" }
        }))
        .unwrap();
        for count in [1, 2] {
            result.retry_count = Some(count);
            let outcome = result.outcome(&req);
            assert!(outcome.complete);
            assert_eq!(outcome.exhausted_retries, 1);
            assert_eq!(outcome.max_retry_delay_secs, Some(0));
        }

        result.retry_count = Some(0);
        assert!(!result.outcome(&req).complete);
        result.warnings.insert("pending".into(), result.warnings["failed"].clone());
        let outcome = result.outcome(&req);
        assert!(outcome.complete);
        assert_eq!(outcome.exhausted_retries, 2);
        assert_eq!(outcome.max_retry_delay_secs, None);
        result.warnings.remove("pending");
        result.retry_count = Some(2);
        result.ack_count = Some(0);
        assert!(!result.outcome(&req).complete);
        result.ack_count = Some(1);
        let warning = result.warnings.remove("failed").unwrap();
        for lease in ["ok", "unknown"] {
            result.warnings.insert(lease.into(), warning.clone());
            let outcome = result.outcome(&req);
            assert!(!outcome.complete);
            assert_eq!(outcome.exhausted_retries, 0);
            assert_eq!(outcome.max_retry_delay_secs, Some(15));
            result.warnings.remove(lease);
        }
    }

    #[test]
    fn retry_status_and_retry_after() {
        assert!(is_retryable_status(StatusCode::REQUEST_TIMEOUT));
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED));
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST));

        let mut h = HeaderMap::new();
        h.insert(RETRY_AFTER, HeaderValue::from_static("12"));
        assert_eq!(parse_retry_after(&h), Some(Duration::from_secs(12)));
        h.insert(RETRY_AFTER, HeaderValue::from_static("300"));
        assert_eq!(parse_retry_after(&h), Some(Duration::from_secs(300)));

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let future = httpdate::fmt_http_date(now + Duration::from_secs(45));
        h.insert(RETRY_AFTER, HeaderValue::from_str(&future).unwrap());
        assert_eq!(
            parse_retry_after_at(&h, now),
            Some(Duration::from_secs(45))
        );
    }

    static TEST_DIR_SEQ: AtomicUsize = AtomicUsize::new(1);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "img2webp-test-{}-{label}-{seq}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn crc32_ieee(chunks: &[&[u8]]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for slice in chunks {
            for &b in *slice {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    if crc & 1 != 0 {
                        crc = (crc >> 1) ^ 0xEDB8_8320;
                    } else {
                        crc >>= 1;
                    }
                }
            }
        }
        !crc
    }

    fn adler32(data: &[u8]) -> u32 {
        let mut s1 = 1u32;
        let mut s2 = 0u32;
        for &b in data {
            s1 = (s1 + u32::from(b)) % 65_521;
            s2 = (s2 + s1) % 65_521;
        }
        (s2 << 16) | s1
    }

    fn make_png(width: u32, height: u32, rgb: [u8; 3]) -> Vec<u8> {
        fn push_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(tag);
            out.extend_from_slice(data);
            out.extend_from_slice(&crc32_ieee(&[tag, data]).to_be_bytes());
        }

        let mut row = Vec::with_capacity(1 + width as usize * 3);
        row.push(0); // filter: None
        row.extend_from_slice(&rgb.repeat(width as usize));
        let raw = row.repeat(height as usize);
        assert!(raw.len() <= u16::MAX as usize);

        let mut zlib = Vec::with_capacity(raw.len() + 11);
        zlib.extend_from_slice(&[0x78, 0x01, 0x01]);
        let len = raw.len() as u16;
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(&raw);
        zlib.extend_from_slice(&adler32(&raw).to_be_bytes());

        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);

        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        push_chunk(&mut png, b"IHDR", &ihdr);
        push_chunk(&mut png, b"IDAT", &zlib);
        push_chunk(&mut png, b"IEND", &[]);
        png
    }

    struct RawHttpReq {
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl RawHttpReq {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    async fn read_http_req(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> std::io::Result<Option<RawHttpReq>> {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};
        let mut req_line = String::new();
        loop {
            req_line.clear();
            let n = reader.read_line(&mut req_line).await?;
            if n == 0 {
                return Ok(None);
            }
            if !req_line.trim().is_empty() {
                break;
            }
        }
        let mut parts = req_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or_default().to_string();

        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }

        let is_chunked = headers
            .iter()
            .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
        let mut body = Vec::new();
        if is_chunked {
            loop {
                let mut sz_line = String::new();
                reader.read_line(&mut sz_line).await?;
                let sz_hex = sz_line.trim().split(';').next().unwrap_or("0");
                let sz = usize::from_str_radix(sz_hex, 16).unwrap_or(0);
                if sz == 0 {
                    let mut trailer = String::new();
                    let _ = reader.read_line(&mut trailer).await?;
                    break;
                }
                let start = body.len();
                body.resize(start + sz, 0);
                reader.read_exact(&mut body[start..]).await?;
                let mut crlf = [0u8; 2];
                reader.read_exact(&mut crlf).await?;
            }
        } else {
            let content_len = headers
                .iter()
                .find(|(k, _)| k == "content-length")
                .and_then(|(_, v)| v.parse::<usize>().ok())
                .unwrap_or(0);
            if content_len > 0 {
                body.resize(content_len, 0);
                reader.read_exact(&mut body).await?;
            }
        }

        Ok(Some(RawHttpReq {
            method,
            target,
            headers,
            body,
        }))
    }

    async fn write_http_resp(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        status: u16,
        reason: &str,
        extra_headers: &[(String, String)],
        body: &[u8],
        head_content_len: Option<usize>,
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let content_len = head_content_len.unwrap_or(body.len());
        let mut head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {content_len}\r\nConnection: keep-alive\r\n"
        );
        for (k, v) in extra_headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        writer.write_all(head.as_bytes()).await?;
        if head_content_len.is_none() && !body.is_empty() {
            writer.write_all(body).await?;
        }
        writer.flush().await
    }

    fn percent_decode(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
                && let Ok(val) = u8::from_str_radix(hex, 16)
            {
                out.push(val);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    #[derive(Clone)]
    struct StoredObjMeta {
        etag: String,
        size: usize,
        user_meta: HashMap<String, String>,
    }

    struct MockS3State {
        fs_op: Operator,
        bucket: String,
        next_etag: usize,
        objects: HashMap<String, StoredObjMeta>,
        head_src_count: usize,
        head_dst_count: usize,
        get_count: usize,
        put_count: usize,
        delete_count: usize,
    }

    struct MockS3Server {
        endpoint: String,
        bucket: String,
        state: Arc<tokio::sync::Mutex<MockS3State>>,
        _dir: TestDir,
        _task: AbortOnDrop,
    }

    impl MockS3Server {
        async fn start(label: &str, bucket: &str) -> Self {
            let dir = TestDir::new(label);
            let fs_op = Operator::new(opendal::services::Fs::default().root(&dir.path().to_string_lossy()))
                .unwrap();
            let state = Arc::new(tokio::sync::Mutex::new(MockS3State {
                fs_op,
                bucket: bucket.to_string(),
                next_etag: 1,
                objects: HashMap::new(),
                head_src_count: 0,
                head_dst_count: 0,
                get_count: 0,
                put_count: 0,
                delete_count: 0,
            }));

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let endpoint = format!("http://{addr}");

            let state_loop = Arc::clone(&state);
            let handle = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let st = Arc::clone(&state_loop);
                    tokio::spawn(async move {
                        let (r, mut w) = stream.into_split();
                        let mut reader = tokio::io::BufReader::new(r);
                        while let Ok(Some(req)) = read_http_req(&mut reader).await {
                            if handle_s3_req(&st, &req, &mut w).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });

            Self {
                endpoint,
                bucket: bucket.to_string(),
                state,
                _dir: dir,
                _task: AbortOnDrop(handle),
            }
        }

        fn operator(&self) -> Operator {
            Operator::new(
                S3::default()
                    .endpoint(&self.endpoint)
                    .bucket(&self.bucket)
                    .region("us-east-1")
                    .access_key_id("test-key")
                    .secret_access_key("test-secret")
                    .disable_config_load()
                    .disable_ec2_metadata(),
            )
            .unwrap()
        }

        async fn put_raw(&self, key: &str, bytes: Vec<u8>) -> String {
            let mut st = self.state.lock().await;
            let etag = format!("\"etag-{}\"", st.next_etag);
            st.next_etag += 1;
            let size = bytes.len();
            st.fs_op.write(key, bytes).await.unwrap();
            st.objects.insert(
                key.to_string(),
                StoredObjMeta {
                    etag: etag.clone(),
                    size,
                    user_meta: HashMap::new(),
                },
            );
            etag
        }

        async fn reset_counts(&self) {
            let mut st = self.state.lock().await;
            st.head_src_count = 0;
            st.head_dst_count = 0;
            st.get_count = 0;
            st.put_count = 0;
            st.delete_count = 0;
        }
    }

    async fn handle_s3_req(
        state: &Arc<tokio::sync::Mutex<MockS3State>>,
        req: &RawHttpReq,
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
    ) -> std::io::Result<()> {
        let (raw_path, query) = req.target.split_once('?').unwrap_or((&req.target, ""));
        let mut st = state.lock().await;
        let bucket_prefix = format!("/{}", st.bucket);
        let rest = raw_path.strip_prefix(&bucket_prefix).unwrap_or(raw_path);
        let key = percent_decode(rest.strip_prefix('/').unwrap_or(rest));

        // Batch DeleteObjects: POST /<bucket>?delete
        if req.method == "POST" && (query == "delete" || query.starts_with("delete=")) {
            let xml = String::from_utf8_lossy(&req.body);
            let mut rest_xml = xml.as_ref();
            while let Some(start) = rest_xml.find("<Key>") {
                let after = &rest_xml[start + 5..];
                let Some(end) = after.find("</Key>") else {
                    break;
                };
                let del_key = after[..end]
                    .replace("&amp;", "&")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&quot;", "\"")
                    .replace("&apos;", "'");
                st.delete_count += 1;
                let _ = st.fs_op.delete(&del_key).await;
                st.objects.remove(&del_key);
                rest_xml = &after[end + 6..];
            }
            let resp_xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></DeleteResult>";
            return write_http_resp(
                writer,
                200,
                "OK",
                &[("Content-Type".into(), "application/xml".into())],
                resp_xml,
                None,
            )
            .await;
        }

        // ListObjectsV2: GET /<bucket>?list-type=2...
        if req.method == "GET" && key.is_empty() && query.contains("list-type=2") {
            let mut prefix = String::new();
            for pair in query.split('&') {
                if let Some(("prefix", val)) = pair.split_once('=') {
                    prefix = percent_decode(val);
                }
            }
            let mut keys: Vec<(String, StoredObjMeta)> = st
                .objects
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, m)| (k.clone(), m.clone()))
                .collect();
            keys.sort_by(|a, b| a.0.cmp(&b.0));

            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsTruncated>false</IsTruncated>",
            );
            for (k, m) in keys {
                // Intentionally include sub-second milliseconds as real R2/S3 ListObjectsV2 does!
                xml.push_str(&format!(
                    "<Contents><Key>{}</Key><LastModified>2026-11-18T15:36:51.456Z</LastModified><ETag>{}</ETag><Size>{}</Size></Contents>",
                    xml_escape(&k),
                    xml_escape(&m.etag),
                    m.size
                ));
            }
            xml.push_str("</ListBucketResult>");
            return write_http_resp(
                writer,
                200,
                "OK",
                &[("Content-Type".into(), "application/xml".into())],
                xml.as_bytes(),
                None,
            )
            .await;
        }

        match req.method.as_str() {
            "HEAD" => {
                if key.to_ascii_lowercase().ends_with(".webp") {
                    st.head_dst_count += 1;
                } else {
                    st.head_src_count += 1;
                }
                let Some(meta) = st.objects.get(&key).cloned() else {
                    return write_http_resp(writer, 404, "Not Found", &[], b"", Some(0)).await;
                };
                // Intentionally use RFC 7231 1-second HTTP-date as real R2/S3 HeadObject does!
                let mut hdrs = vec![
                    ("ETag".to_string(), meta.etag),
                    (
                        "Last-Modified".to_string(),
                        "Wed, 18 Nov 2026 15:36:51 GMT".to_string(),
                    ),
                ];
                for (mk, mv) in &meta.user_meta {
                    hdrs.push((format!("x-amz-meta-{mk}"), mv.clone()));
                }
                write_http_resp(writer, 200, "OK", &hdrs, b"", Some(meta.size)).await
            }
            "GET" => {
                st.get_count += 1;
                let Some(meta) = st.objects.get(&key).cloned() else {
                    return write_http_resp(writer, 404, "Not Found", &[], b"NotFound", None)
                        .await;
                };
                if let Some(if_match) = req.header("if-match")
                    && if_match.trim() != meta.etag
                {
                    return write_http_resp(
                        writer,
                        412,
                        "Precondition Failed",
                        &[],
                        b"PreconditionFailed",
                        None,
                    )
                    .await;
                }
                let full = st.fs_op.read(&key).await.unwrap().to_bytes();
                let mut hdrs = vec![
                    ("ETag".to_string(), meta.etag),
                    (
                        "Last-Modified".to_string(),
                        "Wed, 18 Nov 2026 15:36:51 GMT".to_string(),
                    ),
                ];
                for (mk, mv) in &meta.user_meta {
                    hdrs.push((format!("x-amz-meta-{mk}"), mv.clone()));
                }
                if let Some(range_hdr) = req.header("range")
                    && let Some(spec) = range_hdr.strip_prefix("bytes=")
                    && let Some((s, e)) = spec.split_once('-')
                    && let Ok(start) = s.parse::<usize>()
                {
                    let end = e
                        .parse::<usize>()
                        .unwrap_or(full.len().saturating_sub(1))
                        .min(full.len().saturating_sub(1));
                    if start < full.len() && start <= end {
                        hdrs.push((
                            "Content-Range".to_string(),
                            format!("bytes {start}-{end}/{}", full.len()),
                        ));
                        return write_http_resp(
                            writer,
                            206,
                            "Partial Content",
                            &hdrs,
                            &full[start..=end],
                            None,
                        )
                        .await;
                    }
                }
                write_http_resp(writer, 200, "OK", &hdrs, &full, None).await
            }
            "PUT" => {
                st.put_count += 1;
                if let Some(inm) = req.header("if-none-match")
                    && inm.trim() == "*"
                    && st.objects.contains_key(&key)
                {
                    return write_http_resp(
                        writer,
                        412,
                        "Precondition Failed",
                        &[],
                        b"PreconditionFailed",
                        None,
                    )
                    .await;
                }
                if let Some(im) = req.header("if-match")
                    && st.objects.get(&key).map(|m| m.etag.as_str()) != Some(im.trim())
                {
                    return write_http_resp(
                        writer,
                        412,
                        "Precondition Failed",
                        &[],
                        b"PreconditionFailed",
                        None,
                    )
                    .await;
                }
                let mut user_meta = HashMap::new();
                for (hk, hv) in &req.headers {
                    if let Some(mk) = hk.strip_prefix("x-amz-meta-") {
                        user_meta.insert(mk.to_string(), hv.clone());
                    }
                }
                let etag = format!("\"etag-{}\"", st.next_etag);
                st.next_etag += 1;
                let size = req.body.len();
                st.fs_op.write(&key, req.body.clone()).await.unwrap();
                st.objects.insert(
                    key,
                    StoredObjMeta {
                        etag: etag.clone(),
                        size,
                        user_meta,
                    },
                );
                write_http_resp(
                    writer,
                    200,
                    "OK",
                    &[("ETag".to_string(), etag)],
                    b"",
                    None,
                )
                .await
            }
            "DELETE" => {
                st.delete_count += 1;
                if let Some(im) = req.header("if-match")
                    && let Some(meta) = st.objects.get(&key)
                    && meta.etag != im.trim()
                {
                    return write_http_resp(
                        writer,
                        412,
                        "Precondition Failed",
                        &[],
                        b"PreconditionFailed",
                        None,
                    )
                    .await;
                }
                let _ = st.fs_op.delete(&key).await;
                st.objects.remove(&key);
                write_http_resp(writer, 204, "No Content", &[], b"", None).await
            }
            _ => write_http_resp(writer, 405, "Method Not Allowed", &[], b"", None).await,
        }
    }

    #[derive(Debug, Deserialize)]
    struct RecordedAckReq {
        acks: Vec<RecordedAckLease>,
        retries: Vec<RecordedRetryLease>,
    }

    #[derive(Debug, Deserialize)]
    struct RecordedAckLease {
        lease_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct RecordedRetryLease {
        lease_id: String,
        delay_seconds: u64,
    }

    struct MockQueueState {
        pull_batches: std::collections::VecDeque<serde_json::Value>,
        ack_warning_first: Option<serde_json::Value>,
        cancel_on_first_pull: Option<CancellationToken>,
        received_acks: Vec<RecordedAckReq>,
    }

    struct MockQueueServer {
        base_url: String,
        state: Arc<tokio::sync::Mutex<MockQueueState>>,
        _task: AbortOnDrop,
    }

    impl MockQueueServer {
        async fn start(
            batches: Vec<serde_json::Value>,
            ack_warning_first: Option<serde_json::Value>,
            cancel_on_first_pull: Option<CancellationToken>,
        ) -> Self {
            let state = Arc::new(tokio::sync::Mutex::new(MockQueueState {
                pull_batches: batches.into(),
                ack_warning_first,
                cancel_on_first_pull,
                received_acks: Vec::new(),
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let base_url = format!("http://{addr}");

            let st_loop = Arc::clone(&state);
            let handle = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let st = Arc::clone(&st_loop);
                    tokio::spawn(async move {
                        let (r, mut w) = stream.into_split();
                        let mut reader = tokio::io::BufReader::new(r);
                        while let Ok(Some(req)) = read_http_req(&mut reader).await {
                            let mut guard = st.lock().await;
                            if req.target.ends_with("/messages/pull") {
                                let msgs = guard
                                    .pull_batches
                                    .pop_front()
                                    .unwrap_or_else(|| serde_json::json!([]));
                                if let Some(cancel) = guard.cancel_on_first_pull.take() {
                                    cancel.cancel();
                                }
                                let body = serde_json::to_vec(&serde_json::json!({
                                    "success": true,
                                    "errors": [],
                                    "result": { "messages": msgs }
                                }))
                                .unwrap();
                                drop(guard);
                                if write_http_resp(
                                    &mut w,
                                    200,
                                    "OK",
                                    &[("Content-Type".into(), "application/json".into())],
                                    &body,
                                    None,
                                )
                                .await
                                .is_err()
                                {
                                    break;
                                }
                            } else if req.target.ends_with("/messages/ack") {
                                let parsed: RecordedAckReq =
                                    serde_json::from_slice(&req.body).unwrap();
                                let ack_len = parsed.acks.len();
                                let retry_len = parsed.retries.len();
                                guard.received_acks.push(parsed);
                                let resp_json = if let Some(warn_obj) =
                                    guard.ack_warning_first.take()
                                {
                                    serde_json::json!({
                                        "success": true,
                                        "errors": [],
                                        "result": {
                                            "ackCount": ack_len.saturating_sub(1),
                                            "retryCount": retry_len,
                                            "warnings": warn_obj
                                        }
                                    })
                                } else {
                                    serde_json::json!({
                                        "success": true,
                                        "errors": [],
                                        "result": {
                                            "ackCount": ack_len,
                                            "retryCount": retry_len,
                                            "warnings": {}
                                        }
                                    })
                                };
                                let body = serde_json::to_vec(&resp_json).unwrap();
                                drop(guard);
                                if write_http_resp(
                                    &mut w,
                                    200,
                                    "OK",
                                    &[("Content-Type".into(), "application/json".into())],
                                    &body,
                                    None,
                                )
                                .await
                                .is_err()
                                {
                                    break;
                                }
                            } else {
                                drop(guard);
                                let _ =
                                    write_http_resp(&mut w, 404, "Not Found", &[], b"{}", None)
                                        .await;
                            }
                        }
                    });
                }
            });

            Self {
                base_url,
                state,
                _task: AbortOnDrop(handle),
            }
        }
    }

    #[tokio::test]
    async fn walk_convert_fs_bin_prefix_boundary_and_delete_origin() {
        let dir = TestDir::new("walk-fs");
        let fs_op =
            Operator::new(opendal::services::Fs::default().root(&dir.path().to_string_lossy()))
                .unwrap();

        fs_op
            .write("album/by Alice - photo 1.png", make_png(8, 6, [200, 50, 50]))
            .await
            .unwrap();
        fs_op
            .write("album/legacy.bin", make_png(12, 9, [50, 200, 50]))
            .await
            .unwrap();
        fs_op
            .write("album/video.mp4", b"not-an-image".to_vec())
            .await
            .unwrap();
        fs_op
            .write("album-other/outside.png", make_png(4, 4, [10, 10, 200]))
            .await
            .unwrap();

        let metas = walk_convert_prefix(fs_op.clone(), fs_op.clone(), "album", true)
            .await
            .unwrap();

        assert!(!fs_op.exists("album/by Alice - photo 1.png").await.unwrap());
        assert!(!fs_op.exists("album/legacy.bin").await.unwrap());
        assert!(fs_op.exists("album/by Alice - photo 1.webp").await.unwrap());
        assert!(fs_op.exists("album/legacy.webp").await.unwrap());
        assert!(fs_op.exists("album/video.mp4").await.unwrap());
        // Prefix boundary: `album` must NOT touch `album-other/`!
        assert!(fs_op.exists("album-other/outside.png").await.unwrap());
        assert!(!fs_op.exists("album-other/outside.webp").await.unwrap());

        assert_eq!(metas.len(), 1);
        let meta = metas.iter().next().unwrap();
        assert_eq!(meta.title, "album");
        assert_eq!(meta.images.len(), 2);
        let img1 = meta
            .images
            .iter()
            .find(|i| i.name == "album/by Alice - photo 1")
            .unwrap();
        assert_eq!((img1.width, img1.height), (8, 6));
        let img2 = meta
            .images
            .iter()
            .find(|i| i.name == "album/legacy")
            .unwrap();
        assert_eq!((img2.width, img2.height), (12, 9));
    }

    #[tokio::test]
    async fn scan_recovers_a_webp_published_after_its_first_head() {
        let s3 = MockS3Server::start("walk-race", "test-bucket").await;
        let path = "Album/photo.jpg";
        let png = make_png(8, 6, [10, 20, 30]);
        s3.put_raw(path, png.clone()).await;
        let op = s3.operator();
        let listed = op.stat(path).await.unwrap();
        let budget = Arc::new(Semaphore::new(0));
        let scan = tokio::spawn({
            let op = op.clone();
            let budget = Arc::clone(&budget);
            async move {
                convert_object(
                    &op,
                    &op,
                    path,
                    Some(&listed),
                    true,
                    true,
                    1,
                    &budget,
                    &Arc::new(Semaphore::new(1)),
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while s3.state.lock().await.head_dst_count == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        op.write_with("Album/photo.webp", convert_checked(&png).unwrap())
            .user_metadata([("source-key".to_owned(), path.to_owned())])
            .await
            .unwrap();
        op.delete(path).await.unwrap();
        budget.add_permits(png.len());
        assert!(matches!(
            scan.await.unwrap().unwrap(),
            ConvertOutcome::SkippedWithMeta { size: (8, 6), .. }
        ));
    }

    #[tokio::test]
    async fn failed_scan_reports_keys_and_causes_without_a_log_subscriber() {
        let s3 = MockS3Server::start("walk-errors", "test-bucket").await;
        for i in 0..5 {
            s3.put_raw(&format!("Album/bad-{i}.jpg"), vec![0; 128])
                .await;
        }
        s3.put_raw("Album/good.png", make_png(8, 6, [10, 20, 30]))
            .await;
        let op = s3.operator();
        let err = walk_convert_prefix_with_concurrency(op.clone(), op, "/", true, 2)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("list_failed=false, item_errors=5"),
            "{message}"
        );
        assert_eq!(message.matches("  \"Album/bad-").count(), 3, "{message}");
        assert_eq!(
            message.matches("Could not decode image").count(),
            3,
            "{message}"
        );
        let st = s3.state.lock().await;
        assert!(st.objects.contains_key("Album/good.webp"));
        assert!(!st.objects.contains_key("Album/good.png"));
        assert!((0..5).all(|i| st.objects.contains_key(&format!("Album/bad-{i}.jpg"))));
    }

    #[tokio::test]
    async fn walk_convert_s3_zero_src_head_and_resume_skip() {
        let s3 = MockS3Server::start("walk-s3", "cos-bucket").await;
        s3.put_raw("AuthorX PostA/照片 1.png", make_png(10, 8, [100, 120, 140]))
            .await;
        s3.put_raw("AuthorX PostA/pic2.bin", make_png(14, 10, [40, 80, 160]))
            .await;
        s3.put_raw("root_photo.jpg", make_png(6, 6, [90, 90, 90]))
            .await;
        s3.reset_counts().await;

        let op = s3.operator();
        let metas1 = walk_convert_prefix_with_concurrency(op.clone(), op.clone(), "/", false, 4)
            .await
            .unwrap();

        {
            let st = s3.state.lock().await;
            assert_eq!(
                st.head_src_count, 0,
                "walk_convert_prefix must reuse ListObjectsV2 Entry::metadata() with zero src HeadObject RPCs"
            );
            assert_eq!(st.head_dst_count, 3);
            assert_eq!(st.get_count, 3);
            assert_eq!(st.put_count, 3);
            let legacy = &st.objects["root_photo.webp"].user_meta;
            assert_eq!(legacy["source-key"], "root_photo.jpg");
            assert!(!legacy.contains_key("source-key-encoding"));
            let encoded = &st.objects["AuthorX PostA/照片 1.webp"].user_meta;
            assert_eq!(encoded["source-key-encoding"], "base64");
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(&encoded["source-key"])
                    .unwrap(),
                "AuthorX PostA/照片 1.png".as_bytes(),
            );
        }

        let root_meta = metas1.iter().find(|m| m.title == "/").unwrap();
        assert_eq!(root_meta.authors, vec!["Unknown".to_string()]);
        assert_eq!(root_meta.images.len(), 1);
        assert_eq!((root_meta.images[0].width, root_meta.images[0].height), (6, 6));

        // Second resumed scan (`!delete_origin` + unchanged source ETags) must skip GET & PUT!
        s3.reset_counts().await;
        let metas2 = walk_convert_prefix_with_concurrency(op.clone(), op, "/", false, 4)
            .await
            .unwrap();

        {
            let st = s3.state.lock().await;
            assert_eq!(st.head_src_count, 0);
            assert_eq!(st.head_dst_count, 3);
            assert_eq!(st.get_count, 0, "resumed scan must skip downloading unchanged sources");
            assert_eq!(st.put_count, 0, "resumed scan must skip re-uploading unchanged WebPs");
        }
        assert_eq!(metas2.len(), 2);
    }

    #[tokio::test]
    async fn pull_convert_base64_json_r2_events_and_journal_recovery() {
        let s3 = MockS3Server::start("pull-ok", "my-bucket").await;
        s3.put_raw("Post1/img_a.png", make_png(8, 6, [10, 20, 30]))
            .await;
        s3.put_raw("Post1/img_b.bin", make_png(10, 12, [40, 50, 60]))
            .await;

        // Seed a WebP whose source was already deleted on an earlier un-acked attempt:
        let pre_webp = convert_checked(&make_png(16, 8, [70, 80, 90])).unwrap();
        let op = s3.operator();
        op.write_with("Post0/redelivered.webp", pre_webp)
            .user_metadata([("source-key".to_string(), "Post0/redelivered.png".to_string())])
            .await
            .unwrap();

        // Seed metadata journal from an earlier interrupted one-shot run:
        let jdir = TestDir::new("journal");
        let journal_file = jdir.path().join("meta-journal.json");
        let mut crashed_metas = HashMap::new();
        record_meta(
            &mut crashed_metas,
            "PostCrashed/saved.webp",
            "PostCrashed/saved".to_string(),
            20,
            30,
        );
        persist_journal(&journal_file, &crashed_metas).unwrap();

        let b64 = |val: serde_json::Value| {
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&val).unwrap())
        };
        let batch1 = serde_json::json!([
            {
                "id": "m1",
                "lease_id": "lease-1",
                "attempts": 1,
                "metadata": { "CF-Content-Type": "json" },
                "body": b64(serde_json::json!({ "key": "Post1/img_a.png" }))
            },
            {
                "lease_id": "lease-2",
                "attempts": 1,
                "metadata": { "CF-Content-Type": "json" },
                "body": b64(serde_json::json!({
                    "bucket": "my-bucket",
                    "action": "PutObject",
                    "object": { "key": "Post1/img_b.bin", "size": 100 }
                }))
            },
            {
                "lease_id": "lease-3",
                "attempts": 2,
                "metadata": { "CF-Content-Type": "json" },
                "body": b64(serde_json::json!({ "key": "Post0/redelivered.png" }))
            },
            {
                "lease_id": "lease-other-bucket",
                "attempts": 1,
                "metadata": { "CF-Content-Type": "json" },
                "body": b64(serde_json::json!({
                    "bucket": "different-bucket",
                    "action": "PutObject",
                    "object": { "key": "Post1/img_a.png" }
                }))
            },
            {
                "lease_id": "lease-delete",
                "attempts": 1,
                "metadata": { "CF-Content-Type": "json" },
                "body": b64(serde_json::json!({
                    "bucket": "my-bucket",
                    "action": "DeleteObject",
                    "object": { "key": "Post1/img_a.png" }
                }))
            }
        ]);

        let q = MockQueueServer::start(vec![batch1], None, None).await;
        let cfg = QueueConfig {
            account_id: "acct".into(),
            queue_id: "q1".into(),
            api_token: "tok".into(),
            batch_size: 32,
            visibility_timeout_ms: 60_000,
            daemon: false,
            poll_interval: Duration::from_secs(1),
            concurrency: 4,
        };

        let metas = pull_convert_inner(
            op.clone(),
            op.clone(),
            cfg,
            true,
            &q.base_url,
            Some(&journal_file),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert!(!journal_file.exists(), "clean one-shot exit must remove journal");
        assert!(!op.exists("Post1/img_a.png").await.unwrap());
        assert!(!op.exists("Post1/img_b.bin").await.unwrap());
        assert!(op.exists("Post1/img_a.webp").await.unwrap());
        assert!(op.exists("Post1/img_b.webp").await.unwrap());
        assert!(s3.state.lock().await.delete_count >= 2);

        assert!(metas.iter().any(|m| m.title == "PostCrashed"));
        let post0 = metas.iter().find(|m| m.title == "Post0").unwrap();
        assert_eq!((post0.images[0].width, post0.images[0].height), (16, 8));
        let post1 = metas.iter().find(|m| m.title == "Post1").unwrap();
        assert_eq!(post1.images.len(), 2);

        let q_state = q.state.lock().await;
        let all_acked: HashSet<String> = q_state
            .received_acks
            .iter()
            .flat_map(|r| r.acks.iter().map(|a| a.lease_id.clone()))
            .collect();
        assert_eq!(all_acked.len(), 5);
    }

    #[tokio::test]
    async fn exhausted_retry_drains_later_unicode_upload_and_preserves_journal() {
        let s3 = MockS3Server::start("pull-exhausted", "my-bucket").await;
        let bad_key = "相册/bad.png";
        let good_key = "相册/照片 1";
        s3.put_raw(bad_key, b"invalid image".to_vec()).await;
        s3.put_raw(good_key, make_png(12, 8, [1, 2, 3])).await;

        let mut task = vec![0xff, 0x0f, b'o'];
        task.extend(v8_one_byte(b"key"));
        task.extend(v8_two_byte(good_key));
        task.extend([b'{', 1]);
        let q = MockQueueServer::start(
            vec![
                serde_json::json!([{ "lease_id": "failed", "body": { "key": bad_key } }]),
                serde_json::json!([{
                    "lease_id": "good",
                    "metadata": { "CF-Content-Type": "v8" },
                    "body": base64::engine::general_purpose::STANDARD.encode(task)
                }]),
            ],
            Some(serde_json::json!({ "failed": "Message has exhausted maxRetries" })),
            None,
        )
        .await;
        let cfg = QueueConfig {
            account_id: "acct".into(),
            queue_id: "q1".into(),
            api_token: "tok".into(),
            batch_size: 32,
            visibility_timeout_ms: 60_000,
            daemon: false,
            poll_interval: Duration::from_secs(1),
            concurrency: 2,
        };
        let dir = TestDir::new("exhausted-journal");
        let journal = dir.path().join("metas.json");
        let op = s3.operator();
        let err = pull_convert_inner(
            op.clone(),
            op.clone(),
            cfg,
            true,
            &q.base_url,
            Some(&journal),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("exhausted_retries=1"));
        assert!(op.exists(bad_key).await.unwrap());
        assert!(!op.exists(good_key).await.unwrap());
        let output = op
            .read(&format!("{good_key}.webp"))
            .await
            .unwrap()
            .to_bytes();
        let size = imagesize::blob_size(&output).unwrap();
        assert_eq!((size.width, size.height), (12, 8));
        assert_eq!(
            load_journal(&journal).unwrap()["相册"].images[0].name,
            good_key
        );
        let state = q.state.lock().await;
        assert_eq!(state.received_acks.len(), 2);
        assert!(state.received_acks[0].acks.is_empty());
        assert_eq!(state.received_acks[0].retries[0].lease_id, "failed");
        assert_eq!(state.received_acks[1].acks[0].lease_id, "good");
        assert!(state.received_acks[1].retries.is_empty());
    }

    #[tokio::test]
    async fn pull_convert_ack_warnings_drains_acks_and_requeues_unstarted() {
        let s3 = MockS3Server::start("pull-warn", "my-bucket").await;
        for i in 0..6 {
            s3.put_raw(&format!("Album/p{i}.png"), make_png(8, 8, [i * 20, 50, 90]))
                .await;
        }
        let op = s3.operator();

        // 8 ignored messages reach flush_threshold (8) immediately on batch start while
        // concurrency=1 leaves 5 pending items unstarted and 1 conversion in flight!
        let mut msgs = Vec::new();
        for i in 0..8 {
            let b64 = base64::engine::general_purpose::STANDARD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "action": "DeleteObject",
                    "object": { "key": format!("Album/old{i}.png") }
                }))
                .unwrap(),
            );
            msgs.push(serde_json::json!({
                "lease_id": format!("lease-ig-{i}"),
                "attempts": 1,
                "metadata": { "CF-Content-Type": "json" },
                "body": b64
            }));
        }
        for i in 0..6 {
            let b64 = base64::engine::general_purpose::STANDARD.encode(
                serde_json::to_vec(&serde_json::json!({ "key": format!("Album/p{i}.png") }))
                    .unwrap(),
            );
            msgs.push(serde_json::json!({
                "lease_id": format!("lease-conv-{i}"),
                "attempts": 1,
                "metadata": { "CF-Content-Type": "json" },
                "body": b64
            }));
        }

        let jdir = TestDir::new("journal-warn");
        let journal_file = jdir.path().join("warn-journal.json");
        let q = MockQueueServer::start(
            vec![serde_json::Value::Array(msgs)],
            Some(serde_json::json!({ "lease-ig-0": "lease expired" })),
            None,
        )
        .await;

        let cfg = QueueConfig {
            account_id: "acct".into(),
            queue_id: "q1".into(),
            api_token: "tok".into(),
            batch_size: 32,
            visibility_timeout_ms: 60_000,
            daemon: false,
            poll_interval: Duration::from_secs(1),
            concurrency: 1,
        };

        let err = pull_convert_inner(
            op,
            s3.operator(),
            cfg,
            false,
            &q.base_url,
            Some(&journal_file),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("warnings or short counts"),
            "unexpected error: {err}"
        );
        assert!(
            journal_file.exists(),
            "journal must be retained when batch is incomplete"
        );

        let q_state = q.state.lock().await;
        assert!(
            q_state.received_acks.len() >= 2,
            "must send follow-up drain ack/retry flush even after ack warnings"
        );
        let settled_conv: HashSet<String> = q_state
            .received_acks
            .iter()
            .flat_map(|r| {
                r.acks
                    .iter()
                    .map(|a| a.lease_id.clone())
                    .chain(r.retries.iter().map(|rt| {
                        assert_eq!(rt.delay_seconds, 0);
                        rt.lease_id.clone()
                    }))
            })
            .filter(|id| id.starts_with("lease-conv-"))
            .collect();
        assert_eq!(
            settled_conv.len(),
            6,
            "every conversion lease must be either acked (completed) or released with 0s delay"
        );
    }

    #[tokio::test]
    async fn collision_and_stale_version_overwrite_protection() {
        let s3 = MockS3Server::start("collision-stale", "my-bucket").await;
        let jpg = "相册 100%/照片.jpg";
        let png = "相册 100%/照片.png";
        s3.put_raw(jpg, make_png(8, 6, [10, 20, 30]))
            .await;
        s3.put_raw(png, make_png(12, 9, [40, 50, 60]))
            .await;

        let op = s3.operator();
        let byte_sem = Arc::new(Semaphore::new(SOURCE_BYTE_BUDGET));
        let cpu_sem = Arc::new(Semaphore::new(2));

        // 1. Convert photo.jpg -> photo.webp
        convert_object(
            &op,
            &op,
            jpg,
            None,
            true,
            true,
            1,
            &byte_sem,
            &cpu_sem,
        )
        .await
        .unwrap();

        // 2. Colliding photo.png -> photo.webp must fail BEFORE reading photo.png!
        s3.reset_counts().await;
        let col_err = convert_object(
            &op,
            &op,
            png,
            None,
            true,
            true,
            1,
            &byte_sem,
            &cpu_sem,
        )
        .await
        .err()
        .expect("collision must fail");
        assert!(col_err.to_string().contains("destination collision"));
        assert_eq!(
            s3.state.lock().await.get_count,
            0,
            "collision must be caught before downloading source"
        );
        assert!(
            op.exists(png).await.unwrap(),
            "colliding source must not be deleted"
        );

        // 3. Stale-version race: slow Worker 1 (v1, 8x6) must not overwrite or delete v2 (16x12)
        s3.put_raw("Album/mutable.jpg", make_png(8, 6, [100, 0, 0]))
            .await;
        let v1_stat = op.stat("Album/mutable.jpg").await.unwrap();
        let v1_id = SourceIdentity::from_meta(&v1_stat);
        let v1_webp = convert_checked(&make_png(8, 6, [100, 0, 0])).unwrap();

        // Producer uploads v2 (16x12) and fast Worker 2 converts it (without deleting v2):
        s3.put_raw("Album/mutable.jpg", make_png(16, 12, [0, 100, 0]))
            .await;
        convert_object(
            &op,
            &op,
            "Album/mutable.jpg",
            None,
            false,
            true,
            1,
            &byte_sem,
            &cpu_sem,
        )
        .await
        .unwrap();

        // Now slow Worker 1 attempts to publish stale v1 (with pre_dst = None AND with existing dst)
        let stale_err = publish_and_cleanup(
            &op,
            &op,
            "Album/mutable.jpg",
            "Album/mutable.webp",
            &v1_id,
            None,
            v1_webp,
            (8, 6),
            true,
        )
        .await
        .unwrap_err();
        assert!(stale_err.to_string().contains("changed during conversion"));
        assert!(
            op.exists("Album/mutable.jpg").await.unwrap(),
            "newer source v2 must not be deleted by stale worker"
        );
        let surviving = op.read("Album/mutable.webp").await.unwrap().to_bytes();
        let sz = imagesize::blob_size(&surviving).unwrap();
        assert_eq!((sz.width, sz.height), (16, 12), "v2 WebP must remain intact");
    }

    #[tokio::test]
    async fn pull_convert_cancellation_exits_nonzero_in_oneshot_and_ok_in_daemon() {
        let s3 = MockS3Server::start("pull-cancel", "my-bucket").await;
        s3.put_raw("Album/c1.png", make_png(8, 6, [1, 2, 3])).await;
        let op = s3.operator();

        let b64 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&serde_json::json!({ "key": "Album/c1.png" })).unwrap());
        let batch = serde_json::json!([{
            "lease_id": "lease-cancel-1",
            "attempts": 1,
            "metadata": { "CF-Content-Type": "json" },
            "body": b64
        }]);

        // 1. One-shot mode: cancellation must release lease (0s delay) and return Err
        let cancel_oneshot = CancellationToken::new();
        let q1 = MockQueueServer::start(
            vec![batch.clone()],
            None,
            Some(cancel_oneshot.clone()),
        )
        .await;
        let jdir = TestDir::new("journal-cancel");
        let jfile = jdir.path().join("cancel.json");
        let cfg_oneshot = QueueConfig {
            account_id: "acct".into(),
            queue_id: "q1".into(),
            api_token: "tok".into(),
            batch_size: 32,
            visibility_timeout_ms: 60_000,
            daemon: false,
            poll_interval: Duration::from_secs(1),
            concurrency: 2,
        };
        let err = pull_convert_inner(
            op.clone(),
            op.clone(),
            cfg_oneshot,
            false,
            &q1.base_url,
            Some(&jfile),
            cancel_oneshot,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("queue pull interrupted by signal"));
        {
            let qs = q1.state.lock().await;
            assert_eq!(qs.received_acks.len(), 1);
            assert_eq!(qs.received_acks[0].retries.len(), 1);
            assert_eq!(qs.received_acks[0].retries[0].lease_id, "lease-cancel-1");
            assert_eq!(qs.received_acks[0].retries[0].delay_seconds, 0);
        }

        // 2. Daemon mode: cancellation must release lease and return Ok(empty)
        let cancel_daemon = CancellationToken::new();
        let q2 = MockQueueServer::start(vec![batch], None, Some(cancel_daemon.clone())).await;
        let cfg_daemon = QueueConfig {
            account_id: "acct".into(),
            queue_id: "q1".into(),
            api_token: "tok".into(),
            batch_size: 32,
            visibility_timeout_ms: 60_000,
            daemon: true,
            poll_interval: Duration::from_secs(1),
            concurrency: 2,
        };
        let ok_metas = pull_convert_inner(
            op.clone(),
            op,
            cfg_daemon,
            false,
            &q2.base_url,
            None,
            cancel_daemon,
        )
        .await
        .unwrap();
        assert!(ok_metas.is_empty());
    }
}
