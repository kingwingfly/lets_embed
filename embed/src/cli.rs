use std::{
    io::Cursor,
    iter::repeat,
    path::PathBuf,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
    thread::available_parallelism,
    time::{Duration, Instant},
};

use anyhow::bail;
use clap::Parser;
use futures::{StreamExt, stream};
use opendal::{
    Operator,
    layers::{RetryLayer, TimeoutLayer},
    services::{Fs, Http, S3},
};
use opentelemetry::{global, metrics::Counter};
use ort::session::Session;
use pgvector::HalfVector;
use sqlx::postgres::PgPool;
use tokio::{
    sync::{Semaphore, mpsc},
    task::{JoinError, JoinSet},
    time::MissedTickBehavior,
};
use tokio_util::sync::CancellationToken;
use wd_tagger::Tag;

#[derive(Debug, Parser)]
#[clap(version)]
pub struct EmbedCli {
    /// storage url of image data directory: e.g. `fs:./images`, `http://127.0.0.1:3000/path/to/images`,
    /// leave none to use s3/r2
    #[arg(short, long)]
    storage: Option<url::Url>,

    /// wd-tagger onnx model path
    #[arg(
        long,
        alias = "wd",
        default_value = "models/wd-eva02-large-tagger-v3/onnx/model.onnx"
    )]
    wd_tagger_model: PathBuf,

    /// wd-tagger selected tags csv
    #[arg(
        long,
        alias = "tags",
        default_value = "models/wd-eva02-large-tagger-v3/selected_tags.csv"
    )]
    selected_tags: PathBuf,

    /// wd-tagger top_k
    #[arg(long, alias = "tk", default_value_t = 36)]
    top_k: usize,

    /// wd-tagger threshold for general tags
    #[arg(long, alias = "gth", default_value_t = 0.3)]
    general_threshold: f32,

    /// wd-tagger threshold for character tags
    #[arg(long, alias = "cth", default_value_t = 0.75)]
    character_threshold: f32,

    /// CLIP vision onnx model path
    #[arg(
        long,
        alias = "cv",
        default_value = "models/siglip2-so400m-patch14-384/onnx/vision_model.onnx"
    )]
    clip_vision_model: PathBuf,

    /// DINOv3 onnx model path
    #[arg(
        long,
        alias = "dn",
        default_value = "models/dinov3-vitb16-pretrain-lvd1689m/onnx/model.onnx"
    )]
    dinov3_model: PathBuf,

    /// images per inference batch fed to the device
    #[arg(long, alias = "bs", default_value_t = 4)]
    batch_size: usize,

    /// upper bound (seconds) on draining claimed images after SIGINT; the number of images in
    /// flight adapts to throughput and storage latency, but never exceeds throughput × this
    #[arg(long, alias = "drain", default_value_t = 10)]
    max_drain_secs: u64,

    /// per-IO timeout (seconds) for remote storage reads
    #[arg(long, default_value_t = 30)]
    io_timeout_secs: u64,

    /// whether to quit if `SELECT ... FOR UPDATE SKIP LOCKED` got no record
    #[arg(long, alias = "nq")]
    no_quit_while_empty: bool,
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

impl EmbedCli {
    pub async fn run(self, cancel: CancellationToken) -> anyhow::Result<()> {
        let pool = PgPool::connect(&dotenvy::var("DATABASE_URL")?).await?;
        let io_timeout = Duration::from_secs(self.io_timeout_secs);

        let op = match self.storage {
            Some(url) => match url.scheme() {
                "fs" | "file" => {
                    let root = url.path();
                    tracing::info!(dal = "fs", root, "building OpenDAL");
                    let fs = Fs::default().root(root);
                    Operator::new(fs)?.finish()
                }
                "http" | "https" => {
                    let endpoint = url.as_str();
                    tracing::info!(dal = "http", endpoint, "building OpenDAL");
                    let http = Http::default().endpoint(endpoint);
                    Operator::new(http)?.finish()
                }
                _ => bail!("Unsupported storage"),
            },
            None => {
                let config = Config::new()?;
                Operator::new(
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
                // fail a stalled read fast (the image goes back to `pending`) instead of
                // holding its slot for minutes
                .layer(
                    TimeoutLayer::new()
                        .with_timeout(io_timeout * 2)
                        .with_io_timeout(io_timeout),
                )
                .finish()
            }
        };

        let tags = wd_tagger::tags(self.selected_tags)?;
        let tags = tags.leak::<'static>();

        let wd_tagger_session = wd_tagger::model(self.wd_tagger_model)?;
        let clip_vision_session = siglip2::model(self.clip_vision_model)?;
        let dinov3_session = dinov3::model(self.dinov3_model)?;

        let batch_size = self.batch_size.max(1);
        let decode_concurrency = available_parallelism().map(|num| num.get()).unwrap_or(1);
        // images claimed but not yet recorded; sized by `pace_in_flight`
        let in_flight = Arc::new(Semaphore::new(2 * batch_size));
        let pace = Arc::new(Pace::default());
        let pacer = tokio::spawn(pace_in_flight(
            in_flight.clone(),
            pace.clone(),
            batch_size,
            Duration::from_secs(self.max_drain_secs),
        ));

        let mut jhs = JoinSet::new();

        let (tx, rx) = mpsc::channel(1);
        jhs.spawn(fetch_batch(
            pool.clone(),
            in_flight.clone(),
            pace.clone(),
            tx,
            self.no_quit_while_empty,
            cancel,
        ));
        // room for every in-progress decode plus two batches, so decoding never waits on the device
        let (tx, rx_) = mpsc::channel(decode_concurrency + 2 * batch_size);
        jhs.spawn(convert_image(op, rx, tx, pace.clone(), decode_concurrency));
        let (tx, rx__) = mpsc::channel(2);
        let infer_pace = pace.clone();
        jhs.spawn_blocking(move || {
            infer(
                wd_tagger_session,
                tags,
                self.top_k,
                self.general_threshold,
                self.character_threshold,
                clip_vision_session,
                dinov3_session,
                batch_size,
                rx_,
                tx,
                infer_pace,
            )
        });
        jhs.spawn(record(pool, in_flight.clone(), pace, rx__));

        // a failed stage never returns its permits, so wake `fetch_batch` from its permit wait;
        // the other stages stop on their closed channels. Keep the first failure (a panic over
        // an error, since the errors are usually closed channels downstream of it) to report
        // once the pipeline has drained.
        let mut failure: Option<Result<anyhow::Error, JoinError>> = None;
        while let Some(res) = jhs.join_next().await {
            let err = match res {
                Ok(Ok(())) => continue,
                Ok(Err(e)) => Ok(e),
                Err(e) => Err(e),
            };
            in_flight.close();
            // first failure wins, except a later panic replaces a returned error
            if failure.as_ref().is_none_or(|f| f.is_ok() && err.is_err()) {
                failure = Some(err);
            }
        }
        pacer.abort();

        match failure {
            None => Ok(()),
            Some(Ok(e)) => Err(e),
            Some(Err(e)) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Some(Err(e)) => Err(e.into()),
        }
    }
}

#[tracing::instrument(skip_all, err)]
async fn fetch_batch(
    pool: PgPool,
    in_flight: Arc<Semaphore>,
    pace: Arc<Pace>,
    tx: mpsc::Sender<Vec<(i64, String)>>,
    no_quit_while_empty: bool,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        // claim a row as soon as one slot frees up, plus whatever else the in-flight limit
        // allows; batching is left to `infer`, so a stalled download never holds back admission.
        // Permits are forgotten here and given back through `Pace::release`
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            permit = in_flight.acquire() => match permit {
                Ok(permit) => permit.forget(),
                // closed: a downstream stage failed
                Err(_) => break,
            },
        }
        let mut claim = 1;
        while let Ok(permit) = in_flight.try_acquire() {
            permit.forget();
            claim += 1;
        }

        let start = Instant::now();
        let records = sqlx::query!(
            r#"
            WITH next_jobs AS (
                SELECT id, name FROM images
                WHERE status = 'pending'::process_status AND attempt <= 5
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE images SET
            status = 'processing'::process_status, attempt = attempt + 1
            FROM next_jobs WHERE images.id = next_jobs.id
            RETURNING images.id, images.name
        "#,
            claim as i64
        )
        .fetch_all(&pool)
        .await?
        .into_iter()
        .map(|r| (r.id, r.name))
        .collect::<Vec<_>>();
        pace.release(&in_flight, claim - records.len());
        // every claimed image waited for this query
        pace.service_micros.fetch_add(
            start.elapsed().as_micros() as u64 * records.len() as u64,
            Relaxed,
        );

        if records.is_empty() {
            match no_quit_while_empty {
                true => {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
                false => break,
            }
        }
        tx.send(records).await?;
    }
    Ok(())
}

/// Download and decode images one by one; `infer` batches them.
///
/// Every claimed image is downloaded at once (their number is already capped by the in-flight
/// limit), a slow image never holds back the others, and each read runs in its own task so the
/// network keeps pulling while this stage waits on the downstream channel.
#[tracing::instrument(skip_all, err)]
#[allow(clippy::type_complexity)]
async fn convert_image(
    op: Operator,
    rx: mpsc::Receiver<Vec<(i64, String)>>,
    tx: mpsc::Sender<(i64, Option<(Vec<f32>, Vec<f32>, Vec<f32>)>)>,
    pace: Arc<Pace>,
    decode_concurrency: usize,
) -> anyhow::Result<()> {
    let images = stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|r| (r, rx)) })
        .flat_map(stream::iter)
        .map(|(id, name)| {
            let op = op.clone();
            let pace = pace.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                let buf = op
                    .read(&format!("{}.webp", name))
                    .await
                    .inspect_err(|e| tracing::warn!(id, err = %e, "read image"))
                    .ok();
                pace.service_micros
                    .fetch_add(start.elapsed().as_micros() as u64, Relaxed);
                (id, buf)
            })
        })
        .buffer_unordered(usize::MAX)
        .map(|res| {
            let pace = pace.clone();
            async move {
                let (id, buf) = res?;
                tokio::task::spawn_blocking(move || {
                    let start = Instant::now();
                    let image = (
                        id,
                        buf.and_then(|buf| {
                            let buf = buf.to_bytes();
                            Some((
                                wd_tagger::convert_image(Cursor::new(buf.clone()))
                                    .inspect_err(
                                        |e| tracing::warn!(id, err = %e, "wd_tagger convert image"),
                                    )
                                    .ok()?,
                                siglip2::convert_image(Cursor::new(buf.clone()))
                                    .inspect_err(
                                        |e| tracing::warn!(id, err = %e, "siglip2 convert image"),
                                    )
                                    .ok()?,
                                dinov3::convert_image(Cursor::new(buf))
                                    .inspect_err(
                                        |e| tracing::warn!(id, err = %e, "dinov3 convert image"),
                                    )
                                    .ok()?,
                            ))
                        }),
                    );
                    pace.service_micros
                        .fetch_add(start.elapsed().as_micros() as u64, Relaxed);
                    image
                })
                .await
            }
        })
        .buffer_unordered(decode_concurrency);
    let mut images = std::pin::pin!(images);

    while let Some(image) = images.next().await {
        tx.send(image?).await?;
    }
    Ok(())
}

#[tracing::instrument(skip_all, err)]
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn infer(
    mut wd_tagger_session: Session,
    tags: &'static [Tag],
    top_k: usize,
    general_threshold: f32,
    character_threshold: f32,
    mut clip_vision_session: Session,
    mut dinov3_session: Session,
    batch_size: usize,
    mut rx: mpsc::Receiver<(i64, Option<(Vec<f32>, Vec<f32>, Vec<f32>)>)>,
    tx: mpsc::Sender<Vec<(i64, Option<(Vec<(&'static Tag, f32)>, Vec<f32>, Vec<f32>)>)>>,
    pace: Arc<Pace>,
) -> anyhow::Result<()> {
    while let Some(image) = rx.blocking_recv() {
        // take whatever else is decoded, up to a batch: a backlogged device runs full batches,
        // an idle one starts on what it has instead of waiting for slow downloads
        let mut images = vec![image];
        while images.len() < batch_size
            && let Ok(image) = rx.try_recv()
        {
            images.push(image);
        }
        let start = Instant::now();
        let batch_len = images.len() as u64;
        let (some_ids, wd_images, clip_images, dino_images, none_ids) = images.into_iter().fold(
            (vec![], vec![], vec![], vec![], vec![]),
            |(mut sids, mut wd_images, mut clip_images, mut dino_images, mut nids), (id, opt)| {
                match opt {
                    Some((a, b, c)) => {
                        sids.push(id);
                        wd_images.push(a);
                        clip_images.push(b);
                        dino_images.push(c);
                    }
                    None => nids.push(id),
                }
                (sids, wd_images, clip_images, dino_images, nids)
            },
        );
        let res = match wd_tagger::infer_tag(
            &mut wd_tagger_session,
            wd_images,
            tags,
            top_k,
            general_threshold,
            character_threshold,
        )
        .and_then(|tags| {
            Ok((
                tags,
                siglip2::infer_vision(&mut clip_vision_session, clip_images)?,
            ))
        })
        .and_then(|(tags, clip_embeddings)| {
            Ok((
                tags,
                clip_embeddings,
                dinov3::infer_vision(&mut dinov3_session, dino_images)?,
            ))
        }) {
            Ok((wd_res, clip_res, dino_res)) => some_ids
                .into_iter()
                .chain(none_ids)
                .zip(
                    wd_res
                        .into_iter()
                        .zip(clip_res)
                        .zip(dino_res)
                        .map(|((a, b), c)| (a, b, c))
                        .map(Some)
                        .chain(repeat(None)),
                )
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::error!("{e}");
                some_ids
                    .into_iter()
                    .chain(none_ids)
                    .zip(repeat(None))
                    .collect::<Vec<_>>()
            }
        };
        // every image of the batch waits for the whole batch
        pace.service_micros
            .fetch_add(start.elapsed().as_micros() as u64 * batch_len, Relaxed);
        tx.blocking_send(res)?;
    }
    Ok(())
}

#[tracing::instrument(skip_all, err)]
#[allow(clippy::type_complexity)]
async fn record(
    pool: PgPool,
    in_flight: Arc<Semaphore>,
    pace: Arc<Pace>,
    mut rx: mpsc::Receiver<Vec<(i64, Option<(Vec<(&'static Tag, f32)>, Vec<f32>, Vec<f32>)>)>>,
) -> anyhow::Result<()> {
    while let Some(res) = rx.recv().await {
        let start = Instant::now();
        let recorded = res.len();
        let mut wd_ids = vec![];
        let mut tag_names = vec![];
        let mut scores = vec![];
        let mut embed_ids = vec![];
        let mut clip_embeddings = vec![];
        let mut dino_embeddings = vec![];
        let mut completed_ids = vec![];
        let mut failed_ids = vec![];
        for (id, opt_out) in res {
            match opt_out {
                Some((tags, clip_embedding, dino_embedding)) => {
                    for (tag, score) in tags {
                        wd_ids.push(id);
                        tag_names.push(tag.name.as_str());
                        scores.push(score);
                    }
                    embed_ids.push(id);
                    clip_embeddings.push(HalfVector::from_f32_slice(&clip_embedding));
                    dino_embeddings.push(HalfVector::from_f32_slice(&dino_embedding));
                    completed_ids.push(id);
                }
                None => failed_ids.push(id),
            }
        }

        sqlx::query!(
            r#"
            WITH input AS (
                SELECT * FROM unnest($1::BIGINT[], $2::TEXT[], $3::REAL[]) AS _(id, name, score)
            ),
            ins_wd_tags AS (
                INSERT INTO wd_tags (name)
                SELECT DISTINCT ON (name) name FROM input i
                WHERE trim(i.name) != ''
                ORDER BY i.name
                ON CONFLICT DO NOTHING
                RETURNING id, name
            ),
            wd_tags AS (
                SELECT * FROM ins_wd_tags
                UNION ALL
                SELECT DISTINCT ON (wt.id) wt.id, name
                FROM input i
                JOIN wd_tags wt USING (name)
            )
            INSERT INTO wd_tag_images (wd_tag_id, image_id, score)
            SELECT wt.id, i.id, i.score
            FROM input i
            JOIN wd_tags wt USING (name)
            ON CONFLICT (wd_tag_id, image_id) DO UPDATE
            SET score = EXCLUDED.score
        "#,
            &wd_ids,
            &tag_names as _,
            &scores
        )
        .execute(&pool)
        .await?;

        sqlx::query!(
            r#"
            UPDATE images
            SET dinov3_embedding = embeddings.dinov3_embedding,
                clip_embedding = embeddings.clip_embedding
            FROM unnest($1::BIGINT[], $2::halfvec[], $3::halfvec[])
                AS embeddings(id, dinov3_embedding, clip_embedding)
            WHERE embeddings.id = images.id
        "#,
            &embed_ids,
            &dino_embeddings as _,
            &clip_embeddings as _
        )
        .execute(&pool)
        .await?;

        sqlx::query!(
            r#"
            UPDATE images SET status = 'completed'::process_status
            FROM unnest($1::BIGINT[]) AS ids (id)
            WHERE ids.id = images.id
        "#,
            &completed_ids
        )
        .execute(&pool)
        .await?;

        sqlx::query!(
            r#"
            UPDATE images SET status = 'pending'::process_status
            FROM unnest($1::BIGINT[]) AS ids (id)
            WHERE ids.id = images.id
        "#,
            &failed_ids
        )
        .execute(&pool)
        .await?;

        static COMPLETE_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
            let infer = global::meter("infer");
            infer
                .u64_counter("infer.complete")
                .with_description("infer counter of the completed")
                .with_unit("1")
                .build()
        });
        (*COMPLETE_COUNTER).add(completed_ids.len() as u64, &[]);

        pace.service_micros.fetch_add(
            start.elapsed().as_micros() as u64 * recorded as u64,
            Relaxed,
        );
        pace.recorded.fetch_add(recorded as u64, Relaxed);
        pace.release(&in_flight, recorded);
    }
    Ok(())
}

/// Counters sampled by `pace_in_flight`
#[derive(Default)]
struct Pace {
    /// images written back by `record`, i.e. pipeline throughput
    recorded: AtomicU64,
    /// summed per-image service time (µs) of every stage: fetch, download, decode, infer, record
    service_micros: AtomicU64,
    /// permits still to retire for a shrink the pacer couldn't apply to idle permits
    retiring: AtomicUsize,
}

impl Pace {
    /// Return `n` permits, first retiring any the pacer asked to drop
    fn release(&self, in_flight: &Semaphore, n: usize) {
        let retired = self
            .retiring
            .fetch_update(Relaxed, Relaxed, |r| Some(r - r.min(n)))
            .map_or(0, |r| r.min(n));
        in_flight.add_permits(n - retired);
    }
}

/// Size the in-flight limit by Little's law: an image holds its permit from claim to record, so
/// keeping every stage busy needs `throughput × latency` images in flight, where latency is the
/// time an image is being served by the stages. Time spent queued between stages is left out, so
/// a saturated device doesn't inflate the limit. The limit is kept within
/// `[2 × batch_size, throughput × max_drain]`, which bounds the SIGINT drain time.
#[tracing::instrument(skip_all)]
async fn pace_in_flight(
    in_flight: Arc<Semaphore>,
    pace: Arc<Pace>,
    batch_size: usize,
    max_drain: Duration,
) {
    const HEADROOM: f64 = 1.5;
    const SMOOTHING: f64 = 0.5;

    let floor = 2 * batch_size;
    // permits in circulation once pending retirements (`Pace::retiring`) are done
    let mut limit = floor;
    // images/s and seconds per image, exponentially smoothed
    let (mut throughput, mut latency) = (0f64, 0f64);
    let (mut recorded, mut service_micros) = (0, 0);
    let mut last = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    // after a stall, don't fire a burst of catch-up ticks with near-zero `elapsed`
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let elapsed = last.elapsed().as_secs_f64();
        last = Instant::now();

        let now_recorded = pace.recorded.load(Relaxed);
        let sample = (now_recorded - recorded) as f64 / elapsed;
        throughput += SMOOTHING * (sample - throughput);
        // until images get recorded, keep accumulating their service time into the next sample
        if now_recorded > recorded {
            let now_service_micros = pace.service_micros.load(Relaxed);
            let sample = (now_service_micros - service_micros) as f64
                / 1e6
                / (now_recorded - recorded) as f64;
            latency += SMOOTHING * (sample - latency);
            (recorded, service_micros) = (now_recorded, now_service_micros);
        }

        let ceiling = ((throughput * max_drain.as_secs_f64()) as usize).max(floor);
        let target = ((throughput * latency * HEADROOM) as usize + floor).min(ceiling);
        if target > limit {
            // cancel pending retirements before adding permits
            let grow = target - limit;
            let cancelled = pace
                .retiring
                .fetch_update(Relaxed, Relaxed, |r| Some(r - r.min(grow)))
                .map_or(0, |r| r.min(grow));
            in_flight.add_permits(grow - cancelled);
        } else if target < limit {
            // idle permits go now; held ones are retired by `Pace::release` as they come back,
            // since a waiting `fetch_batch` would otherwise take them before they turn idle
            let shrink = limit - target;
            let forgotten = in_flight.forget_permits(shrink);
            pace.retiring.fetch_add(shrink - forgotten, Relaxed);
        }
        limit = target;
        tracing::debug!(throughput, latency, limit, "in-flight limit");
    }
}
