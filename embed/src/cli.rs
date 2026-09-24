use std::{
    io::Cursor, iter::repeat, path::PathBuf, sync::LazyLock, thread::available_parallelism,
    time::Duration,
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
use starve_not::{DrainBounded, Gate, IdleProbe, Pacer, Ticket};
use tokio::{
    sync::mpsc,
    task::{JoinError, JoinSet},
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
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

    /// target (seconds) for draining claimed images after SIGINT; the number of images in flight
    /// grows while the device starves, but not past what completes within this, or within 1.5×
    /// the fastest observed per-image time when that alone is longer
    #[arg(long, alias = "drain", default_value_t = 10)]
    max_drain_secs: u64,

    /// per-IO timeout (seconds) for remote storage reads
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    io_timeout_secs: u64,

    /// seconds after which an image still `processing` counts as stranded (its worker crashed or
    /// failed mid-flight) and any worker may claim it again; keep well above the worst-case time
    /// an image spends claimed (retried downloads plus drain)
    #[arg(long, alias = "reclaim", default_value_t = 1800, value_parser = clap::value_parser!(u64).range(1..))]
    reclaim_after_secs: u64,

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
                tracing::info!(dal = "r2/s3", config.endpoint, "building OpenDAL");
                Operator::new(
                    S3::default()
                        .endpoint(&config.endpoint)
                        .bucket(&config.bucket)
                        .region(&config.region)
                        .access_key_id(&config.key_id)
                        .secret_access_key(&config.secret),
                )?
                .finish()
            }
        }
        .layer(TimeoutLayer::new().with_io_timeout(io_timeout))
        .layer(
            RetryLayer::new()
                .with_max_times(3)
                .with_min_delay(Duration::from_millis(200))
                .with_max_delay(Duration::from_secs(10))
                .with_jitter(),
        );

        let tags = wd_tagger::tags(self.selected_tags)?;
        let tags = tags.leak::<'static>();

        let wd_tagger_session = wd_tagger::model(self.wd_tagger_model)?;
        let clip_vision_session = siglip2::model(self.clip_vision_model)?;
        let dinov3_session = dinov3::model(self.dinov3_model)?;

        let batch_size = self.batch_size.max(1);
        let decode_concurrency = available_parallelism().map(|num| num.get()).unwrap_or(1);

        let floor = 2 * batch_size;
        let gate = Gate::new(floor);
        let device = IdleProbe::new();
        let policy = DrainBounded::builder()
            .floor(floor)
            .drain_target(Duration::from_secs(self.max_drain_secs))
            .build();
        let pacer = Pacer::builder(&gate, policy)
            .probe(&device)
            .on_decision(|d, _| {
                tracing::debug!(
                    limit = d.limit,
                    target = d.target,
                    in_flight = d.sample.in_flight,
                    diagnostics = %d.diagnostics,
                    "in-flight limit"
                )
            })
            .build()
            .spawn();

        let mut jhs = JoinSet::new();

        let (tx, rx) = mpsc::channel(1);
        jhs.spawn(fetch_batch(
            pool.clone(),
            gate.clone(),
            tx,
            Duration::from_secs(self.reclaim_after_secs),
            self.no_quit_while_empty,
            cancel,
        ));
        // room for every in-progress decode plus two batches, so decoding never waits on the device
        let (tx, rx_) = mpsc::channel(decode_concurrency + 2 * batch_size);
        jhs.spawn(convert_image(op, rx, tx, decode_concurrency));
        // `record` merges whatever queues here into its next write, so let `infer` run ahead
        let (tx, rx__) = mpsc::channel(32);
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
                device,
            )
        });
        jhs.spawn(record(pool, rx__));

        let mut failure: Option<Result<anyhow::Error, JoinError>> = None;
        while let Some(res) = jhs.join_next().await {
            let err = match res {
                Ok(Ok(())) => continue,
                Ok(Err(e)) => Ok(e),
                Err(e) => Err(e),
            };
            gate.close();
            if failure.as_ref().is_none_or(|f| f.is_ok() && err.is_err()) {
                failure = Some(err);
            }
        }
        drop(pacer);

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
    gate: Gate,
    tx: mpsc::Sender<Vec<(i64, String, Ticket)>>,
    reclaim_after: Duration,
    no_quit_while_empty: bool,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let reclaim_after = reclaim_after.as_secs_f64();
    loop {
        // claim as many images as the gate lets in right now
        let mut ticket = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            ticket = gate.acquire_up_to(usize::MAX) => match ticket {
                Ok(ticket) => ticket,
                // closed: a downstream stage failed
                Err(_) => break,
            },
        };
        let claim = ticket.len();

        let records = sqlx::query!(
            r#"
            WITH next_jobs AS (
                SELECT id, name FROM images
                WHERE attempt <= 5 AND (
                    status = 'pending'::process_status
                    -- stranded by a worker that crashed or failed mid-flight
                    OR (status = 'processing'::process_status
                        AND claimed_at < NOW() - make_interval(secs => $2))
                )
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE images SET
            status = 'processing'::process_status, attempt = attempt + 1, claimed_at = NOW()
            FROM next_jobs WHERE images.id = next_jobs.id
            RETURNING images.id, images.name
        "#,
            claim as i64,
            reclaim_after
        )
        .fetch_all(&pool)
        .await?
        .into_iter()
        .map(|r| (r.id, r.name, ticket.split(1)))
        .collect::<Vec<_>>();
        // fewer rows than permits: give the rest back
        ticket.release();

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
    rx: mpsc::Receiver<Vec<(i64, String, Ticket)>>,
    tx: mpsc::Sender<(i64, Option<(Vec<f32>, Vec<f32>, Vec<f32>)>, Ticket)>,
    decode_concurrency: usize,
) -> anyhow::Result<()> {
    let images = ReceiverStream::new(rx)
        .flat_map(stream::iter)
        .map(|(id, name, ticket)| {
            let op = op.clone();
            let download = tokio::spawn(
                async move {
                    op.read(&format!("{}.webp", name))
                        .await
                        .inspect_err(|e| tracing::warn!(id, err = %e, "read image"))
                        .ok()
                }
                .in_current_span(),
            );
            // a panic fails only this image, which goes back to `pending` like a failed read
            async move {
                let buf = download
                    .await
                    .inspect_err(|e| tracing::error!(id, err = %e, "download task"))
                    .ok()
                    .flatten();
                (id, buf, ticket)
            }
        })
        .buffer_unordered(usize::MAX)
        .map(|(id, buf, ticket)| async move {
            let decoded = tokio::task::spawn_blocking(move || {
                buf.and_then(|buf| {
                    let buf = buf.to_bytes();
                    Some((
                        wd_tagger::convert_image(Cursor::new(buf.clone()))
                            .inspect_err(
                                |e| tracing::warn!(id, err = %e, "wd_tagger convert image"),
                            )
                            .ok()?,
                        siglip2::convert_image(Cursor::new(buf.clone()))
                            .inspect_err(|e| tracing::warn!(id, err = %e, "siglip2 convert image"))
                            .ok()?,
                        dinov3::convert_image(Cursor::new(buf))
                            .inspect_err(|e| tracing::warn!(id, err = %e, "dinov3 convert image"))
                            .ok()?,
                    ))
                })
            })
            .await
            .unwrap_or_else(|e| {
                tracing::error!(id, err = %e, "decode task");
                None
            });
            (id, decoded, ticket)
        })
        .buffer_unordered(decode_concurrency);
    let mut images = std::pin::pin!(images);

    while let Some(image) = images.next().await {
        tx.send(image).await?;
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
    mut rx: mpsc::Receiver<(i64, Option<(Vec<f32>, Vec<f32>, Vec<f32>)>, Ticket)>,
    tx: mpsc::Sender<(
        Vec<(i64, Option<(Vec<(&'static Tag, f32)>, Vec<f32>, Vec<f32>)>)>,
        Ticket,
    )>,
    device: IdleProbe,
) -> anyhow::Result<()> {
    // waiting for input is the device starving; waiting on `record` below isn't, since more
    // images in flight wouldn't help
    while let Some((id, image, mut ticket)) = {
        let _idle = device.idle();
        rx.blocking_recv()
    } {
        // take whatever else is decoded, up to a batch: a backlogged device runs full batches,
        // an idle one starts on what it has instead of waiting for slow downloads
        let mut images = vec![(id, image)];
        while images.len() < batch_size
            && let Ok((id, image, more)) = rx.try_recv()
        {
            images.push((id, image));
            ticket.merge(more);
        }
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
        // nothing decoded: skip the device instead of running three zero-size batches
        let res = if some_ids.is_empty() {
            none_ids.into_iter().zip(repeat(None)).collect::<Vec<_>>()
        } else {
            match wd_tagger::infer_tag(
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
            }
        };
        tx.blocking_send((res, ticket))?;
    }
    Ok(())
}

#[tracing::instrument(skip_all, err)]
#[allow(clippy::type_complexity)]
async fn record(
    pool: PgPool,
    mut rx: mpsc::Receiver<(
        Vec<(i64, Option<(Vec<(&'static Tag, f32)>, Vec<f32>, Vec<f32>)>)>,
        Ticket,
    )>,
) -> anyhow::Result<()> {
    /// batches merged into one write, see below
    const COALESCE: usize = 16;
    /// writes in flight at once
    const CONCURRENCY: usize = 4;

    // each write costs 5 sequential DB round trips, which dominate on a remote database: merge
    // whatever batches queued up meanwhile into one write, and overlap writes, so `infer`
    // doesn't block on handing over results. Writes touch disjoint images, and new tag names
    // are inserted in sorted order, so concurrent writes can't deadlock each other.
    // (A plain loop over spawned writes rather than stream combinators: holding those across
    // `.await` with `&'static Tag` inside trips rust-lang/rust#100013.)
    let reap = |write: Result<anyhow::Result<()>, JoinError>| match write {
        Ok(write) => write,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    };
    let mut writes = JoinSet::new();
    let mut failure = None;
    while failure.is_none() {
        let (mut res, mut ticket) = tokio::select! {
            Some(write) = writes.join_next(), if !writes.is_empty() => {
                failure = reap(write).err();
                continue;
            }
            batch = rx.recv(), if writes.len() < CONCURRENCY => match batch {
                Some(batch) => batch,
                None => break,
            },
        };
        for _ in 1..COALESCE {
            match rx.try_recv() {
                Ok((more, more_ticket)) => {
                    res.extend(more);
                    ticket.merge(more_ticket);
                }
                Err(_) => break,
            }
        }

        let pool = pool.clone();
        writes.spawn(
            async move {
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

                // tags first, then associations in a separate statement: a concurrent writer
                // (another write here, or another node) may insert the same new tag, in which
                // case `DO NOTHING` returns no row and a join in the same statement couldn't see
                // the winner's row in its snapshot; the next statement's snapshot does
                sqlx::query!(
                    r#"
            INSERT INTO wd_tags (name)
            SELECT DISTINCT name FROM unnest($1::TEXT[]) AS _(name)
            WHERE trim(name) != ''
            ORDER BY name
            ON CONFLICT DO NOTHING
        "#,
                    &tag_names as _
                )
                .execute(&pool)
                .await?;

                sqlx::query!(
                    r#"
            INSERT INTO wd_tag_images (wd_tag_id, image_id, score)
            SELECT wt.id, i.id, i.score
            FROM unnest($1::BIGINT[], $2::TEXT[], $3::REAL[]) AS i(id, name, score)
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

                // only successes count as throughput: fast failures (e.g. a storage outage) must not
                // grow the in-flight limit and burn retry attempts across the table
                ticket.complete_n(completed_ids.len());
                ticket.release();
                anyhow::Ok(())
            }
            .in_current_span(),
        );
    }
    while let Some(write) = writes.join_next().await {
        if let Err(e) = reap(write) {
            failure.get_or_insert(e);
        }
    }
    failure.map_or(Ok(()), Err)
}
