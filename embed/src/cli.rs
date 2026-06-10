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
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use sqlx::postgres::PgPool;
use tokio::{sync::mpsc, task::JoinSet};
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
        default_value = "models/wd-eva02-large-tagger-v3/onnx/wd-eva02-large-tagger-v3.onnx"
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

    #[arg(long, alias = "bs", default_value_t = 4)]
    batch_size: i64,

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
                .layer(
                    TimeoutLayer::new()
                        .with_timeout(Duration::from_secs(600))
                        .with_io_timeout(Duration::from_secs(300)),
                )
                .finish()
            }
        };

        let tags = wd_tagger::tags(self.selected_tags)?;
        let tags = tags.leak::<'static>();

        let wd_tagger_session = wd_tagger::model(self.wd_tagger_model)?;
        let clip_vision_session = siglip2::model(self.clip_vision_model)?;
        let dinov3_session = dinov3::model(self.dinov3_model)?;

        let mut jhs = JoinSet::new();

        let (tx, rx) = mpsc::channel(2);
        jhs.spawn(fetch_batch(
            pool.clone(),
            self.batch_size,
            tx,
            self.no_quit_while_empty,
            cancel,
        ));
        let (tx, rx_) = mpsc::channel(4);
        jhs.spawn(convert_image(op, rx, tx));
        let (tx, rx__) = mpsc::channel(4);
        jhs.spawn_blocking(move || {
            infer(
                wd_tagger_session,
                tags,
                self.top_k,
                self.general_threshold,
                self.character_threshold,
                clip_vision_session,
                dinov3_session,
                rx_,
                tx,
            )
        });
        jhs.spawn(record(pool, rx__));

        let _ = jhs.join_all().await;

        Ok(())
    }
}

#[tracing::instrument(skip_all, err)]
async fn fetch_batch(
    pool: PgPool,
    batch_size: i64,
    tx: mpsc::Sender<Vec<(i64, String)>>,
    no_quit_while_empty: bool,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        if cancel.is_cancelled() {
            break;
        }
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
            batch_size
        )
        .fetch_all(&pool)
        .await?
        .into_iter()
        .map(|r| (r.id, r.name))
        .collect::<Vec<_>>();

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

#[tracing::instrument(skip_all, err)]
#[allow(clippy::type_complexity)]
async fn convert_image(
    op: Operator,
    mut rx: mpsc::Receiver<Vec<(i64, String)>>,
    tx: mpsc::Sender<Vec<(i64, Option<(Vec<f32>, Vec<f32>, Vec<f32>)>)>>,
) -> anyhow::Result<()> {
    while let Some(records) = rx.recv().await {
        let buffers = stream::iter(records)
            .map(|(id, name)| {
                let op = op.clone();
                async move {
                    (
                        id,
                        op.read(name.as_str())
                            .await
                            .inspect_err(|e| tracing::warn!(id, err = %e, "read image"))
                            .map(|buf| buf.to_bytes())
                            .ok(),
                    )
                }
            })
            .buffer_unordered(available_parallelism().map(|num| num.get()).unwrap_or(1))
            .collect::<Vec<_>>()
            .await;
        let images = tokio::task::spawn_blocking(move || {
            buffers
                .into_par_iter()
                .map(|(id, opt_buf)| {
                    {
                        (
                            id,
                            opt_buf.and_then(|buf| {
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
                        )
                    }
                })
                .collect::<Vec<_>>()
        })
        .await?;
        tx.send(images).await?;
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
    mut rx: mpsc::Receiver<Vec<(i64, Option<(Vec<f32>, Vec<f32>, Vec<f32>)>)>>,
    tx: mpsc::Sender<Vec<(i64, Option<(Vec<(&'static Tag, f32)>, Vec<f32>, Vec<f32>)>)>>,
) -> anyhow::Result<()> {
    while let Some(images) = rx.blocking_recv() {
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
        tx.blocking_send(res)?;
    }
    Ok(())
}

#[tracing::instrument(skip_all, err)]
#[allow(clippy::type_complexity)]
async fn record(
    pool: PgPool,
    mut rx: mpsc::Receiver<Vec<(i64, Option<(Vec<(&'static Tag, f32)>, Vec<f32>, Vec<f32>)>)>>,
) -> anyhow::Result<()> {
    while let Some(res) = rx.recv().await {
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
    }
    Ok(())
}
