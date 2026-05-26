use std::{
    io::Cursor, iter::repeat, path::PathBuf, sync::LazyLock, thread::available_parallelism,
    time::Duration,
};

use anyhow::bail;
use clap::Parser;
use futures::{StreamExt, stream};
use opendal::{
    Operator,
    services::{Fs, Http},
};
use opentelemetry::{global, metrics::Counter};
use ort::session::Session;
use pgvector::HalfVector;
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use sanitize_filename::sanitize;
use sqlx::postgres::PgPool;
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[clap(version)]
pub struct EmbedCli {
    /// the postgres database of image records
    #[arg(
        short,
        long,
        default_value = "postgres://postgres:postgres@postgres:5432/postgres"
    )]
    database_url: String,

    /// storage url of image data directory: e.g. `fs:./images`, `http://127.0.0.1:3000/path/to/images`
    #[arg(short, long)]
    storage: url::Url,

    /// CLIP vision onnx model path
    #[arg(
        long,
        alias = "cv",
        default_value = "models/jina-clip-v2/onnx/jina-clip-v2-vision.onnx"
    )]
    clip_vision_model: PathBuf,

    /// wd-tagger onnx model path
    #[arg(
        long,
        alias = "wd",
        default_value = "models/wd-eva02-large-tagger-v3/wd-eva02-large-tagger-v3.onnx"
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
    #[arg(long, alias = "tk", default_value_t = 16)]
    top_k: usize,

    /// wd-tagger threshold
    #[arg(long, alias = "th", default_value_t = 0.75)]
    threshold: f32,

    #[arg(long, alias = "bs", default_value_t = 8)]
    batch_size: i64,

    /// whether to quit if `SELECT ... FOR UPDATE SKIP LOCKED` got no record
    #[arg(long, alias = "nq")]
    no_quit_while_empty: bool,
}

impl EmbedCli {
    pub async fn run(self, cancel: CancellationToken) -> anyhow::Result<()> {
        let op = match self.storage.scheme() {
            "fs" | "file" => {
                let root = self.storage.path();
                tracing::info!(dal = "fs", root, "building OpenDAL");
                let fs = Fs::default().root(root);
                Operator::new(fs)?.finish()
            }
            "http" | "https" => {
                let endpoint = self.storage.as_str();
                tracing::info!(dal = "http", endpoint, "building OpenDAL");
                let http = Http::default().endpoint(endpoint);
                Operator::new(http)?.finish()
            }
            _ => bail!("Unsupported storage"),
        };

        let pool = PgPool::connect(&self.database_url).await?;

        let tags = wd_tagger::tags(self.selected_tags)?;
        let tags = tags
            .into_iter()
            .map(|t| &*t.leak::<'static>())
            .collect::<Vec<_>>();

        let wd_tagger_session = wd_tagger::model(self.wd_tagger_model)?;
        let clip_vision_session = jina_clip::model(self.clip_vision_model)?;

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
                &tags,
                self.top_k,
                self.threshold,
                clip_vision_session,
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
    tx: mpsc::Sender<Vec<(i64, Option<(Vec<f32>, Vec<f32>)>)>>,
) -> anyhow::Result<()> {
    while let Some(records) = rx.recv().await {
        let buffers = stream::iter(records)
            .map(|(id, name)| {
                let op = op.clone();
                async move {
                    let filename = format!("{}.webp", sanitize(name));
                    (
                        id,
                        op.read(filename.as_str())
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
                                    jina_clip::convert_image(Cursor::new(buf))
                                        .inspect_err(
                                            |e| tracing::warn!(id, err = %e, "clip convert image"),
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
#[allow(clippy::type_complexity)]
fn infer(
    mut wd_tagger_session: Session,
    tags: &[&'static str],
    top_k: usize,
    threshold: f32,
    mut clip_vision_session: Session,
    mut rx: mpsc::Receiver<Vec<(i64, Option<(Vec<f32>, Vec<f32>)>)>>,
    tx: mpsc::Sender<Vec<(i64, Option<(Vec<(&'static str, f32)>, Vec<f32>)>)>>,
) -> anyhow::Result<()> {
    while let Some(images) = rx.blocking_recv() {
        let (some_ids, wd_images, clip_images, none_ids) = images.into_iter().fold(
            (vec![], vec![], vec![], vec![]),
            |(mut sids, mut wd_images, mut clip_images, mut nids), (id, opt)| {
                match opt {
                    Some((a, b)) => {
                        sids.push(id);
                        wd_images.push(a);
                        clip_images.push(b);
                    }
                    None => nids.push(id),
                }
                (sids, wd_images, clip_images, nids)
            },
        );
        let res =
            match wd_tagger::infer_tag(&mut wd_tagger_session, wd_images, tags, top_k, threshold)
                .and_then(|tags| {
                    Ok((
                        tags,
                        jina_clip::infer_vision(&mut clip_vision_session, clip_images)?,
                    ))
                }) {
                Ok((wd_res, clip_res)) => some_ids
                    .into_iter()
                    .chain(none_ids)
                    .zip(
                        wd_res
                            .into_iter()
                            .zip(clip_res)
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
    mut rx: mpsc::Receiver<Vec<(i64, Option<(Vec<(&'static str, f32)>, Vec<f32>)>)>>,
) -> anyhow::Result<()> {
    while let Some(res) = rx.recv().await {
        let mut wd_ids = vec![];
        let mut tag_names = vec![];
        let mut scores = vec![];
        let mut clip_ids = vec![];
        let mut embeddings = vec![];
        let mut completed_ids = vec![];
        let mut failed_ids = vec![];
        for (id, opt_out) in res {
            match opt_out {
                Some((tags, embedding)) => {
                    for (name, score) in tags {
                        wd_ids.push(id);
                        tag_names.push(name);
                        scores.push(score);
                    }
                    clip_ids.push(id);
                    embeddings.push(HalfVector::from_f32_slice(&embedding));
                    completed_ids.push(id);
                }
                None => failed_ids.push(id),
            }
        }

        sqlx::query!(
            r#"
            WITH input AS (
                SELECT * FROM UNNEST($1::BIGINT[], $2::TEXT[], $3::REAL[]) AS _(id, name, score)
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
            UPDATE images SET clip_embedding = embeddings.embedding
            FROM UNNEST($1::BIGINT[], $2::halfvec[]) AS embeddings (id, embedding)
            WHERE embeddings.id = images.id
        "#,
            &clip_ids,
            &embeddings as _
        )
        .execute(&pool)
        .await?;

        sqlx::query!(
            r#"
            UPDATE images SET status = 'completed'::process_status
            FROM UNNEST($1::BIGINT[]) AS ids (id)
            WHERE ids.id = images.id
        "#,
            &completed_ids
        )
        .execute(&pool)
        .await?;

        sqlx::query!(
            r#"
            UPDATE images SET status = 'pending'::process_status
            FROM UNNEST($1::BIGINT[]) AS ids (id)
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
