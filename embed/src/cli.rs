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
use opentelemetry::{KeyValue, global, metrics::Counter};
use ort::session::Session;
use pgvector::Vector;
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use sanitize_filename::sanitize;
use sqlx::postgres::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info_span};

use crate::telemetry::HOSTNAME;

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

    /// storage url of image data directory: e.g. `fs:./`, `http://127.0.0.1:3000/path/to/image`
    #[arg(short, long)]
    storage: url::Url,

    /// CLIP vision onnx model path
    #[arg(long, alias = "cv", default_value = "models/cn_clip_vision.onnx")]
    clip_vision_model: PathBuf,

    /// wd-tagger onnx model path
    #[arg(
        long,
        alias = "wd",
        default_value = "models/wd-eva02-large-tagger-v3.onnx"
    )]
    wd_tagger_model: PathBuf,

    /// wd-tagger selected tags csv
    #[arg(long, alias = "tags", default_value = "models/selected_tags.csv")]
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
    #[arg(long, default_value_t = true)]
    quit_while_empty: bool,
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
        let mut wd_tagger_session = wd_tagger::model(self.wd_tagger_model)?;
        let mut clip_vision_session = cn_clip::model(self.clip_vision_model)?;

        loop {
            if cancel.is_cancelled() {
                break;
            }
            let records = sqlx::query!(
                r#"
                WITH next_jobs AS (
                    SELECT id, name FROM images
                    WHERE status = 'Pending'::process_status
                    LIMIT $1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE images SET status = 'Processing'::process_status
                FROM next_jobs WHERE images.id = next_jobs.id
                RETURNING images.id, images.name
            "#,
                self.batch_size
            )
            .fetch_all(&pool)
            .await?
            .into_iter()
            .map(|r| (r.id, r.name));

            if records.len() == 0 {
                match self.quit_while_empty {
                    true => break,
                    false => {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                }
            }

            if let Ok(res) = handle_batch(
                records,
                &op,
                &mut wd_tagger_session,
                &tags,
                self.top_k,
                self.threshold,
                &mut clip_vision_session,
            )
            .await
            {
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
                            embeddings.push(Vector::from(embedding));
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
                    FROM UNNEST($1::BIGINT[], $2::vector[]) AS embeddings (id, embedding)
                    WHERE embeddings.id = images.id
                "#,
                    &clip_ids,
                    &embeddings as _
                )
                .execute(&pool)
                .await?;

                sqlx::query!(
                    r#"
                    UPDATE images SET status = 'Complete'::process_status
                    FROM UNNEST($1::BIGINT[]) AS ids (id)
                    WHERE ids.id = images.id
                "#,
                    &completed_ids
                )
                .execute(&pool)
                .await?;

                sqlx::query!(
                    r#"
                    UPDATE images SET status = 'Pending'::process_status
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
                (*COMPLETE_COUNTER).add(
                    completed_ids.len() as u64,
                    &[
                        KeyValue::new("service.name", "embed"),
                        KeyValue::new("job", "embed"),
                        KeyValue::new("hostname", (*HOSTNAME).as_str()),
                    ],
                );
            }
        }

        Ok(())
    }
}

/// Records: (id, name)
///
/// Returns iterator of `(id, ([(tag, p)], clip_embed))`
#[tracing::instrument(skip_all, err)]
async fn handle_batch<'a>(
    records: impl IntoIterator<Item = (i64, String)>,
    op: &Operator,
    wd_tagger_session: &mut Session,
    tags: &'a [impl AsRef<str>],
    top_k: usize,
    threshold: f32,
    clip_vision_session: &mut Session,
) -> anyhow::Result<impl IntoIterator<Item = (i64, Option<(Vec<(&'a str, f32)>, Vec<f32>)>)>> {
    let buffers = stream::iter(records)
        .map(|(id, name)| {
            async move {
                let filename = format!("{}.jpeg", sanitize(name));
                (
                    id,
                    op.read(filename.as_str())
                        .await
                        .inspect_err(|e| tracing::warn!(id, err = %e, "read image"))
                        .map(|buf| buf.to_bytes())
                        .ok(),
                )
            }
            .instrument(info_span!("read_image"))
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
                                cn_clip::convert_image(Cursor::new(buf))
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

    Ok(
        match (
            wd_tagger::infer_tag(wd_tagger_session, wd_images, tags, top_k, threshold),
            cn_clip::infer_vision(clip_vision_session, clip_images),
        ) {
            (Ok(wd_res), Ok(clip_res)) => some_ids.into_iter().chain(none_ids).zip(
                wd_res
                    .into_iter()
                    .zip(clip_res)
                    .map(Some)
                    .chain(repeat(None)),
            ),
            _ => some_ids
                .into_iter()
                .chain(none_ids)
                .zip(vec![].into_iter().zip(vec![]).map(Some).chain(repeat(None))),
        },
    )
}
