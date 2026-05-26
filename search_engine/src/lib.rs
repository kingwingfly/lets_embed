use std::{env, path::Path, sync::Arc};

use anyhow::bail;
use ort::session::Session;
use parking_lot::Mutex;
use pgvector::HalfVector;
use sqlx::{PgPool, Postgres};
use tokenizers::{EncodeInput, Tokenizer};

#[derive(Debug)]
pub struct Engine {
    pool: PgPool,
    clip_text_session: Arc<Mutex<Session>>,
    tokenizer: Tokenizer,
}

impl Engine {
    pub async fn new(
        clip_text_model_path: impl AsRef<Path>,
        tokenizer_config_path: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        let pool = PgPool::connect(
            env::var("DATABASE_URL")
                .unwrap_or("postgres://postgres:postgres@postgres:5432/postgres".to_string())
                .as_str(),
        )
        .await?;
        let clip_text_session = siglip2::model(clip_text_model_path)?;
        let tokenizer = siglip2::tokenizer(tokenizer_config_path)?;
        Ok(Self {
            pool,
            clip_text_session: Arc::new(Mutex::new(clip_text_session)),
            tokenizer,
        })
    }

    pub async fn search_tag<T>(
        &self,
        tags: impl IntoIterator<Item = T>,
        not_tags: impl IntoIterator<Item = T>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<Post>, Vec<Image>)>
    where
        for<'a> &'a [T]: sqlx::Type<Postgres> + sqlx::Encode<'a, Postgres>,
    {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let tags = tags.into_iter().collect::<Vec<_>>();
        let not_tags = not_tags.into_iter().collect::<Vec<_>>();
        let posts = sqlx::query_as!(
            Post,
            r#"
            SELECT DISTINCT ON (p.id) p.id, p.title
                FROM posts p
                WHERE (
                    EXISTS (
                        SELECT 1
                        FROM tag_posts tp
                        JOIN tags t ON t.id = tp.tag_id
                        WHERE tp.post_id = p.id
                          AND t.name ~* ANY($1::TEXT[])
                          AND NOT t.name ~* ANY($2::TEXT[])
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM author_posts ap
                        JOIN authors a ON a.id = ap.author_id
                        WHERE ap.post_id = p.id
                          AND a.name ~* ANY($1::TEXT[])
                          AND NOT a.name ~* ANY($2::TEXT[])
                    )
                )
                LIMIT $3 OFFSET $4
            "#,
            tags.as_slice() as _,
            not_tags.as_slice() as _,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await?;

        let images = sqlx::query_as!(
            Image,
            r#"
            SELECT i.id, i.name, i.width, i.height
            FROM images i
            JOIN (
                SELECT wti.image_id, MAX(wti.score) AS max_score
                FROM wd_tag_images wti
                JOIN wd_tags wt ON wt.id = wti.wd_tag_id
                WHERE wt.name ~* ANY($1::TEXT[])
                  AND NOT wt.name ~* ANY($2::TEXT[])
                GROUP BY wti.image_id
            ) sub ON sub.image_id = i.id
            ORDER BY sub.max_score DESC
            LIMIT $3 OFFSET $4
            "#,
            tags.as_slice() as _,
            not_tags.as_slice() as _,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await?;

        Ok((posts, images))
    }

    pub async fn search_clip<'s>(
        &self,
        describes: impl IntoIterator<Item = impl Into<EncodeInput<'s>> + Send + 's>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Vec<Image>>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let text_embeddings = siglip2::infer_text(
            &self.tokenizer,
            &mut self.clip_text_session.lock(),
            describes,
        )?
        .into_iter()
        .map(|embedding| HalfVector::from_f32_slice(&embedding))
        .collect::<Vec<_>>();

        let mut res: Vec<Vec<Image>> = Vec::with_capacity(text_embeddings.len());

        let mut xact = self.pool.begin().await?;

        sqlx::query(
            format!(
                "SET LOCAL hnsw.ef_search = {}",
                (limit * 4).clamp(100, 1000)
            )
            .as_str(),
        )
        .execute(&mut *xact)
        .await?;

        sqlx::query!("SET LOCAL hnsw.iterative_scan = strict_order")
            .execute(&mut *xact)
            .await?;
        sqlx::query!("SET LOCAL hnsw.max_scan_tuples = 20000")
            .execute(&mut *xact)
            .await?;

        sqlx::query!(
            r#"
            SELECT
                q.ord AS "ord!",
                i.id,
                i.name,
                i.width,
                i.height
            FROM unnest($1::halfvec[]) WITH ORDINALITY AS q(vec, ord)
            CROSS JOIN LATERAL (
                SELECT id, name, width, height, clip_embedding <=> q.vec AS dist
                FROM images
                ORDER BY dist
                LIMIT $2 OFFSET $3
            ) AS i
            ORDER BY q.ord, i.dist;
            "#,
            &text_embeddings as _,
            limit,
            offset
        )
        .fetch_all(&mut *xact)
        .await?
        .into_iter()
        .for_each(|r| {
            let idx = (r.ord - 1) as usize;
            if res.len() <= idx {
                res.resize_with(idx + 1, || Vec::with_capacity(limit as usize));
            }
            res[idx].push(Image {
                id: r.id,
                name: r.name,
                width: r.width,
                height: r.height,
            });
        });

        xact.commit().await?;

        Ok(res)
    }

    pub async fn list(&self, post_id: i64) -> anyhow::Result<Vec<Image>> {
        sqlx::query_as!(
            Image,
            r#"
            SELECT id, name, width, height
            FROM images i
            JOIN post_images pi
            ON i.id = pi.image_id
            WHERE pi.post_id = $1
            "#,
            post_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Image {
    pub id: i64,
    pub name: String,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Post {
    pub id: i64,
    pub title: String,
}
