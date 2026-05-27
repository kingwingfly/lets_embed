#![feature(iterator_try_collect)]

use std::{
    env,
    io::{Read, Seek},
    path::Path,
    sync::Arc,
};

use anyhow::{Ok, bail};
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
    dinov3_session: Arc<Mutex<Session>>,
}

impl Engine {
    pub async fn new(
        clip_text_model_path: impl AsRef<Path>,
        tokenizer_config_path: impl AsRef<Path>,
        dinov3_model_path: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        let pool = PgPool::connect(
            env::var("DATABASE_URL")
                .unwrap_or("postgres://postgres:postgres@postgres:5432/postgres".to_string())
                .as_str(),
        )
        .await?;
        let clip_text_session = siglip2::model(clip_text_model_path)?;
        let tokenizer = siglip2::tokenizer(tokenizer_config_path)?;
        let dinov3_session = dinov3::model(dinov3_model_path)?;
        Ok(Self {
            pool,
            clip_text_session: Arc::new(Mutex::new(clip_text_session)),
            tokenizer,
            dinov3_session: Arc::new(Mutex::new(dinov3_session)),
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
        if tags.is_empty() && not_tags.is_empty() {
            bail!("limit and offset should not be empty at the same time")
        }

        let posts = sqlx::query_as!(
            Post,
            r#"
            SELECT DISTINCT ON (p.id) p.id, p.title
                FROM posts p
                WHERE (
                    NOT EXISTS (
                        SELECT 1
                        FROM unnest($1::TEXT[]) AS pattern
                        WHERE NOT (
                            EXISTS (
                                SELECT 1
                                FROM tag_posts tp
                                JOIN tags t ON t.id = tp.tag_id
                                WHERE tp.post_id = p.id
                                    AND t.name ~* pattern
                            )
                            OR EXISTS (
                                SELECT 1
                                FROM author_posts ap
                                JOIN authors a ON a.id = ap.author_id
                                WHERE ap.post_id = p.id
                                    AND a.name ~* pattern
                            )
                        )
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM tag_posts tp
                        JOIN tags t ON t.id = tp.tag_id
                        WHERE tp.post_id = p.id
                            AND t.name ~* ANY($2::TEXT[])
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM author_posts ap
                        JOIN authors a ON a.id = ap.author_id
                        WHERE ap.post_id = p.id
                            AND a.name ~* ANY($2::TEXT[])
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
                        OR EXISTS (
                            SELECT 1 FROM unnest(wt.translations) AS tr
                            WHERE tr ~* ANY($1::TEXT[])
                        )
                    GROUP BY wti.image_id
                ) sub ON sub.image_id = i.id
                WHERE
                    NOT EXISTS (
                        SELECT 1
                        FROM unnest($1::TEXT[]) AS pattern
                        WHERE NOT EXISTS (
                            SELECT 1
                            FROM wd_tag_images wti
                            JOIN wd_tags wt ON wt.id = wti.wd_tag_id
                            WHERE wti.image_id = i.id
                                AND (
                                    wt.name ~* pattern
                                    OR EXISTS (
                                        SELECT 1 FROM unnest(wt.translations) AS tr
                                        WHERE tr ~* pattern
                                    )
                                )
                        )
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM wd_tag_images wti
                        JOIN wd_tags wt ON wt.id = wti.wd_tag_id
                        WHERE wti.image_id = i.id
                            AND (
                                wt.name ~* ANY($2::TEXT[])
                                OR EXISTS (
                                    SELECT 1 FROM unnest(wt.translations) AS tr
                                    WHERE tr ~* ANY($2::TEXT[])
                                )
                            )
                    )
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
    ) -> anyhow::Result<Vec<Image>> {
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

        let res = sqlx::query_as!(
            Image,
            r#"
            SELECT id, name, width, height
            FROM images i
            ORDER BY (
                SELECT MAX(i.clip_embedding <=> q.vec)
                FROM unnest($1::halfvec[]) AS q(vec)
            )
            LIMIT $2 OFFSET $3
            "#,
            &text_embeddings as _,
            limit,
            offset
        )
        .fetch_all(&mut *xact)
        .await?;

        xact.commit().await?;

        Ok(res)
    }

    pub async fn search_dinov3<R: Read + Seek>(
        &self,
        images: impl IntoIterator<Item = R>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let converted = images
            .into_iter()
            .map(|i| dinov3::convert_image(i))
            .try_collect::<Vec<_>>()?;
        let embeddings = dinov3::infer_vision(&mut self.dinov3_session.lock(), converted)?
            .into_iter()
            .map(|v| HalfVector::from_f32_slice(&v))
            .collect::<Vec<_>>();

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

        let res = sqlx::query_as!(
            Image,
            r#"
            SELECT id, name, width, height
            FROM images i
            ORDER BY (
                SELECT MAX(i.dinov3_embedding <=> q.vec)
                FROM unnest($1::halfvec[]) AS q(vec)
            )
            LIMIT $2 OFFSET $3
            "#,
            &embeddings as _,
            limit,
            offset
        )
        .fetch_all(&mut *xact)
        .await?;

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
