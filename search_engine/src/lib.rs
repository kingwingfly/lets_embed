#![feature(iterator_try_collect)]

use std::{
    env,
    future::ready,
    io::{Read, Seek},
    path::Path,
    sync::Arc,
};

use anyhow::{Ok, bail};
use futures::{Stream, StreamExt as _};
use ort::session::Session;
use parking_lot::Mutex;
use pgvector::HalfVector;
use search_types::{Image, ImageDetails, Post, Tag};
use sqlx::PgPool;
use tokenizers::{EncodeInput, Tokenizer};

pub use search_types;

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

    pub async fn search_post_by_author<'a>(
        &'a self,
        author_re: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Post> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let author_re = author_re.as_ref().to_owned();
        if author_re.is_empty() {
            bail!("tag should not be empty")
        }

        let posts = sqlx::query_as!(
            Post,
            r#"
            WITH
            pos_authors AS (
                SELECT DISTINCT a.id AS author_id
                FROM authors a
                WHERE a.name ~* $1::TEXT
            ),
            post_match AS (
                SELECT ap.post_id
                FROM author_posts ap
                JOIN pos_authors pa ON pa.author_id = ap.author_id
                GROUP BY ap.post_id
                HAVING count(DISTINCT pa.author_id) = (SELECT count(*) FROM pos_authors)
            )
            SELECT p.id, p.title
            FROM post_match pm
            JOIN posts p ON p.id = pm.post_id
            LIMIT $2 OFFSET $3;
            "#,
            author_re,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(posts)
    }

    pub async fn search_post_by_tag<'a>(
        &'a self,
        tag_re: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Post> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let tag_re = tag_re.as_ref().to_owned();
        if tag_re.is_empty() {
            bail!("tag should not be empty")
        }

        let posts = sqlx::query_as!(
            Post,
            r#"
            WITH
            pos_tags AS (
                SELECT DISTINCT t.id AS tag_id
                FROM tags t
                WHERE t.name ~* $1::TEXT
            ),
            post_match AS (
                SELECT tp.post_id
                FROM tag_posts tp
                JOIN pos_tags pt ON pt.tag_id = tp.tag_id
                GROUP BY tp.post_id
                HAVING count(DISTINCT pt.tag_id) = (SELECT count(*) FROM pos_tags)
            )
            SELECT p.id, p.title
            FROM post_match pm
            JOIN posts p ON p.id = pm.post_id
            LIMIT $2 OFFSET $3;
            "#,
            tag_re,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(posts)
    }

    pub async fn search_image_by_tag<'a>(
        &'a self,
        tag_re: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let tag_re = tag_re.as_ref().to_owned();
        if tag_re.is_empty() {
            bail!("tag should not be empty")
        }

        let images = sqlx::query_as!(
            Image,
            r#"
            WITH
            pos_tags AS (
                SELECT DISTINCT wt.id AS tag_id
                FROM wd_tags wt
                WHERE wt.name ~* $1::TEXT
                    OR EXISTS (SELECT 1 FROM unnest(wt.translations) tr WHERE tr ~*  $1::TEXT)
            ),
            img_match AS (
                SELECT wti.image_id, MAX(wti.score) AS max_score
                FROM wd_tag_images wti
                JOIN pos_tags pt ON pt.tag_id = wti.wd_tag_id
                GROUP BY wti.image_id
                HAVING count(DISTINCT pt.tag_id) = (SELECT count(*) FROM pos_tags)
            )
            SELECT i.id, i.name, i.width, i.height
            FROM img_match im
            JOIN images i ON i.id = im.image_id
            ORDER BY im.max_score DESC
            LIMIT $2 OFFSET $3;
            "#,
            tag_re,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(images)
    }

    pub async fn search_clip<'a, 's>(
        &'a self,
        describes: impl IntoIterator<Item = impl Into<EncodeInput<'s>> + Send + 's>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a> {
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

        let res = sqlx::query_as!(
            Image,
            r#"
            WITH qs AS (
                SELECT q FROM
                unnest($1::halfvec[]) AS _(q)
            )
            SELECT id, name, width, height
            FROM images i
            CROSS JOIN qs
            ORDER BY i.clip_embedding <=> qs.q
            LIMIT $2 OFFSET $3
            "#,
            &text_embeddings as _,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(res)
    }

    pub async fn search_dinov3<'a, R: Read + Seek>(
        &'a self,
        images: impl IntoIterator<Item = R> + Send + 'static,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let converted = tokio::task::spawn_blocking(move || {
            images
                .into_iter()
                .map(|i| dinov3::convert_image(i))
                .try_collect::<Vec<_>>()
        })
        .await
        .unwrap()?;

        let embeddings = dinov3::infer_vision(&mut self.dinov3_session.lock(), converted)?
            .into_iter()
            .map(|v| HalfVector::from_f32_slice(&v))
            .collect::<Vec<_>>();

        let res = sqlx::query_as!(
            Image,
            r#"
            WITH qs AS (
                SELECT q FROM
                unnest($1::halfvec[]) AS _(q)
            )
            SELECT id, name, width, height
            FROM images i
            CROSS JOIN qs
            ORDER BY i.dinov3_embedding <=> qs.q
            LIMIT $2 OFFSET $3
            "#,
            &embeddings as _,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(res)
    }

    pub async fn list_post_images(&self, post_id: i64) -> anyhow::Result<Vec<Image>> {
        sqlx::query_as!(
            Image,
            r#"
            SELECT id, name, width, height
            FROM images i
            JOIN post_images pi ON i.id=pi.image_id
            WHERE pi.post_id=$1
            "#,
            post_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn image_details(&self, id: i64) -> anyhow::Result<ImageDetails> {
        let image = sqlx::query_as!(
            Image,
            r#"
            SELECT id, name, width, height
            FROM images
            WHERE id=$1
            LIMIT 1
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await?;

        let post = sqlx::query_as!(
            Post,
            r#"
            SELECT p.id, p.title
            FROM posts p
            JOIN post_images pi ON p.id=pi.post_id
            WHERE pi.image_id=$1
            LIMIT 1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        let tags = sqlx::query_as!(
            Tag,
            r#"
            SELECT wt.id, wt.name
            FROM wd_tags wt
            JOIN wd_tag_images wti ON wt.id=wti.wd_tag_id
            WHERE wti.image_id=$1
            ORDER BY wti.score DESC
            "#,
            id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(ImageDetails { image, post, tags })
    }
}
