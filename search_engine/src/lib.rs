#![feature(iterator_try_collect, portable_simd)]

use std::{
    fmt,
    future::ready,
    io::{Read, Seek},
    path::Path,
    simd::f32x16,
    sync::Arc,
    time::Duration,
};

use anyhow::bail;
use futures::{Stream, StreamExt as _};
use ort::session::Session;
use pgvector::HalfVector;
use search_types::{Author, Image, ImageDetails, Post, Tag, Video, VideoDetails};
use sqlx::{Executor as _, PgPool, postgres::PgPoolOptions};
use tokenizers::{EncodeInput, Tokenizer};

pub use search_types;
use tokio::{sync::Mutex, time::Instant};

#[derive(Debug)]
struct Inner {
    session: Option<Arc<Mutex<Session>>>,
    last_used: Instant,
}

#[derive(Clone)]
pub struct LazyModel {
    name: &'static str,
    model: &'static (dyn Fn() -> ort::Result<Session> + Send + Sync + 'static),
    inner: Arc<Mutex<Inner>>,
    idle_timeout: Option<Duration>,
}

impl fmt::Debug for LazyModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyModel")
            .field("name", &self.name)
            .field("inner", &self.inner)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

impl LazyModel {
    pub fn new(
        name: &'static str,
        model: impl Fn() -> ort::Result<Session> + Send + Sync + 'static,
        idle_timeout: Option<Duration>,
    ) -> Self {
        let me = Self {
            name,
            model: Box::leak(Box::new(model)),
            inner: Arc::new(Mutex::new(Inner {
                session: None,
                last_used: Instant::now(),
            })),
            idle_timeout,
        };
        me.spawn_reaper();
        me
    }

    pub async fn session(&self) -> anyhow::Result<Arc<Mutex<Session>>> {
        let mut guard = self.inner.lock().await;

        if guard.session.is_none() {
            let session = tokio::task::spawn_blocking(self.model).await.unwrap()?;
            tracing::info!(model = self.name, "model session ready");
            guard.session = Some(Arc::new(Mutex::new(session)));
        }

        guard.last_used = Instant::now();
        Ok(guard.session.clone().unwrap())
    }

    fn spawn_reaper(&self) {
        let Some(idle_timeout) = self.idle_timeout else {
            return;
        };
        let inner = self.inner.clone();
        let name = self.name;

        tokio::spawn(async move {
            loop {
                let wait = {
                    let mut guard = inner.lock().await;
                    match &guard.session {
                        Some(_) => {
                            let elapsed = guard.last_used.elapsed();
                            if elapsed >= idle_timeout {
                                guard.session = None;
                                tracing::info!(model = name, "model session unloaded (idle)");
                                idle_timeout
                            } else {
                                (idle_timeout - elapsed).max(Duration::from_secs(1))
                            }
                        }
                        None => idle_timeout,
                    }
                };
                tokio::time::sleep(wait).await;
            }
        });
    }
}

#[derive(Debug)]
pub struct Engine {
    pool: PgPool,
    clip_text_session: Option<LazyModel>,
    tokenizer: Option<Arc<Tokenizer>>,
    dinov3_session: Option<LazyModel>,
}

impl Engine {
    /// Create search engine.
    /// This call will return immediately after connecting db and loading tokenizer,
    /// and load siglip2 and dinov3 in back threads lazily.
    pub async fn new(
        clip_text_model_path: Option<impl AsRef<Path>>,
        tokenizer_config_path: Option<impl AsRef<Path>>,
        dinov3_model_path: Option<impl AsRef<Path>>,
        idle_timeout: Option<Duration>,
    ) -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let pool = PgPoolOptions::new()
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    conn.execute("SET hnsw.ef_search = 1000").await?;
                    conn.execute("SET hnsw.iterative_scan = strict_order")
                        .await?;
                    conn.execute("SET hnsw.max_scan_tuples = 2000").await?;
                    Ok(())
                })
            })
            .connect(&dotenvy::var("DATABASE_URL").unwrap())
            .await?;

        if clip_text_model_path.is_some() ^ tokenizer_config_path.is_some() {
            bail!("either both clip_text and tokenizer must be provided, or neither")
        }

        let tokenizer = match tokenizer_config_path {
            Some(p) => Some(Arc::new(siglip2::tokenizer(p)?)),
            None => None,
        };

        let clip_text_session = clip_text_model_path.map(|clip_text_model_path| {
            let clip_text_model_path = clip_text_model_path.as_ref().to_owned();
            LazyModel::new(
                "clip_text",
                move || siglip2::model(&clip_text_model_path),
                idle_timeout,
            )
        });
        let dinov3_session = dinov3_model_path.map(|dinov3_model_path| {
            let dinov3_model_path = dinov3_model_path.as_ref().to_owned();
            LazyModel::new(
                "dinov3",
                move || dinov3::model(&dinov3_model_path),
                idle_timeout,
            )
        });

        Ok(Self {
            pool,
            clip_text_session,
            tokenizer,
            dinov3_session,
        })
    }

    pub async fn newest_posts<'a>(
        &'a self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Post> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let res = sqlx::query_as!(
            Post,
            r#"
            SELECT id, title
            FROM posts
            ORDER BY id DESC
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(res)
    }

    pub async fn search_posts_by_title<'a>(
        &'a self,
        title: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Post> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let title = title.as_ref().to_owned();
        if title.is_empty() {
            bail!("title should not be empty")
        }

        let posts = sqlx::query_as!(
            Post,
            r#"
            SELECT p.id, p.title
            FROM posts p
            WHERE p.title % $1::TEXT
            ORDER BY p.id DESC
            LIMIT $2 OFFSET $3;
            "#,
            &title,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(posts)
    }

    pub async fn search_posts_by_author<'a>(
        &'a self,
        author: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Post> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let author = author.as_ref().to_owned();
        if author.is_empty() {
            bail!("author name should not be empty")
        }

        let posts = sqlx::query_as!(
            Post,
            r#"
            SELECT p.id, p.title
            FROM authors a
            JOIN author_posts ap ON ap.author_id = a.id
            JOIN posts p ON p.id = ap.post_id
            WHERE a.name ILIKE '%' || $1::TEXT || '%'
            ORDER BY p.id DESC
            LIMIT $2 OFFSET $3;
            "#,
            author,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(posts)
    }

    pub async fn search_posts_by_tag<'a>(
        &'a self,
        tag: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Post> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let tag = tag.as_ref().to_owned();
        if tag.is_empty() {
            bail!("tag should not be empty")
        }

        let posts = sqlx::query_as!(
            Post,
            r#"
            SELECT p.id, p.title
            FROM tags t
            JOIN tag_posts tp ON tp.tag_id = t.id
            JOIN posts p ON p.id = tp.post_id
            WHERE t.name ILIKE '%' || $1::TEXT || '%'
            ORDER BY p.id DESC
            LIMIT $2 OFFSET $3;
            "#,
            tag,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(posts)
    }

    pub async fn search_images_by_tag<'a>(
        &'a self,
        tag: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let tag = tag.as_ref().to_owned();
        if tag.is_empty() {
            bail!("tag should not be empty")
        }

        let images = sqlx::query_as!(
            Image,
            r#"
            WITH
            pos_tags AS (
                SELECT wt.id AS tag_id
                FROM wd_tags wt
                WHERE wt.name ILIKE '%' || $1::TEXT || '%'
                UNION
                SELECT tt.tag_id
                FROM wd_tag_translations tt
                WHERE tt.translation ILIKE '%' || $1::TEXT || '%'
            ),
            img_match AS (
                SELECT wti.image_id, MAX(wti.score) AS max_score
                FROM wd_tag_images wti
                JOIN pos_tags pt ON pt.tag_id = wti.wd_tag_id
                GROUP BY wti.image_id
            )
            SELECT i.id, i.name, i.width, i.height
            FROM img_match im
            JOIN images i ON i.id = im.image_id
            ORDER BY im.max_score DESC, im.image_id DESC
            LIMIT $2 OFFSET $3
            "#,
            tag,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(images)
    }

    pub async fn search_clip<'a, 's>(
        &'a self,
        describes: impl IntoIterator<Item = impl Into<EncodeInput<'s>> + Send + 's> + Send + 'static,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let Some(tokenizer) = self.tokenizer.clone() else {
            bail!("tokenizer not enabled")
        };
        let Some(clip_text_lazy) = self.clip_text_session.clone() else {
            bail!("clip_text_session not enabled")
        };
        let clip_text_session = clip_text_lazy.session().await?;
        let text_embeddings = tokio::task::spawn_blocking(move || {
            let mut clip_text_session = clip_text_session.blocking_lock();
            let text_embeddings =
                siglip2::infer_text(&tokenizer, &mut clip_text_session, describes)?
                    .into_iter()
                    .map(|embedding| HalfVector::from_f32_slice(&embedding))
                    .collect::<Vec<_>>();
            anyhow::Ok(text_embeddings)
        })
        .await
        .unwrap()?;

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

        let Some(dinov3_lazy) = self.dinov3_session.as_ref() else {
            bail!("dinov3_session not enblaed")
        };
        let dinov3_session = dinov3_lazy.session().await?;
        let embedding = tokio::task::spawn_blocking(move || {
            let mut dinov3_session = dinov3_session.blocking_lock();
            let embeddings = dinov3::infer_vision(&mut dinov3_session, converted)?;
            drop(dinov3_session);
            let div = f32x16::splat(1.0 / embeddings.len() as f32);
            let mut embedding = embeddings
                .into_iter()
                .map(|v| <[f32; 768]>::try_from(v).unwrap())
                .fold([f32x16::splat(0.0); 768 / 16], |mut acc, v| {
                    for (c, x) in acc.iter_mut().zip(v.chunks_exact(16)) {
                        *c += f32x16::from_slice(x);
                    }
                    acc
                });
            embedding.iter_mut().for_each(|c| *c *= div);
            let embedding =
                HalfVector::from_f32_slice(unsafe { &*(embedding.as_ptr() as *const [f32; 768]) });
            anyhow::Ok(embedding)
        })
        .await
        .unwrap()?;

        let res = sqlx::query_as!(
            Image,
            r#"
            SELECT id, name, width, height
            FROM images i
            ORDER BY i.dinov3_embedding <=> $1::halfvec
            LIMIT $2 OFFSET $3
            "#,
            &embedding as _,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(res)
    }

    pub async fn search_dinov3_by_id<'a>(
        &'a self,
        image_ids: impl IntoIterator<Item = i64> + Send + 'static,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let image_ids = image_ids.into_iter().collect::<Vec<_>>();

        let res = sqlx::query_as!(
            Image,
            r#"
            WITH qs AS (
                SELECT avg(dinov3_embedding) AS q
                FROM images i
                WHERE i.id=ANY($1::BIGINT[])
            )
            SELECT id, name, width, height
            FROM images i
            CROSS JOIN qs
            ORDER BY i.dinov3_embedding <=> qs.q
            LIMIT $2 OFFSET $3
            "#,
            &image_ids as _,
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

        let authors = match post.as_ref() {
            Some(post) => {
                sqlx::query_as!(
                    Author,
                    r#"
                    SELECT id, name
                    FROM authors a
                    JOIN author_posts ap ON a.id=ap.author_id
                    WHERE ap.post_id=$1
                    "#,
                    &post.id
                )
                .fetch_all(&self.pool)
                .await?
            }
            None => vec![],
        };

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

        Ok(ImageDetails {
            image,
            post,
            authors,
            tags,
        })
    }

    pub async fn list_post_videos(&self, post_id: i64) -> anyhow::Result<Vec<Video>> {
        sqlx::query_as!(
            Video,
            r#"
            SELECT id, name, width, height, duration
            FROM videos v
            JOIN post_videos pv ON v.id=pv.video_id
            WHERE pv.post_id=$1
            "#,
            post_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn video_details(&self, id: i64) -> anyhow::Result<VideoDetails> {
        let video = sqlx::query_as!(
            Video,
            r#"
            SELECT id, name, width, height, duration
            FROM videos
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
            JOIN post_videos pv ON p.id=pv.post_id
            WHERE pv.video_id=$1
            LIMIT 1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        let authors = match post.as_ref() {
            Some(post) => {
                sqlx::query_as!(
                    Author,
                    r#"
                    SELECT id, name
                    FROM authors a
                    JOIN author_posts ap ON a.id=ap.author_id
                    WHERE ap.post_id=$1
                    "#,
                    &post.id
                )
                .fetch_all(&self.pool)
                .await?
            }
            None => vec![],
        };

        Ok(VideoDetails {
            video,
            post,
            authors,
            tags: vec![], // TODO: tag video
        })
    }
}
