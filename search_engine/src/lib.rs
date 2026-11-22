#![feature(iterator_try_collect, portable_simd)]

mod advanced;

pub use advanced::{AdvancedSearchRequest, AdvancedSearchResult};

use std::{
    borrow::Borrow,
    fmt,
    future::ready,
    hash::{DefaultHasher, Hash, Hasher},
    io::{Cursor, Read, Seek},
    path::Path,
    simd::f32x16,
    sync::{Arc, LazyLock},
    time::Duration,
};

use anyhow::{anyhow, bail};
use futures::{Stream, StreamExt as _};
use moka::future::Cache;
use ort::session::Session;
use pgvector::HalfVector;
use search_types::{Author, Image, ImageDetails, Post, PostMeta, Tag, Video, VideoDetails};
use sqlx::{Executor as _, PgPool, Row as _, postgres::PgPoolOptions};
use tokenizers::{EncodeInput, Tokenizer};

/// Compact post summary returned by batch preview lookups.
#[derive(Debug, Clone)]
pub struct PostPreview {
    pub post_id: i64,
    pub title: String,
    pub cover: Option<Image>,
    pub image_count: usize,
    pub video_count: usize,
}

/// Batch gallery cover summary returned for album cards.
#[derive(Debug, Clone)]
pub struct PostGalleryCover {
    pub post_id: i64,
    pub title: String,
    pub cover_image: Option<Image>,
    pub cover_video: Option<Video>,
    pub image_count: usize,
    pub video_count: usize,
}

/// Escape `%`, `_`, and `\` so user input is treated as a literal substring in `ILIKE`.
fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Build an `ILIKE` pattern for autocomplete: uses substring `%pat%` only when
/// the query has at least 3 characters (so `pg_trgm` GIN indexes can extract
/// trigrams), and prefix-only `pat%` for shorter 1–2 char inputs.
fn autocomplete_like_pattern(raw: &str, escaped: &str) -> String {
    if raw.chars().count() >= 3 {
        format!("%{escaped}%")
    } else {
        format!("{escaped}%")
    }
}

pub use search_types;
use tokio::{sync::Mutex, time::Instant};

/// splitmix64 finalizer — a fast, well-distributed integer hash.
fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Counter-based RNG: map sequence indices `[offset, offset+limit)` to ids in
/// `[min, max]`. Being counter-based (each index hashed independently) means any
/// offset costs O(1) to reach and the whole stream is reproducible from `seed`
/// alone. Ids are sampled with replacement, so we de-duplicate within the page
/// (order preserved) to avoid showing the same row twice; the caller drops ids
/// that don't resolve to a row. Requires `min <= max`.
fn random_ids(seed: i64, min: i64, max: i64, limit: i64, offset: i64) -> Vec<i64> {
    let span = (max - min + 1) as u64;
    let seed = seed as u64;
    let mut seen = std::collections::HashSet::new();
    (offset..offset.saturating_add(limit))
        .map(|i| min + (mix64(seed ^ mix64(i as u64)) % span) as i64)
        .filter(|id| seen.insert(*id))
        .collect()
}

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

fn ort_env() -> ort::Result<ort::environment::Environment> {
    static ENV: std::sync::Mutex<Option<ort::environment::Environment>> =
        std::sync::Mutex::new(None);
    let mut guard = ENV
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(env) = guard.as_ref() {
        return Ok(env.clone());
    }
    let env = ort::init().with_name("search_engine").build()?;
    *guard = Some(env.clone());
    Ok(env)
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
                    conn.execute("SET hnsw.max_scan_tuples = 4000").await?;
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
                move || {
                    let env = ort_env()?;
                    siglip2::model_with_env(&env, &clip_text_model_path)
                },
                idle_timeout,
            )
        });
        let dinov3_session = dinov3_model_path.map(|dinov3_model_path| {
            let dinov3_model_path = dinov3_model_path.as_ref().to_owned();
            LazyModel::new(
                "dinov3",
                move || {
                    let env = ort_env()?;
                    dinov3::model_with_env(&env, &dinov3_model_path)
                },
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

    /// Deterministic random posts for a given `seed`. Page `[offset, offset+limit)`
    /// indexes a counter-based RNG (see [`random_ids`]), so any offset is reached in
    /// O(1) — the random state lives entirely in `seed` and can be carried in a URL.
    /// Ids that no longer exist are silently dropped, so a page may hold < `limit`
    /// rows; if the row set changes the sample is allowed to change with it.
    pub async fn random_posts<'a>(
        &'a self,
        seed: i64,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Post> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let bounds = sqlx::query!(r#"SELECT MIN(id) AS min_id, MAX(id) AS max_id FROM posts"#)
            .fetch_one(&self.pool)
            .await?;
        let ids = match (bounds.min_id, bounds.max_id) {
            (Some(min), Some(max)) => random_ids(seed, min, max, limit, offset),
            _ => vec![],
        };

        let res = sqlx::query_as!(
            Post,
            r#"
            SELECT p.id, p.title
            FROM UNNEST($1::BIGINT[]) WITH ORDINALITY AS c(id, ord)
            JOIN posts p ON p.id = c.id
            ORDER BY c.ord
            "#,
            &ids,
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(res)
    }

    /// Deterministic random images for a given `seed`; see [`Engine::random_posts`].
    pub async fn random_images<'a>(
        &'a self,
        seed: i64,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let bounds = sqlx::query!(r#"SELECT MIN(id) AS min_id, MAX(id) AS max_id FROM images"#)
            .fetch_one(&self.pool)
            .await?;
        let ids = match (bounds.min_id, bounds.max_id) {
            (Some(min), Some(max)) => random_ids(seed, min, max, limit, offset),
            _ => vec![],
        };

        let res = sqlx::query_as!(
            Image,
            r#"
            SELECT i.id, i.name, i.width, i.height
            FROM UNNEST($1::BIGINT[]) WITH ORDINALITY AS c(id, ord)
            JOIN images i ON i.id = c.id
            ORDER BY c.ord
            "#,
            &ids,
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
            WHERE p.title ILIKE '%' || $1::TEXT || '%'
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

        let raw = tag.as_ref().trim().to_owned();
        if raw.is_empty() {
            bail!("tag should not be empty")
        }
        let underscored = raw.replace(' ', "_");
        let pat_raw = format!("%{}%", escape_like(&raw));
        let pat_under = format!("%{}%", escape_like(&underscored));

        let images = sqlx::query(
            r#"
            WITH
            pos_tags AS (
                SELECT wt.id AS tag_id
                FROM wd_tags wt
                WHERE wt.name ILIKE $1 ESCAPE '\'
                   OR ($2 <> $1 AND wt.name ILIKE $2 ESCAPE '\')
                UNION
                SELECT tt.tag_id
                FROM wd_tag_translations tt
                WHERE tt.translation ILIKE $1 ESCAPE '\'
            ),
            img_match AS (
                SELECT wti.image_id, MAX(wti.score) AS max_score
                FROM wd_tag_images wti
                JOIN pos_tags pt ON pt.tag_id = wti.wd_tag_id
                GROUP BY wti.image_id
            )
            SELECT i.id, i.name::TEXT AS name, i.width, i.height
            FROM img_match im
            JOIN images i ON i.id = im.image_id
            ORDER BY im.max_score DESC, im.image_id DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(pat_raw)
        .bind(pat_under)
        .bind(limit)
        .bind(offset)
        .fetch(&self.pool)
        .filter_map(|res| {
            ready(res.ok().and_then(|r| {
                Some(Image {
                    id: r.try_get("id").ok()?,
                    name: r.try_get("name").ok()?,
                    width: r.try_get("width").ok()?,
                    height: r.try_get("height").ok()?,
                })
            }))
        });

        Ok(images)
    }

    async fn clip_embedding<'s, I>(
        &self,
        describes: impl IntoIterator<Item = I> + Send + 'static,
    ) -> anyhow::Result<HalfVector>
    where
        I: Into<EncodeInput<'s>> + Send + 's,
    {
        let Some(tokenizer) = self.tokenizer.clone() else {
            bail!("tokenizer not enabled")
        };
        let Some(clip_text_lazy) = self.clip_text_session.clone() else {
            bail!("clip_text_session not enabled")
        };
        let clip_text_session = clip_text_lazy.session().await?;
        tokio::task::spawn_blocking(move || {
            let mut clip_text_session = clip_text_session.blocking_lock();
            let embeddings = siglip2::infer_text(&tokenizer, &mut clip_text_session, describes)?
                .into_iter()
                .collect::<Vec<_>>();
            let div = f32x16::splat(1.0 / embeddings.len() as f32);
            let mut embedding = embeddings
                .into_iter()
                .map(|v| <[f32; siglip2::EMBED_DIM]>::try_from(v).unwrap())
                .fold(
                    [f32x16::splat(0.0); siglip2::EMBED_DIM / 16],
                    |mut acc, v| {
                        for (c, x) in acc.iter_mut().zip(v.as_chunks::<16>().0) {
                            *c += f32x16::from_slice(x);
                        }
                        acc
                    },
                );
            embedding.iter_mut().for_each(|c| *c *= div);
            let embedding = HalfVector::from_f32_slice(unsafe {
                &*(embedding.as_ptr() as *const [f32; siglip2::EMBED_DIM])
            });
            anyhow::Ok(embedding)
        })
        .await
        .unwrap()
    }

    async fn search_clip_inner<'a>(
        &'a self,
        embedding: impl Borrow<HalfVector>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let res = sqlx::query_as!(
            Image,
            r#"
            SELECT id, name, width, height
            FROM images i
            ORDER BY i.clip_embedding <=> $1::halfvec
            LIMIT $2 OFFSET $3
            "#,
            embedding.borrow() as _,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));

        Ok(res)
    }

    pub async fn search_clip<'a, 's, I>(
        &'a self,
        describes: impl IntoIterator<Item = I> + Send + 'static,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a>
    where
        I: Into<EncodeInput<'s>> + Send + 's,
    {
        let embedding = self.clip_embedding(describes).await?;
        self.search_clip_inner(embedding, limit, offset).await
    }

    pub async fn search_clip_cached<'a, 's, I>(
        &'a self,
        describes: impl IntoIterator<Item = I> + Send + 'static,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a>
    where
        I: Into<EncodeInput<'s>> + Send + 's,
        I: AsRef<str>,
    {
        static CACHE: LazyLock<Cache<u64, Arc<HalfVector>>> = LazyLock::new(|| Cache::new(2 << 14));
        let describes = describes
            .into_iter()
            .map(|s| s.as_ref().to_owned())
            .collect::<Vec<_>>();
        let mut hasher = DefaultHasher::default();
        describes.hash(&mut hasher);
        let hash = hasher.finish();
        let embedding = CACHE
            .try_get_with(hash, async move {
                self.clip_embedding(describes).await.map(Arc::new)
            })
            .await
            .map_err(|e| anyhow!("{e}"))?;
        self.search_clip_inner(embedding, limit, offset).await
    }

    async fn dinov3_embedding<R>(
        &self,
        images: impl IntoIterator<Item = R> + Send + 'static,
    ) -> anyhow::Result<HalfVector>
    where
        R: Read + Seek,
    {
        static PREPROCESS_SEM: LazyLock<Arc<tokio::sync::Semaphore>> =
            LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));
        let Some(dinov3_lazy) = self.dinov3_session.as_ref() else {
            bail!("dinov3_session not enabled")
        };
        let dinov3_session = dinov3_lazy.session().await?;
        let permit = Arc::clone(&PREPROCESS_SEM)
            .acquire_owned()
            .await
            .map_err(|e| anyhow!("{e}"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let converted = images
                .into_iter()
                .map(|i| dinov3::convert_image(i))
                .try_collect::<Vec<_>>()?;
            if converted.is_empty() {
                bail!("no images provided");
            }
            let mut dinov3_session = dinov3_session.blocking_lock();
            let embeddings = dinov3::infer_vision(&mut dinov3_session, converted)?;
            drop(dinov3_session);
            let div = f32x16::splat(1.0 / embeddings.len() as f32);
            let mut embedding = embeddings
                .into_iter()
                .map(|v| <[f32; dinov3::EMBED_DIM]>::try_from(v).unwrap())
                .fold(
                    [f32x16::splat(0.0); dinov3::EMBED_DIM / 16],
                    |mut acc, v| {
                        for (c, x) in acc.iter_mut().zip(v.as_chunks::<16>().0) {
                            *c += f32x16::from_slice(x);
                        }
                        acc
                    },
                );
            embedding.iter_mut().for_each(|c| *c *= div);
            let embedding = HalfVector::from_f32_slice(unsafe {
                &*(embedding.as_ptr() as *const [f32; dinov3::EMBED_DIM])
            });
            anyhow::Ok(embedding)
        })
        .await
        .map_err(|e| anyhow!("dinov3 task panicked: {e}"))?
    }

    async fn search_dinov3_inner<'a>(
        &'a self,
        embedding: impl Borrow<HalfVector>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }

        let res = sqlx::query_as!(
            Image,
            r#"
            SELECT id, name, width, height
            FROM images i
            ORDER BY i.dinov3_embedding <=> $1::halfvec
            LIMIT $2 OFFSET $3
            "#,
            embedding.borrow() as _,
            limit,
            offset
        )
        .fetch(&self.pool)
        .filter_map(|res| ready(res.ok()));
        Ok(res)
    }

    pub async fn search_dinov3<'a, R>(
        &'a self,
        images: impl IntoIterator<Item = R> + Send + 'static,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a>
    where
        R: Read + Seek,
    {
        let embedding = self.dinov3_embedding(images).await?;
        self.search_dinov3_inner(embedding, limit, offset).await
    }

    pub async fn search_dinov3_cached<'a, R>(
        &'a self,
        images: impl IntoIterator<Item = R> + Send + 'static,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<impl Stream<Item = Image> + Send + 'a>
    where
        R: Read + Seek,
    {
        static CACHE: LazyLock<Cache<u64, Arc<HalfVector>>> = LazyLock::new(|| Cache::new(2 << 14));
        let images = images
            .into_iter()
            .map(|mut i| {
                let mut buf = vec![];
                i.read_to_end(&mut buf)?;
                anyhow::Ok(buf)
            })
            .try_collect::<Vec<_>>()?;
        let mut hasher = DefaultHasher::default();
        images.hash(&mut hasher);
        let hash = hasher.finish();
        let embedding = CACHE
            .try_get_with(hash, async move {
                self.dinov3_embedding(images.into_iter().map(Cursor::new))
                    .await
                    .map(Arc::new)
            })
            .await
            .map_err(|e| anyhow!("{e}"))?;
        self.search_dinov3_inner(embedding, limit, offset).await
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
        let mut images = sqlx::query_as!(
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
        .await?;
        images.sort_by_key(|im| im.id);
        Ok(images)
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

        let tags = sqlx::query(
            r#"
            SELECT
                wt.id,
                wt.name::TEXT AS name,
                wti.score,
                COALESCE(
                    array_agg(DISTINCT tt.translation::TEXT ORDER BY tt.translation::TEXT)
                        FILTER (WHERE tt.translation IS NOT NULL),
                    ARRAY[]::TEXT[]
                ) AS aliases
            FROM wd_tags wt
            JOIN wd_tag_images wti ON wt.id = wti.wd_tag_id
            LEFT JOIN wd_tag_translations tt ON tt.tag_id = wt.id
            WHERE wti.image_id = $1
            GROUP BY wt.id, wt.name, wti.score
            ORDER BY wti.score DESC
            "#,
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| -> sqlx::Result<Tag> {
            Ok(Tag {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                aliases: row.try_get("aliases")?,
                score: row.try_get("score")?,
            })
        })
        .try_collect()?;

        Ok(ImageDetails {
            image,
            post,
            authors,
            tags,
        })
    }

    /// Batch-fetch image thumbnail fields for a slice of image IDs in one query.
    pub async fn images_by_ids(&self, ids: &[i64]) -> anyhow::Result<Vec<Image>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"
            SELECT id, name::TEXT AS name, width, height
            FROM images
            WHERE id = ANY($1::BIGINT[])
            "#,
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| -> sqlx::Result<Image> {
                Ok(Image {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    width: r.try_get("width")?,
                    height: r.try_get("height")?,
                })
            })
            .try_collect()
            .map_err(Into::into)
    }

    /// Batch-fetch post titles, deterministic cover images (`MIN(image_id)`), and
    /// media counts in a single set-based query (no N+1 album scans).
    pub async fn post_previews_by_ids(&self, ids: &[i64]) -> anyhow::Result<Vec<PostPreview>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"
            WITH target_posts AS (
                SELECT p.id, p.title::TEXT AS title
                FROM posts p
                WHERE p.id = ANY($1::BIGINT[])
            ),
            img_counts AS (
                SELECT pi.post_id, COUNT(*)::BIGINT AS cnt
                FROM post_images pi
                WHERE pi.post_id = ANY($1::BIGINT[])
                GROUP BY pi.post_id
            ),
            vid_counts AS (
                SELECT pv.post_id, COUNT(*)::BIGINT AS cnt
                FROM post_videos pv
                WHERE pv.post_id = ANY($1::BIGINT[])
                GROUP BY pv.post_id
            ),
            covers AS (
                SELECT DISTINCT ON (pi.post_id)
                    pi.post_id,
                    i.id AS image_id,
                    i.name::TEXT AS name,
                    i.width,
                    i.height
                FROM post_images pi
                JOIN images i ON i.id = pi.image_id
                WHERE pi.post_id = ANY($1::BIGINT[])
                ORDER BY pi.post_id, i.id ASC
            )
            SELECT
                tp.id AS post_id,
                tp.title,
                c.image_id,
                c.name,
                c.width,
                c.height,
                COALESCE(ic.cnt, 0) AS image_count,
                COALESCE(vc.cnt, 0) AS video_count
            FROM target_posts tp
            LEFT JOIN covers c ON c.post_id = tp.id
            LEFT JOIN img_counts ic ON ic.post_id = tp.id
            LEFT JOIN vid_counts vc ON vc.post_id = tp.id
            "#,
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| -> sqlx::Result<PostPreview> {
                let image_id: Option<i64> = r.try_get("image_id")?;
                let cover = match image_id {
                    Some(id) => Some(Image {
                        id,
                        name: r.try_get("name")?,
                        width: r.try_get("width")?,
                        height: r.try_get("height")?,
                    }),
                    None => None,
                };
                let image_count: i64 = r.try_get("image_count")?;
                let video_count: i64 = r.try_get("video_count")?;
                Ok(PostPreview {
                    post_id: r.try_get("post_id")?,
                    title: r.try_get("title")?,
                    cover,
                    image_count: image_count.max(0) as usize,
                    video_count: video_count.max(0) as usize,
                })
            })
            .try_collect()
            .map_err(Into::into)
    }

    /// Batch-fetch post titles, deterministic cover image (`MIN(image_id)`),
    /// deterministic cover video (`MIN(video_id)`), and media counts in one query.
    pub async fn post_gallery_covers_by_ids(
        &self,
        ids: &[i64],
    ) -> anyhow::Result<Vec<PostGalleryCover>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"
            WITH target_posts AS (
                SELECT p.id, p.title::TEXT AS title
                FROM posts p
                WHERE p.id = ANY($1::BIGINT[])
            ),
            img_counts AS (
                SELECT pi.post_id, COUNT(*)::BIGINT AS cnt
                FROM post_images pi
                WHERE pi.post_id = ANY($1::BIGINT[])
                GROUP BY pi.post_id
            ),
            vid_counts AS (
                SELECT pv.post_id, COUNT(*)::BIGINT AS cnt
                FROM post_videos pv
                WHERE pv.post_id = ANY($1::BIGINT[])
                GROUP BY pv.post_id
            ),
            img_covers AS (
                SELECT DISTINCT ON (pi.post_id)
                    pi.post_id,
                    i.id AS image_id,
                    i.name::TEXT AS image_name,
                    i.width AS image_width,
                    i.height AS image_height
                FROM post_images pi
                JOIN images i ON i.id = pi.image_id
                WHERE pi.post_id = ANY($1::BIGINT[])
                ORDER BY pi.post_id, i.id ASC
            ),
            vid_covers AS (
                SELECT DISTINCT ON (pv.post_id)
                    pv.post_id,
                    v.id AS video_id,
                    v.name::TEXT AS video_name,
                    v.width AS video_width,
                    v.height AS video_height,
                    v.duration AS video_duration
                FROM post_videos pv
                JOIN videos v ON v.id = pv.video_id
                WHERE pv.post_id = ANY($1::BIGINT[])
                ORDER BY pv.post_id, v.id ASC
            )
            SELECT
                tp.id AS post_id,
                tp.title,
                icov.image_id,
                icov.image_name,
                icov.image_width,
                icov.image_height,
                vcov.video_id,
                vcov.video_name,
                vcov.video_width,
                vcov.video_height,
                vcov.video_duration,
                COALESCE(ic.cnt, 0) AS image_count,
                COALESCE(vc.cnt, 0) AS video_count
            FROM target_posts tp
            LEFT JOIN img_covers icov ON icov.post_id = tp.id
            LEFT JOIN vid_covers vcov ON vcov.post_id = tp.id
            LEFT JOIN img_counts ic ON ic.post_id = tp.id
            LEFT JOIN vid_counts vc ON vc.post_id = tp.id
            "#,
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| -> sqlx::Result<PostGalleryCover> {
                let image_id: Option<i64> = r.try_get("image_id")?;
                let cover_image = match image_id {
                    Some(id) => Some(Image {
                        id,
                        name: r.try_get("image_name")?,
                        width: r.try_get("image_width")?,
                        height: r.try_get("image_height")?,
                    }),
                    None => None,
                };
                let video_id: Option<i64> = r.try_get("video_id")?;
                let cover_video = match video_id {
                    Some(id) => Some(Video {
                        id,
                        name: r.try_get("video_name")?,
                        width: r.try_get("video_width")?,
                        height: r.try_get("video_height")?,
                        duration: r.try_get("video_duration")?,
                    }),
                    None => None,
                };
                let image_count: i64 = r.try_get("image_count")?;
                let video_count: i64 = r.try_get("video_count")?;
                Ok(PostGalleryCover {
                    post_id: r.try_get("post_id")?,
                    title: r.try_get("title")?,
                    cover_image,
                    cover_video,
                    image_count: image_count.max(0) as usize,
                    video_count: video_count.max(0) as usize,
                })
            })
            .try_collect()
            .map_err(Into::into)
    }

    pub async fn newest_posts_vec(&self, limit: i64, offset: i64) -> anyhow::Result<Vec<Post>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let rows = sqlx::query(
            r#"
            SELECT id, title::TEXT AS title
            FROM posts
            ORDER BY id DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        advanced::map_post_rows(rows)
    }

    pub async fn random_posts_vec(
        &self,
        seed: i64,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Post>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let bounds = sqlx::query("SELECT MIN(id) AS min_id, MAX(id) AS max_id FROM posts")
            .fetch_one(&self.pool)
            .await?;
        let min_id: Option<i64> = bounds.try_get("min_id")?;
        let max_id: Option<i64> = bounds.try_get("max_id")?;
        let ids = match (min_id, max_id) {
            (Some(min), Some(max)) => random_ids(seed, min, max, limit, offset),
            _ => return Ok(Vec::new()),
        };
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"
            SELECT p.id, p.title::TEXT AS title
            FROM UNNEST($1::BIGINT[]) WITH ORDINALITY AS c(id, ord)
            JOIN posts p ON p.id = c.id
            ORDER BY c.ord
            "#,
        )
        .bind(&ids)
        .fetch_all(&self.pool)
        .await?;

        advanced::map_post_rows(rows)
    }

    pub async fn random_images_vec(
        &self,
        seed: i64,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let bounds = sqlx::query("SELECT MIN(id) AS min_id, MAX(id) AS max_id FROM images")
            .fetch_one(&self.pool)
            .await?;
        let min_id: Option<i64> = bounds.try_get("min_id")?;
        let max_id: Option<i64> = bounds.try_get("max_id")?;
        let ids = match (min_id, max_id) {
            (Some(min), Some(max)) => random_ids(seed, min, max, limit, offset),
            _ => return Ok(Vec::new()),
        };
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"
            SELECT i.id, i.name::TEXT AS name, i.width, i.height
            FROM UNNEST($1::BIGINT[]) WITH ORDINALITY AS c(id, ord)
            JOIN images i ON i.id = c.id
            ORDER BY c.ord
            "#,
        )
        .bind(&ids)
        .fetch_all(&self.pool)
        .await?;

        advanced::map_image_rows(rows)
    }

    pub async fn search_posts_by_title_vec(
        &self,
        title: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Post>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let raw = title.as_ref().trim();
        if raw.is_empty() {
            bail!("title should not be empty")
        }
        let pat = format!("%{}%", escape_like(raw));
        let rows = sqlx::query(
            r#"
            SELECT p.id, p.title::TEXT AS title
            FROM posts p
            WHERE p.title ILIKE $1 ESCAPE '\'
            ORDER BY p.id DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(&pat)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        advanced::map_post_rows(rows)
    }

    pub async fn search_posts_by_author_vec(
        &self,
        author: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Post>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let raw = author.as_ref().trim();
        if raw.is_empty() {
            bail!("author name should not be empty")
        }
        let pat = format!("%{}%", escape_like(raw));
        let rows = sqlx::query(
            r#"
            SELECT p.id, p.title::TEXT AS title
            FROM posts p
            WHERE EXISTS (
                SELECT 1
                FROM author_posts ap
                JOIN authors a ON a.id = ap.author_id
                WHERE ap.post_id = p.id
                  AND a.name ILIKE $1 ESCAPE '\'
            )
            ORDER BY p.id DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(&pat)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        advanced::map_post_rows(rows)
    }

    pub async fn search_images_by_tag_vec(
        &self,
        tag: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let raw = tag.as_ref().trim();
        if raw.is_empty() {
            bail!("tag should not be empty")
        }
        let underscored = raw.replace(' ', "_");
        let pat_raw = format!("%{}%", escape_like(raw));
        let pat_under = format!("%{}%", escape_like(&underscored));

        let rows = sqlx::query(
            r#"
            WITH
            pos_tags AS (
                SELECT wt.id AS tag_id
                FROM wd_tags wt
                WHERE wt.name ILIKE $1 ESCAPE '\'
                   OR ($2 <> $1 AND wt.name ILIKE $2 ESCAPE '\')
                UNION
                SELECT tt.tag_id
                FROM wd_tag_translations tt
                WHERE tt.translation ILIKE $1 ESCAPE '\'
            ),
            img_match AS (
                SELECT wti.image_id, MAX(wti.score) AS max_score
                FROM wd_tag_images wti
                JOIN pos_tags pt ON pt.tag_id = wti.wd_tag_id
                GROUP BY wti.image_id
            )
            SELECT i.id, i.name::TEXT AS name, i.width, i.height
            FROM img_match im
            JOIN images i ON i.id = im.image_id
            ORDER BY im.max_score DESC, im.image_id DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(pat_raw)
        .bind(pat_under)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        advanced::map_image_rows(rows)
    }

    pub async fn search_clip_cached_vec(
        &self,
        describe: &str,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let raw = describe.trim();
        if raw.is_empty() {
            bail!("description should not be empty")
        }
        let vec = self.clip_text_vec_cached(raw).await?;
        let hv = advanced::combine_unit_vectors(&[(*vec).clone()], &[], siglip2::EMBED_DIM)?;
        self.query_images_single_vector(
            "clip_embedding",
            hv,
            None,
            &std::collections::HashMap::new(),
            limit,
            offset,
        )
        .await
    }

    pub async fn search_dinov3_upload_vec(
        &self,
        bytes: Vec<u8>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        if bytes.is_empty() {
            bail!("uploaded image is empty")
        }
        let vec = self.dinov3_upload_vec_cached(bytes).await?;
        let hv = advanced::combine_unit_vectors(&[(*vec).clone()], &[], dinov3::EMBED_DIM)?;
        self.query_images_single_vector(
            "dinov3_embedding",
            hv,
            None,
            &std::collections::HashMap::new(),
            limit,
            offset,
        )
        .await
    }

    pub async fn search_similar_images(
        &self,
        image_id: i64,
        exclude_post_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        if image_id <= 0 {
            bail!("Image #{image_id} not found or has no visual embedding")
        }
        let id_vecs = self.fetch_dino_id_vectors(&[image_id]).await?;
        let seed_vec =
            advanced::combine_unit_vectors(&[id_vecs[&image_id].clone()], &[], dinov3::EMBED_DIM)?;
        let mut qb = advanced::build_similar_images_query(
            seed_vec,
            image_id,
            exclude_post_id,
            limit,
            offset,
        );
        if exclude_post_id.is_some() {
            let mut tx = self.pool.begin().await?;
            tx.execute("SET TRANSACTION READ ONLY").await?;
            tx.execute("SET LOCAL hnsw.max_scan_tuples = 20000").await?;
            let rows = qb.build().fetch_all(&mut *tx).await?;
            tx.commit().await?;
            advanced::map_image_rows(rows)
        } else {
            let rows = qb.build().fetch_all(&self.pool).await?;
            advanced::map_image_rows(rows)
        }
    }

    /// Fetch authors attached to a post (for Lightbox headers).
    pub async fn post_meta(&self, post_id: i64) -> anyhow::Result<PostMeta> {
        let authors: Vec<Author> = sqlx::query(
            r#"
            SELECT a.id, a.name::TEXT AS name
            FROM authors a
            JOIN author_posts ap ON a.id = ap.author_id
            WHERE ap.post_id = $1
            ORDER BY a.name ASC
            "#,
        )
        .bind(post_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| -> sqlx::Result<Author> {
            Ok(Author {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
            })
        })
        .try_collect()?;

        Ok(PostMeta { authors })
    }

    /// Suggest WD tags matching either their English name or any translation/alias,
    /// ranked by exact > prefix > substring match, with aliases attached.
    /// Uses prefix-only matching when `< 3` characters so `pg_trgm` GIN indexes stay active.
    pub async fn suggest_tags(&self, query: &str, limit: i64) -> anyhow::Result<Vec<Tag>> {
        let raw = query.trim();
        if raw.is_empty() {
            return Ok(vec![]);
        }
        let limit = limit.clamp(1, 20);
        let underscored = raw.replace(' ', "_");
        let esc_raw = escape_like(raw);
        let esc_under = escape_like(&underscored);
        let pat_raw = autocomplete_like_pattern(raw, &esc_raw);
        let pat_under = autocomplete_like_pattern(&underscored, &esc_under);
        let prefix_raw = format!("{esc_raw}%");
        let prefix_under = format!("{esc_under}%");

        let rows = sqlx::query(
            r#"
            WITH matched AS (
                SELECT wt.id, wt.name::TEXT AS name,
                       CASE
                           WHEN lower(wt.name) = lower($1) OR lower(wt.name) = lower($2) THEN 0
                           WHEN wt.name ILIKE $5 ESCAPE '\' OR ($6 <> $5 AND wt.name ILIKE $6 ESCAPE '\') THEN 1
                           ELSE 2
                       END AS rank
                FROM wd_tags wt
                WHERE wt.name ILIKE $3 ESCAPE '\'
                   OR ($4 <> $3 AND wt.name ILIKE $4 ESCAPE '\')
                UNION ALL
                SELECT wt.id, wt.name::TEXT AS name,
                       CASE
                           WHEN lower(tt.translation) = lower($1) THEN 0
                           WHEN tt.translation ILIKE $5 ESCAPE '\' THEN 1
                           ELSE 2
                       END AS rank
                FROM wd_tag_translations tt
                JOIN wd_tags wt ON wt.id = tt.tag_id
                WHERE tt.translation ILIKE $3 ESCAPE '\'
            ),
            best AS (
                SELECT id, name, MIN(rank) AS best_rank
                FROM matched
                GROUP BY id, name
                ORDER BY best_rank ASC, length(name) ASC, name ASC
                LIMIT $7
            )
            SELECT
                b.id,
                b.name,
                COALESCE(
                    array_agg(DISTINCT tt.translation::TEXT ORDER BY tt.translation::TEXT)
                        FILTER (WHERE tt.translation IS NOT NULL),
                    ARRAY[]::TEXT[]
                ) AS aliases
            FROM best b
            LEFT JOIN wd_tag_translations tt ON tt.tag_id = b.id
            GROUP BY b.id, b.name, b.best_rank
            ORDER BY b.best_rank ASC, length(b.name) ASC, b.name ASC
            "#,
        )
        .bind(raw)
        .bind(&underscored)
        .bind(&pat_raw)
        .bind(&pat_under)
        .bind(&prefix_raw)
        .bind(&prefix_under)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| -> sqlx::Result<Tag> {
                Ok(Tag {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    aliases: r.try_get("aliases")?,
                    score: None,
                })
            })
            .try_collect()
            .map_err(Into::into)
    }

    /// Suggest authors matching `query`, ranked by exact > prefix > substring.
    /// Uses prefix-only matching when `< 3` characters so `pg_trgm` GIN indexes stay active.
    pub async fn suggest_authors(&self, query: &str, limit: i64) -> anyhow::Result<Vec<Author>> {
        let raw = query.trim();
        if raw.is_empty() {
            return Ok(vec![]);
        }
        let limit = limit.clamp(1, 20);
        let esc = escape_like(raw);
        let pat = autocomplete_like_pattern(raw, &esc);
        let prefix = format!("{esc}%");

        let rows = sqlx::query(
            r#"
            SELECT id, name::TEXT AS name
            FROM authors
            WHERE name ILIKE $2 ESCAPE '\'
            ORDER BY
                CASE
                    WHEN lower(name) = lower($1) THEN 0
                    WHEN name ILIKE $3 ESCAPE '\' THEN 1
                    ELSE 2
                END ASC,
                length(name) ASC,
                name ASC
            LIMIT $4
            "#,
        )
        .bind(raw)
        .bind(&pat)
        .bind(&prefix)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| -> sqlx::Result<Author> {
                Ok(Author {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                })
            })
            .try_collect()
            .map_err(Into::into)
    }

    /// Suggest post titles matching `query`, ranked by exact > prefix > newest.
    /// Uses prefix-only matching when `< 3` characters so `pg_trgm` GIN indexes stay active.
    pub async fn suggest_titles(&self, query: &str, limit: i64) -> anyhow::Result<Vec<Post>> {
        let raw = query.trim();
        if raw.is_empty() {
            return Ok(vec![]);
        }
        let limit = limit.clamp(1, 15);
        let esc = escape_like(raw);
        let pat = autocomplete_like_pattern(raw, &esc);
        let prefix = format!("{esc}%");

        let rows = sqlx::query(
            r#"
            SELECT id, title::TEXT AS title
            FROM posts
            WHERE title ILIKE $2 ESCAPE '\'
            ORDER BY
                CASE
                    WHEN lower(title) = lower($1) THEN 0
                    WHEN title ILIKE $3 ESCAPE '\' THEN 1
                    ELSE 2
                END ASC,
                id DESC
            LIMIT $4
            "#,
        )
        .bind(raw)
        .bind(&pat)
        .bind(&prefix)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| -> sqlx::Result<Post> {
                Ok(Post {
                    id: r.try_get("id")?,
                    title: r.try_get("title")?,
                })
            })
            .try_collect()
            .map_err(Into::into)
    }

    pub async fn list_post_videos(&self, post_id: i64) -> anyhow::Result<Vec<Video>> {
        let mut videos = sqlx::query_as!(
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
        .await?;
        videos.sort_by_key(|v| v.id);
        Ok(videos)
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

#[cfg(test)]
mod tests {
    use super::{autocomplete_like_pattern, escape_like};

    #[test]
    fn escapes_like_wildcards() {
        assert_eq!(escape_like("blue_sky"), r"blue\_sky");
        assert_eq!(escape_like("100%_raw\\x"), r"100\%\_raw\\x");
        assert_eq!(escape_like("黄玫瑰"), "黄玫瑰");
    }

    #[test]
    fn autocomplete_uses_prefix_under_three_chars() {
        assert_eq!(autocomplete_like_pattern("花", "花"), "花%");
        assert_eq!(autocomplete_like_pattern("ab", "ab"), "ab%");
        assert_eq!(autocomplete_like_pattern("sky", "sky"), "%sky%");
        assert_eq!(autocomplete_like_pattern("黄玫瑰", "黄玫瑰"), "%黄玫瑰%");
    }
}
