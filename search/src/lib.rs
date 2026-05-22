use std::{env, path::Path};

use ort::session::Session;
use sqlx::{PgPool, Postgres};
use tokenizers::{EncodeInput, Tokenizer};

#[derive(Debug)]
pub struct Engine {
    pool: PgPool,
    clip_text_session: Session,
    tokeniser: Tokenizer,
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
        let clip_text_session = cn_clip::model(clip_text_model_path)?;
        let tokeniser = cn_clip::tokenizer(tokenizer_config_path)?;
        Ok(Self {
            pool,
            clip_text_session,
            tokeniser,
        })
    }

    pub async fn search_tag<T>(
        &self,
        tags: impl IntoIterator<Item = T>,
        not_tags: impl IntoIterator<Item = T>,
    ) -> anyhow::Result<(
        impl IntoIterator<Item = Post>,
        impl IntoIterator<Item = Image>,
    )>
    where
        for<'a> &'a [T]: sqlx::Type<Postgres> + sqlx::Encode<'a, Postgres>,
    {
        let tags = tags.into_iter().collect::<Vec<_>>();
        let not_tags = not_tags.into_iter().collect::<Vec<_>>();
        let posts = sqlx::query!(
            r#"
            SELECT DISTINCT p.id, p.title
                FROM posts p
                WHERE (
                    EXISTS (
                        SELECT 1
                        FROM tag_posts tp
                        JOIN tags t ON t.id = tp.tag_id
                        WHERE tp.post_id = p.id
                          AND t.name ~* ANY($1::TEXT[])
                          AND NOT (t.name ~* ANY($2::TEXT[]))
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
            "#,
            tags.as_slice() as _,
            not_tags.as_slice() as _,
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| Post {
            id: r.id,
            title: r.title,
        });
        let images = sqlx::query!(
            r#"
            SELECT DISTINCT i.id, i.name
                FROM images i
                WHERE EXISTS (
                    SELECT 1
                    FROM wd_tag_images wti
                    JOIN wd_tags wt ON wt.id = wti.wd_tag_id
                    WHERE wti.image_id = i.id
                        AND wt.name ~* ANY($1::TEXT[])
                        AND NOT wt.name ~* ANY($2::TEXT[])
                )
            "#,
            tags.as_slice() as _,
            not_tags.as_slice() as _,
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| Image {
            id: r.id,
            name: r.name,
        });
        Ok((posts, images))
    }

    pub async fn search_clip<'s>(
        &mut self,
        describes: impl IntoIterator<Item = impl Into<EncodeInput<'s>> + Send + 's>,
        _limit: usize,
    ) -> anyhow::Result<Vec<Image>> {
        let _text_embeddings =
            cn_clip::infer_text(&self.tokeniser, &mut self.clip_text_session, describes)?;
        todo!()
    }
}

#[derive(Debug)]
pub struct Image {
    pub id: i64,
    pub name: String,
}

#[derive(Debug)]
pub struct Post {
    pub id: i64,
    pub title: String,
}
