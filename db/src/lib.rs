use borrow_key::BorrowKey;
use serde::{Deserialize, Serialize};
use sqlx::{Acquire, Database, Postgres, postgres::PgQueryResult, prelude::*};

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[sqlx(type_name = "translation")]
pub struct Translation {
    pub name: String,
    pub translations: Vec<String>,
}

pub async fn upsert_translations<'e, E>(
    translations: &[Translation],
    executor: E,
) -> sqlx::Result<<E::Database as Database>::QueryResult>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query!(
        r#"
        INSERT INTO wd_tag_translations (tag_id, translation)
        SELECT t.id, btrim(x)
        FROM UNNEST($1::translation[]) AS v(name, translations)
        JOIN wd_tags t ON t.name = v.name
        CROSS JOIN LATERAL unnest(v.translations) AS x
        WHERE btrim(x) <> ''
        ON CONFLICT (tag_id, translation) DO NOTHING
        "#,
        &translations as _
    )
    .execute(executor)
    .await
}

#[derive(Debug, Default, Clone, sqlx::Type, BorrowKey, Serialize, Deserialize)]
#[sqlx(type_name = "image")]
pub struct Image {
    #[key(str)]
    pub name: String,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Default, Clone, sqlx::Type, BorrowKey, Serialize, Deserialize)]
#[sqlx(type_name = "meta")]
pub struct Meta {
    #[key(str)]
    pub title: String,
    pub authors: Vec<String>,
    pub tags: Vec<String>,
    pub images: Vec<Image>,
}

pub async fn upsert_metas<'a, A>(metas: &[Meta], conn: A) -> sqlx::Result<PgQueryResult>
where
    A: Acquire<'a, Database = Postgres>,
{
    if metas.is_empty() {
        return Ok(PgQueryResult::default());
    }

    let mut tx = conn.begin().await?;

    sqlx::query!(
        r#"
            WITH input AS (
                SELECT * FROM unnest($1::meta[]) WITH ORDINALITY
                AS _(title, authors, tags, images, meta_ord)
            ),
            ins_posts AS (
                INSERT INTO posts (title)
                SELECT DISTINCT title FROM input
                WHERE trim(title) != ''
                ORDER BY title
                ON CONFLICT (title) DO NOTHING
            ),
            ins_images AS (
                INSERT INTO images (name, width, height)
                SELECT DISTINCT ON (img.name) img.name, img.width, img.height
                FROM input i
                CROSS JOIN LATERAL unnest(i.images::image[]) WITH ORDINALITY
                    AS img(name, width, height, img_ord)
                WHERE trim(img.name) != ''
                ORDER BY img.name, i.meta_ord DESC, img.img_ord DESC
                ON CONFLICT (name) DO UPDATE
                SET width = EXCLUDED.width,
                    height = EXCLUDED.height
                WHERE images.width IS DISTINCT FROM EXCLUDED.width
                   OR images.height IS DISTINCT FROM EXCLUDED.height
            ),
            ins_authors AS (
                INSERT INTO authors (name)
                SELECT DISTINCT name
                FROM input i
                CROSS JOIN LATERAL unnest(i.authors::VARCHAR[]) AS _(name)
                WHERE trim(name) != ''
                ORDER BY name
                ON CONFLICT (name) DO NOTHING
            )
            INSERT INTO tags (name)
            SELECT DISTINCT name
            FROM input i
            CROSS JOIN LATERAL unnest(i.tags::VARCHAR[]) AS _(name)
            WHERE trim(name) != ''
            ORDER BY name
            ON CONFLICT (name) DO NOTHING
        "#,
        metas as _
    )
    .execute(&mut *tx)
    .await?;

    let res = sqlx::query!(
        r#"
            WITH input AS (
                SELECT * FROM unnest($1::meta[])
                AS _(title, authors, tags, images)
            ),
            post_images AS (
                INSERT INTO post_images (post_id, image_id)
                SELECT DISTINCT p.id, img.id
                FROM input i
                JOIN posts p ON p.title = i.title
                CROSS JOIN LATERAL unnest(i.images::image[]) AS u(name, width, height)
                JOIN images img ON img.name = u.name
                WHERE trim(i.title) != '' AND trim(u.name) != ''
                ORDER BY p.id, img.id
                ON CONFLICT (post_id, image_id) DO NOTHING
            ),
            author_posts AS (
                INSERT INTO author_posts (author_id, post_id)
                SELECT DISTINCT a.id, p.id
                FROM input i
                JOIN posts p ON p.title = i.title
                CROSS JOIN LATERAL unnest(i.authors::VARCHAR[]) AS u(name)
                JOIN authors a ON a.name = u.name
                WHERE trim(i.title) != '' AND trim(u.name) != ''
                ORDER BY a.id, p.id
                ON CONFLICT (author_id, post_id) DO NOTHING
            )
            INSERT INTO tag_posts (tag_id, post_id)
            SELECT DISTINCT t.id, p.id
            FROM input i
            JOIN posts p ON p.title = i.title
            CROSS JOIN LATERAL unnest(i.tags::VARCHAR[]) AS u(name)
            JOIN tags t ON t.name = u.name
            WHERE trim(i.title) != '' AND trim(u.name) != ''
            ORDER BY t.id, p.id
            ON CONFLICT (tag_id, post_id) DO NOTHING
        "#,
        metas as _
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(res)
}
