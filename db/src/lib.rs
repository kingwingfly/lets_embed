use serde::Deserialize;
use sqlx::{Database, Postgres, prelude::*};

#[derive(Debug, Deserialize, Type)]
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

#[derive(Debug, Default, sqlx::Type)]
#[sqlx(type_name = "image")]
pub struct Image {
    pub name: String,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Default, sqlx::Type)]
#[sqlx(type_name = "meta")]
pub struct Meta {
    pub title: String,
    pub authors: Vec<String>,
    pub tags: Vec<String>,
    pub images: Vec<Image>,
}

pub async fn upsert_metas<'e, E>(
    metas: &[Meta],
    executor: E,
) -> sqlx::Result<<E::Database as Database>::QueryResult>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query!(
        r#"
            WITH input AS (
                SELECT * FROM unnest($1::meta[])
                AS _(title, authors, tags, images)
            ),
            ins_posts AS (
                INSERT INTO posts (title)
                SELECT DISTINCT title FROM input
                WHERE trim(title) != ''
                ORDER BY title
                ON CONFLICT DO NOTHING
                RETURNING id, title
            ),
            posts AS (
                SELECT * FROM ins_posts
                UNION ALL
                SELECT DISTINCT ON (id) id, title
                FROM input i
                JOIN posts p USING (title)
            ),
            ins_images AS (
                INSERT INTO images (name, width, height)
                SELECT DISTINCT ON (name) name, width, height
                FROM input i
                CROSS JOIN LATERAL unnest(i.images::image[]) as _(name, width, height)
                WHERE trim(name) != ''
                ORDER BY name
                ON CONFLICT DO NOTHING
                RETURNING id, name
            ),
            images AS (
                SELECT * FROM ins_images
                UNION ALL
                SELECT DISTINCT ON (id) id, name
                FROM input i
                CROSS JOIN LATERAL unnest(i.images::image[]) as _(name, width, height)
                JOIN images USING (name)
            ),
            post_images AS (
                INSERT INTO post_images (post_id, image_id)
                SELECT p.id, images.id
                FROM input i JOIN posts p USING (title)
                CROSS JOIN LATERAL unnest(i.images::image[]) AS _(name, width, height)
                JOIN images USING (name)
                ORDER BY p.id, images.id
                ON CONFLICT DO NOTHING
                RETURNING post_id, image_id
            ),
            ins_authors AS (
                INSERT INTO authors (name)
                SELECT DISTINCT name
                FROM input i
                CROSS JOIN LATERAL unnest(i.authors::VARCHAR[]) AS _(name)
                WHERE trim(name) != ''
                ORDER BY name
                ON CONFLICT DO NOTHING
                RETURNING id, name
            ),
            authors AS (
                SELECT * FROM ins_authors
                UNION ALL
                SELECT DISTINCT ON (id) id, name
                FROM input i
                CROSS JOIN LATERAL unnest(i.authors::VARCHAR[]) as _(name)
                JOIN authors USING (name)
            ),
            author_posts AS (
                INSERT INTO author_posts (author_id, post_id)
                SELECT authors.id, p.id
                FROM input i JOIN posts p USING (title)
                CROSS JOIN LATERAL unnest(i.authors::VARCHAR[]) AS _(name)
                JOIN authors USING (name)
                ORDER BY authors.id, p.id
                ON CONFLICT DO NOTHING
                RETURNING author_id, post_id
            ),
            ins_tags AS (
                INSERT INTO tags (name)
                SELECT name
                FROM input i
                CROSS JOIN LATERAL unnest(i.tags::VARCHAR[]) AS _(name)
                WHERE trim(name) != ''
                ORDER BY name
                ON CONFLICT DO NOTHING
                RETURNING id, name
            ),
            tags AS (
                SELECT * FROM ins_tags
                UNION ALL
                SELECT DISTINCT ON (id) id, name
                FROM input i
                CROSS JOIN LATERAL unnest(i.tags::VARCHAR[]) as _(name)
                JOIN tags USING (name)
            )
            INSERT INTO tag_posts (tag_id, post_id)
            SELECT tags.id, p.id
            FROM input i JOIN posts p USING (title)
            CROSS JOIN LATERAL unnest(i.tags::VARCHAR[]) AS _(name)
            JOIN tags USING (name)
            ORDER BY tags.id, p.id
            ON CONFLICT DO NOTHING
            "#,
        metas as _
    )
    .execute(executor)
    .await
}
