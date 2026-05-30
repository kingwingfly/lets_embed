use std::{
    env,
    thread::{self, available_parallelism},
};

use anyhow::anyhow;
use futures::StreamExt as _;
use sqlx::PgPool;
use struson::reader::simple::{SimpleJsonReader, ValueReader};
use tokio::{sync::mpsc, time::Instant};
use tokio_stream::wrappers::UnboundedReceiverStream;

const BATCH_SIZE: usize = 4; // each meta has 80 or so images

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = PgPool::connect_lazy(
        env::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@postgres:5432/postgres".to_string())
            .as_str(),
    )?;

    let (tx, rx) = mpsc::unbounded_channel();

    let jh = thread::spawn(move || -> anyhow::Result<()> {
        let meta = std::fs::read_to_string("meta.json")?;
        let mut metas = Vec::with_capacity(BATCH_SIZE);
        SimpleJsonReader::new(meta.as_bytes())
            .read_array_items(|reader| {
                let mut meta = Meta::default();
                reader.read_object_borrowed_names(|mut reader| {
                    match reader.read_name()? {
                        "title" => meta.title = reader.read_string()?,
                        "authors" | "cosplayers" => {
                            let mut items = vec![];
                            reader.read_array_items(|reader| {
                                items.push(reader.read_string()?);
                                Ok(())
                            })?;
                            meta.authors = items;
                        }
                        "characters" | "tags" => {
                            let mut items = vec![];
                            reader.read_array_items(|reader| {
                                items.push(reader.read_string()?);
                                Ok(())
                            })?;
                            meta.tags.extend(items);
                        }
                        "images" => {
                            let mut items = vec![];
                            reader.read_array_items(|reader| {
                                let mut image = Image::default();
                                reader.read_object_borrowed_names(|mut reader| {
                                    match reader.read_name()? {
                                        "name" => image.name = reader.read_string()?,
                                        "width" => image.width = reader.read_number()??,
                                        "height" => image.height = reader.read_number()??,
                                        _ => {}
                                    }
                                    Ok(())
                                })?;
                                items.push(image);
                                Ok(())
                            })?;
                            meta.images = items;
                        }
                        _ => {}
                    }
                    Ok(())
                })?;
                metas.push(meta);
                if metas.len() >= BATCH_SIZE {
                    tx.send(std::mem::take(&mut metas))?;
                }
                Ok(())
            })
            .map_err(|e| anyhow!(e.to_string()))?;
        tx.send(std::mem::take(&mut metas))?;

        Ok(())
    });

    let now = Instant::now();
    UnboundedReceiverStream::new(rx)
        .map(async |metas| -> Result<(), sqlx::Error> {
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
                ),
                tag_posts AS (
                    INSERT INTO tag_posts (tag_id, post_id)
                    SELECT tags.id, p.id
                    FROM input i JOIN posts p USING (title)
                    CROSS JOIN LATERAL unnest(i.tags::VARCHAR[]) AS _(name)
                    JOIN tags USING (name)
                    ORDER BY tags.id, p.id
                    ON CONFLICT DO NOTHING
                    RETURNING tag_id, post_id
                )
                SELECT 1 AS ok
                "#,
                &metas as _
            )
            .fetch_all(&pool)
            .await?;

            Ok(())
        })
        .buffer_unordered(available_parallelism().map(|num| num.get()).unwrap_or(1))
        .for_each(async |res| {
            if let Err(e) = res {
                eprintln!("{}", e);
            }
        })
        .await;

    jh.join().unwrap()?;

    println!("{:?}", now.elapsed());

    Ok(())
}

#[derive(Debug, Default, sqlx::Type)]
#[sqlx(type_name = "image")]
struct Image {
    name: String,
    width: i32,
    height: i32,
}

#[derive(Debug, Default, sqlx::Type)]
#[sqlx(type_name = "meta")]
struct Meta {
    title: String,
    authors: Vec<String>,
    tags: Vec<String>,
    images: Vec<Image>,
}
