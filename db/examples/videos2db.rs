use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
};

use clap::Parser;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct State {
    pub downloaded_medias: HashMap<i64, MediaAttr>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MediaAttr {
    pub title: String,
    pub key: String,
    pub resolution: (i32, i32),
    pub duration: f64,
}

impl State {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut file = File::open(path.as_ref())?;
        serde_json::from_reader(&mut file).map_err(Into::into)
    }
}

#[derive(Debug, Parser)]
struct Cli {
    state: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    dotenvy::dotenv().ok();
    let pool = PgPool::connect_lazy(
        dotenvy::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@postgres:5432/postgres".to_string())
            .as_str(),
    )?;
    let state = State::load(cli.state)?;
    for MediaAttr {
        title,
        key,
        resolution: (w, h),
        duration,
    } in state.downloaded_medias.values()
    {
        if title.is_empty() || key.is_empty() || *w == 0 || *h == 0 || *duration == 0.0 {
            continue;
        }
        let author = title.split_whitespace().next().unwrap_or("Unknown");
        sqlx::query!(
            r#"
            WITH ins_v AS (
                INSERT INTO videos (name, width, height, duration)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (name) DO NOTHING
                RETURNING id
            ),
            v AS (
                SELECT * FROM ins_v
                UNION ALL
                SELECT id
                FROM videos WHERE name=$1
            ),
            ins_p AS (
                INSERT INTO posts (title)
                VALUES ($5)
                ON CONFLICT (title) DO NOTHING
                RETURNING id
            ),
            p AS (
                SELECT * FROM ins_p
                UNION ALL
                SELECT id
                FROM posts WHERE title=$5
            ),
            ins_a AS (
                INSERT INTO authors (name)
                VALUES ($6)
                ON CONFLICT (name) DO NOTHING
                RETURNING id
            ),
            a AS (
                SELECT * FROM ins_a
                UNION ALL
                SELECT id
                FROM authors WHERE name=$6
            ),
            ap AS (
                INSERT INTO author_posts (author_id, post_id)
                SELECT a.id, p.id
                FROM a, p
                ON CONFLICT DO NOTHING
            )
            INSERT INTO post_videos (post_id, video_id)
            SELECT p.id, v.id
            FROM p, v
            ON CONFLICT DO NOTHING
            "#,
            key,
            *w,
            *h,
            *duration as i32 + 1,
            title,
            author
        )
        .execute(&pool)
        .await?;
    }
    Ok(())
}
