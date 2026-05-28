//! import wd tag translations to db

use std::env;

use serde::Deserialize;
use sqlx::{PgPool, prelude::Type};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut file = std::fs::File::open("assets/translations.json")?;

    let translations: Vec<Translation> = serde_json::from_reader(&mut file)?;

    let pool = PgPool::connect_lazy(
        env::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@postgres:5432/postgres".to_string())
            .as_str(),
    )?;

    sqlx::query!(
        r#"
        UPDATE wd_tags AS t
        SET translations = COALESCE(
            (
                SELECT array_agg(DISTINCT x)
                FROM unnest(COALESCE(t.translations, ARRAY[]::varchar[]) || v.translations::varchar[]) AS _(x)
                WHERE btrim(x) != ''
            ),
            t.translations
        )
        FROM UNNEST($1::translation[]) AS v(name, translations)
        WHERE t.name = v.name
        "#,
        &translations as _
    ).execute(&pool).await?;

    Ok(())
}

#[derive(Debug, Deserialize, Type)]
#[sqlx(type_name = "translation")]
struct Translation {
    name: String,
    translations: Vec<String>,
}
