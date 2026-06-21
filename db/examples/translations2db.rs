//! import wd tag translations to db

use serde::Deserialize;
use sqlx::{PgPool, prelude::Type};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut file = std::fs::File::open("assets/translations.json")?;

    let translations: Vec<Translation> = serde_json::from_reader(&mut file)?;

    dotenvy::dotenv().ok();

    let pool = PgPool::connect_lazy(
        dotenvy::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@postgres:5432/postgres".to_string())
            .as_str(),
    )?;

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
    .execute(&pool)
    .await?;

    Ok(())
}

#[derive(Debug, Deserialize, Type)]
#[sqlx(type_name = "translation")]
struct Translation {
    name: String,
    translations: Vec<String>,
}
