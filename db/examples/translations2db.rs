//! import wd tag translations to db

use db::{Translation, upsert_translations};
use sqlx::PgPool;

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

    upsert_translations(&translations, &pool).await?;

    Ok(())
}
