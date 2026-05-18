use std::env;

use sqlx::PgPool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = PgPool::connect_lazy(
        env::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@postgres:5432/postgres".to_string())
            .as_str(),
    )?;
    let migrater = sqlx::migrate!();
    migrater.undo(&pool, 0).await?;
    migrater.run(&pool).await?;
    Ok(())
}
