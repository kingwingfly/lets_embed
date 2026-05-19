use anyhow::bail;
use clap::Parser;
use opendal::{
    Operator,
    services::{Fs, Http},
};
use sqlx::postgres::PgPool;

#[derive(Debug, Parser)]
#[clap(version)]
pub struct EmbedCli {
    /// the postgres database of image records
    #[arg(
        short,
        long,
        default_value = "postgres://postgres:postgres@postgres:5432/postgres"
    )]
    database_url: String,

    #[arg(short, long)]
    storage: url::Url,

    /// whether to quit if `SELECT ... FOR UPDATE SKIP LOCKED` got no record
    #[arg(long, default_value_t = false)]
    quit_on_empty: bool,
}

impl EmbedCli {
    pub async fn run(self) -> anyhow::Result<()> {
        let op = match self.storage.scheme() {
            "fs" | "file" => {
                let root = self.storage.path();
                tracing::info!(dal = "fs", root, "building OpenDAL");
                let fs = Fs::default().root(root);
                Operator::new(fs)?.finish()
            }
            "http" | "https" => {
                let endpoint = self.storage.as_str();
                tracing::info!(dal = "http", endpoint, "building OpenDAL");
                let http = Http::default().endpoint(endpoint);
                Operator::new(http)?.finish()
            }
            _ => bail!("Unsupported storage"),
        };

        let pool = PgPool::connect(&self.database_url).await?;

        loop {
            tracing::info!("aaa");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }
}
