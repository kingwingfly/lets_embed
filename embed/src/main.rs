use anyhow::Result;
use clap::Parser as _;
use embed::{cli::EmbedCli, telemetry::Telemetry};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = EmbedCli::parse();

    let telemetry = Telemetry::init("embed")?;

    tokio::select! {
        res = cli.run() => {
            res?;
            tracing::info!("embed service exited: all finished")
        },
        _ = tokio::signal::ctrl_c() => {},
    }

    println!("syncing otel, press ctrl-c again to force quit");
    tokio::select! {
        _ = tokio::task::spawn_blocking(move || telemetry.shutdown()) => println!("otel synced, quited successfully"),
        _ = tokio::signal::ctrl_c() => eprintln!("otel syncing cancelled, force quited"),
    }

    Ok(())
}
