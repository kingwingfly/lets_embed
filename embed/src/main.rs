use anyhow::Result;
use clap::Parser as _;
use embed::{cli::EmbedCli, telemetry::Telemetry};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = EmbedCli::parse();

    let telemetry = Telemetry::init("embed")?;

    let cancel = CancellationToken::new();
    let task = cli.run(cancel.clone());
    tokio::pin!(task);
    tokio::select! {
        res = &mut task => {
            if let Err(e) = res {
                tracing::error!(err = %e, "Exit");
            }
        },
        _ = tokio::signal::ctrl_c() => {
            cancel.cancel();
            println!("Ctrl-C received: waiting last batch to finish...");
            if let Err(e) = task.await {
                tracing::error!(err = %e, "Cancelled");
            }
        },
    }
    println!("embed service exited");

    println!("syncing otel, press ctrl-c again to force quit");
    tokio::select! {
        _ = tokio::task::spawn_blocking(move || telemetry.shutdown()) => println!("otel synced, quited successfully"),
        _ = tokio::signal::ctrl_c() => eprintln!("otel syncing cancelled, force quited"),
    }

    Ok(())
}
