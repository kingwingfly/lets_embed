use std::io::Write as _;

use anyhow::Result;
use clap::Parser as _;
use embed::{cli::EmbedCli, telemetry::Telemetry};
use tokio_util::sync::CancellationToken;

/// Tell whoever runs this what's going on. On stderr, so it still shows when stdout is piped, and
/// without panicking: Ctrl-C also stops a pipe's reader such as `tee`, and a closed pipe must not
/// cut the drain short.
fn status(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
}

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
            status("Ctrl-C received: waiting the last queued batch to finish...");
            if let Err(e) = task.await {
                tracing::error!(err = %e, "Cancelled");
            }
        },
    }
    status("embed service exited");

    status("syncing otel, press ctrl-c again to force quit");
    tokio::select! {
        _ = tokio::task::spawn_blocking(move || telemetry.shutdown()) => status("otel synced, quited successfully"),
        _ = tokio::signal::ctrl_c() => status("otel syncing cancelled, force quited"),
    }

    Ok(())
}
