use std::{future::ready, sync::LazyLock, thread::available_parallelism};

use futures::{StreamExt as _, TryStreamExt};
use libvips::{
    VipsApp, VipsImage,
    ops::{ForeignKeep, ForeignWebpPreset, WebpsaveBufferOptions, webpsave_buffer_with_opts},
};
use mime_guess::{MimeGuess, mime::IMAGE};
use opendal::Operator;
use tokio_util::sync::CancellationToken;

static CONCURRENT: LazyLock<usize> = LazyLock::new(|| {
    available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
});

pub async fn walk_convert(op: Operator) -> anyhow::Result<()> {
    let app = VipsApp::new("img2webp", false).expect("Cannot initialize libvips");
    app.concurrency_set(1);

    let entries = op.lister_with("/").recursive(true).await?;

    let cancel = CancellationToken::new();

    let finished_paths = entries
        .take_until(cancel.cancelled())
        .filter_map(|e| ready(e.ok()))
        .filter(|e| {
            let mimes = MimeGuess::from_path(e.path());
            ready(
                e.metadata().is_file()
                    && !e.path().ends_with(".webp")
                    && (mimes.is_empty() || mimes.into_iter().any(|m| m.type_() == IMAGE)),
            )
        })
        .map(|e| e.into_parts().0)
        .map(async |path| Ok::<_, opendal::Error>((op.read(&path).await?, path)))
        .buffer_unordered(*CONCURRENT)
        .inspect_err(|e| tracing::error!("{e}"))
        .filter_map(async |res| res.ok())
        .map(async |(bytes, path)| {
            tokio::task::spawn_blocking(move || {
                let bytes = bytes.to_bytes();
                convert(&bytes)
            })
            .await
            .unwrap()
            .map(|bytes| (path, bytes))
        })
        .buffer_unordered(*CONCURRENT)
        .inspect_err(|e| {
            tracing::error!("{e} {:?}", app.error_buffer());
            app.error_clear();
        })
        .filter_map(async |res| res.ok())
        .map(async |(path, bytes)| {
            op.write(&format!("{}.webp", path), bytes).await?;
            #[cfg(not(debug_assertions))]
            op.delete(&path).await?;
            Ok::<_, opendal::Error>(path)
        })
        .buffer_unordered(*CONCURRENT)
        .inspect_err(|e| tracing::error!("{e}"))
        .filter_map(async |res| res.ok());

    let task = async {
        tokio::pin!(finished_paths);
        while let Some(path) = finished_paths.next().await {
            tracing::info!(path, "converted");
        }
    };

    tokio::pin!(task);
    tokio::select! {
        _ = &mut task => {},
        _ = tokio::signal::ctrl_c() => {
            cancel.cancel();
            task.await
        }
    }
    Ok(())
}

pub fn convert(bytes: &[u8]) -> Result<Vec<u8>, libvips::error::Error> {
    let inp = VipsImage::new_from_buffer(bytes, "")?;
    webpsave_buffer_with_opts(
        &inp,
        &WebpsaveBufferOptions {
            q: 80,
            preset: ForeignWebpPreset::Photo,
            // lossless: true,
            // near_lossless: true,
            // exact: true,
            alpha_q: 100,
            smart_subsample: true,
            keep: ForeignKeep::Icc,
            ..Default::default()
        },
    )
}
