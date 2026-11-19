use opendal::{
    Buffer, Metadata, Operator, Result,
    options::{DeleteOptions, ReadOptions},
    raw::{
        OpDelete, Service,
        oio::{Delete as _, Read as _, ReadStream as _},
    },
};

// The Operator trims outer whitespace from paths. Its underlying service accepts
// literal keys and retains the operator's layers, including retries and timeouts.
pub(super) async fn stat(op: &Operator, key: &str) -> Result<Metadata> {
    Ok(op
        .service()
        .stat(op.context(), key, Default::default())
        .await?
        .into_metadata())
}

pub(super) async fn read(op: &Operator, key: &str, if_match: Option<&str>) -> Result<Buffer> {
    let options = ReadOptions {
        if_match: if_match.map(str::to_owned),
        ..Default::default()
    };
    if key.trim() == key {
        return op.read_options(key, options).await;
    }
    let (range, args, _) = options.into();
    let reader = op.service().read(op.context(), key, args)?;
    let (_, mut stream) = reader.open(range).await?;
    stream.read_all().await
}

pub(super) async fn delete(op: &Operator, key: &str, if_match: Option<&str>) -> Result<()> {
    let options = DeleteOptions {
        if_match: if_match.map(str::to_owned),
        ..Default::default()
    };
    let args = OpDelete::from_options(&op.info().capability(), options)?;
    let mut deleter = op.service().delete(op.context())?;
    deleter.delete(key, args).await?;
    deleter.close().await
}

// Directory prefixes end in '/' and generated destinations end in '.webp'.
// An initial slash protects their first character during Operator normalization.
pub(super) fn rooted_path(path: &str) -> String {
    debug_assert!(path.ends_with('/') || path.ends_with(".webp"));
    format!("/{path}")
}
