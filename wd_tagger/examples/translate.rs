//! translate the selected tags by scraper on `https://danbooru.donmai.us/wiki_pages`

use std::{
    collections::HashSet,
    future::ready,
    io::{Seek, SeekFrom},
    sync::LazyLock,
    thread::available_parallelism,
};

use borrow_key::BorrowKey;
use futures::{StreamExt, stream};
use reqwest::{Client, StatusCode};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use tokio_retry::{
    Retry,
    strategy::{FixedInterval, jitter},
};
use tokio_util::sync::CancellationToken;
use wd_tagger::{Tag, tags};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let tags = tags("models/wd-eva02-large-tagger-v3/selected_tags.csv")?;

    let mut file = std::fs::File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open("assets/translations.json")?;

    let mut translated: HashSet<Tranlation> =
        serde_json::from_reader(&mut file).unwrap_or_default();
    let cancel = CancellationToken::new();

    {
        let task = translate(&mut translated, &tags, cancel.clone());
        tokio::pin!(task);
        tokio::select! {
            _ = &mut task => {}
            _ = tokio::signal::ctrl_c() => {cancel.cancel(); task.await?;}
        }
    }

    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    serde_json::to_writer_pretty(&mut file, &translated)?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, BorrowKey)]
struct Tranlation {
    #[key(str)]
    name: String,
    translations: Vec<String>,
}

async fn translate(
    translated: &mut HashSet<Tranlation>,
    tags: &[Tag],
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let new = stream::iter(tags)
        .take_until(cancel.cancelled())
        .filter(|t| ready(!translated.contains(t.name.as_str())))
        .map(async |tag| {
            Retry::spawn(
                FixedInterval::from_millis(1000).map(jitter).take(8),
                async || translate_inner(&tag.name).await,
            )
            .await
            .inspect(|t| println!("{:#?}", t))
            .inspect_err(|e| eprintln!("{e}"))
        })
        .buffer_unordered(
            available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1),
        )
        .filter_map(|res| ready(res.ok()))
        .collect::<HashSet<_>>()
        .await;

    translated.extend(new);

    Ok(())
}

async fn translate_inner(name: impl AsRef<str>) -> anyhow::Result<Tranlation> {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| {
        Client::builder().user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15").build().unwrap()
    });
    static SELECTOR: LazyLock<Selector> =
        LazyLock::new(|| Selector::parse("#content > p > a[class^='wiki-other-name']").unwrap());

    let url = format!("https://danbooru.donmai.us/wiki_pages/{}", name.as_ref());

    let resp = CLIENT.get(url).send().await?;
    if matches!(resp.status(), StatusCode::NOT_FOUND) {
        return Ok(Tranlation {
            name: name.as_ref().to_owned(),
            translations: vec![],
        });
    }

    let html = resp.text().await?;
    let html = Html::parse_document(&html);

    let translations = html
        .select(&SELECTOR)
        .map(|el| el.text().collect::<String>())
        .collect::<Vec<String>>();

    Ok(Tranlation {
        name: name.as_ref().to_owned(),
        translations,
    })
}
