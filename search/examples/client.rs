//! Unix-philosophy client: prints post.title / image.name to stdout, one per line.
//!
//!   cargo run --example client -- tag  --include "genshin impact" --include "1girl"
//!   cargo run --example client -- clip --query "长满青苔的小路" --query "樱花" --limit 10

use clap::{Parser, Subcommand};
use eventsource_stream::Eventsource;
use futures::StreamExt;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:3000")]
    base: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Tag {
        #[arg(long)]
        include: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
    },
    Clip {
        #[arg(long)]
        query: Vec<String>,
        #[arg(long, default_value_t = 20)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::new();

    let (url, body) = match cli.cmd {
        Cmd::Tag {
            include,
            exclude,
            limit,
            offset,
        } => (
            format!("{}/api/search/tag", cli.base),
            serde_json::json!({ "tags": include, "not_tags": exclude, "limit": limit, "offset": offset }),
        ),
        Cmd::Clip {
            query,
            limit,
            offset,
        } => (
            format!("{}/api/search/clip", cli.base),
            serde_json::json!({ "queries": query, "limit": limit, "offset": offset }),
        ),
    };

    let resp = client
        .post(&url)
        .header("Accept", "text/event-stream")
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    let mut stream = resp.bytes_stream().eventsource();
    while let Some(ev) = stream.next().await {
        let ev = ev?;
        match ev.event.as_str() {
            "post" => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&ev.data)
                    && let Some(t) = v["title"].as_str()
                {
                    println!("{t}");
                }
            }
            "image" => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&ev.data)
                    && let Some(n) = v["name"].as_str()
                {
                    println!("{n}");
                }
            }
            "done" => break,
            "error" => {
                eprintln!("server error: {}", ev.data);
                std::process::exit(1);
            }
            _ => {}
        }
    }
    Ok(())
}
