use std::thread::{self, available_parallelism};

use anyhow::anyhow;
use db::{Image, Meta, upsert_metas};
use futures::StreamExt as _;
use sqlx::PgPool;
use struson::reader::simple::{SimpleJsonReader, ValueReader};
use tokio::{sync::mpsc, time::Instant};
use tokio_stream::wrappers::UnboundedReceiverStream;

const BATCH_SIZE: usize = 4; // each meta has 80 or so images

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let pool = PgPool::connect_lazy(
        dotenvy::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@postgres:5432/postgres".to_string())
            .as_str(),
    )?;

    let (tx, rx) = mpsc::unbounded_channel();

    let jh = thread::spawn(move || -> anyhow::Result<()> {
        let meta = std::fs::read_to_string("metas.json")?;
        let mut metas = Vec::with_capacity(BATCH_SIZE);
        SimpleJsonReader::new(meta.as_bytes())
            .read_array_items(|reader| {
                let mut meta = Meta::default();
                reader.read_object_borrowed_names(|mut reader| {
                    match reader.read_name()? {
                        "title" => meta.title = reader.read_string()?,
                        "authors" | "cosplayers" => {
                            let mut items = vec![];
                            reader.read_array_items(|reader| {
                                items.push(reader.read_string()?);
                                Ok(())
                            })?;
                            meta.authors = items;
                        }
                        "characters" | "tags" => {
                            let mut items = vec![];
                            reader.read_array_items(|reader| {
                                items.push(reader.read_string()?);
                                Ok(())
                            })?;
                            meta.tags.extend(items);
                        }
                        "images" => {
                            let mut items = vec![];
                            reader.read_array_items(|reader| {
                                let mut image = Image::default();
                                reader.read_object_borrowed_names(|mut reader| {
                                    match reader.read_name()? {
                                        "name" => image.name = reader.read_string()?,
                                        "width" => image.width = reader.read_number()??,
                                        "height" => image.height = reader.read_number()??,
                                        _ => {}
                                    }
                                    Ok(())
                                })?;
                                items.push(image);
                                Ok(())
                            })?;
                            meta.images = items;
                        }
                        _ => {}
                    }
                    Ok(())
                })?;
                metas.push(meta);
                if metas.len() >= BATCH_SIZE {
                    tx.send(std::mem::take(&mut metas))?;
                }
                Ok(())
            })
            .map_err(|e| anyhow!(e.to_string()))?;
        tx.send(std::mem::take(&mut metas))?;

        Ok(())
    });

    let now = Instant::now();
    UnboundedReceiverStream::new(rx)
        .map(async |metas| -> Result<(), sqlx::Error> {
            upsert_metas(&metas, &pool).await?;
            Ok(())
        })
        .buffer_unordered(available_parallelism().map(|num| num.get()).unwrap_or(1))
        .for_each(async |res| {
            if let Err(e) = res {
                eprintln!("{}", e);
            }
        })
        .await;

    jh.join().unwrap()?;

    println!("{:?}", now.elapsed());

    Ok(())
}
