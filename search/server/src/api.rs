use std::{
    collections::HashSet, convert::Infallible, fs::File, io::BufReader, path::PathBuf, pin::Pin,
    sync::Arc, time::Duration,
};

use app::types::{DoneEvent, ErrorEvent, ImageItem, Mode, PostItem};
use axum::{
    extract::{Query, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt as _};
use sanitize_filename::sanitize;
use search_engine::{Engine, search_types};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default)]
    q: String,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_mode() -> String {
    "tag".into()
}
fn default_limit() -> i64 {
    20
}

pub async fn search_sse(
    State(engine): State<Arc<Engine>>,
    State(path): State<Arc<PathBuf>>,
    Query(p): Query<SearchParams>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mode = Mode::parse(&p.mode);
    let limit = p.limit.max(1);
    let offset = p.offset.max(0);
    let q = p.q;

    let stream = async_stream::stream! {
        let send_err = |msg: String| -> Event {
            Event::default()
                .event("error")
                .json_data(ErrorEvent { message: msg })
                .unwrap()
        };

        match mode {
            Mode::Tag | Mode::Clip => {
                let res = match mode {
                     Mode::Tag =>
                        engine.search_image_by_tag(q, limit, offset)
                            .await
                            .map(|s| Box::pin(s) as Pin<Box<dyn Stream<Item = search_types::Image> + Send>>),
                     Mode::Clip =>
                        engine.search_clip([q.as_str()], limit, offset)
                            .await
                            .map(|s| Box::pin(s) as _),
                     _ => unreachable!()
                };
                match res {
                    Ok(mut images) => {
                        let mut count = 0i64;

                        while let Some(img) = images.next().await {
                            let item = ImageItem {
                                id: img.id,
                                name: sanitize(img.name),
                                width: img.width as u32,
                                height: img.height as u32,
                            };
                            count += 1;
                            yield Ok(Event::default()
                                .event("image")
                                .json_data(item)
                                .unwrap());
                        }

                        yield Ok(Event::default()
                            .event("done")
                            .json_data(DoneEvent { has_more: count >= limit })
                            .unwrap());
                    }
                    Err(e) => yield Ok(send_err(e.to_string())),
                }
            }
            Mode::Author => {
                match engine.search_post_by_author(q, limit, offset).await {
                    Ok(mut posts) => {
                        let mut count = 0;

                        while let Some(post) = posts.next().await {
                            let images = match engine.list_post_images(post.id).await {
                                Ok(images) =>
                                    images.into_iter().map(|img| ImageItem {
                                        id: img.id,
                                        name: sanitize(img.name),
                                        width: img.width as u32,
                                        height: img.height as u32,
                                    })
                                    .collect(),
                                Err(_) => continue
                            };
                            let item = PostItem {
                                id: post.id,
                                title: sanitize(post.title),
                                images,
                            };
                            count += 1;
                            yield Ok(Event::default()
                                .event("post")
                                .json_data(item)
                                .unwrap());
                        }

                        let has_more = (count as i64) >= limit;
                        yield Ok(Event::default()
                            .event("done")
                            .json_data(DoneEvent { has_more })
                            .unwrap());
                    }
                    Err(e) => yield Ok(send_err(e.to_string())),
                }
            }
            Mode::Similar => {
                let prepared = async {
                    let id = q.parse::<i64>().map_err(|e| e.to_string())?;
                    let details = engine.image_details(id).await.map_err(|e| e.to_string())?;

                    let post_image_ids = match details.post.as_ref().map(|p| p.id) {
                        Some(post_id) => engine
                            .list_post_images(post_id)
                            .await
                            .ok()
                            .map(|imgs| imgs.into_iter().map(|i| i.id).collect::<HashSet<_>>()),
                        None => None,
                    };

                    let mut path = (*path).to_owned();
                    path.push(sanitize(details.image.name));
                    path.add_extension("webp");

                    let file = File::open(&path).map_err(|e| e.to_string())?;
                    let reader = BufReader::new(file);
                    let images = engine
                        .search_dinov3([reader], limit, offset)
                        .await
                        .map_err(|e| e.to_string())?;

                    Ok::<_, String>((images, post_image_ids))
                }
                .await;

                match prepared {
                    Err(e) => yield Ok(send_err(e)),
                    Ok((mut images, post_image_ids)) => {
                        let mut count = 0i64;
                        while let Some(img) = images.next().await {
                            count += 1;
                            if post_image_ids.as_ref().is_some_and(|ids| ids.contains(&img.id)) {
                                continue;
                            }
                            let item = ImageItem {
                                id: img.id,
                                name: sanitize(img.name),
                                width: img.width as u32,
                                height: img.height as u32,
                            };
                            yield Ok(Event::default()
                                .event("image")
                                .json_data(item)
                                .unwrap());
                        }

                        yield Ok(Event::default()
                            .event("done")
                            .json_data(DoneEvent { has_more: count >= limit })
                            .unwrap());
                    }
                }
            }
            _ => {}
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}
