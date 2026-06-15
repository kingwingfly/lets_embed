use std::{collections::HashSet, convert::Infallible, pin::Pin, sync::Arc, time::Duration};

use app::types::{DoneEvent, ErrorEvent, ImageItem, Mode, PostItem};
use axum::{
    extract::{Query, State},
    response::sse::{Event, KeepAlive, Sse},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{Stream, StreamExt as _};
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

        match (mode, q.is_empty()) {
            (_, true) | (Mode::Author, false)  => {
                let res = match q.is_empty() {
                     true =>
                        engine.newest_posts(limit, offset)
                            .await
                            .map(|s| Box::pin(s) as Pin<Box<dyn Stream<Item = search_types::Post> + Send>>),
                     false =>
                        engine.search_posts_by_author(q, limit, offset).await
                            .map(|s| Box::pin(s) as _),
                };
                match res {
                    Ok(mut posts) => {
                        let mut count = 0i64;

                        while let Some(post) = posts.next().await {
                            let images = match engine.list_post_images(post.id).await {
                                Ok(images) =>
                                    images.into_iter().map(|img| ImageItem {
                                        id: img.id,
                                        name: img.name,
                                        width: img.width as u32,
                                        height: img.height as u32,
                                    })
                                    .collect(),
                                Err(_) => continue
                            };
                            let item = PostItem {
                                id: post.id,
                                title: post.title,
                                images,
                            };
                            count += 1;
                            yield Ok(Event::default()
                                .event("post")
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
            (Mode::Tag | Mode::Clip, false) => {
                let res = match mode {
                     Mode::Tag =>
                        engine.search_images_by_tag(q, limit, offset)
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
                                name: img.name,
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
            (Mode::Similar, false) => {
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

                    let images = engine
                        .search_dinov3_by_id([id], limit, offset)
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
                                name: img.name,
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
            (Mode::SearchImage, false) => {
                let decoded = URL_SAFE_NO_PAD.decode(q.as_bytes());

                match decoded {
                    Err(e) => yield Ok(send_err(format!("invalid image data: {e}"))),
                    Ok(bytes) => {
                        let cursor = std::io::Cursor::new(bytes);
                        match engine.search_dinov3([cursor], limit, offset).await {
                            Err(e) => yield Ok(send_err(e.to_string())),
                            Ok(mut images) => {
                                let mut count = 0i64;
                                while let Some(img) = images.next().await {
                                    count += 1;
                                    let item = ImageItem {
                                        id: img.id,
                                        name: img.name,
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
