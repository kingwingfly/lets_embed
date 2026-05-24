use crate::state::AppState;
use app::types::{DoneEvent, ErrorEvent, ImageItem, Mode, PostItem, parse_tag_query};
use axum::{
    extract::{Query, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures::Stream;
use sanitize_filename::sanitize;
use serde::Deserialize;
use std::{convert::Infallible, time::Duration};

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
    State(state): State<AppState>,
    Query(p): Query<SearchParams>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let engine = state.engine.clone();
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
            Mode::Tag => {
                let (tags, not_tags) = parse_tag_query(&q);
                match engine.search_tag(tags, not_tags, limit, offset).await {
                    Ok((posts, images)) => {
                        let total = posts.len() + images.len();

                        for post in posts {
                            match engine.list(post.id).await {
                                Ok(imgs) => {
                                    let item = PostItem {
                                        id: post.id,
                                        title: sanitize(post.title),
                                        images: imgs.into_iter()
                                            .map(|i| ImageItem { id: i.id, name: sanitize(i.name) })
                                            .collect(),
                                    };
                                    yield Ok(Event::default()
                                        .event("post")
                                        .json_data(item)
                                        .unwrap());
                                }
                                Err(e) => {
                                    yield Ok(send_err(e.to_string()));
                                    return;
                                }
                            }
                        }

                        for img in images {
                            let item = ImageItem { id: img.id, name: sanitize(img.name) };
                            yield Ok(Event::default()
                                .event("image")
                                .json_data(item)
                                .unwrap());
                        }

                        let has_more = (total as i64) >= limit;
                        yield Ok(Event::default()
                            .event("done")
                            .json_data(DoneEvent { has_more })
                            .unwrap());
                    }
                    Err(e) => {
                        yield Ok(send_err(e.to_string()));
                    }
                }
            }
            Mode::Clip => {
                match engine.search_clip([q.as_str()], limit, offset).await {
                    Ok(mut results) => {
                        let images = results.pop().unwrap_or_default();
                        let count = images.len();
                        for img in images {
                            let item = ImageItem { id: img.id, name: img.name };
                            yield Ok(Event::default()
                                .event("image")
                                .json_data(item)
                                .unwrap());
                        }
                        let has_more = (count as i64) >= limit;
                        yield Ok(Event::default()
                            .event("done")
                            .json_data(DoneEvent { has_more })
                            .unwrap());
                    }
                    Err(e) => {
                        yield Ok(send_err(e.to_string()));
                    }
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}
