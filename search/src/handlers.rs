use crate::{payload::*, server::AppState};
use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use sanitize_filename::sanitize;
use std::convert::Infallible;

pub async fn search_tag(
    State(state): State<AppState>,
    Json(body): Json<TagBody>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let result = state.engine
            .search_tag(body.tags, body.not_tags, body.limit, body.offset)
            .await;

        match result {
            Ok((posts, images)) => {
                for post in posts {
                    let imgs = match state.engine.list(post.id).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("engine.list({}) failed: {e:#}", post.id);
                            continue;
                        }
                    };
                    let title_enc = encode_path(&post.title);
                    let payload = PostPayload {
                        id: post.id,
                        title: post.title.clone(),
                        images: imgs.into_iter().map(|i| {
                            let url = format!("/files/{}/{}", title_enc, encode_path(&format!("{}.jpeg", sanitize(&i.name))));
                            ImagePayload { id: i.id, name: i.name, url }
                        }).collect(),
                    };
                    yield ev("post", &payload);
                }
                for img in images {
                    let url = format!("/files/{}", encode_path(&format!("{}.jpeg", sanitize(&img.name))));
                    yield ev("image", &ImagePayload { id: img.id, name: img.name, url });
                }
                yield ev("done", &Done { next_offset: body.offset + body.limit });
            }
            Err(e) => {
                tracing::warn!("search_tag failed: {e:#}");
                yield Ok(Event::default().event("error").data(e.to_string()));
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn search_clip(
    State(state): State<AppState>,
    Json(body): Json<ClipBody>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let queries = body.queries.clone();
        let result = state.engine
            .search_clip(queries.iter().map(|s| s.as_str()), body.limit, body.offset)
            .await;

        match result {
            Ok(groups) => {
                for img in merge_clip(groups) {
                    let url = format!("/files/{}", encode_path(&format!("{}.jpeg", sanitize(&img.name))));
                    yield ev("image", &ImagePayload { id: img.id, name: img.name, url });
                }
                yield ev("done", &Done { next_offset: body.offset + body.limit });
            }
            Err(e) => {
                tracing::warn!("search_clip failed: {e:#}");
                yield Ok(Event::default().event("error").data(e.to_string()));
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn ev<T: serde::Serialize>(name: &str, v: &T) -> Result<Event, Infallible> {
    let data = serde_json::to_string(v).unwrap_or_else(|_| "{}".into());
    Ok(Event::default().event(name).data(data))
}
