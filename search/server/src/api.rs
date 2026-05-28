use std::{convert::Infallible, pin::Pin, sync::Arc, time::Duration};

use app::types::{DoneEvent, ErrorEvent, ImageItem, Mode};
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
                        let mut count = 0;

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
            _ => {}
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}
