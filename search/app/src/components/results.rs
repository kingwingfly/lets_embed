use std::iter::repeat_with;

use crate::{
    components::{lightbox::Lightbox, viewer::Viewer},
    types::{ImageQuery, Mode, PostItem, SearchResponse},
    util::encode_path,
};

use leptos::{prelude::*, task::spawn_local};
use leptos_router::hooks::use_query_map;
use leptos_use::{
    UseElementSizeReturn, signal_debounced, use_element_size, use_intersection_observer,
};
use search_types::Image;

const COLUMN_WIDTH: u32 = 360;
const COLUMN_PAD: u32 = 2;

#[derive(Debug, Clone)]
enum Item {
    Post(PostItem),
    Image(Image),
}

/// An item already placed into a column, carrying its rendered pixel box so we can
/// hand the browser a `contain-intrinsic-size` and skip off-screen decode/layout.
#[derive(Debug, Clone)]
struct Placed {
    item: Item,
    w: u32,
    h: u32,
}

#[derive(Debug, Clone)]
struct Column {
    items: Vec<Placed>,
    width: u32,
    height: u32,
}

#[component]
pub fn Results() -> impl IntoView {
    let qmap = use_query_map();

    let params = Memo::new(move |_| {
        qmap.with(|m| {
            (
                Mode::parse(m.get("mode").as_deref().unwrap_or("tag")),
                m.get("q").unwrap_or_default(),
                m.get("limit")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(50)
                    .max(1),
            )
        })
    });

    let size_el = NodeRef::<leptos::html::Div>::new();
    let UseElementSizeReturn { width, .. } = use_element_size(size_el);
    let width: Signal<f64> = signal_debounced(width, 250.0);
    let width = Memo::new(move |_| width());

    let columns: RwSignal<Vec<Column>> = RwSignal::new(vec![]);

    Effect::new(move || {
        let width = width();
        let column_count = ((width / COLUMN_WIDTH as f64).round() as usize).max(1);
        let column_width = (width / column_count as f64).round() as u32;
        let mut new = repeat_with(|| Column {
            items: vec![],
            width: column_width,
            height: 0,
        })
        .take(column_count)
        .collect::<Vec<_>>();
        let old = columns.get_untracked();
        let max_row = old.iter().map(|c| c.items.len()).max().unwrap_or_default();
        for placed in (0..max_row)
            .flat_map(|row| old.iter().filter_map(move |c| c.items.get(row).cloned()))
        {
            match placed.item {
                Item::Post(p) => {
                    let Some(cover) = p.images.first() else {
                        continue;
                    };
                    let Some(column) = new.iter_mut().min_by_key(|c| c.height) else {
                        continue;
                    };
                    let height = ((cover.height as f64 / cover.width as f64) * column.width as f64)
                        .round() as u32;
                    let w = column.width;
                    column.height += height + COLUMN_PAD;
                    column.items.push(Placed { item: Item::Post(p), w, h: height });
                }
                Item::Image(im) => {
                    let Some(column) = new.iter_mut().min_by_key(|c| c.height) else {
                        continue;
                    };
                    let height =
                        ((im.height as f64 / im.width as f64) * column.width as f64).round() as u32;
                    let w = column.width;
                    column.height += height + COLUMN_PAD;
                    column.items.push(Placed { item: Item::Image(im), w, h: height });
                }
            }
        }
        columns.set(new);
    });

    let offset = RwSignal::new(0i64);
    let has_more = RwSignal::new(true);
    let loading = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let lightbox: RwSignal<Option<PostItem>> = RwSignal::new(None);
    let viewer: RwSignal<Option<usize>> = RwSignal::new(None);
    let images: StoredValue<Vec<Image>> = StoredValue::new(Vec::new());

    let viewer_open = Memo::new(move |_| viewer.get().is_some());

    let img_query = expect_context::<ImageQuery>();
    // Monotonic id used to discard responses from superseded requests: a new
    // search or the next page bumps it, and stale in-flight calls return early.
    let req_id: StoredValue<u64> = StoredValue::new(0);

    Effect::new(move |_| {
        let _ = params.get();
        columns.update(|cs| {
            cs.iter_mut().for_each(|c| {
                c.items.clear();
                c.height = 0;
            })
        });
        images.update_value(|v| v.clear());
        offset.set(0);
        has_more.set(true);
        error.set(None);
        load_page(
            0, params, img_query, columns, images, has_more, loading, error, req_id,
        );
    });

    let sentinel = NodeRef::<leptos::html::Div>::new();
    let is_intersecting = RwSignal::new(false);
    use_intersection_observer(sentinel, move |entries, _| {
        is_intersecting.set(entries[0].is_intersecting());
    });
    Effect::new(move |_| {
        let intersecting = is_intersecting.get();
        let is_loading = loading.get();
        let more = has_more.get();

        if intersecting && !is_loading && more {
            let (_, _, limit) = params.get_untracked();
            offset.update(|old| *old += limit);
            let next = offset.get_untracked();
            load_page(
                next, params, img_query, columns, images, has_more, loading, error, req_id,
            );
        }
    });

    let render_item = move |placed: Placed| -> AnyView {
        // Off-screen items skip render/decode; the reserved box keeps scroll stable.
        let cv = format!("content-visibility:auto;contain-intrinsic-size:{}px {}px;", placed.w, placed.h);
        match placed.item {
            Item::Post(p) => {
                let cover = p.images.first().cloned();
                let img_count = p.images.len();
                let video_count = p.videos.len();
                view! {
                    <div class="mb-2 break-inside-avoid" style=cv>
                        <div
                            class="relative cursor-pointer group rounded-xl overflow-hidden bg-sky-100 ring-1 ring-sky-200/70 shadow-sm shadow-sky-200/50 hover:shadow-md hover:shadow-sky-300/50 transition-shadow"
                            on:click=move |_| lightbox.set(Some(p.clone()))
                        >
                            {cover.map(|c| view! {
                                <img
                                    loading="lazy"
                                    decoding="async"
                                    style=format!("aspect-ratio: {} / {}", c.width, c.height)
                                    class="w-full h-auto block bg-sky-100 select-none group-hover:scale-[1.03] transition-transform duration-300"
                                    src=format!("/images/{}.webp", encode_path(&c.name))
                                />
                            })}
                            <div class="absolute top-1.5 right-1.5 bg-sky-500/85 text-white text-xs font-medium px-2 py-0.5 rounded-full shadow-sm">
                                {img_count}"p "{video_count}"v"
                            </div>
                            <div class="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/70 to-transparent text-white text-xs p-1.5 truncate">
                                {p.title.clone()}
                            </div>
                        </div>
                    </div>
                }
                .into_any()
            }
            Item::Image(im) => {
                let url = format!("/images/{}.webp", encode_path(&im.name));
                let id = im.id;
                view! {
                    <div class="m-1" style=cv>
                        <img
                            loading="lazy"
                            decoding="async"
                            style=format!("aspect-ratio: {} / {}", im.width, im.height)
                            class="w-full h-auto block rounded-xl bg-sky-100 ring-1 ring-sky-200/70 shadow-sm shadow-sky-200/50
                                cursor-zoom-in select-none hover:shadow-md hover:shadow-sky-300/50 hover:scale-[1.02] transition-all"
                            src=url
                            on:click=move |_| {
                                if let Some(i) = images.with_value(|v| v.iter().position(|x| x.id == id)) {
                                    viewer.set(Some(i));
                                }
                            }
                        />
                    </div>
                }
                .into_any()
            }
        }
    };

    let error_view = move || {
        error.get().map(|e| {
            view! {
                <div class="w-full text-rose-500 p-4 text-center">
                    {format!("Error: {e}")}
                </div>
            }
        })
    };

    let loading_view = move || {
        loading.get().then(|| {
            view! {
                <div class="w-full text-sky-500 p-4 text-center animate-pulse">"Loading\u{2026} \u{1f4ab}"</div>
            }
        })
    };

    let end_view = move || {
        (!loading.get() && !has_more.get() && !columns.read().iter().all(|c| c.items.is_empty()))
            .then(|| {
                view! {
                    <div class="w-full text-sky-400 p-4 text-center">"\u{2014} \u{1f33f} \u{2014}"</div>
                }
            })
    };

    let lightbox_view = move || {
        lightbox
            .get()
            .map(|post| view! { <Lightbox post lightbox/> })
    };

    let viewer_view = move || {
        viewer_open.get().then(|| {
            view! { <Viewer images=images index=viewer /> }
        })
    };

    view! {
        <div node_ref=size_el class="w-full flex flex-col">
            {error_view}
            <div class="flex w-full h-fit">
                <For
                    each=move || columns.get().into_iter().enumerate()
                    key=|(i, _)| *i
                    let((i, _))
                >
                    <div class="flex-1 columns-1 gap-2">
                        <For
                            each=move || {
                                columns
                                    .with(|cs| cs.get(i).map(|c| c.items.clone()).unwrap_or_default())
                                    .into_iter()
                                    .enumerate()
                            }
                            key=|(i, placed)| match &placed.item {
                                Item::Post(p) => format!("p_{}_{}", i, p.id),
                                Item::Image(im) => format!("i_{}_{}", i, im.id),
                            }
                            let((_, placed))
                        >
                        { render_item(placed) }
                        </For>
                    </div>
                </For>
            </div>

            <div node_ref=sentinel class="w-full min-h-10"></div>

            {loading_view}
            {end_view}
            {lightbox_view}
            {viewer_view}
        </div>
    }
}

/// Place a post into the shortest column, mirroring the masonry layout logic.
fn place_post(columns: RwSignal<Vec<Column>>, p: PostItem) {
    columns.update(move |columns| {
        let Some(cover) = p.images.first() else {
            return;
        };
        let Some(column) = columns.iter_mut().min_by_key(|c| c.height) else {
            return;
        };
        let height =
            ((cover.height as f64 / cover.width as f64) * column.width as f64).round() as u32;
        let w = column.width;
        column.height += height + COLUMN_PAD;
        column.items.push(Placed { item: Item::Post(p), w, h: height });
    });
}

/// Place an image into the shortest column and remember it for the viewer.
fn place_image(columns: RwSignal<Vec<Column>>, images: StoredValue<Vec<Image>>, im: Image) {
    images.update_value(|v| v.push(im.clone()));
    columns.update(|columns| {
        let Some(column) = columns.iter_mut().min_by_key(|c| c.height) else {
            return;
        };
        let height = ((im.height as f64 / im.width as f64) * column.width as f64).round() as u32;
        let w = column.width;
        column.height += height + COLUMN_PAD;
        column.items.push(Placed { item: Item::Image(im), w, h: height });
    });
}

/// Fetch one page of results through the REST search endpoints and merge it into
/// the columns. Superseded requests (a new search or an earlier page) are dropped
/// via `req_id` so their late responses can't corrupt the current view.
#[allow(clippy::too_many_arguments)]
fn load_page(
    offset_val: i64,
    params: Memo<(Mode, String, i64)>,
    img_query: ImageQuery,
    columns: RwSignal<Vec<Column>>,
    images: StoredValue<Vec<Image>>,
    has_more: RwSignal<bool>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    req_id: StoredValue<u64>,
) {
    let (mode, q, limit) = params.get_untracked();

    // Claim the newest request id; any in-flight call becomes stale.
    let this_id = req_id.get_value() + 1;
    req_id.set_value(this_id);

    loading.set(true);
    error.set(None);

    spawn_local(async move {
        let result = if mode == Mode::SearchImage {
            match img_query.0.get_untracked() {
                // The image bytes live only in client memory, so a reloaded or
                // shared `search_image` URL has none. Degrade to an empty result
                // instead of sending an empty body that would fail to decode.
                None => {
                    if req_id.get_value() == this_id {
                        has_more.set(false);
                        loading.set(false);
                    }
                    return;
                }
                Some(b64) => search_by_image(b64, limit, offset_val).await,
            }
        } else {
            search_query(mode.as_str().to_string(), q, limit, offset_val).await
        };

        // A newer request started while we were awaiting: discard this response.
        if req_id.get_value() != this_id {
            return;
        }

        match result {
            Ok(resp) => {
                for p in resp.posts {
                    place_post(columns, p);
                }
                for im in resp.images {
                    place_image(columns, images, im);
                }
                has_more.set(resp.has_more);
            }
            Err(e) => {
                error.set(Some(e.to_string()));
                has_more.set(false);
            }
        }
        loading.set(false);
    });
}

#[server]
async fn search_query(
    mode: String,
    q: String,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::AppState;

    use std::pin::Pin;
    use std::sync::Arc;

    use axum::extract::State;
    use futures::{Stream, StreamExt as _};
    use leptos_axum::extract_with_state;
    use search_engine::{Engine, search_types};

    let mode = Mode::parse(&mode);
    let limit = limit.max(1);
    let offset = offset.max(0);

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    // Return-type annotations pin `ServerFnError`'s generic parameter.
    fn to_err(e: impl std::fmt::Display) -> ServerFnError {
        ServerFnError::Response(e.to_string())
    }
    fn to_args(e: impl std::fmt::Display) -> ServerFnError {
        ServerFnError::Args(e.to_string())
    }

    // Post-oriented modes: newest (empty query), author, title, or random posts.
    if q.is_empty()
        || matches!(mode, Mode::Author | Mode::Title)
        || (mode == Mode::Random && q != "images")
    {
        let mut posts: Pin<Box<dyn Stream<Item = search_types::Post> + Send>> = if q.is_empty() {
            Box::pin(engine.newest_posts(limit, offset).await.map_err(to_err)?)
        } else {
            match mode {
                Mode::Author => Box::pin(
                    engine
                        .search_posts_by_author(q, limit, offset)
                        .await
                        .map_err(to_err)?,
                ),
                Mode::Title => Box::pin(
                    engine
                        .search_posts_by_title(q, limit, offset)
                        .await
                        .map_err(to_err)?,
                ),
                Mode::Random => Box::pin(engine.random_posts(limit).await.map_err(to_err)?),
                _ => unreachable!(),
            }
        };

        let mut items = Vec::new();
        let mut count = 0i64;
        while let Some(post) = posts.next().await {
            let Ok(images) = engine.list_post_images(post.id).await else {
                continue;
            };
            let Ok(videos) = engine.list_post_videos(post.id).await else {
                continue;
            };
            count += 1;
            items.push(PostItem {
                id: post.id,
                title: post.title,
                images,
                videos,
            });
        }
        return Ok(SearchResponse {
            has_more: count >= limit,
            posts: items,
            images: vec![],
        });
    }

    // Image-oriented modes.
    let mut stream: Pin<Box<dyn Stream<Item = Image> + Send>> = match mode {
        Mode::Tag => Box::pin(
            engine
                .search_images_by_tag(q, limit, offset)
                .await
                .map_err(to_err)?,
        ),
        Mode::Clip => Box::pin(
            engine
                .search_clip_cached([q], limit, offset)
                .await
                .map_err(to_err)?,
        ),
        Mode::Random => Box::pin(engine.random_images(limit).await.map_err(to_err)?),
        Mode::Similar => {
            let id = q.parse::<i64>().map_err(to_args)?;
            let details = engine.image_details(id).await.map_err(to_err)?;
            let post_image_ids = match details.post.as_ref().map(|p| p.id) {
                Some(post_id) => engine.list_post_images(post_id).await.ok().map(|imgs| {
                    imgs.into_iter()
                        .map(|i| i.id)
                        .collect::<std::collections::HashSet<_>>()
                }),
                None => None,
            };
            let mut stream = engine
                .search_dinov3_by_id([id], limit, offset)
                .await
                .map_err(to_err)?;
            let mut items = Vec::new();
            let mut count = 0i64;
            while let Some(img) = stream.next().await {
                count += 1;
                if post_image_ids.as_ref().is_some_and(|ids| ids.contains(&img.id)) {
                    continue;
                }
                items.push(img);
            }
            return Ok(SearchResponse {
                has_more: count >= limit,
                posts: vec![],
                images: items,
            });
        }
        _ => return Ok(SearchResponse::default()),
    };

    let mut items = Vec::new();
    let mut count = 0i64;
    while let Some(img) = stream.next().await {
        count += 1;
        items.push(img);
    }
    Ok(SearchResponse {
        has_more: count >= limit,
        posts: vec![],
        images: items,
    })
}

#[server]
async fn search_by_image(
    image: String,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::AppState;

    use std::io::Cursor;
    use std::sync::Arc;

    use axum::extract::State;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use futures::StreamExt as _;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    fn to_err(e: impl std::fmt::Display) -> ServerFnError {
        ServerFnError::Response(e.to_string())
    }
    fn to_args(msg: String) -> ServerFnError {
        ServerFnError::Args(msg)
    }

    let limit = limit.max(1);
    let offset = offset.max(0);

    let bytes = URL_SAFE_NO_PAD
        .decode(image.as_bytes())
        .map_err(|e| to_args(format!("invalid image data: {e}")))?;

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let mut stream = engine
        .search_dinov3_cached([Cursor::new(bytes)], limit, offset)
        .await
        .map_err(to_err)?;

    let mut items = Vec::new();
    let mut count = 0i64;
    while let Some(img) = stream.next().await {
        count += 1;
        items.push(img);
    }
    Ok(SearchResponse {
        has_more: count >= limit,
        posts: vec![],
        images: items,
    })
}
