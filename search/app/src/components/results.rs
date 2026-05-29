#![cfg_attr(feature = "ssr", allow(unused))]

use std::iter::repeat_with;

use crate::{
    components::{lightbox::Lightbox, viewer::Viewer},
    types::{DoneEvent, ErrorEvent, ImageItem, Mode, PostItem},
};
use leptos::prelude::*;
use leptos_router::hooks::use_query_map;
use leptos_use::{
    UseElementSizeReturn, signal_debounced, use_element_size, use_intersection_observer,
};
use urlencoding::encode;
use wasm_bindgen::{JsCast, prelude::Closure};

const COLUMN_WIDTH: u32 = 360;
const COLUMN_PAD: u32 = 2;

#[derive(Debug, Clone)]
enum Item {
    Post(PostItem),
    Image(ImageItem),
}

#[derive(Debug, Clone)]
struct Column {
    items: Vec<Item>,
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
        for item in
            (0..max_row).flat_map(|row| old.iter().filter_map(move |c| c.items.get(row).cloned()))
        {
            match item {
                Item::Post(p) => {
                    let Some(cover) = p.images.first() else {
                        continue;
                    };
                    let Some(column) = new.iter_mut().min_by_key(|c| c.height) else {
                        continue;
                    };
                    let height = ((cover.height as f64 / cover.width as f64) * column.width as f64)
                        .round() as u32;
                    column.height += height + COLUMN_PAD;
                    column.items.push(Item::Post(p));
                }
                Item::Image(im) => {
                    let Some(column) = new.iter_mut().min_by_key(|c| c.height) else {
                        continue;
                    };
                    let height =
                        ((im.height as f64 / im.width as f64) * column.width as f64).round() as u32;
                    column.height += height + COLUMN_PAD;
                    column.items.push(Item::Image(im));
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
    let viewer: RwSignal<Option<ImageItem>> = RwSignal::new(None);

    #[cfg(feature = "hydrate")]
    let active: StoredValue<Option<ActiveSse>, LocalStorage> = StoredValue::new_local(None);

    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        let _ = params.get();
        columns.update(|cs| {
            cs.iter_mut().for_each(|c| {
                c.items.clear();
                c.height = 0;
            })
        });
        offset.set(0);
        has_more.set(true);
        error.set(None);
        load_page(0, params, columns, has_more, loading, error, active);
    });

    let sentinel = NodeRef::<leptos::html::Div>::new();

    #[cfg(feature = "hydrate")]
    use_intersection_observer(sentinel, move |entries, _| {
        if !entries[0].is_intersecting() || loading.get_untracked() || !has_more.get_untracked() {
            return;
        }
        let (_, _, limit) = params.get_untracked();
        let next = offset.with_untracked(|old| *old + limit);
        load_page(next, params, columns, has_more, loading, error, active);
    });

    let render_item = move |it: Item| -> AnyView {
        match it {
            Item::Post(p) => {
                let cover = p.images.first().cloned();
                let count = p.images.len();
                view! {
                    <div class="mb-2 break-inside-avoid">
                        <div
                            class="relative cursor-pointer group rounded overflow-hidden bg-gray-900"
                            on:click=move |_| lightbox.set(Some(p.clone()))
                        >
                            {cover.map(|c| view! {
                                <img
                                    loading="lazy"
                                    decoding="async"
                                    class="w-full h-auto block group-hover:opacity-90 select-none"
                                    src=format!("/images/{}.webp", encode(&c.name))
                                />
                            })}
                            <div class="absolute top-1 right-1 bg-black/70 text-white text-xs px-2 py-0.5 rounded">
                                {count}" imgs"
                            </div>
                            <div class="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent text-white text-xs p-1 truncate">
                                {p.title.clone()}
                            </div>
                        </div>
                    </div>
                }
                .into_any()
            }
            Item::Image(im) => {
                let url = format!("/images/{}.webp", encode(&im.name));
                view! {
                    <div class="mb-2 break-inside-avoid">
                        <img
                            loading="lazy"
                            decoding="async"
                            class="w-full h-auto block bg-gray-900 cursor-zoom-in"
                            src=url
                            on:click=move |_| viewer.set(Some(im.clone()))
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
                <div class="w-full h-fit text-red-400 p-4 text-center">
                    {format!("Error: {e}")}
                </div>
            }
        })
    };

    let loading_view = move || {
        loading.get().then(|| {
            view! {
                <div class="w-full h-fit text-gray-400 p-4 text-center">"Loading..."</div>
            }
        })
    };

    let end_view = move || {
        (!loading.get() && !has_more.get() && !columns.read().iter().all(|c| c.items.is_empty()))
            .then(|| {
                view! {
                    <div class="w-full h-fit text-gray-500 p-4 text-center">"-- End --"</div>
                }
            })
    };

    let lightbox_view = move || {
        lightbox.get().map(|post| {
            view! {
                <Lightbox post lightbox viewer />
            }
        })
    };

    let viewer_view = move || {
        viewer.get().map(|image| {
            view! {
                <Viewer image viewer />
            }
        })
    };

    view! {
        <div node_ref=size_el class="w-full h-full flex flex-col overflow-y-auto">
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
                            key=|(i, it)| match it {
                                Item::Post(p) => format!("p_{}_{}", i, p.id),
                                Item::Image(im) => format!("i_{}_{}", i, im.id),
                            }
                            let((_, it))
                        >
                        { render_item(it) }
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

// ===================== wasm-only =====================

#[derive(Debug)]
struct ActiveSse {
    es: web_sys::EventSource,
    _closures: Vec<Closure<dyn FnMut(web_sys::MessageEvent)>>,
    _err_closure: Closure<dyn FnMut(web_sys::Event)>,
}

impl Drop for ActiveSse {
    fn drop(&mut self) {
        self.es.close();
    }
}

#[allow(clippy::too_many_arguments)]
fn load_page(
    offset_val: i64,
    params: Memo<(Mode, String, i64)>,
    columns: RwSignal<Vec<Column>>,
    has_more: RwSignal<bool>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    active: StoredValue<Option<ActiveSse>, LocalStorage>,
) {
    let (mode, q, limit) = params.get_untracked();
    if q.trim().is_empty() {
        return;
    }

    active.update_value(|v| *v = None);

    let url = format!(
        "/api/search?mode={}&q={}&limit={}&offset={}",
        mode.as_str(),
        encode(&q),
        limit,
        offset_val,
    );

    let es = match web_sys::EventSource::new(&url) {
        Ok(es) => es,
        Err(_) => {
            error.set(Some("Failed to open EventSource".into()));
            return;
        }
    };

    loading.set(true);
    error.set(None);

    let mut closures: Vec<Closure<dyn FnMut(web_sys::MessageEvent)>> = Vec::new();

    // post
    let cb = Closure::wrap(Box::new(move |ev: web_sys::MessageEvent| {
        if let Some(s) = ev.data().as_string()
            && let Ok(p) = serde_json::from_str::<PostItem>(&s)
        {
            columns.update(move |columns| {
                let Some(cover) = p.images.first() else {
                    return;
                };
                let Some(column) = columns.iter_mut().min_by_key(|c| c.height) else {
                    return;
                };
                let height = ((cover.height as f64 / cover.width as f64) * column.width as f64)
                    .round() as u32;
                column.height += height + COLUMN_PAD;
                column.items.push(Item::Post(p));
            });
        }
    }) as Box<dyn FnMut(_)>);
    es.add_event_listener_with_callback("post", cb.as_ref().unchecked_ref())
        .ok();
    closures.push(cb);

    // image
    let cb = Closure::wrap(Box::new(move |ev: web_sys::MessageEvent| {
        if let Some(s) = ev.data().as_string()
            && let Ok(im) = serde_json::from_str::<ImageItem>(&s)
        {
            columns.update(|columns| {
                let Some(column) = columns.iter_mut().min_by_key(|c| c.height) else {
                    return;
                };
                let height =
                    ((im.height as f64 / im.width as f64) * column.width as f64).round() as u32;
                column.height += height + COLUMN_PAD;
                column.items.push(Item::Image(im));
            });
        }
    }) as Box<dyn FnMut(_)>);
    es.add_event_listener_with_callback("image", cb.as_ref().unchecked_ref())
        .ok();
    closures.push(cb);

    // done
    let cb = Closure::wrap(Box::new(move |ev: web_sys::MessageEvent| {
        let d: DoneEvent = ev
            .data()
            .as_string()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(DoneEvent { has_more: false });
        has_more.set(d.has_more);
        loading.set(false);
        active.set_value(None);
    }) as Box<dyn FnMut(_)>);
    es.add_event_listener_with_callback("done", cb.as_ref().unchecked_ref())
        .ok();
    closures.push(cb);

    // server-side error event
    let cb = Closure::wrap(Box::new(move |ev: web_sys::MessageEvent| {
        let msg = ev
            .data()
            .as_string()
            .and_then(|s| serde_json::from_str::<ErrorEvent>(&s).ok())
            .map(|e| e.message)
            .unwrap_or_else(|| "stream error".into());
        error.set(Some(msg));
        loading.set(false);
        has_more.set(false);
        active.set_value(None);
    }) as Box<dyn FnMut(_)>);
    es.add_event_listener_with_callback("error", cb.as_ref().unchecked_ref())
        .ok();
    closures.push(cb);

    let onerror = Closure::wrap(Box::new(move |_ev: web_sys::Event| {
        loading.set(false);
    }) as Box<dyn FnMut(_)>);
    es.set_onerror(Some(onerror.as_ref().unchecked_ref()));

    let new_sse = ActiveSse {
        es,
        _closures: closures,
        _err_closure: onerror,
    };
    active.update_value(|v| *v = Some(new_sse));
}
