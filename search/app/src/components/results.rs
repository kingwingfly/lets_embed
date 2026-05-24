use crate::{
    components::lightbox::Lightbox,
    types::{ImageItem, Mode, PostItem},
};
use leptos::prelude::*;
use leptos_router::hooks::use_query_map;
use urlencoding::encode;

#[cfg(target_arch = "wasm32")]
use crate::types::{DoneEvent, ErrorEvent};
#[cfg(target_arch = "wasm32")]
use leptos::prelude::LocalStorage;

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Clone)]
enum Item {
    Post(PostItem),
    Image(ImageItem),
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
                    .unwrap_or(20)
                    .max(1),
            )
        })
    });

    let items: RwSignal<Vec<Item>> = RwSignal::new(Vec::new());
    let offset = RwSignal::new(0i64);
    let has_more = RwSignal::new(true);
    let loading = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let lightbox: RwSignal<Option<PostItem>> = RwSignal::new(None);
    let viewer: RwSignal<Option<String>> = RwSignal::new(None);

    #[cfg(target_arch = "wasm32")]
    let active: StoredValue<Option<ActiveSse>, LocalStorage> = StoredValue::new_local(None);

    Effect::new(move |_| {
        let _ = params.get();
        items.set(Vec::new());
        offset.set(0);
        has_more.set(true);
        error.set(None);
        #[cfg(target_arch = "wasm32")]
        load_page(0, params, items, offset, has_more, loading, error, active);
    });

    let sentinel = NodeRef::<leptos::html::Div>::new();

    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        use wasm_bindgen::JsCast;
        if let Some(el) = sentinel.get() {
            let element: web_sys::Element = el.unchecked_into();
            setup_observer(
                element, params, items, offset, has_more, loading, error, active,
            );
        }
    });

    let render_item = move |(_, it): (usize, Item)| -> AnyView {
        match it {
            Item::Post(p) => {
                let cover = p.images.first().cloned();
                let count = p.images.len();
                let p_for_click = p.clone();
                view! {
                    <div class="mb-2 break-inside-avoid">
                        <div
                            class="relative cursor-pointer group rounded overflow-hidden bg-gray-900"
                            on:click=move |_| lightbox.set(Some(p_for_click.clone()))
                        >
                            {cover.map(|c| view! {
                                <img
                                    loading="lazy"
                                    decoding="async"
                                    class="w-full h-auto block group-hover:opacity-90"
                                    src=format!("/images/{}.jpeg", encode(&c.name))
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
                let url = format!("/images/{}.jpeg", encode(&im.name));
                let url_for_click = url.clone();
                view! {
                    <div class="mb-2 break-inside-avoid">
                        <img
                            loading="lazy"
                            decoding="async"
                            class="w-full h-auto block rounded bg-gray-900 cursor-zoom-in"
                            src=url
                            on:click=move |_| viewer.set(Some(url_for_click.clone()))
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
                <div class="text-red-400 p-4 text-center">
                    {format!("Error: {e}")}
                </div>
            }
        })
    };

    let loading_view = move || {
        loading.get().then(|| {
            view! {
                <div class="text-gray-400 p-4 text-center">"Loading..."</div>
            }
        })
    };

    let end_view = move || {
        (!loading.get() && !has_more.get() && !items.get().is_empty()).then(|| {
            view! {
                <div class="text-gray-500 p-4 text-center">"-- End --"</div>
            }
        })
    };

    let lightbox_view = move || {
        lightbox.get().map(|p| {
            view! {
                <Lightbox post=p lightbox=lightbox viewer=viewer />
            }
        })
    };

    let viewer_view = move || {
        viewer.get().map(|url| view! {
            <div
                class="fixed inset-0 bg-black/95 z-[60] flex items-center justify-center cursor-zoom-out p-2"
                on:click=move |ev| { ev.stop_propagation(); viewer.set(None); }
            >
                <img
                    src=url
                    class="max-w-full max-h-full object-contain select-none"
                    on:click=move |_| viewer.set(None)
                />
                <button
                    class="absolute top-2 right-2 text-white bg-black/60 hover:bg-black/80 rounded-full w-10 h-10 text-2xl"
                    on:click=move |_| viewer.set(None)
                >"×"</button>
            </div>
        })
    };

    let items_iter = move || items.get().into_iter().enumerate().collect::<Vec<_>>();

    view! {
        <div class="px-2 pb-8">
            {error_view}

            <div class="columns-2 sm:columns-3 md:columns-4 lg:columns-6 gap-2 px-2 pt-2">
                <For
                    each=items_iter
                    key=|(i, it)| match it {
                        Item::Post(p) => format!("p_{}_{}", i, p.id),
                        Item::Image(im) => format!("i_{}_{}", i, im.id),
                    }
                    children=render_item
                />
            </div>

            <div node_ref=sentinel class="h-10 w-full"></div>

            {loading_view}
            {end_view}
            {lightbox_view}
            {viewer_view}
        </div>
    }
}

// ===================== wasm-only =====================

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, prelude::Closure};

#[cfg(target_arch = "wasm32")]
struct ActiveSse {
    es: web_sys::EventSource,
    _closures: Vec<Closure<dyn FnMut(web_sys::MessageEvent)>>,
}

#[cfg(target_arch = "wasm32")]
impl Drop for ActiveSse {
    fn drop(&mut self) {
        self.es.close();
    }
}

#[cfg(target_arch = "wasm32")]
fn load_page(
    offset_val: i64,
    params: Memo<(Mode, String, i64)>,
    items: RwSignal<Vec<Item>>,
    offset: RwSignal<i64>,
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
        urlencoding::encode(&q),
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
        if let Some(s) = ev.data().as_string() {
            if let Ok(p) = serde_json::from_str::<PostItem>(&s) {
                items.update(|v| v.push(Item::Post(p)));
            }
        }
    }) as Box<dyn FnMut(_)>);
    es.add_event_listener_with_callback("post", cb.as_ref().unchecked_ref())
        .ok();
    closures.push(cb);

    // image
    let cb = Closure::wrap(Box::new(move |ev: web_sys::MessageEvent| {
        if let Some(s) = ev.data().as_string() {
            if let Ok(im) = serde_json::from_str::<ImageItem>(&s) {
                items.update(|v| v.push(Item::Image(im)));
            }
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
    onerror.forget();

    let new_sse = ActiveSse {
        es,
        _closures: closures,
    };
    active.update_value(|v| *v = Some(new_sse));
    let _ = offset; // suppress unused
}

#[cfg(target_arch = "wasm32")]
fn setup_observer(
    el: web_sys::Element,
    params: Memo<(Mode, String, i64)>,
    items: RwSignal<Vec<Item>>,
    offset: RwSignal<i64>,
    has_more: RwSignal<bool>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    active: StoredValue<Option<ActiveSse>, LocalStorage>,
) {
    use wasm_bindgen::JsCast;

    let cb = Closure::wrap(Box::new(
        move |entries: js_sys::Array, _obs: web_sys::IntersectionObserver| {
            let mut intersect = false;
            for i in 0..entries.length() {
                if let Ok(entry) = entries
                    .get(i)
                    .dyn_into::<web_sys::IntersectionObserverEntry>()
                {
                    if entry.is_intersecting() {
                        intersect = true;
                        break;
                    }
                }
            }
            if !intersect || loading.get_untracked() || !has_more.get_untracked() {
                return;
            }
            let (_, _, limit) = params.get_untracked();
            let next = offset.get_untracked() + limit;
            offset.set(next);
            load_page(
                next, params, items, offset, has_more, loading, error, active,
            );
        },
    )
        as Box<dyn FnMut(js_sys::Array, web_sys::IntersectionObserver)>);

    if let Ok(obs) = web_sys::IntersectionObserver::new(cb.as_ref().unchecked_ref()) {
        obs.observe(&el);
        cb.forget();
        std::mem::forget(obs);
    }
}
