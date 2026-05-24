use crate::types::{ImageItem, Mode, PostItem};
use leptos::prelude::*;
use leptos_router::hooks::use_query_map;

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

#[island]
pub fn Results() -> impl IntoView {
    let qmap = use_query_map();

    // 响应式参数：mode / q / limit
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

    // 通过 StoredValue 在 wasm 端持有当前 EventSource 与闭包，避免泄漏
    #[cfg(target_arch = "wasm32")]
    let active: StoredValue<Option<ActiveSse>, LocalStorage> = StoredValue::new_local(None);

    // 触发加载：参数变化 → 重置；offset 变化 → 拉新一页
    Effect::new(move |_| {
        let _ = params.get(); // 订阅
        items.set(Vec::new());
        offset.set(0);
        has_more.set(true);
        error.set(None);
        #[cfg(target_arch = "wasm32")]
        load_page(0, params, items, offset, has_more, loading, error, active);
    });

    // 无限滚动哨兵
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

    // 先把 children 渲染逻辑提出来
    let render_item = move |(_, it): (usize, Item)| -> AnyView {
        match it {
            Item::Post(p) => render_post_card(p, lightbox).into_any(),
            Item::Image(im) => view! {
                <img
                    loading="lazy"
                    decoding="async"
                    class="w-full h-auto rounded bg-gray-900"
                    src=format!("/images/{}.jpeg", im.name)
                />
            }
            .into_any(),
        }
    };

    // 各种条件片段也单独绑定
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

    let lightbox_view = move || lightbox.get().map(|p| render_lightbox(p, lightbox));

    let items_iter = move || items.get().into_iter().enumerate().collect::<Vec<_>>();

    view! {
        <div class="px-2 pb-8">
            {error_view}

            <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2 pt-2">
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
        </div>
    }
}

fn render_post_card(p: PostItem, lightbox: RwSignal<Option<PostItem>>) -> impl IntoView {
    let cover = p.images.first().cloned();
    let count = p.images.len();
    let p_for_click = p.clone();
    view! {
        <div class="relative cursor-pointer group"
             on:click=move |_| lightbox.set(Some(p_for_click.clone()))>
            {cover.map(|c| view!{
                <img loading="lazy" decoding="async"
                    class="w-full h-auto rounded bg-gray-900 group-hover:opacity-90"
                    src=format!("/images/{}.jpeg", c.name) />
            })}
            <div class="absolute top-1 right-1 bg-black/70 text-white text-xs px-2 py-0.5 rounded">
                {count}" imgs"
            </div>
            <div class="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent text-white text-xs p-1 truncate rounded-b">
                {p.title.clone()}
            </div>
        </div>
    }
}

fn render_lightbox(p: PostItem, lightbox: RwSignal<Option<PostItem>>) -> impl IntoView {
    let close = move |_| lightbox.set(None);
    view! {
        <div class="fixed inset-0 bg-black/95 z-50 overflow-y-auto" on:click=close>
            <div class="sticky top-0 flex items-center justify-between px-4 py-2 bg-black/80 text-white">
                <div class="font-semibold truncate">{p.title.clone()}</div>
                <button class="px-3 py-1 hover:bg-gray-700 rounded"
                        on:click=close>"Close"</button>
            </div>
            <div class="flex flex-col items-center gap-2 p-2"
                 on:click=move |ev| ev.stop_propagation()>
                { p.images.into_iter().map(|im| view!{
                    <img loading="lazy" decoding="async"
                        class="max-w-full h-auto"
                        src=format!("/images/{}.jpeg", im.name) />
                }).collect::<Vec<_>>() }
            </div>
        </div>
    }
}

// ===================== wasm-only =====================

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, prelude::Closure};

#[cfg(target_arch = "wasm32")]
struct ActiveSse {
    es: web_sys::EventSource,
    // 保留闭包所有权，避免提前 drop
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

    // 关闭旧连接
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
        // 关闭连接（drop ActiveSse 时 close）
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

    // 同时监听原生 onerror（连接级）
    let onerror = Closure::wrap(Box::new(move |_ev: web_sys::Event| {
        // 连接级错误：可能是网络问题；不一定致命，但停止加载
        loading.set(false);
    }) as Box<dyn FnMut(_)>);
    es.set_onerror(Some(onerror.as_ref().unchecked_ref()));
    // onerror 与上面四个不同签名，单独 leak（数量有限：每次搜索一次）
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
