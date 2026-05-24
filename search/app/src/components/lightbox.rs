use crate::types::PostItem;
use leptos::prelude::*;
use urlencoding::encode;

const PAGE: usize = 20;

#[component]
pub fn Lightbox(
    post: PostItem,
    lightbox: RwSignal<Option<PostItem>>,
    viewer: RwSignal<Option<String>>,
) -> impl IntoView {
    let total = post.images.len();
    let images = StoredValue::new(post.images.clone());
    let title = post.title.clone();

    let visible = RwSignal::new(PAGE.min(total));
    let sentinel = NodeRef::<leptos::html::Div>::new();

    let close = move |_| lightbox.set(None);

    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        use wasm_bindgen::{JsCast, closure::Closure};
        let Some(el) = sentinel.get() else { return };
        let el: web_sys::Element = el.unchecked_into();

        let cb = Closure::wrap(Box::new(
            move |entries: js_sys::Array, _: web_sys::IntersectionObserver| {
                let mut hit = false;
                for i in 0..entries.length() {
                    if let Ok(e) = entries
                        .get(i)
                        .dyn_into::<web_sys::IntersectionObserverEntry>()
                    {
                        if e.is_intersecting() {
                            hit = true;
                            break;
                        }
                    }
                }
                if !hit {
                    return;
                }
                let cur = visible.get_untracked();
                if cur < total {
                    visible.set((cur + PAGE).min(total));
                }
            },
        )
            as Box<dyn FnMut(js_sys::Array, web_sys::IntersectionObserver)>);

        if let Ok(obs) = web_sys::IntersectionObserver::new(cb.as_ref().unchecked_ref()) {
            obs.observe(&el);
            cb.forget();
            std::mem::forget(obs);
        }
    });

    let render_items = move || {
        let v = visible.get();
        images.with_value(|imgs| {
            imgs.iter()
                .take(v)
                .map(|im| {
                    let url = format!("/images/{}.jpeg", encode(&im.name));
                    let url_for_click = url.clone();
                    view! {
                        <div class="relative aspect-square overflow-hidden rounded bg-gray-800">
                            <img
                                loading="lazy"
                                decoding="async"
                                class="absolute inset-0 w-full h-full object-cover cursor-zoom-in"
                                src=url
                                on:click=move |_| viewer.set(Some(url_for_click.clone()))
                            />
                        </div>
                    }
                })
                .collect::<Vec<_>>()
        })
    };

    view! {
        <div
            class="fixed inset-0 bg-black/95 z-50 overflow-y-auto"
            on:click=close
        >
            <div class="sticky top-0 z-10 flex items-center justify-between px-4 py-2 bg-black/80 text-white">
                <div class="font-semibold truncate">{title}</div>
                <div class="flex items-center gap-4">
                    <div class="text-sm text-gray-400">
                        {move || format!("{} / {}", visible.get(), total)}
                    </div>
                    <button
                        class="px-3 py-1 hover:bg-gray-700 rounded"
                        on:click=close
                    >"Close"</button>
                </div>
            </div>

            <div
                class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2 p-2"
                on:click=move |ev| ev.stop_propagation()
            >
                {render_items}
            </div>

            <div node_ref=sentinel class="h-12 w-full"></div>

            {move || (visible.get() >= total).then(|| view! {
                <div class="text-gray-500 text-center pb-6">"-- End --"</div>
            })}
        </div>
    }
}
