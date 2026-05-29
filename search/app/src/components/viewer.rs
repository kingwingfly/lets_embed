use leptos::prelude::*;
use urlencoding::encode;

use crate::types::ImageItem;

#[component]
pub fn Viewer(image: ImageItem, viewer: RwSignal<Option<ImageItem>>) -> impl IntoView {
    let src = format!("/images/{}.webp", encode(&image.name));
    let href = format!("/details/{}", image.id);
    view! {
        <div
            class="fixed inset-0 bg-black/95 z-[60] grid place-items-center cursor-zoom-out p-2"
            on:click=move |ev| { ev.stop_propagation(); viewer.set(None); }
        >
            <a
                href=href
                on:click=|ev| ev.stop_propagation()
            >
                <img
                    src=src
                    alt=image.name
                    class="max-h-screen max-w-screen object-contain select-none cursor-cell"
                />
            </a>
            <button
                class="absolute top-2 right-2 text-white bg-black/60 hover:bg-black/80 rounded-full w-10 h-10 text-2xl"
                on:click=move |_| viewer.set(None)
            >"×"</button>
        </div>
    }
}
