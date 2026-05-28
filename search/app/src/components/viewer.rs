use leptos::prelude::*;
use urlencoding::encode;

use crate::types::ImageItem;

#[component]
pub fn Viewer(image: ImageItem, viewer: RwSignal<Option<ImageItem>>) -> impl IntoView {
    let url = format!("/images/{}.webp", encode(&image.name));
    view! {
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
    }
}
