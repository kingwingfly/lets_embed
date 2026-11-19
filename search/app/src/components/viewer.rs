use leptos::ev;
use leptos::prelude::*;
use leptos_use_event_listener::use_event_listener;
use search_types::Image;
use web_sys::TouchEvent;

use crate::util::encode_path;

const SWIPE_RATIO: f64 = 0.05;

#[component]
pub fn Viewer(images: StoredValue<Vec<Image>>, index: RwSignal<Option<usize>>) -> impl IntoView {
    let total = images.with_value(|v| v.len());
    let dragging = RwSignal::new(false);
    let drag = RwSignal::new(0.0_f64);

    let has_prev = move || matches!(index.get(), Some(i) if i > 0);
    let has_next = move || matches!(index.get(), Some(i) if i + 1 < total);

    let slide = move |offset: isize| {
        if let Some(next) = index
            .get_untracked()
            .and_then(|i| i.checked_add_signed(offset))
            && next < total
        {
            index.set(Some(next));
        }
    };

    let _ = use_event_listener(window(), ev::keydown, move |e| {
        if e.alt_key() || e.ctrl_key() || e.meta_key() {
            return;
        }
        match e.key().as_str() {
            "ArrowLeft" => slide(-1),
            "ArrowRight" => slide(1),
            "Escape" | " " => index.set(None),
            _ => return,
        }
        e.prevent_default();
    });

    let start_x = StoredValue::new(0.0_f64);
    let width = StoredValue::new(1.0_f64);
    let on_touch_start = move |ev: TouchEvent| {
        if let Some(t) = ev.touches().get(0) {
            start_x.set_value(t.client_x() as f64);
            let w = window()
                .inner_width()
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0)
                .max(1.0);
            width.set_value(w);
            dragging.set(true);
        }
    };
    let on_touch_move = move |ev: TouchEvent| {
        if !dragging.get_untracked() {
            return;
        }
        if let Some(t) = ev.changed_touches().get(0) {
            let mut dx = t.client_x() as f64 - start_x.get_value();
            if dx > 0.0 && !has_prev() {
                dx = 0.0;
            }
            if dx < 0.0 && !has_next() {
                dx = 0.0;
            }
            drag.set(dx);
        }
    };
    let on_touch_end = move |_: TouchEvent| {
        if !dragging.get_untracked() {
            return;
        }
        dragging.set(false);
        let frac = drag.get_untracked() / width.get_value();
        if frac <= -SWIPE_RATIO {
            slide(1);
        } else if frac >= SWIPE_RATIO {
            slide(-1);
        }
        drag.set(0.0);
    };

    let track_style = move || {
        let i = index.get().unwrap_or(0);
        format!(
            "transform: translateX(calc(-{i}00vw + {d}px)); transition: {t};",
            i = i,
            d = drag.get(),
            t = if dragging.get() {
                "none"
            } else {
                "transform 0.3s ease"
            },
        )
    };

    let slides = images.with_value(|v| {
        v.iter()
            .map(|im| {
                let src = format!("/images/{}.webp", encode_path(&im.name));
                let href = format!("/details/{id}?mode=similar&q={id}&limit=50", id = im.id);
                let alt = im.name.clone();
                view! {
                    <div class="flex-none w-screen h-full grid place-items-center p-2">
                        <a href=href>
                            <img
                                src=src
                                alt=alt
                                loading="lazy"
                                class="max-h-screen max-w-screen object-contain select-none cursor-cell"
                            />
                        </a>
                    </div>
                }
            })
            .collect_view()
    });

    view! {
        <div
            class="fixed inset-0 bg-black/95 z-[60] overflow-hidden cursor-zoom-out select-none touch-none"
            on:click=move |ev| {
                if !(ev.alt_key() || ev.ctrl_key() || ev.meta_key() || ev.shift_key()) {
                    index.set(None);
                }
            }
            on:touchstart=on_touch_start
            on:touchmove=on_touch_move
            on:touchend=on_touch_end
            on:touchcancel=move |_: TouchEvent| {
                dragging.set(false);
                drag.set(0.0);
            }
        >
            <div class="flex h-full will-change-transform" style=track_style>
                {slides}
            </div>

            <button
                class="absolute left-2 top-1/2 -translate-y-1/2 text-white bg-black/50 hover:bg-sky-500/70 transition-colors rounded-full w-12 h-12 text-3xl disabled:opacity-30 disabled:cursor-default"
                prop:disabled=move || !has_prev()
                on:touchstart=|ev: TouchEvent| ev.stop_propagation()
                on:touchend=|ev: TouchEvent| ev.stop_propagation()
                on:click=move |ev| { ev.stop_propagation(); slide(-1); }
            >"‹"</button>
            <button
                class="absolute right-2 top-1/2 -translate-y-1/2 text-white bg-black/50 hover:bg-sky-500/70 transition-colors rounded-full w-12 h-12 text-3xl disabled:opacity-30 disabled:cursor-default"
                prop:disabled=move || !has_next()
                on:touchstart=|ev: TouchEvent| ev.stop_propagation()
                on:touchend=|ev: TouchEvent| ev.stop_propagation()
                on:click=move |ev| { ev.stop_propagation(); slide(1); }
            >"›"</button>

            <div class="absolute bottom-3 left-1/2 -translate-x-1/2 text-sm text-sky-100 bg-black/55 px-3 py-1 rounded-full">
                {move || index.get().map(|i| format!("{} / {}", i + 1, total)).unwrap_or_default()}
            </div>

            <button
                class="absolute top-2 right-2 text-white bg-black/50 hover:bg-sky-500/70 transition-colors rounded-full w-10 h-10 text-2xl"
                on:click=move |ev| { ev.stop_propagation(); index.set(None); }
            >"×"</button>
        </div>
    }
}
