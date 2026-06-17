use leptos::ev;
use leptos::prelude::*;
use leptos_use::use_event_listener;
use web_sys::TouchEvent;

use crate::{types::ImageItem, util::encode_path};

const SWIPE_RATIO: f64 = 0.05;

#[component]
pub fn Viewer(
    images: StoredValue<Vec<ImageItem>>,
    index: RwSignal<Option<usize>>,
) -> impl IntoView {
    let total = images.with_value(|v| v.len());
    let track = NodeRef::<leptos::html::Div>::new();

    let tx = RwSignal::new(-100.0_f64);
    let animating = RwSignal::new(false);

    let has_prev = move || matches!(index.get(), Some(i) if i > 0);
    let has_next = move || matches!(index.get(), Some(i) if i + 1 < total);

    let slide = move |dir: i32| {
        if animating.get_untracked() {
            return;
        }
        match dir {
            -1 if matches!(index.get_untracked(), Some(i) if i > 0) => {
                animating.set(true);
                tx.set(0.0);
            }
            1 if matches!(index.get_untracked(), Some(i) if i + 1 < total) => {
                animating.set(true);
                tx.set(-200.0);
            }
            _ => {}
        }
    };

    let _ = use_event_listener(track, ev::transitionend, move |_| {
        let cur = tx.get_untracked();
        if cur <= -199.0 {
            index.update(|i| {
                if let Some(c) = i {
                    *c += 1;
                }
            });
        } else if cur >= -1.0 {
            index.update(|i| {
                if let Some(c) = i {
                    *c -= 1;
                }
            });
        }
        animating.set(false);
        tx.set(-100.0);
    });

    let _ = use_event_listener(window(), ev::keydown, move |e| match e.key().as_str() {
        "ArrowLeft" => slide(-1),
        "ArrowRight" => slide(1),
        "Escape" | " " => index.set(None),
        _ => {}
    });

    let start_x = StoredValue::new(0.0_f64);
    let width = StoredValue::new(1.0_f64);
    let dragging = StoredValue::new(false);

    let on_touch_start = move |ev: TouchEvent| {
        if animating.get_untracked() {
            return;
        }
        if let Some(t) = ev.touches().get(0) {
            start_x.set_value(t.client_x() as f64);
            let w = window()
                .inner_width()
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0)
                .max(1.0);
            width.set_value(w);
            dragging.set_value(true);
        }
    };
    let on_touch_move = move |ev: TouchEvent| {
        if !dragging.get_value() {
            return;
        }
        if let Some(t) = ev.changed_touches().get(0) {
            let dx = t.client_x() as f64 - start_x.get_value();
            let mut pct = dx / width.get_value() * 100.0;
            if pct > 0.0 && !has_prev() {
                pct = 0.0;
            }
            if pct < 0.0 && !has_next() {
                pct = 0.0;
            }
            tx.set(-100.0 + pct);
        }
    };
    let on_touch_end = move |_: TouchEvent| {
        if !dragging.get_value() {
            return;
        }
        dragging.set_value(false);
        let drag = tx.get_untracked() + 100.0;
        let target = if drag <= -SWIPE_RATIO * 100.0 && has_next() {
            -200.0
        } else if drag >= SWIPE_RATIO * 100.0 && has_prev() {
            0.0
        } else {
            -100.0
        };
        if (target - tx.get_untracked()).abs() < 0.5 {
            animating.set(false);
            tx.set(target);
        } else {
            animating.set(true);
            tx.set(target);
        }
    };

    let track_style = move || {
        format!(
            "transform: translateX({}%); transition: {};",
            tx.get(),
            if animating.get() {
                "transform 0.3s ease"
            } else {
                "none"
            }
        )
    };

    let view_slide = move |idx: Option<usize>| {
        let data = idx.and_then(|i| {
            images.with_value(|v| {
                v.get(i).map(|im| {
                    (
                        format!("/images/{}.webp", encode_path(&im.name)),
                        format!("/details/{id}?mode=similar&q={id}&limit=50", id = im.id),
                        im.name.clone(),
                    )
                })
            })
        });
        view! {
            <div class="flex-none w-full h-full grid place-items-center p-2">
                {data.map(|(src, href, alt)| view! {
                    <a href=href on:click=|ev| ev.stop_propagation()>
                        <img
                            src=src
                            alt=alt
                            class="max-h-screen max-w-screen object-contain select-none cursor-cell"
                        />
                    </a>
                })}
            </div>
        }
    };

    view! {
        <div
            class="fixed inset-0 bg-black/95 z-[60] overflow-hidden cursor-zoom-out select-none touch-none"
            on:click=move |ev| { ev.stop_propagation(); index.set(None); }
            on:touchstart=on_touch_start
            on:touchmove=on_touch_move
            on:touchend=on_touch_end
            on:touchcancel=move |_: TouchEvent| {
                dragging.set_value(false);
                animating.set(true);
                tx.set(-100.0);
            }
        >
            <div node_ref=track class="flex h-full w-full will-change-transform" style=track_style>
                {move || view_slide(index.get().filter(|&i| i > 0).map(|i| i - 1))}
                {move || view_slide(index.get())}
                {move || view_slide(index.get().map(|i| i + 1).filter(|&i| i < total))}
            </div>

            <button
                class="absolute left-2 top-1/2 -translate-y-1/2 text-white bg-black/60 hover:bg-black/80 rounded-full w-12 h-12 text-3xl disabled:opacity-30 disabled:cursor-default"
                prop:disabled=move || !has_prev()
                on:click=move |ev| { ev.stop_propagation(); slide(-1); }
            >"‹"</button>
            <button
                class="absolute right-2 top-1/2 -translate-y-1/2 text-white bg-black/60 hover:bg-black/80 rounded-full w-12 h-12 text-3xl disabled:opacity-30 disabled:cursor-default"
                prop:disabled=move || !has_next()
                on:click=move |ev| { ev.stop_propagation(); slide(1); }
            >"›"</button>

            <div class="absolute bottom-3 left-1/2 -translate-x-1/2 text-sm text-gray-300 bg-black/60 px-3 py-1 rounded-full">
                {move || index.get().map(|i| format!("{} / {}", i + 1, total)).unwrap_or_default()}
            </div>

            <button
                class="absolute top-2 right-2 text-white bg-black/60 hover:bg-black/80 rounded-full w-10 h-10 text-2xl"
                on:click=move |ev| { ev.stop_propagation(); index.set(None); }
            >"×"</button>
        </div>
    }
}
