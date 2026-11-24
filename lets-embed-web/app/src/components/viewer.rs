use leptos::{ev, html, prelude::*};
use leptos_router::{NavigateOptions, hooks::use_navigate};
use leptos_use_event_listener::use_event_listener;
use lets_embed_ui::{ContentMaskCard, GalleryMask, ReportTargetKind};
use search_types::{MediaKind, ProjectedImage};
use wasm_bindgen::JsCast;
use web_sys::TouchEvent;

use crate::{
    components::{BlurredMediaCard, LikeButton, LikeVariant},
    types::{SafetyUiState, handle_mask_unlock, mask_to_ui},
    util::{lock_body_scroll, navigate_from_modal, push_modal_history, trap_dialog_tab},
};

const SWIPE_RATIO: f64 = 0.05;

fn details_href(id: i64) -> String {
    format!("/details/{id}?mode=similar&q={id}&limit=50")
}

/// True when `target` is inside an editable form field (`INPUT`/`TEXTAREA`/`SELECT`/contenteditable).
fn is_editable_target(target: Option<web_sys::EventTarget>) -> bool {
    let Some(el) = target.and_then(|t| t.dyn_into::<web_sys::Element>().ok()) else {
        return false;
    };
    el.closest("input, textarea, select, [contenteditable='true'], [contenteditable='']")
        .ok()
        .flatten()
        .is_some()
}

/// True when `target` is (or is inside) an interactive button or link that consumes `Space`.
fn is_interactive_target(target: Option<web_sys::EventTarget>) -> bool {
    let Some(el) = target.and_then(|t| t.dyn_into::<web_sys::Element>().ok()) else {
        return false;
    };
    el.closest("button, a, [role='button']")
        .ok()
        .flatten()
        .is_some()
}

#[component]
pub fn Viewer(
    images: StoredValue<Vec<ProjectedImage>>,
    index: RwSignal<Option<usize>>,
    #[prop(optional)] post_id: Option<i64>,
    #[prop(optional)] on_navigate: Option<Callback<()>>,
) -> impl IntoView {
    let total = images.with_value(|v| v.len());
    let dragging = RwSignal::new(false);
    let drag = RwSignal::new(0.0_f64);
    let navigate = use_navigate();
    let dialog_ref: NodeRef<html::Div> = NodeRef::new();
    let safety = use_context::<SafetyUiState>();

    lock_body_scroll();
    let modal_layer = lets_embed_ui::browser::push_modal_layer();
    push_modal_history(move || index.set(None));

    // Immediately wipe media elements and close Viewer on cross-tab safety invalidation.
    if let Some(s) = safety {
        let last_epoch = StoredValue::new(s.invalidation_epoch.get_untracked());
        Effect::new(move |_| {
            let cur = s.invalidation_epoch.get();
            if cur != last_epoch.get_value() {
                last_epoch.set_value(cur);
                #[cfg(feature = "hydrate")]
                if let Some(el) = dialog_ref.get_untracked() {
                    lets_embed_ui::browser::wipe_media_elements_in(Some(el.as_ref()));
                }
                index.set(None);
            }
        });
    }

    // Move keyboard focus into the dialog on mount so shortcuts and Tab stay inside.
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        if let Some(el) = dialog_ref.get() {
            let _ = el.focus();
        }
    });

    let has_prev = move || matches!(index.get(), Some(i) if i > 0);
    let has_next = move || matches!(index.get(), Some(i) if i + 1 < total);
    let current_image = Memo::new(move |_| {
        index
            .get()
            .and_then(|i| images.with_value(|v| v.get(i).cloned()))
    });

    let slide = move |offset: isize| {
        if let Some(next) = index
            .get_untracked()
            .and_then(|i| i.checked_add_signed(offset))
            && next < total
        {
            index.set(Some(next));
        }
    };

    let nav_key = navigate.clone();
    let _ = use_event_listener(window(), ev::keydown, move |e| {
        if !lets_embed_ui::browser::is_top_modal(modal_layer) {
            return;
        }
        if e.alt_key() || e.ctrl_key() || e.meta_key() {
            return;
        }
        let key = e.key();
        if key == "Tab" {
            trap_dialog_tab(&e, dialog_ref.get_untracked());
            return;
        }
        if key != "Escape" && is_editable_target(e.target()) {
            return;
        }
        match key.as_str() {
            "ArrowLeft" | "k" | "K" => slide(-1),
            "ArrowRight" | "j" | "J" => slide(1),
            "Escape" => index.set(None),
            " " => {
                if is_interactive_target(e.target()) {
                    return;
                }
                index.set(None);
            }
            "d" | "D" => {
                if let Some(im) = current_image.get_untracked()
                    && !im.is_placeholder()
                {
                    let href = details_href(im.id());
                    let nav = nav_key.clone();
                    navigate_from_modal(
                        href,
                        move || {
                            index.set(None);
                            if let Some(cb) = on_navigate {
                                cb.run(());
                            }
                        },
                        move |dest, replace| {
                            nav(
                                dest,
                                NavigateOptions {
                                    replace,
                                    ..Default::default()
                                },
                            );
                        },
                    );
                }
            }
            _ => return,
        }
        e.prevent_default();
        e.stop_immediate_propagation();
    });

    let start_x = StoredValue::new(0.0_f64);
    let width = StoredValue::new(1.0_f64);
    let on_touch_start = move |ev: TouchEvent| {
        if ev.touches().length() != 1 {
            dragging.set(false);
            drag.set(0.0);
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
            dragging.set(true);
        }
    };
    let on_touch_move = move |ev: TouchEvent| {
        if !dragging.get_untracked() {
            return;
        }
        if ev.touches().length() != 1 {
            dragging.set(false);
            drag.set(0.0);
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

    let on_unlock = Callback::new(move |mask: GalleryMask| {
        handle_mask_unlock(&mask, safety);
    });

    let nav_slide = navigate.clone();
    let slides = images.with_value(|v| {
        v.iter()
            .enumerate()
            .map(|(slide_idx, im)| {
                let content = match im {
                    ProjectedImage::Clear {
                        id, url, name, ..
                    } => {
                        let href = details_href(*id);
                        let click_href = href.clone();
                        let nav = nav_slide.clone();
                        let src = url.clone();
                        let alt = name
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| format!("Image #{id}"));
                        view! {
                            <a
                                href=href
                                title="Open image details & similar"
                                class="max-h-full max-w-full flex items-center justify-center"
                                on:click=move |ev: ev::MouseEvent| {
                                    ev.stop_propagation();
                                    if !(ev.ctrl_key() || ev.meta_key() || ev.shift_key() || ev.alt_key() || ev.button() != 0) {
                                        ev.prevent_default();
                                        let nav = nav.clone();
                                        navigate_from_modal(
                                            click_href.clone(),
                                            move || {
                                                index.set(None);
                                                if let Some(cb) = on_navigate {
                                                    cb.run(());
                                                }
                                            },
                                            move |dest, replace| {
                                                nav(dest, NavigateOptions { replace, ..Default::default() });
                                            },
                                        );
                                    }
                                }
                            >
                                <img
                                    src=src
                                    alt=alt
                                    loading="lazy"
                                    class="max-h-[calc(100dvh-6.5rem)] max-w-[96vw] object-contain select-none cursor-pointer"
                                />
                            </a>
                        }
                        .into_any()
                    }
                    ProjectedImage::Blurred {
                        id,
                        preview_url,
                        can_click_reveal,
                        policy_rev,
                        width,
                        height,
                        label,
                        preset,
                        ..
                    } => {
                        let img_id = *id;
                        let w = *width;
                        let h = *height;
                        let p_url = preview_url.clone().unwrap_or_default();
                        let lbl = label.clone();
                        let alt = format!("Image #{img_id}");
                        view! {
                            <div
                                class="w-full max-w-[min(92vw,760px)] max-h-[calc(100dvh-7rem)] overflow-hidden rounded-2xl"
                                on:click=|ev| ev.stop_propagation()
                            >
                                <BlurredMediaCard
                                    kind=MediaKind::Image
                                    asset_id=img_id
                                    width=w
                                    height=h
                                    preview_url=p_url
                                    can_click_reveal=*can_click_reveal
                                    policy_rev=*policy_rev
                                    label=lbl
                                    preset=*preset
                                    alt=alt
                                />
                            </div>
                        }
                        .into_any()
                    }
                    ProjectedImage::Placeholder {
                        width,
                        height,
                        mask,
                        ..
                    } => {
                        let ui_mask = mask_to_ui(mask);
                        let dims = (*width, *height);
                        view! {
                            <div
                                class="w-full max-w-md"
                                on:click=|ev| ev.stop_propagation()
                            >
                                <ContentMaskCard
                                    mask=ui_mask
                                    dimensions=dims
                                    on_unlock_click=on_unlock
                                />
                            </div>
                        }
                        .into_any()
                    }
                };
                view! {
                    <div
                        class="flex-none w-screen h-full grid place-items-center px-2 py-2"
                        inert=move || index.get() != Some(slide_idx)
                    >
                        {content}
                    </div>
                }
            })
            .collect_view()
    });

    let nav_bar = navigate.clone();

    view! {
        <div
            node_ref=dialog_ref
            role="dialog"
            aria-modal="true"
            aria-label="Image viewer"
            tabindex="-1"
            class="web-viewer fixed inset-0 h-dvh bg-black/95 z-[60] overflow-hidden cursor-zoom-out select-none touch-none
                   flex flex-col outline-none"
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
            <div
                class="web-viewer-topbar shrink-0 z-20 flex items-center justify-between gap-1.5 sm:gap-2
                       px-2.5 sm:px-3 py-2 bg-black/85 border-b border-white/10 cursor-default"
                on:click=|ev| ev.stop_propagation()
                on:touchstart=|ev: TouchEvent| ev.stop_propagation()
                on:touchend=|ev: TouchEvent| ev.stop_propagation()
            >
                <div class="web-viewer-meta flex items-center gap-1.5 min-w-0">
                    <div class="web-viewer-counter text-xs sm:text-sm font-medium text-sky-100 bg-white/10 px-2.5 sm:px-3 py-1 rounded-full shrink-0 tabular-nums">
                        {move || index.get().map(|i| format!("{} / {}", i + 1, total)).unwrap_or_default()}
                    </div>
                    {move || current_image.get().and_then(|im| {
                        let (w, h) = (im.width(), im.height());
                        (w > 0 && h > 0).then(|| view! {
                            <span class="web-viewer-dims hidden sm:inline-block text-xs text-sky-200/75 bg-white/5 px-2.5 py-1 rounded-full tabular-nums">
                                {format!("{w} × {h}")}
                            </span>
                        })
                    })}
                </div>

                <div class="web-viewer-actions flex items-center gap-1.5 sm:gap-2 justify-end shrink-0">
                    {post_id.map(|pid| view! {
                        <LikeButton
                            kind="post"
                            target_id=pid
                            variant=LikeVariant::Overlay
                            show_label=true
                            hide_label_mobile=true
                        />
                    })}
                    {move || current_image.get().map(|im| {
                        let im_id = im.id();
                        let is_placeholder = im.is_placeholder();
                        let href = details_href(im_id);
                        let click_href = href.clone();
                        let nav = nav_bar.clone();
                        view! {
                            <LikeButton
                                kind="image"
                                target_id=im_id
                                variant=LikeVariant::Overlay
                                show_label=true
                                hide_label_mobile=true
                            />
                            {safety.filter(|s| s.is_managed.get()).map(|s| view! {
                                <button
                                    type="button"
                                    title="Report image"
                                    class="web-viewer-report-btn px-2.5 py-1.5 rounded-full bg-white/10 hover:bg-rose-500/70
                                           text-sky-100 text-xs font-medium transition-colors cursor-pointer whitespace-nowrap"
                                    on:click=move |ev: ev::MouseEvent| {
                                        ev.stop_propagation();
                                        s.open_report(
                                            ReportTargetKind::Image,
                                            im_id,
                                            format!("Image #{im_id}"),
                                        );
                                    }
                                >
                                    "Report"
                                </button>
                            })}
                            {(!is_placeholder).then(|| view! {
                                <a
                                    href=href
                                    class="web-viewer-details-link inline-flex items-center gap-1 px-2.5 sm:px-3 py-1.5 rounded-full
                                           bg-sky-500 hover:bg-sky-400 text-white text-xs sm:text-sm
                                           font-semibold shadow-sm transition-colors whitespace-nowrap"
                                    on:click=move |ev: ev::MouseEvent| {
                                        ev.stop_propagation();
                                        if !(ev.ctrl_key() || ev.meta_key() || ev.shift_key() || ev.alt_key() || ev.button() != 0) {
                                            ev.prevent_default();
                                            let nav = nav.clone();
                                            navigate_from_modal(
                                                click_href.clone(),
                                                move || {
                                                    index.set(None);
                                                    if let Some(cb) = on_navigate {
                                                        cb.run(());
                                                    }
                                                },
                                                move |dest, replace| {
                                                    nav(dest, NavigateOptions { replace, ..Default::default() });
                                                },
                                            );
                                        }
                                    }
                                >
                                    <span class="sm:hidden">"Details \u{2197}"</span>
                                    <span class="hidden sm:inline">"Details & similar \u{2197}"</span>
                                </a>
                            })}
                        }
                    })}
                    <button
                        type="button"
                        aria-label="Close viewer"
                        title="Close (Esc)"
                        class="text-white bg-white/10 hover:bg-sky-500/70 transition-colors rounded-full w-8 h-8 sm:w-9 sm:h-9 text-xl flex items-center justify-center cursor-pointer shrink-0"
                        on:click=move |ev| { ev.stop_propagation(); index.set(None); }
                    >"×"</button>
                </div>
            </div>

            <div class="relative flex-1 min-h-0 overflow-hidden">
                <div class="flex h-full will-change-transform" style=track_style>
                    {slides}
                </div>

                <button
                    type="button"
                    aria-label="Previous image"
                    class="absolute left-2 top-1/2 -translate-y-1/2 text-white bg-black/50 hover:bg-sky-500/70 transition-colors rounded-full w-11 h-11 sm:w-12 sm:h-12 text-3xl disabled:opacity-30 disabled:cursor-default cursor-pointer"
                    prop:disabled=move || !has_prev()
                    on:touchstart=|ev: TouchEvent| ev.stop_propagation()
                    on:touchend=|ev: TouchEvent| ev.stop_propagation()
                    on:click=move |ev| { ev.stop_propagation(); slide(-1); }
                >"‹"</button>
                <button
                    type="button"
                    aria-label="Next image"
                    class="absolute right-2 top-1/2 -translate-y-1/2 text-white bg-black/50 hover:bg-sky-500/70 transition-colors rounded-full w-11 h-11 sm:w-12 sm:h-12 text-3xl disabled:opacity-30 disabled:cursor-default cursor-pointer"
                    prop:disabled=move || !has_next()
                    on:touchstart=|ev: TouchEvent| ev.stop_propagation()
                    on:touchend=|ev: TouchEvent| ev.stop_propagation()
                    on:click=move |ev| { ev.stop_propagation(); slide(1); }
                >"›"</button>
            </div>

            <div class="hidden sm:flex shrink-0 justify-center pb-2.5 pt-0.5 pointer-events-none">
                <span class="text-xs text-sky-100/75 bg-white/5 px-3 py-1 rounded-full whitespace-nowrap">
                    "Click image or press D for details & similar · ← / → browse · Esc close"
                </span>
            </div>
        </div>
    }
}
