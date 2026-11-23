use leptos::{ev, html, prelude::*};

use crate::browser::{
    is_editable_target, lock_body_scroll, trap_dialog_tab, use_window_keydown,
    wipe_media_elements_in,
};
use crate::components::{ContentMaskCard, LikeButton, SpoilerOverlay};
use crate::models::{
    GalleryMask, GalleryMedia, GalleryMediaKind, LikeTargetKind, LikeVariant, ReportTargetKind,
    ViewerItem,
};

const SWIPE_THRESHOLD_PX: f64 = 44.0;
const ZOOM_STEPS: [f32; 4] = [1.0, 1.5, 2.0, 3.0];

/// Fullscreen image & video viewer with keyboard navigation (`Esc` / `←` / `→` / `+` / `-` / `0`),
/// touch swipe navigation, zoom controls, download/like/report hooks, and immediate
/// close + media-source eviction on `panic_epoch` change (security finding L1).
#[component]
pub fn Viewer(
    items: Signal<Vec<ViewerItem>>,
    index: RwSignal<Option<usize>>,
    #[prop(optional)] panic_epoch: Option<Signal<u64>>,
    #[prop(optional)] post_id: Option<i64>,
    #[prop(optional)] post_liked: Option<Signal<bool>>,
    #[prop(optional)] on_close: Option<Callback<()>>,
    #[prop(optional)] on_like_toggle: Option<Callback<(LikeTargetKind, i64, bool)>>,
    #[prop(optional)] on_report: Option<Callback<(ReportTargetKind, i64)>>,
    #[prop(optional)] on_unlock_click: Option<Callback<GalleryMask>>,
    #[prop(optional)] on_details_click: Option<Callback<(ViewerItem, String)>>,
    #[prop(optional)] on_download: Option<Callback<ViewerItem>>,
) -> impl IntoView {
    let is_open = Memo::new(move |_| index.get().is_some());

    view! {
        {move || {
            is_open.get().then(|| view! {
                <ViewerOverlay
                    items=items
                    index=index
                    panic_epoch=panic_epoch
                    post_id=post_id
                    post_liked=post_liked
                    on_close=on_close
                    on_like_toggle=on_like_toggle
                    on_report=on_report
                    on_unlock_click=on_unlock_click
                    on_details_click=on_details_click
                    on_download=on_download
                />
            })
        }}
    }
}

#[component]
fn ViewerOverlay(
    items: Signal<Vec<ViewerItem>>,
    index: RwSignal<Option<usize>>,
    panic_epoch: Option<Signal<u64>>,
    post_id: Option<i64>,
    post_liked: Option<Signal<bool>>,
    on_close: Option<Callback<()>>,
    on_like_toggle: Option<Callback<(LikeTargetKind, i64, bool)>>,
    on_report: Option<Callback<(ReportTargetKind, i64)>>,
    on_unlock_click: Option<Callback<GalleryMask>>,
    on_details_click: Option<Callback<(ViewerItem, String)>>,
    on_download: Option<Callback<ViewerItem>>,
) -> impl IntoView {
    lock_body_scroll();

    let dialog_ref = NodeRef::<html::Div>::new();
    let zoom_idx = RwSignal::new(0usize);
    let revealed_spoiler_id: RwSignal<Option<i64>> = RwSignal::new(None);
    let touch_start_x = StoredValue::new(None::<f64>);

    let close_now = move || {
        if let Some(el) = dialog_ref.get_untracked() {
            wipe_media_elements_in(Some(el.as_ref()));
        }
        zoom_idx.set(0);
        revealed_spoiler_id.set(None);
        index.set(None);
        if let Some(cb) = on_close {
            cb.run(());
        }
    };

    // Also wipe active <video>/<img> elements on unmount so parent-driven close
    // (e.g. Lightbox closing Viewer on panic_epoch) never leaves media decoding/playing.
    on_cleanup(move || {
        if let Some(el) = dialog_ref.get_untracked() {
            wipe_media_elements_in(Some(el.as_ref()));
        }
    });

    // Focus dialog on client mount for immediate keyboard support.
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    Effect::new(move |_| {
        if let Some(el) = dialog_ref.get() {
            let _ = el.focus();
        }
    });

    // Security finding L1: immediately wipe media sources and close viewer when Safe Mode triggers.
    if let Some(epoch_sig) = panic_epoch {
        let initial_epoch = StoredValue::new(epoch_sig.get_untracked());
        Effect::new(move |_| {
            let cur = epoch_sig.get();
            if cur != initial_epoch.get_value() {
                initial_epoch.set_value(cur);
                close_now();
            }
        });
    }

    let total = Memo::new(move |_| items.with(Vec::len));
    let current = Memo::new(move |_| {
        let idx = index.get()?;
        items.with(|list| list.get(idx).cloned())
    });

    // Reset zoom and spoiler reveal tracking when navigating to another slide so
    // revisiting an unrevealed ServerTransform spoiler never exposes reveal_url.
    Effect::new(move |_| {
        let _ = index.get();
        zoom_idx.set(0);
        revealed_spoiler_id.set(None);
    });

    let has_prev = move || matches!(index.get(), Some(i) if i > 0);
    let has_next = move || matches!(index.get(), Some(i) if i + 1 < total.get());

    let step = move |delta: isize| {
        let len = total.get_untracked();
        if let Some(next) = index
            .get_untracked()
            .and_then(|i| i.checked_add_signed(delta))
            && next < len
        {
            index.set(Some(next));
        }
    };

    let zoom_in = move || {
        zoom_idx.update(|i| *i = (*i + 1).min(ZOOM_STEPS.len() - 1));
    };
    let zoom_out = move || {
        zoom_idx.update(|i| *i = i.saturating_sub(1));
    };
    let zoom_reset = move || zoom_idx.set(0);

    use_window_keydown(false, move |e: ev::KeyboardEvent| {
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
            "Escape" => close_now(),
            "ArrowLeft" | "k" | "K" => step(-1),
            "ArrowRight" | "j" | "J" => step(1),
            "+" | "=" => zoom_in(),
            "-" | "_" => zoom_out(),
            "0" => zoom_reset(),
            _ => return,
        }
        e.prevent_default();
        e.stop_propagation();
    });

    let on_touch_start = move |ev: ev::TouchEvent| {
        if zoom_idx.get_untracked() > 0 || ev.touches().length() != 1 {
            touch_start_x.set_value(None);
            return;
        }
        if let Some(t) = ev.touches().get(0) {
            touch_start_x.set_value(Some(t.client_x() as f64));
        }
    };

    let on_touch_end = move |ev: ev::TouchEvent| {
        let Some(start) = touch_start_x.get_value() else {
            return;
        };
        touch_start_x.set_value(None);
        if let Some(t) = ev.changed_touches().get(0) {
            let dx = t.client_x() as f64 - start;
            if dx <= -SWIPE_THRESHOLD_PX {
                step(1);
            } else if dx >= SWIPE_THRESHOLD_PX {
                step(-1);
            }
        }
    };

    let zoom_factor = move || ZOOM_STEPS[zoom_idx.get().min(ZOOM_STEPS.len() - 1)];

    view! {
        <div
            node_ref=dialog_ref
            role="dialog"
            aria-modal="true"
            aria-label="Media viewer"
            tabindex="-1"
            class="le-viewer"
            on:click=move |ev: ev::MouseEvent| {
                if !(ev.alt_key() || ev.ctrl_key() || ev.meta_key() || ev.shift_key()) {
                    close_now();
                }
            }
            on:touchstart=on_touch_start
            on:touchend=on_touch_end
        >
            <div
                class="le-viewer-bar"
                on:click=|ev: ev::MouseEvent| ev.stop_propagation()
                on:touchstart=|ev: ev::TouchEvent| ev.stop_propagation()
                on:touchend=|ev: ev::TouchEvent| ev.stop_propagation()
            >
                <div class="le-viewer-info">
                    <span class="le-viewer-counter">
                        {move || {
                            index
                                .get()
                                .map(|i| format!("{} / {}", i + 1, total.get()))
                                .unwrap_or_default()
                        }}
                    </span>
                    {move || current.get().map(|item| {
                        let (w, h) = item.media.dimensions();
                        view! {
                            <span class="le-viewer-title">{item.title}</span>
                            <span class="le-viewer-dims">{format!("{w} \u{00D7} {h}")}</span>
                        }
                    })}
                </div>

                <div class="le-viewer-actions">
                    // Zoom controls (shown for images)
                    {move || current.get().is_some_and(|it| it.kind == GalleryMediaKind::Image && !it.media.is_locked()).then(|| view! {
                        <div class="le-viewer-zoom-group" role="group" aria-label="Zoom controls">
                            <button
                                type="button"
                                class="le-viewer-btn"
                                title="Zoom out (-)"
                                aria-label="Zoom out"
                                disabled=move || zoom_idx.get() == 0
                                on:click=move |_| zoom_out()
                            >
                                "\u{2212}"
                            </button>
                            <button
                                type="button"
                                class="le-viewer-btn le-viewer-zoom-readout"
                                title="Reset zoom (0)"
                                on:click=move |_| zoom_reset()
                            >
                                {move || format!("{}%", (zoom_factor() * 100.0).round() as u32)}
                            </button>
                            <button
                                type="button"
                                class="le-viewer-btn"
                                title="Zoom in (+)"
                                aria-label="Zoom in"
                                disabled=move || zoom_idx.get() + 1 >= ZOOM_STEPS.len()
                                on:click=move |_| zoom_in()
                            >
                                "+"
                            </button>
                        </div>
                    })}

                    // Optional Post favorite button
                    {post_id.map(|pid| {
                        let liked_sig = post_liked.unwrap_or_else(|| Signal::derive(|| false));
                        if let Some(cb) = on_like_toggle {
                            view! {
                                <LikeButton
                                    kind=LikeTargetKind::Post
                                    target_id=pid
                                    liked=liked_sig
                                    variant=LikeVariant::Overlay
                                    show_label=true
                                    hide_label_mobile=true
                                    on_toggle=Callback::new(move |next| cb.run((LikeTargetKind::Post, pid, next)))
                                />
                            }
                            .into_any()
                        } else {
                            view! {
                                <LikeButton
                                    kind=LikeTargetKind::Post
                                    target_id=pid
                                    liked=liked_sig
                                    variant=LikeVariant::Overlay
                                    show_label=true
                                    hide_label_mobile=true
                                />
                            }
                            .into_any()
                        }
                    })}

                    // Current item controls (Like, Download, Report, Details)
                    {move || current.get().map(|item| {
                        let item_id = item.id;
                        let like_kind = match item.kind {
                            GalleryMediaKind::Image => LikeTargetKind::Image,
                            GalleryMediaKind::Video => LikeTargetKind::Video,
                        };
                        let report_kind = match item.kind {
                            GalleryMediaKind::Image => ReportTargetKind::Image,
                            GalleryMediaKind::Video => ReportTargetKind::Video,
                        };
                        let item_liked = item.liked;
                        let show_like = item_liked.is_some() || on_like_toggle.is_some();
                        let liked_sig = Signal::derive(move || item_liked.unwrap_or(false));
                        let is_revealed = revealed_spoiler_id.get() == Some(item_id);
                        let dl_url = item.effective_download_url(is_revealed).map(str::to_string);
                        let dl_name = item.download_filename.clone();
                        let dl_item = item.clone();
                        let details_href = if item.media.is_locked() {
                            None
                        } else {
                            item.details_href.clone()
                        };
                        let details_item = item.clone();

                        view! {
                            {show_like.then(|| {
                                if let Some(cb) = on_like_toggle {
                                    view! {
                                        <LikeButton
                                            kind=like_kind
                                            target_id=item_id
                                            liked=liked_sig
                                            variant=LikeVariant::Overlay
                                            show_label=true
                                            hide_label_mobile=true
                                            on_toggle=Callback::new(move |next| cb.run((like_kind, item_id, next)))
                                        />
                                    }
                                    .into_any()
                                } else {
                                    view! {
                                        <LikeButton
                                            kind=like_kind
                                            target_id=item_id
                                            liked=liked_sig
                                            variant=LikeVariant::Overlay
                                            show_label=true
                                            hide_label_mobile=true
                                        />
                                    }
                                    .into_any()
                                }
                            })}

                            {dl_url.map(|href| {
                                if let Some(cb) = on_download {
                                    view! {
                                        <button
                                            type="button"
                                            class="le-viewer-btn"
                                            title="Download media"
                                            on:click=move |_| cb.run(dl_item.clone())
                                        >
                                            "\u{2193} Download"
                                        </button>
                                    }
                                    .into_any()
                                } else {
                                    view! {
                                        <a
                                            href=href
                                            download=dl_name.unwrap_or_default()
                                            class="le-viewer-btn"
                                            title="Download media"
                                        >
                                            "\u{2193} Download"
                                        </a>
                                    }
                                    .into_any()
                                }
                            })}

                            {on_report.map(|cb| view! {
                                <button
                                    type="button"
                                    class="le-viewer-btn le-viewer-btn--danger"
                                    title="Report this media"
                                    aria-label="Report this media"
                                    on:click=move |_| cb.run((report_kind, item_id))
                                >
                                    "\u{2691} Report"
                                </button>
                            })}

                            {details_href.map(|href| {
                                let click_href = href.clone();
                                view! {
                                    <a
                                        href=href
                                        class="le-viewer-btn le-viewer-btn--primary"
                                        on:click=move |ev: ev::MouseEvent| {
                                            ev.stop_propagation();
                                            if let Some(cb) = on_details_click
                                                && !(ev.ctrl_key() || ev.meta_key() || ev.shift_key() || ev.alt_key() || ev.button() != 0)
                                            {
                                                ev.prevent_default();
                                                close_now();
                                                cb.run((details_item.clone(), click_href.clone()));
                                            }
                                        }
                                    >
                                        "Details \u{2197}"
                                    </a>
                                }
                            })}
                        }
                    })}

                    <button
                        type="button"
                        class="le-viewer-close"
                        aria-label="Close viewer"
                        title="Close (Esc)"
                        on:click=move |ev: ev::MouseEvent| {
                            ev.stop_propagation();
                            close_now();
                        }
                    >
                        "\u{00D7}"
                    </button>
                </div>
            </div>

            <div class="le-viewer-stage">
                {move || current.get().map(|item| {
                    let zoom = zoom_factor();
                    let zoom_style = if (zoom - 1.0).abs() > 0.01 {
                        format!("transform: scale({zoom}); transform-origin: center center;")
                    } else {
                        String::new()
                    };

                    match item.media {
                        GalleryMedia::Clear {
                            kind,
                            url,
                            alt,
                            width,
                            height,
                            ..
                        } => {
                            let alt_text = if alt.is_empty() { item.title } else { alt };
                            match kind {
                                GalleryMediaKind::Image => view! {
                                    <div
                                        class="le-viewer-media-wrap"
                                        on:click=move |ev: ev::MouseEvent| {
                                            ev.stop_propagation();
                                            if zoom_idx.get_untracked() == 0 {
                                                zoom_idx.set(1);
                                            } else {
                                                zoom_idx.set(0);
                                            }
                                        }
                                    >
                                        <img
                                            class=move || {
                                                if zoom_idx.get() > 0 {
                                                    "le-viewer-img is-zoomed"
                                                } else {
                                                    "le-viewer-img"
                                                }
                                            }
                                            src=url
                                            alt=alt_text
                                            style=zoom_style
                                        />
                                    </div>
                                }
                                .into_any(),
                                GalleryMediaKind::Video => {
                                    let aspect = if width > 0 && height > 0 {
                                        format!("aspect-ratio: {width} / {height};")
                                    } else {
                                        "aspect-ratio: 16 / 9;".to_string()
                                    };
                                    view! {
                                        <div
                                            class="le-viewer-media-wrap"
                                            on:click=|ev: ev::MouseEvent| ev.stop_propagation()
                                        >
                                            <video
                                                class="le-viewer-video"
                                                src=url
                                                controls
                                                playsinline
                                                preload="metadata"
                                                style=aspect
                                            />
                                        </div>
                                    }
                                    .into_any()
                                }
                            }
                        }
                        GalleryMedia::Spoiler {
                            id,
                            kind,
                            width,
                            height,
                            preview_url,
                            reveal_url,
                            alt,
                            label,
                            preset,
                            blur_mode,
                            ..
                        } => view! {
                            <div
                                class="le-viewer-spoiler-box"
                                on:click=|ev: ev::MouseEvent| ev.stop_propagation()
                            >
                                <SpoilerOverlay
                                    id=id
                                    kind=kind
                                    width=width
                                    height=height
                                    preview_url=preview_url
                                    reveal_url=reveal_url
                                    alt=alt
                                    label=label
                                    preset=preset
                                    blur_mode=blur_mode
                                    panic_epoch=panic_epoch.unwrap_or_else(|| Signal::derive(|| 0))
                                    on_reveal=Callback::new(move |rid| revealed_spoiler_id.set(Some(rid)))
                                    on_hide=Callback::new(move |hid| {
                                        if revealed_spoiler_id.get_untracked() == Some(hid) {
                                            revealed_spoiler_id.set(None);
                                        }
                                    })
                                />
                            </div>
                        }
                        .into_any(),
                        GalleryMedia::Locked {
                            width,
                            height,
                            mask,
                            ..
                        } => view! {
                            <div
                                class="le-viewer-locked-box"
                                on:click=|ev: ev::MouseEvent| ev.stop_propagation()
                            >
                                {if let Some(cb) = on_unlock_click {
                                    view! {
                                        <ContentMaskCard
                                            mask=mask
                                            dimensions=(width, height)
                                            on_unlock_click=cb
                                        />
                                    }
                                    .into_any()
                                } else {
                                    view! {
                                        <ContentMaskCard
                                            mask=mask
                                            dimensions=(width, height)
                                        />
                                    }
                                    .into_any()
                                }}
                            </div>
                        }
                        .into_any(),
                    }
                })}

                <button
                    type="button"
                    class="le-viewer-nav le-viewer-nav--prev"
                    aria-label="Previous item"
                    disabled=move || !has_prev()
                    on:touchstart=|ev: ev::TouchEvent| ev.stop_propagation()
                    on:touchend=|ev: ev::TouchEvent| ev.stop_propagation()
                    on:click=move |ev: ev::MouseEvent| {
                        ev.stop_propagation();
                        step(-1);
                    }
                >
                    "\u{2039}"
                </button>
                <button
                    type="button"
                    class="le-viewer-nav le-viewer-nav--next"
                    aria-label="Next item"
                    disabled=move || !has_next()
                    on:touchstart=|ev: ev::TouchEvent| ev.stop_propagation()
                    on:touchend=|ev: ev::TouchEvent| ev.stop_propagation()
                    on:click=move |ev: ev::MouseEvent| {
                        ev.stop_propagation();
                        step(1);
                    }
                >
                    "\u{203A}"
                </button>
            </div>

            <div class="le-viewer-hint" aria-hidden="true">
                <span>"\u{2190} / \u{2192} navigate \u{00B7} + / - zoom \u{00B7} Esc close"</span>
            </div>
        </div>
    }
}
