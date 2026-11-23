use leptos::{ev, html, prelude::*};

use crate::browser::wipe_media_elements_in;
use crate::models::{GalleryBlurMode, GalleryMaskPreset, GalleryMediaKind};

/// Click-to-reveal spoiler media wrapper supporting both:
/// - [`GalleryBlurMode::ServerTransform`]: renders only `preview_url` until the user
///   explicitly clicks reveal, then switches to `reveal_url`.
/// - [`GalleryBlurMode::CssCourtesy`]: applies a heavy frosted CSS blur + warning chip
///   over `preview_url` and clears the blur on click.
///
/// Whenever `panic_epoch` changes (Safe Mode / Panic), any revealed spoiler immediately
/// re-blurs and clears its media element sources.
#[component]
pub fn SpoilerOverlay(
    id: i64,
    #[prop(default = GalleryMediaKind::Image)] kind: GalleryMediaKind,
    width: i32,
    height: i32,
    preview_url: String,
    reveal_url: String,
    #[prop(default = String::new())] alt: String,
    label: String,
    #[prop(default = GalleryMaskPreset::Sensitive)] preset: GalleryMaskPreset,
    #[prop(default = GalleryBlurMode::ServerTransform)] blur_mode: GalleryBlurMode,
    #[prop(optional)] panic_epoch: Option<Signal<u64>>,
    #[prop(optional)] on_reveal: Option<Callback<i64>>,
    #[prop(optional)] on_open: Option<Callback<()>>,
) -> impl IntoView {
    let revealed = RwSignal::new(false);
    let root_ref = NodeRef::<html::Div>::new();

    if let Some(epoch_sig) = panic_epoch {
        let last_epoch = StoredValue::new(epoch_sig.get_untracked());
        Effect::new(move |_| {
            let cur = epoch_sig.get();
            if cur != last_epoch.get_value() {
                last_epoch.set_value(cur);
                if revealed.get_untracked() {
                    if let Some(el) = root_ref.get_untracked() {
                        wipe_media_elements_in(Some(el.as_ref()));
                    }
                    revealed.set(false);
                }
            }
        });
    }

    let (w, h) = if width > 0 && height > 0 {
        (width, height)
    } else {
        match kind {
            GalleryMediaKind::Video => (16, 9),
            GalleryMediaKind::Image => (4, 3),
        }
    };
    let aspect_style = format!("aspect-ratio: {w} / {h};");
    let chip_label = if label.trim().is_empty() {
        preset.label().to_string()
    } else {
        label
    };
    let blur_cls = match blur_mode {
        GalleryBlurMode::ServerTransform => "le-spoiler-img le-spoiler-img--server",
        GalleryBlurMode::CssCourtesy => "le-spoiler-img le-spoiler-img--css",
    };
    let mode_attr = match blur_mode {
        GalleryBlurMode::ServerTransform => "server_transform",
        GalleryBlurMode::CssCourtesy => "css_courtesy",
    };
    let preset_slug = preset.as_str();

    let preview_stored = StoredValue::new(preview_url);
    let reveal_stored = StoredValue::new(reveal_url);
    let alt_stored = StoredValue::new(alt);
    let chip_stored = StoredValue::new(chip_label);
    let root_aspect = aspect_style.clone();

    view! {
        <div
            node_ref=root_ref
            class=format!("le-spoiler le-spoiler--{preset_slug}")
            data-blur-mode=mode_attr
            data-revealed=move || revealed.get().to_string()
            style=root_aspect
        >
            {move || {
                if !revealed.get() {
                    let preview = preview_stored.get_value();
                    let alt_text = alt_stored.get_value();
                    let warning = chip_stored.get_value();
                    let aria = format!("Reveal blurred media: {warning}");
                    view! {
                        <button
                            type="button"
                            class="le-spoiler-trigger"
                            aria-label=aria
                            on:click=move |ev: ev::MouseEvent| {
                                ev.stop_propagation();
                                revealed.set(true);
                                if let Some(cb) = on_reveal {
                                    cb.run(id);
                                }
                            }
                        >
                            {(!preview.is_empty()).then(|| view! {
                                <img
                                    class=blur_cls
                                    src=preview
                                    alt=alt_text
                                    loading="lazy"
                                    decoding="async"
                                    width=w
                                    height=h
                                />
                            })}
                            <div class="le-spoiler-scrim" aria-hidden="true"></div>
                            <div class="le-spoiler-chip">
                                <span class="le-spoiler-chip-badge">{preset.short_badge()}</span>
                                <span class="le-spoiler-chip-label">{warning}</span>
                                <span class="le-spoiler-chip-hint">"Click to reveal"</span>
                            </div>
                        </button>
                    }
                    .into_any()
                } else {
                    let clear_url = reveal_stored.get_value();
                    let alt_text = alt_stored.get_value();
                    let aspect = aspect_style.clone();
                    view! {
                        <div class="le-spoiler-revealed">
                            {match kind {
                                GalleryMediaKind::Image => {
                                    if let Some(open_cb) = on_open {
                                        view! {
                                            <button
                                                type="button"
                                                class="le-media-btn"
                                                aria-label=format!("Open media #{id}")
                                                on:click=move |ev: ev::MouseEvent| {
                                                    ev.stop_propagation();
                                                    open_cb.run(());
                                                }
                                            >
                                                <img
                                                    class="gallery-img le-spoiler-clear-img"
                                                    src=clear_url
                                                    alt=alt_text
                                                    loading="lazy"
                                                    decoding="async"
                                                    width=w
                                                    height=h
                                                    style=aspect
                                                />
                                            </button>
                                        }
                                        .into_any()
                                    } else {
                                        view! {
                                            <img
                                                class="gallery-img le-spoiler-clear-img"
                                                src=clear_url
                                                alt=alt_text
                                                loading="lazy"
                                                decoding="async"
                                                width=w
                                                height=h
                                                style=aspect
                                            />
                                        }
                                        .into_any()
                                    }
                                }
                                GalleryMediaKind::Video => view! {
                                    <video
                                        class="le-video-player"
                                        src=clear_url
                                        controls
                                        playsinline
                                        preload="metadata"
                                        style=aspect
                                    />
                                }
                                .into_any(),
                            }}
                            <button
                                type="button"
                                class="le-spoiler-rehide"
                                aria-label="Re-blur media"
                                title="Hide spoiler"
                                on:click=move |ev: ev::MouseEvent| {
                                    ev.stop_propagation();
                                    if let Some(el) = root_ref.get_untracked() {
                                        wipe_media_elements_in(Some(el.as_ref()));
                                    }
                                    revealed.set(false);
                                }
                            >
                                "Hide"
                            </button>
                        </div>
                    }
                    .into_any()
                }
            }}
        </div>
    }
}
