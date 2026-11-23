use leptos::{ev, html, prelude::*};

use crate::browser::{observe_element_width, read_window_width, wipe_media_elements_in};
use crate::components::{ContentMaskCard, LikeButton, SpoilerOverlay};
use crate::layout::{column_gap_for, column_pixel_width, format_duration, layout_masonry};
use crate::models::{
    Density, GalleryCard, GalleryCardKind, GalleryMask, GalleryMedia, GalleryMediaKind,
    LikeTargetKind, LikeVariant, ReportTargetKind,
};

/// Single gallery tile supporting `Clear`, `Spoiler` (via [`SpoilerOverlay`]),
/// and `Locked` (via [`ContentMaskCard`]) states while preserving exact aspect
/// ratios (`width / height`) and post badge counts (`Np Mv`) with zero layout shift.
#[component]
pub fn MediaTile(
    card: GalleryCard,
    #[prop(optional)] panic_epoch: Option<Signal<u64>>,
    #[prop(default = false)] is_selected: bool,
    #[prop(default = false)] compact: bool,
    #[prop(optional)] intrinsic_size: Option<Signal<(u32, u32)>>,
    #[prop(optional)] on_open: Option<Callback<GalleryCard>>,
    #[prop(optional)] on_unlock_click: Option<Callback<GalleryMask>>,
    #[prop(optional)] on_like_toggle: Option<Callback<(LikeTargetKind, i64, bool)>>,
    #[prop(optional)] on_details_click: Option<Callback<(GalleryCard, String)>>,
    #[prop(optional)] on_report_click: Option<Callback<(ReportTargetKind, i64)>>,
) -> impl IntoView {
    let is_post = card.kind == GalleryCardKind::Post;
    let is_locked = card.media.is_locked();
    let is_clear = card.media.is_clear();
    let frame_ref = NodeRef::<html::Div>::new();

    // Security finding L1: immediately wipe Clear <img>/<video> tiles when Safe Mode triggers,
    // without waiting for the host application's refetch to complete.
    if is_clear && let Some(epoch_sig) = panic_epoch {
        let initial_epoch = StoredValue::new(epoch_sig.get_untracked());
        Effect::new(move |_| {
            let cur = epoch_sig.get();
            if cur != initial_epoch.get_value() {
                initial_epoch.set_value(cur);
                if let Some(el) = frame_ref.get_untracked() {
                    wipe_media_elements_in(Some(el.as_ref()));
                }
            }
        });
    }
    let (w, h) = card.dimensions();
    let aspect_style = format!("aspect-ratio: {w} / {h};");
    let media_badge = card.media_badge();
    let duration_badge = card
        .media
        .duration_secs()
        .filter(|&d| d > 0)
        .map(format_duration);

    let tile_cls = {
        let mut cls = String::from("gallery-tile le-tile");
        if is_post {
            cls.push_str(" gallery-post le-tile--post");
        }
        if is_selected {
            cls.push_str(" le-tile--selected");
        }
        if is_locked {
            cls.push_str(" le-tile--locked");
        }
        cls
    };

    let frame_style = move || {
        if let Some(sig) = intrinsic_size {
            let (rw, rh) = sig.get();
            if rw > 0 && rh > 0 {
                return format!("content-visibility:auto;contain-intrinsic-size:{rw}px {rh}px;");
            }
        }
        String::new()
    };

    let card_for_open = card.clone();
    let card_for_details = card.clone();
    let open_label = if card.title.is_empty() {
        format!("Open item #{}", card.id)
    } else {
        format!("Open {}", card.title)
    };
    let like_kind = card.kind.like_kind();
    let report_kind = card.kind.report_kind();
    let target_id = card.id;
    let show_like = card.liked.is_some() || on_like_toggle.is_some();
    let initial_liked = card.liked.unwrap_or(false);
    let liked_sig = Signal::derive(move || initial_liked);

    let overlay_meta = if !card.title.is_empty() {
        card.title.clone()
    } else if let Some(sub) = &card.subtitle {
        sub.clone()
    } else {
        format!("#{}", card.id)
    };
    let details_href = if is_locked {
        None
    } else {
        card.details_href.clone()
    };
    let show_overlay = !is_locked && (!overlay_meta.is_empty() || details_href.is_some());

    let media_view = match card.media.clone() {
        GalleryMedia::Clear {
            id,
            kind,
            width,
            height,
            url,
            alt,
            ..
        } => {
            let (mw, mh) = if width > 0 && height > 0 {
                (width, height)
            } else {
                (w, h)
            };
            let alt_text = if alt.is_empty() {
                card.title.clone()
            } else {
                alt
            };
            let media_body = match kind {
                GalleryMediaKind::Image => view! {
                    <img
                        loading="lazy"
                        decoding="async"
                        width=mw
                        height=mh
                        alt=alt_text
                        style=aspect_style.clone()
                        class="gallery-img le-tile-img"
                        src=url
                    />
                }
                .into_any(),
                GalleryMediaKind::Video => view! {
                    <div class="le-tile-video-poster" style=aspect_style.clone()>
                        {(!url.is_empty()).then(|| view! {
                            <video
                                class="le-tile-video"
                                src=url
                                muted
                                playsinline
                                preload="metadata"
                                aria-label=alt_text
                            />
                        })}
                        <span class="le-video-play-glyph" aria-hidden="true">"\u{25B6}"</span>
                    </div>
                }
                .into_any(),
            };

            let open_cb = on_open;
            let open_item = card_for_open.clone();
            view! {
                <button
                    type="button"
                    aria-label=open_label
                    class="le-media-btn"
                    data-media-id=id
                    on:click=move |_| {
                        if let Some(cb) = open_cb {
                            cb.run(open_item.clone());
                        }
                    }
                >
                    {media_body}
                </button>
            }
            .into_any()
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
        } => {
            let open_cb = on_open.map(|cb| {
                let open_item = card_for_open.clone();
                Callback::new(move |()| cb.run(open_item.clone()))
            });
            view! {
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
                    on_open=open_cb.unwrap_or_else(|| Callback::new(|()| {}))
                />
            }
            .into_any()
        }
        GalleryMedia::Locked {
            width,
            height,
            mask,
            ..
        } => {
            let dims = if width > 0 && height > 0 {
                (width, height)
            } else {
                (w, h)
            };
            if let Some(unlock_cb) = on_unlock_click {
                view! {
                    <ContentMaskCard
                        mask=mask
                        dimensions=dims
                        compact=compact
                        on_unlock_click=unlock_cb
                    />
                }
                .into_any()
            } else {
                view! {
                    <ContentMaskCard
                        mask=mask
                        dimensions=dims
                        compact=compact
                    />
                }
                .into_any()
            }
        }
    };

    view! {
        <article class=tile_cls data-card-id=target_id>
            <div node_ref=frame_ref class="gallery-frame le-tile-frame" style=frame_style>
                {media_view}

                {(media_badge.is_some() || duration_badge.is_some()).then(|| view! {
                    <div class="gallery-top-left">
                        {media_badge.map(|badge| view! {
                            <span class="gallery-post-pill">
                                <span class="star" aria-hidden="true">"\u{2605}"</span>
                                <span>{badge}</span>
                            </span>
                        })}
                        {duration_badge.map(|dur| view! {
                            <span class="le-duration-pill">{dur}</span>
                        })}
                    </div>
                })}

                {(show_like || on_report_click.is_some()).then(|| view! {
                    <div class="gallery-top-right">
                        {on_report_click.map(|cb| view! {
                            <button
                                type="button"
                                class="le-tile-action-btn"
                                title="Report content"
                                aria-label=format!("Report {} #{target_id}", report_kind.as_str())
                                on:click=move |ev: ev::MouseEvent| {
                                    ev.stop_propagation();
                                    ev.prevent_default();
                                    cb.run((report_kind, target_id));
                                }
                            >
                                "\u{2691}"
                            </button>
                        })}
                        {show_like.then(|| {
                            if let Some(cb) = on_like_toggle {
                                view! {
                                    <LikeButton
                                        kind=like_kind
                                        target_id=target_id
                                        liked=liked_sig
                                        variant=LikeVariant::Card
                                        on_toggle=Callback::new(move |next| cb.run((like_kind, target_id, next)))
                                    />
                                }
                                .into_any()
                            } else {
                                view! {
                                    <LikeButton
                                        kind=like_kind
                                        target_id=target_id
                                        liked=liked_sig
                                        variant=LikeVariant::Card
                                    />
                                }
                                .into_any()
                            }
                        })}
                    </div>
                })}

                {show_overlay.then(|| {
                    let details_card = card_for_details.clone();
                    view! {
                        <div class="gallery-overlay">
                            <span class="gallery-overlay-meta">{overlay_meta}</span>
                            {details_href.map(|href| {
                                let click_href = href.clone();
                                view! {
                                    <a
                                        href=href
                                        title="Open details"
                                        class="gallery-overlay-link"
                                        on:click=move |ev: ev::MouseEvent| {
                                            ev.stop_propagation();
                                            if let Some(cb) = on_details_click
                                                && !(ev.ctrl_key() || ev.meta_key() || ev.shift_key() || ev.alt_key() || ev.button() != 0)
                                            {
                                                ev.prevent_default();
                                                cb.run((details_card.clone(), click_href.clone()));
                                            }
                                        }
                                    >
                                        "Details \u{2197}"
                                    </a>
                                }
                            })}
                        </div>
                    }
                })}
            </div>
        </article>
    }
}

/// Responsive aspect-ratio masonry gallery supporting both post-cover albums and
/// flat image/favorite lists, with an SSR-friendly CSS multi-column fallback that
/// hydrates cleanly into JS-balanced flex columns once container width is measured.
#[component]
pub fn MasonryGallery(
    cards: Signal<Vec<GalleryCard>>,
    density: Signal<Density>,
    #[prop(optional)] panic_epoch: Option<Signal<u64>>,
    #[prop(default = false)] embedded: bool,
    #[prop(optional)] selected_id: Option<Signal<Option<i64>>>,
    #[prop(optional, into)] empty_message: Option<String>,
    #[prop(optional)] on_open: Option<Callback<GalleryCard>>,
    #[prop(optional)] on_unlock_click: Option<Callback<GalleryMask>>,
    #[prop(optional)] on_like_toggle: Option<Callback<(LikeTargetKind, i64, bool)>>,
    #[prop(optional)] on_details_click: Option<Callback<(GalleryCard, String)>>,
    #[prop(optional)] on_report_click: Option<Callback<(ReportTargetKind, i64)>>,
) -> impl IntoView {
    let container_ref = NodeRef::<html::Div>::new();
    let measured_width = RwSignal::new(0.0_f64);
    observe_element_width(container_ref, measured_width);

    let col_count = Memo::new(move |_| {
        let w = measured_width.get();
        if w <= 0.0 {
            0
        } else {
            density.get().column_count(w)
        }
    });

    let col_width = Memo::new(move |_| {
        let w = measured_width.get();
        let cols = col_count.get();
        if w <= 0.0 || cols == 0 {
            return 0;
        }
        let vp = read_window_width();
        let gap = column_gap_for(if vp > 0.0 { vp } else { w });
        column_pixel_width(w, cols, gap)
    });

    let balanced_cols = Memo::new(move |_| {
        let cols = col_count.get();
        if cols == 0 {
            return Vec::new();
        }
        cards.with(|list| layout_masonry(list, cols, GalleryCard::masonry_ratio))
    });

    let wrap_cls = if embedded {
        "gallery-wrap gallery-embedded le-gallery-wrap"
    } else {
        "gallery-wrap le-gallery-wrap"
    };

    let render_tile_with_opts = move |card: GalleryCard, is_compact: bool| {
        let (w, h) = card.dimensions();
        let card_id = card.id;
        let is_sel = selected_id.is_some_and(|s| s.get_untracked() == Some(card_id));
        let intrinsic = Signal::derive(move || {
            let cw = col_width.get();
            if cw > 0 {
                let rh = ((f64::from(h) / f64::from(w)) * f64::from(cw))
                    .round()
                    .max(1.0) as u32;
                (cw, rh)
            } else {
                (0, 0)
            }
        });
        MediaTile(MediaTileProps {
            card,
            panic_epoch,
            is_selected: is_sel,
            compact: is_compact,
            intrinsic_size: Some(intrinsic),
            on_open,
            on_unlock_click,
            on_like_toggle,
            on_details_click,
            on_report_click,
        })
    };

    view! {
        <div node_ref=container_ref class=wrap_cls>
            {move || {
                let is_empty = cards.with(Vec::is_empty);
                if is_empty {
                    return empty_message
                        .clone()
                        .map(|msg| view! { <div class="le-gallery-empty">{msg}</div> }.into_any())
                        .unwrap_or_else(|| ().into_any());
                }

                let cols = col_count.get();
                let is_compact = density.get() == Density::Compact;
                if cols == 0 {
                    // SSR & initial hydration pass: CSS multi-column fallback grid
                    // matching density (mobile Compact=3, Medium=2, Large=1).
                    view! {
                        <div
                            class="gallery-ssr-grid le-ssr-grid"
                            data-density=move || density.get().as_str()
                        >
                            <For
                                each=move || cards.get()
                                key=|c| c.key.clone()
                                let(card)
                            >
                                {render_tile_with_opts(card, is_compact)}
                            </For>
                        </div>
                    }
                    .into_any()
                } else {
                    view! {
                        <div
                            class="gallery-masonry le-masonry"
                            data-density=move || density.get().as_str()
                            data-columns=cols
                        >
                            <For
                                each=move || 0..col_count.get()
                                key=|col_idx| *col_idx
                                let(col_idx)
                            >
                                <div class="gallery-col le-masonry-col">
                                    <For
                                        each=move || {
                                            balanced_cols.with(|all| {
                                                all.get(col_idx).cloned().unwrap_or_default()
                                            })
                                        }
                                        key=|placed| placed.item.key.clone()
                                        let(placed)
                                    >
                                        {render_tile_with_opts(placed.item, is_compact)}
                                    </For>
                                </div>
                            </For>
                        </div>
                    }
                    .into_any()
                }
            }}
        </div>
    }
}
