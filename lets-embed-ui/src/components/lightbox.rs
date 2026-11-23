use leptos::{ev, html, prelude::*};

use crate::browser::{
    lock_body_scroll, trap_dialog_tab, use_window_keydown, wipe_media_elements_in,
};
use crate::components::{
    ContentMaskCard, DensityPicker, LikeButton, MasonryGallery, MasonryGalleryProps,
    SpoilerOverlay, Viewer, ViewerProps,
};
use crate::layout::format_duration;
use crate::models::{
    AuthorChip, Density, GalleryCard, GalleryMask, GalleryMedia, LightboxAlbum, LikeTargetKind,
    LikeVariant, ReportTargetKind, ViewerItem,
};

/// Post album modal preview rendering all album images inside [`MasonryGallery`]
/// paired with [`DensityPicker`], plus a responsive video rail, [`LikeButton`],
/// Report trigger, nested [`Viewer`], and immediate close + media wipe on
/// `panic_epoch` change.
#[component]
pub fn Lightbox(
    album: Signal<Option<LightboxAlbum>>,
    density: RwSignal<Density>,
    on_close: Callback<()>,
    #[prop(optional)] panic_epoch: Option<Signal<u64>>,
    #[prop(optional)] on_open_viewer: Option<Callback<(usize, Vec<ViewerItem>)>>,
    #[prop(optional)] on_like_post: Option<Callback<(i64, bool)>>,
    #[prop(optional)] on_like_item: Option<Callback<(LikeTargetKind, i64, bool)>>,
    #[prop(optional)] on_report: Option<Callback<(ReportTargetKind, i64)>>,
    #[prop(optional)] on_unlock_click: Option<Callback<GalleryMask>>,
    #[prop(optional)] on_author_click: Option<Callback<AuthorChip>>,
    #[prop(optional)] on_details_click: Option<Callback<(GalleryCard, String)>>,
) -> impl IntoView {
    let is_open = Memo::new(move |_| album.with(Option::is_some));

    view! {
        {move || {
            is_open.get().then(|| view! {
                <LightboxDialog
                    album=album
                    density=density
                    on_close=on_close
                    panic_epoch=panic_epoch
                    on_open_viewer=on_open_viewer
                    on_like_post=on_like_post
                    on_like_item=on_like_item
                    on_report=on_report
                    on_unlock_click=on_unlock_click
                    on_author_click=on_author_click
                    on_details_click=on_details_click
                />
            })
        }}
    }
}

#[component]
fn LightboxDialog(
    album: Signal<Option<LightboxAlbum>>,
    density: RwSignal<Density>,
    on_close: Callback<()>,
    panic_epoch: Option<Signal<u64>>,
    on_open_viewer: Option<Callback<(usize, Vec<ViewerItem>)>>,
    on_like_post: Option<Callback<(i64, bool)>>,
    on_like_item: Option<Callback<(LikeTargetKind, i64, bool)>>,
    on_report: Option<Callback<(ReportTargetKind, i64)>>,
    on_unlock_click: Option<Callback<GalleryMask>>,
    on_author_click: Option<Callback<AuthorChip>>,
    on_details_click: Option<Callback<(GalleryCard, String)>>,
) -> impl IntoView {
    lock_body_scroll();

    let dialog_ref = NodeRef::<html::Div>::new();
    let viewer_index: RwSignal<Option<usize>> = RwSignal::new(None);
    let viewer_open = Memo::new(move |_| viewer_index.get().is_some());

    let close_now = move || {
        if let Some(el) = dialog_ref.get_untracked() {
            wipe_media_elements_in(Some(el.as_ref()));
        }
        viewer_index.set(None);
        on_close.run(());
    };

    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    Effect::new(move |_| {
        if let Some(el) = dialog_ref.get() {
            let _ = el.focus();
        }
    });

    // Safe Mode / Panic: immediately wipe media elements, close nested viewer & lightbox.
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

    use_window_keydown(false, move |e: ev::KeyboardEvent| {
        if viewer_open.get_untracked() {
            return;
        }
        if e.key() == "Tab" {
            trap_dialog_tab(&e, dialog_ref.get_untracked());
            return;
        }
        if e.key() == "Escape"
            && !e.default_prevented()
            && !e.alt_key()
            && !e.ctrl_key()
            && !e.meta_key()
        {
            e.prevent_default();
            close_now();
        }
    });

    let image_cards: Signal<Vec<GalleryCard>> = Signal::derive(move || {
        album.with(|a| a.as_ref().map(|x| x.images.clone()).unwrap_or_default())
    });

    let viewer_items: Signal<Vec<ViewerItem>> = Signal::derive(move || {
        image_cards.with(|cards| cards.iter().map(ViewerItem::from_card).collect())
    });

    let handle_open_card = Callback::new(move |card: GalleryCard| {
        let list = viewer_items.get_untracked();
        let idx = list
            .iter()
            .position(|it| it.id == card.media.id())
            .unwrap_or(0);
        if let Some(ext) = on_open_viewer {
            ext.run((idx, list));
        } else {
            viewer_index.set(Some(idx));
        }
    });

    let gallery_view = move || {
        MasonryGallery(MasonryGalleryProps {
            cards: image_cards,
            density: Signal::derive(move || density.get()),
            panic_epoch,
            embedded: true,
            selected_id: None,
            empty_message: None,
            on_open: Some(handle_open_card),
            on_unlock_click,
            on_like_toggle: on_like_item,
            on_details_click,
            on_report_click: on_report,
        })
    };

    view! {
        <div
            node_ref=dialog_ref
            role="dialog"
            aria-modal="true"
            aria-label="Post album"
            tabindex="-1"
            class="le-lightbox"
            on:click=move |ev: ev::MouseEvent| {
                ev.stop_propagation();
                close_now();
            }
        >
            {move || album.get().map(|cur| {
                let post_id = cur.post_id;
                let total_imgs = cur.effective_total_images();
                let loaded_imgs = cur.images.len();
                let has_videos = !cur.videos.is_empty();
                let post_liked_sig = Signal::derive(move || cur.liked.unwrap_or(false));
                let show_post_like = cur.liked.is_some() || on_like_post.is_some();

                view! {
                    <div
                        class="le-lightbox-header"
                        on:click=|ev: ev::MouseEvent| ev.stop_propagation()
                    >
                        <div class="le-lightbox-title-block">
                            <div class="le-lightbox-title">{cur.title}</div>
                            {(!cur.authors.is_empty()).then(|| view! {
                                <div class="le-lightbox-authors">
                                    {cur.authors.into_iter().map(|author| {
                                        let label = author.name.clone();
                                        let href = author.href.clone().unwrap_or_else(|| "#".to_string());
                                        let chip_clone = author.clone();
                                        view! {
                                            <a
                                                href=href
                                                class="le-author-chip"
                                                on:click=move |ev: ev::MouseEvent| {
                                                    ev.stop_propagation();
                                                    if let Some(cb) = on_author_click {
                                                        ev.prevent_default();
                                                        cb.run(chip_clone.clone());
                                                    }
                                                }
                                            >
                                                <span class="le-author-at">"@"</span>
                                                <span>{label}</span>
                                            </a>
                                        }
                                    }).collect_view()}
                                </div>
                            })}
                        </div>

                        {(total_imgs > 0).then(|| view! {
                            <div class="le-lightbox-density">
                                <DensityPicker density=density dark=true />
                            </div>
                        })}

                        <div class="le-lightbox-actions">
                            {show_post_like.then(|| {
                                if let Some(cb) = on_like_post {
                                    view! {
                                        <LikeButton
                                            kind=LikeTargetKind::Post
                                            target_id=post_id
                                            liked=post_liked_sig
                                            variant=LikeVariant::Overlay
                                            show_label=true
                                            hide_label_mobile=true
                                            on_toggle=Callback::new(move |next| cb.run((post_id, next)))
                                        />
                                    }
                                    .into_any()
                                } else {
                                    view! {
                                        <LikeButton
                                            kind=LikeTargetKind::Post
                                            target_id=post_id
                                            liked=post_liked_sig
                                            variant=LikeVariant::Overlay
                                            show_label=true
                                            hide_label_mobile=true
                                        />
                                    }
                                    .into_any()
                                }
                            })}

                            {on_report.map(|cb| view! {
                                <button
                                    type="button"
                                    class="le-viewer-btn le-viewer-btn--danger"
                                    title="Report post"
                                    aria-label="Report post"
                                    on:click=move |_| cb.run((ReportTargetKind::Post, post_id))
                                >
                                    "\u{2691} Report"
                                </button>
                            })}

                            <span class="le-lightbox-counter">
                                {format!("{loaded_imgs} / {total_imgs}")}
                            </span>

                            <button
                                type="button"
                                class="le-lightbox-close"
                                aria-label="Close album"
                                on:click=move |_| close_now()
                            >
                                "Close"
                            </button>
                        </div>
                    </div>

                    <div
                        class="le-lightbox-body"
                        on:click=|ev: ev::MouseEvent| ev.stop_propagation()
                    >
                        <div class="le-lightbox-images">
                            {gallery_view()}

                            {cur.loading.then(|| view! {
                                <div class="le-lightbox-status">"Loading album\u{2026}"</div>
                            })}

                            {cur.error.map(|err| view! {
                                <div class="le-lightbox-error">{format!("Could not load full album: {err}")}</div>
                            })}
                        </div>

                        {has_videos.then(|| view! {
                            <div class="le-lightbox-videos">
                                {cur.videos.into_iter().map(|vid| {
                                    let vid_id = vid.id();
                                    let (vw, vh) = vid.dimensions();
                                    let aspect = format!("aspect-ratio: {vw} / {vh};");
                                    let dur = vid.duration_secs().filter(|&d| d > 0).map(format_duration);
                                    let dims = format!("{vw}\u{00D7}{vh}");

                                    match vid {
                                        GalleryMedia::Clear { url, .. } => view! {
                                            <div class="le-lightbox-video-card">
                                                <video
                                                    class="le-video-player"
                                                    style=aspect
                                                    controls
                                                    playsinline
                                                    preload="metadata"
                                                    src=url
                                                />
                                                <div class="le-lightbox-video-badges">
                                                    {dur.map(|d| view! { <span class="le-duration-pill">{d}</span> })}
                                                    <span class="le-dims-pill">{dims}</span>
                                                </div>
                                                {on_like_item.map(|cb| view! {
                                                    <div class="gallery-top-right">
                                                        <LikeButton
                                                            kind=LikeTargetKind::Video
                                                            target_id=vid_id
                                                            liked=Signal::derive(|| false)
                                                            variant=LikeVariant::Card
                                                            on_toggle=Callback::new(move |next| cb.run((LikeTargetKind::Video, vid_id, next)))
                                                        />
                                                    </div>
                                                })}
                                            </div>
                                        }
                                        .into_any(),
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
                                            <div class="le-lightbox-video-card">
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
                                            <div class="le-lightbox-video-card">
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
                                }).collect_view()}
                            </div>
                        })}
                    </div>
                }
            })}
        </div>

        {Viewer(ViewerProps {
            items: viewer_items,
            index: viewer_index,
            panic_epoch,
            post_id: None,
            post_liked: None,
            on_close: None,
            on_like_toggle: on_like_item,
            on_report,
            on_unlock_click,
            on_details_click: None,
            on_download: None,
        })}
    }
}
