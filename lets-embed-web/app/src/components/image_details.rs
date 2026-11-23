use crate::{
    components::{Lightbox, LikeButton, LikeVariant, Results, Viewer},
    types::{
        ImageQuery, ImageQueryPayload, PostItem, ProjectedImageDetails, SafetyUiState,
        blur_mode_to_ui, mask_to_ui, navigate_external, unlock_href_for_mask,
    },
    util::{format_duration, layout_image_masonry, public_origin, set_document_title},
};

#[cfg(feature = "hydrate")]
use leptos::{ev, task::spawn_local};
use leptos::{ev::PointerEvent, html, prelude::*};
use leptos_meta::{Link, Meta, Title};
use leptos_router::hooks::{use_location, use_navigate, use_params_map, use_query_map};
use leptos_use_element_size::{UseElementSizeReturn, use_element_size};
#[cfg(feature = "hydrate")]
use leptos_use_event_listener::use_event_listener;
use lets_embed_ui::{
    ContentMaskCard, GalleryMask, GalleryMaskPreset, GalleryMediaKind, ReportTargetKind,
    SpoilerOverlay,
};
use search_types::{
    ProjectedImage, ProjectedVideo, Tag,
    query::{QueryExpr, SearchField},
};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, HtmlImageElement};

/// Maximum number of aliases joined inline when "Show aliases" is toggled on.
const MAX_INLINE_ALIASES: usize = 6;

/// Build a concise meta description (~155 chars) from DB-backed post title,
/// authors, top tags, and image dimensions.
fn build_detail_description(
    title: &str,
    authors: &[search_types::Author],
    tags: &[Tag],
    width: i32,
    height: i32,
) -> String {
    let mut parts = Vec::new();
    if !authors.is_empty() {
        let names = authors
            .iter()
            .take(3)
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("{title} by {names}"));
    } else {
        parts.push(title.to_string());
    }
    if !tags.is_empty() {
        let tag_list = tags
            .iter()
            .take(8)
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("Tags: {tag_list}"));
    }
    if width > 0 && height > 0 {
        parts.push(format!("{width}×{height}"));
    }
    parts.push("Explore the full album and visually similar images on Let's Embed.".to_string());
    let joined = parts.join(" · ");
    if joined.chars().count() <= 165 {
        joined
    } else {
        let truncated: String = joined.chars().take(162).collect();
        format!("{truncated}…")
    }
}

/// Build an Advanced Search URL targeting a single WD tag or multilingual alias.
fn tag_search_href(value: &str) -> String {
    let query = QueryExpr::Term {
        field: SearchField::Tag,
        value: value.to_string(),
    }
    .format_query();
    format!("/?mode=advanced&adv={}", urlencoding::encode(&query))
}

#[derive(Clone, Debug, PartialEq)]
struct TagTooltip {
    tag_id: i64,
    name: String,
    aliases: Vec<String>,
    score_pct: Option<u8>,
    x: f64,
    y: f64,
    below: bool,
}

fn build_tag_tooltip(tag: &Tag, el: &web_sys::Element) -> TagTooltip {
    let rect = el.get_bounding_client_rect();
    let vw = web_sys::window()
        .and_then(|w| w.inner_width().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(1024.0);
    let x = (rect.left() + rect.width() / 2.0).clamp(156.0, (vw - 156.0).max(156.0));
    let below = rect.top() < 260.0;
    let y = if below { rect.bottom() } else { rect.top() };
    let score_pct = tag.score.map(|s| (s.clamp(0.0, 1.0) * 100.0).round() as u8);
    TagTooltip {
        tag_id: tag.id,
        name: tag.name.clone(),
        aliases: tag.aliases.clone(),
        score_pct,
        x,
        y,
        below,
    }
}

/// Selected region in original image coordinates.
#[derive(Clone, Copy)]
struct Region {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

fn crop_to_base64(img: &HtmlImageElement, region: Region) -> Option<String> {
    const MAX_EDGE: f64 = 256.0;

    let sw = region.w as f64;
    let sh = region.h as f64;
    if sw < 1.0 || sh < 1.0 {
        return None;
    }
    let scale = (MAX_EDGE / sw.max(sh)).min(1.0);
    let dw = (sw * scale).round().max(1.0);
    let dh = (sh * scale).round().max(1.0);

    let document = web_sys::window()?.document()?;
    let canvas: HtmlCanvasElement = document.create_element("canvas").ok()?.dyn_into().ok()?;
    canvas.set_width(dw as u32);
    canvas.set_height(dh as u32);

    let ctx: CanvasRenderingContext2d = canvas.get_context("2d").ok()??.dyn_into().ok()?;

    ctx.draw_image_with_html_image_element_and_sw_and_sh_and_dx_and_dy_and_dw_and_dh(
        img,
        region.x as f64,
        region.y as f64,
        sw,
        sh,
        0.0,
        0.0,
        dw,
        dh,
    )
    .ok()?;

    let data_url = canvas
        .to_data_url_with_type_and_encoder_options("image/webp", &JsValue::from_f64(0.7))
        .ok()?;

    let b64 = data_url.split_once(',')?.1;
    let url_safe = b64
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string();
    Some(url_safe)
}

#[component]
pub fn ImageDetails() -> impl IntoView {
    let params = use_params_map();
    let id_sig: Signal<Option<String>> = Memo::new(move |_| params.with(|p| p.get("id"))).into();
    view! {
        <div class="w-full min-h-full flex flex-col pt-2 sm:pt-3">
            <For each=move || params.with(|p| p.get("id")) key=String::clone let(id)>
                <ImageDetailPage id />
            </For>
            <div class="w-full px-3 md:px-4 pb-4 mt-2">
                <Results embedded=true default_similar_id=id_sig heading="Similar \u{1f49e}" />
            </div>
        </div>
    }
}

/// Aspect-ratio masonry for the post album sidebar on `/details/:id`.
#[component]
fn PostAlbumMasonry(
    images: Vec<ProjectedImage>,
    current_image_id: i64,
    on_zoom: Callback<usize>,
) -> impl IntoView {
    let safety = use_context::<SafetyUiState>();
    let panic_epoch_sig: Option<Signal<u64>> = safety.map(|s| s.panic_epoch.into());
    let images_store = StoredValue::new(images);
    let container_ref = NodeRef::<html::Div>::new();
    let UseElementSizeReturn {
        width: container_w, ..
    } = use_element_size(container_ref);
    let col_count = Memo::new(move |_| {
        let w = container_w.get();
        if w <= 0.0 || w < 340.0 {
            2
        } else if w < 560.0 {
            3
        } else {
            4
        }
    });
    let cols = Memo::new(move |_| {
        let count = col_count.get();
        images_store.with_value(|imgs| layout_image_masonry(imgs, count))
    });

    let on_unlock = Callback::new(move |mask: GalleryMask| {
        navigate_external(unlock_href_for_mask(&mask));
    });

    view! {
        <div
            node_ref=container_ref
            class="flex-[2] min-w-0 max-h-[40vh] overflow-y-auto md:max-h-none md:min-h-0 p-0.5 pr-1.5"
        >
            <div class="flex items-start gap-2 w-full">
                <For
                    each=move || 0..col_count.get()
                    key=|col_idx| *col_idx
                    let(col_idx)
                >
                    <div class="flex-1 min-w-0 flex flex-col gap-2">
                        <For
                            each=move || {
                                cols.with(|c| c.get(col_idx).cloned().unwrap_or_default())
                            }
                            key=|(_, im)| im.id()
                            let((i, image))
                        >
                            {
                                let img_id = image.id();
                                let is_current = img_id == current_image_id;
                                let (raw_w, raw_h) = (image.width(), image.height());
                                let (w, h) = if raw_w > 0 && raw_h > 0 {
                                    (raw_w, raw_h)
                                } else {
                                    (4, 3)
                                };
                                let aspect_style = format!("aspect-ratio:{w}/{h};");
                                let ring_cls = if is_current { "ring-2 ring-sky-400" } else { "" };

                                match image {
                                    ProjectedImage::Clear { url, name, .. } => {
                                        let alt = name
                                            .filter(|s| !s.is_empty())
                                            .unwrap_or_else(|| format!("Image #{img_id}"));
                                        let cls = format!(
                                            "relative block w-full p-0 border-0 rounded-lg overflow-hidden bg-sky-100 \
                                             cursor-zoom-in hover:opacity-85 hover:scale-[1.02] transition-all \
                                             focus-visible:outline-2 focus-visible:outline-sky-500 {ring_cls}"
                                        );
                                        view! {
                                            <button
                                                type="button"
                                                aria-label=format!("Zoom album image {}", i + 1)
                                                class=cls
                                                style=aspect_style
                                                on:click=move |_| on_zoom.run(i)
                                            >
                                                <img
                                                    loading="lazy"
                                                    decoding="async"
                                                    width=w
                                                    height=h
                                                    class="block w-full h-full object-cover select-none"
                                                    src=url
                                                    alt=alt
                                                />
                                            </button>
                                        }
                                        .into_any()
                                    }
                                    ProjectedImage::Spoiler {
                                        preview_url,
                                        reveal_url,
                                        label,
                                        preset,
                                        blur_mode,
                                        ..
                                    } => {
                                        let open_cb = Callback::new(move |()| on_zoom.run(i));
                                        let ui_preset = GalleryMaskPreset::parse(&preset);
                                        let ui_blur = blur_mode_to_ui(blur_mode);
                                        let alt = format!("Image #{img_id}");
                                        view! {
                                            <div class=format!("rounded-lg overflow-hidden {ring_cls}")>
                                                {match panic_epoch_sig {
                                                    Some(epoch) => view! {
                                                        <SpoilerOverlay
                                                            id=img_id
                                                            kind=GalleryMediaKind::Image
                                                            width=w
                                                            height=h
                                                            preview_url=preview_url
                                                            reveal_url=reveal_url
                                                            alt=alt
                                                            label=label
                                                            preset=ui_preset
                                                            blur_mode=ui_blur
                                                            panic_epoch=epoch
                                                            on_open=open_cb
                                                        />
                                                    }
                                                    .into_any(),
                                                    None => view! {
                                                        <SpoilerOverlay
                                                            id=img_id
                                                            kind=GalleryMediaKind::Image
                                                            width=w
                                                            height=h
                                                            preview_url=preview_url
                                                            reveal_url=reveal_url
                                                            alt=alt
                                                            label=label
                                                            preset=ui_preset
                                                            blur_mode=ui_blur
                                                            on_open=open_cb
                                                        />
                                                    }
                                                    .into_any(),
                                                }}
                                            </div>
                                        }
                                        .into_any()
                                    }
                                    ProjectedImage::Locked { mask, .. } => {
                                        let ui_mask = mask_to_ui(&mask);
                                        view! {
                                            <div class=format!("rounded-lg overflow-hidden {ring_cls}")>
                                                <ContentMaskCard
                                                    mask=ui_mask
                                                    dimensions=(w, h)
                                                    compact=true
                                                    on_unlock_click=on_unlock
                                                />
                                            </div>
                                        }
                                        .into_any()
                                    }
                                }
                            }
                        </For>
                    </div>
                </For>
            </div>
        </div>
    }
}

#[component]
fn ImageDetailPage(id: String) -> impl IntoView {
    let img_query = expect_context::<ImageQuery>();
    let safety = use_context::<SafetyUiState>();
    let panic_epoch_sig: Option<Signal<u64>> = safety.map(|s| s.panic_epoch.into());
    let id_stored = StoredValue::new(id);

    let details = Resource::new(
        move || {
            let epoch = safety.map(|s| s.reload_epoch.get()).unwrap_or(0);
            (id_stored.get_value(), epoch)
        },
        move |(id_val, _epoch)| async move {
            fetch_image_details(Some(id_val))
                .await
                .map_err(|e| e.to_string())
        },
    );
    let post_images = Resource::new(
        move || {
            let epoch = safety.map(|s| s.reload_epoch.get()).unwrap_or(0);
            let pid = details
                .get()
                .and_then(|res| res.ok())
                .and_then(|d| d.post.map(|p| p.id));
            (pid, epoch)
        },
        move |(pid, _epoch)| async move {
            let Some(post_id) = pid else {
                return Ok(Vec::new());
            };
            list_post_images(post_id).await.map_err(|e| e.to_string())
        },
    );
    let post_videos = Resource::new(
        move || {
            let epoch = safety.map(|s| s.reload_epoch.get()).unwrap_or(0);
            let pid = details
                .get()
                .and_then(|res| res.ok())
                .and_then(|d| d.post.map(|p| p.id));
            (pid, epoch)
        },
        move |(pid, _epoch)| async move {
            let Some(post_id) = pid else {
                return Ok(Vec::new());
            };
            list_post_videos(post_id).await.map_err(|e| e.to_string())
        },
    );

    let lightbox: RwSignal<Option<PostItem>> = RwSignal::new(None);
    let viewer: RwSignal<Option<usize>> = RwSignal::new(None);
    let current_post_id: RwSignal<Option<i64>> = RwSignal::new(None);
    let post_images_store: StoredValue<Vec<ProjectedImage>> = StoredValue::new(Vec::new());
    let post_images_count: RwSignal<Option<usize>> = RwSignal::new(None);
    let viewer_images_store: StoredValue<Vec<ProjectedImage>> = StoredValue::new(Vec::new());
    let post_videos_store: StoredValue<Vec<ProjectedVideo>> = StoredValue::new(Vec::new());
    let post_videos_count: RwSignal<Option<usize>> = RwSignal::new(None);

    // Immediately wipe media and close modals on Safe Mode / Panic trigger.
    if let Some(s) = safety {
        let last_epoch = StoredValue::new(s.panic_epoch.get_untracked());
        Effect::new(move |_| {
            let cur = s.panic_epoch.get();
            if cur != last_epoch.get_value() {
                last_epoch.set_value(cur);
                lets_embed_ui::browser::wipe_media_elements_in(None);
                viewer.set(None);
                lightbox.set(None);
                post_images_store.set_value(Vec::new());
                viewer_images_store.set_value(Vec::new());
                post_videos_store.set_value(Vec::new());
            }
        });
    }

    Effect::new(move |_| {
        if let Some(Ok(d)) = details.get() {
            let page_title = d
                .post
                .as_ref()
                .map(|p| p.title.clone())
                .unwrap_or_else(|| format!("Image #{}", d.image.id()));
            set_document_title(&page_title);
            current_post_id.set(d.post.map(|p| p.id));
        }
    });
    Effect::new(move |_| {
        if let Some(res) = post_images.get() {
            match res {
                Ok(imgs) => {
                    let count = imgs.len();
                    post_images_store.set_value(imgs);
                    post_images_count.set(Some(count));
                }
                Err(_) => {
                    post_images_count.set(Some(0));
                }
            }
        }
    });
    Effect::new(move |_| {
        if let Some(res) = post_videos.get() {
            match res {
                Ok(videos) => {
                    let count = videos.len();
                    post_videos_store.set_value(videos);
                    post_videos_count.set(Some(count));
                }
                Err(_) => {
                    post_videos_count.set(Some(0));
                }
            }
        }
    });
    let viewer_open = Memo::new(move |_| viewer.get().is_some());

    let img_ref: NodeRef<html::Img> = NodeRef::new();
    let container_ref: NodeRef<html::Div> = NodeRef::new();
    let overlay_ref: NodeRef<html::Div> = NodeRef::new();
    let drag_origin: RwSignal<Option<(f64, f64)>> = RwSignal::new(None);
    let sel_box: RwSignal<Option<(f64, f64, f64, f64)>> = RwSignal::new(None);

    let qmap = use_query_map();
    Effect::new(move |_| {
        let is_crop_search = qmap.with(|m| m.get("mode").as_deref() == Some("search_image"));
        if !is_crop_search {
            sel_box.set(None);
            drag_origin.set(None);
        }
    });

    let navigate = use_navigate();
    let pathname = use_location().pathname;

    let hovered_tag: RwSignal<Option<TagTooltip>> = RwSignal::new(None);
    let tip_close_gen: StoredValue<u64> = StoredValue::new(0);
    let pointer_in_tip: StoredValue<bool> = StoredValue::new(false);
    let focus_in_tip: StoredValue<bool> = StoredValue::new(false);
    let show_inline_aliases = RwSignal::new(false);
    let copied_id = RwSignal::new(false);
    #[cfg(feature = "hydrate")]
    let copy_gen: StoredValue<u64> = StoredValue::new(0);

    let cancel_tip_close = move || {
        tip_close_gen.set_value(tip_close_gen.get_value().wrapping_add(1));
    };

    let close_tip_now = move || {
        cancel_tip_close();
        pointer_in_tip.set_value(false);
        focus_in_tip.set_value(false);
        hovered_tag.set(None);
    };

    let schedule_tip_close = move || {
        let close_id = tip_close_gen.get_value().wrapping_add(1);
        tip_close_gen.set_value(close_id);
        #[cfg(feature = "hydrate")]
        set_timeout(
            move || {
                if tip_close_gen.try_get_value() == Some(close_id)
                    && !pointer_in_tip.try_get_value().unwrap_or(false)
                    && !focus_in_tip.try_get_value().unwrap_or(false)
                {
                    let _ = hovered_tag.try_set(None);
                }
            },
            std::time::Duration::from_millis(180),
        );
    };

    #[cfg(feature = "hydrate")]
    {
        let _ = use_event_listener(window(), ev::scroll, move |_| {
            if hovered_tag.with_untracked(Option::is_some) {
                close_tip_now();
            }
        });
        let _ = use_event_listener(window(), ev::keydown, move |e: ev::KeyboardEvent| {
            if e.key() == "Escape" && hovered_tag.with_untracked(Option::is_some) {
                close_tip_now();
            }
        });
    }

    let lightbox_view = move || {
        lightbox
            .get()
            .map(|post| view! { <Lightbox post lightbox/> })
    };

    let viewer_view = move || {
        viewer_open
            .get()
            .then(|| match current_post_id.get_untracked() {
                Some(pid) => {
                    view! { <Viewer images=viewer_images_store index=viewer post_id=pid /> }
                        .into_any()
                }
                None => view! { <Viewer images=viewer_images_store index=viewer /> }.into_any(),
            })
    };

    let on_unlock = Callback::new(move |mask: GalleryMask| {
        navigate_external(unlock_href_for_mask(&mask));
    });

    let render_author_pill = |name: String| {
        let href = format!("/?mode=author&q={}&limit=50", urlencoding::encode(&name));
        let tip = format!("Search posts by {name}");
        view! {
            <a href=href title=tip>
                <span class="inline-flex items-center gap-1 px-3 py-1 text-xs md:text-sm font-medium text-white
                             bg-gradient-to-r from-sky-500 to-cyan-500 rounded-full shadow-sm whitespace-nowrap
                             hover:scale-105 transition-transform cursor-pointer">
                    <span class="opacity-80">"@"</span>
                    <span>{ name }</span>
                </span>
            </a>
        }
    };

    let render_tag_pill = move |tag: Tag| {
        let href = tag_search_href(&tag.name);
        let tag_id = tag.id;
        let has_aliases = !tag.aliases.is_empty();
        let name = tag.name.clone();
        let tag_enter = tag.clone();
        let tag_focus = tag;
        let show_tip = move |target: Option<web_sys::EventTarget>, tag_data: &Tag| {
            cancel_tip_close();
            if let Some(el) = target.and_then(|t| t.dyn_into::<web_sys::Element>().ok()) {
                hovered_tag.set(Some(build_tag_tooltip(tag_data, &el)));
            }
        };
        let show_tip_focus = show_tip;
        view! {
            <a
                href=href
                aria-describedby=move || {
                    hovered_tag
                        .with(|t| t.as_ref().is_some_and(|tip| tip.tag_id == tag_id))
                        .then_some("tag-alias-tooltip")
                }
                class="inline-flex items-center gap-1.5 px-3 py-1 text-xs md:text-sm font-medium text-white
                       bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full shadow-sm max-w-full
                       hover:scale-105 hover:brightness-110 transition-all cursor-pointer"
                on:mouseenter=move |ev: leptos::ev::MouseEvent| {
                    show_tip(ev.current_target(), &tag_enter);
                }
                on:mouseleave=move |_| schedule_tip_close()
                on:focus=move |ev: leptos::ev::FocusEvent| {
                    show_tip_focus(ev.current_target(), &tag_focus);
                }
                on:blur=move |_| schedule_tip_close()
                on:click=move |_| close_tip_now()
            >
                <span class="truncate">{ name }</span>
                {has_aliases.then(|| view! {
                    <span class="w-1.5 h-1.5 rounded-full bg-white/75 shrink-0" aria-hidden="true" />
                })}
            </a>
        }
    };

    let render_tag_alias_card = move |tag: Tag| {
        let href = tag_search_href(&tag.name);
        let score_pct = tag.score.map(|s| (s.clamp(0.0, 1.0) * 100.0).round() as u8);
        let aliases = StoredValue::new(tag.aliases);
        let total_aliases = aliases.with_value(Vec::len);
        let alias_count_label = if total_aliases == 1 {
            "1 alias".to_string()
        } else {
            format!("{total_aliases} aliases")
        };
        let extra = total_aliases.saturating_sub(MAX_INLINE_ALIASES);
        let expanded = RwSignal::new(false);
        view! {
            <div class="min-w-0 rounded-xl bg-white/90 ring-1 ring-indigo-200/75 px-2.5 py-1.5 flex flex-col gap-1">
                <div class="flex items-center justify-between gap-2 min-w-0">
                    <a
                        href=href
                        class="text-xs md:text-sm font-semibold text-indigo-700 hover:text-sky-600 hover:underline truncate min-w-0"
                    >
                        {tag.name}
                    </a>
                    <div class="flex items-center gap-1.5 shrink-0">
                        {(total_aliases > 0).then(|| view! {
                            <span class="text-[10px] text-slate-400 tabular-nums whitespace-nowrap">
                                {alias_count_label}
                            </span>
                        })}
                        {score_pct.map(|pct| view! {
                            <span class="px-1.5 py-0.5 rounded-full bg-indigo-50 text-indigo-600 text-[10px] font-semibold tabular-nums">
                                {format!("{pct}%")}
                            </span>
                        })}
                    </div>
                </div>
                {(total_aliases > 0).then(|| view! {
                    <div class="flex flex-wrap items-center gap-1 min-w-0">
                        {move || {
                            let limit = if expanded.get() { total_aliases } else { MAX_INLINE_ALIASES };
                            let items: Vec<String> = aliases.with_value(|v| {
                                v.iter().take(limit).cloned().collect()
                            });
                            items.into_iter().map(|a| {
                                let alias_href = tag_search_href(&a);
                                view! {
                                    <a
                                        href=alias_href
                                        class="max-w-full break-words px-1.5 py-0.5 rounded-md bg-sky-50 hover:bg-sky-500 text-slate-700
                                               hover:text-white ring-1 ring-sky-200/70 text-[11px] leading-snug
                                               transition-colors"
                                    >
                                        {a}
                                    </a>
                                }
                            }).collect_view()
                        }}
                        {(extra > 0).then(|| view! {
                            <button
                                type="button"
                                aria-expanded=move || expanded.get().to_string()
                                class="px-1.5 py-0.5 rounded-md bg-indigo-50 hover:bg-indigo-100 text-indigo-600
                                       text-[11px] font-medium leading-snug transition-colors cursor-pointer"
                                on:click=move |_| expanded.update(|v| *v = !*v)
                            >
                                {move || if expanded.get() {
                                    "Show less".to_string()
                                } else {
                                    format!("+{extra} more")
                                }}
                            </button>
                        })}
                    </div>
                })}
            </div>
        }
    };

    let render_details = move |ProjectedImageDetails {
                                   image,
                                   post,
                                   authors,
                                   tags,
                                   og_image_allowed,
                                   noindex,
                               }| {
        let image_id = image.id();
        let (image_width, image_height) = (image.width(), image.height());
        let clear_url = match &image {
            ProjectedImage::Clear { url, .. } => Some(url.clone()),
            _ => None,
        };
        let is_locked = image.is_locked();
        let tag_count = tags.len();
        let any_aliases = tags.iter().any(|t| !t.aliases.is_empty());

        let post_meta = post.as_ref().map(|p| (p.id, p.title.clone()));
        let post_like_id = post_meta.as_ref().map(|(id, _)| *id);
        let post_store = StoredValue::new(post_meta);

        let album_ready =
            move || post_images_count.get().is_some() && post_videos_count.get().is_some();

        let open_lightbox = move || {
            if !album_ready() {
                return;
            }
            post_store.with_value(|m| {
                if let Some((id, title)) = m {
                    let images = post_images_store.with_value(|v| v.clone());
                    let videos = post_videos_store.with_value(|v| v.clone());
                    let image_count = images.len();
                    let video_count = videos.len();
                    lightbox.set(Some(PostItem {
                        id: *id,
                        title: title.clone(),
                        images,
                        videos,
                        image_count,
                        video_count,
                    }));
                }
            });
        };

        let open_zoom_at = {
            let image = image.clone();
            move |preferred_idx: Option<usize>| {
                let imgs = post_images_store.with_value(|v| v.clone());
                if !imgs.is_empty() {
                    let idx = preferred_idx
                        .filter(|&i| i < imgs.len())
                        .or_else(|| imgs.iter().position(|im| im.id() == image_id))
                        .unwrap_or(0);
                    viewer_images_store.set_value(imgs);
                    viewer.set(Some(idx));
                } else {
                    viewer_images_store.set_value(vec![image.clone()]);
                    viewer.set(Some(0));
                }
            }
        };

        let compute =
            move |sx: f64, sy: f64, ex: f64, ey: f64| -> Option<(Region, (f64, f64, f64, f64))> {
                let img = img_ref.get()?;
                let cont = container_ref.get()?;
                let irect = img.get_bounding_client_rect();
                let crect = cont.get_bounding_client_rect();
                let nat_w = img.natural_width() as f64;
                let nat_h = img.natural_height() as f64;
                if nat_w == 0.0 || nat_h == 0.0 {
                    return None;
                }
                let scale = (irect.width() / nat_w).min(irect.height() / nat_h);
                let disp_w = nat_w * scale;
                let disp_h = nat_h * scale;
                let off_x = irect.left() + (irect.width() - disp_w) / 2.0;
                let off_y = irect.top() + (irect.height() - disp_h) / 2.0;

                let to_img = |cx: f64, cy: f64| {
                    (
                        ((cx - off_x) / scale).clamp(0.0, nat_w),
                        ((cy - off_y) / scale).clamp(0.0, nat_h),
                    )
                };
                let (ix0, iy0) = to_img(sx, sy);
                let (ix1, iy1) = to_img(ex, ey);
                let x = ix0.min(ix1);
                let y = iy0.min(iy1);
                let w = (ix1 - ix0).abs();
                let h = (iy1 - iy0).abs();

                let lx = off_x + x * scale - crect.left();
                let ly = off_y + y * scale - crect.top();
                let lw = w * scale;
                let lh = h * scale;

                let region = Region {
                    x: x.round() as u32,
                    y: y.round() as u32,
                    w: w.round() as u32,
                    h: h.round() as u32,
                };
                Some((region, (lx, ly, lw, lh)))
            };

        let on_down = move |ev: PointerEvent| {
            if !ev.is_primary() || (ev.pointer_type() == "mouse" && ev.button() != 0) {
                return;
            }
            ev.prevent_default();
            if let Some(el) = overlay_ref.get() {
                let _ = el.set_pointer_capture(ev.pointer_id());
            }
            drag_origin.set(Some((ev.client_x() as f64, ev.client_y() as f64)));
        };

        let on_move = move |ev: PointerEvent| {
            if let Some((sx, sy)) = drag_origin.get()
                && let Some((_, lbox)) = compute(sx, sy, ev.client_x() as f64, ev.client_y() as f64)
            {
                sel_box.set(Some(lbox));
            }
        };

        let nav_up = navigate.clone();
        let open_zoom_click = open_zoom_at.clone();
        let on_up = move |ev: PointerEvent| {
            let Some((sx, sy)) = drag_origin.get() else {
                return;
            };
            drag_origin.set(None);

            let ex = ev.client_x() as f64;
            let ey = ev.client_y() as f64;
            let dist = ((ex - sx).powi(2) + (ey - sy).powi(2)).sqrt();

            if dist < 6.0 {
                sel_box.set(None);
                open_zoom_click(None);
                return;
            }

            if let Some((region, lbox)) = compute(sx, sy, ex, ey) {
                if region.w < 4 || region.h < 4 {
                    sel_box.set(None);
                    return;
                }
                sel_box.set(Some(lbox));

                if let Some(img) = img_ref.get()
                    && let Some(b64) = crop_to_base64(&img, region)
                {
                    let nonce = format!("{}", js_sys::Date::now() as u64);
                    img_query.0.set(Some(ImageQueryPayload {
                        nonce: nonce.clone(),
                        b64,
                    }));
                    let path = pathname.get_untracked();
                    nav_up(
                        &format!("{path}?mode=search_image&q={nonce}"),
                        Default::default(),
                    );
                } else {
                    sel_box.set(None);
                }
            } else {
                sel_box.set(None);
            }
        };

        let nav_clear = navigate.clone();
        let on_clear = move |_| {
            sel_box.set(None);
            let path = pathname.get_untracked();
            nav_clear(
                &format!("{path}?mode=similar&q={image_id}"),
                Default::default(),
            );
        };

        let open_zoom_btn = open_zoom_at.clone();
        let open_zoom_thumb = open_zoom_at;
        let on_copy_id = move |_| {
            #[cfg(feature = "hydrate")]
            {
                let next_gen = copy_gen.get_value().wrapping_add(1);
                copy_gen.set_value(next_gen);
                let text = image_id.to_string();
                spawn_local(async move {
                    if crate::util::copy_to_clipboard(&text).await
                        && copy_gen.try_get_value() == Some(next_gen)
                    {
                        let _ = copied_id.try_set(true);
                        set_timeout(
                            move || {
                                if copy_gen.try_get_value() == Some(next_gen) {
                                    let _ = copied_id.try_set(false);
                                }
                            },
                            std::time::Duration::from_millis(1500),
                        );
                    }
                });
            }
        };

        let album_badge = move || {
            let (Some(ic), Some(vc)) = (post_images_count.get(), post_videos_count.get()) else {
                return "Loading\u{2026}".to_string();
            };
            match (ic > 0, vc > 0) {
                (true, true) => format!("Album · {ic}p {vc}v \u{2922}"),
                (true, false) => format!("Album · {ic}p \u{2922}"),
                (false, true) => format!("Album · {vc}v \u{2922}"),
                (false, false) => "Album \u{2922}".to_string(),
            }
        };

        let seo_title = post
            .as_ref()
            .map(|p| p.title.clone())
            .unwrap_or_else(|| format!("Image #{image_id}"));
        let full_title = format!("{seo_title} \u{00B7} Let's Embed");
        let seo_description =
            build_detail_description(&seo_title, &authors, &tags, image_width, image_height);
        let origin = public_origin();
        let canonical_url = origin.as_ref().map(|o| format!("{o}/details/{image_id}"));
        let og_image_url = if og_image_allowed {
            origin
                .as_ref()
                .zip(clear_url.as_ref())
                .map(|(o, u)| format!("{o}{u}"))
        } else {
            None
        };

        let hero_stage = match image {
            ProjectedImage::Clear { url, name, .. } => {
                let alt = name
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| format!("Image #{image_id}"));
                let open_zoom_hero = open_zoom_btn.clone();
                view! {
                    <img
                        node_ref=img_ref
                        loading="lazy"
                        decoding="async"
                        class="max-w-full max-h-full object-contain select-none"
                        src=url
                        alt=alt
                    />
                    <div
                        node_ref=overlay_ref
                        class="absolute inset-0 cursor-crosshair touch-none select-none"
                        on:pointerdown=on_down
                        on:pointermove=on_move
                        on:pointerup=on_up
                        on:pointercancel=move |_| {
                            drag_origin.set(None);
                            sel_box.set(None);
                        }
                    />
                    {move || sel_box.get().map(|(l, t, w, h)| view! {
                        <div
                            class="absolute border-2 border-sky-400 bg-sky-400/20
                                    pointer-events-none rounded-sm"
                            style=format!("left:{l}px;top:{t}px;width:{w}px;height:{h}px;")
                        />
                    })}
                    {move || (sel_box.get().is_none() && drag_origin.get().is_none()).then(|| view! {
                        <div class="hidden sm:block absolute bottom-2 left-2 pointer-events-none px-2.5 py-1 rounded-full
                                    bg-slate-900/55 text-white/90 text-[11px] font-medium backdrop-blur-xs">
                            "Click to zoom · Drag to crop-search"
                        </div>
                    })}
                    <button
                        type="button"
                        title="View full screen"
                        class="absolute bottom-2 right-2 z-10 px-2.5 py-1 rounded-full
                               bg-slate-900/65 hover:bg-sky-500 text-white text-xs font-semibold
                               backdrop-blur-xs transition-colors cursor-pointer"
                        on:click=move |ev| {
                            ev.stop_propagation();
                            open_zoom_hero(None);
                        }
                    >
                        "Zoom \u{2922}"
                    </button>
                    {move || sel_box.get().map(|_| view! {
                        <button
                            type="button"
                            aria-label="Clear crop selection"
                            title="Clear crop selection"
                            class="absolute top-2 left-2 z-10 w-7 h-7 flex items-center justify-center
                                    rounded-full bg-black/60 text-white text-sm
                                    hover:bg-black/80 transition-colors cursor-pointer"
                            on:click=on_clear.clone()
                        >
                            "✕"
                        </button>
                    })}
                }
                .into_any()
            }
            ProjectedImage::Spoiler {
                preview_url,
                reveal_url,
                width: sw,
                height: sh,
                label,
                preset,
                blur_mode,
                ..
            } => {
                let ui_preset = GalleryMaskPreset::parse(&preset);
                let ui_blur = blur_mode_to_ui(blur_mode);
                let open_zoom_spoiler = open_zoom_btn.clone();
                let open_cb = Callback::new(move |()| open_zoom_spoiler(None));
                let alt = format!("Image #{image_id}");
                view! {
                    <div class="w-full h-full flex items-center justify-center p-2">
                        <div class="w-full max-w-[min(100%,640px)] max-h-full overflow-hidden rounded-xl">
                            {match panic_epoch_sig {
                                Some(epoch) => view! {
                                    <SpoilerOverlay
                                        id=image_id
                                        kind=GalleryMediaKind::Image
                                        width=sw
                                        height=sh
                                        preview_url=preview_url
                                        reveal_url=reveal_url
                                        alt=alt
                                        label=label
                                        preset=ui_preset
                                        blur_mode=ui_blur
                                        panic_epoch=epoch
                                        on_open=open_cb
                                    />
                                }
                                .into_any(),
                                None => view! {
                                    <SpoilerOverlay
                                        id=image_id
                                        kind=GalleryMediaKind::Image
                                        width=sw
                                        height=sh
                                        preview_url=preview_url
                                        reveal_url=reveal_url
                                        alt=alt
                                        label=label
                                        preset=ui_preset
                                        blur_mode=ui_blur
                                        on_open=open_cb
                                    />
                                }
                                .into_any(),
                            }}
                        </div>
                    </div>
                }
                .into_any()
            }
            ProjectedImage::Locked { mask, .. } => {
                let ui_mask = mask_to_ui(&mask);
                view! {
                    <div class="w-full h-full flex items-center justify-center p-4">
                        <div class="w-full max-w-md">
                            <ContentMaskCard
                                mask=ui_mask
                                dimensions=(image_width, image_height)
                                on_unlock_click=on_unlock
                            />
                        </div>
                    </div>
                }
                .into_any()
            }
        };

        view! {
            <Title text=full_title.clone()/>
            <Meta name="description" content=seo_description.clone()/>
            <Meta property="og:type" content="article"/>
            <Meta property="og:title" content=full_title/>
            <Meta property="og:description" content=seo_description/>
            {noindex.then(|| view! {
                <Meta name="robots" content="noindex, nofollow"/>
            })}
            {canonical_url.map(|url| view! {
                <Link rel="canonical" href=url.clone()/>
                <Meta property="og:url" content=url/>
            })}
            {og_image_url.map(|img_url| view! {
                <Meta property="og:image" content=img_url/>
                <Meta property="og:image:width" content=image_width.to_string()/>
                <Meta property="og:image:height" content=image_height.to_string()/>
            })}
            <div class="flex flex-col md:flex-row w-full gap-3 md:gap-4 p-3 md:p-4 md:h-[72vh]">
                <div
                    node_ref=container_ref
                    class="relative w-full h-[45vh] md:h-full md:flex-1 md:min-w-0 shrink-0
                            flex items-center justify-center bg-sky-100/70 ring-1 ring-sky-200 rounded-2xl overflow-hidden"
                >
                    {hero_stage}
                </div>

                <div class="w-full md:w-96 lg:w-[28rem] xl:w-[32rem] md:shrink-0
                            md:h-full flex flex-col gap-3 md:min-h-0">
                    {
                        post.map(|p| view! {
                            <button
                                type="button"
                                prop:disabled=move || !album_ready()
                                class="w-full flex items-center justify-between gap-2 text-left text-sky-800
                                       text-lg md:text-xl font-bold shrink-0 px-3 py-2 md:py-3
                                       bg-white/80 ring-1 ring-sky-200 shadow-sm shadow-sky-200/50
                                       rounded-2xl cursor-pointer hover:bg-white disabled:opacity-75 disabled:cursor-wait transition-colors"
                                title="Open full post album"
                                on:click=move |_| open_lightbox()
                            >
                                <h1 class="line-clamp-2 min-w-0 m-0 text-inherit font-inherit">{ p.title }</h1>
                                <span class="shrink-0 text-xs font-semibold px-2.5 py-1 rounded-full bg-sky-100 text-sky-700 whitespace-nowrap">
                                    {album_badge}
                                </span>
                            </button>
                        })
                    }

                    <div class="shrink-0 flex flex-col gap-2 px-3 py-2.5
                                bg-white/75 ring-1 ring-sky-100 rounded-2xl">
                        <div class="flex items-center justify-center flex-wrap gap-2">
                            <LikeButton kind="image" target_id=image_id show_label=true />
                            {
                                post_like_id.map(|post_id| view! {
                                    <LikeButton kind="post" target_id=post_id show_label=true />
                                })
                            }
                            <a
                                href="/user/favorites"
                                rel="external"
                                class="inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium
                                       text-sky-700 bg-sky-50 ring-1 ring-sky-200 hover:bg-sky-100 transition-colors"
                            >
                                "\u{2605} Favorites"
                            </a>
                            {move || safety.filter(|s| s.is_managed.get()).map(|s| view! {
                                <button
                                    type="button"
                                    title="Report content"
                                    class="inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium
                                           text-rose-700 bg-rose-50 ring-1 ring-rose-200 hover:bg-rose-100 transition-colors cursor-pointer"
                                    on:click=move |_| {
                                        s.open_report(
                                            ReportTargetKind::Image,
                                            image_id,
                                            format!("Image #{image_id}"),
                                        );
                                    }
                                >
                                    "Report"
                                </button>
                            })}
                        </div>
                        <div class="flex items-center justify-center flex-wrap gap-1.5 text-xs text-slate-500">
                            <button
                                type="button"
                                title="Copy image ID (for DINO search)"
                                class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-100
                                       hover:bg-sky-100 hover:text-sky-700 text-slate-600 font-mono transition-colors cursor-pointer"
                                on:click=on_copy_id
                            >
                                {move || if copied_id.get() {
                                    format!("\u{2713} Copied #{image_id}")
                                } else {
                                    format!("#{image_id}")
                                }}
                            </button>
                            {(image_width > 0 && image_height > 0).then(|| view! {
                                <span class="px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 tabular-nums">
                                    {format!("{image_width} × {image_height}")}
                                </span>
                            })}
                            {clear_url.filter(|_| !is_locked).map(|orig_href| view! {
                                <a
                                    href=orig_href
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    class="px-2 py-0.5 rounded-full bg-slate-100 hover:bg-sky-100 hover:text-sky-700
                                           text-slate-600 font-medium transition-colors"
                                >
                                    "Original \u{2197}"
                                </a>
                            })}
                        </div>
                    </div>

                    <div class="min-h-0 shrink flex flex-col gap-1.5 p-2.5 bg-white/75 ring-1 ring-sky-100 rounded-2xl">
                        {(tag_count > 0).then(|| view! {
                            <div class="flex items-center justify-between gap-2 px-0.5 text-[11px] text-sky-600/80">
                                <span>
                                    {move || if any_aliases && !show_inline_aliases.get() {
                                        format!("Tags ({tag_count}) · hover for aliases")
                                    } else {
                                        format!("Tags ({tag_count})")
                                    }}
                                </span>
                                {any_aliases.then(|| view! {
                                    <button
                                        type="button"
                                        aria-pressed=move || show_inline_aliases.get().to_string()
                                        class="px-2 py-0.5 rounded-full bg-sky-100/80 hover:bg-sky-200/80
                                               text-sky-700 font-medium transition-colors cursor-pointer"
                                        on:click=move |_| {
                                            close_tip_now();
                                            show_inline_aliases.update(|v| *v = !*v);
                                        }
                                    >
                                        {move || if show_inline_aliases.get() { "Hide aliases" } else { "Show aliases" }}
                                    </button>
                                })}
                            </div>
                        })}
                        {is_locked.then(|| view! {
                            <p class="text-xs text-slate-500 px-1 py-0.5 m-0">
                                "Tag metadata is hidden while this item is locked."
                            </p>
                        })}
                        {
                            let authors_store = StoredValue::new(authors);
                            let tags_store = StoredValue::new(tags);
                            move || if show_inline_aliases.get() {
                                view! {
                                    <div class="max-h-40 md:max-h-44 lg:max-h-48 min-h-0 overflow-y-auto overscroll-contain flex flex-col gap-1.5 pr-0.5">
                                        {authors_store.with_value(|list| {
                                            (!list.is_empty()).then(|| view! {
                                                <div class="flex flex-wrap gap-1.5">
                                                    {list.iter().map(|a| render_author_pill(a.name.clone())).collect_view()}
                                                </div>
                                            })
                                        })}
                                        {tags_store.with_value(|list| {
                                            list.iter().cloned().map(render_tag_alias_card).collect_view()
                                        })}
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div
                                        class="max-h-24 md:max-h-32 overflow-y-auto flex flex-wrap content-start gap-1.5"
                                        on:scroll=move |_| {
                                            if !pointer_in_tip.get_value() && !focus_in_tip.get_value() {
                                                close_tip_now();
                                            }
                                        }
                                    >
                                        {authors_store.with_value(|list| {
                                            list.iter().map(|a| render_author_pill(a.name.clone())).collect_view()
                                        })}
                                        {tags_store.with_value(|list| {
                                            list.iter().cloned().map(render_tag_pill).collect_view()
                                        })}
                                    </div>
                                }.into_any()
                            }
                        }
                    </div>

                    <div class="flex-1 min-h-0 md:min-h-[8.5rem] flex flex-row gap-2">
                        <Transition fallback=move || view! { <div class="flex-1 min-h-0" /> }>
                            {
                                let open_thumb = open_zoom_thumb.clone();
                                move || {
                                    let open_thumb = open_thumb.clone();
                                    post_images.get().and_then(|images| match images {
                                        Ok(images) if !images.is_empty() => Some(view! {
                                            <PostAlbumMasonry
                                                images=images
                                                current_image_id=image_id
                                                on_zoom=Callback::new(move |i| open_thumb(Some(i)))
                                            />
                                        }.into_any()),
                                        Ok(_) => None,
                                        Err(e) => Some(e.to_string().into_any()),
                                    })
                                }
                            }
                        </Transition>

                        <Transition fallback=|| ()>
                            {
                                move || {
                                    post_videos.get().and_then(|videos| match videos {
                                        Ok(videos) if !videos.is_empty() => Some(view! {
                                            <div class="flex-1 min-w-0 max-h-[40vh] overflow-y-auto md:max-h-none md:min-h-0 pr-1">
                                                <div class="flex flex-col gap-2">
                                                    {
                                                        videos.into_iter().map(|v| match v {
                                                            ProjectedVideo::Clear {
                                                                id: vid_id,
                                                                url,
                                                                width,
                                                                height,
                                                                duration,
                                                                ..
                                                            } => {
                                                                let aspect = if width > 0 && height > 0 {
                                                                    format!("aspect-ratio:{width}/{height};")
                                                                } else {
                                                                    "aspect-ratio:16/9;".to_string()
                                                                };
                                                                let dur = (duration > 0).then(|| format_duration(duration));
                                                                view! {
                                                                    <div class="relative group rounded-lg overflow-hidden bg-black">
                                                                        <video
                                                                            class="w-full block bg-black object-contain select-none"
                                                                            style=aspect
                                                                            controls
                                                                            playsinline
                                                                            preload="metadata"
                                                                            src=url
                                                                        />
                                                                        <div class="absolute top-1.5 right-1.5 z-10">
                                                                            <LikeButton
                                                                                kind="video"
                                                                                target_id=vid_id
                                                                                variant=LikeVariant::Card
                                                                            />
                                                                        </div>
                                                                        {dur.map(|d| view! {
                                                                            <span class="absolute top-1.5 left-1.5 z-10 pointer-events-none px-2 py-0.5 rounded-full bg-black/70 text-white text-[11px] font-medium tabular-nums">
                                                                                {d}
                                                                            </span>
                                                                        })}
                                                                    </div>
                                                                }
                                                                .into_any()
                                                            }
                                                            ProjectedVideo::Locked {
                                                                id: vid_id,
                                                                width,
                                                                height,
                                                                duration,
                                                                mask,
                                                            } => {
                                                                let dur = (duration > 0).then(|| format_duration(duration));
                                                                let ui_mask = mask_to_ui(&mask);
                                                                view! {
                                                                    <div class="relative group rounded-lg overflow-hidden bg-slate-900">
                                                                        <ContentMaskCard
                                                                            mask=ui_mask
                                                                            dimensions=(width, height)
                                                                            compact=true
                                                                            on_unlock_click=on_unlock
                                                                        />
                                                                        <div class="absolute top-1.5 right-1.5 z-10">
                                                                            <LikeButton
                                                                                kind="video"
                                                                                target_id=vid_id
                                                                                variant=LikeVariant::Card
                                                                            />
                                                                        </div>
                                                                        {dur.map(|d| view! {
                                                                            <span class="absolute top-1.5 left-1.5 z-10 pointer-events-none px-2 py-0.5 rounded-full bg-black/70 text-white text-[11px] font-medium tabular-nums">
                                                                                {d}
                                                                            </span>
                                                                        })}
                                                                    </div>
                                                                }
                                                                .into_any()
                                                            }
                                                        })
                                                        .collect_view()
                                                    }
                                                </div>
                                            </div>
                                        }.into_any()),
                                        Ok(_) => None,
                                        Err(e) => Some(e.to_string().into_any()),
                                    })
                                }
                            }
                        </Transition>
                    </div>
                </div>
            </div>
        }
    };

    let tag_tooltip_view = move || {
        hovered_tag.get().map(|tip| {
            let transform = if tip.below {
                "translate(-50%, 0)"
            } else {
                "translate(-50%, -100%)"
            };
            let bridge_cls = if tip.below { "fixed z-[45] pt-2" } else { "fixed z-[45] pb-2" };
            let style = format!("left:{:.1}px;top:{:.1}px;transform:{transform};", tip.x, tip.y);
            let canonical_href = tag_search_href(&tip.name);
            let dialog_label = format!("Aliases for {}", tip.name);
            let alias_count = tip.aliases.len();
            let alias_count_label = if alias_count == 1 {
                "1 alias".to_string()
            } else {
                format!("{alias_count} aliases")
            };
            view! {
                <div
                    id="tag-alias-tooltip"
                    role="dialog"
                    aria-label=dialog_label
                    style=style
                    class=bridge_cls
                    on:mouseenter=move |_| {
                        pointer_in_tip.set_value(true);
                        cancel_tip_close();
                    }
                    on:mouseleave=move |_| {
                        pointer_in_tip.set_value(false);
                        schedule_tip_close();
                    }
                    on:focusin=move |_| {
                        focus_in_tip.set_value(true);
                        cancel_tip_close();
                    }
                    on:focusout=move |_| {
                        focus_in_tip.set_value(false);
                        schedule_tip_close();
                    }
                >
                    <div class="w-72 max-w-[calc(100vw-1.5rem)] px-3 py-2.5 rounded-xl
                                bg-slate-900/95 text-white shadow-xl ring-1 ring-white/15 backdrop-blur-md">
                        <div class="flex items-center justify-between gap-2 text-xs">
                            <a
                                href=canonical_href
                                class="font-semibold text-sky-200 hover:text-white hover:underline truncate"
                                on:click=move |_| close_tip_now()
                            >
                                {tip.name}
                            </a>
                            <div class="flex items-center gap-1.5 shrink-0">
                                {(alias_count > 0).then(|| view! {
                                    <span class="text-[10px] text-slate-300/80 tabular-nums">
                                        {alias_count_label}
                                    </span>
                                })}
                                {tip.score_pct.map(|pct| view! {
                                    <span class="px-1.5 py-0.5 rounded-full bg-indigo-500/35 text-indigo-100 text-[10px] font-semibold tabular-nums">
                                        {format!("{pct}%")}
                                    </span>
                                })}
                            </div>
                        </div>
                        {if alias_count > 0 {
                            view! {
                                <div class="flex flex-wrap gap-1 mt-2 max-h-52 overflow-y-auto overscroll-contain pr-0.5">
                                    {tip.aliases.into_iter().map(|a| {
                                        let href = tag_search_href(&a);
                                        view! {
                                            <a
                                                href=href
                                                class="px-2 py-0.5 rounded-md bg-white/10 hover:bg-sky-500/80
                                                       text-slate-100 hover:text-white text-[11px] leading-snug
                                                       transition-colors cursor-pointer"
                                                on:click=move |_| close_tip_now()
                                            >
                                                {a}
                                            </a>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="text-[11px] text-slate-400 mt-1">
                                    "Click to search this tag"
                                </div>
                            }.into_any()
                        }}
                    </div>
                </div>
            }
        })
    };

    view! {
        <Transition fallback=move || view! { <div class="w-full h-[72vh]" /> }>
            {
                move || {
                    details.get().map(|details| match details {
                        Ok(details) => render_details(details).into_any(),
                        Err(e) => {
                            #[cfg(feature = "ssr")]
                            if let Some(resp) = use_context::<leptos_axum::ResponseOptions>() {
                                resp.set_status(axum::http::StatusCode::NOT_FOUND);
                            }
                            view! {
                                <Title text="Not Found · Let's Embed"/>
                                <Meta name="robots" content="noindex"/>
                                <div class="text-rose-500 p-4">{ e.to_string() }</div>
                            }.into_any()
                        }
                    })
                }
            }
        </Transition>
        {tag_tooltip_view}
        {lightbox_view}
        {viewer_view}
    }
}

#[server(endpoint = "fetch_image_details")]
async fn fetch_image_details(id: Option<String>) -> Result<ProjectedImageDetails, ServerFnError> {
    use crate::state::{AppState, RequestSafetyContext};
    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::{Engine, MediaOutcome};

    let id = id
        .and_then(|id| id.parse().ok())
        .ok_or::<ServerFnError>(ServerFnError::Args("invalid id".to_string()))?;

    let state = expect_context::<AppState>();
    let ctx = RequestSafetyContext::from_leptos_context(&state)?;
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    fn to_err(e: impl std::fmt::Display) -> ServerFnError {
        ServerFnError::Response(e.to_string())
    }

    let details = engine.image_details(id).await.map_err(to_err)?;
    let outcomes = engine
        .evaluate_images(&[id], &ctx.policy, &ctx.caller)
        .await
        .map_err(to_err)?;
    let outcome = outcomes
        .get(&id)
        .cloned()
        .unwrap_or(MediaOutcome::Clear {
            req_switchers: Vec::new(),
        });
    let projected = ctx
        .policy
        .project_image(&details.image, outcome.clone(), &ctx.caller, &ctx.signer);
    let is_locked = projected.is_locked();
    let public_safe_clear = !is_locked && outcome.is_public_safe_clear();
    let noindex = !public_safe_clear && ctx.policy.policy.legal.noindex_restricted;

    Ok(ProjectedImageDetails {
        image: projected,
        post: details.post,
        authors: details.authors,
        // Withhold restricted WD-tags & per-tag scores when image is locked (H5).
        tags: if is_locked { Vec::new() } else { details.tags },
        og_image_allowed: public_safe_clear,
        noindex,
    })
}

#[server(endpoint = "list_post_images")]
pub async fn list_post_images(post_id: i64) -> Result<Vec<ProjectedImage>, ServerFnError> {
    use crate::state::{AppState, RequestSafetyContext};
    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    fn to_err(e: impl std::fmt::Display) -> ServerFnError {
        ServerFnError::Response(e.to_string())
    }

    let state = expect_context::<AppState>();
    let ctx = RequestSafetyContext::from_leptos_context(&state)?;
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let raw = engine.list_post_images(post_id).await.map_err(to_err)?;
    engine
        .project_images(&raw, &ctx.policy, &ctx.caller, &ctx.signer)
        .await
        .map_err(to_err)
}

#[server(endpoint = "list_post_videos")]
pub async fn list_post_videos(post_id: i64) -> Result<Vec<ProjectedVideo>, ServerFnError> {
    use crate::state::{AppState, RequestSafetyContext};
    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    fn to_err(e: impl std::fmt::Display) -> ServerFnError {
        ServerFnError::Response(e.to_string())
    }

    let state = expect_context::<AppState>();
    let ctx = RequestSafetyContext::from_leptos_context(&state)?;
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let raw = engine.list_post_videos(post_id).await.map_err(to_err)?;
    engine
        .project_videos(&raw, &ctx.policy, &ctx.caller, &ctx.signer)
        .await
        .map_err(to_err)
}

#[cfg(test)]
mod tests {
    use super::tag_search_href;

    #[cfg(feature = "ssr")]
    #[test]
    fn pinned_paths() {
        use super::{FetchImageDetails, ListPostImages, ListPostVideos};
        use leptos::server_fn::ServerFn;
        assert_eq!(FetchImageDetails::PATH, "/api/fetch_image_details");
        assert_eq!(ListPostImages::PATH, "/api/list_post_images");
        assert_eq!(ListPostVideos::PATH, "/api/list_post_videos");
    }

    #[test]
    fn tag_links_use_advanced_query_syntax() {
        assert_eq!(tag_search_href("maid"), "/?mode=advanced&adv=tag%3Amaid");
        assert_eq!(
            tag_search_href("black hair"),
            "/?mode=advanced&adv=tag%3A%22black%20hair%22"
        );
    }
}
