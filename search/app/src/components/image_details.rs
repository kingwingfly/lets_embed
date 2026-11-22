use crate::{
    components::{Lightbox, LikeButton, LikeVariant, Results, Viewer},
    types::{ImageQuery, ImageQueryPayload, PostItem},
    util::{encode_path, format_duration, set_document_title},
};

#[cfg(feature = "hydrate")]
use leptos::{ev, task::spawn_local};
use leptos::{ev::PointerEvent, html, prelude::*};
use leptos_router::hooks::{use_location, use_navigate, use_params_map};
#[cfg(feature = "hydrate")]
use leptos_use_event_listener::use_event_listener;
use search_types::{Image, ImageDetails as ImageDetailsData, Tag, Video};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, HtmlImageElement};

/// Maximum number of aliases joined inline when "Show aliases" is toggled on.
const MAX_INLINE_ALIASES: usize = 6;

/// Interactive hover/focus popover state for a tag pill, rendered with `position: fixed`
/// so it is never clipped by the scrollable tag box and stays open when moving into it.
#[derive(Clone, Debug, PartialEq)]
struct TagTooltip {
    tag_id: i64,
    name: String,
    aliases: Vec<String>,
    score_pct: Option<u8>,
    /// Horizontal center in viewport pixels (clamped safely on render).
    x: f64,
    /// Anchor Y in viewport pixels (flush with pill edge; outer padding bridges the hover gap).
    y: f64,
    /// When true, anchor below the pill instead of above it.
    below: bool,
}

fn build_tag_tooltip(tag: &Tag, el: &web_sys::Element) -> TagTooltip {
    let rect = el.get_bounding_client_rect();
    let vw = web_sys::window()
        .and_then(|w| w.inner_width().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(1024.0);
    let x = (rect.left() + rect.width() / 2.0).clamp(156.0, (vw - 156.0).max(156.0));
    // Account for the sticky header height + scrollable popover height before flipping.
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

/// selected region in original image coordinate
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
    view! {
        <div class="w-full min-h-full flex flex-col">
            <For each=move || params.with(|p| p.get("id")) key=String::clone let(id)>
                <ImageDetailPage id />
            </For>
            <div class="w-full px-3 md:px-4 pb-4 mt-2">
                <h2 class="text-sky-700 text-lg md:text-xl font-semibold mb-3">"Similar \u{1f49e}"</h2>
                <Results embedded=true />
            </div>
        </div>
    }
}

#[component]
fn ImageDetailPage(id: String) -> impl IntoView {
    let img_query = expect_context::<ImageQuery>();

    let details = OnceResource::new(async move {
        fetch_image_details(Some(id))
            .await
            .map_err(|e| e.to_string())
    });
    let post_images = OnceResource::new(async move {
        let details = details.await?;
        let post_id = details
            .post
            .map(|p| p.id)
            .ok_or("this image belongs to no post".to_string())?;
        list_post_images(post_id).await.map_err(|e| e.to_string())
    });
    let post_videos = OnceResource::new(async move {
        let details = details.await?;
        let post_id = details
            .post
            .map(|p| p.id)
            .ok_or("this image belongs to no post".to_string())?;
        list_post_videos(post_id).await.map_err(|e| e.to_string())
    });

    let lightbox: RwSignal<Option<PostItem>> = RwSignal::new(None);
    let viewer: RwSignal<Option<usize>> = RwSignal::new(None);
    let current_post_id: RwSignal<Option<i64>> = RwSignal::new(None);
    let post_images_store: StoredValue<Vec<Image>> = StoredValue::new(Vec::new());
    // Dedicated snapshot handed to `<Viewer>` so zooming before `post_images` resolves
    // never overwrites `post_images_store`.
    let viewer_images_store: StoredValue<Vec<Image>> = StoredValue::new(Vec::new());

    Effect::new(move |_| {
        if let Some(Ok(d)) = details.get() {
            let page_title = d
                .post
                .as_ref()
                .map(|p| p.title.clone())
                .unwrap_or_else(|| format!("Image #{}", d.image.id));
            set_document_title(&page_title);
            current_post_id.set(d.post.map(|p| p.id));
        }
    });
    Effect::new(move |_| {
        if let Some(Ok(imgs)) = post_images.get() {
            post_images_store.set_value(imgs);
        }
    });
    let post_videos_store: StoredValue<Vec<Video>> = StoredValue::new(Vec::new());
    Effect::new(move |_| {
        if let Some(Ok(videos)) = post_videos.get() {
            post_videos_store.set_value(videos);
        }
    });
    let viewer_open = Memo::new(move |_| viewer.get().is_some());

    let img_ref: NodeRef<html::Img> = NodeRef::new();
    let container_ref: NodeRef<html::Div> = NodeRef::new();
    let overlay_ref: NodeRef<html::Div> = NodeRef::new();
    let drag_origin: RwSignal<Option<(f64, f64)>> = RwSignal::new(None);
    let sel_box: RwSignal<Option<(f64, f64, f64, f64)>> = RwSignal::new(None);

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

    // Dismiss the interactive tag popover on window scroll or Escape (WCAG 1.4.13).
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
        let href = format!("/?mode=tag&q={}&limit=50", urlencoding::encode(&tag.name));
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
                       bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full shadow-sm whitespace-nowrap
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
                <span>{ name }</span>
                {has_aliases.then(|| view! {
                    <span class="w-1.5 h-1.5 rounded-full bg-white/75 shrink-0" aria-hidden="true" />
                })}
            </a>
        }
    };

    let render_tag_alias_card = move |tag: Tag| {
        let href = format!("/?mode=tag&q={}&limit=50", urlencoding::encode(&tag.name));
        let score_pct = tag.score.map(|s| (s.clamp(0.0, 1.0) * 100.0).round() as u8);
        let aliases = StoredValue::new(tag.aliases);
        let total_aliases = aliases.with_value(Vec::len);
        let expanded = RwSignal::new(false);
        view! {
            <div class="rounded-xl bg-white/90 ring-1 ring-indigo-200/75 px-2.5 py-1.5 flex flex-col gap-1">
                <div class="flex items-center justify-between gap-2 min-w-0">
                    <a
                        href=href
                        class="text-xs md:text-sm font-semibold text-indigo-700 hover:text-sky-600 hover:underline truncate"
                    >
                        {tag.name}
                    </a>
                    <div class="flex items-center gap-1 shrink-0">
                        {(total_aliases > 0).then(|| view! {
                            <span class="text-[10px] text-slate-400 tabular-nums">
                                {total_aliases}
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
                    <div class="flex flex-wrap items-center gap-1">
                        {move || {
                            let is_open = expanded.get();
                            let limit = if is_open { total_aliases } else { MAX_INLINE_ALIASES };
                            let extra = total_aliases.saturating_sub(MAX_INLINE_ALIASES);
                            let items: Vec<String> = aliases.with_value(|v| {
                                v.iter().take(limit).cloned().collect()
                            });
                            view! {
                                {items.into_iter().map(|a| {
                                    let alias_href = format!("/?mode=tag&q={}&limit=50", urlencoding::encode(&a));
                                    view! {
                                        <a
                                            href=alias_href
                                            class="px-1.5 py-0.5 rounded-md bg-sky-50 hover:bg-sky-500 text-slate-700
                                                   hover:text-white ring-1 ring-sky-200/70 text-[11px] leading-snug
                                                   transition-colors"
                                        >
                                            {a}
                                        </a>
                                    }
                                }).collect_view()}
                                {(extra > 0).then(|| view! {
                                    <button
                                        type="button"
                                        class="px-1.5 py-0.5 rounded-md bg-indigo-50 hover:bg-indigo-100 text-indigo-600
                                               text-[11px] font-medium leading-snug transition-colors cursor-pointer"
                                        on:click=move |_| expanded.update(|v| *v = !*v)
                                    >
                                        {if is_open {
                                            "Show less".to_string()
                                        } else {
                                            format!("+{extra} more")
                                        }}
                                    </button>
                                })}
                            }
                        }}
                    </div>
                })}
            </div>
        }
    };

    let render_details = move |ImageDetailsData {
                                   image,
                                   post,
                                   authors,
                                   tags,
                               }| {
        let image_id = image.id;
        let image_width = image.width;
        let image_height = image.height;
        let original_src = format!("/images/{}.webp", encode_path(&image.name));
        let tag_count = tags.len();
        let any_aliases = tags.iter().any(|t| !t.aliases.is_empty());

        let post_meta = post.as_ref().map(|p| (p.id, p.title.clone()));
        let post_like_id = post_meta.as_ref().map(|(id, _)| *id);
        let post_store = StoredValue::new(post_meta);

        let album_ready = move || post_images.get().is_some() && post_videos.get().is_some();

        let open_lightbox = move || {
            if !album_ready() {
                return;
            }
            post_store.with_value(|m| {
                if let Some((id, title)) = m {
                    let images = post_images_store.with_value(|v| v.clone());
                    let videos = post_videos_store.with_value(|v| v.clone());
                    lightbox.set(Some(PostItem {
                        id: *id,
                        title: title.clone(),
                        images,
                        videos,
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
                        .or_else(|| imgs.iter().position(|im| im.id == image_id))
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
            // Only respond to primary pointer / left mouse button so context-menu
            // right-clicks, middle-clicks, and multi-touch pinch don't open Viewer.
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
            if !album_ready() {
                return "Loading\u{2026}".to_string();
            }
            let ic = post_images
                .get()
                .and_then(|r| r.ok())
                .map(|v| v.len())
                .unwrap_or(0);
            let vc = post_videos
                .get()
                .and_then(|r| r.ok())
                .map(|v| v.len())
                .unwrap_or(0);
            match (ic > 0, vc > 0) {
                (true, true) => format!("Album · {ic}p {vc}v \u{2922}"),
                (true, false) => format!("Album · {ic}p \u{2922}"),
                (false, true) => format!("Album · {vc}v \u{2922}"),
                (false, false) => "Album \u{2922}".to_string(),
            }
        };

        view! {
            <div class="flex flex-col md:flex-row w-full gap-3 md:gap-4 p-3 md:p-4 md:h-[72vh]">
                <div
                    node_ref=container_ref
                    class="relative w-full h-[45vh] md:h-full md:flex-1 md:min-w-0 shrink-0
                            flex items-center justify-center bg-sky-100/70 ring-1 ring-sky-200 rounded-2xl overflow-hidden"
                >
                    <img
                        node_ref=img_ref
                        loading="lazy"
                        decoding="async"
                        class="max-w-full max-h-full object-contain select-none"
                        src=original_src.clone()
                        alt=image.name.clone()
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

                    {
                        move || sel_box.get().map(|(l, t, w, h)| view! {
                            <div
                                class="absolute border-2 border-sky-400 bg-sky-400/20
                                        pointer-events-none rounded-sm"
                                style=format!("left:{l}px;top:{t}px;width:{w}px;height:{h}px;")
                            />
                        })
                    }

                    {
                        move || (sel_box.get().is_none() && drag_origin.get().is_none()).then(|| view! {
                            <div class="hidden sm:block absolute bottom-2 left-2 pointer-events-none px-2.5 py-1 rounded-full
                                        bg-slate-900/55 text-white/90 text-[11px] font-medium backdrop-blur-xs">
                                "Click to zoom · Drag to crop-search"
                            </div>
                        })
                    }

                    <button
                        type="button"
                        title="View full screen"
                        class="absolute bottom-2 right-2 z-10 px-2.5 py-1 rounded-full
                               bg-slate-900/65 hover:bg-sky-500 text-white text-xs font-semibold
                               backdrop-blur-xs transition-colors cursor-pointer"
                        on:click=move |ev| {
                            ev.stop_propagation();
                            open_zoom_btn(None);
                        }
                    >
                        "Zoom \u{2922}"
                    </button>

                    {
                        move || sel_box.get().map(|_| view! {
                            <button
                                type="button"
                                aria-label="Clear crop selection"
                                title="Clear crop selection"
                                class="absolute top-2 right-2 z-10 w-7 h-7 flex items-center justify-center
                                        rounded-full bg-black/60 text-white text-sm
                                        hover:bg-black/80 transition-colors cursor-pointer"
                                on:click=on_clear.clone()
                            >
                                "✕"
                            </button>
                        })
                    }
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
                                <span class="line-clamp-2 min-w-0">{ p.title }</span>
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
                            <a
                                href=original_src
                                target="_blank"
                                rel="noopener noreferrer"
                                class="px-2 py-0.5 rounded-full bg-slate-100 hover:bg-sky-100 hover:text-sky-700
                                       text-slate-600 font-medium transition-colors"
                            >
                                "Original \u{2197}"
                            </a>
                        </div>
                    </div>

                    <div class="shrink-0 flex flex-col gap-1.5 p-2.5 bg-white/75 ring-1 ring-sky-100 rounded-2xl">
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
                        {
                            let authors_store = StoredValue::new(authors);
                            let tags_store = StoredValue::new(tags);
                            move || if show_inline_aliases.get() {
                                view! {
                                    <div class="max-h-48 md:max-h-56 overflow-y-auto overscroll-contain flex flex-col gap-1.5 pr-0.5">
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

                    <div class="flex-1 min-h-0 flex flex-row gap-2">
                        <Transition fallback=move || view! { <div class="flex-1 min-h-0" /> }>
                            {
                                let open_thumb = open_zoom_thumb.clone();
                                move || {
                                    let open_thumb = open_thumb.clone();
                                    post_images.get().map(|images| match images {
                                        Ok(images) => view! {
                                            <div class="flex-[2] min-w-0 max-h-[40vh] overflow-y-auto md:max-h-none md:min-h-0 p-0.5 pr-1.5">
                                                <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-2 lg:grid-cols-3 gap-2 content-start">
                                                    {
                                                        images.into_iter().enumerate().map(|(i, image)| {
                                                            let open_thumb = open_thumb.clone();
                                                            let is_current = image.id == image_id;
                                                            let cls = if is_current {
                                                                "relative block w-full aspect-square p-0 border-0 rounded-lg overflow-hidden bg-sky-100 \
                                                                 cursor-zoom-in ring-2 ring-sky-400 hover:opacity-85 \
                                                                 hover:scale-[1.02] transition-all focus-visible:outline-2 focus-visible:outline-sky-500"
                                                            } else {
                                                                "relative block w-full aspect-square p-0 border-0 rounded-lg overflow-hidden bg-sky-100 \
                                                                 cursor-zoom-in hover:opacity-85 hover:scale-[1.02] \
                                                                 transition-all focus-visible:outline-2 focus-visible:outline-sky-500"
                                                            };
                                                            view! {
                                                                <button
                                                                    type="button"
                                                                    aria-label=format!("Zoom album image {}", i + 1)
                                                                    class=cls
                                                                    on:click=move |_| open_thumb(Some(i))
                                                                >
                                                                    <img
                                                                        loading="lazy"
                                                                        decoding="async"
                                                                        class="absolute inset-0 w-full h-full object-cover select-none"
                                                                        src=format!("/images/{}.webp", encode_path(&image.name))
                                                                        alt=image.name.clone()
                                                                    />
                                                                </button>
                                                            }
                                                        })
                                                        .collect_view()
                                                    }
                                                </div>
                                            </div>
                                        }.into_any(),
                                        Err(e) => e.to_string().into_any(),
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
                                                        videos.into_iter().map(|v| {
                                                            let vid_id = v.id;
                                                            let aspect = if v.width > 0 && v.height > 0 {
                                                                format!("aspect-ratio:{}/{};", v.width, v.height)
                                                            } else {
                                                                "aspect-ratio:16/9;".to_string()
                                                            };
                                                            let dur = (v.duration > 0).then(|| format_duration(v.duration));
                                                            view! {
                                                                <div class="relative group rounded-lg overflow-hidden bg-black">
                                                                    <video
                                                                        class="w-full block bg-black object-contain select-none"
                                                                        style=aspect
                                                                        controls
                                                                        playsinline
                                                                        preload="metadata"
                                                                        src=format!("/videos/{}", encode_path(&v.name))
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
            // Invisible outer padding bridges the gap between the tag pill and card
            // so moving the cursor into the popover never dismisses it.
            let bridge_cls = if tip.below { "fixed z-[45] pt-2" } else { "fixed z-[45] pb-2" };
            let style = format!("left:{:.1}px;top:{:.1}px;transform:{transform};", tip.x, tip.y);
            let canonical_href = format!("/?mode=tag&q={}&limit=50", urlencoding::encode(&tip.name));
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
                                        let href = format!("/?mode=tag&q={}&limit=50", urlencoding::encode(&a));
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
                        Err(e) => view! {
                            <div class="text-rose-500 p-4">{ e.to_string() }</div>
                        }.into_any(),
                    })
                }
            }
        </Transition>
        {tag_tooltip_view}
        {lightbox_view}
        {viewer_view}
    }
}

#[server]
async fn fetch_image_details(id: Option<String>) -> Result<ImageDetailsData, ServerFnError> {
    use crate::state::AppState;

    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    let id = id
        .and_then(|id| id.parse().ok())
        .ok_or::<ServerFnError>(ServerFnError::Args("invalid id".to_string()))?;

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    engine
        .image_details(id)
        .await
        .map_err(|e| ServerFnError::Response(e.to_string()))
}

#[server]
async fn list_post_images(post_id: i64) -> Result<Vec<Image>, ServerFnError> {
    use crate::state::AppState;

    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    engine
        .list_post_images(post_id)
        .await
        .map_err(|e| ServerFnError::Response(e.to_string()))
}

#[server]
async fn list_post_videos(post_id: i64) -> Result<Vec<Video>, ServerFnError> {
    use crate::state::AppState;

    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    engine
        .list_post_videos(post_id)
        .await
        .map_err(|e| ServerFnError::Response(e.to_string()))
}
