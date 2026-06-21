use crate::{
    components::{Lightbox, Results, Viewer},
    types::PostItem,
    util::encode_path,
};

use leptos::{ev::PointerEvent, html, prelude::*};
use leptos_router::hooks::{use_location, use_navigate, use_params_map};
use search_types::{Image, ImageDetails as ImageDetailsData, Video};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, HtmlImageElement};

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
    let id = Memo::new(move |_| params.with(|p| p.get("id")));

    let details =
        OnceResource::new(
            async move { fetch_image_details(id()).await.map_err(|e| e.to_string()) },
        );
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
    let post_images_store: StoredValue<Vec<Image>> = StoredValue::new(Vec::new());
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

    let lightbox_view = move || {
        lightbox
            .get()
            .map(|post| view! { <Lightbox post lightbox/> })
    };

    let viewer_view = move || {
        viewer_open.get().then(|| {
            view! { <Viewer images=post_images_store index=viewer /> }
        })
    };

    let render_pill = |name: String, mode, gradient| {
        let href = format!("/?mode={}&q={}&limit=50", mode, encode_path(name.as_str()));
        let class = format!(
            "inline-block px-3 py-1 text-xs md:text-sm font-medium text-white \
             bg-gradient-to-r {} \
             rounded-full shadow-sm whitespace-nowrap \
             hover:scale-[1.1] transition-transform cursor-pointer",
            gradient
        );
        view! {
            <a href=href>
                <span class=class>{ name }</span>
            </a>
        }
    };

    let render_details = move |ImageDetailsData {
                                   image,
                                   post,
                                   authors,
                                   tags,
                               }| {
        let image_id = image.id;

        let post_meta = post.as_ref().map(|p| (p.id, p.title.clone()));
        let post_store = StoredValue::new(post_meta);

        let open_lightbox = move || {
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
        let on_up = {
            let image = image.clone();
            move |ev: PointerEvent| {
                let Some((sx, sy)) = drag_origin.get() else {
                    return;
                };
                drag_origin.set(None);

                let ex = ev.client_x() as f64;
                let ey = ev.client_y() as f64;
                let dist = ((ex - sx).powi(2) + (ey - sy).powi(2)).sqrt();

                if dist < 6.0 {
                    let idx =
                        post_images_store.with_value(|v| v.iter().position(|im| im.id == image_id));
                    match idx {
                        Some(i) => viewer.set(Some(i)),
                        None => {
                            post_images_store.set_value(vec![image.clone()]);
                            viewer.set(Some(0));
                        }
                    }
                    return;
                };

                if let Some((region, lbox)) = compute(sx, sy, ex, ey) {
                    if region.w < 4 || region.h < 4 {
                        return;
                    }
                    sel_box.set(Some(lbox));

                    if let Some(img) = img_ref.get()
                        && let Some(q) = crop_to_base64(&img, region)
                    {
                        let path = pathname.get_untracked();
                        nav_up(
                            &format!("{path}?mode=search_image&q={q}"),
                            Default::default(),
                        );
                    }
                }
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

        view! {
            <div class="flex flex-col md:flex-row w-full gap-3 md:gap-4 p-3 md:p-4 md:h-[72vh]">
                <div
                    node_ref=container_ref
                    class="relative w-full h-[45vh] md:h-full md:flex-1 md:min-w-0 shrink-0
                            flex items-center justify-center bg-black/30 rounded-lg overflow-hidden"
                >
                    <img
                        node_ref=img_ref
                        loading="lazy"
                        decoding="async"
                        class="max-w-full max-h-full object-contain select-none"
                        src=format!("/images/{}.webp", encode_path(&image.name))
                        alt=image.name.clone()
                    />

                    <div
                        node_ref=overlay_ref
                        class="absolute inset-0 cursor-crosshair touch-none select-none"
                        on:pointerdown=on_down
                        on:pointermove=on_move
                        on:pointerup=on_up
                        on:pointercancel=move |_| { drag_origin.set(None); }
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
                        move || sel_box.get().map(|_| view! {
                            <button
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

                        view! {
                            <div class="text-white text-xl md:text-2xl font-bold text-center shrink-0
                                        px-3 py-2 md:py-3 bg-white/10 rounded-lg line-clamp-2 cursor-pointer"
                                on:click=move |_| open_lightbox()
                            >
                                { post.map(|p| p.title) }
                            </div>
                        }
                    }

                    <div class="shrink-0 max-h-24 md:max-h-32 overflow-y-auto
                                flex flex-wrap content-start gap-2 p-2 bg-white/5 rounded-lg
                                scrollbar-thin scrollbar-thumb-white/20 scrollbar-track-transparent">
                        {
                            authors.into_iter().map(|author|
                                render_pill(author.name, "author", "from-sky-500 to-cyan-500")
                            )
                            .collect_view()
                        }
                        {
                            tags.into_iter().map(|tag| {
                                render_pill(tag.name, "tag", "from-indigo-500 to-purple-500")
                            })
                            .collect_view()
                        }
                    </div>

                    <div class="flex-1 min-h-0 flex flex-row gap-2">
                        <Transition fallback=move || view! { <div class="flex-1 min-h-0" /> }>
                            {
                                move || {
                                    post_images.get().map(|images| match images {
                                        Ok(images) => view! {
                                            <div class="flex-[2] min-w-0 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-2 lg:grid-cols-3
                                                    gap-2 pr-1
                                                    max-h-[40vh] overflow-y-auto
                                                    md:max-h-none md:min-h-0
                                                    scrollbar-thin scrollbar-thumb-white/20 scrollbar-track-transparent">
                                                {
                                                    images.into_iter().enumerate().map(|(i, image)| view! {
                                                        <img
                                                            loading="lazy"
                                                            decoding="async"
                                                            class="w-full aspect-square object-cover rounded-md
                                                                    select-none cursor-zoom-in
                                                                    hover:opacity-80 hover:scale-[1.02]
                                                                    transition-all"
                                                            src=format!("/images/{}.webp", encode_path(&image.name))
                                                            alt=image.name.clone()
                                                            on:click=move |_| viewer.set(Some(i))
                                                        />
                                                    })
                                                    .collect_view()
                                                }
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
                                            <div class="flex-1 min-w-0 grid grid-cols-1
                                                    gap-2 pr-1
                                                    max-h-[40vh] overflow-y-auto
                                                    md:max-h-none md:min-h-0
                                                    scrollbar-thin scrollbar-thumb-white/20 scrollbar-track-transparent">
                                                {
                                                    videos.into_iter().map(|v| {
                                                        let aspect = if v.width > 0 && v.height > 0 {
                                                            format!("aspect-ratio:{}/{};", v.width, v.height)
                                                        } else {
                                                            "aspect-ratio:16/9;".to_string()
                                                        };
                                                        view! {
                                                            <video
                                                                class="w-full rounded-md bg-black object-contain select-none"
                                                                style=aspect
                                                                controls
                                                                playsinline
                                                                preload="metadata"
                                                                src=format!("/videos/{}", encode_path(&v.name))
                                                            />
                                                        }
                                                    })
                                                    .collect_view()
                                                }
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

    view! {
        <div class="w-full min-h-full flex flex-col">
            <Transition fallback=move || view! { <div class="w-full h-[72vh]" /> }>
                {
                    move || {
                        details.get().map(|details| match details {
                            Ok(details) => render_details(details).into_any(),
                            Err(e) => view! {
                                <div class="text-red-400 p-4">{ e.to_string() }</div>
                            }.into_any(),
                        })
                    }
                }
            </Transition>

            <div class="w-full px-3 md:px-4 pb-4 mt-2">
                <h2 class="text-white text-lg md:text-xl font-semibold mb-3">"Similar"</h2>
                <Results />
            </div>

            {lightbox_view}
            {viewer_view}
        </div>
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
