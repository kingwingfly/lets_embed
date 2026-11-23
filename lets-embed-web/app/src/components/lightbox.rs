use crate::{
    components::{
        LikeButton, LikeVariant, Viewer,
        image_details::{list_post_images, list_post_videos},
    },
    types::{GalleryDensity, GalleryDensityState, PostItem, save_gallery_density},
    util::{
        encode_path, format_duration, layout_image_masonry, lock_body_scroll, navigate_from_modal,
        push_modal_history, trap_dialog_tab,
    },
};
use leptos::{ev, html, prelude::*};
use leptos_router::{NavigateOptions, hooks::use_navigate};
use leptos_use_element_size::{UseElementSizeReturn, use_element_size};
use leptos_use_event_listener::use_event_listener;
use leptos_use_intersection_observer::use_intersection_observer;
use search_types::{Image, PostMeta, Video};

const PAGE: usize = 20;

#[component]
pub fn Lightbox(post: PostItem, lightbox: RwSignal<Option<PostItem>>) -> impl IntoView {
    let post_id = post.id;
    let initial_img_len = post.images.len();
    let initial_vid_len = post.videos.len();
    let expected_img_count = post.image_count.max(initial_img_len);
    let expected_vid_count = post.video_count.max(initial_vid_len);
    let need_images = initial_img_len < expected_img_count;
    let need_videos = initial_vid_len < expected_vid_count;

    let images_sig: RwSignal<Vec<Image>> = RwSignal::new(post.images.clone());
    let viewer_images: StoredValue<Vec<Image>> = StoredValue::new(post.images);
    let videos_sig: RwSignal<Vec<Video>> = RwSignal::new(post.videos);
    let images_err: RwSignal<Option<String>> = RwSignal::new(None);
    let title = post.title;
    let navigate = use_navigate();
    let dialog_ref: NodeRef<html::Div> = NodeRef::new();
    lock_body_scroll();
    push_modal_history(move || lightbox.set(None));

    // Move keyboard focus into the dialog on mount.
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        if let Some(el) = dialog_ref.get() {
            let _ = el.focus();
        }
    });

    // Lazily load authors so users can pivot straight from a post album.
    let meta = OnceResource::new(async move { fetch_post_meta(post_id).await.ok() });

    // Lazily hydrate full album images/videos only when the PostItem only carries its cover.
    let full_images = need_images.then(|| {
        OnceResource::new(async move { list_post_images(post_id).await.map_err(|e| e.to_string()) })
    });
    let full_videos = need_videos.then(|| {
        OnceResource::new(async move { list_post_videos(post_id).await.map_err(|e| e.to_string()) })
    });

    let visible = RwSignal::new(PAGE.min(initial_img_len));
    let sentinel = NodeRef::<html::Div>::new();

    if let Some(res) = full_images {
        Effect::new(move |_| {
            if let Some(result) = res.get() {
                match result {
                    Ok(list) => {
                        let new_len = list.len();
                        viewer_images.set_value(list.clone());
                        images_sig.set(list);
                        images_err.set(None);
                        visible.update(|v| {
                            let target = PAGE.min(new_len);
                            if *v < target || *v > new_len {
                                *v = target;
                            }
                        });
                    }
                    Err(e) => {
                        images_err.set(Some(e));
                    }
                }
            }
        });
    }
    if let Some(res) = full_videos {
        Effect::new(move |_| {
            if let Some(Ok(list)) = res.get() {
                videos_sig.set(list);
            }
        });
    }

    let images_loading = move || full_images.is_some_and(|r| r.get().is_none());
    let total_images = move || {
        let loaded = images_sig.with(Vec::len);
        if images_loading() {
            expected_img_count.max(loaded)
        } else {
            loaded
        }
    };
    let has_videos = move || {
        !videos_sig.with(Vec::is_empty)
            || (full_videos.is_some_and(|r| r.get().is_none()) && expected_vid_count > 0)
    };

    let viewer = RwSignal::new(None::<usize>);
    let viewer_open = Memo::new(move |_| viewer.get().is_some());

    // Close the lightbox on Escape and trap Tab when the nested Viewer is not on top.
    let _ = use_event_listener(window(), ev::keydown, move |e| {
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
            lightbox.set(None);
        }
    });

    use_intersection_observer([sentinel], move |entries, _| {
        if !entries[0].is_intersecting() {
            return;
        }
        let cur = visible.get_untracked();
        let loaded_len = images_sig.with_untracked(Vec::len);
        if cur < loaded_len {
            visible.set((cur + PAGE).min(loaded_len));
        }
    });

    let render_videos = move || {
        videos_sig.with(|vids| {
            vids.iter()
                .map(|v| {
                    let vid_id = v.id;
                    let url = format!("/videos/{}", encode_path(&v.name));
                    let aspect = if v.width > 0 && v.height > 0 {
                        format!("aspect-ratio:{}/{};", v.width, v.height)
                    } else {
                        "aspect-ratio:16/9;".to_string()
                    };
                    let dur = (v.duration > 0).then(|| format_duration(v.duration));
                    let dims = (v.width > 0 && v.height > 0)
                        .then(|| format!("{}×{}", v.width, v.height));
                    view! {
                        <div class="relative group rounded-xl overflow-hidden bg-black ring-1 ring-white/10">
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
                            {(dur.is_some() || dims.is_some()).then(|| view! {
                                <div class="absolute top-1.5 left-1.5 z-10 pointer-events-none flex items-center gap-1">
                                    {dur.map(|d| view! {
                                        <span class="px-2 py-0.5 rounded-full bg-black/70 text-white text-[11px] font-medium tabular-nums">
                                            {d}
                                        </span>
                                    })}
                                    {dims.map(|dim| view! {
                                        <span class="px-2 py-0.5 rounded-full bg-black/60 text-sky-100/80 text-[11px] tabular-nums">
                                            {dim}
                                        </span>
                                    })}
                                </div>
                            })}
                        </div>
                    }
                })
                .collect::<Vec<_>>()
        })
    };

    let nav_meta = navigate.clone();
    let header_meta = move || {
        let nav_outer = nav_meta.clone();
        meta.get().flatten().and_then(|pm| {
            if pm.authors.is_empty() {
                return None;
            }
            Some(view! {
                <div class="flex flex-wrap items-center gap-1.5 mt-1">
                    {pm.authors.into_iter().map(|a| {
                        let href = format!("/?mode=author&q={}&limit=50", encode_path(&a.name));
                        let tip = format!("Search posts by {}", a.name);
                        let click_href = href.clone();
                        let nav = nav_outer.clone();
                        view! {
                            <a
                                href=href
                                title=tip
                                class="inline-flex items-center gap-0.5 px-2.5 py-0.5 rounded-full
                                       bg-sky-500/25 hover:bg-sky-500/50 text-sky-100 text-xs font-medium
                                       ring-1 ring-sky-400/35 transition-colors"
                                on:click=move |ev: ev::MouseEvent| {
                                    ev.stop_propagation();
                                    if !(ev.ctrl_key() || ev.meta_key() || ev.shift_key() || ev.alt_key() || ev.button() != 0) {
                                        ev.prevent_default();
                                        let nav = nav.clone();
                                        navigate_from_modal(
                                            click_href.clone(),
                                            move || lightbox.set(None),
                                            move |dest, replace| {
                                                nav(dest, NavigateOptions { replace, ..Default::default() });
                                            },
                                        );
                                    }
                                }
                            >
                                <span class="opacity-75">"@"</span>
                                <span>{a.name}</span>
                            </a>
                        }
                    }).collect_view()}
                </div>
            })
        })
    };

    let density = use_context::<GalleryDensityState>().unwrap_or_default().0;
    let render_density_btn = move |d: GalleryDensity, label: &'static str| {
        view! {
            <button
                type="button"
                class="gallery-density-btn"
                aria-pressed=move || (density.get() == d).to_string()
                on:click=move |_| {
                    density.set(d);
                    save_gallery_density(d);
                }
            >
                {label}
            </button>
        }
    };

    let album_scroll_el = NodeRef::<html::Div>::new();
    let UseElementSizeReturn {
        width: album_width, ..
    } = use_element_size(album_scroll_el);
    let col_count = Memo::new(move |_| {
        let cur_density = density.get();
        let measured = album_width.get();
        let w = if measured > 0.0 {
            measured
        } else {
            album_scroll_el
                .get_untracked()
                .map(|el| el.client_width() as f64)
                .unwrap_or(0.0)
        };
        cur_density.column_count(w)
    });
    let masonry_cols = Memo::new(move |_| {
        let v = visible.get();
        let cols = col_count.get();
        images_sig.with(|imgs| layout_image_masonry(&imgs[..v.min(imgs.len())], cols))
    });

    view! {
        <div
            node_ref=dialog_ref
            role="dialog"
            aria-modal="true"
            aria-label="Post album"
            tabindex="-1"
            class="fixed inset-0 h-dvh bg-black/95 z-50 overflow-hidden cursor-zoom-out flex flex-col outline-none"
            on:click=move |ev| { ev.stop_propagation(); lightbox.set(None); }
        >
            <div
                class="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-x-3 gap-y-2 px-3 sm:px-4 py-2 bg-black/85 backdrop-blur text-white shrink-0 border-b border-sky-400/30 cursor-default"
                on:click=|ev| ev.stop_propagation()
            >
                <div class="order-1 min-w-0 flex-1">
                    <div class="font-semibold truncate text-sky-100">{title}</div>
                    {header_meta}
                </div>
                {move || (total_images() > 0).then(|| view! {
                    <div class="order-3 md:order-2 w-full md:w-auto flex items-center justify-start md:justify-end">
                        <div class="gallery-density gallery-density-dark" role="group" aria-label="Grid size">
                            {render_density_btn(GalleryDensity::Compact, "Compact")}
                            {render_density_btn(GalleryDensity::Medium, "Medium")}
                            {render_density_btn(GalleryDensity::Large, "Large")}
                        </div>
                    </div>
                })}
                <div class="order-2 md:order-3 flex items-center gap-2 sm:gap-3 shrink-0">
                    <LikeButton
                        kind="post"
                        target_id=post_id
                        variant=LikeVariant::Overlay
                        show_label=true
                        hide_label_mobile=true
                    />
                    <div class="text-xs sm:text-sm text-sky-200/70 tabular-nums whitespace-nowrap">
                        {move || {
                            let tot = total_images();
                            format!("{} / {}", visible.get().min(tot), tot)
                        }}
                    </div>
                    <button
                        type="button"
                        aria-label="Close post"
                        class="px-3 py-1 rounded-full bg-sky-500/30 hover:bg-sky-500/60 text-sky-50 text-xs sm:text-sm font-medium transition-colors cursor-pointer"
                        on:click=move |_| lightbox.set(None)
                    >"Close"</button>
                </div>
            </div>

            <div
                class="flex-1 min-h-0 flex flex-col md:flex-row gap-2 p-2 cursor-default"
                on:click=move |ev| ev.stop_propagation()
            >
                <div
                    node_ref=album_scroll_el
                    class="flex-[2] min-w-0 overflow-y-auto overscroll-contain"
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
                                        masonry_cols
                                            .with(|cols| cols.get(col_idx).cloned().unwrap_or_default())
                                    }
                                    key=|(_, im)| im.id
                                    let((i, im))
                                >
                                    {
                                        let img_id = im.id;
                                        let url = format!("/images/{}.webp", encode_path(&im.name));
                                        let alt = im.name.clone();
                                        let href = format!("/details/{img_id}");
                                        let click_href = href.clone();
                                        let nav = use_navigate();
                                        let (w, h) = if im.width > 0 && im.height > 0 {
                                            (im.width, im.height)
                                        } else {
                                            (4, 3)
                                        };
                                        let aspect_style = format!("aspect-ratio:{w}/{h};");
                                        view! {
                                            <div class="relative group w-full overflow-hidden rounded-xl bg-white/10 ring-1 ring-white/10">
                                                <button
                                                    type="button"
                                                    aria-label=move || format!("Zoom image {} of {}", i + 1, total_images())
                                                    class="block w-full p-0 border-0 bg-transparent cursor-zoom-in focus-visible:outline-2 focus-visible:outline-sky-400"
                                                    style=aspect_style
                                                    on:click=move |_| {
                                                        viewer_images.set_value(images_sig.get_untracked());
                                                        viewer.set(Some(i));
                                                    }
                                                >
                                                    <img
                                                        loading="lazy"
                                                        decoding="async"
                                                        width=w
                                                        height=h
                                                        alt=alt
                                                        class="block w-full h-full object-cover group-hover:scale-[1.02] transition-transform duration-300"
                                                        src=url
                                                    />
                                                </button>
                                                <div class="absolute top-1.5 right-1.5 z-10">
                                                    <LikeButton
                                                        kind="image"
                                                        target_id=img_id
                                                        variant=LikeVariant::Card
                                                    />
                                                </div>
                                                <a
                                                    href=href
                                                    title="Open image details & similar"
                                                    class="absolute bottom-1.5 right-1.5 z-10 px-2 py-0.5 rounded-full
                                                           text-[11px] font-semibold bg-slate-900/75 hover:bg-sky-500
                                                           text-white backdrop-blur-xs opacity-0 group-hover:opacity-100
                                                           group-focus-within:opacity-100 touch-visible transition-opacity"
                                                    on:click=move |ev: ev::MouseEvent| {
                                                        ev.stop_propagation();
                                                        if !(ev.ctrl_key() || ev.meta_key() || ev.shift_key() || ev.alt_key() || ev.button() != 0) {
                                                            ev.prevent_default();
                                                            let nav = nav.clone();
                                                            navigate_from_modal(
                                                                click_href.clone(),
                                                                move || lightbox.set(None),
                                                                move |dest, replace| {
                                                                    nav(dest, NavigateOptions { replace, ..Default::default() });
                                                                },
                                                            );
                                                        }
                                                    }
                                                >
                                                    "Details \u{2197}"
                                                </a>
                                            </div>
                                        }
                                    }
                                </For>
                            </div>
                        </For>
                    </div>

                    <div node_ref=sentinel class="h-12 w-full"></div>

                    {move || images_loading().then(|| view! {
                        <div class="text-sky-300/80 text-center text-sm pb-6 animate-pulse">
                            "Loading album\u{2026}"
                        </div>
                    })}

                    {move || images_err.get().map(|err| view! {
                        <div class="text-rose-300 text-center text-xs pb-4 px-4">
                            {format!("Could not load full album: {err}")}
                        </div>
                    })}

                    {move || (!images_loading() && visible.get() >= images_sig.with(Vec::len)).then(|| view! {
                        <div class="text-sky-300/70 text-center pb-6">"\u{2014} \u{1f33f} \u{2014}"</div>
                    })}
                </div>

                {move || has_videos().then(|| view! {
                    <div class="flex-1 min-w-0 overflow-y-auto overscroll-contain">
                        <div class="grid grid-cols-1 gap-2">
                            {render_videos}
                        </div>
                    </div>
                })}
            </div>
        </div>

        {move || viewer_open.get().then(|| view! {
            <Viewer
                images=viewer_images
                index=viewer
                post_id=post_id
                on_navigate=Callback::new(move |_| lightbox.set(None))
            />
        })}
    }
}

#[server(endpoint = "fetch_post_meta")]
async fn fetch_post_meta(post_id: i64) -> Result<PostMeta, ServerFnError> {
    use crate::state::AppState;
    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    engine
        .post_meta(post_id)
        .await
        .map_err(|e| ServerFnError::Response(e.to_string()))
}

#[cfg(feature = "ssr")]
#[test]
fn pinned_path() {
    use leptos::server_fn::ServerFn;
    assert_eq!(FetchPostMeta::PATH, "/api/fetch_post_meta");
}
