use crate::{
    components::{LikeButton, LikeVariant, Viewer},
    types::PostItem,
    util::{
        encode_path, format_duration, lock_body_scroll, prepare_modal_navigation,
        push_modal_history,
    },
};
use leptos::{ev, html, prelude::*};
use leptos_router::{NavigateOptions, hooks::use_navigate};
use leptos_use_event_listener::use_event_listener;
use leptos_use_intersection_observer::use_intersection_observer;
use search_types::PostMeta;

const PAGE: usize = 20;

#[component]
pub fn Lightbox(post: PostItem, lightbox: RwSignal<Option<PostItem>>) -> impl IntoView {
    let post_id = post.id;
    let total = post.images.len();
    let images = StoredValue::new(post.images);
    let videos = StoredValue::new(post.videos);
    let has_videos = !videos.with_value(|v| v.is_empty());
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

    let visible = RwSignal::new(PAGE.min(total));
    let sentinel = NodeRef::<html::Div>::new();

    let viewer = RwSignal::new(None::<usize>);
    let viewer_open = Memo::new(move |_| viewer.get().is_some());

    // Close the lightbox on Escape when the nested Viewer is not on top.
    let _ = use_event_listener(window(), ev::keydown, move |e| {
        if e.key() == "Escape"
            && !e.default_prevented()
            && !e.alt_key()
            && !e.ctrl_key()
            && !e.meta_key()
            && !viewer_open.get_untracked()
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
        if cur < total {
            visible.set((cur + PAGE).min(total));
        }
    });

    let render_videos = move || {
        has_videos.then(|| {
            videos.with_value(|vids| {
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
                                        let replace = prepare_modal_navigation();
                                        lightbox.set(None);
                                        nav(&click_href, NavigateOptions { replace, ..Default::default() });
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
                class="sticky top-0 z-10 flex items-center justify-between gap-3 px-4 py-2 bg-black/85 backdrop-blur text-white shrink-0 border-b border-sky-400/30 cursor-default"
                on:click=|ev| ev.stop_propagation()
            >
                <div class="min-w-0 flex-1">
                    <div class="font-semibold truncate text-sky-100">{title}</div>
                    {header_meta}
                </div>
                <div class="flex items-center gap-2 sm:gap-3 shrink-0">
                    <LikeButton
                        kind="post"
                        target_id=post_id
                        variant=LikeVariant::Overlay
                        show_label=true
                        hide_label_mobile=true
                    />
                    <div class="text-xs sm:text-sm text-sky-200/70 tabular-nums whitespace-nowrap">
                        {move || format!("{} / {}", visible.get(), total)}
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
                <div class="flex-[2] min-w-0 overflow-y-auto overscroll-contain">
                    <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-3 lg:grid-cols-4 gap-2">
                        <For
                            each=move || {
                                let v = visible.get();
                                images.with_value(|imgs| {
                                    imgs.iter().take(v).cloned().enumerate().collect::<Vec<_>>()
                                })
                            }
                            key=|(_, im)| im.id
                            let((i, im))
                        >
                            {
                                let img_id = im.id;
                                let url = format!("/images/{}.webp", encode_path(&im.name));
                                let alt = im.name.clone();
                                let href = format!("/details/{img_id}?mode=similar&q={img_id}&limit=50");
                                let click_href = href.clone();
                                let nav = use_navigate();
                                view! {
                                    <div
                                        class="relative group aspect-square overflow-hidden rounded-xl bg-white/10 ring-1 ring-white/10"
                                        style="content-visibility:auto;contain-intrinsic-size:240px 240px;"
                                    >
                                        <button
                                            type="button"
                                            aria-label=format!("Zoom image {} of {}", i + 1, total)
                                            class="absolute inset-0 w-full h-full p-0 border-0 bg-transparent cursor-zoom-in focus-visible:outline-2 focus-visible:outline-sky-400"
                                            on:click=move |_| viewer.set(Some(i))
                                        >
                                            <img
                                                loading="lazy"
                                                decoding="async"
                                                alt=alt
                                                class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
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
                                                    let replace = prepare_modal_navigation();
                                                    lightbox.set(None);
                                                    nav(&click_href, NavigateOptions { replace, ..Default::default() });
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

                    <div node_ref=sentinel class="h-12 w-full"></div>

                    {move || (visible.get() >= total).then(|| view! {
                        <div class="text-sky-300/70 text-center pb-6">"\u{2014} \u{1f33f} \u{2014}"</div>
                    })}
                </div>

                {has_videos.then(|| view! {
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
                images=images
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
