use crate::{components::Viewer, types::PostItem, util::encode_path};
use leptos::prelude::*;
use leptos_use::use_intersection_observer;

const PAGE: usize = 20;

#[component]
pub fn Lightbox(post: PostItem, lightbox: RwSignal<Option<PostItem>>) -> impl IntoView {
    let total = post.images.len();
    let images = StoredValue::new(post.images);
    let videos = StoredValue::new(post.videos);
    let has_videos = !videos.with_value(|v| v.is_empty());
    let title = post.title;

    let visible = RwSignal::new(PAGE.min(total));
    let sentinel = NodeRef::<leptos::html::Div>::new();

    let viewer = RwSignal::new(None::<usize>);
    let viewer_open = Memo::new(move |_| viewer.get().is_some());

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
                        let url = format!("/videos/{}", encode_path(&v.name));
                        let aspect = if v.width > 0 && v.height > 0 {
                            format!("aspect-ratio:{}/{};", v.width, v.height)
                        } else {
                            "aspect-ratio:16/9;".to_string()
                        };
                        view! {
                            <video
                                class="w-full rounded bg-black object-contain select-none"
                                style=aspect
                                controls
                                playsinline
                                preload="metadata"
                                src=url
                            />
                        }
                    })
                    .collect::<Vec<_>>()
            })
        })
    };

    let render_images = move || {
        let v = visible.get();
        images.with_value(|imgs| {
            imgs.iter()
                .take(v)
                .enumerate()
                .map(|(i, im)| {
                    let url = format!("/images/{}.webp", encode_path(&im.name));
                    view! {
                        <div
                            class="relative aspect-square overflow-hidden rounded-xl bg-white/10 ring-1 ring-white/10"
                            style="content-visibility:auto;contain-intrinsic-size:240px 240px;"
                        >
                            <img
                                loading="lazy"
                                decoding="async"
                                class="absolute inset-0 w-full h-full object-cover cursor-zoom-in hover:scale-105 transition-transform duration-300"
                                src=url
                                on:click=move |_| viewer.set(Some(i))
                            />
                        </div>
                    }
                })
                .collect::<Vec<_>>()
        })
    };

    view! {
        <div
            class="fixed inset-0 bg-black/95 z-50 overflow-hidden cursor-zoom-out flex flex-col"
            on:click=move |ev| { ev.stop_propagation(); lightbox.set(None); }
        >
            <div class="sticky top-0 z-10 flex items-center justify-between px-4 py-2 bg-black/85 backdrop-blur text-white shrink-0 border-b border-sky-400/30">
                <div class="font-semibold truncate text-sky-100">{title}</div>
                <div class="flex items-center gap-4">
                    <div class="text-sm text-sky-200/70">
                        {move || format!("{} / {}", visible.get(), total)}
                    </div>
                    <button
                        class="px-3 py-1 rounded-full bg-sky-500/30 hover:bg-sky-500/60 text-sky-50 transition-colors"
                        on:click=move |_| lightbox.set(None)
                    >"Close"</button>
                </div>
            </div>

            <div
                class="flex-1 min-h-0 flex flex-col md:flex-row gap-2 p-2"
                on:click=move |ev| ev.stop_propagation()
            >
                <div class="flex-[2] min-w-0 overflow-y-auto overscroll-contain
                        scrollbar-thin scrollbar-thumb-sky-400/40 scrollbar-track-transparent">
                    <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-3 lg:grid-cols-4 gap-2">
                        {render_images}
                    </div>

                    <div node_ref=sentinel class="h-12 w-full"></div>

                    {move || (visible.get() >= total).then(|| view! {
                        <div class="text-sky-300/70 text-center pb-6">"\u{2014} \u{1f33f} \u{2014}"</div>
                    })}
                </div>

                {has_videos.then(|| view! {
                    <div class="flex-1 min-w-0 overflow-y-auto overscroll-contain
                            scrollbar-thin scrollbar-thumb-sky-400/40 scrollbar-track-transparent">
                        <div class="grid grid-cols-1 gap-2">
                            {render_videos}
                        </div>
                    </div>
                })}
            </div>
        </div>

        {move || viewer_open.get().then(|| view! {
            <Viewer images=images index=viewer />
        })}
    }
}
