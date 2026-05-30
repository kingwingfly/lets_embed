use crate::{
    components::{Lightbox, Results, Viewer},
    types::{ImageItem, PostItem},
};

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use search_types::{Image, ImageDetails as ImageDetailsData};
use urlencoding::encode;

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
        list_post_images(post_id)
            .await
            .map_err(|e| e.to_string())
            .map(|images| {
                images
                    .into_iter()
                    .map(|image| ImageItem {
                        id: image.id,
                        name: image.name.clone(),
                        width: image.width as u32,
                        height: image.height as u32,
                    })
                    .collect::<Vec<_>>()
            })
    });

    let lightbox: RwSignal<Option<PostItem>> = RwSignal::new(None);
    let viewer: RwSignal<Option<ImageItem>> = RwSignal::new(None);

    let lightbox_view = move || {
        lightbox.get().map(|post| {
            view! {
                <Lightbox post lightbox viewer />
            }
        })
    };
    let viewer_view = move || {
        viewer.get().map(|image| {
            view! {
                <Viewer image viewer />
            }
        })
    };

    let render_pill = |name, mode, gradient| {
        let href = format!("/?mode={}&q={}&limit=50", mode, encode(name));
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
        view! {
            <div class="flex flex-col md:flex-row w-full gap-3 md:gap-4 p-3 md:p-4 md:h-[72vh]">
                <div class="w-full h-[45vh] md:h-full md:flex-1 md:min-w-0 shrink-0
                            flex items-center justify-center bg-black/30 rounded-lg overflow-hidden">
                    <img
                        loading="lazy"
                        decoding="async"
                        class="max-w-full max-h-full object-contain select-none"
                        src=format!("/images/{}.webp", encode(&image.name))
                        alt=image.name
                    />
                </div>

                <div class="w-full md:w-96 lg:w-[28rem] xl:w-[32rem] md:shrink-0
                            md:h-full flex flex-col gap-3 md:min-h-0">
                    {
                        post.map(|post| {
                            let post_item = post_images.get().map(|images| {
                                PostItem {
                                    id: post.id,
                                    title: post.title.clone(),
                                    images: images.unwrap_or_default()
                                }
                            });
                            view! {
                                <div class="text-white text-xl md:text-2xl font-bold text-center shrink-0
                                            px-3 py-2 md:py-3 bg-white/10 rounded-lg line-clamp-2 cursor-pointer"
                                    on:click=move |_| lightbox.set(post_item.clone())
                                >
                                    { post.title }
                                </div>
                            }
                        })
                    }

                    <div class="shrink-0 max-h-24 md:max-h-32 overflow-y-auto
                                flex flex-wrap content-start gap-2 p-2 bg-white/5 rounded-lg
                                scrollbar-thin scrollbar-thumb-white/20 scrollbar-track-transparent">
                        {
                            authors.into_iter().map(|author|
                                render_pill(&author.name, "author", "from-sky-500 to-cyan-500")
                            )
                            .collect_view()
                        }
                        {
                            tags.into_iter().map(|tag| {
                                render_pill(&tag.name, "tag", "from-indigo-500 to-purple-500")
                            })
                            .collect_view()
                        }
                    </div>

                    <Transition fallback=move || view! { <div class="flex-1 min-h-0" /> }>
                        {
                            move || {
                                post_images.get().map(|images| match images {
                                    Ok(images) => view! {
                                        <div class="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-2 lg:grid-cols-3
                                                gap-2 pr-1
                                                max-h-[40vh] overflow-y-auto
                                                md:max-h-none md:flex-1 md:min-h-0
                                                scrollbar-thin scrollbar-thumb-white/20 scrollbar-track-transparent">
                                            {
                                                images.into_iter().map(|image| view! {
                                                    <img
                                                        loading="lazy"
                                                        decoding="async"
                                                        class="w-full aspect-square object-cover rounded-md
                                                                select-none cursor-zoom-in
                                                                hover:opacity-80 hover:scale-[1.02]
                                                                transition-all"
                                                        src=format!("/images/{}.webp", encode(&image.name))
                                                        alt=image.name.clone()
                                                        on:click=move |_| viewer.set(Some(image.clone()))
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
                </div>
            </div>
        }
    };

    view! {
        <div class="w-full min-h-full flex flex-col">
            <Transition fallback=move || view! { <div class="w-full" style="height: 72vh;" /> }>
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
    use sanitize_filename::sanitize;
    use search_engine::Engine;

    let id = id
        .and_then(|id| id.parse().ok())
        .ok_or::<ServerFnError>(ServerFnError::Args("invalid id".to_string()))?;

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    engine
        .image_details(id)
        .await
        .map(|mut details| {
            details.image.name = sanitize(&details.image.name);
            details
        })
        .map_err(|e| ServerFnError::Response(e.to_string()))
}

#[server]
async fn list_post_images(post_id: i64) -> Result<Vec<Image>, ServerFnError> {
    use crate::state::AppState;

    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use sanitize_filename::sanitize;
    use search_engine::Engine;

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    engine
        .list_post_images(post_id)
        .await
        .map(|mut images| {
            images
                .iter_mut()
                .for_each(|image| image.name = sanitize(&image.name));
            images
        })
        .map_err(|e| ServerFnError::Response(e.to_string()))
}
