use crate::components::Results;

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use search_types::ImageDetails as ImageDetailsData;
use urlencoding::encode;

#[component]
pub fn ImageDetails() -> impl IntoView {
    let params = use_params_map();
    let id = move || params.with(|p| p.get("id"));

    let details =
        OnceResource::new(
            async move { fetch_image_details(id()).await.map_err(|e| e.to_string()) },
        );

    let render_details = |ImageDetailsData { image, post, tags }| {
        let src = format!("/images/{}.webp", encode(&image.name));
        view! {
            <div class="w-full h-full">
                {
                    post.map(|post| view! {<div class="text-white text-2xl font-bold text-center">{ post.title }</div>})
                }
                <img
                    loading="lazy"
                    decoding="async"
                    class="flex-1 object-contain bg-gray-900 select-none"
                    src=src
                    alt=image.name
                />
            </div>
        }
    };

    view! {
        <div class="grid md:grid-cols-2 w-full h-full">
            <Transition fallback=move || "fetching image details".into_view()>
                {
                    move || {
                        details.get().map(|details|
                            match details {
                                Ok(details) => render_details(details).into_any(),
                                Err(e) => e.to_string().into_any(),
                            }
                        )
                    }
                }
            </Transition>
            <Results />
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
