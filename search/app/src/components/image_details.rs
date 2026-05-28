use crate::components::Results;

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use search_types::ImageDetails as ImageDetailsData;
use urlencoding::encode;

#[component]
pub fn ImageDetails() -> impl IntoView {
    let params = use_params_map();
    let id = move || params.with(|p| p.get("id"));

    let details = Resource::new(id, async |id| {
        fetch_image_details(id).await.map_err(|e| e.to_string())
    });

    view! {
        <div class="flex flex-col md:flex-row w-full h-full">
            <div class="flex w-full h-full justify-center items-center">
                <Transition fallback=move || "fetching image details".into_view()>
                    {
                        move || {
                            details.get().map(|details|
                                match details {
                                    Ok(details) => {
                                        let url = format!("/images/{}.webp", encode(&details.image.name));
                                        view! {
                                            <img
                                                loading="lazy"
                                                decoding="async"
                                                class="w-full h-full block bg-gray-900 cursor-zoom-in"
                                                src=url
                                            />
                                        }
                                        .into_any()
                                    }
                                    Err(e) => e.to_string().into_any(),
                                }
                            )
                        }
                    }
                </Transition>
            </div>
            <div class="w-full h-full">
                <Results />
            </div>
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
