//! Plain axum route serving thumbnail metadata for the user_worker favorites
//! page. Given a comma-separated `kind:id` list, it resolves each post to its
//! cover image and each image to itself, returning just enough info to render a
//! thumbnail and link to `/details/{image_id}`.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use futures::future::join_all;
use search_engine::Engine;
use serde::{Deserialize, Serialize};

/// Cap on how many items a single request may ask about.
const MAX_ITEMS: usize = 100;

#[derive(Debug, Deserialize)]
pub struct PreviewsQuery {
    /// Comma-separated `kind:id` pairs, e.g. `post:12,image:34`.
    #[serde(default)]
    items: String,
}

#[derive(Debug, Serialize)]
pub struct Preview {
    /// `"post"` or `"image"` — echoes the requested kind so the client can
    /// match previews back to the originating like.
    kind: &'static str,
    /// The originally requested id (post_id for posts, image_id for images).
    target_id: i64,
    /// The image id to link to (`/details/{image_id}`). For posts this is the
    /// cover image; for images it equals `target_id`.
    image_id: i64,
    /// Image name — displayed as `/images/{name}.webp`.
    name: String,
    width: i32,
    height: i32,
}

/// `GET /api/like_previews?items=post:12,image:34`
pub async fn like_previews(
    State(engine): State<Arc<Engine>>,
    Query(q): Query<PreviewsQuery>,
) -> Json<Vec<Preview>> {
    // Parse `kind:id` pairs, skipping anything malformed, and cap the count.
    let requests: Vec<(&str, i64)> = q
        .items
        .split(',')
        .filter_map(|pair| {
            let (kind, id) = pair.split_once(':')?;
            let id: i64 = id.trim().parse().ok()?;
            match kind.trim() {
                "post" => Some(("post", id)),
                "image" => Some(("image", id)),
                _ => None, // videos and unknown kinds are omitted
            }
        })
        .take(MAX_ITEMS)
        .collect();

    let previews = join_all(requests.into_iter().map(|(kind, id)| {
        let engine = engine.clone();
        async move {
            match kind {
                "image" => {
                    let details = engine.image_details(id).await.ok()?;
                    let img = details.image;
                    Some(Preview {
                        kind: "image",
                        target_id: id,
                        image_id: img.id,
                        name: img.name,
                        width: img.width,
                        height: img.height,
                    })
                }
                // "post": cover = first image of the post.
                _ => {
                    let cover = engine.list_post_images(id).await.ok()?.into_iter().next()?;
                    Some(Preview {
                        kind: "post",
                        target_id: id,
                        image_id: cover.id,
                        name: cover.name,
                        width: cover.width,
                        height: cover.height,
                    })
                }
            }
        }
    }))
    .await
    .into_iter()
    .flatten()
    .collect();

    Json(previews)
}
