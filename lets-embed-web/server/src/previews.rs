//! Plain axum route serving thumbnail metadata for the user_worker favorites
//! page. Given a comma-separated `kind:id` list, it resolves each post to its
//! deterministic cover image + title + counts and each image to itself using
//! at most two set-based Postgres queries.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use search_engine::Engine;
use serde::{Deserialize, Serialize};

/// Cap on how many unique items a single request may ask about.
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
    /// cover image (absent for video-only posts); for images it equals `target_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    image_id: Option<i64>,
    /// Image name — displayed as `/images/{name}.webp` (absent for video-only posts).
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    width: i32,
    height: i32,
    /// Post title (omitted for single images).
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    /// Total image count for a post preview (omitted for single images).
    #[serde(skip_serializing_if = "Option::is_none")]
    image_count: Option<usize>,
    /// Total video count for a post preview when > 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    video_count: Option<usize>,
}

/// `GET /api/like_previews?items=post:12,image:34`
pub async fn like_previews(
    State(engine): State<Arc<Engine>>,
    Query(q): Query<PreviewsQuery>,
) -> Result<Json<Vec<Preview>>, StatusCode> {
    // Parse and deduplicate `kind:id` pairs, capping raw scan and unique count.
    let mut seen: HashSet<(&'static str, i64)> = HashSet::new();
    let mut order: Vec<(&'static str, i64)> = Vec::new();
    let mut image_ids: Vec<i64> = Vec::new();
    let mut post_ids: Vec<i64> = Vec::new();

    for pair in q.items.split(',').take(MAX_ITEMS * 2) {
        if order.len() >= MAX_ITEMS {
            break;
        }
        let Some((kind, id)) = pair.split_once(':') else {
            continue;
        };
        let Ok(id) = id.trim().parse::<i64>() else {
            continue;
        };
        let kind = match kind.trim() {
            "post" => "post",
            "image" => "image",
            _ => continue,
        };
        if seen.insert((kind, id)) {
            order.push((kind, id));
            if kind == "image" {
                image_ids.push(id);
            } else {
                post_ids.push(id);
            }
        }
    }

    if order.is_empty() {
        return Ok(Json(Vec::new()));
    }

    let (images, posts) = tokio::try_join!(
        engine.images_by_ids(&image_ids),
        engine.post_previews_by_ids(&post_ids),
    )
    .map_err(|e| {
        tracing::error!("like_previews query failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let image_map: HashMap<i64, _> = images.into_iter().map(|im| (im.id, im)).collect();
    let post_map: HashMap<i64, _> = posts.into_iter().map(|p| (p.post_id, p)).collect();

    let previews = order
        .into_iter()
        .filter_map(|(kind, id)| match kind {
            "image" => {
                let img = image_map.get(&id)?;
                Some(Preview {
                    kind: "image",
                    target_id: id,
                    image_id: Some(img.id),
                    name: Some(img.name.clone()),
                    width: img.width,
                    height: img.height,
                    title: None,
                    image_count: None,
                    video_count: None,
                })
            }
            _ => {
                let p = post_map.get(&id)?;
                let title = (!p.title.trim().is_empty()).then(|| p.title.clone());
                Some(Preview {
                    kind: "post",
                    target_id: id,
                    image_id: p.cover.as_ref().map(|c| c.id),
                    name: p.cover.as_ref().map(|c| c.name.clone()),
                    width: p.cover.as_ref().map(|c| c.width).unwrap_or(0),
                    height: p.cover.as_ref().map(|c| c.height).unwrap_or(0),
                    title,
                    image_count: (p.image_count > 0).then_some(p.image_count),
                    video_count: (p.video_count > 0).then_some(p.video_count),
                })
            }
        })
        .collect();

    Ok(Json(previews))
}
