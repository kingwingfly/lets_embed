//! Plain Axum route serving server-projected thumbnail metadata for the
//! `user_worker` favorites page (`GET /api/like_previews?items=post:12,image:34`).
//!
//! Projects EVERY image and video through `CompiledPolicy` BEFORE serialization:
//! - Clear items emit server-projected `url` (and `name` in Standalone Mode only).
//! - Spoiler items emit `preview_url`, `reveal_url`, `blur_mode`, `label`, `preset`.
//! - Locked items emit ZERO `name`, ZERO `url`, ZERO `preview_url`, ZERO `reveal_url`,
//!   while preserving `title`, `image_count`, `video_count`, and natural dimensions.

use std::collections::{HashMap, HashSet};

use app::state::{AppState, RequestSafetyContext};
use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use search_types::{BlurDeliveryMode, MaskMetadata, ProjectedImage, ProjectedVideo};
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
    pub kind: &'static str,
    /// The originally requested id (post_id for posts, image_id for images).
    pub target_id: i64,
    /// The image id to link to (`/details/{image_id}`). Absent for video-only posts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_id: Option<i64>,
    /// Raw image name — emitted ONLY for Clear images in Standalone Mode; ALWAYS omitted
    /// in Managed Mode and ALWAYS omitted for Locked / Spoiler items.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Server-projected clear URL (`/images/{name}.webp` in Standalone, `/media/image/{id}?cap=...` in Managed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Spoiler blurred preview URL (`/media/preview/{id}?cap=...` or clear preview).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_url: Option<String>,
    /// Spoiler reveal clear URL (`/media/image/{id}?cap=...` or standalone URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reveal_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blur_mode: Option<BlurDeliveryMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// True when the item is locked under the caller's safety policy (ZERO url/name/cap emitted).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<MaskMetadata>,
    pub width: i32,
    pub height: i32,
    /// Post title (omitted for single images).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Total image count for a post preview (omitted for single images).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_count: Option<usize>,
    /// Total video count for a post preview when > 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub video_count: Option<usize>,
}

pub(crate) fn preview_from_projected_image(
    kind: &'static str,
    target_id: i64,
    proj: &ProjectedImage,
    title: Option<String>,
    image_count: Option<usize>,
    video_count: Option<usize>,
) -> Preview {
    match proj {
        ProjectedImage::Clear {
            id,
            url,
            name,
            width,
            height,
        } => Preview {
            kind,
            target_id,
            image_id: Some(*id),
            name: name.clone(),
            url: Some(url.clone()),
            preview_url: None,
            reveal_url: None,
            blur_mode: None,
            label: None,
            preset: None,
            locked: false,
            mask: None,
            width: *width,
            height: *height,
            title,
            image_count,
            video_count,
        },
        ProjectedImage::Spoiler {
            id,
            preview_url,
            reveal_url,
            width,
            height,
            label,
            preset,
            blur_mode,
            ..
        } => Preview {
            kind,
            target_id,
            image_id: Some(*id),
            name: None,
            url: None,
            preview_url: Some(preview_url.clone()),
            reveal_url: Some(reveal_url.clone()),
            blur_mode: Some(*blur_mode),
            label: Some(label.clone()),
            preset: Some(preset.clone()),
            locked: false,
            mask: None,
            width: *width,
            height: *height,
            title,
            image_count,
            video_count,
        },
        ProjectedImage::Locked {
            id,
            width,
            height,
            mask,
        } => Preview {
            kind,
            target_id,
            image_id: Some(*id),
            name: None,
            url: None,
            preview_url: None,
            reveal_url: None,
            blur_mode: None,
            label: None,
            preset: None,
            locked: true,
            mask: Some(mask.clone()),
            width: *width,
            height: *height,
            title,
            image_count,
            video_count,
        },
    }
}

pub(crate) fn preview_from_projected_video_post(
    post_id: i64,
    vid: Option<&ProjectedVideo>,
    title: Option<String>,
    image_count: Option<usize>,
    video_count: Option<usize>,
) -> Preview {
    match vid {
        Some(ProjectedVideo::Locked {
            width,
            height,
            mask,
            ..
        }) => Preview {
            kind: "post",
            target_id: post_id,
            image_id: None,
            name: None,
            url: None,
            preview_url: None,
            reveal_url: None,
            blur_mode: None,
            label: None,
            preset: None,
            locked: true,
            mask: Some(mask.clone()),
            width: *width,
            height: *height,
            title,
            image_count,
            video_count,
        },
        Some(ProjectedVideo::Clear { width, height, .. }) => Preview {
            kind: "post",
            target_id: post_id,
            image_id: None,
            name: None,
            url: None,
            preview_url: None,
            reveal_url: None,
            blur_mode: None,
            label: None,
            preset: None,
            locked: false,
            mask: None,
            width: *width,
            height: *height,
            title,
            image_count,
            video_count,
        },
        None => Preview {
            kind: "post",
            target_id: post_id,
            image_id: None,
            name: None,
            url: None,
            preview_url: None,
            reveal_url: None,
            blur_mode: None,
            label: None,
            preset: None,
            locked: false,
            mask: None,
            width: 0,
            height: 0,
            title,
            image_count,
            video_count,
        },
    }
}

/// `GET /api/like_previews?items=post:12,image:34`
pub async fn like_previews(
    State(state): State<AppState>,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    Query(q): Query<PreviewsQuery>,
) -> Result<Json<Vec<Preview>>, StatusCode> {
    let ctx = match ctx_ext {
        Some(Extension(c)) => c,
        None if state.mode.is_managed() => return Err(StatusCode::FORBIDDEN),
        None => RequestSafetyContext::standalone(
            state.policy_store.current_standalone(),
            state.trust_proxy,
        ),
    };

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

    let engine = &state.engine;
    let (images, posts) = tokio::try_join!(
        engine.images_by_ids(&image_ids),
        engine.post_gallery_covers_by_ids(&post_ids),
    )
    .map_err(|e| {
        tracing::error!("like_previews query failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Deduplicate all images (standalone + post cover images) for a single batch projection.
    let mut all_images_map: HashMap<i64, search_types::Image> = HashMap::new();
    for im in &images {
        all_images_map.insert(im.id, im.clone());
    }
    for p in &posts {
        if let Some(im) = &p.cover_image {
            all_images_map.insert(im.id, im.clone());
        }
    }
    let all_images: Vec<search_types::Image> = all_images_map.into_values().collect();
    let cover_videos: Vec<search_types::Video> = posts
        .iter()
        .filter_map(|p| p.cover_video.clone())
        .collect();

    let (proj_images, proj_videos) = tokio::try_join!(
        engine.project_images(&all_images, &ctx.policy, &ctx.caller, &ctx.signer),
        engine.project_videos(&cover_videos, &ctx.policy, &ctx.caller, &ctx.signer),
    )
    .map_err(|e| {
        tracing::error!("like_previews projection failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let proj_img_map: HashMap<i64, ProjectedImage> =
        proj_images.into_iter().map(|im| (im.id(), im)).collect();
    let proj_vid_map: HashMap<i64, ProjectedVideo> =
        proj_videos.into_iter().map(|v| (v.id(), v)).collect();
    let post_map: HashMap<i64, _> = posts.into_iter().map(|p| (p.post_id, p)).collect();

    let previews = order
        .into_iter()
        .filter_map(|(kind, id)| match kind {
            "image" => {
                let proj = proj_img_map.get(&id)?;
                Some(preview_from_projected_image(
                    "image", id, proj, None, None, None,
                ))
            }
            _ => {
                let p = post_map.get(&id)?;
                let title = (!p.title.trim().is_empty()).then(|| p.title.clone());
                let image_count = (p.image_count > 0).then_some(p.image_count);
                let video_count = (p.video_count > 0).then_some(p.video_count);
                if let Some(cover) = p.cover_image.as_ref().and_then(|c| proj_img_map.get(&c.id)) {
                    Some(preview_from_projected_image(
                        "post",
                        id,
                        cover,
                        title,
                        image_count,
                        video_count,
                    ))
                } else {
                    let vid = p.cover_video.as_ref().and_then(|v| proj_vid_map.get(&v.id));
                    Some(preview_from_projected_video_post(
                        id,
                        vid,
                        title,
                        image_count,
                        video_count,
                    ))
                }
            }
        })
        .collect();

    Ok(Json(previews))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_preview_emits_zero_name_zero_url_zero_cap_while_preserving_counts() {
        let locked = ProjectedImage::Locked {
            id: 77,
            width: 1200,
            height: 1600,
            mask: MaskMetadata {
                rule_id: "r18".into(),
                label: "Adult 18+".into(),
                preset: "r18".into(),
                requires_login: true,
                requires_age: true,
                requires_terms: true,
            },
        };
        let p = preview_from_projected_image(
            "post",
            12,
            &locked,
            Some("My Album".into()),
            Some(9),
            Some(2),
        );
        let json = serde_json::to_string(&p).unwrap();
        assert!(p.locked);
        assert!(p.name.is_none());
        assert!(p.url.is_none());
        assert!(p.preview_url.is_none());
        assert!(p.reveal_url.is_none());
        assert!(!json.contains("\"name\""));
        assert!(!json.contains("\"url\""));
        assert!(!json.contains("cap="));
        assert!(json.contains("\"title\":\"My Album\""));
        assert!(json.contains("\"image_count\":9"));
        assert!(json.contains("\"video_count\":2"));
    }
}
