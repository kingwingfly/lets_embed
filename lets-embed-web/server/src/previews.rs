//! Plain Axum routes serving server-projected thumbnail & album metadata for
//! `user_worker`'s `/user/favorites` SPA:
//!
//! - `POST /api/like_previews` — primary JSON API (`{ posts, images, videos }` ->
//!   `{ posts: [{ post_id, title, image_count, video_count, cover }], images: [ProjectedImage], videos: [ProjectedVideo] }`)
//! - `GET /api/like_previews?items=post:12,image:34` — backwards-compatible flat array endpoint
//! - `GET /api/post_images?post_id=12` — full projected album details
//!   (`{ title, authors, images: [ProjectedImage], videos: [ProjectedVideo] }`)
//!
//! Every image and video is projected through `CompiledPolicy` BEFORE serialization:
//! locked items emit `"state": "locked"` with ZERO `name`, ZERO `url`, ZERO `cap`.

use std::collections::{HashMap, HashSet};

use app::state::{AppState, RequestSafetyContext};
use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use search_types::{MaskMetadata, PlaceholderPreset, ProjectedImage, ProjectedVideo};
use serde::{Deserialize, Serialize};

/// Cap on how many unique items a single request may ask about per kind.
const MAX_ITEMS: usize = 100;

fn resolve_ctx(
    state: &AppState,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
) -> Result<RequestSafetyContext, StatusCode> {
    match ctx_ext {
        Some(Extension(c)) => Ok(c),
        None if state.mode.is_managed() => Err(StatusCode::FORBIDDEN),
        None => Ok(RequestSafetyContext::standalone(
            state.policy_store.current_standalone(),
            state.trust_proxy,
        )),
    }
}

fn dedup_capped(ids: &[i64], cap: usize) -> Vec<i64> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for &id in ids {
        if out.len() >= cap {
            break;
        }
        if seen.insert(id) {
            out.push(id);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// POST /api/like_previews (primary favorites SPA wire contract)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct LikePreviewsPostBody {
    #[serde(default)]
    pub posts: Vec<i64>,
    #[serde(default)]
    pub images: Vec<i64>,
    #[serde(default)]
    pub videos: Vec<i64>,
}

#[derive(Debug, Serialize)]
pub struct PostPreviewItem {
    pub post_id: i64,
    pub title: String,
    pub image_count: usize,
    pub video_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cover: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct LikePreviewsPostResp {
    pub posts: Vec<PostPreviewItem>,
    pub images: Vec<ProjectedImage>,
    pub videos: Vec<ProjectedVideo>,
}

pub(crate) fn video_cover_json(video: &ProjectedVideo) -> Option<serde_json::Value> {
    let mut val = serde_json::to_value(video).ok()?;
    if let Some(obj) = val.as_object_mut() {
        obj.insert("kind".to_string(), serde_json::Value::String("video".into()));
    }
    Some(val)
}

pub(crate) fn build_post_preview_item(
    post_id: i64,
    title: String,
    image_count: usize,
    video_count: usize,
    cover_image: Option<&ProjectedImage>,
    cover_video: Option<&ProjectedVideo>,
) -> PostPreviewItem {
    let cover = if let Some(img) = cover_image {
        serde_json::to_value(img).ok()
    } else if let Some(vid) = cover_video {
        video_cover_json(vid)
    } else {
        None
    };
    PostPreviewItem {
        post_id,
        title,
        image_count,
        video_count,
        cover,
    }
}

/// `POST /api/like_previews` with JSON body `{"posts":[...],"images":[...],"videos":[...]}`.
pub async fn like_previews_post(
    State(state): State<AppState>,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    Json(body): Json<LikePreviewsPostBody>,
) -> Result<Json<LikePreviewsPostResp>, StatusCode> {
    let ctx = resolve_ctx(&state, ctx_ext)?;

    let post_ids = dedup_capped(&body.posts, MAX_ITEMS);
    let image_ids = dedup_capped(&body.images, MAX_ITEMS);
    let video_ids = dedup_capped(&body.videos, MAX_ITEMS);

    if post_ids.is_empty() && image_ids.is_empty() && video_ids.is_empty() {
        return Ok(Json(LikePreviewsPostResp {
            posts: Vec::new(),
            images: Vec::new(),
            videos: Vec::new(),
        }));
    }

    let engine = &state.engine;
    let (raw_images, raw_videos, raw_posts) = tokio::try_join!(
        engine.images_by_ids(&image_ids),
        engine.videos_by_ids(&video_ids),
        engine.post_gallery_covers_by_ids(&post_ids),
    )
    .map_err(|e| {
        tracing::error!("like_previews_post query failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Deduplicate all images (standalone + post covers) and all videos (standalone + post covers)
    // so safety evaluation & capability signing happen in two batched passes.
    let mut all_images_map: HashMap<i64, search_types::Image> = HashMap::new();
    for im in &raw_images {
        all_images_map.insert(im.id, im.clone());
    }
    for p in &raw_posts {
        if let Some(im) = &p.cover_image {
            all_images_map.insert(im.id, im.clone());
        }
    }
    let mut all_videos_map: HashMap<i64, search_types::Video> = HashMap::new();
    for v in &raw_videos {
        all_videos_map.insert(v.id, v.clone());
    }
    for p in &raw_posts {
        if let Some(v) = &p.cover_video {
            all_videos_map.insert(v.id, v.clone());
        }
    }

    let all_images: Vec<search_types::Image> = all_images_map.into_values().collect();
    let all_videos: Vec<search_types::Video> = all_videos_map.into_values().collect();

    let (proj_images, proj_videos) = tokio::try_join!(
        engine.project_images(&all_images, &ctx.policy, &ctx.caller, &ctx.signer),
        engine.project_videos(&all_videos, &ctx.policy, &ctx.caller, &ctx.signer),
    )
    .map_err(|e| {
        tracing::error!("like_previews_post projection failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let proj_img_map: HashMap<i64, ProjectedImage> =
        proj_images.into_iter().map(|im| (im.id(), im)).collect();
    let proj_vid_map: HashMap<i64, ProjectedVideo> =
        proj_videos.into_iter().map(|v| (v.id(), v)).collect();
    let post_map: HashMap<i64, _> = raw_posts.into_iter().map(|p| (p.post_id, p)).collect();

    // Only query full post media displayability for posts whose projected cover is hard-blocked / unclassified.
    let need_displayable_check: Vec<i64> = post_ids
        .iter()
        .copied()
        .filter(|pid| {
            let Some(p) = post_map.get(pid) else {
                return false;
            };
            let cover_displayable = p
                .cover_image
                .as_ref()
                .and_then(|c| proj_img_map.get(&c.id))
                .is_some_and(ProjectedImage::is_bypassable_or_clear)
                || p.cover_video
                    .as_ref()
                    .and_then(|v| proj_vid_map.get(&v.id))
                    .is_some_and(ProjectedVideo::is_bypassable_or_clear);
            !cover_displayable
        })
        .collect();
    let extra_displayable_posts = if need_displayable_check.is_empty() {
        HashSet::new()
    } else {
        engine
            .posts_with_any_displayable_media(&need_displayable_check, &ctx.policy, &ctx.caller)
            .await
            .map_err(|e| {
                tracing::error!("like_previews_post post displayability check failed: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    };

    let posts = post_ids
        .into_iter()
        .filter_map(|pid| {
            let p = post_map.get(&pid)?;
            let cover_img = p
                .cover_image
                .as_ref()
                .and_then(|c| proj_img_map.get(&c.id));
            let cover_vid = p
                .cover_video
                .as_ref()
                .and_then(|v| proj_vid_map.get(&v.id));
            let has_displayable = cover_img.is_some_and(ProjectedImage::is_bypassable_or_clear)
                || cover_vid.is_some_and(ProjectedVideo::is_bypassable_or_clear)
                || extra_displayable_posts.contains(&pid);
            let safe_title = if has_displayable {
                p.title.clone()
            } else {
                format!("Restricted Post #{pid}")
            };
            Some(build_post_preview_item(
                pid,
                safe_title,
                p.image_count,
                p.video_count,
                cover_img,
                cover_vid,
            ))
        })
        .collect();

    let images = image_ids
        .into_iter()
        .filter_map(|iid| proj_img_map.get(&iid).cloned())
        .collect();

    let videos = video_ids
        .into_iter()
        .filter_map(|vid| proj_vid_map.get(&vid).cloned())
        .collect();

    Ok(Json(LikePreviewsPostResp {
        posts,
        images,
        videos,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/post_images?post_id={id} (album lightbox contract for favorites SPA)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PostImagesQuery {
    pub post_id: i64,
}

#[derive(Debug, Serialize)]
pub struct PostImagesResp {
    pub title: String,
    pub authors: Vec<String>,
    pub images: Vec<ProjectedImage>,
    pub videos: Vec<ProjectedVideo>,
}

/// `GET /api/post_images?post_id={id}` — returns projected album title, authors,
/// images, and videos matching `user_worker/web/src/pages/favorites.rs`.
pub async fn post_images(
    State(state): State<AppState>,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    Query(q): Query<PostImagesQuery>,
) -> Result<Json<PostImagesResp>, StatusCode> {
    let ctx = resolve_ctx(&state, ctx_ext)?;
    let engine = &state.engine;

    let (title_opt, meta, raw_images, raw_videos) = tokio::try_join!(
        engine.post_title_by_id(q.post_id),
        engine.post_meta(q.post_id),
        engine.list_post_images(q.post_id),
        engine.list_post_videos(q.post_id),
    )
    .map_err(|e| {
        tracing::error!(post_id = q.post_id, "post_images query failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some(title) = title_opt else {
        return Err(StatusCode::NOT_FOUND);
    };

    let (images, videos) = tokio::try_join!(
        engine.project_images(&raw_images, &ctx.policy, &ctx.caller, &ctx.signer),
        engine.project_videos(&raw_videos, &ctx.policy, &ctx.caller, &ctx.signer),
    )
    .map_err(|e| {
        tracing::error!(post_id = q.post_id, "post_images projection failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let has_any_displayable = images.iter().any(ProjectedImage::is_bypassable_or_clear)
        || videos.iter().any(ProjectedVideo::is_bypassable_or_clear);
    let (safe_title, safe_authors) = if has_any_displayable {
        (
            title,
            meta.authors.into_iter().map(|a| a.name).collect(),
        )
    } else {
        (format!("Restricted Post #{}", q.post_id), Vec::new())
    };

    Ok(Json(PostImagesResp {
        title: safe_title,
        authors: safe_authors,
        images,
        videos,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/like_previews?items=post:12,image:34 (legacy backwards-compat)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PreviewsQuery {
    /// Comma-separated `kind:id` pairs, e.g. `post:12,image:34`.
    #[serde(default)]
    items: String,
}

#[derive(Debug, Serialize)]
pub struct Preview {
    pub kind: &'static str,
    pub target_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_url: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub blurred: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_click_reveal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_rev: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<PlaceholderPreset>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<MaskMetadata>,
    pub width: i32,
    pub height: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_count: Option<usize>,
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
            blurred: false,
            can_click_reveal: false,
            policy_rev: None,
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
        ProjectedImage::Blurred {
            id,
            preview_url,
            can_click_reveal,
            policy_rev,
            label,
            preset,
            width,
            height,
            ..
        } => Preview {
            kind,
            target_id,
            image_id: Some(*id),
            name: None,
            url: None,
            preview_url: preview_url.clone(),
            blurred: true,
            can_click_reveal: *can_click_reveal,
            policy_rev: Some(*policy_rev),
            label: Some(label.clone()),
            preset: Some(*preset),
            locked: false,
            mask: None,
            width: *width,
            height: *height,
            title,
            image_count,
            video_count,
        },
        ProjectedImage::Placeholder {
            id,
            policy_rev,
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
            blurred: false,
            can_click_reveal: false,
            policy_rev: Some(*policy_rev),
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
        Some(ProjectedVideo::Placeholder {
            policy_rev,
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
            blurred: false,
            can_click_reveal: false,
            policy_rev: Some(*policy_rev),
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
        Some(ProjectedVideo::Blurred {
            preview_url,
            can_click_reveal,
            policy_rev,
            label,
            preset,
            width,
            height,
            ..
        }) => Preview {
            kind: "post",
            target_id: post_id,
            image_id: None,
            name: None,
            url: None,
            preview_url: preview_url.clone(),
            blurred: true,
            can_click_reveal: *can_click_reveal,
            policy_rev: Some(*policy_rev),
            label: Some(label.clone()),
            preset: Some(*preset),
            locked: false,
            mask: None,
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
            blurred: false,
            can_click_reveal: false,
            policy_rev: None,
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
            blurred: false,
            can_click_reveal: false,
            policy_rev: None,
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
    let ctx = resolve_ctx(&state, ctx_ext)?;

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

    let need_displayable_check: Vec<i64> = post_ids
        .iter()
        .copied()
        .filter(|pid| {
            let Some(p) = post_map.get(pid) else {
                return false;
            };
            let cover_displayable = p
                .cover_image
                .as_ref()
                .and_then(|c| proj_img_map.get(&c.id))
                .is_some_and(ProjectedImage::is_bypassable_or_clear)
                || p.cover_video
                    .as_ref()
                    .and_then(|v| proj_vid_map.get(&v.id))
                    .is_some_and(ProjectedVideo::is_bypassable_or_clear);
            !cover_displayable
        })
        .collect();
    let extra_displayable_posts = if need_displayable_check.is_empty() {
        HashSet::new()
    } else {
        engine
            .posts_with_any_displayable_media(&need_displayable_check, &ctx.policy, &ctx.caller)
            .await
            .map_err(|e| {
                tracing::error!("like_previews post displayability check failed: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    };

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
                let cover_img = p.cover_image.as_ref().and_then(|c| proj_img_map.get(&c.id));
                let cover_vid = p.cover_video.as_ref().and_then(|v| proj_vid_map.get(&v.id));
                let has_displayable = cover_img.is_some_and(ProjectedImage::is_bypassable_or_clear)
                    || cover_vid.is_some_and(ProjectedVideo::is_bypassable_or_clear)
                    || extra_displayable_posts.contains(&id);
                let title = if has_displayable {
                    (!p.title.trim().is_empty()).then(|| p.title.clone())
                } else {
                    Some(format!("Restricted Post #{id}"))
                };
                let image_count = (p.image_count > 0).then_some(p.image_count);
                let video_count = (p.video_count > 0).then_some(p.video_count);
                if let Some(cover) = cover_img {
                    Some(preview_from_projected_image(
                        "post",
                        id,
                        cover,
                        title,
                        image_count,
                        video_count,
                    ))
                } else {
                    Some(preview_from_projected_video_post(
                        id,
                        cover_vid,
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

    fn sample_mask() -> MaskMetadata {
        MaskMetadata {
            policy_id: "r18".into(),
            matched_policy_ids: vec!["r18".into()],
            label: "Adult 18+".into(),
            preset: PlaceholderPreset::R18,
            requires_login: true,
            requires_age: true,
            requires_terms: true,
        }
    }

    #[test]
    fn placeholder_and_blurred_previews_never_emit_clear_urls_or_reveal_urls() {
        let placeholder = ProjectedImage::Placeholder {
            id: 77,
            policy_rev: 4,
            width: 1200,
            height: 1600,
            mask: sample_mask(),
        };
        let p = preview_from_projected_image(
            "post",
            12,
            &placeholder,
            Some("My Album".into()),
            Some(9),
            Some(2),
        );
        let json = serde_json::to_string(&p).unwrap();
        assert!(p.locked);
        assert!(p.name.is_none());
        assert!(p.url.is_none());
        assert!(p.preview_url.is_none());
        assert!(!json.contains("\"name\""));
        assert!(!json.contains("\"url\""));
        assert!(!json.contains("reveal_url"));
        assert!(!json.contains("cap="));
        assert!(json.contains("\"title\":\"My Album\""));
        assert!(json.contains("\"image_count\":9"));
        assert!(json.contains("\"video_count\":2"));

        let blurred = ProjectedImage::Blurred {
            id: 78,
            preview_url: Some("/media/preview/78?cap=mc3.prev".into()),
            can_click_reveal: true,
            policy_rev: 4,
            matched_policy_ids: vec!["sensitive".into()],
            label: "Suggestive".into(),
            preset: PlaceholderPreset::Sensitive,
            width: 800,
            height: 1000,
        };
        let bp = preview_from_projected_image("image", 78, &blurred, None, None, None);
        let bp_json = serde_json::to_string(&bp).unwrap();
        assert!(bp.blurred);
        assert!(bp.can_click_reveal);
        assert_eq!(bp.policy_rev, Some(4));
        assert!(bp.url.is_none());
        assert!(!bp_json.contains("\"url\""));
        assert!(!bp_json.contains("reveal_url"));
    }

    #[test]
    fn post_like_previews_and_post_images_match_policy_v3_wire_contract() {
        let placeholder_img = ProjectedImage::Placeholder {
            id: 501,
            policy_rev: 7,
            width: 1000,
            height: 1500,
            mask: sample_mask(),
        };
        let blurred_img = ProjectedImage::Blurred {
            id: 503,
            preview_url: Some("/media/preview/503?cap=mc3.prev".into()),
            can_click_reveal: true,
            policy_rev: 7,
            matched_policy_ids: vec!["sensitive".into()],
            label: "Suggestive".into(),
            preset: PlaceholderPreset::Sensitive,
            width: 800,
            height: 600,
        };
        let clear_img = ProjectedImage::Clear {
            id: 502,
            url: "/media/image/502?cap=mc3.tok1".into(),
            name: None,
            width: 800,
            height: 600,
        };
        let blurred_vid = ProjectedVideo::Blurred {
            id: 901,
            preview_url: None,
            can_click_reveal: true,
            policy_rev: 7,
            matched_policy_ids: vec!["sensitive".into()],
            label: "Suggestive".into(),
            preset: PlaceholderPreset::Sensitive,
            width: 1920,
            height: 1080,
            duration: 30,
        };

        let post_item = build_post_preview_item(
            12,
            "Locked Album".into(),
            5,
            1,
            Some(&placeholder_img),
            None,
        );
        let vid_only_post = build_post_preview_item(
            13,
            "Blurred Video".into(),
            0,
            1,
            None,
            Some(&blurred_vid),
        );

        let resp = LikePreviewsPostResp {
            posts: vec![post_item, vid_only_post],
            images: vec![clear_img.clone(), blurred_img.clone(), placeholder_img.clone()],
            videos: vec![blurred_vid.clone()],
        };
        let val = serde_json::to_value(&resp).unwrap();

        // Post 12 cover has tagged `"state":"placeholder"` and zero url/name/cap.
        let p0 = &val["posts"][0];
        assert_eq!(p0["post_id"], 12);
        assert_eq!(p0["title"], "Locked Album");
        assert_eq!(p0["image_count"], 5);
        assert_eq!(p0["video_count"], 1);
        assert_eq!(p0["cover"]["state"], "placeholder");
        assert!(p0["cover"].get("url").is_none());
        assert!(p0["cover"].get("name").is_none());

        // Video-only Post 13 cover preserves `"kind":"video"` and `"state":"blurred"` (NEVER Clear!).
        let p1 = &val["posts"][1];
        assert_eq!(p1["cover"]["kind"], "video");
        assert_eq!(p1["cover"]["state"], "blurred");
        assert_eq!(p1["cover"]["can_click_reveal"], true);
        assert!(p1["cover"].get("url").is_none());
        assert!(p1["cover"].get("reveal_url").is_none());

        // Standalone images & videos use tagged `state` with ZERO pre-minted `reveal_url`.
        assert_eq!(val["images"][0]["state"], "clear");
        assert_eq!(val["images"][0]["url"], "/media/image/502?cap=mc3.tok1");
        assert_eq!(val["images"][1]["state"], "blurred");
        assert_eq!(val["images"][1]["can_click_reveal"], true);
        assert!(val["images"][1].get("url").is_none());
        assert!(val["images"][1].get("reveal_url").is_none());
        assert_eq!(val["images"][2]["state"], "placeholder");
        assert!(val["images"][2].get("url").is_none());
        assert_eq!(val["videos"][0]["state"], "blurred");
        assert!(val["videos"][0].get("url").is_none());
        assert!(val["videos"][0].get("reveal_url").is_none());

        // GET /api/post_images response matches `{title, authors, images, videos}`.
        let album = PostImagesResp {
            title: "Album Title".into(),
            authors: vec!["Artist A".into()],
            images: vec![clear_img, blurred_img, placeholder_img],
            videos: vec![blurred_vid],
        };
        let album_val = serde_json::to_value(&album).unwrap();
        assert_eq!(album_val["title"], "Album Title");
        assert_eq!(album_val["authors"][0], "Artist A");
        assert_eq!(album_val["images"][1]["state"], "blurred");
        assert!(album_val["images"][1].get("reveal_url").is_none());
        assert_eq!(album_val["images"][2]["state"], "placeholder");
        assert!(album_val["images"][2].get("url").is_none());
        assert_eq!(album_val["videos"][0]["state"], "blurred");
        assert!(album_val["videos"][0].get("url").is_none());
    }
}
