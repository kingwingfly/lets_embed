//! Policy v3 server-side media projection types, object-bound reveal DTOs,
//! and similarity threshold helpers.
//!
//! Security invariants enforced structurally by the type definitions:
//! - `Blurred` NEVER carries a pre-minted clear `reveal_url` or filename; clear
//!   bytes require an explicit CSRF-protected `POST /api/safety/reveal`.
//! - `Placeholder` carries ZERO media locator, filename, preview URL, or clear URL.

use std::fmt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PlaceholderPreset {
    R18,
    Blood,
    Sensitive,
    #[default]
    Custom,
}

impl PlaceholderPreset {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R18 => "r18",
            Self::Blood => "blood",
            Self::Sensitive => "sensitive",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum MediaKind {
    Image,
    Video,
}

impl MediaKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Video => "video",
        }
    }
}

impl fmt::Display for MediaKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MaskMetadata {
    /// Highest-priority outstanding policy ID selecting the displayed reason.
    pub policy_id: String,
    /// All unsatisfied policy IDs that caused this placeholder.
    #[cfg_attr(feature = "serde", serde(default))]
    pub matched_policy_ids: Vec<String>,
    pub label: String,
    pub preset: PlaceholderPreset,
    pub requires_login: bool,
    pub requires_age: bool,
    pub requires_terms: bool,
}

/// Policy v3 per-asset visibility projection.
///
/// - `Clear`: all matched `Block` and `Blur` policies are satisfied.
/// - `Blurred`: all matched `Block` policies are satisfied, >= 1 `Blur` policy
///   remains unsatisfied. NEVER carries a pre-minted clear `reveal_url`.
/// - `Placeholder`: any unsatisfied `Block`, indeterminate `Unknown` restriction,
///   or unsatisfied `Blur` when `fixed_blur_enabled == false`. Carries ZERO
///   media locator, filename, preview URL, or clear URL.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "state", rename_all = "snake_case"))]
pub enum MediaVisibility {
    Clear {
        asset_id: i64,
        kind: MediaKind,
        url: String,
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        name: Option<String>,
    },
    Blurred {
        asset_id: i64,
        kind: MediaKind,
        /// Present ONLY when `policy.fixed_blur_enabled == true` (fixed server transform).
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        preview_url: Option<String>,
        can_click_reveal: bool,
        policy_rev: u64,
        matched_policy_ids: Vec<String>,
        label: String,
        preset: PlaceholderPreset,
    },
    Placeholder {
        asset_id: i64,
        kind: MediaKind,
        policy_rev: u64,
        mask: MaskMetadata,
    },
}

impl MediaVisibility {
    pub const fn asset_id(&self) -> i64 {
        match self {
            Self::Clear { asset_id, .. }
            | Self::Blurred { asset_id, .. }
            | Self::Placeholder { asset_id, .. } => *asset_id,
        }
    }

    pub const fn kind(&self) -> MediaKind {
        match self {
            Self::Clear { kind, .. }
            | Self::Blurred { kind, .. }
            | Self::Placeholder { kind, .. } => *kind,
        }
    }

    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear { .. })
    }

    pub const fn is_blurred(&self) -> bool {
        matches!(self, Self::Blurred { .. })
    }

    pub const fn is_placeholder(&self) -> bool {
        matches!(self, Self::Placeholder { .. })
    }
}

/// Top-level Policy v3 projection envelope for an individual media item.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SafetyProjection {
    pub policy_rev: u64,
    pub fixed_blur_enabled: bool,
    pub media: MediaVisibility,
}

/// Projected image with dimensions and structurally safe Policy v3 visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "state", rename_all = "snake_case"))]
pub enum ProjectedImage {
    Clear {
        id: i64,
        url: String,
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        name: Option<String>,
        width: i32,
        height: i32,
    },
    Blurred {
        id: i64,
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        preview_url: Option<String>,
        can_click_reveal: bool,
        policy_rev: u64,
        matched_policy_ids: Vec<String>,
        label: String,
        preset: PlaceholderPreset,
        width: i32,
        height: i32,
    },
    Placeholder {
        id: i64,
        policy_rev: u64,
        width: i32,
        height: i32,
        mask: MaskMetadata,
    },
}

impl ProjectedImage {
    pub const fn id(&self) -> i64 {
        match self {
            Self::Clear { id, .. } | Self::Blurred { id, .. } | Self::Placeholder { id, .. } => *id,
        }
    }

    pub const fn width(&self) -> i32 {
        match self {
            Self::Clear { width, .. }
            | Self::Blurred { width, .. }
            | Self::Placeholder { width, .. } => *width,
        }
    }

    pub const fn height(&self) -> i32 {
        match self {
            Self::Clear { height, .. }
            | Self::Blurred { height, .. }
            | Self::Placeholder { height, .. } => *height,
        }
    }

    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear { .. })
    }

    pub const fn is_blurred(&self) -> bool {
        matches!(self, Self::Blurred { .. })
    }

    pub const fn is_placeholder(&self) -> bool {
        matches!(self, Self::Placeholder { .. })
    }
}

/// Projected video with dimensions, duration, and structurally safe Policy v3 visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "state", rename_all = "snake_case"))]
pub enum ProjectedVideo {
    Clear {
        id: i64,
        url: String,
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        name: Option<String>,
        width: i32,
        height: i32,
        duration: i32,
    },
    Blurred {
        id: i64,
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        preview_url: Option<String>,
        can_click_reveal: bool,
        policy_rev: u64,
        matched_policy_ids: Vec<String>,
        label: String,
        preset: PlaceholderPreset,
        width: i32,
        height: i32,
        duration: i32,
    },
    Placeholder {
        id: i64,
        policy_rev: u64,
        width: i32,
        height: i32,
        duration: i32,
        mask: MaskMetadata,
    },
}

impl ProjectedVideo {
    pub const fn id(&self) -> i64 {
        match self {
            Self::Clear { id, .. } | Self::Blurred { id, .. } | Self::Placeholder { id, .. } => *id,
        }
    }

    pub const fn width(&self) -> i32 {
        match self {
            Self::Clear { width, .. }
            | Self::Blurred { width, .. }
            | Self::Placeholder { width, .. } => *width,
        }
    }

    pub const fn height(&self) -> i32 {
        match self {
            Self::Clear { height, .. }
            | Self::Blurred { height, .. }
            | Self::Placeholder { height, .. } => *height,
        }
    }

    pub const fn duration(&self) -> i32 {
        match self {
            Self::Clear { duration, .. }
            | Self::Blurred { duration, .. }
            | Self::Placeholder { duration, .. } => *duration,
        }
    }

    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear { .. })
    }

    pub const fn is_blurred(&self) -> bool {
        matches!(self, Self::Blurred { .. })
    }

    pub const fn is_placeholder(&self) -> bool {
        matches!(self, Self::Placeholder { .. })
    }
}

/// Unified rendered media item pairing geometry with [`MediaVisibility`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RenderedMedia {
    pub width: i32,
    pub height: i32,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub duration: Option<i32>,
    pub visibility: MediaVisibility,
}

impl From<ProjectedImage> for RenderedMedia {
    fn from(img: ProjectedImage) -> Self {
        match img {
            ProjectedImage::Clear {
                id,
                url,
                name,
                width,
                height,
            } => Self {
                width,
                height,
                duration: None,
                visibility: MediaVisibility::Clear {
                    asset_id: id,
                    kind: MediaKind::Image,
                    url,
                    name,
                },
            },
            ProjectedImage::Blurred {
                id,
                preview_url,
                can_click_reveal,
                policy_rev,
                matched_policy_ids,
                label,
                preset,
                width,
                height,
            } => Self {
                width,
                height,
                duration: None,
                visibility: MediaVisibility::Blurred {
                    asset_id: id,
                    kind: MediaKind::Image,
                    preview_url,
                    can_click_reveal,
                    policy_rev,
                    matched_policy_ids,
                    label,
                    preset,
                },
            },
            ProjectedImage::Placeholder {
                id,
                policy_rev,
                width,
                height,
                mask,
            } => Self {
                width,
                height,
                duration: None,
                visibility: MediaVisibility::Placeholder {
                    asset_id: id,
                    kind: MediaKind::Image,
                    policy_rev,
                    mask,
                },
            },
        }
    }
}

impl From<ProjectedVideo> for RenderedMedia {
    fn from(vid: ProjectedVideo) -> Self {
        match vid {
            ProjectedVideo::Clear {
                id,
                url,
                name,
                width,
                height,
                duration,
            } => Self {
                width,
                height,
                duration: Some(duration),
                visibility: MediaVisibility::Clear {
                    asset_id: id,
                    kind: MediaKind::Video,
                    url,
                    name,
                },
            },
            ProjectedVideo::Blurred {
                id,
                preview_url,
                can_click_reveal,
                policy_rev,
                matched_policy_ids,
                label,
                preset,
                width,
                height,
                duration,
            } => Self {
                width,
                height,
                duration: Some(duration),
                visibility: MediaVisibility::Blurred {
                    asset_id: id,
                    kind: MediaKind::Video,
                    preview_url,
                    can_click_reveal,
                    policy_rev,
                    matched_policy_ids,
                    label,
                    preset,
                },
            },
            ProjectedVideo::Placeholder {
                id,
                policy_rev,
                width,
                height,
                duration,
                mask,
            } => Self {
                width,
                height,
                duration: Some(duration),
                visibility: MediaVisibility::Placeholder {
                    asset_id: id,
                    kind: MediaKind::Video,
                    policy_rev,
                    mask,
                },
            },
        }
    }
}

/// Rendered post carrying only Policy v3 projected media.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RenderedPost {
    pub post: crate::Post,
    #[cfg_attr(feature = "serde", serde(default))]
    pub authors: Vec<crate::Author>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub images: Vec<ProjectedImage>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub videos: Vec<ProjectedVideo>,
}

/// Request payload for same-origin CSRF-protected `POST /api/safety/reveal`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RevealRequest {
    pub kind: MediaKind,
    pub asset_id: i64,
    pub policy_rev: u64,
}

/// Response payload returned by `POST /api/safety/reveal` containing a freshly
/// minted single-asset clear capability URL bound to the caller's live actor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RevealResponse {
    pub kind: MediaKind,
    pub asset_id: i64,
    pub policy_rev: u64,
    pub clear_url: String,
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// Similarity Threshold Validation Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityThresholdError {
    pub message: String,
}

impl fmt::Display for SimilarityThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SimilarityThresholdError {}

/// Validates an optional minimum cosine similarity threshold (`0.0..=1.0`, finite).
pub fn validate_min_similarity(
    min_similarity: Option<f32>,
) -> Result<Option<f32>, SimilarityThresholdError> {
    match min_similarity {
        None => Ok(None),
        Some(v) if v.is_finite() && (0.0..=1.0).contains(&v) => Ok(Some(v)),
        Some(v) => Err(SimilarityThresholdError {
            message: format!("min_similarity '{v}' must be finite and within 0.0..=1.0"),
        }),
    }
}

/// Clamps a finite similarity threshold into `0.0..=1.0`, returning `None` for non-finite values.
pub fn clamp_min_similarity(v: f32) -> Option<f32> {
    v.is_finite().then(|| v.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn similarity_validation_checks_bounds_and_finiteness() {
        assert_eq!(validate_min_similarity(None), Ok(None));
        assert_eq!(validate_min_similarity(Some(0.0)), Ok(Some(0.0)));
        assert_eq!(validate_min_similarity(Some(0.65)), Ok(Some(0.65)));
        assert_eq!(validate_min_similarity(Some(1.0)), Ok(Some(1.0)));

        assert!(validate_min_similarity(Some(-0.01)).is_err());
        assert!(validate_min_similarity(Some(1.01)).is_err());
        assert!(validate_min_similarity(Some(f32::NAN)).is_err());
        assert!(validate_min_similarity(Some(f32::INFINITY)).is_err());
        assert!(validate_min_similarity(Some(f32::NEG_INFINITY)).is_err());

        assert_eq!(clamp_min_similarity(1.5), Some(1.0));
        assert_eq!(clamp_min_similarity(-0.2), Some(0.0));
        assert_eq!(clamp_min_similarity(f32::NAN), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn blurred_and_placeholder_projections_never_emit_reveal_or_clear_urls() {
        let blurred_vis = MediaVisibility::Blurred {
            asset_id: 42,
            kind: MediaKind::Image,
            preview_url: Some("/media/preview/42?cap=mc3.xxx".to_string()),
            can_click_reveal: true,
            policy_rev: 5,
            matched_policy_ids: vec!["sensitive".to_string()],
            label: "Suggestive".to_string(),
            preset: PlaceholderPreset::Sensitive,
        };
        let blur_val = serde_json::to_value(&blurred_vis).expect("serialize blurred");
        let blur_obj = blur_val.as_object().expect("json object");
        assert_eq!(
            blur_obj.get("state").and_then(|v| v.as_str()),
            Some("blurred")
        );
        assert!(!blur_obj.contains_key("reveal_url"));
        assert!(!blur_obj.contains_key("clear_url"));
        assert!(!blur_obj.contains_key("url"));
        assert!(!blur_obj.contains_key("name"));
        assert_eq!(
            blur_obj.get("can_click_reveal").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(blur_obj.get("policy_rev").and_then(|v| v.as_u64()), Some(5));

        let placeholder_img = ProjectedImage::Placeholder {
            id: 99,
            policy_rev: 5,
            width: 1200,
            height: 1600,
            mask: MaskMetadata {
                policy_id: "r18".to_string(),
                matched_policy_ids: vec!["r18".to_string()],
                label: "NSFW".to_string(),
                preset: PlaceholderPreset::R18,
                requires_login: true,
                requires_age: true,
                requires_terms: true,
            },
        };
        let img_val = serde_json::to_value(&placeholder_img).expect("serialize placeholder image");
        let img_obj = img_val.as_object().expect("json object");
        assert_eq!(
            img_obj.get("state").and_then(|v| v.as_str()),
            Some("placeholder")
        );
        assert!(!img_obj.contains_key("name"));
        assert!(!img_obj.contains_key("url"));
        assert!(!img_obj.contains_key("preview_url"));
        assert!(!img_obj.contains_key("reveal_url"));
        assert!(!img_obj.contains_key("clear_url"));

        let blurred_vid = ProjectedVideo::Blurred {
            id: 77,
            preview_url: None,
            can_click_reveal: true,
            policy_rev: 5,
            matched_policy_ids: vec!["sensitive".to_string()],
            label: "Suggestive".to_string(),
            preset: PlaceholderPreset::Sensitive,
            width: 1920,
            height: 1080,
            duration: 45,
        };
        let vid_val = serde_json::to_value(&blurred_vid).expect("serialize blurred video");
        let vid_obj = vid_val.as_object().expect("json object");
        assert_eq!(
            vid_obj.get("state").and_then(|v| v.as_str()),
            Some("blurred")
        );
        assert!(!vid_obj.contains_key("preview_url"));
        assert!(!vid_obj.contains_key("reveal_url"));
        assert!(!vid_obj.contains_key("url"));
        assert!(!vid_obj.contains_key("name"));

        let rendered: RenderedMedia = blurred_vid.into();
        assert!(rendered.visibility.is_blurred());
        assert_eq!(rendered.visibility.kind(), MediaKind::Video);
        assert_eq!(rendered.duration, Some(45));
    }
}
