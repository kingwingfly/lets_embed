//! Unified server-side media projection types and similarity threshold helpers.
//!
//! `ProjectedImage::Locked` and `ProjectedVideo::Locked` structurally omit `name`
//! and media URLs so restricted paths or capabilities can never leak across SSR,
//! hydration, or API responses.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum BlurDeliveryMode {
    /// Server-side Cloudflare Images blur transform (no clear bytes delivered).
    ServerTransform,
    /// Client-side CSS courtesy blur (clear bytes delivered; non-security spoiler).
    CssCourtesy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MaskMetadata {
    pub rule_id: String,
    pub label: String,
    pub preset: String,
    pub requires_login: bool,
    pub requires_age: bool,
    pub requires_terms: bool,
}

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
    Spoiler {
        id: i64,
        preview_url: String,
        reveal_url: String,
        width: i32,
        height: i32,
        rule_id: String,
        label: String,
        preset: String,
        blur_mode: BlurDeliveryMode,
    },
    Locked {
        id: i64,
        width: i32,
        height: i32,
        mask: MaskMetadata,
    },
}

impl ProjectedImage {
    pub const fn id(&self) -> i64 {
        match self {
            Self::Clear { id, .. } | Self::Spoiler { id, .. } | Self::Locked { id, .. } => *id,
        }
    }

    pub const fn width(&self) -> i32 {
        match self {
            Self::Clear { width, .. }
            | Self::Spoiler { width, .. }
            | Self::Locked { width, .. } => *width,
        }
    }

    pub const fn height(&self) -> i32 {
        match self {
            Self::Clear { height, .. }
            | Self::Spoiler { height, .. }
            | Self::Locked { height, .. } => *height,
        }
    }

    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear { .. })
    }

    pub const fn is_spoiler(&self) -> bool {
        matches!(self, Self::Spoiler { .. })
    }

    pub const fn is_locked(&self) -> bool {
        matches!(self, Self::Locked { .. })
    }
}

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
    Locked {
        id: i64,
        width: i32,
        height: i32,
        duration: i32,
        mask: MaskMetadata,
    },
}

impl ProjectedVideo {
    pub const fn id(&self) -> i64 {
        match self {
            Self::Clear { id, .. } | Self::Locked { id, .. } => *id,
        }
    }

    pub const fn width(&self) -> i32 {
        match self {
            Self::Clear { width, .. } | Self::Locked { width, .. } => *width,
        }
    }

    pub const fn height(&self) -> i32 {
        match self {
            Self::Clear { height, .. } | Self::Locked { height, .. } => *height,
        }
    }

    pub const fn duration(&self) -> i32 {
        match self {
            Self::Clear { duration, .. } | Self::Locked { duration, .. } => *duration,
        }
    }

    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear { .. })
    }

    pub const fn is_locked(&self) -> bool {
        matches!(self, Self::Locked { .. })
    }
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
    fn locked_projections_serialize_with_zero_name_or_url_fields() {
        let locked_img = ProjectedImage::Locked {
            id: 99,
            width: 1200,
            height: 1600,
            mask: MaskMetadata {
                rule_id: "r18".to_string(),
                label: "NSFW".to_string(),
                preset: "r18".to_string(),
                requires_login: true,
                requires_age: true,
                requires_terms: true,
            },
        };
        let img_val = serde_json::to_value(&locked_img).expect("serialize locked image");
        let img_obj = img_val.as_object().expect("json object");
        assert_eq!(img_obj.get("state").and_then(|v| v.as_str()), Some("locked"));
        assert!(!img_obj.contains_key("name"));
        assert!(!img_obj.contains_key("url"));
        assert!(!img_obj.contains_key("preview_url"));
        assert!(!img_obj.contains_key("reveal_url"));

        let locked_vid = ProjectedVideo::Locked {
            id: 77,
            width: 1920,
            height: 1080,
            duration: 45,
            mask: MaskMetadata {
                rule_id: "unclassified".to_string(),
                label: "Pending classification".to_string(),
                preset: "custom".to_string(),
                requires_login: false,
                requires_age: false,
                requires_terms: false,
            },
        };
        let vid_val = serde_json::to_value(&locked_vid).expect("serialize locked video");
        let vid_obj = vid_val.as_object().expect("json object");
        assert_eq!(vid_obj.get("state").and_then(|v| v.as_str()), Some("locked"));
        assert!(!vid_obj.contains_key("name"));
        assert!(!vid_obj.contains_key("url"));
    }
}
