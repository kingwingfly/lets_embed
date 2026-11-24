pub mod projection;
pub mod query;
pub mod safety;
pub mod wd_vocab;

pub use projection::{
    MASK_NO_UNLOCK_MARKER, MaskMetadata, MediaKind, MediaVisibility, PlaceholderPreset,
    ProjectedImage, ProjectedVideo, RenderedMedia, RenderedPost, RevealRequest, RevealResponse,
    SafetyProjection, SimilarityThresholdError, clamp_min_similarity, validate_min_similarity,
};
pub use query::{
    ClipClause, DinoClause, ThresholdError, UploadClause, VectorClause, VectorTarget,
    format_threshold_hundredths, parse_threshold_hundredths, validate_threshold_hundredths_f32,
    validate_threshold_range,
};
pub use safety::{
    TriBool, collect_catalog_refs, parse_safety_rule, parse_safety_rule_legacy_precision,
    validate_policy_expr_pair, validate_wd_tags_in_expr,
};
pub use wd_vocab::{
    BUILTIN_SAFETY_PRESET_TAGS, PRESET_EXTREME_QUERY, PRESET_EXTREME_TAGS, PRESET_R18_QUERY,
    PRESET_R18_TAGS, PRESET_SENSITIVE_QUERY, PRESET_SENSITIVE_TAGS, WD_VOCAB_COUNT,
    WD_VOCAB_DIGEST, canonical_wd_vocab_bytes, is_canonical_wd_tag, wd_vocab_count,
    wd_vocab_tags,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Image {
    pub id: i64,
    pub name: String,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Post {
    pub id: i64,
    pub title: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tag {
    pub id: i64,
    pub name: String,
    /// Multilingual aliases/translations (e.g. from `wd_tag_translations`).
    #[cfg_attr(feature = "serde", serde(default))]
    pub aliases: Vec<String>,
    /// Model confidence score in `[0.0, 1.0]` when attached to an image.
    #[cfg_attr(feature = "serde", serde(default))]
    pub score: Option<f32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Author {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ImageDetails {
    pub image: Image,
    pub post: Option<Post>,
    pub authors: Vec<Author>,
    pub tags: Vec<Tag>,
}

#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PostMeta {
    pub authors: Vec<Author>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Video {
    pub id: i64,
    pub name: String,
    pub width: i32,
    pub height: i32,
    pub duration: i32,
}

#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VideoDetails {
    pub video: Video,
    pub post: Option<Post>,
    pub authors: Vec<Author>,
    pub tags: Vec<Tag>,
}
