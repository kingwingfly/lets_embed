pub mod projection;
pub mod query;
pub mod safety;

pub use projection::{
    BlurDeliveryMode, MaskMetadata, ProjectedImage, ProjectedVideo, SimilarityThresholdError,
    clamp_min_similarity, validate_min_similarity,
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
