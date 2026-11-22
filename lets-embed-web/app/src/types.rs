use leptos::prelude::RwSignal;
use search_types::{Image, Video};
use serde::{Deserialize, Serialize};

pub const MAX_SEARCH_LIMIT: i64 = 100;
pub const DEFAULT_SEARCH_LIMIT: i64 = 50;

/// Parse a URL `limit` query parameter identically across `SearchBar` and `Results`.
/// Missing, unparseable, or `<= 0` values fall back to `DEFAULT_SEARCH_LIMIT`;
/// positive values are clamped to `1..=MAX_SEARCH_LIMIT`.
pub fn parse_url_limit(raw: Option<&str>) -> i64 {
    raw.and_then(|s| s.parse::<i64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.clamp(1, MAX_SEARCH_LIMIT))
        .unwrap_or(DEFAULT_SEARCH_LIMIT)
}

/// Pending client-side single-image search payload bound to the URL nonce that triggered it,
/// so navigating Back to an older crop/upload nonce never silently runs with newer bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageQueryPayload {
    pub nonce: String,
    pub b64: String,
}

/// Client-side holder for a pending single-image search payload (URL-safe base64, no pad).
#[derive(Clone, Copy)]
pub struct ImageQuery(pub RwSignal<Option<ImageQueryPayload>>);

/// Uploaded image slot used by Advanced Search (`upload:0`, `upload:1`, ...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadedImageSlot {
    pub filename: String,
    /// URL-safe base64 (no pad) encoded <=256px WebP bytes.
    pub b64: String,
    /// `data:image/webp;base64,...` URL for thumbnail preview in the builder.
    pub preview_url: String,
}

/// Client-side holder for uploaded images attached to an Advanced Search navigation nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvancedUploadsPayload {
    pub nonce: String,
    pub slots: Vec<UploadedImageSlot>,
}

/// Provided at the app root so `AdvancedSearchPanel` and `Results` share uploaded images
/// without stuffing image bytes into the URL.
#[derive(Clone, Copy)]
pub struct AdvancedUploads(pub RwSignal<Option<AdvancedUploadsPayload>>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Mode {
    /// Default post search matching Post Title OR Author (no Tag).
    All,
    /// Post search by Author name.
    Author,
    /// Post search by Title.
    Title,
    /// Web-of-Science-style multi-condition boolean + semantic Advanced Search.
    Advanced,
    /// Random Posts or Images shuffle.
    Random,
    /// Legacy single-tag search (still supported for old bookmarks/links).
    Tag,
    /// Legacy single CLIP description search.
    Clip,
    /// Single-image DINOv3 similarity (used by `/details/:id` and legacy links).
    Similar,
    /// Single uploaded/cropped reverse image search (used by `/details/:id` crop-search).
    SearchImage,
}

impl Mode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Mode::All => "all",
            Mode::Author => "author",
            Mode::Title => "title",
            Mode::Advanced => "advanced",
            Mode::Random => "random",
            Mode::Tag => "tag",
            Mode::Clip => "clip",
            Mode::Similar => "similar",
            Mode::SearchImage => "search_image",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "all" => Mode::All,
            "author" => Mode::Author,
            "title" => Mode::Title,
            "advanced" => Mode::Advanced,
            "random" => Mode::Random,
            "tag" => Mode::Tag,
            "clip" => Mode::Clip,
            "similar" => Mode::Similar,
            "search_image" => Mode::SearchImage,
            _ => Mode::All,
        }
    }

    /// True if this mode belongs to the default top Post search selector.
    pub const fn is_default_post_mode(self) -> bool {
        matches!(self, Mode::All | Mode::Title | Mode::Author)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MediaItem {
    Image(Image),
    Video(Video),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostItem {
    pub id: i64,
    pub title: String,
    pub images: Vec<Image>,
    pub videos: Vec<Video>,
    #[serde(default)]
    pub image_count: usize,
    #[serde(default)]
    pub video_count: usize,
}

/// A single page of search results returned by the REST search endpoints.
///
/// Exactly one of `posts` / `images` is populated depending on the search mode;
/// the other is empty. `has_more` drives infinite-scroll pagination.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SearchResponse {
    pub posts: Vec<PostItem>,
    pub images: Vec<Image>,
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT, parse_url_limit};

    #[test]
    fn parse_url_limit_defaults_non_positive_and_clamps_high() {
        assert_eq!(parse_url_limit(None), DEFAULT_SEARCH_LIMIT);
        assert_eq!(parse_url_limit(Some("")), DEFAULT_SEARCH_LIMIT);
        assert_eq!(parse_url_limit(Some("abc")), DEFAULT_SEARCH_LIMIT);
        assert_eq!(parse_url_limit(Some("0")), DEFAULT_SEARCH_LIMIT);
        assert_eq!(parse_url_limit(Some("-5")), DEFAULT_SEARCH_LIMIT);
        assert_eq!(parse_url_limit(Some("1")), 1);
        assert_eq!(parse_url_limit(Some("25")), 25);
        assert_eq!(parse_url_limit(Some("999")), MAX_SEARCH_LIMIT);
    }
}
