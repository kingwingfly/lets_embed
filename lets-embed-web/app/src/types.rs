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

#[cfg(feature = "hydrate")]
const GALLERY_DENSITY_KEY: &str = "lets-embed:gallery-density";
#[cfg(feature = "hydrate")]
const FAV_DENSITY_KEY: &str = "lets-embed:fav-density";

/// Masonry column density shared between the floating home header and embedded
/// Similar galleries, matching `/user/favorites`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GalleryDensity {
    Compact,
    Medium,
    Large,
}

impl GalleryDensity {
    pub const fn target_width(self) -> f64 {
        match self {
            Self::Compact => 200.0,
            Self::Medium => 300.0,
            Self::Large => 440.0,
        }
    }

    pub const fn desktop_bounds(self) -> (usize, usize) {
        match self {
            Self::Compact => (2, 12),
            Self::Medium => (1, 8),
            Self::Large => (1, 6),
        }
    }

    /// Responsive masonry column count matching `Results` across mobile and desktop widths.
    pub fn column_count(self, width: f64) -> usize {
        if width <= 0.0 {
            return match self {
                Self::Compact => 3,
                Self::Medium => 2,
                Self::Large => 1,
            };
        }
        if width <= 540.0 {
            return match self {
                Self::Compact => {
                    if width >= 340.0 {
                        3
                    } else {
                        2
                    }
                }
                Self::Medium => 2,
                Self::Large => 1,
            };
        }
        let (min_cols, max_cols) = self.desktop_bounds();
        ((width / self.target_width()).round() as usize).clamp(min_cols, max_cols)
    }

    #[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }

    #[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "compact" => Some(Self::Compact),
            "medium" => Some(Self::Medium),
            "large" => Some(Self::Large),
            _ => None,
        }
    }
}

/// App-root context carrying the active masonry density across `SearchBar` and `Results`.
#[derive(Clone, Copy)]
pub struct GalleryDensityState(pub RwSignal<GalleryDensity>);

impl GalleryDensityState {
    pub fn new() -> Self {
        Self(RwSignal::new(GalleryDensity::Medium))
    }
}

impl Default for GalleryDensityState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "hydrate")]
pub fn load_gallery_density() -> Option<GalleryDensity> {
    let storage = web_sys::window()?.local_storage().ok()??;
    storage
        .get_item(GALLERY_DENSITY_KEY)
        .ok()
        .flatten()
        .and_then(|s| GalleryDensity::parse(&s))
        .or_else(|| {
            storage
                .get_item(FAV_DENSITY_KEY)
                .ok()
                .flatten()
                .and_then(|s| GalleryDensity::parse(&s))
        })
}

#[cfg(feature = "hydrate")]
pub fn save_gallery_density(density: GalleryDensity) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(GALLERY_DENSITY_KEY, density.as_str());
        let _ = storage.set_item(FAV_DENSITY_KEY, density.as_str());
    }
}

#[cfg(not(feature = "hydrate"))]
pub fn save_gallery_density(_density: GalleryDensity) {}

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
