use leptos::prelude::{RwSignal, Set};
use lets_embed_ui::{
    Density, GalleryBlurMode, GalleryCard, GalleryCardKind, GalleryMask, GalleryMaskPreset,
    GalleryMedia, GalleryMediaKind, ReportTargetKind, ViewerItem,
};
use search_types::{
    Author, BlurDeliveryMode, MaskMetadata, Post, ProjectedImage, ProjectedVideo, Tag,
};
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

/// Parse an optional URL `min_sim` query parameter (`0.0..=1.0`, finite).
pub fn parse_url_min_similarity(raw: Option<&str>) -> Option<f32> {
    raw.and_then(|s| s.trim().parse::<f32>().ok())
        .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
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

pub type GalleryDensity = Density;

/// App-root context carrying the active masonry density across `SearchBar`, `Results`, and `Lightbox`.
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

pub fn load_gallery_density() -> Option<GalleryDensity> {
    lets_embed_ui::browser::load_density()
}

pub fn save_gallery_density(density: GalleryDensity) {
    lets_embed_ui::browser::save_density(density);
}

/// Public UI configuration hydrated from the pinned server policy snapshot.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SiteUiConfig {
    pub is_managed: bool,
    pub safety_enabled: bool,
    pub safe_mode: bool,
    pub default_dinov3_min: f32,
    pub default_siglip2_min: f32,
    pub notice_banner_enabled: bool,
    pub notice_banner_html: Option<String>,
    pub notice_banner_key: String,
    pub rta_meta_enabled: bool,
    pub noindex_restricted: bool,
    pub panic_shortcut: String,
}

/// Pending report dialog target `(kind, id, label)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportTarget {
    pub kind: ReportTargetKind,
    pub id: i64,
    pub label: String,
}

/// Shared client-side safety, Safe Mode panic epoch, similarity defaults, and
/// report dialog trigger provided at the `<App/>` root.
#[derive(Clone, Copy)]
pub struct SafetyUiState {
    pub safe_mode: RwSignal<bool>,
    pub panic_epoch: RwSignal<u64>,
    /// Bumped whenever `safe_mode` toggles (either ON or OFF) so active galleries
    /// discard stale in-flight fetches and reload from server projection.
    pub reload_epoch: RwSignal<u64>,
    pub is_managed: RwSignal<bool>,
    pub safety_enabled: RwSignal<bool>,
    pub default_dinov3_min: RwSignal<f32>,
    pub default_siglip2_min: RwSignal<f32>,
    pub notice_banner_enabled: RwSignal<bool>,
    pub notice_banner_html: RwSignal<Option<String>>,
    pub notice_banner_key: RwSignal<String>,
    pub report_target: RwSignal<Option<ReportTarget>>,
}

impl SafetyUiState {
    pub fn new() -> Self {
        Self {
            safe_mode: RwSignal::new(false),
            panic_epoch: RwSignal::new(0),
            reload_epoch: RwSignal::new(0),
            is_managed: RwSignal::new(false),
            safety_enabled: RwSignal::new(false),
            default_dinov3_min: RwSignal::new(0.0),
            default_siglip2_min: RwSignal::new(0.0),
            notice_banner_enabled: RwSignal::new(false),
            notice_banner_html: RwSignal::new(None),
            notice_banner_key: RwSignal::new(String::new()),
            report_target: RwSignal::new(None),
        }
    }

    pub fn apply_site_config(&self, cfg: &SiteUiConfig) {
        self.is_managed.set(cfg.is_managed);
        self.safety_enabled.set(cfg.safety_enabled);
        self.safe_mode.set(cfg.safe_mode);
        self.default_dinov3_min
            .set(if cfg.default_dinov3_min.is_finite() {
                cfg.default_dinov3_min.clamp(0.0, 1.0)
            } else {
                0.0
            });
        self.default_siglip2_min
            .set(if cfg.default_siglip2_min.is_finite() {
                cfg.default_siglip2_min.clamp(0.0, 1.0)
            } else {
                0.0
            });
        self.notice_banner_enabled.set(cfg.notice_banner_enabled);
        self.notice_banner_html.set(cfg.notice_banner_html.clone());
        self.notice_banner_key.set(cfg.notice_banner_key.clone());
    }

    pub fn open_report(&self, kind: ReportTargetKind, id: i64, label: impl Into<String>) {
        self.report_target.set(Some(ReportTarget {
            kind,
            id,
            label: label.into(),
        }));
    }
}

impl Default for SafetyUiState {
    fn default() -> Self {
        Self::new()
    }
}

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
pub struct PostItem {
    pub id: i64,
    pub title: String,
    pub images: Vec<ProjectedImage>,
    pub videos: Vec<ProjectedVideo>,
    #[serde(default)]
    pub image_count: usize,
    #[serde(default)]
    pub video_count: usize,
}

/// Projected image details response returned by `/api/fetch_image_details`.
///
/// When `image` is `ProjectedImage::Locked`, `image` contains ZERO `name`/`url`/`cap`,
/// `tags` is withheld (empty), and `og_image_allowed` is `false`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectedImageDetails {
    pub image: ProjectedImage,
    pub post: Option<Post>,
    pub authors: Vec<Author>,
    pub tags: Vec<Tag>,
    #[serde(default)]
    pub og_image_allowed: bool,
    #[serde(default)]
    pub noindex: bool,
}

/// A single page of search results returned by the REST search endpoints.
///
/// Exactly one of `posts` / `images` is populated depending on the search mode;
/// the other is empty. `has_more` drives infinite-scroll pagination.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SearchResponse {
    pub posts: Vec<PostItem>,
    pub images: Vec<ProjectedImage>,
    pub has_more: bool,
}

// ---------------------------------------------------------------------------
// Conversion helpers between `search_types::Projected*` and `lets-embed-ui`
// ---------------------------------------------------------------------------

pub fn mask_to_ui(mask: &MaskMetadata) -> GalleryMask {
    GalleryMask {
        rule_id: mask.rule_id.clone(),
        label: mask.label.clone(),
        preset: GalleryMaskPreset::parse(&mask.preset),
        reason: None,
        requires_login: mask.requires_login,
        requires_age: mask.requires_age,
        requires_terms: mask.requires_terms,
        cta_label: None,
    }
}

pub fn blur_mode_to_ui(mode: BlurDeliveryMode) -> GalleryBlurMode {
    match mode {
        BlurDeliveryMode::ServerTransform => GalleryBlurMode::ServerTransform,
        BlurDeliveryMode::CssCourtesy => GalleryBlurMode::CssCourtesy,
    }
}

pub fn projected_image_to_ui(img: &ProjectedImage, fallback_alt: impl Into<String>) -> GalleryMedia {
    let fallback_alt = fallback_alt.into();
    match img {
        ProjectedImage::Clear {
            id,
            url,
            name,
            width,
            height,
        } => GalleryMedia::Clear {
            id: *id,
            kind: GalleryMediaKind::Image,
            width: *width,
            height: *height,
            url: url.clone(),
            alt: name
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| {
                    if fallback_alt.is_empty() {
                        format!("Image #{id}")
                    } else {
                        fallback_alt
                    }
                }),
            duration_secs: None,
        },
        ProjectedImage::Spoiler {
            id,
            preview_url,
            reveal_url,
            width,
            height,
            rule_id,
            label,
            preset,
            blur_mode,
        } => GalleryMedia::Spoiler {
            id: *id,
            kind: GalleryMediaKind::Image,
            width: *width,
            height: *height,
            preview_url: preview_url.clone(),
            reveal_url: reveal_url.clone(),
            alt: if fallback_alt.is_empty() {
                format!("Image #{id}")
            } else {
                fallback_alt
            },
            duration_secs: None,
            rule_id: rule_id.clone(),
            label: label.clone(),
            preset: GalleryMaskPreset::parse(preset),
            blur_mode: blur_mode_to_ui(*blur_mode),
        },
        ProjectedImage::Locked {
            id,
            width,
            height,
            mask,
        } => GalleryMedia::Locked {
            id: *id,
            kind: GalleryMediaKind::Image,
            width: *width,
            height: *height,
            mask: mask_to_ui(mask),
        },
    }
}

pub fn projected_video_to_ui(vid: &ProjectedVideo, fallback_alt: impl Into<String>) -> GalleryMedia {
    let fallback_alt = fallback_alt.into();
    match vid {
        ProjectedVideo::Clear {
            id,
            url,
            name,
            width,
            height,
            duration,
        } => GalleryMedia::Clear {
            id: *id,
            kind: GalleryMediaKind::Video,
            width: *width,
            height: *height,
            url: url.clone(),
            alt: name
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| {
                    if fallback_alt.is_empty() {
                        format!("Video #{id}")
                    } else {
                        fallback_alt
                    }
                }),
            duration_secs: (*duration > 0).then_some(*duration),
        },
        ProjectedVideo::Locked {
            id,
            width,
            height,
            mask,
            ..
        } => GalleryMedia::Locked {
            id: *id,
            kind: GalleryMediaKind::Video,
            width: *width,
            height: *height,
            mask: mask_to_ui(mask),
        },
    }
}

pub fn projected_image_to_card(
    img: &ProjectedImage,
    title: impl Into<String>,
    liked: Option<bool>,
) -> GalleryCard {
    let id = img.id();
    let title = title.into();
    let media = projected_image_to_ui(img, &title);
    GalleryCard {
        key: format!("image:{id}"),
        id,
        kind: GalleryCardKind::Image,
        title: if title.is_empty() {
            format!("#{id}")
        } else {
            title
        },
        subtitle: None,
        media,
        image_count: 0,
        video_count: 0,
        details_href: (!img.is_locked()).then(|| format!("/details/{id}")),
        liked,
    }
}

pub fn projected_image_to_viewer_item(
    img: &ProjectedImage,
    title: impl Into<String>,
    liked: Option<bool>,
) -> ViewerItem {
    let id = img.id();
    let title = title.into();
    let media = projected_image_to_ui(img, &title);
    let download_url = match img {
        ProjectedImage::Clear { url, .. } => Some(url.clone()),
        ProjectedImage::Spoiler { reveal_url, .. } => Some(reveal_url.clone()),
        ProjectedImage::Locked { .. } => None,
    };
    ViewerItem {
        id,
        kind: GalleryMediaKind::Image,
        title: if title.is_empty() {
            format!("#{id}")
        } else {
            title
        },
        media,
        details_href: (!img.is_locked()).then(|| format!("/details/{id}?mode=similar&q={id}&limit=50")),
        download_url,
        download_filename: None,
        liked,
    }
}

pub fn unlock_href_for_mask(mask: &GalleryMask) -> &'static str {
    if mask.requires_login {
        "/user/login"
    } else {
        "/user/account"
    }
}

/// Navigate the browser top-level window to an external route (such as `/user/login`
/// or `/user/account` served by `user_worker`). No-op during SSR.
pub fn navigate_external(href: &str) {
    #[cfg(feature = "hydrate")]
    {
        if let Some(win) = web_sys::window() {
            let _ = win.location().set_href(href);
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = href;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT, parse_url_limit, parse_url_min_similarity,
    };

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

    #[test]
    fn parse_url_min_similarity_validates_range() {
        assert_eq!(parse_url_min_similarity(None), None);
        assert_eq!(parse_url_min_similarity(Some("0.0")), Some(0.0));
        assert_eq!(parse_url_min_similarity(Some("0.45")), Some(0.45));
        assert_eq!(parse_url_min_similarity(Some("1.0")), Some(1.0));
        assert_eq!(parse_url_min_similarity(Some("-0.1")), None);
        assert_eq!(parse_url_min_similarity(Some("1.2")), None);
        assert_eq!(parse_url_min_similarity(Some("NaN")), None);
    }
}
