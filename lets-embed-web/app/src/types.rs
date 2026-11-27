use leptos::prelude::{GetUntracked, RwSignal, Set};
use lets_embed_ui::{
    Density, GalleryCard, GalleryCardKind, GalleryMask, GalleryMaskPreset, GalleryMedia,
    GalleryMediaKind, ReportTargetKind, ViewerItem,
};
use search_types::{
    Author, MaskMetadata, PlaceholderPreset, Post, ProjectedImage, ProjectedVideo, Tag,
};
use serde::{Deserialize, Serialize};
use site_access::{AgeGateTrigger, AgeVerificationPolicy};

/// Reserved marker emitted in `MaskMetadata::matched_policy_ids` when a
/// placeholder restriction has no user self-service unlock path.
pub use search_types::MASK_NO_UNLOCK_MARKER;

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

/// App-root context tracking whether the main gallery `<Results>` is currently
/// executing a new page-0 query (drives header progress bar and Search button spinner).
#[derive(Clone, Copy)]
pub struct SearchStatusState(pub RwSignal<bool>);

impl SearchStatusState {
    pub fn new() -> Self {
        Self(RwSignal::new(false))
    }
}

impl Default for SearchStatusState {
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

/// Public UI configuration hydrated from the pinned Policy v3 server snapshot.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SiteUiConfig {
    pub is_managed: bool,
    pub safety_enabled: bool,
    pub default_dinov3_min: f32,
    pub default_siglip2_min: f32,
    pub notice_banner_enabled: bool,
    pub notice_banner_html: Option<String>,
    pub notice_banner_key: String,
    pub rta_meta_enabled: bool,
    pub noindex_restricted: bool,
    #[serde(default)]
    pub age_policy: AgeVerificationPolicy,
    #[serde(default)]
    pub age_gate_trigger: AgeGateTrigger,
    #[serde(default)]
    pub caller_authenticated: bool,
    #[serde(default)]
    pub caller_age_verified: bool,
    #[serde(default)]
    pub caller_terms_accepted: bool,
}

/// Pending report dialog target `(kind, id, label)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportTarget {
    pub kind: ReportTargetKind,
    pub id: i64,
    pub label: String,
}

/// Shared client-side Policy v3 safety invalidation epochs, similarity defaults,
/// age-gate modal state, and report dialog trigger provided at the `<App/>` root.
#[derive(Clone, Copy)]
pub struct SafetyUiState {
    /// Bumped on logout / account switch / opt-out / policy change via `BroadcastChannel`
    /// so revealed blurred cards, viewers, and lightboxes wipe DOM media immediately.
    pub invalidation_epoch: RwSignal<u64>,
    /// Bumped whenever cross-tab safety/session state changes so active galleries
    /// discard stale in-flight fetches and reload fresh server projections.
    pub reload_epoch: RwSignal<u64>,
    pub is_managed: RwSignal<bool>,
    pub safety_enabled: RwSignal<bool>,
    pub default_dinov3_min: RwSignal<f32>,
    pub default_siglip2_min: RwSignal<f32>,
    pub notice_banner_enabled: RwSignal<bool>,
    pub notice_banner_html: RwSignal<Option<String>>,
    pub notice_banner_key: RwSignal<String>,
    pub age_policy: RwSignal<AgeVerificationPolicy>,
    pub age_gate_trigger: RwSignal<AgeGateTrigger>,
    pub caller_authenticated: RwSignal<bool>,
    pub caller_age_verified: RwSignal<bool>,
    pub caller_terms_accepted: RwSignal<bool>,
    pub age_gate_open: RwSignal<bool>,
    /// True when `<AgeGateModal>` was triggered from a locked card's `"Confirm 18+ to unlock"`
    /// CTA rather than an automatic site-wide splash.
    pub age_gate_from_card: RwSignal<bool>,
    pub report_target: RwSignal<Option<ReportTarget>>,
}

impl SafetyUiState {
    pub fn new() -> Self {
        Self {
            invalidation_epoch: RwSignal::new(0),
            reload_epoch: RwSignal::new(0),
            is_managed: RwSignal::new(false),
            safety_enabled: RwSignal::new(false),
            default_dinov3_min: RwSignal::new(0.0),
            default_siglip2_min: RwSignal::new(0.0),
            notice_banner_enabled: RwSignal::new(false),
            notice_banner_html: RwSignal::new(None),
            notice_banner_key: RwSignal::new(String::new()),
            age_policy: RwSignal::new(AgeVerificationPolicy::Off),
            age_gate_trigger: RwSignal::new(AgeGateTrigger::Off),
            caller_authenticated: RwSignal::new(false),
            caller_age_verified: RwSignal::new(false),
            caller_terms_accepted: RwSignal::new(false),
            age_gate_open: RwSignal::new(false),
            age_gate_from_card: RwSignal::new(false),
            report_target: RwSignal::new(None),
        }
    }

    pub fn apply_site_config(&self, cfg: &SiteUiConfig) {
        self.is_managed.set(cfg.is_managed);
        self.safety_enabled.set(cfg.safety_enabled);
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
        // Update key & HTML before flipping `notice_banner_enabled` so NoticeBanner
        // mounts directly with the final dismiss key and sanitized content.
        self.notice_banner_key.set(cfg.notice_banner_key.clone());
        self.notice_banner_html.set(cfg.notice_banner_html.clone());
        self.notice_banner_enabled.set(cfg.notice_banner_enabled);
        self.age_policy.set(cfg.age_policy);
        self.age_gate_trigger.set(cfg.age_gate_trigger);
        self.caller_authenticated.set(cfg.caller_authenticated);
        self.caller_age_verified.set(cfg.caller_age_verified);
        self.caller_terms_accepted.set(cfg.caller_terms_accepted);
    }

    pub fn open_age_gate_from_card(&self) {
        self.age_gate_from_card.set(true);
        self.age_gate_open.set(true);
    }

    pub fn open_age_gate_site_wide(&self) {
        self.age_gate_from_card.set(false);
        self.age_gate_open.set(true);
    }

    pub fn close_age_gate(&self) {
        self.age_gate_open.set(false);
        self.age_gate_from_card.set(false);
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
/// Whenever `image` is NOT `ProjectedImage::Clear` (`Placeholder` or `Blurred`),
/// `tags` is withheld (empty) and `og_image_allowed` is `false`.
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
// Conversion helpers between Policy v3 `search_types::Projected*` and `lets-embed-ui`
// ---------------------------------------------------------------------------

pub const fn preset_to_ui(preset: PlaceholderPreset) -> GalleryMaskPreset {
    match preset {
        PlaceholderPreset::R18 => GalleryMaskPreset::R18,
        PlaceholderPreset::Blood => GalleryMaskPreset::Blood,
        PlaceholderPreset::Sensitive => GalleryMaskPreset::Sensitive,
        PlaceholderPreset::Custom => GalleryMaskPreset::Custom,
    }
}

pub fn mask_has_no_unlock_path(mask: &MaskMetadata) -> bool {
    mask.has_no_unlock_path()
}

pub fn mask_to_ui(mask: &MaskMetadata) -> GalleryMask {
    let no_unlock = mask_has_no_unlock_path(mask);
    GalleryMask {
        rule_id: mask.policy_id.clone(),
        label: mask.label.clone(),
        preset: preset_to_ui(mask.preset),
        reason: if no_unlock {
            if mask.policy_id == "unclassified" || mask.label.starts_with("Pending classification") {
                Some("Waiting for automated content classification.".to_string())
            } else {
                Some("Restricted by site content policy.".to_string())
            }
        } else {
            None
        },
        requires_login: !no_unlock && mask.requires_login,
        requires_age: !no_unlock && mask.requires_age,
        requires_terms: !no_unlock && mask.requires_terms,
        cta_label: no_unlock.then(String::new),
    }
}

/// Full trimmed name of a `ProjectedImage::Clear` when non-empty.
/// Always returns `None` for empty names, `Blurred`, and `Placeholder` (Policy v3 invariant).
pub fn image_full_name(im: &ProjectedImage) -> Option<&str> {
    match im {
        ProjectedImage::Clear {
            name: Some(raw), ..
        } => {
            let trimmed = raw.trim();
            (!trimmed.is_empty()).then_some(trimmed)
        }
        _ => None,
    }
}

/// Display-friendly image name: basename after the last `/` (trimmed if non-empty),
/// falling back to the full trimmed name. Always returns `None` for empty, `Blurred`,
/// and `Placeholder`.
pub fn image_display_name(im: &ProjectedImage) -> Option<&str> {
    let full = image_full_name(im)?;
    let base = full
        .rsplit('/')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    Some(base.unwrap_or(full))
}

/// Primary card/UI label for a `ProjectedImage`: its display name when available,
/// falling back to `#{id}`.
pub fn image_card_label(im: &ProjectedImage) -> String {
    image_display_name(im)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("#{}", im.id()))
}

/// Tooltip text for an image label: `"{full_name} (#{id})"` when named, else `#{id}`.
pub fn image_card_tooltip(im: &ProjectedImage) -> String {
    let id = im.id();
    match image_full_name(im) {
        Some(full) => format!("{full} (#{id})"),
        None => format!("#{id}"),
    }
}

pub fn projected_image_to_ui(img: &ProjectedImage, fallback_alt: impl Into<String>) -> GalleryMedia {
    let fallback_alt = fallback_alt.into();
    match img {
        ProjectedImage::Clear {
            id,
            url,
            width,
            height,
            ..
        } => GalleryMedia::Clear {
            id: *id,
            kind: GalleryMediaKind::Image,
            width: *width,
            height: *height,
            url: url.clone(),
            alt: image_display_name(img)
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
        // Policy v3 NEVER pre-mints a clear `reveal_url`; `Blurred` cards render through
        // `BlurredMediaCard` (explicit `POST /api/safety/reveal`) and map safely to `Locked`
        // in generic UI containers.
        ProjectedImage::Blurred {
            id,
            width,
            height,
            matched_policy_ids,
            label,
            preset,
            ..
        } => GalleryMedia::Locked {
            id: *id,
            kind: GalleryMediaKind::Image,
            width: *width,
            height: *height,
            mask: GalleryMask {
                rule_id: matched_policy_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "blur".to_string()),
                label: label.clone(),
                preset: preset_to_ui(*preset),
                reason: Some("Blurred by safety policy.".to_string()),
                requires_login: false,
                requires_age: false,
                requires_terms: false,
                cta_label: None,
            },
        },
        ProjectedImage::Placeholder {
            id,
            width,
            height,
            mask,
            ..
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
        ProjectedVideo::Blurred {
            id,
            width,
            height,
            matched_policy_ids,
            label,
            preset,
            ..
        } => GalleryMedia::Locked {
            id: *id,
            kind: GalleryMediaKind::Video,
            width: *width,
            height: *height,
            mask: GalleryMask {
                rule_id: matched_policy_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "blur".to_string()),
                label: label.clone(),
                preset: preset_to_ui(*preset),
                reason: Some("Blurred by safety policy.".to_string()),
                requires_login: false,
                requires_age: false,
                requires_terms: false,
                cta_label: None,
            },
        },
        ProjectedVideo::Placeholder {
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
    let raw_title = title.into();
    let resolved_title = if !raw_title.trim().is_empty() {
        raw_title
    } else {
        image_card_label(img)
    };
    let media = projected_image_to_ui(img, &resolved_title);
    GalleryCard {
        key: format!("image:{id}"),
        id,
        kind: GalleryCardKind::Image,
        title: resolved_title,
        subtitle: None,
        media,
        image_count: 0,
        video_count: 0,
        details_href: (!img.is_placeholder()).then(|| format!("/details/{id}")),
        liked,
    }
}

pub fn projected_image_to_viewer_item(
    img: &ProjectedImage,
    title: impl Into<String>,
    liked: Option<bool>,
) -> ViewerItem {
    let id = img.id();
    let raw_title = title.into();
    let resolved_title = if !raw_title.trim().is_empty() {
        raw_title
    } else {
        image_card_label(img)
    };
    let media = projected_image_to_ui(img, &resolved_title);
    let download_url = match img {
        ProjectedImage::Clear { url, .. } => Some(url.clone()),
        ProjectedImage::Blurred { .. } | ProjectedImage::Placeholder { .. } => None,
    };
    ViewerItem {
        id,
        kind: GalleryMediaKind::Image,
        title: resolved_title,
        media,
        details_href: (!img.is_placeholder())
            .then(|| format!("/details/{id}?mode=similar&q={id}&limit=50")),
        download_url,
        download_filename: None,
        liked,
    }
}

pub fn unlock_href_for_mask(mask: &GalleryMask) -> &'static str {
    if mask.requires_login {
        "/user/login"
    } else if mask.requires_age {
        "/user/account#age-confirm"
    } else if mask.requires_terms {
        "/user/account#terms"
    } else {
        "/user/account#content-safety"
    }
}

/// Handle a user click on a locked Placeholder card's unlock CTA:
/// - `requires_login` -> `/user/login`
/// - `requires_age` -> opens `<AgeGateModal>` right on `/` (for `SelfAttestation`), or
///   redirects to `/user/account#age-confirm` / `/user/login?next=/user/account%23age-confirm`
///   under strict OIDC age verification
/// - `requires_terms` -> `/user/account#terms`
/// - otherwise -> `/user/account#content-safety` (`"Enable in Account Settings"`)
pub fn handle_mask_unlock(mask: &GalleryMask, safety: Option<SafetyUiState>) {
    if mask.resolved_cta_opt().is_none() {
        return;
    }
    if mask.requires_login {
        navigate_external("/user/login");
        return;
    }
    if mask.requires_age {
        if let Some(s) = safety {
            if s.age_policy.get_untracked() != AgeVerificationPolicy::StrictProviderVerified18 {
                s.open_age_gate_from_card();
                return;
            }
            if s.caller_authenticated.get_untracked() {
                navigate_external("/user/account#age-confirm");
            } else {
                navigate_external("/user/login?next=/user/account%23age-confirm");
            }
            return;
        }
        navigate_external("/user/account#age-confirm");
        return;
    }
    navigate_external(unlock_href_for_mask(mask));
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
        DEFAULT_SEARCH_LIMIT, MASK_NO_UNLOCK_MARKER, MAX_SEARCH_LIMIT, image_card_label,
        image_card_tooltip, image_display_name, image_full_name, mask_to_ui, parse_url_limit,
        parse_url_min_similarity, projected_image_to_card, projected_image_to_viewer_item,
        unlock_href_for_mask,
    };
    use search_types::{MaskMetadata, PlaceholderPreset, ProjectedImage};

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

    #[test]
    fn mask_to_ui_and_unlock_href_distinguish_login_age_terms_settings_and_no_unlock() {
        let guest_mask = mask_to_ui(&MaskMetadata {
            policy_id: "r18".into(),
            matched_policy_ids: vec!["r18".into()],
            label: "NSFW".into(),
            preset: PlaceholderPreset::R18,
            requires_login: true,
            requires_age: true,
            requires_terms: true,
        });
        assert_eq!(guest_mask.resolved_cta_opt().as_deref(), Some("Sign in to unlock"));
        assert_eq!(unlock_href_for_mask(&guest_mask), "/user/login");

        let age_mask = mask_to_ui(&MaskMetadata {
            policy_id: "r18".into(),
            matched_policy_ids: vec!["r18".into()],
            label: "NSFW".into(),
            preset: PlaceholderPreset::R18,
            requires_login: false,
            requires_age: true,
            requires_terms: true,
        });
        assert_eq!(age_mask.resolved_cta_opt().as_deref(), Some("Confirm 18+ to unlock"));
        assert_eq!(unlock_href_for_mask(&age_mask), "/user/account#age-confirm");

        let terms_mask = mask_to_ui(&MaskMetadata {
            policy_id: "r18".into(),
            matched_policy_ids: vec!["r18".into()],
            label: "NSFW".into(),
            preset: PlaceholderPreset::R18,
            requires_login: false,
            requires_age: false,
            requires_terms: true,
        });
        assert_eq!(terms_mask.resolved_cta_opt().as_deref(), Some("Accept Terms to unlock"));
        assert_eq!(unlock_href_for_mask(&terms_mask), "/user/account#terms");

        let settings_mask = mask_to_ui(&MaskMetadata {
            policy_id: "r18".into(),
            matched_policy_ids: vec!["r18".into()],
            label: "NSFW".into(),
            preset: PlaceholderPreset::R18,
            requires_login: false,
            requires_age: false,
            requires_terms: false,
        });
        assert_eq!(
            settings_mask.resolved_cta_opt().as_deref(),
            Some("Enable in Account Settings")
        );
        assert_eq!(
            unlock_href_for_mask(&settings_mask),
            "/user/account#content-safety"
        );

        let no_unlock_mask = mask_to_ui(&MaskMetadata {
            policy_id: "staff_only".into(),
            matched_policy_ids: vec!["staff_only".into(), MASK_NO_UNLOCK_MARKER.into()],
            label: "Staff Only".into(),
            preset: PlaceholderPreset::Custom,
            requires_login: false,
            requires_age: false,
            requires_terms: false,
        });
        assert_eq!(no_unlock_mask.cta_label.as_deref(), Some(""));
        assert_eq!(no_unlock_mask.resolved_cta_opt(), None);
    }

    #[test]
    fn image_display_name_and_card_label_handle_paths_empty_and_restricted_variants() {
        let with_path = ProjectedImage::Clear {
            id: 10,
            url: "/images/a.webp".into(),
            name: Some("Album Title/by Author - photo 1".into()),
            width: 800,
            height: 600,
        };
        assert_eq!(image_display_name(&with_path), Some("by Author - photo 1"));
        assert_eq!(
            image_full_name(&with_path),
            Some("Album Title/by Author - photo 1")
        );
        assert_eq!(image_card_label(&with_path), "by Author - photo 1");
        assert_eq!(
            image_card_tooltip(&with_path),
            "Album Title/by Author - photo 1 (#10)"
        );

        let simple = ProjectedImage::Clear {
            id: 11,
            url: "/images/b.webp".into(),
            name: Some("  sunset_beach  ".into()),
            width: 800,
            height: 600,
        };
        assert_eq!(image_display_name(&simple), Some("sunset_beach"));
        assert_eq!(image_full_name(&simple), Some("sunset_beach"));
        assert_eq!(image_card_label(&simple), "sunset_beach");
        assert_eq!(image_card_tooltip(&simple), "sunset_beach (#11)");

        let trailing_slash = ProjectedImage::Clear {
            id: 12,
            url: "/images/c.webp".into(),
            name: Some("folder/".into()),
            width: 800,
            height: 600,
        };
        assert_eq!(image_display_name(&trailing_slash), Some("folder/"));
        assert_eq!(image_card_label(&trailing_slash), "folder/");

        let empty_name = ProjectedImage::Clear {
            id: 13,
            url: "/images/d.webp".into(),
            name: Some("   ".into()),
            width: 800,
            height: 600,
        };
        assert_eq!(image_display_name(&empty_name), None);
        assert_eq!(image_full_name(&empty_name), None);
        assert_eq!(image_card_label(&empty_name), "#13");
        assert_eq!(image_card_tooltip(&empty_name), "#13");

        let none_name = ProjectedImage::Clear {
            id: 14,
            url: "/images/e.webp".into(),
            name: None,
            width: 800,
            height: 600,
        };
        assert_eq!(image_display_name(&none_name), None);
        assert_eq!(image_card_label(&none_name), "#14");

        let blurred = ProjectedImage::Blurred {
            id: 15,
            preview_url: None,
            can_click_reveal: true,
            policy_rev: 1,
            matched_policy_ids: vec!["sensitive".into()],
            label: "Sensitive".into(),
            preset: PlaceholderPreset::Sensitive,
            width: 800,
            height: 600,
        };
        assert_eq!(image_display_name(&blurred), None);
        assert_eq!(image_full_name(&blurred), None);
        assert_eq!(image_card_label(&blurred), "#15");

        let placeholder = ProjectedImage::Placeholder {
            id: 16,
            policy_rev: 1,
            width: 800,
            height: 600,
            mask: MaskMetadata {
                policy_id: "r18".into(),
                matched_policy_ids: vec!["r18".into()],
                label: "NSFW".into(),
                preset: PlaceholderPreset::R18,
                requires_login: true,
                requires_age: false,
                requires_terms: false,
            },
        };
        assert_eq!(image_display_name(&placeholder), None);
        assert_eq!(image_card_label(&placeholder), "#16");

        // Card and viewer item helpers prefer image display name when caller title is empty.
        let card = projected_image_to_card(&with_path, "", None);
        assert_eq!(card.title, "by Author - photo 1");
        let explicit_card = projected_image_to_card(&with_path, "Custom Title", Some(true));
        assert_eq!(explicit_card.title, "Custom Title");
        let fallback_card = projected_image_to_card(&placeholder, "", None);
        assert_eq!(fallback_card.title, "#16");

        let viewer_item = projected_image_to_viewer_item(&with_path, "", None);
        assert_eq!(viewer_item.title, "by Author - photo 1");
        let fallback_viewer = projected_image_to_viewer_item(&blurred, "", None);
        assert_eq!(fallback_viewer.title, "#15");
    }
}
