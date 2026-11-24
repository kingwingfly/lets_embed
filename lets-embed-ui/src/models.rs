use serde::{Deserialize, Serialize};

/// Maximum Unicode character length accepted in user content report notes.
pub const MAX_REPORT_NOTE_CHARS: usize = 500;

/// Responsive masonry column density shared across `/`, `/details/:id`,
/// `/user/favorites`, and `Lightbox` albums.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Density {
    Compact,
    #[default]
    Medium,
    Large,
}

impl Density {
    pub const ALL: [Self; 3] = [Self::Compact, Self::Medium, Self::Large];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Compact => "Compact",
            Self::Medium => "Medium",
            Self::Large => "Large",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "compact" => Some(Self::Compact),
            "medium" => Some(Self::Medium),
            "large" => Some(Self::Large),
            _ => None,
        }
    }

    pub const fn target_width(self) -> f64 {
        match self {
            Self::Compact => 200.0,
            Self::Medium => 300.0,
            Self::Large => 440.0,
        }
    }

    pub const fn desktop_bounds(self) -> (usize, usize) {
        match self {
            Self::Compact => (3, 12),
            Self::Medium => (2, 8),
            Self::Large => (1, 6),
        }
    }

    /// Responsive masonry column count.
    ///
    /// Guarantees distinct mobile column counts (`<= 540px`):
    /// `Compact = 3`, `Medium = 2`, `Large = 1`.
    pub fn column_count(self, width: f64) -> usize {
        if width <= 0.0 || width <= 540.0 {
            return match self {
                Self::Compact => 3,
                Self::Medium => 2,
                Self::Large => 1,
            };
        }
        let (min_cols, max_cols) = self.desktop_bounds();
        ((width / self.target_width()).round() as usize).clamp(min_cols, max_cols)
    }
}

/// Visual preset illustration for masked/locked/spoiler content cards.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GalleryMaskPreset {
    R18,
    Blood,
    Sensitive,
    #[default]
    Custom,
}

impl GalleryMaskPreset {
    pub const ALL: [Self; 4] = [Self::R18, Self::Sensitive, Self::Blood, Self::Custom];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R18 => "r18",
            Self::Blood => "blood",
            Self::Sensitive => "sensitive",
            Self::Custom => "custom",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::R18 => "NSFW / Adult & Explicit",
            Self::Blood => "Extreme / Gore & Illegal",
            Self::Sensitive => "Sensitive / Niche Themes",
            Self::Custom => "Restricted Content",
        }
    }

    pub const fn short_badge(self) -> &'static str {
        match self {
            Self::R18 => "18+",
            Self::Blood => "Extreme",
            Self::Sensitive => "Sensitive",
            Self::Custom => "Restricted",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "r18" | "r-18" | "nsfw" | "explicit" => Self::R18,
            "blood" | "gore" | "violence" | "extreme" | "illegal" => Self::Blood,
            "sensitive" | "suggestive" | "ecchi" | "niche" => Self::Sensitive,
            _ => Self::Custom,
        }
    }
}

/// Blur strategy applied to [`GalleryMedia::Spoiler`] items.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GalleryBlurMode {
    /// Server-side blurred preview (`preview_url` is a blurred rendition; clear
    /// `reveal_url` is never rendered in DOM until user explicitly clicks reveal).
    #[default]
    ServerTransform,
    /// Voluntary client CSS blur over `preview_url` with warning chip.
    CssCourtesy,
}

/// Lock metadata for [`GalleryMedia::Locked`] items.
///
/// Intentionally carries zero URLs or file paths so locked records can never leak
/// media endpoints during SSR or CSR rendering.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GalleryMask {
    pub rule_id: String,
    pub label: String,
    #[serde(default)]
    pub preset: GalleryMaskPreset,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub requires_login: bool,
    #[serde(default)]
    pub requires_age: bool,
    #[serde(default)]
    pub requires_terms: bool,
    #[serde(default)]
    pub cta_label: Option<String>,
}

impl GalleryMask {
    /// Human-readable explanation describing why the item is locked.
    pub fn resolved_reason(&self) -> String {
        if let Some(reason) = self.reason.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            return reason.to_string();
        }
        let mut reqs: Vec<&'static str> = Vec::new();
        if self.requires_login {
            reqs.push("sign in");
        }
        if self.requires_age {
            reqs.push("18+ verification");
        }
        if self.requires_terms {
            reqs.push("Terms acceptance");
        }
        if reqs.is_empty() {
            "Hidden by content safety filter.".to_string()
        } else {
            format!("Requires {} to view.", reqs.join(" & "))
        }
    }

    /// Label rendered inside the unlock call-to-action button.
    ///
    /// - When `cta_label` is `Some(explicit)`: returns `explicit.trim().to_string()` (so
    ///   `Some("")` cleanly suppresses the CTA button for permanently blocked items).
    /// - When `cta_label` is `None`: resolves deterministically from missing requirements.
    pub fn resolved_cta(&self) -> String {
        if let Some(cta) = self.cta_label.as_deref() {
            return cta.trim().to_string();
        }
        if self.requires_login {
            "Sign in to unlock".to_string()
        } else if self.requires_age {
            "Confirm 18+ to unlock".to_string()
        } else if self.requires_terms {
            "Accept Terms to unlock".to_string()
        } else {
            "Enable in Account Settings".to_string()
        }
    }

    /// Resolved CTA label, or `None` when explicitly suppressed (e.g. `cta_label: Some("")`).
    pub fn resolved_cta_opt(&self) -> Option<String> {
        let cta = self.resolved_cta();
        (!cta.is_empty()).then_some(cta)
    }
}

/// Kind of underlying media asset inside a tile or viewer slide.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GalleryMediaKind {
    #[default]
    Image,
    Video,
}

/// Projected visibility state of an image or video asset.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GalleryMedia {
    Clear {
        id: i64,
        #[serde(default)]
        kind: GalleryMediaKind,
        width: i32,
        height: i32,
        url: String,
        #[serde(default)]
        alt: String,
        #[serde(default)]
        duration_secs: Option<i32>,
    },
    Spoiler {
        id: i64,
        #[serde(default)]
        kind: GalleryMediaKind,
        width: i32,
        height: i32,
        preview_url: String,
        reveal_url: String,
        #[serde(default)]
        alt: String,
        #[serde(default)]
        duration_secs: Option<i32>,
        rule_id: String,
        label: String,
        #[serde(default)]
        preset: GalleryMaskPreset,
        #[serde(default)]
        blur_mode: GalleryBlurMode,
    },
    /// Locked media carries zero URLs, zero filenames, and zero capability tokens.
    Locked {
        id: i64,
        #[serde(default)]
        kind: GalleryMediaKind,
        width: i32,
        height: i32,
        mask: GalleryMask,
    },
}

impl GalleryMedia {
    pub const fn id(&self) -> i64 {
        match self {
            Self::Clear { id, .. } | Self::Spoiler { id, .. } | Self::Locked { id, .. } => *id,
        }
    }

    pub const fn kind(&self) -> GalleryMediaKind {
        match self {
            Self::Clear { kind, .. } | Self::Spoiler { kind, .. } | Self::Locked { kind, .. } => {
                *kind
            }
        }
    }

    /// Natural `(width, height)` clamped to a sensible positive fallback so
    /// aspect-ratio boxes never collapse or divide by zero.
    pub const fn dimensions(&self) -> (i32, i32) {
        let (w, h, kind) = match self {
            Self::Clear {
                width,
                height,
                kind,
                ..
            }
            | Self::Spoiler {
                width,
                height,
                kind,
                ..
            }
            | Self::Locked {
                width,
                height,
                kind,
                ..
            } => (*width, *height, *kind),
        };
        if w > 0 && h > 0 {
            (w, h)
        } else {
            match kind {
                GalleryMediaKind::Video => (16, 9),
                GalleryMediaKind::Image => (4, 3),
            }
        }
    }

    pub fn height_over_width(&self) -> f64 {
        let (w, h) = self.dimensions();
        (f64::from(h) / f64::from(w)).clamp(0.25, 4.0)
    }

    pub const fn is_locked(&self) -> bool {
        matches!(self, Self::Locked { .. })
    }

    pub const fn is_spoiler(&self) -> bool {
        matches!(self, Self::Spoiler { .. })
    }

    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear { .. })
    }

    pub const fn duration_secs(&self) -> Option<i32> {
        match self {
            Self::Clear { duration_secs, .. } | Self::Spoiler { duration_secs, .. } => {
                *duration_secs
            }
            Self::Locked { .. } => None,
        }
    }
}

/// Top-level card entity type in [`MasonryGallery`](crate::components::MasonryGallery).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GalleryCardKind {
    Post,
    #[default]
    Image,
    Video,
}

impl GalleryCardKind {
    pub const fn like_kind(self) -> LikeTargetKind {
        match self {
            Self::Post => LikeTargetKind::Post,
            Self::Image => LikeTargetKind::Image,
            Self::Video => LikeTargetKind::Video,
        }
    }

    pub const fn report_kind(self) -> ReportTargetKind {
        match self {
            Self::Post => ReportTargetKind::Post,
            Self::Image => ReportTargetKind::Image,
            Self::Video => ReportTargetKind::Video,
        }
    }
}

/// Unified gallery tile view-model supporting post-cover albums and flat
/// image/video/favorite lists.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GalleryCard {
    /// Stable unique DOM key for reactive lists (e.g. `"post:42"`, `"image:99"`).
    pub key: String,
    pub id: i64,
    #[serde(default)]
    pub kind: GalleryCardKind,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub subtitle: Option<String>,
    pub media: GalleryMedia,
    #[serde(default)]
    pub image_count: usize,
    #[serde(default)]
    pub video_count: usize,
    #[serde(default)]
    pub details_href: Option<String>,
    /// Current favorite state (`None` hides the like button unless a callback is supplied).
    #[serde(default)]
    pub liked: Option<bool>,
}

impl GalleryCard {
    /// Compact album badge string (`"12p 2v"`, `"8p"`, `"1v"`, or `None`).
    pub fn media_badge(&self) -> Option<String> {
        if self.kind != GalleryCardKind::Post {
            return None;
        }
        match (self.image_count > 0, self.video_count > 0) {
            (true, true) => Some(format!("{}p {}v", self.image_count, self.video_count)),
            (true, false) => Some(format!("{}p", self.image_count)),
            (false, true) => Some(format!("{}v", self.video_count)),
            (false, false) => None,
        }
    }

    pub const fn dimensions(&self) -> (i32, i32) {
        self.media.dimensions()
    }

    pub fn masonry_ratio(&self) -> f64 {
        let extra = if self.kind == GalleryCardKind::Post {
            0.08
        } else {
            0.04
        };
        self.media.height_over_width() + extra
    }
}

/// Author chip rendered inside [`Lightbox`](crate::components::Lightbox) headers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorChip {
    pub name: String,
    #[serde(default)]
    pub href: Option<String>,
}

/// Post album view-model rendered by [`Lightbox`](crate::components::Lightbox).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LightboxAlbum {
    pub post_id: i64,
    pub title: String,
    #[serde(default)]
    pub authors: Vec<AuthorChip>,
    #[serde(default)]
    pub images: Vec<GalleryCard>,
    #[serde(default)]
    pub videos: Vec<GalleryMedia>,
    #[serde(default)]
    pub total_images: usize,
    #[serde(default)]
    pub total_videos: usize,
    #[serde(default)]
    pub liked: Option<bool>,
    #[serde(default)]
    pub loading: bool,
    #[serde(default)]
    pub error: Option<String>,
}

impl LightboxAlbum {
    pub fn effective_total_images(&self) -> usize {
        self.total_images.max(self.images.len())
    }

    pub fn effective_total_videos(&self) -> usize {
        self.total_videos.max(self.videos.len())
    }
}

/// Single media slide inside the fullscreen [`Viewer`](crate::components::Viewer).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ViewerItem {
    pub id: i64,
    #[serde(default)]
    pub kind: GalleryMediaKind,
    #[serde(default)]
    pub title: String,
    pub media: GalleryMedia,
    #[serde(default)]
    pub details_href: Option<String>,
    #[serde(default)]
    pub download_url: Option<String>,
    #[serde(default)]
    pub download_filename: Option<String>,
    #[serde(default)]
    pub liked: Option<bool>,
}

impl ViewerItem {
    /// Convert a [`GalleryCard`] into a [`ViewerItem`].
    pub fn from_card(card: &GalleryCard) -> Self {
        let download_url = match &card.media {
            GalleryMedia::Clear { url, .. } => Some(url.clone()),
            GalleryMedia::Spoiler { reveal_url, .. } => Some(reveal_url.clone()),
            GalleryMedia::Locked { .. } => None,
        };
        Self {
            id: card.media.id(),
            kind: card.media.kind(),
            title: if card.title.is_empty() {
                format!("#{}", card.media.id())
            } else {
                card.title.clone()
            },
            media: card.media.clone(),
            details_href: if card.media.is_locked() {
                None
            } else {
                card.details_href.clone()
            },
            download_url,
            download_filename: None,
            liked: card.liked,
        }
    }

    /// Download URL only when the underlying media is allowed to be viewed
    /// (never for `Locked`, and never for unrevealed `Spoiler`).
    pub fn effective_download_url(&self, spoiler_revealed: bool) -> Option<&str> {
        match &self.media {
            GalleryMedia::Clear { url, .. } => {
                self.download_url.as_deref().or(Some(url.as_str()))
            }
            GalleryMedia::Spoiler { reveal_url, .. } if spoiler_revealed => {
                self.download_url.as_deref().or(Some(reveal_url.as_str()))
            }
            GalleryMedia::Spoiler { .. } | GalleryMedia::Locked { .. } => None,
        }
    }
}

/// Entity kind for [`LikeButton`](crate::components::LikeButton).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LikeTargetKind {
    #[default]
    Image,
    Post,
    Video,
}

impl LikeTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Post => "post",
            Self::Video => "video",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Image => "Image",
            Self::Post => "Post",
            Self::Video => "Video",
        }
    }

    pub const fn filled_icon(self) -> &'static str {
        match self {
            Self::Post => "\u{2605}",
            Self::Image | Self::Video => "\u{2665}",
        }
    }

    pub const fn outline_icon(self) -> &'static str {
        match self {
            Self::Post => "\u{2606}",
            Self::Image | Self::Video => "\u{2661}",
        }
    }
}

/// Visual style of [`LikeButton`](crate::components::LikeButton).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LikeVariant {
    #[default]
    Inline,
    Card,
    Overlay,
}

/// Option item for [`SkySelect`](crate::components::SkySelect).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectOption {
    pub value: String,
    pub label: String,
    #[serde(default)]
    pub disabled: bool,
}

impl SelectOption {
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            disabled: false,
        }
    }

    pub const fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }
}

/// Visual variant of [`SkySelect`](crate::components::SkySelect).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SelectVariant {
    SearchPill,
    #[default]
    SkyBox,
    IndigoBox,
}

/// Target kind for [`ReportDialog`](crate::components::ReportDialog).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportTargetKind {
    #[default]
    Image,
    Post,
    Video,
}

impl ReportTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Post => "post",
            Self::Video => "video",
        }
    }
}

/// Strict allowlist of user report reasons accepted by `/user/api/report`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportReason {
    IllegalContent,
    Underage,
    NonConsensual,
    ViolenceGore,
    CopyrightDmca,
    #[default]
    MisclassifiedSafety,
    SpamOther,
}

impl ReportReason {
    pub const ALL: [Self; 7] = [
        Self::MisclassifiedSafety,
        Self::IllegalContent,
        Self::Underage,
        Self::NonConsensual,
        Self::ViolenceGore,
        Self::CopyrightDmca,
        Self::SpamOther,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IllegalContent => "illegal_content",
            Self::Underage => "underage",
            Self::NonConsensual => "non_consensual",
            Self::ViolenceGore => "violence_gore",
            Self::CopyrightDmca => "copyright_dmca",
            Self::MisclassifiedSafety => "misclassified_safety",
            Self::SpamOther => "spam_other",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::IllegalContent => "Illegal or prohibited content",
            Self::Underage => "Suspected underage / CSAM",
            Self::NonConsensual => "Non-consensual or private imagery",
            Self::ViolenceGore => "Extreme violence / gore",
            Self::CopyrightDmca => "Copyright / DMCA removal",
            Self::MisclassifiedSafety => "Missing NSFW / safety label",
            Self::SpamOther => "Spam or other policy issue",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "illegal_content" => Some(Self::IllegalContent),
            "underage" => Some(Self::Underage),
            "non_consensual" => Some(Self::NonConsensual),
            "violence_gore" => Some(Self::ViolenceGore),
            "copyright_dmca" => Some(Self::CopyrightDmca),
            "misclassified_safety" => Some(Self::MisclassifiedSafety),
            "spam_other" => Some(Self::SpamOther),
            _ => None,
        }
    }

    pub fn select_options() -> Vec<SelectOption> {
        Self::ALL
            .iter()
            .map(|r| SelectOption::new(r.as_str(), r.label()))
            .collect()
    }
}

/// Payload emitted when a user submits [`ReportDialog`](crate::components::ReportDialog).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSubmission {
    pub target_kind: ReportTargetKind,
    pub target_id: i64,
    pub reason: ReportReason,
    /// User-supplied note, always trimmed and capped to [`MAX_REPORT_NOTE_CHARS`].
    pub note: String,
}

/// Content rendered inside [`NoticeBanner`](crate::components::NoticeBanner).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoticeContent {
    /// Escaped plain text (safe default).
    Text(String),
    /// Pre-sanitized HTML rendered directly.
    ///
    /// # Security Warning
    /// Callers MUST ONLY pass HTML that has been sanitized server-side through
    /// a strict allowlist (such as `ammonia`). Never construct this variant
    /// from untrusted user input or unsanitized Markdown.
    ///
    /// Marked `#[serde(skip_deserializing)]` so untrusted JSON can never
    /// deserialize directly into `inner_html`.
    #[serde(skip_deserializing)]
    PreSanitizedHtml(String),
}

impl Default for NoticeContent {
    fn default() -> Self {
        Self::Text(String::new())
    }
}

impl From<String> for NoticeContent {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for NoticeContent {
    fn from(value: &str) -> Self {
        Self::Text(value.to_string())
    }
}

/// Visual tone for [`NoticeBanner`](crate::components::NoticeBanner).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeTone {
    #[default]
    Info,
    Warning,
    Danger,
    Success,
}

impl NoticeTone {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Danger => "danger",
            Self::Success => "success",
        }
    }
}

/// Enforcement mode for a content safety rule in [`QueryRuleBuilder`](crate::components::QueryRuleBuilder).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    /// Hard-gated switcher requiring unlock / auth / age verification.
    #[default]
    Switcher,
    /// Click-to-reveal spoiler blur.
    SpoilerBlur,
}

impl RuleMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Switcher => "switcher",
            Self::SpoilerBlur => "spoiler_blur",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Switcher => "Switcher (Locked)",
            Self::SpoilerBlur => "Spoiler Blur",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim() {
            "spoiler_blur" | "blur" | "spoiler" => Self::SpoilerBlur,
            _ => Self::Switcher,
        }
    }
}

/// Top-level boolean connector in [`QueryRuleBuilder`](crate::components::QueryRuleBuilder).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleConnector {
    #[default]
    And,
    Or,
    Not,
}

impl RuleConnector {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::And => "and",
            Self::Or => "or",
            Self::Not => "not",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "or" => Self::Or,
            "not" => Self::Not,
            _ => Self::And,
        }
    }
}

/// Inner combinator for parenthesized rule groups `( ... )`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleGroupCombinator {
    #[default]
    Or,
    And,
}

impl RuleGroupCombinator {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Or => "or",
            Self::And => "and",
        }
    }
}

/// Allowed metadata-only predicates in the safety rule grammar.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleField {
    #[default]
    Tag,
    PostTag,
    Author,
    Unclassified,
}

impl RuleField {
    pub const ALL: [Self; 4] = [Self::Tag, Self::PostTag, Self::Author, Self::Unclassified];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tag => "tag",
            Self::PostTag => "post_tag",
            Self::Author => "author",
            Self::Unclassified => "unclassified",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Tag => "WD Tag (tag:)",
            Self::PostTag => "Post Tag (post_tag:)",
            Self::Author => "Author (author:)",
            Self::Unclassified => "Unclassified",
        }
    }

    pub const fn placeholder(self) -> &'static str {
        match self {
            Self::Tag => "canonical_wd_tag (e.g. explicit)",
            Self::PostTag => "canonical post tag…",
            Self::Author => "exact author name…",
            Self::Unclassified => "Matches pending / untagged media",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "tag" => Some(Self::Tag),
            "post_tag" => Some(Self::PostTag),
            "author" => Some(Self::Author),
            "unclassified" => Some(Self::Unclassified),
            _ => None,
        }
    }

    pub fn select_options() -> Vec<SelectOption> {
        Self::ALL
            .iter()
            .map(|f| SelectOption::new(f.as_str(), f.label()))
            .collect()
    }
}

/// Single metadata predicate row inside [`QueryRuleBuilder`](crate::components::QueryRuleBuilder).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleClause {
    pub id: u64,
    #[serde(default)]
    pub negated: bool,
    #[serde(default)]
    pub field: RuleField,
    #[serde(default)]
    pub value: String,
    /// Optional WD-Tagger minimum confidence threshold (`0.0..=1.0`), serialized as `>=0.45`.
    #[serde(default)]
    pub min_score: Option<f32>,
}

/// Either a standalone clause or a parenthesized boolean group `( ... )`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RuleBlockKind {
    Clause(RuleClause),
    Group {
        combinator: RuleGroupCombinator,
        clauses: Vec<RuleClause>,
    },
}

/// Top-level visual builder entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleBlock {
    pub id: u64,
    #[serde(default)]
    pub connector: RuleConnector,
    pub kind: RuleBlockKind,
}

/// Editable content safety rule draft bound to [`QueryRuleBuilder`](crate::components::QueryRuleBuilder).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleDraft {
    pub name: String,
    #[serde(default)]
    pub mode: RuleMode,
    #[serde(default)]
    pub preset: GalleryMaskPreset,
    #[serde(default)]
    pub requires_age: bool,
    #[serde(default)]
    pub blocks: Vec<RuleBlock>,
    /// Canonical safety-rule query string kept in sync with `blocks`.
    #[serde(default)]
    pub query: String,
}

impl Default for RuleDraft {
    fn default() -> Self {
        Self {
            name: String::new(),
            mode: RuleMode::Switcher,
            preset: GalleryMaskPreset::Custom,
            requires_age: false,
            blocks: vec![RuleBlock {
                id: 1,
                connector: RuleConnector::And,
                kind: RuleBlockKind::Clause(RuleClause {
                    id: 2,
                    negated: false,
                    field: RuleField::Tag,
                    value: String::new(),
                    min_score: Some(0.45),
                }),
            }],
            query: String::new(),
        }
    }
}

/// Predefined WD-Tagger rule template button rendered in [`QueryRuleBuilder`](crate::components::QueryRuleBuilder).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetTemplate {
    pub id: String,
    pub label: String,
    pub description: String,
    pub default_mode: RuleMode,
    pub preset: GalleryMaskPreset,
    pub requires_age: bool,
    pub query: String,
}

impl PresetTemplate {
    /// Built-in WD-Tagger safety presets verified against canonical tag vocabulary.
    ///
    /// Exactly 3 presets using compact single-row `tag IN (...) >= 0.45` syntax so each
    /// preset produces one clean multi-chip `WD Tag in [...]` condition card:
    /// 1. `r18` — NSFW / Adult & Explicit (sexual, nudity, exposure, adult content)
    /// 2. `sensitive` — Sensitive / Niche Themes (childlike, TS/femboy/futa, elderly, SM/BDSM, niche fetishes)
    /// 3. `blood` — Extreme / Gore & Illegal (bloody, gore, kill, severe violence, self-harm, illegal — hard blocked)
    pub fn builtins() -> Vec<Self> {
        vec![
            Self {
                id: "r18".to_string(),
                label: "NSFW / Adult & Explicit".to_string(),
                description: "Sexual, explicit, nudity, and adult exposure content.".to_string(),
                default_mode: RuleMode::Switcher,
                preset: GalleryMaskPreset::R18,
                requires_age: true,
                query: search_types::PRESET_R18_QUERY.to_string(),
            },
            Self {
                id: "sensitive".to_string(),
                label: "Sensitive / Niche Themes".to_string(),
                description: "Childlike, TS/femboy/futa, elderly, moderate-to-heavy SM/BDSM, and niche fetish themes.".to_string(),
                default_mode: RuleMode::SpoilerBlur,
                preset: GalleryMaskPreset::Sensitive,
                requires_age: true,
                query: search_types::PRESET_SENSITIVE_QUERY.to_string(),
            },
            Self {
                id: "blood".to_string(),
                label: "Extreme / Gore & Illegal".to_string(),
                description: "Hard-blocked gore, bloody violence, killing, self-harm, non-consensual, and illegal content.".to_string(),
                default_mode: RuleMode::Switcher,
                preset: GalleryMaskPreset::Blood,
                requires_age: false,
                query: search_types::PRESET_EXTREME_QUERY.to_string(),
            },
        ]
    }
}

/// Visual variant for [`FloatingHeader`](crate::components::FloatingHeader).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum HeaderVariant {
    /// Top site navigation card (`.floating-nav-card`).
    #[default]
    Nav,
    /// Sticky gallery sub-toolbar (`.gallery-floating-bar`).
    Toolbar,
}
