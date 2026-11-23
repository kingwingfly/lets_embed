//! Shared pure-Leptos 0.8 gallery, viewer, safety, and rule-builder UI crate.
//!
//! Designed to compile cleanly under:
//! - `--features ssr` (`lets-embed-web` server-side rendering & unit tests)
//! - `--target wasm32-unknown-unknown --features hydrate` (`lets-embed-web` hydration)
//! - `--target wasm32-unknown-unknown --features csr` (`user_worker` & `admin_dashboard_worker` SPAs)
//!
//! Contains zero `axum`, `#[server]`, `sqlx`, or Cloudflare `worker` dependencies.

pub mod browser;
pub mod components;
pub mod layout;
pub mod models;
pub mod rule_syntax;

/// Standalone stylesheet defining all `.le-*` and shared `.gallery-*` styles.
/// Can be embedded directly by CSR workers without Tailwind build coupling.
pub const UI_CSS: &str = include_str!("../styles/ui.css");

pub use components::{
    ContentMaskCard, DensityPicker, FloatingHeader, Lightbox, LikeButton, MAX_VISIBLE_TOASTS,
    MasonryGallery, MediaTile, MinSimilaritySlider, NoticeBanner, QueryBuilder, QueryBuilderDraft,
    QueryBuilderMode, QueryBuilderNode, QueryCombinator, QueryCondition, QueryConnector,
    QueryFieldKind, QueryGroup, QueryRuleBuilder, QueryThresholdDefaults, ReportDialog,
    SafeModeToggle, SkySelect, SpoilerOverlay, ToastHost, ToastItem, ToastKind, ToastStore,
    ToggleSwitch, Viewer, apply_safe_mode_change, format_query_condition, format_query_nodes,
    parse_query_to_nodes, provide_toast_store, use_toast_store,
};
pub use models::{
    AuthorChip, Density, GalleryBlurMode, GalleryCard, GalleryCardKind, GalleryMask,
    GalleryMaskPreset, GalleryMedia, GalleryMediaKind, HeaderVariant, LightboxAlbum,
    LikeTargetKind, LikeVariant, MAX_REPORT_NOTE_CHARS, NoticeContent, NoticeTone, PresetTemplate,
    ReportReason, ReportSubmission, ReportTargetKind, RuleBlock, RuleBlockKind, RuleClause,
    RuleConnector, RuleDraft, RuleField, RuleGroupCombinator, RuleMode, SelectOption,
    SelectVariant, ViewerItem,
};

#[cfg(test)]
mod tests;
