//! Root-level persistent draft store across all `/admin` settings tabs.
//!
//! Provided via `provide_context` in `AdminApp` so switching between tabs (for
//! example `Content Safety` -> `Age & Legal` -> `Content Safety`) NEVER wipes
//! unsaved edits or disposes nested card signals.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use leptos::prelude::*;
use lets_embed_ui::{QueryBuilderDraft, QueryBuilderMode};
use site_access::{
    AgeGateTrigger, AgeVerificationPolicy, AuthProviderId, ContentPolicy, DEFAULT_POLICY_TAG_MIN,
    PlaceholderPreset, PolicyAction, PolicyBypass, UnclassifiedMode,
};

use crate::{
    api::{
        FieldValidationError, OverviewResp, ProviderUpdateItem, ProviderView, ProvidersResp,
        SafetyConfigResp,
    },
    tabs::AdminTab,
};

static NEXT_CARD_KEY: AtomicU64 = AtomicU64::new(1);

fn alloc_key() -> u64 {
    NEXT_CARD_KEY.fetch_add(1, Ordering::Relaxed)
}

pub fn parse_country_codes(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_whitespace() || c == ';') {
        let code = part.trim().to_ascii_uppercase();
        if !code.is_empty() && !out.contains(&code) {
            out.push(code);
        }
    }
    out
}

pub fn draft_from_expr(raw: &str) -> QueryBuilderDraft {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return QueryBuilderDraft::for_mode(QueryBuilderMode::SafetyPolicy);
    }
    QueryBuilderDraft::from_query(QueryBuilderMode::SafetyPolicy, trimmed).unwrap_or_else(|_| {
        let mut d = QueryBuilderDraft::for_mode(QueryBuilderMode::SafetyPolicy);
        d.query = trimmed.to_string();
        d
    })
}

/// Compact single-row `tag IN (...) >= 0.45` preset templates matching `lets-embed-ui`.
pub fn compact_safety_presets() -> Vec<ContentPolicy> {
    vec![
        ContentPolicy {
            id: "r18".to_string(),
            grant_generation: 1,
            enabled: true,
            priority: 10,
            name: "NSFW / Explicit".to_string(),
            preset: PlaceholderPreset::R18,
            match_expr: "tag IN (explicit, nude, nipples, pussy, penis, sex, uncensored, censored, topless, bottomless) >= 0.45".to_string(),
            except_expr: None,
            default_tag_min: DEFAULT_POLICY_TAG_MIN,
            action: PolicyAction::Block,
            bypass: PolicyBypass {
                include_switcher: true,
                include_click: false,
                include_live_admin: false,
                require_gallery_login: true,
                require_age_18: false,
                require_current_terms: true,
                exclude_anonymous: true,
                exclude_countries: Vec::new(),
            },
        },
        ContentPolicy {
            id: "sensitive".to_string(),
            grant_generation: 1,
            enabled: true,
            priority: 20,
            name: "Suggestive / Ecchi".to_string(),
            preset: PlaceholderPreset::Sensitive,
            match_expr: "tag IN (questionable, sensitive, lingerie, bikini, underwear, panties, cleavage, bdsm) >= 0.45".to_string(),
            except_expr: None,
            default_tag_min: DEFAULT_POLICY_TAG_MIN,
            action: PolicyAction::Blur,
            bypass: PolicyBypass {
                include_switcher: true,
                include_click: true,
                include_live_admin: false,
                require_gallery_login: false,
                require_age_18: false,
                require_current_terms: false,
                exclude_anonymous: false,
                exclude_countries: Vec::new(),
            },
        },
        ContentPolicy {
            id: "blood".to_string(),
            grant_generation: 1,
            enabled: true,
            priority: 30,
            name: "Blood / Violence".to_string(),
            preset: PlaceholderPreset::Blood,
            match_expr: "tag IN (blood) >= 0.45".to_string(),
            except_expr: None,
            default_tag_min: DEFAULT_POLICY_TAG_MIN,
            action: PolicyAction::Block,
            bypass: PolicyBypass {
                include_switcher: true,
                include_click: false,
                include_live_admin: false,
                require_gallery_login: false,
                require_age_18: false,
                require_current_terms: false,
                exclude_anonymous: false,
                exclude_countries: Vec::new(),
            },
        },
    ]
}

/// Normalizes a server-provided preset into compact `tag IN (...) >= 0.45` form.
pub fn normalize_preset_compact(mut tpl: ContentPolicy) -> ContentPolicy {
    match tpl.preset {
        PlaceholderPreset::R18 => {
            tpl.match_expr = "tag IN (explicit, nude, nipples, pussy, penis, sex, uncensored, censored, topless, bottomless) >= 0.45".to_string();
        }
        PlaceholderPreset::Sensitive => {
            tpl.match_expr = "tag IN (questionable, sensitive, lingerie, bikini, underwear, panties, cleavage, bdsm) >= 0.45".to_string();
        }
        PlaceholderPreset::Blood => {
            tpl.name = "Blood / Violence".to_string();
            tpl.match_expr = "tag IN (blood) >= 0.45".to_string();
        }
        PlaceholderPreset::Custom => {}
    }
    tpl
}

pub const fn preset_css_slug(preset: PlaceholderPreset) -> &'static str {
    match preset {
        PlaceholderPreset::R18 => "r18",
        PlaceholderPreset::Sensitive => "sensitive",
        PlaceholderPreset::Blood => "blood",
        PlaceholderPreset::Custom => "custom",
    }
}

pub const fn preset_button_label(preset: PlaceholderPreset) -> &'static str {
    match preset {
        PlaceholderPreset::R18 => "+ NSFW",
        PlaceholderPreset::Sensitive => "+ Suggestive / Ecchi",
        PlaceholderPreset::Blood => "+ Blood / Violence",
        PlaceholderPreset::Custom => "+ Custom Policy",
    }
}

pub const fn preset_badge_label(preset: PlaceholderPreset) -> &'static str {
    match preset {
        PlaceholderPreset::R18 => "R-18",
        PlaceholderPreset::Sensitive => "Sensitive",
        PlaceholderPreset::Blood => "Blood",
        PlaceholderPreset::Custom => "Custom",
    }
}

// ---------------------------------------------------------------------------
// 1. Access & Pricing Draft
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct AccessDraft {
    pub dirty: RwSignal<bool>,
    pub revision: RwSignal<u64>,
    pub login_required: RwSignal<bool>,
    pub free_folders_text: RwSignal<String>,
    pub items_prices: RwSignal<[i64; 5]>,
    pub items_free: RwSignal<[i64; 5]>,
    pub plan_prices: RwSignal<[i64; 2]>,
    pub plan_views: RwSignal<[i64; 2]>,
    pub plan_searches: RwSignal<[i64; 2]>,
    pub signup_points: RwSignal<i64>,
    pub points_per_usd: RwSignal<i64>,
    pub minimum_topup: RwSignal<i64>,
    pub eth_deposit: RwSignal<String>,
    pub sol_deposit: RwSignal<String>,
}

impl AccessDraft {
    fn new() -> Self {
        Self {
            dirty: RwSignal::new(false),
            revision: RwSignal::new(0u64),
            login_required: RwSignal::new(true),
            free_folders_text: RwSignal::new(String::new()),
            items_prices: RwSignal::new([1i64, 5, 100, 10, 100]),
            items_free: RwSignal::new([0i64; 5]),
            plan_prices: RwSignal::new([20_000i64, 50_000]),
            plan_views: RwSignal::new([2_000i64, -1]),
            plan_searches: RwSignal::new([10i64, 50]),
            signup_points: RwSignal::new(3_000i64),
            points_per_usd: RwSignal::new(10_000i64),
            minimum_topup: RwSignal::new(1_000i64),
            eth_deposit: RwSignal::new(String::new()),
            sol_deposit: RwSignal::new(String::new()),
        }
    }

    pub fn hydrate(self, ov: &OverviewResp) {
        let a = &ov.access;
        self.revision.set(ov.revision);
        self.login_required.set(a.login_required);
        self.free_folders_text.set(a.free_media_folders.join("\n"));
        let mut pr = [0i64; 5];
        let mut fr = [0i64; 5];
        for i in 0..5 {
            pr[i] = a.items[i].price;
            fr[i] = a.items[i].daily_free;
        }
        self.items_prices.set(pr);
        self.items_free.set(fr);
        self.plan_prices.set([a.plans[0].price, a.plans[1].price]);
        self.plan_views.set([
            a.plans[0].views.unwrap_or(-1),
            a.plans[1].views.unwrap_or(-1),
        ]);
        self.plan_searches
            .set([a.plans[0].searches, a.plans[1].searches]);
        self.signup_points.set(a.signup_points);
        self.points_per_usd.set(a.points_per_usd);
        self.minimum_topup.set(a.minimum_topup);
        self.eth_deposit.set(a.eth_deposit.clone());
        self.sol_deposit.set(a.sol_deposit.clone());
    }
}

// ---------------------------------------------------------------------------
// 2. Content Safety Policy Draft
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct EditablePolicyCard {
    pub key: u64,
    pub persisted: bool,
    pub collapsed: RwSignal<bool>,
    pub id: RwSignal<String>,
    pub grant_generation: RwSignal<u64>,
    pub enabled: RwSignal<bool>,
    pub priority: RwSignal<u16>,
    pub name: RwSignal<String>,
    pub preset: RwSignal<PlaceholderPreset>,
    pub match_draft: RwSignal<QueryBuilderDraft>,
    pub except_open: RwSignal<bool>,
    pub except_draft: RwSignal<QueryBuilderDraft>,
    pub default_tag_min: RwSignal<f32>,
    pub action: RwSignal<PolicyAction>,
    // Bypass Include (OR)
    pub include_switcher: RwSignal<bool>,
    pub include_click: RwSignal<bool>,
    pub include_live_admin: RwSignal<bool>,
    // Bypass Require (AND)
    pub require_gallery_login: RwSignal<bool>,
    pub require_age_18: RwSignal<bool>,
    pub require_current_terms: RwSignal<bool>,
    // Bypass Exclude (NOR)
    pub exclude_anonymous: RwSignal<bool>,
    pub exclude_countries_text: RwSignal<String>,
}

impl EditablePolicyCard {
    pub fn from_policy(pol: &ContentPolicy, persisted: bool, collapsed: bool) -> Self {
        let has_except = pol
            .except_expr
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());
        Self {
            key: alloc_key(),
            persisted,
            collapsed: RwSignal::new(collapsed),
            id: RwSignal::new(pol.id.clone()),
            grant_generation: RwSignal::new(pol.grant_generation.max(1)),
            enabled: RwSignal::new(pol.enabled),
            priority: RwSignal::new(pol.priority),
            name: RwSignal::new(pol.name.clone()),
            preset: RwSignal::new(pol.preset),
            match_draft: RwSignal::new(draft_from_expr(&pol.match_expr)),
            except_open: RwSignal::new(has_except),
            except_draft: RwSignal::new(draft_from_expr(
                pol.except_expr.as_deref().unwrap_or(""),
            )),
            default_tag_min: RwSignal::new(pol.default_tag_min),
            action: RwSignal::new(pol.action),
            include_switcher: RwSignal::new(pol.bypass.include_switcher),
            include_click: RwSignal::new(
                pol.action == PolicyAction::Blur && pol.bypass.include_click,
            ),
            include_live_admin: RwSignal::new(pol.bypass.include_live_admin),
            require_gallery_login: RwSignal::new(pol.bypass.require_gallery_login),
            require_age_18: RwSignal::new(pol.bypass.require_age_18),
            require_current_terms: RwSignal::new(pol.bypass.require_current_terms),
            exclude_anonymous: RwSignal::new(pol.bypass.exclude_anonymous),
            exclude_countries_text: RwSignal::new(pol.bypass.exclude_countries.join(", ")),
        }
    }

    pub fn to_policy(&self) -> ContentPolicy {
        let action = self.action.get_untracked();
        let match_expr = self
            .match_draft
            .with_untracked(|d| d.query.trim().to_string());
        let except_expr = if self.except_open.get_untracked() {
            let ex = self
                .except_draft
                .with_untracked(|d| d.query.trim().to_string());
            (!ex.is_empty()).then_some(ex)
        } else {
            None
        };

        ContentPolicy {
            id: self.id.get_untracked().trim().to_ascii_lowercase(),
            grant_generation: self.grant_generation.get_untracked().max(1),
            enabled: self.enabled.get_untracked(),
            priority: self.priority.get_untracked(),
            name: self.name.get_untracked().trim().to_string(),
            preset: self.preset.get_untracked(),
            match_expr,
            except_expr,
            default_tag_min: self.default_tag_min.get_untracked(),
            action,
            bypass: PolicyBypass {
                include_switcher: self.include_switcher.get_untracked(),
                include_click: action == PolicyAction::Blur && self.include_click.get_untracked(),
                include_live_admin: self.include_live_admin.get_untracked(),
                require_gallery_login: self.require_gallery_login.get_untracked(),
                require_age_18: self.require_age_18.get_untracked(),
                require_current_terms: self.require_current_terms.get_untracked(),
                exclude_anonymous: self.exclude_anonymous.get_untracked(),
                exclude_countries: parse_country_codes(&self.exclude_countries_text.get_untracked()),
            },
        }
    }

    /// Compact selector string for the folded 1-line policy header.
    pub fn selector_summary(&self) -> String {
        let raw = self.match_draft.with(|d| d.query.trim().to_string());
        let base = if raw.is_empty() {
            "No selector".to_string()
        } else {
            let mut chars = raw.chars();
            let prefix: String = chars.by_ref().take(54).collect();
            if chars.next().is_some() {
                format!("{prefix}…")
            } else {
                prefix
            }
        };
        if self.except_open.get()
            && !self
                .except_draft
                .with(|d| d.query.trim().is_empty())
        {
            format!("{base} · +except")
        } else {
            base
        }
    }

    /// Compact bypass summary for the folded 1-line policy header (e.g. `Switcher · Login · 18+`).
    pub fn bypass_summary(&self) -> String {
        let action = self.action.get();
        let mut parts: Vec<String> = Vec::new();
        if self.include_switcher.get() {
            parts.push("Switcher".to_string());
        }
        if action == PolicyAction::Blur && self.include_click.get() {
            parts.push("Click".to_string());
        }
        if self.include_live_admin.get() {
            parts.push("Admin".to_string());
        }
        if parts.is_empty() {
            return "No bypass".to_string();
        }
        if self.require_gallery_login.get() {
            parts.push("Login".to_string());
        }
        if self.require_age_18.get() {
            parts.push("18+".to_string());
        }
        if self.require_current_terms.get() {
            parts.push("Terms".to_string());
        }
        if self.exclude_anonymous.get() {
            parts.push("No-Anon".to_string());
        }
        let excluded_geo = parse_country_codes(&self.exclude_countries_text.get()).len();
        if excluded_geo > 0 {
            parts.push(format!("-Geo({excluded_geo})"));
        }
        parts.join(" · ")
    }
}

#[derive(Clone, Copy)]
pub struct SafetyDraft {
    owner: StoredValue<Owner, LocalStorage>,
    pub dirty: RwSignal<bool>,
    pub hydrated_once: RwSignal<bool>,
    pub revision: RwSignal<u64>,
    pub min_enforce_rev: RwSignal<u64>,
    pub safety_enabled: RwSignal<bool>,
    pub unclassified_mode: RwSignal<UnclassifiedMode>,
    pub fixed_blur_enabled: RwSignal<bool>,
    pub policy_cards: RwSignal<Vec<EditablePolicyCard>>,
    pub server_field_errors: RwSignal<Vec<FieldValidationError>>,
}

impl SafetyDraft {
    fn new(owner: StoredValue<Owner, LocalStorage>) -> Self {
        Self {
            owner,
            dirty: RwSignal::new(false),
            hydrated_once: RwSignal::new(false),
            revision: RwSignal::new(0u64),
            min_enforce_rev: RwSignal::new(0u64),
            safety_enabled: RwSignal::new(false),
            unclassified_mode: RwSignal::new(UnclassifiedMode::Placeholder),
            fixed_blur_enabled: RwSignal::new(false),
            policy_cards: RwSignal::new(Vec::new()),
            server_field_errors: RwSignal::new(Vec::new()),
        }
    }

    pub fn hydrate(self, cfg: &SafetyConfigResp, preserve_collapse: bool) {
        let prev_collapsed: HashMap<String, bool> = if preserve_collapse
            && self.hydrated_once.get_untracked()
        {
            self.policy_cards.with_untracked(|list| {
                list.iter()
                    .map(|c| (c.id.get_untracked(), c.collapsed.get_untracked()))
                    .collect()
            })
        } else {
            HashMap::new()
        };

        self.revision.set(cfg.revision);
        self.min_enforce_rev.set(cfg.min_enforce_rev);
        self.safety_enabled.set(cfg.safety_enabled);
        self.unclassified_mode.set(cfg.unclassified_mode);
        self.fixed_blur_enabled.set(cfg.fixed_blur_enabled);

        let cards: Vec<EditablePolicyCard> = self.owner.with_value(|root| {
            root.with(|| {
                cfg.policies
                    .iter()
                    .map(|p| {
                        // Existing loaded rules default collapsed; preserve state after save.
                        let collapsed = prev_collapsed.get(&p.id).copied().unwrap_or(true);
                        EditablePolicyCard::from_policy(p, true, collapsed)
                    })
                    .collect()
            })
        });
        self.policy_cards.set(cards);
        self.server_field_errors.set(Vec::new());
        self.hydrated_once.set(true);
    }

    pub fn sync_revision(self, cfg: &SafetyConfigResp) {
        self.revision.set(cfg.revision);
        self.min_enforce_rev.set(cfg.min_enforce_rev);
    }

    /// Creates a new expanded policy card owned by `AdminApp`'s root reactive owner.
    pub fn push_new_policy(self, pol: &ContentPolicy) {
        let card = self
            .owner
            .with_value(|root| root.with(|| EditablePolicyCard::from_policy(pol, false, false)));
        self.policy_cards.update(|list| list.push(card));
    }
}

// ---------------------------------------------------------------------------
// 3. Similarity Defaults Draft & Geo-Blocking Draft (Independent Tabs)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct SimilarityDraft {
    pub dirty: RwSignal<bool>,
    pub revision: RwSignal<u64>,
    pub dinov3_min: RwSignal<f32>,
    pub siglip2_min: RwSignal<f32>,
}

impl SimilarityDraft {
    fn new() -> Self {
        Self {
            dirty: RwSignal::new(false),
            revision: RwSignal::new(0u64),
            dinov3_min: RwSignal::new(0.0f32),
            siglip2_min: RwSignal::new(0.0f32),
        }
    }

    pub fn hydrate(self, cfg: &SafetyConfigResp) {
        self.revision.set(cfg.revision);
        self.dinov3_min.set(cfg.similarity.dinov3_min);
        self.siglip2_min.set(cfg.similarity.siglip2_min);
    }
}

#[derive(Clone, Copy)]
pub struct GeoDraft {
    pub dirty: RwSignal<bool>,
    pub revision: RwSignal<u64>,
    pub countries_text: RwSignal<String>,
    pub block_unknown: RwSignal<bool>,
    pub block_tor: RwSignal<bool>,
}

impl GeoDraft {
    fn new() -> Self {
        Self {
            dirty: RwSignal::new(false),
            revision: RwSignal::new(0u64),
            countries_text: RwSignal::new(String::new()),
            block_unknown: RwSignal::new(false),
            block_tor: RwSignal::new(false),
        }
    }

    pub fn hydrate(self, cfg: &SafetyConfigResp) {
        self.revision.set(cfg.revision);
        self.countries_text.set(cfg.geo.blocked_countries.join(", "));
        self.block_unknown.set(cfg.geo.block_unknown);
        self.block_tor.set(cfg.geo.block_tor);
    }
}

// ---------------------------------------------------------------------------
// 4. Age & Legal Draft
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct AgeLegalDraft {
    pub dirty: RwSignal<bool>,
    pub revision: RwSignal<u64>,
    pub age_policy: RwSignal<AgeVerificationPolicy>,
    pub age_gate_trigger: RwSignal<AgeGateTrigger>,
    pub terms_version: RwSignal<u32>,
    pub terms_digest: RwSignal<String>,
    pub terms_md: RwSignal<String>,
    pub privacy_md: RwSignal<String>,
    pub dmca_md: RwSignal<String>,
    pub content_policy_md: RwSignal<String>,
    pub notice_banner_enabled: RwSignal<bool>,
    pub notice_banner_md: RwSignal<String>,
    pub rta_meta_enabled: RwSignal<bool>,
    pub noindex_restricted: RwSignal<bool>,
}

impl AgeLegalDraft {
    fn new() -> Self {
        Self {
            dirty: RwSignal::new(false),
            revision: RwSignal::new(0u64),
            age_policy: RwSignal::new(AgeVerificationPolicy::Off),
            age_gate_trigger: RwSignal::new(AgeGateTrigger::Off),
            terms_version: RwSignal::new(1u32),
            terms_digest: RwSignal::new(String::new()),
            terms_md: RwSignal::new(String::new()),
            privacy_md: RwSignal::new(String::new()),
            dmca_md: RwSignal::new(String::new()),
            content_policy_md: RwSignal::new(String::new()),
            notice_banner_enabled: RwSignal::new(false),
            notice_banner_md: RwSignal::new(String::new()),
            rta_meta_enabled: RwSignal::new(false),
            noindex_restricted: RwSignal::new(false),
        }
    }

    pub fn hydrate(self, cfg: &SafetyConfigResp) {
        self.revision.set(cfg.revision);
        self.age_policy.set(cfg.age_policy);
        self.age_gate_trigger.set(cfg.age_gate_trigger);
        self.terms_version.set(cfg.legal.terms_version);
        self.terms_digest.set(cfg.legal.terms_digest.clone());
        self.terms_md.set(cfg.legal.terms_md.clone());
        self.privacy_md.set(cfg.legal.privacy_md.clone());
        self.dmca_md.set(cfg.legal.dmca_md.clone());
        self.content_policy_md
            .set(cfg.legal.content_policy_md.clone());
        self.notice_banner_enabled
            .set(cfg.legal.notice_banner_enabled);
        self.notice_banner_md
            .set(cfg.legal.notice_banner_md.clone());
        self.rta_meta_enabled.set(cfg.legal.rta_meta_enabled);
        self.noindex_restricted.set(cfg.legal.noindex_restricted);
    }
}

// ---------------------------------------------------------------------------
// 5. Auth Providers Draft
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct EditableProvider {
    pub id: AuthProviderId,
    pub supports_strict: bool,
    pub secret_field_name: Option<String>,
    pub has_client_secret: RwSignal<bool>,
    pub kid: RwSignal<Option<String>>,
    pub updated_at: RwSignal<Option<i64>>,
    pub updated_by: RwSignal<Option<String>>,
    pub enabled: RwSignal<bool>,
    pub display_name: RwSignal<String>,
    pub issuer: RwSignal<String>,
    pub public_client_id: RwSignal<String>,
    pub soft_birthday_check: RwSignal<bool>,
    pub secret_input: RwSignal<String>,
    pub clear_secret: RwSignal<bool>,
}

impl EditableProvider {
    pub fn from_view(v: &ProviderView) -> Self {
        Self {
            id: v.config.id,
            supports_strict: v.supports_strict_age_verification,
            secret_field_name: v.secret_field_name.clone(),
            has_client_secret: RwSignal::new(v.has_client_secret),
            kid: RwSignal::new(v.kid.clone()),
            updated_at: RwSignal::new(v.updated_at),
            updated_by: RwSignal::new(v.updated_by.clone()),
            enabled: RwSignal::new(v.config.enabled),
            display_name: RwSignal::new(v.config.display_name.clone().unwrap_or_default()),
            issuer: RwSignal::new(v.config.issuer.clone().unwrap_or_default()),
            public_client_id: RwSignal::new(v.config.public_client_id.clone().unwrap_or_default()),
            soft_birthday_check: RwSignal::new(v.config.soft_birthday_check),
            secret_input: RwSignal::new(String::new()),
            clear_secret: RwSignal::new(false),
        }
    }

    pub fn to_update(&self) -> ProviderUpdateItem {
        let opt = |s: String| {
            let t = s.trim().to_string();
            (!t.is_empty()).then_some(t)
        };
        let display_name = if self.id == AuthProviderId::OidcAgeAssurance {
            opt(self.display_name.get_untracked())
        } else {
            None
        };
        let issuer = if matches!(
            self.id,
            AuthProviderId::OidcAgeAssurance | AuthProviderId::EmailOtp
        ) {
            opt(self.issuer.get_untracked())
        } else {
            None
        };
        let public_client_id = if matches!(self.id, AuthProviderId::Siwe | AuthProviderId::Siws) {
            None
        } else if self.id == AuthProviderId::Telegram {
            opt(self
                .public_client_id
                .get_untracked()
                .trim()
                .trim_start_matches('@')
                .to_string())
        } else {
            opt(self.public_client_id.get_untracked())
        };
        ProviderUpdateItem {
            id: self.id,
            enabled: self.enabled.get_untracked(),
            display_name,
            issuer,
            public_client_id,
            soft_birthday_check: self.soft_birthday_check.get_untracked(),
            secret_value: opt(self.secret_input.get_untracked()),
            clear_secret: self.clear_secret.get_untracked(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct ProvidersDraft {
    owner: StoredValue<Owner, LocalStorage>,
    pub dirty: RwSignal<bool>,
    pub loaded: RwSignal<bool>,
    pub server_snapshot: RwSignal<Option<ProvidersResp>>,
    pub revision: RwSignal<u64>,
    pub age_policy: RwSignal<AgeVerificationPolicy>,
    pub current_kid: RwSignal<String>,
    pub has_prev_key: RwSignal<bool>,
    pub public_origin: RwSignal<String>,
    pub rows: RwSignal<Vec<EditableProvider>>,
}

impl ProvidersDraft {
    fn new(owner: StoredValue<Owner, LocalStorage>) -> Self {
        Self {
            owner,
            dirty: RwSignal::new(false),
            loaded: RwSignal::new(false),
            server_snapshot: RwSignal::new(None),
            revision: RwSignal::new(0u64),
            age_policy: RwSignal::new(AgeVerificationPolicy::Off),
            current_kid: RwSignal::new(String::new()),
            has_prev_key: RwSignal::new(false),
            public_origin: RwSignal::new(String::new()),
            rows: RwSignal::new(Vec::new()),
        }
    }

    pub fn hydrate(self, resp: &ProvidersResp) {
        self.server_snapshot.set(Some(resp.clone()));
        self.revision.set(resp.revision);
        self.age_policy.set(resp.age_policy);
        self.current_kid.set(resp.current_kid.clone());
        self.has_prev_key.set(resp.has_prev_key);
        self.public_origin.set(resp.public_origin.clone());
        let built = self.owner.with_value(|root| {
            root.with(|| {
                resp.providers
                    .iter()
                    .map(EditableProvider::from_view)
                    .collect()
            })
        });
        self.rows.set(built);
        self.loaded.set(true);
    }

    /// Syncs server-derived metadata (`revision`, `age_policy`, active key info,
    /// masked secret metadata) without destroying unsaved provider edits.
    pub fn sync_server_metadata(self, resp: &ProvidersResp) {
        self.server_snapshot.set(Some(resp.clone()));
        self.revision.set(resp.revision);
        self.age_policy.set(resp.age_policy);
        self.current_kid.set(resp.current_kid.clone());
        self.has_prev_key.set(resp.has_prev_key);
        self.public_origin.set(resp.public_origin.clone());
        self.rows.with_untracked(|rows| {
            for row in rows {
                if let Some(view) = resp.providers.iter().find(|v| v.config.id == row.id) {
                    row.has_client_secret.set(view.has_client_secret);
                    row.kid.set(view.kid.clone());
                    row.updated_at.set(view.updated_at);
                    row.updated_by.set(view.updated_by.clone());
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Root Context Store
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct AdminDraftStore {
    pub access: AccessDraft,
    pub safety: SafetyDraft,
    pub geo: GeoDraft,
    pub similarity: SimilarityDraft,
    pub age_legal: AgeLegalDraft,
    pub providers: ProvidersDraft,
}

impl AdminDraftStore {
    pub fn new() -> Self {
        let owner = StoredValue::new_local(
            Owner::current().expect("AdminDraftStore must be initialized inside AdminApp"),
        );
        Self {
            access: AccessDraft::new(),
            safety: SafetyDraft::new(owner),
            geo: GeoDraft::new(),
            similarity: SimilarityDraft::new(),
            age_legal: AgeLegalDraft::new(),
            providers: ProvidersDraft::new(owner),
        }
    }

    pub fn is_tab_dirty(self, tab: AdminTab) -> bool {
        match tab {
            AdminTab::Access => self.access.dirty.get(),
            AdminTab::Safety => self.safety.dirty.get(),
            AdminTab::Geo => self.geo.dirty.get(),
            AdminTab::Similarity => self.similarity.dirty.get(),
            AdminTab::AgeLegal => self.age_legal.dirty.get(),
            AdminTab::Providers => self.providers.dirty.get(),
            AdminTab::Accounts | AdminTab::Reports => false,
        }
    }
}

impl Default for AdminDraftStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn provide_admin_drafts() -> AdminDraftStore {
    let store = AdminDraftStore::new();
    provide_context(store);
    store
}

pub fn use_admin_drafts() -> AdminDraftStore {
    expect_context::<AdminDraftStore>()
}
