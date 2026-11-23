//! Cloudflare Access-Style Content Safety Policy v3 Builder tab:
//! - Clean left-aligned cards with `lets_embed_ui::ToggleSwitch` & left-aligned radio cards
//! - Unified `lets_embed_ui::QueryBuilder` (`QueryBuilderMode::SafetyPolicy`) for both
//!   primary `match_expr` AND collapsible optional `except_expr`
//! - Keyboard-friendly `<ScoreInput>` (`0.01..=1.00`, `step=0.01`) for `default_tag_min`
//! - Cloudflare Access-style Include (OR) / Require (AND) / Exclude (NOR) bypass rules
//! - Balanced live `<ContentMaskCard>` preview without cramping `QueryBuilder`
//! - GCP top-right toasts via `use_toast_store()` + two-phase activation handling

use std::sync::atomic::{AtomicU64, Ordering};

use leptos::prelude::*;
use lets_embed_ui::{
    ContentMaskCard, GalleryMask, GalleryMaskPreset, NoticeBanner, NoticeContent, NoticeTone,
    PresetTemplate, QueryBuilder, QueryBuilderDraft, QueryBuilderMode, QueryThresholdDefaults,
    RuleMode as UiRuleMode, ScoreInput, ToggleSwitch, use_toast_store,
};
use search_types::{
    WD_VOCAB_DIGEST,
    safety::{parse_safety_rule, validate_wd_tags_in_expr},
};
use site_access::{
    AgeVerificationPolicy, ContentPolicy, DEFAULT_POLICY_TAG_MIN, PlaceholderPreset, PolicyAction,
    PolicyBypass, PublicSitePolicy, SITE_POLICY_SCHEMA_VERSION, UnclassifiedMode,
    validate_policy_set_with_mode,
};
use wasm_bindgen_futures::spawn_local;

use crate::api::{
    ActivationResult, FieldValidationError, SafetyConfigResp, SaveSafetyReq, SaveSafetyResp,
    post_json_activatable,
};

static NEXT_CARD_KEY: AtomicU64 = AtomicU64::new(1);

fn alloc_key() -> u64 {
    NEXT_CARD_KEY.fetch_add(1, Ordering::Relaxed)
}

fn to_ui_preset(p: PlaceholderPreset) -> GalleryMaskPreset {
    match p {
        PlaceholderPreset::R18 => GalleryMaskPreset::R18,
        PlaceholderPreset::Blood => GalleryMaskPreset::Blood,
        PlaceholderPreset::Sensitive => GalleryMaskPreset::Sensitive,
        PlaceholderPreset::Custom => GalleryMaskPreset::Custom,
    }
}

fn from_ui_preset(p: GalleryMaskPreset) -> PlaceholderPreset {
    match p {
        GalleryMaskPreset::R18 => PlaceholderPreset::R18,
        GalleryMaskPreset::Blood => PlaceholderPreset::Blood,
        GalleryMaskPreset::Sensitive => PlaceholderPreset::Sensitive,
        GalleryMaskPreset::Custom => PlaceholderPreset::Custom,
    }
}

fn validate_expr_client(raw: &str, required: bool) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return required
            .then(|| "Enabled policy requires at least one metadata predicate.".to_string());
    }
    match parse_safety_rule(trimmed) {
        Ok(ast) => validate_wd_tags_in_expr(&ast).err().map(|e| e.to_string()),
        Err(e) => Some(e.to_string()),
    }
}

fn parse_country_codes(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_whitespace() || c == ';') {
        let code = part.trim().to_ascii_uppercase();
        if !code.is_empty() && !out.contains(&code) {
            out.push(code);
        }
    }
    out
}

fn draft_from_expr(raw: &str) -> QueryBuilderDraft {
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

#[derive(Clone)]
struct EditablePolicyCard {
    key: u64,
    persisted: bool,
    id: RwSignal<String>,
    grant_generation: RwSignal<u64>,
    enabled: RwSignal<bool>,
    priority: RwSignal<u16>,
    name: RwSignal<String>,
    preset: RwSignal<PlaceholderPreset>,
    match_draft: RwSignal<QueryBuilderDraft>,
    except_open: RwSignal<bool>,
    except_draft: RwSignal<QueryBuilderDraft>,
    default_tag_min: RwSignal<f32>,
    action: RwSignal<PolicyAction>,
    // Bypass Include (OR)
    include_switcher: RwSignal<bool>,
    include_click: RwSignal<bool>,
    include_live_admin: RwSignal<bool>,
    // Bypass Require (AND)
    require_gallery_login: RwSignal<bool>,
    require_age_18: RwSignal<bool>,
    require_current_terms: RwSignal<bool>,
    // Bypass Exclude (NOR)
    exclude_anonymous: RwSignal<bool>,
    exclude_countries_text: RwSignal<String>,
}

impl EditablePolicyCard {
    fn from_policy(pol: &ContentPolicy, persisted: bool) -> Self {
        let has_except = pol
            .except_expr
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());
        Self {
            key: alloc_key(),
            persisted,
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

    fn to_policy(&self) -> ContentPolicy {
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
}

#[component]
pub fn SafetyTab(
    safety: RwSignal<Option<SafetyConfigResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let toasts = use_toast_store();

    let safety_enabled = RwSignal::new(false);
    let unclassified_mode = RwSignal::new(UnclassifiedMode::Placeholder);
    let fixed_blur_enabled = RwSignal::new(false);
    let policy_cards = RwSignal::new(Vec::<EditablePolicyCard>::new());
    let revision = RwSignal::new(0u64);
    let min_enforce_rev = RwSignal::new(0u64);
    let server_field_errors = RwSignal::new(Vec::<FieldValidationError>::new());

    let saving = RwSignal::new(false);

    let site_age_policy = Memo::new(move |_| {
        safety
            .get()
            .map(|c| c.age_policy)
            .unwrap_or(AgeVerificationPolicy::Off)
    });

    Effect::new(move |_| {
        if let Some(cfg) = safety.get() {
            revision.set(cfg.revision);
            min_enforce_rev.set(cfg.min_enforce_rev);
            safety_enabled.set(cfg.safety_enabled);
            unclassified_mode.set(cfg.unclassified_mode);
            fixed_blur_enabled.set(cfg.fixed_blur_enabled);
            let cards = cfg
                .policies
                .iter()
                .map(|p| EditablePolicyCard::from_policy(p, true))
                .collect();
            policy_cards.set(cards);
            server_field_errors.set(Vec::new());
        }
    });

    let add_policy_template = move |tpl: ContentPolicy| {
        let existing = policy_cards.get_untracked();
        if existing.len() >= 16 {
            toasts.warning(
                "Maximum policy limit reached",
                Some("Policy v3 allows up to 16 policies per site.".to_string()),
            );
            return;
        }
        let existing_ids: Vec<String> = existing.iter().map(|c| c.id.get_untracked()).collect();
        let max_prio = existing
            .iter()
            .map(|c| c.priority.get_untracked())
            .max()
            .unwrap_or(0);
        let mut candidate = tpl.id.clone();
        let mut suffix = 2u32;
        while existing_ids.iter().any(|x| x == &candidate) {
            candidate = format!("{}-{suffix}", tpl.id);
            suffix += 1;
        }
        let mut pol = tpl;
        pol.id = candidate;
        pol.grant_generation = 1;
        pol.priority = max_prio.saturating_add(10);
        pol.enabled = !pol.match_expr.trim().is_empty();
        // Ensure new policies never silently default to live admin bypass!
        pol.bypass.include_live_admin = false;
        let label = pol.name.clone();
        policy_cards.update(|list| list.push(EditablePolicyCard::from_policy(&pol, false)));
        toasts.info(
            format!("Added policy \"{label}\""),
            Some("Configure selector & bypass rules, then click Publish Content Safety Policy.".to_string()),
        );
    };

    let add_custom_policy = move |_| {
        add_policy_template(ContentPolicy {
            id: "custom".to_string(),
            grant_generation: 1,
            enabled: false,
            priority: 40,
            name: "Custom Policy".to_string(),
            preset: PlaceholderPreset::Custom,
            match_expr: String::new(),
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
        });
    };

    let on_save = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if saving.get_untracked() {
            return;
        }
        let Some(current) = safety.get_untracked() else {
            return;
        };

        let policies: Vec<ContentPolicy> = policy_cards
            .get_untracked()
            .iter()
            .map(EditablePolicyCard::to_policy)
            .collect();

        // Client-side full Policy v3 validation (catches WD-Tagger typos, Block+click,
        // Age18+Off, invalid country codes, and term/depth limits before round-trip).
        let candidate = PublicSitePolicy {
            schema_version: SITE_POLICY_SCHEMA_VERSION,
            revision: revision.get_untracked().saturating_add(1),
            min_enforce_rev: min_enforce_rev.get_untracked(),
            policy_digest: String::new(),
            vocab_digest: WD_VOCAB_DIGEST.to_string(),
            safety_enabled: safety_enabled.get_untracked(),
            unclassified_mode: unclassified_mode.get_untracked(),
            fixed_blur_enabled: fixed_blur_enabled.get_untracked(),
            policies: policies.clone(),
            age_policy: current.age_policy,
            age_gate_trigger: current.age_gate_trigger,
            similarity: current.similarity,
            legal: current.legal.clone(),
            geo: current.geo.clone(),
            enabled_providers: Vec::new(),
        };
        if let Err(err) = validate_policy_set_with_mode(&candidate, true) {
            toasts.error("Policy v3 validation failed", Some(err.to_string()));
            return;
        }

        saving.set(true);
        server_field_errors.set(Vec::new());

        let req = SaveSafetyReq {
            revision: revision.get_untracked(),
            safety_enabled: safety_enabled.get_untracked(),
            policies,
            unclassified_mode: unclassified_mode.get_untracked(),
            fixed_blur_enabled: fixed_blur_enabled.get_untracked(),
            age_policy: current.age_policy,
            age_gate_trigger: current.age_gate_trigger,
            similarity: current.similarity,
            geo: current.geo,
            legal: current.legal,
            confirm_policy_v3_migration: true,
        };

        spawn_local(async move {
            match post_json_activatable::<_, SaveSafetyResp>("/admin/api/safety", &req).await {
                Ok(ActivationResult::Active(resp)) => {
                    revision.set(resp.revision);
                    min_enforce_rev.set(resp.min_enforce_rev);
                    let mut detail = format!(
                        "min_enforce_rev #{} · tightened={} · schema v3 active",
                        resp.min_enforce_rev, resp.tightened
                    );
                    if !resp.auto_disabled_providers.is_empty() {
                        detail.push_str(&format!(
                            " · auto-disabled {} incompatible provider(s)",
                            resp.auto_disabled_providers.len()
                        ));
                    }
                    toasts.success(
                        format!("Published Content Safety Policy rev #{}", resp.revision),
                        Some(detail),
                    );
                    on_saved.run(());
                }
                Ok(ActivationResult::PendingActivation(pending)) => {
                    revision.set(pending.revision);
                    min_enforce_rev.set(pending.min_enforce_rev);
                    toasts.warning(
                        format!(
                            "Saved rev #{} to D1 — awaiting SitePolicyDO activation",
                            pending.revision
                        ),
                        Some(pending.error),
                    );
                    on_saved.run(());
                }
                Err(err) => {
                    server_field_errors.set(err.field_errors);
                    toasts.error("Failed to publish safety policy", Some(err.message));
                }
            }
            saving.set(false);
        });
    };

    view! {
        <form class="adm-stack" on:submit=on_save>
            // Global Policy v3 Engine Card
            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Content Safety Engine (Policy v3)"</h2>
                        <p class="adm-sub">
                            "Cloudflare Access-style Block & Blur enforcement with 3-valued tag coverage, object-bound click-to-reveal, and two-phase SitePolicyDO activation."
                        </p>
                    </div>
                    <span class="adm-pill">
                        {move || format!("rev #{} · min_enforce #{} · v3", revision.get(), min_enforce_rev.get())}
                    </span>
                </div>

                <div class="adm-toggle-grid">
                    <ToggleSwitch
                        checked=Signal::derive(move || safety_enabled.get())
                        on_change=Callback::new(move |v| safety_enabled.set(v))
                        label="Enable server-side content safety filtering"
                        description="Evaluates all active Block & Blur policies server-side before HTML, hydration, API, search, or media delivery."
                    />
                    <ToggleSwitch
                        checked=Signal::derive(move || fixed_blur_enabled.get())
                        on_change=Callback::new(move |v| fixed_blur_enabled.set(v))
                        label="Fixed server-side blurred previews"
                        description="Serves locked Cloudflare Images previews (blur=80, width=360, webp) on /media/preview/* for Blur policies."
                    />
                </div>

                {move || (!fixed_blur_enabled.get()).then(|| view! {
                    <NoticeBanner
                        tone=NoticeTone::Info
                        title="Fixed Server Preview Disabled"
                        dismissible=false
                        content=NoticeContent::Text(
                            "Server-side blurred previews are OFF. Any policy set to Blur safely degrades to a hard Placeholder until fixed server previews are enabled — clear media bytes are never sent before reveal."
                                .to_string()
                        )
                    />
                })}

                <div class="adm-field">
                    <span>"Unclassified media policy (`images.status != 'completed'`)"</span>
                    <div class="adm-grid-2">
                        <label class="adm-radio-card">
                            <input
                                type="radio"
                                name="unclassified_mode"
                                prop:checked=move || unclassified_mode.get() == UnclassifiedMode::Placeholder
                                on:change=move |_| unclassified_mode.set(UnclassifiedMode::Placeholder)
                            />
                            <span class="adm-radio-copy">
                                <strong>"Fail-closed Placeholder (Recommended)"</strong>
                                <small>"Pending or legacy-ingested items render behind a safe Placeholder until WD-Tagger v3 finishes."</small>
                            </span>
                        </label>
                        <label class="adm-radio-card">
                            <input
                                type="radio"
                                name="unclassified_mode"
                                prop:checked=move || unclassified_mode.get() == UnclassifiedMode::Continue
                                on:change=move |_| unclassified_mode.set(UnclassifiedMode::Continue)
                            />
                            <span class="adm-radio-copy">
                                <strong>"Continue (Allow unclassified)"</strong>
                                <small>"Waives the general unclassified placeholder; matching explicit policies and tag checks still run."</small>
                            </span>
                        </label>
                    </div>
                </div>

                {move || safety.get().map(|cfg| view! {
                    <div class="adm-note-box">
                        <strong>"WD-Tagger v3 coverage tip: "</strong>
                        <span>{cfg.legacy_unclassified_note}</span>
                    </div>
                })}
            </section>

            // Policy v3 Rules Builder Section
            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Content Safety Policies"</h2>
                        <p class="adm-sub">
                            "Up to 16 policies (32 terms per policy, 128 total). Metadata-only selectors (`tag:`, `post_tag:`, `author:`, `unclassified`) validated against all 10,861 WD-Tagger v3 tags."
                        </p>
                    </div>
                    <div class="adm-btn-group">
                        {move || safety.get().map(|cfg| {
                            cfg.presets.into_iter().map(|preset| {
                                let label = format!("+ {}", preset.name);
                                let tpl = preset.clone();
                                view! {
                                    <button
                                        type="button"
                                        class="adm-btn adm-btn--sm"
                                        on:click=move |_| add_policy_template(tpl.clone())
                                    >
                                        {label}
                                    </button>
                                }
                            }).collect_view()
                        })}
                        <button
                            type="button"
                            class="adm-btn adm-btn--sm adm-btn--primary"
                            on:click=add_custom_policy
                        >
                            "+ Custom Policy"
                        </button>
                    </div>
                </div>

                {move || {
                    let list = policy_cards.get();
                    if list.is_empty() {
                        view! {
                            <div class="adm-empty-card">
                                "No content policies configured yet. Click a WD-Tagger preset button above (+ NSFW / Explicit, + Suggestive / Ecchi, + Blood / Gore) or + Custom Policy to create one."
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="adm-stack">
                                <For
                                    each=move || policy_cards.get()
                                    key=|card| card.key
                                    let(card)
                                >
                                    {
                                        let card_key = card.key;
                                        let persisted = card.persisted;
                                        let id_sig = card.id;
                                        let gen_sig = card.grant_generation;
                                        let enabled_sig = card.enabled;
                                        let priority_sig = card.priority;
                                        let name_sig = card.name;
                                        let preset_sig = card.preset;
                                        let match_draft = card.match_draft;
                                        let except_open = card.except_open;
                                        let except_draft = card.except_draft;
                                        let default_tag_min = card.default_tag_min;
                                        let action_sig = card.action;
                                        let include_switcher = card.include_switcher;
                                        let include_click = card.include_click;
                                        let include_live_admin = card.include_live_admin;
                                        let require_login = card.require_gallery_login;
                                        let require_age = card.require_age_18;
                                        let require_terms = card.require_current_terms;
                                        let exclude_anon = card.exclude_anonymous;
                                        let exclude_countries_text = card.exclude_countries_text;

                                        let threshold_defaults = Signal::derive(move || QueryThresholdDefaults {
                                            tag_min_score: Some(default_tag_min.get()),
                                            ..QueryThresholdDefaults::default()
                                        });

                                        let match_err = Signal::derive(move || {
                                            let q = match_draft.with(|d| d.query.clone());
                                            if let Some(local_err) = validate_expr_client(&q, enabled_sig.get()) {
                                                return Some(local_err);
                                            }
                                            let cur_id = id_sig.get();
                                            server_field_errors.with(|errs| {
                                                errs.iter()
                                                    .find(|e| e.policy_id.as_deref() == Some(cur_id.as_str()) && e.field == "match_expr")
                                                    .map(|e| e.message.clone())
                                            })
                                        });

                                        let except_err = Signal::derive(move || {
                                            if !except_open.get() {
                                                return None;
                                            }
                                            let q = except_draft.with(|d| d.query.clone());
                                            if let Some(local_err) = validate_expr_client(&q, false) {
                                                return Some(local_err);
                                            }
                                            let cur_id = id_sig.get();
                                            server_field_errors.with(|errs| {
                                                errs.iter()
                                                    .find(|e| e.policy_id.as_deref() == Some(cur_id.as_str()) && e.field == "except_expr")
                                                    .map(|e| e.message.clone())
                                            })
                                        });

                                        let on_preset_pick = Callback::new(move |tpl: PresetTemplate| {
                                            preset_sig.set(from_ui_preset(tpl.preset));
                                            if name_sig.get_untracked().trim().is_empty()
                                                || name_sig.get_untracked() == "Custom Policy"
                                            {
                                                name_sig.set(tpl.label.clone());
                                            }
                                            match tpl.default_mode {
                                                UiRuleMode::SpoilerBlur => {
                                                    action_sig.set(PolicyAction::Blur);
                                                    include_click.set(true);
                                                }
                                                UiRuleMode::Switcher => {
                                                    action_sig.set(PolicyAction::Block);
                                                    include_click.set(false);
                                                }
                                            }
                                        });

                                        let any_include = Memo::new(move |_| {
                                            include_switcher.get()
                                                || (action_sig.get() == PolicyAction::Blur && include_click.get())
                                                || include_live_admin.get()
                                        });

                                        view! {
                                            <article class="adm-policy-card">
                                                // Policy Header
                                                <div class="adm-policy-head">
                                                    <div class="adm-policy-head-fields">
                                                        <label class="adm-field">
                                                            <span>"Display Name"</span>
                                                            <input
                                                                type="text"
                                                                placeholder="NSFW / Explicit"
                                                                prop:value=move || name_sig.get()
                                                                on:input=move |ev| name_sig.set(event_target_value(&ev))
                                                            />
                                                        </label>

                                                        <label class="adm-field">
                                                            <span class="adm-field-label-inline">
                                                                <span>"Policy Slug ID"</span>
                                                                <span class="adm-badge adm-mono">
                                                                    {move || format!("gen #{}", gen_sig.get())}
                                                                </span>
                                                            </span>
                                                            <input
                                                                type="text"
                                                                class=if persisted { "adm-mono is-immutable" } else { "adm-mono" }
                                                                placeholder="r18"
                                                                readonly=persisted
                                                                title=if persisted {
                                                                    "Immutable slug ID for persisted policy"
                                                                } else {
                                                                    "Lowercase ASCII slug (a-z0-9_-, max 32 chars)"
                                                                }
                                                                prop:value=move || id_sig.get()
                                                                on:input=move |ev| {
                                                                    if !persisted {
                                                                        id_sig.set(event_target_value(&ev));
                                                                    }
                                                                }
                                                            />
                                                        </label>

                                                        <label class="adm-field adm-field--narrow">
                                                            <span>"Priority"</span>
                                                            <input
                                                                type="text"
                                                                inputmode="numeric"
                                                                class="adm-mono"
                                                                prop:value=move || priority_sig.get().to_string()
                                                                on:input=move |ev| {
                                                                    if let Ok(v) = event_target_value(&ev).trim().parse::<u16>() {
                                                                        priority_sig.set(v);
                                                                    }
                                                                }
                                                            />
                                                        </label>

                                                        <label class="adm-field">
                                                            <span>"Placeholder Art"</span>
                                                            <select
                                                                prop:value=move || to_ui_preset(preset_sig.get()).as_str().to_string()
                                                                on:change=move |ev| {
                                                                    let p = GalleryMaskPreset::parse(&event_target_value(&ev));
                                                                    preset_sig.set(from_ui_preset(p));
                                                                }
                                                            >
                                                                <option value="r18">"R-18 (18+ badge)"</option>
                                                                <option value="sensitive">"Sensitive / Eye-off"</option>
                                                                <option value="blood">"Blood / Warning"</option>
                                                                <option value="custom">"Custom Shield"</option>
                                                            </select>
                                                        </label>
                                                    </div>

                                                    <div class="adm-policy-head-actions">
                                                        <ToggleSwitch
                                                            checked=Signal::derive(move || enabled_sig.get())
                                                            on_change=Callback::new(move |v| enabled_sig.set(v))
                                                            label="Enabled"
                                                            compact=true
                                                        />
                                                        <button
                                                            type="button"
                                                            class="adm-btn adm-btn--danger adm-btn--sm"
                                                            on:click=move |_| {
                                                                let removed = name_sig.get_untracked();
                                                                policy_cards.update(|list| list.retain(|c| c.key != card_key));
                                                                toasts.info(
                                                                    format!("Removed policy \"{removed}\" from draft"),
                                                                    Some("Publish to apply this removal.".to_string()),
                                                                );
                                                            }
                                                        >
                                                            "Remove"
                                                        </button>
                                                    </div>
                                                </div>

                                                // Section 1: Content Selector (Full Width — Uncramped QueryBuilder!)
                                                <div class="adm-policy-section">
                                                    <div class="adm-policy-section-head">
                                                        <span class="adm-step-num">"1"</span>
                                                        <div>
                                                            <h3>"Content Selector"</h3>
                                                            <p class="adm-sub">
                                                                "Matches items where Match is true and optional Exclude / Exception is false."
                                                            </p>
                                                        </div>
                                                    </div>

                                                    <QueryBuilder
                                                        draft=match_draft
                                                        mode=QueryBuilderMode::SafetyPolicy
                                                        presets=PresetTemplate::builtins()
                                                        show_presets=true
                                                        threshold_defaults=threshold_defaults
                                                        validation_error=match_err
                                                        on_preset_select=on_preset_pick
                                                    />

                                                    <div class="adm-default-score-bar">
                                                        <div class="adm-default-score-copy">
                                                            <strong>"Default Tag Min Score"</strong>
                                                            <small>"Fallback min confidence (0.01–1.00) for tags without an explicit >= score"</small>
                                                        </div>
                                                        <div class="adm-default-score-input">
                                                            <ScoreInput
                                                                value=Signal::derive(move || default_tag_min.get())
                                                                on_change=Callback::new(move |v| default_tag_min.set(v))
                                                                min=0.01
                                                                max=1.00
                                                                step=0.01
                                                                aria_label="Default tag minimum score"
                                                            />
                                                        </div>
                                                    </div>

                                                    // Collapsible Optional Exclude / Exception (`except_expr`)
                                                    <div class="adm-except-wrap">
                                                        <div class="adm-except-bar">
                                                            <button
                                                                type="button"
                                                                class="adm-btn adm-btn--sm"
                                                                on:click=move |_| except_open.update(|v| *v = !*v)
                                                            >
                                                                {move || if except_open.get() {
                                                                    "− Hide Exclude / Exception (except_expr)"
                                                                } else {
                                                                    "+ Add Exclude / Exception (except_expr)"
                                                                }}
                                                            </button>
                                                            {move || except_open.get().then(|| view! {
                                                                <button
                                                                    type="button"
                                                                    class="adm-btn adm-btn--sm adm-btn--danger"
                                                                    on:click=move |_| {
                                                                        except_draft.set(QueryBuilderDraft::for_mode(QueryBuilderMode::SafetyPolicy));
                                                                        except_open.set(false);
                                                                    }
                                                                >
                                                                    "Clear Exception"
                                                                </button>
                                                            })}
                                                        </div>

                                                        {move || except_open.get().then(|| view! {
                                                            <div class="adm-except-panel">
                                                                <div class="adm-except-title">
                                                                    <strong>"Exclude / Exception (`except_expr`)"</strong>
                                                                    <span class="adm-sub">
                                                                        "Per-policy exemption: affects ONLY this policy (never overrides stricter matching policies)."
                                                                    </span>
                                                                </div>
                                                                <QueryBuilder
                                                                    draft=except_draft
                                                                    mode=QueryBuilderMode::SafetyPolicy
                                                                    show_presets=false
                                                                    threshold_defaults=threshold_defaults
                                                                    validation_error=except_err
                                                                />
                                                            </div>
                                                        })}
                                                    </div>
                                                </div>

                                                // Sections 2 & 3 + Balanced Live Preview Sidebar
                                                <div class="adm-policy-lower-grid">
                                                    <div class="adm-policy-lower-main">
                                                        // Section 2: Enforcement Action
                                                        <div class="adm-policy-section">
                                                            <div class="adm-policy-section-head">
                                                                <span class="adm-step-num">"2"</span>
                                                                <div>
                                                                    <h3>"Enforcement Action"</h3>
                                                                    <p class="adm-sub">
                                                                        "Strict Policy v3 actions: Block or Blur only (use per-policy Exception above for exemptions)."
                                                                    </p>
                                                                </div>
                                                            </div>

                                                            <div class="adm-segmented" role="radiogroup" aria-label="Enforcement action">
                                                                <button
                                                                    type="button"
                                                                    role="radio"
                                                                    aria-checked=move || (action_sig.get() == PolicyAction::Block).to_string()
                                                                    class=move || if action_sig.get() == PolicyAction::Block {
                                                                        "adm-seg-btn is-active"
                                                                    } else {
                                                                        "adm-seg-btn"
                                                                    }
                                                                    on:click=move |_| {
                                                                        action_sig.set(PolicyAction::Block);
                                                                        include_click.set(false);
                                                                    }
                                                                >
                                                                    <strong>"Block"</strong>
                                                                    <small>"Hard Placeholder — zero media URLs or previews until directly bypassed"</small>
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    role="radio"
                                                                    aria-checked=move || (action_sig.get() == PolicyAction::Blur).to_string()
                                                                    class=move || if action_sig.get() == PolicyAction::Blur {
                                                                        "adm-seg-btn is-active"
                                                                    } else {
                                                                        "adm-seg-btn"
                                                                    }
                                                                    on:click=move |_| {
                                                                        action_sig.set(PolicyAction::Blur);
                                                                    }
                                                                >
                                                                    <strong>"Blur"</strong>
                                                                    <small>"Fixed Server Preview — supports optional Click to Reveal"</small>
                                                                </button>
                                                            </div>

                                                            {move || (action_sig.get() == PolicyAction::Blur && !fixed_blur_enabled.get()).then(|| view! {
                                                                <div class="adm-inline-info">
                                                                    "Fixed server-side blurred previews are currently OFF. Until enabled above, this Blur policy safely renders as a hard Placeholder."
                                                                </div>
                                                            })}
                                                        </div>

                                                        // Section 3: Bypass / Unlock Rules (Cloudflare Access Style)
                                                        <div class="adm-policy-section">
                                                            <div class="adm-policy-section-head">
                                                                <span class="adm-step-num">"3"</span>
                                                                <div>
                                                                    <h3>"Bypass / Unlock Rules"</h3>
                                                                    <p class="adm-sub">
                                                                        "Bypass = any(Include) AND all(Require) AND none(Exclude). Empty Include never grants bypass."
                                                                    </p>
                                                                </div>
                                                            </div>

                                                            <div class="adm-bypass-groups">
                                                                // INCLUDE (OR)
                                                                <div class="adm-bypass-group">
                                                                    <div class="adm-bypass-group-head">
                                                                        <span class="adm-bypass-tag adm-bypass-tag--include">"Include (OR)"</span>
                                                                        <span class="adm-sub">"Caller must match at least 1 enabled branch"</span>
                                                                    </div>
                                                                    <div class="adm-bypass-toggles">
                                                                        <ToggleSwitch
                                                                            checked=Signal::derive(move || include_switcher.get())
                                                                            on_change=Callback::new(move |v| include_switcher.set(v))
                                                                            label="User Switcher"
                                                                            description="Opt-in category toggle in /user/account bound to this policy's grant generation."
                                                                        />
                                                                        {move || (action_sig.get() == PolicyAction::Blur).then(|| view! {
                                                                            <ToggleSwitch
                                                                                checked=Signal::derive(move || include_click.get())
                                                                                on_change=Callback::new(move |v| include_click.set(v))
                                                                                label="Click to Reveal"
                                                                                description="Allows object-bound single-item reveal via POST /api/safety/reveal (Blur policies only)."
                                                                            />
                                                                        })}
                                                                        <ToggleSwitch
                                                                            checked=Signal::derive(move || include_live_admin.get())
                                                                            on_change=Callback::new(move |v| include_live_admin.set(v))
                                                                            label="Live Admin Bypass"
                                                                            description="Explicit opt-in: live staff CF Access identity only; browse cookie does NOT qualify."
                                                                        />
                                                                    </div>
                                                                    {move || (!any_include.get()).then(|| view! {
                                                                        <div class="adm-inline-info">
                                                                            "No Include branch is enabled — this policy is strictly enforced for all callers (zero bypass)."
                                                                        </div>
                                                                    })}
                                                                </div>

                                                                // REQUIRE (AND)
                                                                <div class="adm-bypass-group">
                                                                    <div class="adm-bypass-group-head">
                                                                        <span class="adm-bypass-tag adm-bypass-tag--require">"Require (AND)"</span>
                                                                        <span class="adm-sub">"Every enabled requirement must pass"</span>
                                                                    </div>
                                                                    <div class="adm-bypass-toggles">
                                                                        <ToggleSwitch
                                                                            checked=Signal::derive(move || require_login.get())
                                                                            on_change=Callback::new(move |v| require_login.set(v))
                                                                            label="Gallery Login"
                                                                            description="Requires an active, non-revoked, non-banned gallery account session."
                                                                        />
                                                                        <ToggleSwitch
                                                                            checked=Signal::derive(move || require_age.get())
                                                                            on_change=Callback::new(move |v| require_age.set(v))
                                                                            label="Age 18+"
                                                                            description="Requires verified 18+ status under the site Age Verification policy."
                                                                        />
                                                                        {move || (require_age.get() && site_age_policy.get() == AgeVerificationPolicy::Off).then(|| view! {
                                                                            <div class="adm-inline-warn">
                                                                                "Site Age Verification is currently OFF (in Age & Legal tab). Enable Self-Attestation or Strict 18+ before publishing require_age_18."
                                                                            </div>
                                                                        })}
                                                                        <ToggleSwitch
                                                                            checked=Signal::derive(move || require_terms.get())
                                                                            on_change=Callback::new(move |v| require_terms.set(v))
                                                                            label="Current Terms"
                                                                            description="Requires acceptance of the exact active Terms version and SHA-256 digest."
                                                                        />
                                                                    </div>
                                                                </div>

                                                                // EXCLUDE (NOR)
                                                                <div class="adm-bypass-group">
                                                                    <div class="adm-bypass-group-head">
                                                                        <span class="adm-bypass-tag adm-bypass-tag--exclude">"Exclude (NOR)"</span>
                                                                        <span class="adm-sub">"Matching any exclusion always denies bypass"</span>
                                                                    </div>
                                                                    <div class="adm-bypass-toggles">
                                                                        <ToggleSwitch
                                                                            checked=Signal::derive(move || exclude_anon.get())
                                                                            on_change=Callback::new(move |v| exclude_anon.set(v))
                                                                            label="Anonymous Visitors"
                                                                            description="Always deny bypass for visitors without a gallery session or live staff identity."
                                                                        />
                                                                        <label class="adm-field">
                                                                            <span>"Exclude Countries (ISO-3166 alpha-2 deny list)"</span>
                                                                            <input
                                                                                type="text"
                                                                                class="adm-mono"
                                                                                placeholder="e.g. US, GB"
                                                                                prop:value=move || exclude_countries_text.get()
                                                                                on:input=move |ev| exclude_countries_text.set(event_target_value(&ev))
                                                                            />
                                                                            <small class="adm-field-hint">
                                                                                "Comma-separated 2-letter codes. When non-empty, missing / unknown (XX) / Tor (T1) countries are automatically denied."
                                                                            </small>
                                                                        </label>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    // Balanced Live Preview Sidebar
                                                    <aside class="adm-policy-preview-col">
                                                        <div class="adm-preview-caption">"Live Placeholder Preview"</div>
                                                        {move || {
                                                            let mask = GalleryMask {
                                                                rule_id: id_sig.get(),
                                                                label: {
                                                                    let n = name_sig.get();
                                                                    if n.trim().is_empty() {
                                                                        "Restricted Content".to_string()
                                                                    } else {
                                                                        n
                                                                    }
                                                                },
                                                                preset: to_ui_preset(preset_sig.get()),
                                                                reason: None,
                                                                requires_login: require_login.get(),
                                                                requires_age: require_age.get(),
                                                                requires_terms: require_terms.get(),
                                                                cta_label: None,
                                                            };
                                                            view! {
                                                                <ContentMaskCard
                                                                    mask=mask
                                                                    dimensions=(4, 3)
                                                                    compact=true
                                                                />
                                                            }
                                                        }}
                                                        <div class="adm-preview-meta">
                                                            <span class="adm-badge">
                                                                {move || match action_sig.get() {
                                                                    PolicyAction::Block => "Action: Block",
                                                                    PolicyAction::Blur => "Action: Blur",
                                                                }}
                                                            </span>
                                                            <span class="adm-badge adm-mono">
                                                                {move || format!("{}@{}", id_sig.get(), gen_sig.get())}
                                                            </span>
                                                        </div>
                                                    </aside>
                                                </div>
                                            </article>
                                        }
                                    }
                                </For>
                            </div>
                        }.into_any()
                    }
                }}
            </section>

            <div class="adm-save-bar">
                <span class="adm-sub">
                    "Enforcement edits conservatively bump min_enforce_rev, advance grant_generation on scope changes, and activate via two-phase SitePolicyDO ACK."
                </span>
                <button type="submit" class="adm-btn adm-btn--primary" disabled=move || saving.get()>
                    {move || if saving.get() { "Publishing…" } else { "Publish Content Safety Policy" }}
                </button>
            </div>
        </form>
    }
}
