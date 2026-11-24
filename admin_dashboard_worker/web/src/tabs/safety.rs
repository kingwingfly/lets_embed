//! Cloudflare Access-Style Content Safety Policy v3 Builder tab:
//! - Root-level persistent draft (`AdminDraftStore`) so switching tabs never loses edits
//! - Yellow (`R18`), Purple (`Sensitive`), Red (`Blood`) preset colors across buttons,
//!   folded/expanded rule badges, card accents, and live `<ContentMaskCard>` preview
//! - Compact single-row `tag IN (...) >= 0.45` preset seeding
//! - Foldable (collapsible) policy cards with 1-line summary header + Collapse/Expand all
//! - Auto-enable Content Safety Engine when adding rules or enabling any rule while OFF
//! - 1-click "Open Age & Legal tab →" inside `Require Age 18+` warning
//! - No-op save detection info toast (`"No changes to save (rev #N)"`)

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

use crate::{
    api::{
        ActivationResult, SafetyConfigResp, SaveSafetyReq, SaveSafetyResp, post_json_activatable,
    },
    drafts::{
        EditablePolicyCard, compact_safety_presets, normalize_preset_compact, preset_badge_label,
        preset_button_label, preset_css_slug, use_admin_drafts,
    },
    tabs::AdminTab,
};

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

#[component]
pub fn SafetyTab(
    safety: RwSignal<Option<SafetyConfigResp>>,
    on_saved: Callback<()>,
    on_navigate: Callback<AdminTab>,
) -> impl IntoView {
    let toasts = use_toast_store();
    let draft = use_admin_drafts().safety;

    let saving = RwSignal::new(false);

    let site_age_policy = Memo::new(move |_| {
        safety
            .get()
            .map(|c| c.age_policy)
            .unwrap_or(AgeVerificationPolicy::Off)
    });

    let has_enabled_policies = Memo::new(move |_| {
        draft
            .policy_cards
            .with(|cards| cards.iter().any(|c| c.enabled.get()))
    });

    let any_expanded = Memo::new(move |_| {
        draft
            .policy_cards
            .with(|cards| cards.iter().any(|c| !c.collapsed.get()))
    });

    let auto_enable_safety_if_off = move || {
        if !draft.safety_enabled.get_untracked() {
            draft.safety_enabled.set(true);
            toasts.info(
                "Content Safety filtering enabled automatically for your rule",
                None,
            );
        }
    };

    let add_policy_template = move |tpl: ContentPolicy| {
        let existing = draft.policy_cards.get_untracked();
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
        let mut pol = normalize_preset_compact(tpl);
        pol.id = candidate;
        pol.grant_generation = 1;
        pol.priority = max_prio.saturating_add(10);
        pol.enabled = true;
        // Ensure new policies never silently default to live admin bypass!
        pol.bypass.include_live_admin = false;
        let label = pol.name.clone();
        draft.push_new_policy(&pol);
        draft.dirty.set(true);
        auto_enable_safety_if_off();
        toasts.info(
            format!("Added policy \"{label}\""),
            Some("Configure selector & bypass rules, then click Publish Content Safety Policy.".to_string()),
        );
    };

    let add_custom_policy = move |_| {
        add_policy_template(ContentPolicy {
            id: "custom".to_string(),
            grant_generation: 1,
            enabled: true,
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

    let on_toggle_all_collapse = move |_| {
        let collapse_next = any_expanded.get_untracked();
        draft.policy_cards.with_untracked(|cards| {
            for card in cards {
                card.collapsed.set(collapse_next);
            }
        });
    };

    let on_discard = move |_| {
        if let Some(cfg) = safety.get_untracked() {
            draft.hydrate(&cfg, false);
            draft.dirty.set(false);
            toasts.info("Discarded unsaved Content Safety changes", None);
        }
    };

    let on_save = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if saving.get_untracked() {
            return;
        }
        let Some(current) = safety.get_untracked() else {
            return;
        };

        let policies: Vec<ContentPolicy> = draft
            .policy_cards
            .get_untracked()
            .iter()
            .map(EditablePolicyCard::to_policy)
            .collect();

        // Client-side full Policy v3 validation (catches WD-Tagger typos, Block+click,
        // Age18+Off, invalid country codes, and term/depth limits before round-trip).
        let candidate = PublicSitePolicy {
            schema_version: SITE_POLICY_SCHEMA_VERSION,
            revision: current.revision.saturating_add(1),
            min_enforce_rev: current.min_enforce_rev,
            policy_digest: String::new(),
            vocab_digest: WD_VOCAB_DIGEST.to_string(),
            safety_enabled: draft.safety_enabled.get_untracked(),
            unclassified_mode: draft.unclassified_mode.get_untracked(),
            fixed_blur_enabled: draft.fixed_blur_enabled.get_untracked(),
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
        draft.server_field_errors.set(Vec::new());

        let req = SaveSafetyReq {
            revision: current.revision,
            safety_enabled: draft.safety_enabled.get_untracked(),
            policies,
            unclassified_mode: draft.unclassified_mode.get_untracked(),
            fixed_blur_enabled: draft.fixed_blur_enabled.get_untracked(),
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
                    draft.revision.set(resp.revision);
                    draft.min_enforce_rev.set(resp.min_enforce_rev);
                    draft.dirty.set(false);
                    if resp.unchanged {
                        toasts.info(format!("No changes to save (rev #{})", resp.revision), None);
                    } else {
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
                }
                Ok(ActivationResult::PendingActivation(pending)) => {
                    draft.revision.set(pending.revision);
                    draft.min_enforce_rev.set(pending.min_enforce_rev);
                    draft.dirty.set(false);
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
                    draft.server_field_errors.set(err.field_errors);
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
                        {move || format!(
                            "rev #{} · min_enforce #{} · v3",
                            draft.revision.get(),
                            draft.min_enforce_rev.get()
                        )}
                    </span>
                </div>

                <div class="adm-toggle-grid">
                    <ToggleSwitch
                        checked=Signal::derive(move || draft.safety_enabled.get())
                        on_change=Callback::new(move |v| {
                            draft.safety_enabled.set(v);
                            draft.dirty.set(true);
                        })
                        label="Enable server-side content safety filtering"
                        description="Evaluates all active Block & Blur policies server-side before HTML, hydration, API, search, or media delivery."
                    />
                    <ToggleSwitch
                        checked=Signal::derive(move || draft.fixed_blur_enabled.get())
                        on_change=Callback::new(move |v| {
                            draft.fixed_blur_enabled.set(v);
                            draft.dirty.set(true);
                        })
                        label="Fixed server-side blurred previews (Paid Cloudflare Images)"
                        description="Serves Cloudflare Images previews (blur=80, width=360, webp) on /media/preview/*. Billed by Cloudflare at $0.50 / 1,000 unique blurred images per month (after 5,000 free/mo) — leave OFF to use zero-cost Placeholders."
                    />
                </div>

                {move || if draft.fixed_blur_enabled.get() {
                    view! {
                        <NoticeBanner
                            tone=NoticeTone::Warning
                            title="Cloudflare Images Billing Active ($0.50 / 1,000 Unique Blurred Images / Month)"
                            dismissible=false
                            content=NoticeContent::Text(
                                "Each unique image requested via /media/preview/* counts as 1 Cloudflare Images transformation per calendar month beyond the 5,000 free/mo tier (e.g., 200,000 blurred images/mo ≈ $97.50/mo; 600,000 ≈ $297.50/mo). Turn this OFF and use Block (Placeholder) rules if you want $0 transformation cost."
                                    .to_string()
                            )
                        />
                    }.into_any()
                } else {
                    view! {
                        <NoticeBanner
                            tone=NoticeTone::Info
                            title="Fixed Server Preview Disabled ($0 Transformation Cost — Recommended)"
                            dismissible=false
                            content=NoticeContent::Text(
                                "Server-side blurred previews are OFF. Any policy set to Blur safely degrades to a zero-cost hard Placeholder until fixed server previews are enabled (Cloudflare Images costs $0.50 / 1,000 unique blurred images/mo beyond 5,000 free/mo). Clear media bytes are never sent before reveal."
                                    .to_string()
                            )
                        />
                    }.into_any()
                }}

                <div class="adm-field">
                    <span>"Unclassified media policy (`images.status != 'completed'`)"</span>
                    <div class="adm-grid-2">
                        <label class="adm-radio-card">
                            <input
                                type="radio"
                                name="unclassified_mode"
                                prop:checked=move || draft.unclassified_mode.get() == UnclassifiedMode::Placeholder
                                on:change=move |_| {
                                    draft.unclassified_mode.set(UnclassifiedMode::Placeholder);
                                    draft.dirty.set(true);
                                }
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
                                prop:checked=move || draft.unclassified_mode.get() == UnclassifiedMode::Continue
                                on:change=move |_| {
                                    draft.unclassified_mode.set(UnclassifiedMode::Continue);
                                    draft.dirty.set(true);
                                }
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
                        {move || {
                            let presets = safety
                                .get()
                                .map(|cfg| {
                                    if cfg.presets.is_empty() {
                                        compact_safety_presets()
                                    } else {
                                        cfg.presets
                                            .into_iter()
                                            .map(normalize_preset_compact)
                                            .collect()
                                    }
                                })
                                .unwrap_or_else(compact_safety_presets);
                            presets
                                .into_iter()
                                .map(|preset| {
                                    let btn_class = format!(
                                        "adm-btn adm-btn--sm adm-btn--preset-{}",
                                        preset_css_slug(preset.preset)
                                    );
                                    let label = preset_button_label(preset.preset);
                                    let tpl = preset.clone();
                                    view! {
                                        <button
                                            type="button"
                                            class=btn_class
                                            on:click=move |_| add_policy_template(tpl.clone())
                                        >
                                            {label}
                                        </button>
                                    }
                                })
                                .collect_view()
                        }}
                        <button
                            type="button"
                            class="adm-btn adm-btn--sm adm-btn--primary"
                            on:click=add_custom_policy
                        >
                            "+ Custom Policy"
                        </button>
                        {move || (draft.policy_cards.with(Vec::len) >= 2).then(|| view! {
                            <button
                                type="button"
                                class="adm-btn adm-btn--sm"
                                on:click=on_toggle_all_collapse
                            >
                                {move || if any_expanded.get() { "Collapse all" } else { "Expand all" }}
                            </button>
                        })}
                    </div>
                </div>

                {move || {
                    let is_empty = draft.policy_cards.with(Vec::is_empty);
                    if is_empty {
                        view! {
                            <div class="adm-empty-card">
                                "No content policies configured yet. Click a WD-Tagger preset button above (+ NSFW, + Suggestive / Ecchi, + Blood / Violence) or + Custom Policy to create one."
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="adm-stack">
                                <For
                                    each=move || draft.policy_cards.get()
                                    key=|card| card.key
                                    let(card)
                                >
                                    {
                                        let card_key = card.key;
                                        let persisted = card.persisted;
                                        let collapsed_sig = card.collapsed;
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
                                        let card_for_selector = card.clone();
                                        let card_for_bypass = card.clone();

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
                                            draft.server_field_errors.with(|errs| {
                                                errs.iter()
                                                    .find(|e| e.policy_id.as_deref() == Some(cur_id.as_str()) && e.field == "match_expr")
                                                    .map(|e| e.message.clone())
                                            })
                                        });

                                        let except_err = Signal::derive(move || {
                                            let q = except_draft.with(|d| d.query.clone());
                                            if q.trim().is_empty() && !except_open.get() {
                                                return None;
                                            }
                                            if let Some(local_err) = validate_expr_client(&q, false) {
                                                return Some(local_err);
                                            }
                                            let cur_id = id_sig.get();
                                            draft.server_field_errors.with(|errs| {
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
                                            draft.dirty.set(true);
                                        });

                                        let on_query_change = Callback::new(move |_: QueryBuilderDraft| {
                                            draft.dirty.set(true);
                                        });

                                        let any_include = Memo::new(move |_| {
                                            include_switcher.get()
                                                || (action_sig.get() == PolicyAction::Blur && include_click.get())
                                                || include_live_admin.get()
                                        });

                                        view! {
                                            <article class=move || {
                                                let slug = preset_css_slug(preset_sig.get());
                                                let state = if collapsed_sig.get() { " is-collapsed" } else { "" };
                                                let off = if !enabled_sig.get() { " is-disabled" } else { "" };
                                                format!("adm-policy-card adm-policy-card--{slug}{state}{off}")
                                            }>
                                                // Always-visible 1-line foldable summary header
                                                <div class="adm-policy-summary-bar">
                                                    <button
                                                        type="button"
                                                        class="adm-policy-toggle-btn"
                                                        aria-expanded=move || (!collapsed_sig.get()).to_string()
                                                        on:click=move |_| collapsed_sig.update(|c| *c = !*c)
                                                    >
                                                        <span class="adm-policy-chevron" aria-hidden="true">
                                                            {move || if collapsed_sig.get() { "▸" } else { "▾" }}
                                                        </span>
                                                        <span class=move || format!(
                                                            "adm-preset-badge adm-preset-badge--{}",
                                                            preset_css_slug(preset_sig.get())
                                                        )>
                                                            {move || preset_badge_label(preset_sig.get())}
                                                        </span>
                                                        <strong class="adm-policy-summary-name">
                                                            {move || {
                                                                let n = name_sig.get();
                                                                if n.trim().is_empty() {
                                                                    "Untitled Policy".to_string()
                                                                } else {
                                                                    n
                                                                }
                                                            }}
                                                        </strong>
                                                        <span class=move || match action_sig.get() {
                                                            PolicyAction::Block => "adm-action-pill adm-action-pill--block",
                                                            PolicyAction::Blur => "adm-action-pill adm-action-pill--blur",
                                                        }>
                                                            {move || match action_sig.get() {
                                                                PolicyAction::Block => "Block",
                                                                PolicyAction::Blur => "Blur",
                                                            }}
                                                        </span>
                                                        <span class="adm-policy-selector-summary adm-mono">
                                                            {move || card_for_selector.selector_summary()}
                                                        </span>
                                                        <span class="adm-policy-bypass-summary">
                                                            {move || card_for_bypass.bypass_summary()}
                                                        </span>
                                                    </button>

                                                    <div class="adm-policy-head-actions">
                                                        <ToggleSwitch
                                                            checked=Signal::derive(move || enabled_sig.get())
                                                            on_change=Callback::new(move |v| {
                                                                enabled_sig.set(v);
                                                                draft.dirty.set(true);
                                                                if v {
                                                                    auto_enable_safety_if_off();
                                                                }
                                                            })
                                                            label="Enabled"
                                                            compact=true
                                                        />
                                                        <button
                                                            type="button"
                                                            class="adm-btn adm-btn--danger adm-btn--sm"
                                                            on:click=move |_| {
                                                                let removed = name_sig.get_untracked();
                                                                draft.policy_cards.update(|list| list.retain(|c| c.key != card_key));
                                                                draft.dirty.set(true);
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

                                                // Smoothly collapsible rule editor body
                                                <div
                                                    class="adm-policy-body"
                                                    aria-hidden=move || collapsed_sig.get().to_string()
                                                >
                                                    <div class="adm-policy-body-inner">
                                                        // Editable Metadata Fields
                                                        <div class="adm-policy-head-fields">
                                                            <label class="adm-field">
                                                                <span>"Display Name"</span>
                                                                <input
                                                                    type="text"
                                                                    placeholder="NSFW / Explicit"
                                                                    prop:value=move || name_sig.get()
                                                                    on:input=move |ev| {
                                                                        name_sig.set(event_target_value(&ev));
                                                                        draft.dirty.set(true);
                                                                    }
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
                                                                            draft.dirty.set(true);
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
                                                                            draft.dirty.set(true);
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
                                                                        draft.dirty.set(true);
                                                                    }
                                                                >
                                                                    <option value="r18">"R-18 (Yellow 18+ badge)"</option>
                                                                    <option value="sensitive">"Sensitive (Purple Eye-off)"</option>
                                                                    <option value="blood">"Blood / Violence (Red Warning)"</option>
                                                                    <option value="custom">"Custom Shield"</option>
                                                                </select>
                                                            </label>
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
                                                                on_change=on_query_change
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
                                                                        on_change=Callback::new(move |v| {
                                                                            default_tag_min.set(v);
                                                                            draft.dirty.set(true);
                                                                        })
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
                                                                        } else if !except_draft.with(|d| d.query.trim().is_empty()) {
                                                                            "+ Show Exclude / Exception (except_expr)"
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
                                                                                draft.dirty.set(true);
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
                                                                            on_change=on_query_change
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
                                                                                draft.dirty.set(true);
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
                                                                                draft.dirty.set(true);
                                                                            }
                                                                        >
                                                                            <strong>"Blur"</strong>
                                                                            <small>"Cloudflare Images preview ($0.50/1k unique imgs/mo) + optional Click to Reveal; degrades to free Placeholder when preview is OFF"</small>
                                                                        </button>
                                                                    </div>

                                                                    {move || (action_sig.get() == PolicyAction::Blur && !draft.fixed_blur_enabled.get()).then(|| view! {
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
                                                                                    on_change=Callback::new(move |v| {
                                                                                        include_switcher.set(v);
                                                                                        draft.dirty.set(true);
                                                                                    })
                                                                                    label="User Switcher"
                                                                                    description="Opt-in category toggle in /user/account bound to this policy's grant generation."
                                                                                />
                                                                                {move || (action_sig.get() == PolicyAction::Blur).then(|| view! {
                                                                                    <ToggleSwitch
                                                                                        checked=Signal::derive(move || include_click.get())
                                                                                        on_change=Callback::new(move |v| {
                                                                                            include_click.set(v);
                                                                                            draft.dirty.set(true);
                                                                                        })
                                                                                        label="Click to Reveal"
                                                                                        description="Allows object-bound single-item reveal via POST /api/safety/reveal (Blur policies only)."
                                                                                    />
                                                                                })}
                                                                                <ToggleSwitch
                                                                                    checked=Signal::derive(move || include_live_admin.get())
                                                                                    on_change=Callback::new(move |v| {
                                                                                        include_live_admin.set(v);
                                                                                        draft.dirty.set(true);
                                                                                    })
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
                                                                                    on_change=Callback::new(move |v| {
                                                                                        require_login.set(v);
                                                                                        draft.dirty.set(true);
                                                                                    })
                                                                                    label="Gallery Login"
                                                                                    description="Requires an active, non-revoked, non-banned gallery account session."
                                                                                />
                                                                                <ToggleSwitch
                                                                                    checked=Signal::derive(move || require_age.get())
                                                                                    on_change=Callback::new(move |v| {
                                                                                        require_age.set(v);
                                                                                        draft.dirty.set(true);
                                                                                    })
                                                                                    label="Age 18+"
                                                                                    description="Requires verified 18+ status under the site Age Verification policy."
                                                                                />
                                                                                {move || (require_age.get() && site_age_policy.get() == AgeVerificationPolicy::Off).then(|| view! {
                                                                                    <div class="adm-inline-warn adm-inline-warn--action">
                                                                                        <span>
                                                                                            "Site Age Verification is currently OFF (in Age & Legal tab). Enable Self-Attestation or Strict 18+ before publishing require_age_18 — your Safety rule draft will stay intact."
                                                                                        </span>
                                                                                        <button
                                                                                            type="button"
                                                                                            class="adm-btn adm-btn--sm adm-btn--warn-outline"
                                                                                            on:click=move |_| on_navigate.run(AdminTab::AgeLegal)
                                                                                        >
                                                                                            "Open Age & Legal tab →"
                                                                                        </button>
                                                                                    </div>
                                                                                })}
                                                                                <ToggleSwitch
                                                                                    checked=Signal::derive(move || require_terms.get())
                                                                                    on_change=Callback::new(move |v| {
                                                                                        require_terms.set(v);
                                                                                        draft.dirty.set(true);
                                                                                    })
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
                                                                                    on_change=Callback::new(move |v| {
                                                                                        exclude_anon.set(v);
                                                                                        draft.dirty.set(true);
                                                                                    })
                                                                                    label="Anonymous Visitors"
                                                                                    description="Always deny bypass for visitors without a gallery session or live staff identity."
                                                                                />
                                                                                <div class="adm-field">
                                                                                    <div class="adm-field-label-inline">
                                                                                        <span>"Exclude Countries (ISO-3166 alpha-2 deny list)"</span>
                                                                                        <div class="adm-field-label-actions">
                                                                                            <button
                                                                                                type="button"
                                                                                                class="adm-btn adm-btn--sm adm-btn--preset-r18"
                                                                                                on:click=move |_| {
                                                                                                    let existing = crate::drafts::parse_country_codes(&exclude_countries_text.get_untracked());
                                                                                                    let merged = site_access::merge_country_codes(
                                                                                                        &existing,
                                                                                                        site_access::R18_PROHIBITED_COUNTRIES,
                                                                                                    );
                                                                                                    exclude_countries_text.set(merged.join(", "));
                                                                                                    draft.dirty.set(true);
                                                                                                }
                                                                                            >
                                                                                                {format!("+ R-18 Prohibited ({})", site_access::R18_PROHIBITED_COUNTRIES.len())}
                                                                                            </button>
                                                                                            {move || (!exclude_countries_text.get().trim().is_empty()).then(|| view! {
                                                                                                <button
                                                                                                    type="button"
                                                                                                    class="adm-btn adm-btn--sm"
                                                                                                    on:click=move |_| {
                                                                                                        exclude_countries_text.set(String::new());
                                                                                                        draft.dirty.set(true);
                                                                                                    }
                                                                                                >
                                                                                                    "Clear"
                                                                                                </button>
                                                                                            })}
                                                                                        </div>
                                                                                    </div>
                                                                                    <input
                                                                                        type="text"
                                                                                        class="adm-mono"
                                                                                        placeholder="e.g. US, GB"
                                                                                        prop:value=move || exclude_countries_text.get()
                                                                                        on:input=move |ev| {
                                                                                            exclude_countries_text.set(event_target_value(&ev));
                                                                                            draft.dirty.set(true);
                                                                                        }
                                                                                    />
                                                                                    <small class="adm-field-hint">
                                                                                        "Comma-separated 2-letter codes. When non-empty, missing / unknown (XX) / Tor (T1) countries are automatically denied."
                                                                                    </small>
                                                                                </div>
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
                                                                    <span class=move || format!(
                                                                        "adm-preset-badge adm-preset-badge--{}",
                                                                        preset_css_slug(preset_sig.get())
                                                                    )>
                                                                        {move || preset_badge_label(preset_sig.get())}
                                                                    </span>
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
                                                    </div>
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

            {move || (!draft.safety_enabled.get() && has_enabled_policies.get()).then(|| view! {
                <div class="adm-inline-warn adm-safety-off-notice" role="status">
                    "Content Safety Engine is currently OFF — rules are saved as drafts and won't filter until enabled"
                </div>
            })}

            <div class="adm-save-bar">
                <span class="adm-sub">
                    "Enforcement edits conservatively bump min_enforce_rev, advance grant_generation on scope changes, and activate via two-phase SitePolicyDO ACK."
                </span>
                <div class="adm-save-bar-actions">
                    {move || draft.dirty.get().then(|| view! {
                        <button
                            type="button"
                            class="adm-btn"
                            disabled=move || saving.get()
                            on:click=on_discard
                        >
                            "Discard changes"
                        </button>
                    })}
                    <button type="submit" class="adm-btn adm-btn--primary" disabled=move || saving.get()>
                        {move || if saving.get() { "Publishing…" } else { "Publish Content Safety Policy" }}
                    </button>
                </div>
            </div>
        </form>
    }
}
