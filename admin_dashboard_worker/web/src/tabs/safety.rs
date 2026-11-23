//! Content Safety & Presets tab:
//! - Master `safety_enabled` toggle, `unclassified_mode`, `cloudflare_images_blur` toggle
//!   with explicit warning that free CSS blur is voluntary visual spoiler only
//! - 0..N editable rule cards powered by `lets_embed_ui::QueryRuleBuilder`, WD-Tagger
//!   preset buttons, client-side validation via `search_types::safety::parse_safety_rule`,
//!   and a live `lets_embed_ui::ContentMaskCard` preview!

use std::sync::atomic::{AtomicU64, Ordering};

use leptos::prelude::*;
use lets_embed_ui::{
    ContentMaskCard, GalleryMask, GalleryMaskPreset, NoticeBanner, NoticeContent, NoticeTone,
    PresetTemplate, QueryRuleBuilder, RuleDraft, RuleMode as UiRuleMode,
    rule_syntax::parse_safety_rule_to_blocks,
};
use search_types::safety::parse_safety_rule;
use site_access::{PlaceholderPreset, RuleMode, SafetyRuleConfig, UnclassifiedMode};
use wasm_bindgen_futures::spawn_local;

use crate::api::{SafetyConfigResp, SaveSafetyReq, SaveSafetyResp, post_json};

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

fn to_ui_mode(m: RuleMode) -> UiRuleMode {
    match m {
        RuleMode::Switcher => UiRuleMode::Switcher,
        RuleMode::SpoilerBlur => UiRuleMode::SpoilerBlur,
    }
}

fn from_ui_mode(m: UiRuleMode) -> RuleMode {
    match m {
        UiRuleMode::Switcher => RuleMode::Switcher,
        UiRuleMode::SpoilerBlur => RuleMode::SpoilerBlur,
    }
}

#[derive(Clone)]
struct EditableRuleCard {
    key: u64,
    id: RwSignal<String>,
    enabled: RwSignal<bool>,
    default_min_score: RwSignal<f32>,
    requires_login: RwSignal<bool>,
    requires_age_18: RwSignal<bool>,
    draft: RwSignal<RuleDraft>,
}

impl EditableRuleCard {
    fn from_config(cfg: &SafetyRuleConfig) -> Self {
        let mut alloc = alloc_key;
        let blocks = parse_safety_rule_to_blocks(&cfg.query, &mut alloc).unwrap_or_default();
        let draft = RuleDraft {
            name: cfg.name.clone(),
            mode: to_ui_mode(cfg.mode),
            preset: to_ui_preset(cfg.preset),
            requires_age: cfg.requires_age_18,
            blocks,
            query: cfg.query.clone(),
        };
        Self {
            key: alloc_key(),
            id: RwSignal::new(cfg.id.clone()),
            enabled: RwSignal::new(cfg.enabled),
            default_min_score: RwSignal::new(cfg.default_min_score),
            requires_login: RwSignal::new(cfg.requires_login),
            requires_age_18: RwSignal::new(cfg.requires_age_18),
            draft: RwSignal::new(draft),
        }
    }

    fn to_config(&self) -> SafetyRuleConfig {
        let d = self.draft.get_untracked();
        SafetyRuleConfig {
            id: self.id.get_untracked().trim().to_ascii_lowercase(),
            name: d.name.trim().to_string(),
            mode: from_ui_mode(d.mode),
            query: d.query.trim().to_string(),
            default_min_score: self.default_min_score.get_untracked(),
            preset: from_ui_preset(d.preset),
            requires_login: self.requires_login.get_untracked(),
            requires_age_18: self.requires_age_18.get_untracked(),
            enabled: self.enabled.get_untracked(),
        }
    }
}

#[component]
pub fn SafetyTab(
    safety: RwSignal<Option<SafetyConfigResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let safety_enabled = RwSignal::new(false);
    let unclassified_mode = RwSignal::new(UnclassifiedMode::LockFailClosed);
    let cf_blur = RwSignal::new(false);
    let rule_cards = RwSignal::new(Vec::<EditableRuleCard>::new());
    let revision = RwSignal::new(0u32);
    let min_enforce_rev = RwSignal::new(0u32);

    let saving = RwSignal::new(false);
    let feedback = RwSignal::new(Option::<(bool, String)>::None);

    Effect::new(move |_| {
        if let Some(cfg) = safety.get() {
            revision.set(cfg.revision);
            min_enforce_rev.set(cfg.min_enforce_rev);
            safety_enabled.set(cfg.safety_enabled);
            unclassified_mode.set(cfg.unclassified_mode);
            cf_blur.set(cfg.cloudflare_images_blur);
            let cards = cfg.rules.iter().map(EditableRuleCard::from_config).collect();
            rule_cards.set(cards);
        }
    });

    let add_preset_rule = move |tpl: SafetyRuleConfig| {
        let existing_ids: Vec<String> = rule_cards
            .get_untracked()
            .iter()
            .map(|c| c.id.get_untracked())
            .collect();
        let mut candidate = tpl.id.clone();
        let mut suffix = 2u32;
        while existing_ids.iter().any(|x| x == &candidate) {
            candidate = format!("{}-{suffix}", tpl.id);
            suffix += 1;
        }
        let mut cfg = tpl;
        cfg.id = candidate;
        cfg.enabled = !cfg.query.trim().is_empty();
        rule_cards.update(|list| list.push(EditableRuleCard::from_config(&cfg)));
    };

    let on_save = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if saving.get_untracked() {
            return;
        }
        let Some(current) = safety.get_untracked() else {
            return;
        };

        let rules: Vec<SafetyRuleConfig> = rule_cards
            .get_untracked()
            .iter()
            .map(EditableRuleCard::to_config)
            .collect();

        // Client-side metadata-only grammar sanity check before network roundtrip.
        for rule in &rules {
            if !rule.query.is_empty()
                && let Err(e) = parse_safety_rule(&rule.query)
            {
                feedback.set(Some((false, format!("Rule '{}': {e}", rule.id))));
                return;
            }
        }

        saving.set(true);
        feedback.set(None);

        let req = SaveSafetyReq {
            revision: revision.get_untracked(),
            safety_enabled: safety_enabled.get_untracked(),
            rules,
            unclassified_mode: unclassified_mode.get_untracked(),
            cloudflare_images_blur: cf_blur.get_untracked(),
            age_policy: current.age_policy,
            age_gate_trigger: current.age_gate_trigger,
            similarity: current.similarity,
            geo: current.geo,
            legal: current.legal,
            panic_shortcut: current.panic_shortcut,
        };

        spawn_local(async move {
            match post_json::<_, SaveSafetyResp>("/admin/api/safety", &req).await {
                Ok(resp) => {
                    revision.set(resp.revision);
                    min_enforce_rev.set(resp.min_enforce_rev);
                    let mut msg = format!(
                        "Published safety policy rev #{} (min_enforce_rev={}, tightened={}).",
                        resp.revision, resp.min_enforce_rev, resp.tightened
                    );
                    if !resp.auto_disabled_providers.is_empty() {
                        msg.push_str(&format!(
                            " Auto-disabled {} incompatible provider(s).",
                            resp.auto_disabled_providers.len()
                        ));
                    }
                    feedback.set(Some((true, msg)));
                    on_saved.run(());
                }
                Err(err) => feedback.set(Some((false, err))),
            }
            saving.set(false);
        });
    };

    view! {
        <form class="adm-stack" on:submit=on_save>
            {move || feedback.get().map(|(ok, msg)| view! {
                <div class=if ok { "adm-alert adm-alert--ok" } else { "adm-alert adm-alert--err" } role="status">
                    {msg}
                </div>
            })}

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Content Safety Engine"</h2>
                        <p class="adm-sub">"Disabled by default on fresh deployments (zero SQL/UI overhead until enabled)."</p>
                    </div>
                    <span class="adm-pill">
                        {move || format!("rev #{} · min_enforce #{}", revision.get(), min_enforce_rev.get())}
                    </span>
                </div>

                <div class="adm-toggle-grid">
                    <label class="adm-switch-row">
                        <input
                            type="checkbox"
                            prop:checked=move || safety_enabled.get()
                            on:change=move |ev| safety_enabled.set(event_target_checked(&ev))
                        />
                        <span>
                            <strong>"Enable server-side content safety filtering"</strong>
                            <small>"Evaluates Switcher & Spoiler rules server-side before HTML, hydration, API, or media delivery."</small>
                        </span>
                    </label>

                    <label class="adm-switch-row">
                        <input
                            type="checkbox"
                            prop:checked=move || cf_blur.get()
                            on:change=move |ev| cf_blur.set(event_target_checked(&ev))
                        />
                        <span>
                            <strong>"Cloudflare Images server-side spoiler blur"</strong>
                            <small>"Gateway applies locked Worker cf.image blur (blur=80, width=360, webp) on /media/preview/*."</small>
                        </span>
                    </label>
                </div>

                {move || (!cf_blur.get()).then(|| view! {
                    <NoticeBanner
                        tone=NoticeTone::Warning
                        title="CSS Courtesy Blur Notice"
                        dismissible=false
                        content=NoticeContent::Text(
                            "Cloudflare Images server-side blur is OFF. Spoiler Blur rules will use free client-side CSS blur, which is a voluntary visual spoiler only (clear pixels are still delivered to the browser). Use Switcher mode or enable Cloudflare Images blur for hard gating."
                                .to_string()
                        )
                    />
                })}

                <div class="adm-field">
                    <span>"Unclassified media policy (`images.status != 'completed'` or video-only posts)"</span>
                    <div class="adm-grid-2">
                        <label class="adm-radio-card">
                            <input
                                type="radio"
                                name="unclassified_mode"
                                prop:checked=move || unclassified_mode.get() == UnclassifiedMode::LockFailClosed
                                on:change=move |_| unclassified_mode.set(UnclassifiedMode::LockFailClosed)
                            />
                            <span>
                                <strong>"Fail-closed Locked (Recommended)"</strong>
                                <small>"Pending or legacy-ingested items stay Locked whenever any Switcher rule is enabled."</small>
                            </span>
                        </label>
                        <label class="adm-radio-card">
                            <input
                                type="radio"
                                name="unclassified_mode"
                                prop:checked=move || unclassified_mode.get() == UnclassifiedMode::Allow
                                on:change=move |_| unclassified_mode.set(UnclassifiedMode::Allow)
                            />
                            <span>
                                <strong>"Allow unclassified"</strong>
                                <small>"Explicit admin opt-in to display pending items as Clear before WD-Tagger finishes."</small>
                            </span>
                        </label>
                    </div>
                </div>

                {move || safety.get().map(|cfg| view! {
                    <div class="adm-note-box">
                        <strong>"Legacy backfill tip: "</strong>
                        <span>{cfg.legacy_unclassified_note}</span>
                    </div>
                })}
            </section>

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Safety Rules & WD-Tagger Presets"</h2>
                        <p class="adm-sub">"Metadata-only rules (`tag:`, `post_tag:`, `author:`, `unclassified`). Vector operators and regexes are strictly rejected."</p>
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
                                        on:click=move |_| add_preset_rule(tpl.clone())
                                    >
                                        {label}
                                    </button>
                                }
                            }).collect_view()
                        })}
                    </div>
                </div>

                {move || {
                    let list = rule_cards.get();
                    if list.is_empty() {
                        view! {
                            <div class="adm-empty-card">
                                "No safety rules configured. Click a WD-Tagger preset button above (R-18, Suggestive / Ecchi, Blood / Gore, or Custom) to add one."
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="adm-stack">
                                <For
                                    each=move || rule_cards.get()
                                    key=|card| card.key
                                    let(card)
                                >
                                    {
                                        let card_key = card.key;
                                        let id_sig = card.id;
                                        let enabled_sig = card.enabled;
                                        let min_score_sig = card.default_min_score;
                                        let req_login_sig = card.requires_login;
                                        let req_age_sig = card.requires_age_18;
                                        let draft_sig = card.draft;

                                        let rule_err = Signal::derive(move || {
                                            let q = draft_sig.with(|d| d.query.trim().to_string());
                                            if q.is_empty() {
                                                if enabled_sig.get() {
                                                    Some("Enabled rule requires at least one metadata predicate.".to_string())
                                                } else {
                                                    None
                                                }
                                            } else {
                                                parse_safety_rule(&q).err().map(|e| e.to_string())
                                            }
                                        });

                                        let on_draft_change = Callback::new(move |d: RuleDraft| {
                                            req_age_sig.set(d.requires_age);
                                        });

                                        view! {
                                            <div class="adm-rule-card">
                                                <div class="adm-rule-card-head">
                                                    <div class="adm-rule-meta-grid">
                                                        <label class="adm-field">
                                                            <span>"Rule ID (slug)"</span>
                                                            <input
                                                                type="text"
                                                                placeholder="r18"
                                                                prop:value=move || id_sig.get()
                                                                on:input=move |ev| id_sig.set(event_target_value(&ev))
                                                            />
                                                        </label>
                                                        <label class="adm-field">
                                                            <span>"Display Label"</span>
                                                            <input
                                                                type="text"
                                                                placeholder="NSFW"
                                                                prop:value=move || draft_sig.with(|d| d.name.clone())
                                                                on:input=move |ev| {
                                                                    let val = event_target_value(&ev);
                                                                    draft_sig.update(|d| d.name = val);
                                                                }
                                                            />
                                                        </label>
                                                        <label class="adm-field">
                                                            <span>"Mode"</span>
                                                            <select
                                                                prop:value=move || draft_sig.with(|d| d.mode.as_str().to_string())
                                                                on:change=move |ev| {
                                                                    let m = UiRuleMode::parse(&event_target_value(&ev));
                                                                    draft_sig.update(|d| d.mode = m);
                                                                }
                                                            >
                                                                <option value="switcher">"Switcher (Hard Locked)"</option>
                                                                <option value="spoiler_blur">"Spoiler Blur"</option>
                                                            </select>
                                                        </label>
                                                        <label class="adm-field">
                                                            <span>"Placeholder Art"</span>
                                                            <select
                                                                prop:value=move || draft_sig.with(|d| d.preset.as_str().to_string())
                                                                on:change=move |ev| {
                                                                    let p = GalleryMaskPreset::parse(&event_target_value(&ev));
                                                                    draft_sig.update(|d| d.preset = p);
                                                                }
                                                            >
                                                                <option value="r18">"R-18 (18+ badge)"</option>
                                                                <option value="sensitive">"Sensitive / Eye-off"</option>
                                                                <option value="blood">"Blood / Warning"</option>
                                                                <option value="custom">"Custom Shield"</option>
                                                            </select>
                                                        </label>
                                                        <label class="adm-field">
                                                            <span>"Default Min Score"</span>
                                                            <input
                                                                type="number"
                                                                min="0.01"
                                                                max="1.00"
                                                                step="0.05"
                                                                prop:value=move || format!("{:.2}", min_score_sig.get())
                                                                on:input=move |ev| {
                                                                    if let Ok(v) = event_target_value(&ev).parse::<f32>()
                                                                        && v.is_finite()
                                                                    {
                                                                        min_score_sig.set(v.clamp(0.01, 1.0));
                                                                    }
                                                                }
                                                            />
                                                        </label>
                                                    </div>

                                                    <div class="adm-rule-flags">
                                                        <label class="adm-check">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || enabled_sig.get()
                                                                on:change=move |ev| enabled_sig.set(event_target_checked(&ev))
                                                            />
                                                            <span>"Enabled"</span>
                                                        </label>
                                                        <label class="adm-check">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || req_login_sig.get()
                                                                on:change=move |ev| req_login_sig.set(event_target_checked(&ev))
                                                            />
                                                            <span>"Requires Login"</span>
                                                        </label>
                                                        <label class="adm-check">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || req_age_sig.get()
                                                                on:change=move |ev| {
                                                                    let checked = event_target_checked(&ev);
                                                                    req_age_sig.set(checked);
                                                                    draft_sig.update(|d| d.requires_age = checked);
                                                                }
                                                            />
                                                            <span>"Requires 18+"</span>
                                                        </label>
                                                        <button
                                                            type="button"
                                                            class="adm-btn adm-btn--danger adm-btn--sm"
                                                            on:click=move |_| {
                                                                rule_cards.update(|list| list.retain(|c| c.key != card_key));
                                                            }
                                                        >
                                                            "Remove Rule"
                                                        </button>
                                                    </div>
                                                </div>

                                                <div class="adm-rule-card-body">
                                                    <div class="adm-rule-builder-col">
                                                        <QueryRuleBuilder
                                                            draft=draft_sig
                                                            presets=PresetTemplate::builtins()
                                                            validation_error=rule_err
                                                            on_change=on_draft_change
                                                        />
                                                    </div>
                                                    <div class="adm-rule-preview-col">
                                                        <div class="adm-preview-caption">"Live ContentMaskCard Preview"</div>
                                                        {move || {
                                                            let d = draft_sig.get();
                                                            let mask = GalleryMask {
                                                                rule_id: id_sig.get(),
                                                                label: d.name,
                                                                preset: d.preset,
                                                                reason: None,
                                                                requires_login: req_login_sig.get(),
                                                                requires_age: req_age_sig.get(),
                                                                requires_terms: req_age_sig.get(),
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
                                                    </div>
                                                </div>
                                            </div>
                                        }
                                    }
                                </For>
                            </div>
                        }.into_any()
                    }
                }}
            </section>

            <div class="adm-save-bar">
                <span class="adm-sub">"Tightening safety rules automatically bumps min_enforce_rev and notifies SitePolicyDO."</span>
                <button type="submit" class="adm-btn adm-btn--primary" disabled=move || saving.get()>
                    {move || if saving.get() { "Publishing…" } else { "Publish Content Safety Policy" }}
                </button>
            </div>
        </form>
    }
}
