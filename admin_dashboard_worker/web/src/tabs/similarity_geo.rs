//! Similarity & Geo tab:
//! - Default DINOv3 & SigLIP2 cosine similarity cutoffs using keyboard-friendly
//!   `lets_embed_ui::ScoreInput` (`0.00..=1.00`, `step=0.01`, zero native HTML5 step popups)
//! - Authoritative ISO-3166 country blocklist + `XX` (unknown) & `T1` (Tor) `<ToggleSwitch>`
//! - Root-level persistent draft (`AdminDraftStore`) + GCP top-right toasts via `use_toast_store()`

use leptos::prelude::*;
use lets_embed_ui::{ScoreInput, ToggleSwitch, use_toast_store};
use site_access::{GeoPolicy, SimilarityDefaults};
use wasm_bindgen_futures::spawn_local;

use crate::{
    api::{
        ActivationResult, SafetyConfigResp, SaveSafetyReq, SaveSafetyResp, post_json_activatable,
    },
    drafts::use_admin_drafts,
};

#[component]
pub fn SimilarityGeoTab(
    safety: RwSignal<Option<SafetyConfigResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let toasts = use_toast_store();
    let draft = use_admin_drafts().similarity_geo;

    let saving = RwSignal::new(false);

    let on_discard = move |_| {
        if let Some(cfg) = safety.get_untracked() {
            draft.hydrate(&cfg);
            draft.dirty.set(false);
            toasts.info("Discarded unsaved Similarity & Geo changes", None);
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

        let blocked_countries: Vec<String> = draft
            .countries_text
            .get_untracked()
            .split(|c: char| c == ',' || c.is_whitespace() || c == ';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_uppercase())
            .collect();

        saving.set(true);

        let req = SaveSafetyReq {
            revision: current.revision,
            safety_enabled: current.safety_enabled,
            policies: current.policies,
            unclassified_mode: current.unclassified_mode,
            fixed_blur_enabled: current.fixed_blur_enabled,
            age_policy: current.age_policy,
            age_gate_trigger: current.age_gate_trigger,
            similarity: SimilarityDefaults {
                dinov3_min: draft.dinov3_min.get_untracked(),
                siglip2_min: draft.siglip2_min.get_untracked(),
            },
            geo: GeoPolicy {
                blocked_countries,
                block_unknown: draft.block_unknown.get_untracked(),
                block_tor: draft.block_tor.get_untracked(),
            },
            legal: current.legal,
            confirm_policy_v3_migration: false,
        };

        spawn_local(async move {
            match post_json_activatable::<_, SaveSafetyResp>("/admin/api/safety", &req).await {
                Ok(ActivationResult::Active(resp)) => {
                    draft.revision.set(resp.revision);
                    draft.dirty.set(false);
                    if resp.unchanged {
                        toasts.info(format!("No changes to save (rev #{})", resp.revision), None);
                    } else {
                        toasts.success(
                            format!("Published Similarity & Geo policy rev #{}", resp.revision),
                            Some(format!(
                                "min_enforce_rev #{} · tightened={}",
                                resp.min_enforce_rev, resp.tightened
                            )),
                        );
                        on_saved.run(());
                    }
                }
                Ok(ActivationResult::PendingActivation(pending)) => {
                    draft.revision.set(pending.revision);
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
                    toasts.error("Failed to save Similarity & Geo policy", Some(err.message));
                }
            }
            saving.set(false);
        });
    };

    view! {
        <form class="adm-stack" on:submit=on_save>
            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Default Vector Similarity Thresholds"</h2>
                        <p class="adm-sub">
                            "Site-wide default minimum cosine similarity (`1.0 - distance >= min_similarity`, 0.00 = no cutoff). Visitors can override per-condition thresholds in Advanced Search."
                        </p>
                    </div>
                </div>

                <div class="adm-grid-2">
                    <div class="adm-subcard">
                        <div class="adm-score-card-head">
                            <div>
                                <h3>"Default Image Similarity"</h3>
                                <p class="adm-sub">"Applies to `dino:<id>` and `upload:` searches when no inline `>=` threshold is set."</p>
                            </div>
                            <span class="adm-pill">"DINOv3"</span>
                        </div>
                        <div class="adm-score-control-row">
                            <input
                                type="range"
                                class="adm-range"
                                min="0"
                                max="1"
                                step="0.01"
                                prop:value=move || format!("{:.2}", draft.dinov3_min.get())
                                on:input=move |ev| {
                                    if let Ok(v) = event_target_value(&ev).parse::<f32>()
                                        && v.is_finite()
                                    {
                                        draft.dinov3_min.set(v.clamp(0.0, 1.0));
                                        draft.dirty.set(true);
                                    }
                                }
                            />
                            <div class="adm-score-input-box">
                                <ScoreInput
                                    value=Signal::derive(move || draft.dinov3_min.get())
                                    on_change=Callback::new(move |v| {
                                        draft.dinov3_min.set(v);
                                        draft.dirty.set(true);
                                    })
                                    min=0.00
                                    max=1.00
                                    step=0.01
                                    aria_label="DINOv3 default minimum similarity"
                                />
                            </div>
                        </div>
                    </div>

                    <div class="adm-subcard">
                        <div class="adm-score-card-head">
                            <div>
                                <h3>"Default Description Similarity"</h3>
                                <p class="adm-sub">"Applies to `clip:` natural-language searches when no inline `>=` threshold is set."</p>
                            </div>
                            <span class="adm-pill">"SigLIP2"</span>
                        </div>
                        <div class="adm-score-control-row">
                            <input
                                type="range"
                                class="adm-range"
                                min="0"
                                max="1"
                                step="0.01"
                                prop:value=move || format!("{:.2}", draft.siglip2_min.get())
                                on:input=move |ev| {
                                    if let Ok(v) = event_target_value(&ev).parse::<f32>()
                                        && v.is_finite()
                                    {
                                        draft.siglip2_min.set(v.clamp(0.0, 1.0));
                                        draft.dirty.set(true);
                                    }
                                }
                            />
                            <div class="adm-score-input-box">
                                <ScoreInput
                                    value=Signal::derive(move || draft.siglip2_min.get())
                                    on_change=Callback::new(move |v| {
                                        draft.siglip2_min.set(v);
                                        draft.dirty.set(true);
                                    })
                                    min=0.00
                                    max=1.00
                                    step=0.01
                                    aria_label="SigLIP2 default minimum similarity"
                                />
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Authoritative Geo-Restriction (Edge `request.cf().country()`)"</h2>
                        <p class="adm-sub">
                            "Evaluated at `gateway_worker` before routing, caching, or admin browse pass, returning HTTP 451. `/admin*` is always exempt so staff cannot lock themselves out."
                        </p>
                    </div>
                </div>

                <label class="adm-field">
                    <span>"Blocked ISO-3166 alpha-2 country codes (comma or space separated, e.g. KP, IR, SY)"</span>
                    <textarea
                        rows="3"
                        placeholder="US, GB, JP…"
                        prop:value=move || draft.countries_text.get()
                        on:input=move |ev| {
                            draft.countries_text.set(event_target_value(&ev));
                            draft.dirty.set(true);
                        }
                    />
                </label>

                <div class="adm-toggle-grid">
                    <ToggleSwitch
                        checked=Signal::derive(move || draft.block_unknown.get())
                        on_change=Callback::new(move |v| {
                            draft.block_unknown.set(v);
                            draft.dirty.set(true);
                        })
                        label="Block unknown / missing country (`XX`)"
                        description="Reject visitors whose IP has no resolved Cloudflare country code with HTTP 451."
                    />
                    <ToggleSwitch
                        checked=Signal::derive(move || draft.block_tor.get())
                        on_change=Callback::new(move |v| {
                            draft.block_tor.set(v);
                            draft.dirty.set(true);
                        })
                        label="Block Tor exit nodes (`T1`)"
                        description="Reject traffic Cloudflare identifies as Tor exit network (`T1`) with HTTP 451."
                    />
                </div>
            </section>

            <div class="adm-save-bar">
                <span class="adm-sub">"Editing geo-restrictions conservatively bumps min_enforce_rev and notifies SitePolicyDO."</span>
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
                        {move || if saving.get() { "Publishing…" } else { "Save Similarity & Geo Policy" }}
                    </button>
                </div>
            </div>
        </form>
    }
}
