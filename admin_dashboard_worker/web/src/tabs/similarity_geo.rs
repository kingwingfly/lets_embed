//! Similarity & Geo tab:
//! - Default DINOv3 & SigLIP2 cosine similarity cutoffs using keyboard-friendly
//!   `lets_embed_ui::ScoreInput` (`0.00..=1.00`, `step=0.01`, zero native HTML5 step popups)
//! - Authoritative ISO-3166 country blocklist + `XX` (unknown) & `T1` (Tor) `<ToggleSwitch>`
//! - GCP top-right toasts via `use_toast_store()`

use leptos::prelude::*;
use lets_embed_ui::{ScoreInput, ToggleSwitch, use_toast_store};
use site_access::{GeoPolicy, SimilarityDefaults};
use wasm_bindgen_futures::spawn_local;

use crate::api::{
    ActivationResult, SafetyConfigResp, SaveSafetyReq, SaveSafetyResp, post_json_activatable,
};

#[component]
pub fn SimilarityGeoTab(
    safety: RwSignal<Option<SafetyConfigResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let toasts = use_toast_store();

    let dinov3_min = RwSignal::new(0.0f32);
    let siglip2_min = RwSignal::new(0.0f32);
    let countries_text = RwSignal::new(String::new());
    let block_unknown = RwSignal::new(false);
    let block_tor = RwSignal::new(false);
    let revision = RwSignal::new(0u64);

    let saving = RwSignal::new(false);

    Effect::new(move |_| {
        if let Some(cfg) = safety.get() {
            revision.set(cfg.revision);
            dinov3_min.set(cfg.similarity.dinov3_min);
            siglip2_min.set(cfg.similarity.siglip2_min);
            countries_text.set(cfg.geo.blocked_countries.join(", "));
            block_unknown.set(cfg.geo.block_unknown);
            block_tor.set(cfg.geo.block_tor);
        }
    });

    let on_save = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if saving.get_untracked() {
            return;
        }
        let Some(current) = safety.get_untracked() else {
            return;
        };

        let blocked_countries: Vec<String> = countries_text
            .get_untracked()
            .split(|c: char| c == ',' || c.is_whitespace() || c == ';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_uppercase())
            .collect();

        saving.set(true);

        let req = SaveSafetyReq {
            revision: revision.get_untracked(),
            safety_enabled: current.safety_enabled,
            policies: current.policies,
            unclassified_mode: current.unclassified_mode,
            fixed_blur_enabled: current.fixed_blur_enabled,
            age_policy: current.age_policy,
            age_gate_trigger: current.age_gate_trigger,
            similarity: SimilarityDefaults {
                dinov3_min: dinov3_min.get_untracked(),
                siglip2_min: siglip2_min.get_untracked(),
            },
            geo: GeoPolicy {
                blocked_countries,
                block_unknown: block_unknown.get_untracked(),
                block_tor: block_tor.get_untracked(),
            },
            legal: current.legal,
        };

        spawn_local(async move {
            match post_json_activatable::<_, SaveSafetyResp>("/admin/api/safety", &req).await {
                Ok(ActivationResult::Active(resp)) => {
                    revision.set(resp.revision);
                    toasts.success(
                        format!("Published Similarity & Geo policy rev #{}", resp.revision),
                        Some(format!(
                            "min_enforce_rev #{} · tightened={}",
                            resp.min_enforce_rev, resp.tightened
                        )),
                    );
                    on_saved.run(());
                }
                Ok(ActivationResult::PendingActivation(pending)) => {
                    revision.set(pending.revision);
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
                                prop:value=move || format!("{:.2}", dinov3_min.get())
                                on:input=move |ev| {
                                    if let Ok(v) = event_target_value(&ev).parse::<f32>()
                                        && v.is_finite()
                                    {
                                        dinov3_min.set(v.clamp(0.0, 1.0));
                                    }
                                }
                            />
                            <div class="adm-score-input-box">
                                <ScoreInput
                                    value=Signal::derive(move || dinov3_min.get())
                                    on_change=Callback::new(move |v| dinov3_min.set(v))
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
                                prop:value=move || format!("{:.2}", siglip2_min.get())
                                on:input=move |ev| {
                                    if let Ok(v) = event_target_value(&ev).parse::<f32>()
                                        && v.is_finite()
                                    {
                                        siglip2_min.set(v.clamp(0.0, 1.0));
                                    }
                                }
                            />
                            <div class="adm-score-input-box">
                                <ScoreInput
                                    value=Signal::derive(move || siglip2_min.get())
                                    on_change=Callback::new(move |v| siglip2_min.set(v))
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
                        prop:value=move || countries_text.get()
                        on:input=move |ev| countries_text.set(event_target_value(&ev))
                    />
                </label>

                <div class="adm-toggle-grid">
                    <ToggleSwitch
                        checked=Signal::derive(move || block_unknown.get())
                        on_change=Callback::new(move |v| block_unknown.set(v))
                        label="Block unknown / missing country (`XX`)"
                        description="Reject visitors whose IP has no resolved Cloudflare country code with HTTP 451."
                    />
                    <ToggleSwitch
                        checked=Signal::derive(move || block_tor.get())
                        on_change=Callback::new(move |v| block_tor.set(v))
                        label="Block Tor exit nodes (`T1`)"
                        description="Reject traffic Cloudflare identifies as Tor exit network (`T1`) with HTTP 451."
                    />
                </div>
            </section>

            <div class="adm-save-bar">
                <span class="adm-sub">"Editing geo-restrictions conservatively bumps min_enforce_rev and notifies SitePolicyDO."</span>
                <button type="submit" class="adm-btn adm-btn--primary" disabled=move || saving.get()>
                    {move || if saving.get() { "Publishing…" } else { "Save Similarity & Geo Policy" }}
                </button>
            </div>
        </form>
    }
}
