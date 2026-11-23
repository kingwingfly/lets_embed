//! Similarity & Geo tab:
//! - Default DINOv3 & SigLIP2 cosine similarity cutoffs via `lets_embed_ui::MinSimilaritySlider`
//! - Authoritative ISO-3166 country blocklist + `XX` (unknown) & `T1` (Tor) toggles

use leptos::prelude::*;
use lets_embed_ui::MinSimilaritySlider;
use site_access::{GeoPolicy, SimilarityDefaults};
use wasm_bindgen_futures::spawn_local;

use crate::api::{SafetyConfigResp, SaveSafetyReq, SaveSafetyResp, post_json};

#[component]
pub fn SimilarityGeoTab(
    safety: RwSignal<Option<SafetyConfigResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let dinov3_min = RwSignal::new(0.0f32);
    let siglip2_min = RwSignal::new(0.0f32);
    let countries_text = RwSignal::new(String::new());
    let block_unknown = RwSignal::new(false);
    let block_tor = RwSignal::new(false);
    let revision = RwSignal::new(0u32);

    let saving = RwSignal::new(false);
    let feedback = RwSignal::new(Option::<(bool, String)>::None);

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
        feedback.set(None);

        let req = SaveSafetyReq {
            revision: revision.get_untracked(),
            safety_enabled: current.safety_enabled,
            rules: current.rules,
            unclassified_mode: current.unclassified_mode,
            cloudflare_images_blur: current.cloudflare_images_blur,
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
            panic_shortcut: current.panic_shortcut,
        };

        spawn_local(async move {
            match post_json::<_, SaveSafetyResp>("/admin/api/safety", &req).await {
                Ok(resp) => {
                    revision.set(resp.revision);
                    feedback.set(Some((
                        true,
                        format!(
                            "Published Similarity & Geo policy rev #{} (min_enforce_rev={}, tightened={}).",
                            resp.revision, resp.min_enforce_rev, resp.tightened
                        ),
                    )));
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
                        <h2>"Default Vector Similarity Thresholds"</h2>
                        <p class="adm-sub">"Site-wide default minimum cosine similarity (`1.0 - distance >= min_similarity`). Visitors can adjust per-search sliders on `/` and `/details/:id`."</p>
                    </div>
                </div>
                <div class="adm-grid-2">
                    <div class="adm-subcard">
                        <MinSimilaritySlider
                            value=dinov3_min
                            label="Default Image Similarity"
                            model_badge="DINOv3"
                        />
                        <p class="adm-sub">"Applies to similar-image lookups (`dino:<id>`) and uploaded-image searches."</p>
                    </div>
                    <div class="adm-subcard">
                        <MinSimilaritySlider
                            value=siglip2_min
                            label="Default Description Similarity"
                            model_badge="SigLIP2"
                        />
                        <p class="adm-sub">"Applies to natural-language text description searches (`clip:`)."</p>
                    </div>
                </div>
            </section>

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Authoritative Geo-Restriction (Edge `request.cf().country()`)"</h2>
                        <p class="adm-sub">"Evaluated at `gateway_worker` before routing, caching, or admin browse pass, returning HTTP 451. `/admin*` is always exempt so staff cannot lock themselves out."</p>
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
                    <label class="adm-switch-row">
                        <input
                            type="checkbox"
                            prop:checked=move || block_unknown.get()
                            on:change=move |ev| block_unknown.set(event_target_checked(&ev))
                        />
                        <span>
                            <strong>"Block unknown / missing country (`XX`)"</strong>
                            <small>"Reject visitors whose IP has no resolved Cloudflare country code with HTTP 451."</small>
                        </span>
                    </label>
                    <label class="adm-switch-row">
                        <input
                            type="checkbox"
                            prop:checked=move || block_tor.get()
                            on:change=move |ev| block_tor.set(event_target_checked(&ev))
                        />
                        <span>
                            <strong>"Block Tor exit nodes (`T1`)"</strong>
                            <small>"Reject traffic Cloudflare identifies as Tor exit network (`T1`) with HTTP 451."</small>
                        </span>
                    </label>
                </div>
            </section>

            <div class="adm-save-bar">
                <span class="adm-sub">"Expanding the blocked country list or enabling XX/T1 blocking immediately bumps min_enforce_rev."</span>
                <button type="submit" class="adm-btn adm-btn--primary" disabled=move || saving.get()>
                    {move || if saving.get() { "Publishing…" } else { "Save Similarity & Geo Policy" }}
                </button>
            </div>
        </form>
    }
}
