//! Geo-Blocking tab:
//! - Authoritative ISO-3166 country blocklist + R-18/Adult prohibited countries preset
//! - `XX` (unknown) & `T1` (Tor) `<ToggleSwitch>`
//! - Live equivalent Cloudflare WAF Custom Rule generator with one-click clipboard copy
//! - Root-level persistent draft (`AdminDraftStore`) + GCP top-right toasts via `use_toast_store()`

use leptos::prelude::*;
use lets_embed_ui::{ToggleSwitch, use_toast_store};
use site_access::{
    GeoPolicy, R18_PROHIBITED_COUNTRIES, is_valid_iso_country_code, merge_country_codes,
};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::{
    api::{
        ActivationResult, SafetyConfigResp, SaveSafetyReq, SaveSafetyResp, copy_text_to_clipboard,
        post_json_activatable,
    },
    drafts::{parse_country_codes, use_admin_drafts},
};

#[derive(Clone, PartialEq, Eq)]
struct GeoDraftPreview {
    valid_count: usize,
    invalid_tokens: Vec<String>,
    waf_expr: Option<String>,
    waf_code_count: usize,
}

#[component]
pub fn GeoTab(
    safety: RwSignal<Option<SafetyConfigResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let toasts = use_toast_store();
    let draft = use_admin_drafts().geo;

    let saving = RwSignal::new(false);
    let copied_waf = RwSignal::new(false);

    let geo_preview = Memo::new(move |_| {
        let raw_tokens = parse_country_codes(&draft.countries_text.get());
        let mut valid_countries = Vec::new();
        let mut invalid_tokens = Vec::new();
        for tok in raw_tokens {
            if is_valid_iso_country_code(&tok) {
                valid_countries.push(tok);
            } else {
                invalid_tokens.push(tok);
            }
        }
        let valid_count = valid_countries.len();
        let policy = GeoPolicy {
            blocked_countries: valid_countries,
            block_unknown: draft.block_unknown.get(),
            block_tor: draft.block_tor.get(),
        };
        let waf_code_count = policy.cloudflare_waf_codes().len();
        let waf_expr = policy.to_cloudflare_waf_expression();
        GeoDraftPreview {
            valid_count,
            invalid_tokens,
            waf_expr,
            waf_code_count,
        }
    });

    let on_apply_r18_preset = move |_| {
        let existing = parse_country_codes(&draft.countries_text.get_untracked());
        let before = existing.len();
        let merged = merge_country_codes(&existing, R18_PROHIBITED_COUNTRIES);
        let added = merged.len().saturating_sub(before);
        draft.countries_text.set(merged.join(", "));
        if added > 0 {
            draft.dirty.set(true);
            toasts.info(
                format!(
                    "Added {added} R-18 prohibited {} ({} total)",
                    if added == 1 { "country" } else { "countries" },
                    merged.len()
                ),
                Some(
                    "Review the list or copy the generated Cloudflare WAF rule below before saving."
                        .to_string(),
                ),
            );
        } else {
            toasts.info(
                format!(
                    "All {} R-18 prohibited countries are already included",
                    R18_PROHIBITED_COUNTRIES.len()
                ),
                None,
            );
        }
    };

    let on_clear_countries = move |_| {
        if !draft.countries_text.get_untracked().trim().is_empty() {
            draft.countries_text.set(String::new());
            draft.dirty.set(true);
        }
    };

    let on_copy_waf = move |_| {
        let Some(expr) = geo_preview.with_untracked(|p| p.waf_expr.clone()) else {
            return;
        };
        spawn_local(async move {
            match copy_text_to_clipboard(&expr).await {
                Ok(()) => {
                    copied_waf.set(true);
                    toasts.success(
                        "Copied Cloudflare WAF rule to clipboard",
                        Some(
                            "Paste into Cloudflare Dashboard -> Security -> WAF -> Custom rules -> Edit expression."
                                .to_string(),
                        ),
                    );
                    let cb = wasm_bindgen::closure::Closure::once(move || {
                        copied_waf.set(false);
                    });
                    if let Some(win) = web_sys::window() {
                        let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
                            cb.as_ref().unchecked_ref(),
                            2200,
                        );
                    }
                    cb.forget();
                }
                Err(msg) => {
                    toasts.error("Failed to copy WAF rule", Some(msg));
                }
            }
        });
    };

    let on_discard = move |_| {
        if let Some(cfg) = safety.get_untracked() {
            draft.hydrate(&cfg);
            draft.dirty.set(false);
            toasts.info("Discarded unsaved Geo-Blocking changes", None);
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

        let blocked_countries = parse_country_codes(&draft.countries_text.get_untracked());

        saving.set(true);

        let req = SaveSafetyReq {
            revision: current.revision,
            safety_enabled: current.safety_enabled,
            policies: current.policies,
            unclassified_mode: current.unclassified_mode,
            fixed_blur_enabled: current.fixed_blur_enabled,
            age_policy: current.age_policy,
            age_gate_trigger: current.age_gate_trigger,
            similarity: current.similarity,
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
                            format!("Published Geo-Blocking policy rev #{}", resp.revision),
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
                    toasts.error("Failed to save Geo-Blocking policy", Some(err.message));
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
                        <h2>"Authoritative Geo-Restriction (Edge `request.cf().country()`)"</h2>
                        <p class="adm-sub">
                            "Evaluated at `gateway_worker` before routing, caching, or admin browse pass, returning HTTP 451. `/admin*` is always exempt so staff cannot lock themselves out."
                        </p>
                    </div>
                    <span class="adm-pill">
                        {move || {
                            let count = geo_preview.with(|p| p.valid_count);
                            format!("{count} {}", if count == 1 { "country" } else { "countries" })
                        }}
                    </span>
                </div>

                <div class="adm-geo-preset-bar">
                    <button
                        type="button"
                        class="adm-btn adm-btn--sm adm-btn--preset-r18"
                        on:click=on_apply_r18_preset
                    >
                        {format!("+ R-18 / Adult Prohibited Countries ({})", R18_PROHIBITED_COUNTRIES.len())}
                    </button>
                    {move || (!draft.countries_text.get().trim().is_empty()).then(|| view! {
                        <button
                            type="button"
                            class="adm-btn adm-btn--sm"
                            on:click=on_clear_countries
                        >
                            "Clear list"
                        </button>
                    })}
                    <span class="adm-field-hint">
                        "Merges ISO-3166 codes for jurisdictions prohibiting or blocking online adult/R-18 content. Review & edit before publishing."
                    </span>
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

                {move || {
                    let bad = geo_preview.with(|p| p.invalid_tokens.clone());
                    (!bad.is_empty()).then(|| view! {
                        <div class="adm-inline-warn">
                            {format!(
                                "Ignored invalid code(s) in WAF preview (will be rejected on save): {}. Use 2-letter ISO-3166 codes, or use the XX / T1 toggles below.",
                                bad.join(", ")
                            )}
                        </div>
                    })
                }}

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

                <div class="adm-waf-box">
                    <div class="adm-waf-head">
                        <div class="adm-waf-head-meta">
                            <h3>"Equivalent Cloudflare WAF Custom Rule"</h3>
                            <span class="adm-badge">
                                {move || {
                                    let n = geo_preview.with(|p| p.waf_code_count);
                                    if n == 0 {
                                        "No active codes".to_string()
                                    } else {
                                        let mut extras = Vec::new();
                                        if draft.block_unknown.get() {
                                            extras.push("XX");
                                        }
                                        if draft.block_tor.get() {
                                            extras.push("T1");
                                        }
                                        if extras.is_empty() {
                                            format!("{n} {}", if n == 1 { "code" } else { "codes" })
                                        } else {
                                            format!("{n} codes (incl. {})", extras.join(", "))
                                        }
                                    }
                                }}
                            </span>
                        </div>
                        <button
                            type="button"
                            class="adm-btn adm-btn--sm adm-btn--primary"
                            disabled=move || geo_preview.with(|p| p.waf_expr.is_none())
                            on:click=on_copy_waf
                        >
                            {move || if copied_waf.get() { "Copied!" } else { "Copy WAF Rule" }}
                        </button>
                    </div>
                    {move || match geo_preview.with(|p| p.waf_expr.clone()) {
                        Some(expr) => view! {
                            <pre class="adm-waf-code"><code>{expr}</code></pre>
                        }.into_any(),
                        None => view! {
                            <div class="adm-waf-empty">
                                "Add blocked country codes, apply the R-18 preset, or enable XX / T1 toggles to generate a ready-to-paste Cloudflare WAF Custom Rule."
                            </div>
                        }.into_any(),
                    }}
                    <p class="adm-field-hint">
                        "Paste into Cloudflare Dashboard → Security → WAF → Custom rules → Edit expression (Action: Block, optional custom response HTTP 451). Blocking at the WAF edge stops banned traffic before Worker invocations while keeping `/admin*` exempt."
                    </p>
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
                        {move || if saving.get() { "Publishing…" } else { "Save Geo-Blocking Policy" }}
                    </button>
                </div>
            </div>
        </form>
    }
}
