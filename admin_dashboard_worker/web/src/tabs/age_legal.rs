//! Age & Legal tab:
//! - Three-tier Age Verification Policy selector (left-aligned radio cards)
//! - Auto-selects `JustInTime` when switching `Off` -> `SelfAttestation` while trigger is `Off`
//! - Auto-prefills `DEFAULT_NOTICE_BANNER_MD` when enabling notice banner with blank text
//! - Versioned Markdown editors for `/terms`, `/privacy`, `/dmca`, `/content-policy`
//! - Root-level persistent draft (`AdminDraftStore`) + GCP top-right toasts via `use_toast_store()`

use leptos::prelude::*;
use lets_embed_ui::{NoticeBanner, NoticeContent, NoticeTone, ToggleSwitch, use_toast_store};
use site_access::{
    AgeGateTrigger, AgeVerificationPolicy, DEFAULT_NOTICE_BANNER_MD, LegalDocConfig,
};
use wasm_bindgen_futures::spawn_local;

use crate::{
    api::{
        ActivationResult, SafetyConfigResp, SaveSafetyReq, SaveSafetyResp, post_json_activatable,
    },
    drafts::use_admin_drafts,
};

#[component]
pub fn AgeLegalTab(
    safety: RwSignal<Option<SafetyConfigResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let toasts = use_toast_store();
    let draft = use_admin_drafts().age_legal;

    let saving = RwSignal::new(false);

    let has_age_gated_policies = Memo::new(move |_| {
        safety
            .get()
            .is_some_and(|cfg| cfg.policies.iter().any(|p| p.bypass.require_age_18))
    });

    let on_discard = move |_| {
        if let Some(cfg) = safety.get_untracked() {
            draft.hydrate(&cfg);
            draft.dirty.set(false);
            toasts.info("Discarded unsaved Age & Legal changes", None);
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

        let next_age_policy = draft.age_policy.get_untracked();
        if next_age_policy == AgeVerificationPolicy::Off
            && current.policies.iter().any(|p| p.bypass.require_age_18)
        {
            toasts.error(
                "Cannot turn Age Verification Off",
                Some(
                    "One or more Content Safety policies require Age 18+. Disable require_age_18 on those policies first."
                        .to_string(),
                ),
            );
            return;
        }

        saving.set(true);

        let legal = LegalDocConfig {
            terms_version: draft.terms_version.get_untracked(),
            terms_digest: draft.terms_digest.get_untracked(),
            terms_md: draft.terms_md.get_untracked(),
            privacy_md: draft.privacy_md.get_untracked(),
            dmca_md: draft.dmca_md.get_untracked(),
            content_policy_md: draft.content_policy_md.get_untracked(),
            notice_banner_md: draft.notice_banner_md.get_untracked(),
            notice_banner_enabled: draft.notice_banner_enabled.get_untracked(),
            rta_meta_enabled: draft.rta_meta_enabled.get_untracked(),
            noindex_restricted: draft.noindex_restricted.get_untracked(),
        };

        let req = SaveSafetyReq {
            revision: current.revision,
            safety_enabled: current.safety_enabled,
            policies: current.policies,
            unclassified_mode: current.unclassified_mode,
            fixed_blur_enabled: current.fixed_blur_enabled,
            age_policy: next_age_policy,
            age_gate_trigger: draft.age_gate_trigger.get_untracked(),
            similarity: current.similarity,
            geo: current.geo,
            legal,
            confirm_policy_v3_migration: false,
        };

        spawn_local(async move {
            match post_json_activatable::<_, SaveSafetyResp>("/admin/api/safety", &req).await {
                Ok(ActivationResult::Active(resp)) => {
                    draft.revision.set(resp.revision);
                    draft.terms_version.set(resp.legal.terms_version);
                    draft.terms_digest.set(resp.legal.terms_digest.clone());
                    draft.dirty.set(false);
                    if resp.unchanged {
                        toasts.info(format!("No changes to save (rev #{})", resp.revision), None);
                    } else {
                        let mut detail = format!(
                            "Terms v{} · min_enforce_rev #{}",
                            resp.legal.terms_version, resp.min_enforce_rev
                        );
                        if resp.terms_bumped {
                            detail.push_str(" · Terms bumped (users must re-accept)");
                        }
                        if !resp.auto_disabled_providers.is_empty() {
                            detail.push_str(&format!(
                                " · auto-disabled {} non-18+ provider(s)",
                                resp.auto_disabled_providers.len()
                            ));
                        }
                        toasts.success(
                            format!("Published Age & Legal policy rev #{}", resp.revision),
                            Some(detail),
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
                    toasts.error("Failed to save Age & Legal policy", Some(err.message));
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
                        <h2>"Age Verification Policy (3-Tier)"</h2>
                        <p class="adm-sub">"Controls which authentication providers and age-assurance claims satisfy `Age 18+` bypass requirements."</p>
                    </div>
                </div>

                <div class="adm-grid-3">
                    <label class="adm-radio-card">
                        <input
                            type="radio"
                            name="age_policy"
                            prop:checked=move || draft.age_policy.get() == AgeVerificationPolicy::Off
                            on:change=move |_| {
                                draft.age_policy.set(AgeVerificationPolicy::Off);
                                draft.dirty.set(true);
                            }
                        />
                        <span class="adm-radio-copy">
                            <strong>"Off"</strong>
                            <small>"No age verification active; policies with Age 18+ requirement cannot be published."</small>
                        </span>
                    </label>
                    <label class="adm-radio-card">
                        <input
                            type="radio"
                            name="age_policy"
                            prop:checked=move || draft.age_policy.get() == AgeVerificationPolicy::SelfAttestation
                            on:change=move |_| {
                                let prev = draft.age_policy.get_untracked();
                                draft.age_policy.set(AgeVerificationPolicy::SelfAttestation);
                                draft.dirty.set(true);
                                if prev == AgeVerificationPolicy::Off
                                    && draft.age_gate_trigger.get_untracked() == AgeGateTrigger::Off
                                {
                                    draft.age_gate_trigger.set(AgeGateTrigger::JustInTime);
                                    toasts.info(
                                        "Age Gate Trigger set to Just-in-Time so 18+ confirmation prompts appear",
                                        None,
                                    );
                                }
                            }
                        />
                        <span class="adm-radio-copy">
                            <strong>"Self-Attestation"</strong>
                            <small>"Users confirm 18+ and accept Terms. Optional Google birthday soft pre-check available."</small>
                        </span>
                    </label>
                    <label class="adm-radio-card">
                        <input
                            type="radio"
                            name="age_policy"
                            prop:checked=move || draft.age_policy.get() == AgeVerificationPolicy::StrictProviderVerified18
                            on:change=move |_| {
                                draft.age_policy.set(AgeVerificationPolicy::StrictProviderVerified18);
                                draft.dirty.set(true);
                            }
                        />
                        <span class="adm-radio-copy">
                            <strong>"Strict Provider-Verified 18+"</strong>
                            <small>"ONLY vetted Age-Assurance OIDC providers (e.g. Yoti, Persona OIDC, eID) may grant login or 18+ unlock."</small>
                        </span>
                    </label>
                </div>

                {move || (draft.age_policy.get() == AgeVerificationPolicy::Off && has_age_gated_policies.get()).then(|| view! {
                    <NoticeBanner
                        tone=NoticeTone::Warning
                        title="Active Policies Require Age 18+"
                        dismissible=false
                        content=NoticeContent::Text(
                            "One or more Content Safety policies have `Age 18+` enabled. Disable `Age 18+` on those policies in the Content Safety tab before setting Age Verification to Off."
                                .to_string()
                        )
                    />
                })}

                {move || (draft.age_policy.get() == AgeVerificationPolicy::StrictProviderVerified18).then(|| view! {
                    <NoticeBanner
                        tone=NoticeTone::Warning
                        title="Strict Provider-Verified 18+ Active"
                        dismissible=false
                        content=NoticeContent::Text(
                            "Standard Google OAuth (editable profile birthday), GitHub, X, Discord, Email OTP, Telegram, SIWE, and SIWS are automatically disabled for login and 18+ unlocks in Strict mode. Payment-only wallets can still be linked for top-ups."
                                .to_string()
                        )
                    />
                })}

                <label class="adm-field">
                    <span>"Age Gate Trigger"</span>
                    <select
                        prop:value=move || match draft.age_gate_trigger.get() {
                            AgeGateTrigger::Off => "off",
                            AgeGateTrigger::JustInTime => "just_in_time",
                            AgeGateTrigger::SiteWideSplash => "site_wide_splash",
                        }
                        on:change=move |ev| {
                            let v = match event_target_value(&ev).as_str() {
                                "just_in_time" => AgeGateTrigger::JustInTime,
                                "site_wide_splash" => AgeGateTrigger::SiteWideSplash,
                                _ => AgeGateTrigger::Off,
                            };
                            draft.age_gate_trigger.set(v);
                            draft.dirty.set(true);
                        }
                    >
                        <option value="off">"Off"</option>
                        <option value="just_in_time">"Just-in-time (Recommended for SEO — never blocks /)"</option>
                        <option value="site_wide_splash">"Site-wide entry splash (/terms, /privacy, /dmca, /user/login stay open)"</option>
                    </select>
                </label>

                <div class="adm-toggle-grid">
                    <ToggleSwitch
                        checked=Signal::derive(move || draft.rta_meta_enabled.get())
                        on_change=Callback::new(move |v| {
                            draft.rta_meta_enabled.set(v);
                            draft.dirty.set(true);
                        })
                        label="Emit RTA Adult Rating Meta Tags"
                        description="Adds RTA-5042-1996-1400-1577-RTA and `rating=adult` meta tags on public pages."
                    />
                    <ToggleSwitch
                        checked=Signal::derive(move || draft.noindex_restricted.get())
                        on_change=Callback::new(move |v| {
                            draft.noindex_restricted.set(v);
                            draft.dirty.set(true);
                        })
                        label="`noindex` Bypassable Restricted Pages (SFW-Only SEO)"
                        description="Non-bypassable rules (e.g. Extreme / Gore & Illegal) and unclassified items are always excluded from sitemaps and marked noindex. Enable this to also exclude bypassable restricted pages (e.g. NSFW / Sensitive) from sitemaps and add noindex."
                    />
                </div>
            </section>

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Cookie / Site Notice Banner"</h2>
                        <p class="adm-sub">"Sanitized server-side via strict HTML allowlist before rendering."</p>
                    </div>
                </div>
                <ToggleSwitch
                    checked=Signal::derive(move || draft.notice_banner_enabled.get())
                    on_change=Callback::new(move |v| {
                        draft.notice_banner_enabled.set(v);
                        draft.dirty.set(true);
                        if v && draft.notice_banner_md.get_untracked().trim().is_empty() {
                            draft
                                .notice_banner_md
                                .set(DEFAULT_NOTICE_BANNER_MD.to_string());
                        }
                    })
                    label="Show dismissible site notice banner"
                    description="Displayed across gallery pages with localStorage dismissal."
                />
                <label class="adm-field">
                    <span>"Notice Banner Markdown"</span>
                    <textarea
                        rows="3"
                        placeholder=DEFAULT_NOTICE_BANNER_MD
                        prop:value=move || draft.notice_banner_md.get()
                        on:input=move |ev| {
                            draft.notice_banner_md.set(event_target_value(&ev));
                            draft.dirty.set(true);
                        }
                    />
                </label>
            </section>

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Versioned Legal & Policy Markdown Documents"</h2>
                        <p class="adm-sub">"Editing Terms of Service automatically computes a new SHA-256 digest, bumps `terms_version`, and requires re-acceptance."</p>
                    </div>
                    <span class="adm-pill">
                        {move || {
                            let d = draft.terms_digest.get();
                            let short = if d.len() >= 12 { &d[..12] } else { d.as_str() };
                            format!("Terms v{} ({short}…)", draft.terms_version.get())
                        }}
                    </span>
                </div>

                <label class="adm-field">
                    <span>"Terms of Service (`/terms`)"</span>
                    <textarea
                        rows="8"
                        prop:value=move || draft.terms_md.get()
                        on:input=move |ev| {
                            draft.terms_md.set(event_target_value(&ev));
                            draft.dirty.set(true);
                        }
                    />
                </label>
                <label class="adm-field">
                    <span>"Privacy Policy (`/privacy`)"</span>
                    <textarea
                        rows="6"
                        prop:value=move || draft.privacy_md.get()
                        on:input=move |ev| {
                            draft.privacy_md.set(event_target_value(&ev));
                            draft.dirty.set(true);
                        }
                    />
                </label>
                <label class="adm-field">
                    <span>"DMCA & Copyright Policy (`/dmca`)"</span>
                    <textarea
                        rows="6"
                        prop:value=move || draft.dmca_md.get()
                        on:input=move |ev| {
                            draft.dmca_md.set(event_target_value(&ev));
                            draft.dirty.set(true);
                        }
                    />
                </label>
                <label class="adm-field">
                    <span>"Content Policy (`/content-policy`)"</span>
                    <textarea
                        rows="6"
                        prop:value=move || draft.content_policy_md.get()
                        on:input=move |ev| {
                            draft.content_policy_md.set(event_target_value(&ev));
                            draft.dirty.set(true);
                        }
                    />
                </label>
            </section>

            <div class="adm-save-bar">
                <span class="adm-sub">"All Markdown pages are sanitized server-side with `ammonia` before display."</span>
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
                        {move || if saving.get() { "Publishing…" } else { "Save Age & Legal Policy" }}
                    </button>
                </div>
            </div>
        </form>
    }
}
