//! Age & Legal tab:
//! - Three-tier Age Verification Policy selector (left-aligned radio cards)
//! - Age Gate Trigger (`Off`, `JustInTime`, `SiteWideSplash`)
//! - Versioned Markdown editors for `/terms`, `/privacy`, `/dmca`, `/content-policy`
//! - Dismissible Cookie / Site Notice Banner, RTA adult meta & `noindex_restricted` with `<ToggleSwitch>`
//! - GCP top-right toasts via `use_toast_store()`

use leptos::prelude::*;
use lets_embed_ui::{NoticeBanner, NoticeContent, NoticeTone, ToggleSwitch, use_toast_store};
use site_access::{AgeGateTrigger, AgeVerificationPolicy, LegalDocConfig};
use wasm_bindgen_futures::spawn_local;

use crate::api::{
    ActivationResult, SafetyConfigResp, SaveSafetyReq, SaveSafetyResp, post_json_activatable,
};

#[component]
pub fn AgeLegalTab(
    safety: RwSignal<Option<SafetyConfigResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let toasts = use_toast_store();

    let age_policy = RwSignal::new(AgeVerificationPolicy::Off);
    let age_gate_trigger = RwSignal::new(AgeGateTrigger::Off);

    let terms_version = RwSignal::new(1u32);
    let terms_digest = RwSignal::new(String::new());
    let terms_md = RwSignal::new(String::new());
    let privacy_md = RwSignal::new(String::new());
    let dmca_md = RwSignal::new(String::new());
    let content_policy_md = RwSignal::new(String::new());
    let notice_banner_enabled = RwSignal::new(false);
    let notice_banner_md = RwSignal::new(String::new());
    let rta_meta_enabled = RwSignal::new(false);
    let noindex_restricted = RwSignal::new(false);
    let revision = RwSignal::new(0u64);

    let saving = RwSignal::new(false);

    let has_age_gated_policies = Memo::new(move |_| {
        safety
            .get()
            .is_some_and(|cfg| cfg.policies.iter().any(|p| p.bypass.require_age_18))
    });

    Effect::new(move |_| {
        if let Some(cfg) = safety.get() {
            revision.set(cfg.revision);
            age_policy.set(cfg.age_policy);
            age_gate_trigger.set(cfg.age_gate_trigger);
            terms_version.set(cfg.legal.terms_version);
            terms_digest.set(cfg.legal.terms_digest.clone());
            terms_md.set(cfg.legal.terms_md.clone());
            privacy_md.set(cfg.legal.privacy_md.clone());
            dmca_md.set(cfg.legal.dmca_md.clone());
            content_policy_md.set(cfg.legal.content_policy_md.clone());
            notice_banner_enabled.set(cfg.legal.notice_banner_enabled);
            notice_banner_md.set(cfg.legal.notice_banner_md.clone());
            rta_meta_enabled.set(cfg.legal.rta_meta_enabled);
            noindex_restricted.set(cfg.legal.noindex_restricted);
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

        let next_age_policy = age_policy.get_untracked();
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
            terms_version: terms_version.get_untracked(),
            terms_digest: terms_digest.get_untracked(),
            terms_md: terms_md.get_untracked(),
            privacy_md: privacy_md.get_untracked(),
            dmca_md: dmca_md.get_untracked(),
            content_policy_md: content_policy_md.get_untracked(),
            notice_banner_md: notice_banner_md.get_untracked(),
            notice_banner_enabled: notice_banner_enabled.get_untracked(),
            rta_meta_enabled: rta_meta_enabled.get_untracked(),
            noindex_restricted: noindex_restricted.get_untracked(),
        };

        let req = SaveSafetyReq {
            revision: revision.get_untracked(),
            safety_enabled: current.safety_enabled,
            policies: current.policies,
            unclassified_mode: current.unclassified_mode,
            fixed_blur_enabled: current.fixed_blur_enabled,
            age_policy: next_age_policy,
            age_gate_trigger: age_gate_trigger.get_untracked(),
            similarity: current.similarity,
            geo: current.geo,
            legal,
        };

        spawn_local(async move {
            match post_json_activatable::<_, SaveSafetyResp>("/admin/api/safety", &req).await {
                Ok(ActivationResult::Active(resp)) => {
                    revision.set(resp.revision);
                    terms_version.set(resp.legal.terms_version);
                    terms_digest.set(resp.legal.terms_digest.clone());
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
                            prop:checked=move || age_policy.get() == AgeVerificationPolicy::Off
                            on:change=move |_| age_policy.set(AgeVerificationPolicy::Off)
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
                            prop:checked=move || age_policy.get() == AgeVerificationPolicy::SelfAttestation
                            on:change=move |_| age_policy.set(AgeVerificationPolicy::SelfAttestation)
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
                            prop:checked=move || age_policy.get() == AgeVerificationPolicy::StrictProviderVerified18
                            on:change=move |_| age_policy.set(AgeVerificationPolicy::StrictProviderVerified18)
                        />
                        <span class="adm-radio-copy">
                            <strong>"Strict Provider-Verified 18+"</strong>
                            <small>"ONLY vetted Age-Assurance OIDC providers (e.g. Yoti, Persona OIDC, eID) may grant login or 18+ unlock."</small>
                        </span>
                    </label>
                </div>

                {move || (age_policy.get() == AgeVerificationPolicy::Off && has_age_gated_policies.get()).then(|| view! {
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

                {move || (age_policy.get() == AgeVerificationPolicy::StrictProviderVerified18).then(|| view! {
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
                        prop:value=move || match age_gate_trigger.get() {
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
                            age_gate_trigger.set(v);
                        }
                    >
                        <option value="off">"Off"</option>
                        <option value="just_in_time">"Just-in-time (Recommended for SEO — never blocks /)"</option>
                        <option value="site_wide_splash">"Site-wide entry splash (/terms, /privacy, /dmca, /user/login stay open)"</option>
                    </select>
                </label>

                <div class="adm-toggle-grid">
                    <ToggleSwitch
                        checked=Signal::derive(move || rta_meta_enabled.get())
                        on_change=Callback::new(move |v| rta_meta_enabled.set(v))
                        label="Emit RTA Adult Rating Meta Tags"
                        description="Adds RTA-5042-1996-1400-1577-RTA and `rating=adult` meta tags on public pages."
                    />
                    <ToggleSwitch
                        checked=Signal::derive(move || noindex_restricted.get())
                        on_change=Callback::new(move |v| noindex_restricted.set(v))
                        label="`noindex` Restricted Pages"
                        description="Adds `noindex` robots directive to pages containing blocked adult/restricted items."
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
                    checked=Signal::derive(move || notice_banner_enabled.get())
                    on_change=Callback::new(move |v| notice_banner_enabled.set(v))
                    label="Show dismissible site notice banner"
                    description="Displayed across gallery pages with localStorage dismissal."
                />
                <label class="adm-field">
                    <span>"Notice Banner Markdown"</span>
                    <textarea
                        rows="3"
                        placeholder="This site uses strictly necessary session cookies…"
                        prop:value=move || notice_banner_md.get()
                        on:input=move |ev| notice_banner_md.set(event_target_value(&ev))
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
                            let d = terms_digest.get();
                            let short = if d.len() >= 12 { &d[..12] } else { d.as_str() };
                            format!("Terms v{} ({short}…)", terms_version.get())
                        }}
                    </span>
                </div>

                <label class="adm-field">
                    <span>"Terms of Service (`/terms`)"</span>
                    <textarea
                        rows="8"
                        prop:value=move || terms_md.get()
                        on:input=move |ev| terms_md.set(event_target_value(&ev))
                    />
                </label>
                <label class="adm-field">
                    <span>"Privacy Policy (`/privacy`)"</span>
                    <textarea
                        rows="6"
                        prop:value=move || privacy_md.get()
                        on:input=move |ev| privacy_md.set(event_target_value(&ev))
                    />
                </label>
                <label class="adm-field">
                    <span>"DMCA & Copyright Policy (`/dmca`)"</span>
                    <textarea
                        rows="6"
                        prop:value=move || dmca_md.get()
                        on:input=move |ev| dmca_md.set(event_target_value(&ev))
                    />
                </label>
                <label class="adm-field">
                    <span>"Content Policy (`/content-policy`)"</span>
                    <textarea
                        rows="6"
                        prop:value=move || content_policy_md.get()
                        on:input=move |ev| content_policy_md.set(event_target_value(&ev))
                    />
                </label>
            </section>

            <div class="adm-save-bar">
                <span class="adm-sub">"All Markdown pages are sanitized server-side with `ammonia` before display."</span>
                <button type="submit" class="adm-btn adm-btn--primary" disabled=move || saving.get()>
                    {move || if saving.get() { "Publishing…" } else { "Save Age & Legal Policy" }}
                </button>
            </div>
        </form>
    }
}
