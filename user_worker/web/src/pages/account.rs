//! `/user/account` — Unified account dashboard: Policy v3 content switchers
//! (`ToggleSwitch` + `pref_version` optimistic concurrency), shared `AgeGateModal`
//! 18+ popup confirmation, versioned Terms review/acceptance, linked identities &
//! payment wallets, crypto top-up & subscriptions, device transfer, and sessions.

use leptos::{ev, prelude::*, task::spawn_local};
use lets_embed_ui::{
    AgeGateModal, FloatingHeader, HeaderVariant, NoticeBanner, NoticeContent, NoticeTone,
    ToggleSwitch, browser::use_window_keydown, use_toast_store,
};
use serde_json::json;
use site_access::{
    AgeVerificationPolicy, AssuranceLevel, AuthProviderId, PlaceholderPreset, PolicyAction,
    PolicyRef,
};

use crate::{
    api::{
        self, AcceptTermsConflictResp, AcceptTermsOkResp, AgeConfirmResp, BillingPreferencesResp,
        BootstrapResp, ConfirmMergeResp, LinkStartResp, MeResp, MergePreviewResp, NonceResp,
        PaymentRow, PreferencesConflictResp, PreferencesResp, PrepareCheckoutResp, RatesResp,
        StartWalletMergeResp, TopupResp, TransferCreateResp,
    },
    wallet,
};

fn assurance_label(level: AssuranceLevel) -> (&'static str, &'static str) {
    match level {
        AssuranceLevel::Verified18 => ("Verified 18+", "u-badge u-badge--ok"),
        AssuranceLevel::ProviderSelfReportedDob => {
            ("DOB Checked (Unverified)", "u-badge u-badge--warn")
        }
        AssuranceLevel::SelfAttestation => ("Self-Attested 18+", "u-badge u-badge--ok"),
        AssuranceLevel::None => ("Unverified", "u-badge u-badge--warn"),
    }
}

fn caller_satisfies_age_18(
    age_policy: AgeVerificationPolicy,
    assurance_level: AssuranceLevel,
    strict_age_ok: bool,
) -> bool {
    match age_policy {
        AgeVerificationPolicy::Off => false,
        AgeVerificationPolicy::SelfAttestation => matches!(
            assurance_level,
            AssuranceLevel::SelfAttestation
                | AssuranceLevel::ProviderSelfReportedDob
                | AssuranceLevel::Verified18
        ),
        AgeVerificationPolicy::StrictProviderVerified18 => {
            strict_age_ok && assurance_level == AssuranceLevel::Verified18
        }
    }
}

fn preset_badge_meta(preset: PlaceholderPreset) -> (&'static str, &'static str, &'static str) {
    match preset {
        PlaceholderPreset::R18 => (
            "R-18",
            "u-preset-badge u-preset-badge--r18",
            "u-policy-switcher u-policy-switcher--r18",
        ),
        PlaceholderPreset::Sensitive => (
            "Ecchi / Sensitive",
            "u-preset-badge u-preset-badge--sensitive",
            "u-policy-switcher u-policy-switcher--sensitive",
        ),
        PlaceholderPreset::Blood => (
            "Blood",
            "u-preset-badge u-preset-badge--blood",
            "u-policy-switcher u-policy-switcher--blood",
        ),
        PlaceholderPreset::Custom => (
            "Custom",
            "u-preset-badge u-preset-badge--custom",
            "u-policy-switcher u-policy-switcher--custom",
        ),
    }
}

fn switcher_state_badge(
    action: PolicyAction,
    is_enabled: bool,
    is_effective: bool,
    country_excluded: bool,
    has_missing: bool,
) -> (&'static str, &'static str) {
    if country_excluded {
        return (
            "Not available in your region",
            "u-state-badge u-state-badge--danger",
        );
    }
    if is_enabled && !is_effective && has_missing {
        return (
            "Saved ON \u{00B7} action required",
            "u-state-badge u-state-badge--warn",
        );
    }
    if is_enabled {
        match action {
            PolicyAction::Block => ("Showing automatically", "u-state-badge u-state-badge--on"),
            PolicyAction::Blur => ("Showing clearly", "u-state-badge u-state-badge--on"),
        }
    } else {
        match action {
            PolicyAction::Block => ("Hidden by default", "u-state-badge u-state-badge--off"),
            PolicyAction::Blur => ("Blurred until clicked", "u-state-badge u-state-badge--off"),
        }
    }
}

fn format_accepted_badge(version: u32, accepted_at: Option<u64>) -> String {
    match accepted_at.filter(|&ts| ts > 0) {
        Some(ts) => format!(
            "\u{2713} Accepted Terms v{version} \u{00B7} {}",
            api::format_epoch_date(ts)
        ),
        None => format!("\u{2713} Accepted Terms v{version}"),
    }
}

fn has_media_balance(data: &MeResp) -> bool {
    let min_media_cost = data
        .pricing
        .items
        .iter()
        .filter(|it| matches!(it.kind.as_str(), "image" | "video") && it.price > 0)
        .map(|it| it.price)
        .min()
        .unwrap_or(1);
    data.balance >= min_media_cost
}

fn plan_display_label(plan: Option<&str>, allow_paid_media: bool) -> String {
    match plan.map(str::trim).filter(|s| !s.is_empty()) {
        Some(id) => {
            let mut chars = id.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => "Free".to_string(),
            }
        }
        None if allow_paid_media => "Pay-as-you-go".to_string(),
        None => "Free".to_string(),
    }
}

#[derive(Clone, Copy)]
enum QuotaTone {
    Ok,
    Warn,
    Danger,
    Unlimited,
}

impl QuotaTone {
    fn pill_class(self) -> &'static str {
        match self {
            Self::Ok => "u-quota-pill u-quota-pill--ok",
            Self::Warn => "u-quota-pill u-quota-pill--warn",
            Self::Danger => "u-quota-pill u-quota-pill--danger",
            Self::Unlimited => "u-quota-pill u-quota-pill--unlimited",
        }
    }

    fn fill_class(self) -> &'static str {
        match self {
            Self::Ok => "u-quota-fill u-quota-fill--ok",
            Self::Warn => "u-quota-fill u-quota-fill--warn",
            Self::Danger => "u-quota-fill u-quota-fill--danger",
            Self::Unlimited => "u-quota-fill u-quota-fill--unlimited",
        }
    }
}

struct QuotaMeter {
    label: String,
    status: String,
    detail: String,
    percent_label: Option<String>,
    fill_width_pct: f64,
    aria_now: Option<i64>,
    aria_max: Option<i64>,
    tone: QuotaTone,
}

impl QuotaMeter {
    fn finite(label: impl Into<String>, used_raw: i64, limit: i64, unit_suffix: &str) -> Self {
        let limit = limit.max(1);
        let used = used_raw.clamp(0, limit);
        let remaining = (limit - used).max(0);
        let ratio = (used as f64) / (limit as f64);
        let rounded_pct = (ratio * 100.0).round().clamp(0.0, 100.0) as u32;
        let fill_width_pct = if used == 0 {
            0.0
        } else {
            (ratio * 100.0).clamp(2.0, 100.0)
        };
        let percent_label = if used > 0 && rounded_pct == 0 {
            "<1%".to_string()
        } else {
            format!("{rounded_pct}%")
        };
        let tone = if remaining == 0 {
            QuotaTone::Danger
        } else if rounded_pct >= 75 {
            QuotaTone::Warn
        } else {
            QuotaTone::Ok
        };
        let status = if remaining == 0 {
            "Limit reached".to_string()
        } else {
            format!("{} left", api::format_number(remaining))
        };
        let detail = if unit_suffix.is_empty() {
            format!(
                "{} / {} used",
                api::format_number(used),
                api::format_number(limit)
            )
        } else {
            format!(
                "{} / {} {unit_suffix} used",
                api::format_number(used),
                api::format_number(limit)
            )
        };
        Self {
            label: label.into(),
            status,
            detail,
            percent_label: Some(percent_label),
            fill_width_pct,
            aria_now: Some(used),
            aria_max: Some(limit),
            tone,
        }
    }

    fn unlimited(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: "Unlimited".to_string(),
            detail: detail.into(),
            percent_label: None,
            fill_width_pct: 100.0,
            aria_now: None,
            aria_max: None,
            tone: QuotaTone::Unlimited,
        }
    }
}

fn render_quota_meter(m: QuotaMeter) -> impl IntoView {
    let aria_label = format!("{}: {}, {}", m.label, m.detail, m.status);
    let fill_style = format!("width: {:.1}%", m.fill_width_pct);
    let pill_cls = m.tone.pill_class();
    let fill_cls = m.tone.fill_class();
    view! {
        <div class="u-quota-item">
            <div class="u-quota-row">
                <span class="u-quota-label">{m.label}</span>
                <span class=pill_cls>{m.status}</span>
            </div>
            <div
                class="u-quota-track"
                role="progressbar"
                aria-label=aria_label
                aria-valuemin="0"
                aria-valuemax=m.aria_max.map(|v| v.to_string())
                aria-valuenow=m.aria_now.map(|v| v.to_string())
            >
                <div class=fill_cls style=fill_style />
            </div>
            <div class="u-quota-meta">
                <span>{m.detail}</span>
                {m.percent_label.map(|p| view! { <span class="u-quota-pct">{p}</span> })}
            </div>
        </div>
    }
}

fn quota_exhausted_notice(data: &MeResp, deposit_open: Option<bool>) -> (&'static str, String) {
    let bal = api::format_points(data.balance);
    let deposit_note = if deposit_open == Some(false) {
        " New crypto deposits are currently closed."
    } else {
        ""
    };
    let views_zero = data.views_remaining == Some(0);
    let searches_zero = data.searches_remaining == Some(0);
    let media_credit_spend_blocked = !data.allow_paid_media
        && has_media_balance(data)
        && !(data.plan.is_some() && !views_zero && searches_zero);

    if media_credit_spend_blocked {
        let reset_hint = if data.plan.is_some() {
            api::format_time_until(data.window_reset)
                .map(|t| format!("or wait for your 5-hour window ({t}) / daily UTC reset"))
                .unwrap_or_else(|| "or wait for your quota to reset".to_string())
        } else {
            "or wait for the daily free allowance reset at 00:00 UTC".to_string()
        };
        return (
            "Daily quota reached \u{2014} paid media loading is off",
            format!(
                "You\u{2019}ve reached today\u{2019}s free viewing quota (and any active plan window). You still have {bal} available, but spending credits to load images & videos is currently turned off. Turn on \"Use credits to load images & videos after quota runs out\" below to keep browsing with your points, {reset_hint}."
            ),
        );
    }

    if data.plan.is_some() {
        let reset_hint = api::format_time_until(data.window_reset)
            .map(|t| format!("Wait for your 5-hour window to reset ({t})"))
            .unwrap_or_else(|| "Wait for your 5-hour window to reset".to_string());
        let (title, subject) = match (views_zero, searches_zero) {
            (false, true) => (
                "5-hour search quota reached",
                "Your plan\u{2019}s 5-hour search quota is used up",
            ),
            (true, false) => (
                "5-hour view quota reached",
                "Your plan\u{2019}s 5-hour viewing quota is used up",
            ),
            _ => (
                "Plan quota & points limit reached",
                "Your 5-hour plan quota is used up",
            ),
        };
        return (
            title,
            format!(
                "{subject} and your balance ({bal}) isn\u{2019}t enough to cover pay-as-you-go fallback. {reset_hint}, top up points, or upgrade your plan below.{deposit_note}"
            ),
        );
    }
    (
        "Quota or points balance exhausted",
        format!(
            "You\u{2019}ve reached today\u{2019}s free allowance and your current balance ({bal}) isn\u{2019}t enough to cover this item or search. Top up points or subscribe to a plan below \u{2014} or wait for the daily free allowance reset at 00:00 UTC.{deposit_note}"
        ),
    )
}

#[component]
pub fn AccountPage() -> impl IntoView {
    let toasts = use_toast_store();

    let me = RwSignal::new(None::<MeResp>);
    let boot = RwSignal::new(None::<BootstrapResp>);
    let payments = RwSignal::new(Vec::<PaymentRow>::new());
    let rates = RwSignal::new(None::<RatesResp>);

    let pref_version = RwSignal::new(1u64);
    let busy = RwSignal::new(false);
    let arrived_for_quota = StoredValue::new(matches!(
        api::current_search_param("reason").as_deref(),
        Some("quota" | "limit" | "free_limit")
    ));
    let quota_notice_dismissed = RwSignal::new(false);

    // Terms state (updates dynamically on 409 Conflict!)
    let terms_version = RwSignal::new(0u32);
    let terms_digest = RwSignal::new(String::new());
    let terms_md = RwSignal::new(String::new());
    let self_attest_checked = RwSignal::new(false);
    // Terms modal: read-only when already accepted, Review & Accept when pending.
    let show_terms_modal = RwSignal::new(false);

    // Shared 18+ AgeGateModal state + auto-enable pending switcher after confirmation.
    let age_gate_open = RwSignal::new(false);
    let age_gate_submitting = RwSignal::new(false);
    let age_gate_error = RwSignal::new(None::<String>);
    let pending_switcher_after_age = RwSignal::new(None::<PolicyRef>);
    let pending_switcher_label = RwSignal::new(None::<String>);
    let hash_handled = RwSignal::new(false);

    // Top-up checkout state
    let selected_asset = RwSignal::new("ethereum:eth".to_string());
    let topup_amount = RwSignal::new("0.01".to_string());
    let manual_tx_hash = RwSignal::new(String::new());
    let topup_status = RwSignal::new(None::<String>);

    // Device transfer state
    let transfer = RwSignal::new(None::<TransferCreateResp>);

    // Account fusion / merge modal state
    let merge_preview = RwSignal::new(None::<MergePreviewResp>);
    let merge_preserve = RwSignal::new("current".to_string());
    let merge_favorites = RwSignal::new("both".to_string());
    let merge_submitting = RwSignal::new(false);
    let merge_error = RwSignal::new(None::<String>);

    let reload_me = Callback::new(move |()| {
        spawn_local(async move {
            match api::get_json::<MeResp>("/user/api/me").await {
                Ok(data) => {
                    pref_version.set(data.pref_version.max(1));
                    terms_version.set(data.policy.legal.terms_version);
                    terms_digest.set(data.policy.legal.terms_digest.clone());
                    terms_md.set(data.policy.legal.terms_md.clone());
                    me.set(Some(data));
                }
                Err(e) if e.status == 401 => {
                    api::navigate_hard("/user/login?next=/user/account&reason=session_expired");
                }
                Err(e) => {
                    toasts.error("Could not load account", Some(e.display()));
                }
            }
            if let Ok(rows) = api::get_json::<Vec<PaymentRow>>("/user/api/payments").await {
                payments.set(rows);
            }
        });
    });

    let open_age_gate_modal =
        Callback::new(move |(pending_ref, pending_name): (Option<PolicyRef>, Option<String>)| {
            show_terms_modal.set(false);
            pending_switcher_after_age.set(pending_ref);
            pending_switcher_label.set(pending_name);
            age_gate_error.set(None);
            age_gate_open.set(true);
        });

    let close_age_gate_modal = Callback::new(move |()| {
        if age_gate_submitting.get_untracked() {
            return;
        }
        age_gate_open.set(false);
        age_gate_error.set(None);
        pending_switcher_after_age.set(None);
        pending_switcher_label.set(None);
    });

    let handle_hash_navigation = Callback::new(move |(raw_hash, data): (String, MeResp)| {
        let hash = raw_hash.trim().to_ascii_lowercase();
        let age_verified = caller_satisfies_age_18(
            data.policy.age_policy,
            data.assurance_level,
            data.strict_age_ok,
        );
        let is_self_attest = data.policy.age_policy == AgeVerificationPolicy::SelfAttestation;
        match hash.as_str() {
            "#age-confirm" => {
                api::scroll_to_element("age-confirm");
                if is_self_attest && !age_verified {
                    open_age_gate_modal.run((None, None));
                }
            }
            "#terms" => {
                api::scroll_to_element("terms");
                age_gate_open.set(false);
                show_terms_modal.set(true);
            }
            "#content-safety" => {
                api::scroll_to_element("content-safety");
            }
            "#topup" => {
                api::scroll_to_element("topup");
            }
            "#billing-prefs" => {
                api::scroll_to_element("billing-prefs");
            }
            "#linked-identities" => {
                api::scroll_to_element("linked-identities");
            }
            _ => {}
        }
    });

    // Trigger deep-link hash handling (`#age-confirm`, `#terms`, `#content-safety`, `#topup`, `#linked-identities`)
    // once initial account data renders into the DOM.
    Effect::new(move |_| {
        if let Some(data) = me.get()
            && !hash_handled.get_untracked()
        {
            hash_handled.set(true);
            let h = api::current_hash();
            if !h.is_empty() {
                handle_hash_navigation.run((h, data));
            }
        }
    });

    // Also handle in-page hash navigations while already on `/user/account`.
    api::use_hash_change_listener(move |new_hash| {
        if let Some(data) = me.get_untracked() {
            handle_hash_navigation.run((new_hash, data));
        }
    });

    // Escape closes open Terms or Fuse Accounts modals cleanly (AgeGateModal handles its own Escape).
    use_window_keydown(false, move |ev: ev::KeyboardEvent| {
        if ev.key() == "Escape" {
            if merge_preview.get_untracked().is_some() && !merge_submitting.get_untracked() {
                ev.prevent_default();
                merge_preview.set(None);
                merge_error.set(None);
            } else if show_terms_modal.get_untracked() && !age_gate_open.get_untracked() {
                ev.prevent_default();
                show_terms_modal.set(false);
            }
        }
    });

    // Keep cross-tab BroadcastChannel / storage invalidation active on logout,
    // account change, opt-out, and policy change!
    api::use_safety_invalidation_listener(move |reason| {
        if reason == "logout" {
            api::navigate_hard("/user/login");
        } else {
            reload_me.run(());
        }
    });

    Effect::new(move |_| {
        if let Some(err) = api::current_search_param("error") {
            toasts.error("Account action failed", Some(err));
            api::clear_search_param("error");
        }
        if api::current_search_param("linked").is_some() {
            toasts.success(
                "Sign-in method linked",
                Some("Your new sign-in identity is now linked to this account.".into()),
            );
            api::clear_search_param("linked");
            api::broadcast_safety_invalidation("account_change");
        }
        if let Some(ticket) = api::current_search_param("merge_ticket") {
            api::clear_search_param("merge_ticket");
            busy.set(true);
            spawn_local(async move {
                match api::post_json::<_, MergePreviewResp>(
                    "/user/api/account/merge/preview",
                    &json!({ "merge_ticket": ticket }),
                )
                .await
                {
                    Ok(preview) => {
                        merge_preserve.set("current".to_string());
                        merge_favorites.set("both".to_string());
                        merge_error.set(None);
                        merge_preview.set(Some(preview));
                    }
                    Err(e) => {
                        toasts.error("Could not prepare account merge", Some(e.display()));
                    }
                }
                busy.set(false);
            });
        }
        reload_me.run(());
        spawn_local(async move {
            if let Ok(b) = api::get_json::<BootstrapResp>("/user/api/bootstrap").await {
                boot.set(Some(b));
            }
            if let Ok(r) = api::get_json::<RatesResp>("/user/api/rates").await {
                rates.set(Some(r));
            }
        });
    });

    // Save per-account paid media credit spending toggle (`POST /user/api/billing-preferences`)
    let save_billing_prefs = Callback::new(move |allow_paid_media: bool| {
        busy.set(true);
        spawn_local(async move {
            match api::post_json::<_, BillingPreferencesResp>(
                "/user/api/billing-preferences",
                &json!({ "allow_paid_media": allow_paid_media }),
            )
            .await
            {
                Ok(resp) => {
                    let enabled = resp.allow_paid_media;
                    me.update(|opt| {
                        if let Some(m) = opt {
                            m.allow_paid_media = enabled;
                        }
                    });
                    if enabled {
                        let can_load_media = me.get_untracked().is_some_and(|m| has_media_balance(&m));
                        if arrived_for_quota.get_value() && can_load_media {
                            quota_notice_dismissed.set(true);
                            api::clear_search_param("reason");
                        }
                        let detail = if can_load_media {
                            "Images & videos beyond your daily free quota can now use your points balance."
                        } else {
                            "Top up points below to load images & videos beyond your daily free quota."
                        };
                        toasts.success("Paid media loading enabled", Some(detail.into()));
                    } else {
                        toasts.info(
                            "Paid media loading turned off",
                            Some(
                                "Images & videos will stop loading once your daily free quota and plan window run out, protecting your balance."
                                    .into(),
                            ),
                        );
                    }
                }
                Err(e) => {
                    toasts.error("Could not save billing preference", Some(e.display()));
                }
            }
            busy.set(false);
        });
    });

    // Persist Policy v3 switcher preferences with monotonic `pref_version` optimistic concurrency!
    let save_prefs = Callback::new(move |(switchers, label, turned_on): (Vec<PolicyRef>, String, bool)| {
        busy.set(true);
        let expected_ver = pref_version.get_untracked();
        spawn_local(async move {
            match api::post_json::<_, PreferencesResp>(
                "/user/api/preferences",
                &json!({
                    "enabled_switchers": switchers,
                    "expected_pref_version": expected_ver,
                }),
            )
            .await
            {
                Ok(resp) => {
                    pref_version.set(resp.pref_version.max(1));
                    let next_enabled = resp.enabled_switchers.clone();
                    let next_effective = resp.effective_switchers.clone();
                    let next_statuses = resp.switcher_statuses.clone();
                    let next_ver = resp.pref_version.max(1);
                    me.update(|opt| {
                        if let Some(m) = opt {
                            m.enabled_switchers = next_enabled;
                            m.effective_switchers = next_effective;
                            m.switcher_statuses = next_statuses;
                            m.pref_version = next_ver;
                        }
                    });
                    api::broadcast_safety_invalidation(if turned_on {
                        "prefs_change"
                    } else {
                        "opt_out"
                    });
                    if resp.warnings.is_empty() {
                        let verb = if turned_on { "Enabled" } else { "Disabled" };
                        toasts.success(
                            "Content preferences saved",
                            Some(format!("{verb} {label}.")),
                        );
                    } else {
                        toasts.warning("Preferences saved with notices", Some(resp.warnings.join(" ")));
                    }
                }
                Err(e) if e.status == 409 => {
                    if let Ok(conflict) = serde_json::from_str::<PreferencesConflictResp>(&e.body) {
                        pref_version.set(conflict.pref_version.max(1));
                        me.update(|opt| {
                            if let Some(m) = opt {
                                m.enabled_switchers = conflict.enabled_switchers;
                                m.effective_switchers = conflict.effective_switchers;
                                m.switcher_statuses = conflict.switcher_statuses;
                                m.pref_version = conflict.pref_version.max(1);
                            }
                        });
                        toasts.warning("Preferences updated elsewhere", Some(conflict.error));
                    } else {
                        toasts.warning("Preferences out of date", Some(e.display()));
                        reload_me.run(());
                    }
                }
                Err(e) => {
                    toasts.error("Could not save preferences", Some(e.display()));
                }
            }
            busy.set(false);
        });
    });

    // Accept Terms (and optional 18+ self-attestation) handler — handles 409 Conflict race cleanly!
    let submit_terms = Callback::new(move |attest: bool| {
        busy.set(true);
        let ver = terms_version.get_untracked();
        let dig = terms_digest.get_untracked();
        spawn_local(async move {
            match api::post_json::<_, AcceptTermsOkResp>(
                "/user/api/accept_terms",
                &json!({
                    "terms_version": ver,
                    "terms_digest": dig,
                    "self_attestation": attest,
                }),
            )
            .await
            {
                Ok(resp) => {
                    show_terms_modal.set(false);
                    api::clear_hash_if_matches("#terms");
                    api::broadcast_safety_invalidation("policy_change");
                    toasts.success(
                        "Terms accepted",
                        Some(format!("Accepted Terms v{}.", resp.terms_version_accepted)),
                    );
                    reload_me.run(());
                }
                Err(e) if e.status == 409 => {
                    if let Ok(conflict) = serde_json::from_str::<AcceptTermsConflictResp>(&e.body) {
                        terms_version.set(conflict.terms_version);
                        terms_digest.set(conflict.terms_digest);
                        terms_md.set(conflict.terms_md);
                        show_terms_modal.set(false);
                        toasts.warning("Terms updated", Some(conflict.error));
                        reload_me.run(());
                    } else {
                        toasts.error("Terms version conflict", Some(e.display()));
                    }
                }
                Err(e) => {
                    toasts.error("Could not accept Terms", Some(e.display()));
                }
            }
            busy.set(false);
        });
    });

    let on_accept_terms = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let attest = self_attest_checked.get_untracked();
        submit_terms.run(attest);
    };

    // Confirm 18+ via standalone `POST /user/api/age-confirm` (works regardless of Terms status!)
    // and automatically complete enabling any `pending_switcher_after_age`!
    let on_age_gate_confirm = Callback::new(move |()| {
        if age_gate_submitting.get_untracked() {
            return;
        }
        age_gate_submitting.set(true);
        age_gate_error.set(None);
        busy.set(true);
        spawn_local(async move {
            match api::post_json::<_, AgeConfirmResp>("/user/api/age-confirm", &json!({})).await {
                Ok(age_resp) => {
                    me.update(|opt| {
                        if let Some(m) = opt {
                            m.assurance_level = age_resp.assurance_level;
                            m.strict_age_ok = age_resp.strict_age_ok;
                            m.effective_switchers = age_resp.effective_switchers.clone();
                            m.switcher_statuses = age_resp.switcher_statuses.clone();
                        }
                    });
                    age_gate_open.set(false);
                    age_gate_submitting.set(false);
                    age_gate_error.set(None);
                    api::clear_hash_if_matches("#age-confirm");
                    api::broadcast_safety_invalidation("policy_change");

                    let pending_ref = pending_switcher_after_age.get_untracked();
                    let pending_name = pending_switcher_label.get_untracked();
                    pending_switcher_after_age.set(None);
                    pending_switcher_label.set(None);

                    if let Some(pref) = pending_ref {
                        let label = pending_name.unwrap_or_else(|| pref.id.clone());
                        let mut next_list = me
                            .get_untracked()
                            .map(|m| m.enabled_switchers)
                            .unwrap_or_default();
                        if !next_list.contains(&pref) {
                            next_list.push(pref.clone());
                        }
                        let expected_ver = pref_version.get_untracked();
                        match api::post_json::<_, PreferencesResp>(
                            "/user/api/preferences",
                            &json!({
                                "enabled_switchers": next_list,
                                "expected_pref_version": expected_ver,
                            }),
                        )
                        .await
                        {
                            Ok(resp) => {
                                pref_version.set(resp.pref_version.max(1));
                                let next_enabled = resp.enabled_switchers.clone();
                                let next_effective = resp.effective_switchers.clone();
                                let next_statuses = resp.switcher_statuses.clone();
                                let next_ver = resp.pref_version.max(1);
                                let now_effective = next_effective.contains(&pref);
                                me.update(|opt| {
                                    if let Some(m) = opt {
                                        m.enabled_switchers = next_enabled;
                                        m.effective_switchers = next_effective;
                                        m.switcher_statuses = next_statuses;
                                        m.pref_version = next_ver;
                                    }
                                });
                                api::broadcast_safety_invalidation("prefs_change");
                                if !resp.warnings.is_empty() {
                                    toasts.warning(
                                        "Age 18+ confirmed with notices",
                                        Some(resp.warnings.join(" ")),
                                    );
                                } else if now_effective {
                                    toasts.success(
                                        "Age 18+ confirmed & switcher enabled",
                                        Some(format!("Confirmed 18+ and enabled {label}.")),
                                    );
                                } else {
                                    toasts.success(
                                        "Age 18+ confirmed & switcher saved",
                                        Some(format!(
                                            "Confirmed 18+ and turned on {label}. Complete any remaining requirements to activate it."
                                        )),
                                    );
                                }
                            }
                            Err(e) if e.status == 409 => {
                                if let Ok(conflict) =
                                    serde_json::from_str::<PreferencesConflictResp>(&e.body)
                                {
                                    pref_version.set(conflict.pref_version.max(1));
                                    me.update(|opt| {
                                        if let Some(m) = opt {
                                            m.enabled_switchers = conflict.enabled_switchers;
                                            m.effective_switchers = conflict.effective_switchers;
                                            m.switcher_statuses = conflict.switcher_statuses;
                                            m.pref_version = conflict.pref_version.max(1);
                                        }
                                    });
                                    toasts.warning(
                                        "Age 18+ confirmed; preferences refreshed",
                                        Some(conflict.error),
                                    );
                                } else {
                                    toasts.warning(
                                        "Age 18+ confirmed; preferences out of date",
                                        Some(e.display()),
                                    );
                                    reload_me.run(());
                                }
                            }
                            Err(e) => {
                                toasts.warning(
                                    "Age 18+ confirmed",
                                    Some(format!(
                                        "18+ confirmation saved, but enabling {label} failed: {}",
                                        e.display()
                                    )),
                                );
                                reload_me.run(());
                            }
                        }
                        busy.set(false);
                    } else {
                        toasts.success(
                            "Age 18+ confirmed",
                            Some("Your 18+ confirmation has been saved to your account.".into()),
                        );
                        busy.set(false);
                        reload_me.run(());
                    }
                }
                Err(e) => {
                    age_gate_error.set(Some(e.display()));
                    age_gate_submitting.set(false);
                    busy.set(false);
                }
            }
        });
    });

    // Link OAuth/OIDC identity (automatically transitions to Fuse Accounts modal if already registered)
    let link_oauth_provider = Callback::new(move |provider_id: String| {
        busy.set(true);
        spawn_local(async move {
            match api::post_json::<_, LinkStartResp>(
                "/user/api/identities/link/start",
                &json!({ "provider_id": provider_id }),
            )
            .await
            {
                Ok(resp) => api::navigate_hard(&resp.authorize_url),
                Err(e) => {
                    toasts.error("Could not start identity link", Some(e.display()));
                }
            }
            busy.set(false);
        });
    });

    // Link Ethereum (SIWE) wallet as login method — or open Fuse Accounts modal if registered to another account!
    let on_link_or_merge_eth = Callback::new(move |()| {
        let Some(b) = boot.get_untracked() else {
            return;
        };
        let Some(m) = me.get_untracked() else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            let nonce =
                match api::get_json::<NonceResp>("/user/api/nonce?purpose=merge_account").await {
                    Ok(n) => n.nonce,
                    Err(e) => {
                        toasts.error("Could not verify Ethereum wallet", Some(e.display()));
                        busy.set(false);
                        return;
                    }
                };
            let statement = format!(
                "Link or merge Ethereum wallet with account {}.",
                m.user_id
            );
            match wallet::connect_and_sign_siwe(
                "",
                &b.siwe_domain,
                b.chain_id,
                &nonce,
                &statement,
                None,
            )
            .await
            {
                Ok(sig) => {
                    match api::post_json::<_, StartWalletMergeResp>(
                        "/user/api/account/merge/start/wallet",
                        &json!({
                            "provider_id": "siwe",
                            "message": sig.message,
                            "signature": sig.signature,
                        }),
                    )
                    .await
                    {
                        Ok(StartWalletMergeResp::Linked { subject, .. }) => {
                            api::broadcast_safety_invalidation("account_change");
                            toasts.success(
                                "Ethereum wallet linked",
                                Some(format!("You can now sign in with {subject}.")),
                            );
                            reload_me.run(());
                        }
                        Ok(StartWalletMergeResp::MergeRequired { preview, .. }) => {
                            merge_preserve.set("current".to_string());
                            merge_favorites.set("both".to_string());
                            merge_error.set(None);
                            merge_preview.set(Some(*preview));
                        }
                        Err(e) => {
                            toasts.error("Wallet link or merge failed", Some(e.display()));
                        }
                    }
                }
                Err(msg) => {
                    toasts.error("Wallet signature failed", Some(msg));
                }
            }
            busy.set(false);
        });
    });

    // Link Solana (SIWS) wallet as login method — or open Fuse Accounts modal if registered to another account!
    let on_link_or_merge_sol = Callback::new(move |()| {
        let Some(m) = me.get_untracked() else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            let nonce =
                match api::get_json::<NonceResp>("/user/api/nonce?purpose=merge_account").await {
                    Ok(n) => n.nonce,
                    Err(e) => {
                        toasts.error("Could not verify Solana wallet", Some(e.display()));
                        busy.set(false);
                        return;
                    }
                };
            let challenge = format!(
                "Link or merge Solana wallet with {}\nNonce: {}",
                m.user_id, nonce
            );
            match wallet::connect_and_sign_sol_message("", &challenge).await {
                Ok(sig) => {
                    match api::post_json::<_, StartWalletMergeResp>(
                        "/user/api/account/merge/start/wallet",
                        &json!({
                            "provider_id": "siws",
                            "solana_address": sig.address,
                            "signature": sig.signature,
                            "nonce": nonce,
                            "signed_message": sig.signed_message,
                        }),
                    )
                    .await
                    {
                        Ok(StartWalletMergeResp::Linked { subject, .. }) => {
                            api::broadcast_safety_invalidation("account_change");
                            toasts.success(
                                "Solana wallet linked",
                                Some(format!("You can now sign in with {subject}.")),
                            );
                            reload_me.run(());
                        }
                        Ok(StartWalletMergeResp::MergeRequired { preview, .. }) => {
                            merge_preserve.set("current".to_string());
                            merge_favorites.set("both".to_string());
                            merge_error.set(None);
                            merge_preview.set(Some(*preview));
                        }
                        Err(e) => {
                            toasts.error("Wallet link or merge failed", Some(e.display()));
                        }
                    }
                }
                Err(msg) => {
                    toasts.error("Wallet signature failed", Some(msg));
                }
            }
            busy.set(false);
        });
    });

    // Confirm and execute account fusion
    let on_confirm_merge = Callback::new(move |()| {
        if merge_submitting.get_untracked() {
            return;
        }
        let Some(prev) = merge_preview.get_untracked() else {
            return;
        };
        let preserve = merge_preserve.get_untracked();
        let favorites = merge_favorites.get_untracked();
        merge_submitting.set(true);
        merge_error.set(None);
        busy.set(true);
        spawn_local(async move {
            match api::post_json::<_, ConfirmMergeResp>(
                "/user/api/account/merge/confirm",
                &json!({
                    "merge_ticket": prev.merge_ticket,
                    "preserve": preserve,
                    "favorites": favorites,
                }),
            )
            .await
            {
                Ok(resp) => {
                    merge_preview.set(None);
                    merge_submitting.set(false);
                    merge_error.set(None);
                    busy.set(false);
                    api::broadcast_safety_invalidation("account_change");
                    let detail = if resp.total_credits_added > 0 {
                        format!(
                            "Combined {} sign-in methods, {} favorites, and added {} in paid credits (new balance: {}).",
                            resp.identities_count,
                            api::format_number(resp.favorites_count),
                            api::format_points(resp.total_credits_added),
                            api::format_points(resp.new_balance),
                        )
                    } else {
                        format!(
                            "Combined {} sign-in methods and {} favorites into one account.",
                            resp.identities_count,
                            api::format_number(resp.favorites_count),
                        )
                    };
                    toasts.success("Accounts fused", Some(detail));
                    reload_me.run(());
                }
                Err(e) => {
                    merge_error.set(Some(e.display()));
                    merge_submitting.set(false);
                    busy.set(false);
                }
            }
        });
    });

    // Link Ethereum payment wallet (allowed anytime, zero login/age privilege)
    let on_link_eth_wallet = move |_| {
        let Some(b) = boot.get_untracked() else {
            return;
        };
        let Some(m) = me.get_untracked() else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            let nonce = match api::get_json::<NonceResp>("/user/api/nonce?purpose=link_payment").await {
                Ok(n) => n.nonce,
                Err(e) => {
                    toasts.error("Could not link Ethereum wallet", Some(e.display()));
                    busy.set(false);
                    return;
                }
            };
            let statement = format!(
                "Link Ethereum wallet for payment to account {}.",
                m.user_id
            );
            match wallet::connect_and_sign_siwe(
                "",
                &b.siwe_domain,
                b.chain_id,
                &nonce,
                &statement,
                None,
            )
            .await
            {
                Ok(sig) => {
                    match api::post_json_empty(
                        "/user/api/identities/link/wallet",
                        &json!({
                            "provider_id": "siwe",
                            "purpose": "payment",
                            "message": sig.message,
                            "signature": sig.signature,
                        }),
                    )
                    .await
                    {
                        Ok(()) => {
                            api::broadcast_safety_invalidation("account_change");
                            toasts.success(
                                "Ethereum payment wallet linked",
                                Some("You can now use this wallet for crypto top-ups.".into()),
                            );
                            reload_me.run(());
                        }
                        Err(e) => {
                            toasts.error("Wallet link failed", Some(e.display()));
                        }
                    }
                }
                Err(msg) => {
                    toasts.error("Wallet signature failed", Some(msg));
                }
            }
            busy.set(false);
        });
    };

    // Link Solana payment wallet (allowed anytime, zero login/age privilege)
    let on_link_sol_wallet = move |_| {
        let Some(m) = me.get_untracked() else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            let nonce = match api::get_json::<NonceResp>("/user/api/nonce?purpose=link_payment").await {
                Ok(n) => n.nonce,
                Err(e) => {
                    toasts.error("Could not link Solana wallet", Some(e.display()));
                    busy.set(false);
                    return;
                }
            };
            let challenge = format!(
                "Link Solana wallet for payment to {}\nNonce: {}",
                m.user_id, nonce
            );
            match wallet::connect_and_sign_sol_message("", &challenge).await {
                Ok(sig) => {
                    match api::post_json_empty(
                        "/user/api/identities/link/wallet",
                        &json!({
                            "provider_id": "siws",
                            "purpose": "payment",
                            "solana_address": sig.address,
                            "signature": sig.signature,
                            "nonce": nonce,
                            "signed_message": sig.signed_message,
                        }),
                    )
                    .await
                    {
                        Ok(()) => {
                            api::broadcast_safety_invalidation("account_change");
                            toasts.success(
                                "Solana payment wallet linked",
                                Some("You can now use this wallet for SOL/SPL top-ups.".into()),
                            );
                            reload_me.run(());
                        }
                        Err(e) => {
                            toasts.error("Wallet link failed", Some(e.display()));
                        }
                    }
                }
                Err(msg) => {
                    toasts.error("Wallet signature failed", Some(msg));
                }
            }
            busy.set(false);
        });
    };

    // Unlink identity
    let unlink_identity =
        Callback::new(move |(provider_id, issuer, subject): (String, String, String)| {
            busy.set(true);
            spawn_local(async move {
                match api::delete_json_empty(
                    "/user/api/identities",
                    &json!({ "provider_id": provider_id, "issuer": issuer, "subject": subject }),
                )
                .await
                {
                    Ok(()) => {
                        api::broadcast_safety_invalidation("account_change");
                        toasts.success("Identity unlinked", None);
                        reload_me.run(());
                    }
                    Err(e) => {
                        toasts.error("Could not unlink identity", Some(e.display()));
                    }
                }
                busy.set(false);
            });
        });

    // Wallet checkout top-up
    let on_wallet_topup = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let Some(m) = me.get_untracked() else {
            return;
        };
        let asset = selected_asset.get_untracked();
        let (chain, token) = asset.split_once(':').unwrap_or(("ethereum", "eth"));
        let chain = chain.to_string();
        let token = token.to_string();
        let amount = topup_amount.get_untracked().trim().to_string();
        busy.set(true);
        topup_status.set(Some("Preparing transfer...".into()));

        spawn_local(async move {
            let prep = match api::post_json::<_, PrepareCheckoutResp>(
                "/user/api/topup/prepare",
                &json!({
                    "account": m.user_id,
                    "chain": chain,
                    "token": token,
                    "amount": amount,
                }),
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    topup_status.set(None);
                    toasts.error("Checkout preparation failed", Some(e.display()));
                    busy.set(false);
                    return;
                }
            };

            topup_status.set(Some("Confirm transfer in your wallet...".into()));
            let tx_hash_res = if chain == "ethereum" {
                let tx_str = prep.transaction.to_string();
                wallet::send_eth_tx("", &tx_str).await
            } else {
                let b64 = prep.transaction.as_str().unwrap_or("");
                wallet::send_sol_tx("", b64).await
            };
            let tx_hash = match tx_hash_res {
                Ok(h) => h,
                Err(msg) => {
                    topup_status.set(None);
                    toasts.error("Transfer canceled or failed", Some(msg));
                    busy.set(false);
                    return;
                }
            };

            manual_tx_hash.set(tx_hash.clone());
            topup_status.set(Some(format!(
                "Broadcasted ({tx_hash}). Waiting for confirmation..."
            )));

            for _ in 0..30 {
                match api::post_json::<_, TopupResp>(
                    "/user/api/topup",
                    &json!({
                        "account": m.user_id,
                        "chain": chain,
                        "token": token,
                        "tx_hash": tx_hash,
                    }),
                )
                .await
                {
                    Ok(done) => {
                        topup_status.set(None);
                        toasts.success(
                            "Top-up credited",
                            Some(format!(
                                "Credited {}! New balance: {}.",
                                api::format_points(done.credited_points),
                                api::format_points(done.balance)
                            )),
                        );
                        reload_me.run(());
                        busy.set(false);
                        return;
                    }
                    Err(e) if e.status == 425 => {
                        let delay = js_sys::Promise::new(&mut |resolve, _| {
                            if let Some(w) = web_sys::window() {
                                let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                                    &resolve, 4000,
                                );
                            }
                        });
                        let _ = wasm_bindgen_futures::JsFuture::from(delay).await;
                    }
                    Err(e) => {
                        topup_status.set(None);
                        toasts.error("Top-up verification failed", Some(e.display()));
                        busy.set(false);
                        return;
                    }
                }
            }
            topup_status.set(Some(
                "Still awaiting finality — submit the transaction hash below once confirmed."
                    .into(),
            ));
            toasts.info(
                "Transaction still confirming",
                Some("Submit the transaction hash once it finalizes.".into()),
            );
            busy.set(false);
        });
    };

    // Manual tx hash verification
    let on_manual_topup = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let Some(m) = me.get_untracked() else {
            return;
        };
        let asset = selected_asset.get_untracked();
        let (chain, token) = asset.split_once(':').unwrap_or(("ethereum", "eth"));
        let chain = chain.to_string();
        let token = token.to_string();
        let hash = manual_tx_hash.get_untracked().trim().to_string();
        if hash.is_empty() {
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match api::post_json::<_, TopupResp>(
                "/user/api/topup",
                &json!({
                    "account": m.user_id,
                    "chain": chain,
                    "token": token,
                    "tx_hash": hash,
                }),
            )
            .await
            {
                Ok(done) => {
                    toasts.success(
                        "Top-up credited",
                        Some(format!(
                            "Credited {}! New balance: {}.",
                            api::format_points(done.credited_points),
                            api::format_points(done.balance)
                        )),
                    );
                    manual_tx_hash.set(String::new());
                    reload_me.run(());
                }
                Err(e) => {
                    toasts.error("Verification failed", Some(e.display()));
                }
            }
            busy.set(false);
        });
    };

    let on_subscribe = Callback::new(move |(plan_id, price): (String, i64)| {
        busy.set(true);
        spawn_local(async move {
            match api::post_json_empty(
                "/user/api/subscribe",
                &json!({ "plan": plan_id, "expected_price": price }),
            )
            .await
            {
                Ok(()) => {
                    toasts.success("Subscription active", Some(format!("Subscribed to {plan_id}.")));
                    reload_me.run(());
                }
                Err(e) => {
                    toasts.error("Subscription failed", Some(e.display()));
                }
            }
            busy.set(false);
        });
    });

    let on_unsubscribe = move |_| {
        busy.set(true);
        spawn_local(async move {
            match api::post_empty("/user/api/unsubscribe").await {
                Ok(()) => {
                    toasts.success(
                        "Subscription cancelled",
                        Some("Prorated remainder refunded to your points balance.".into()),
                    );
                    reload_me.run(());
                }
                Err(e) => {
                    toasts.error("Could not cancel plan", Some(e.display()));
                }
            }
            busy.set(false);
        });
    };

    let on_create_transfer = move |_| {
        busy.set(true);
        spawn_local(async move {
            match api::post_json::<_, TransferCreateResp>("/user/api/transfer/create", &json!({}))
                .await
            {
                Ok(t) => {
                    transfer.set(Some(t));
                    toasts.info(
                        "Transfer code created",
                        Some("Valid for 3 minutes (single-use).".into()),
                    );
                }
                Err(e) => {
                    toasts.error("Could not create transfer code", Some(e.display()));
                }
            }
            busy.set(false);
        });
    };

    let on_revoke_transfer = move |_| {
        spawn_local(async move {
            match api::post_empty("/user/api/transfer/revoke").await {
                Ok(()) => {
                    transfer.set(None);
                    toasts.info("Transfer code revoked", None);
                }
                Err(e) => {
                    toasts.error("Could not revoke transfer code", Some(e.display()));
                }
            }
        });
    };

    let on_logout = move |_| {
        busy.set(true);
        spawn_local(async move {
            match api::post_empty("/user/api/logout").await {
                Ok(()) => {
                    api::broadcast_safety_invalidation("logout");
                    toasts.info("Signed out", None);
                    api::navigate_hard("/user/login");
                }
                Err(e) => {
                    toasts.error("Sign out failed", Some(e.display()));
                    busy.set(false);
                }
            }
        });
    };

    let on_revoke_all = move |_| {
        busy.set(true);
        spawn_local(async move {
            match api::post_empty("/user/api/sessions/revoke_all").await {
                Ok(()) => {
                    api::broadcast_safety_invalidation("logout");
                    toasts.info("Signed out of all devices", None);
                    api::navigate_hard("/user/login");
                }
                Err(e) => {
                    toasts.error("Could not revoke sessions", Some(e.display()));
                    busy.set(false);
                }
            }
        });
    };

    view! {
        <div class="u-shell">
            <FloatingHeader
                variant=HeaderVariant::Nav
                left=move || view! {
                    <nav class="u-nav-links">
                        <a class="u-nav-link" href="/">"Gallery"</a>
                        <a class="u-nav-link is-active" href="/user/account">"Account"</a>
                        <a class="u-nav-link" href="/user/favorites">"Favorites"</a>
                    </nav>
                }.into_any()
                right=move || view! {
                    <div class="u-row">
                        <button
                            type="button"
                            class="u-btn u-btn--secondary u-btn--small"
                            disabled=move || busy.get()
                            on:click=on_logout
                        >
                            "Sign out"
                        </button>
                    </div>
                }.into_any()
            />

            <div class="u-stack">
                {move || match me.get() {
                    None => view! {
                        <section class="u-card"><p class="u-sub">"Loading account..."</p></section>
                    }.into_any(),
                    Some(data) => {
                        let (assur_text, assur_cls) = assurance_label(data.assurance_level);
                        let accepted_current_terms =
                            data.accepted_current_terms || data.terms_up_to_date;
                        let accepted_badge_text = format_accepted_badge(
                            data.policy.legal.terms_version,
                            data.terms_accepted_at,
                        );
                        let switchers: Vec<_> = data
                            .policy
                            .policies
                            .iter()
                            .filter(|p| p.enabled && p.bypass.include_switcher)
                            .cloned()
                            .collect();
                        let current_enabled = data.enabled_switchers.clone();
                        let current_effective = data.effective_switchers.clone();
                        let current_statuses = data.switcher_statuses.clone();
                        let is_self_attest_mode =
                            data.policy.age_policy == AgeVerificationPolicy::SelfAttestation;
                        let is_strict_18 =
                            data.policy.age_policy == AgeVerificationPolicy::StrictProviderVerified18;
                        let age_verified = caller_satisfies_age_18(
                            data.policy.age_policy,
                            data.assurance_level,
                            data.strict_age_ok,
                        );
                        let current_terms_version = data.policy.legal.terms_version;
                        let can_link_siwe = data
                            .available_providers
                            .iter()
                            .any(|p| p.enabled && p.id == AuthProviderId::Siwe);
                        let can_link_siws = data
                            .available_providers
                            .iter()
                            .any(|p| p.enabled && p.id == AuthProviderId::Siws);
                        let linkable_oauth: Vec<_> = data
                            .available_providers
                            .iter()
                            .filter(|p| {
                                p.enabled
                                    && matches!(
                                        p.id,
                                        AuthProviderId::OidcAgeAssurance
                                            | AuthProviderId::Google
                                            | AuthProviderId::GitHub
                                            | AuthProviderId::X
                                            | AuthProviderId::Discord
                                    )
                            })
                            .cloned()
                            .collect();
                        let has_any_linkable_login =
                            can_link_siwe || can_link_siws || !linkable_oauth.is_empty();
                        let identities = data.identities.clone();
                        let plans = data.pricing.plans.clone();
                        let items = data.pricing.items.clone();
                        let can_link = data.can_link_identity_now;
                        let deposit_open = boot.get().map(|b| b.deposit_open);
                        let quota_notice = arrived_for_quota
                            .get_value()
                            .then(|| quota_exhausted_notice(&data, deposit_open));
                        let quota_notice_topup = quota_notice.clone();
                        let dismiss_quota_notice = Callback::new(move |()| {
                            quota_notice_dismissed.set(true);
                            api::clear_search_param("reason");
                        });
                        let plan_label = plan_display_label(
                            data.plan.as_deref(),
                            data.allow_paid_media,
                        );
                        let active_plan_cfg = data
                            .plan
                            .as_deref()
                            .and_then(|pid| data.pricing.plans.iter().find(|p| p.id == pid))
                            .cloned();
                        let window_reset_text = api::format_time_until(data.window_reset);
                        let daily_reset_text = api::format_time_until(data.daily_free_reset);

                        let mut plan_meters: Vec<QuotaMeter> = Vec::new();
                        if data.plan.is_some() {
                            if let Some(ref pcfg) = active_plan_cfg {
                                match pcfg.views_per_window {
                                    Some(limit) if limit > 0 => {
                                        let rem = data.views_remaining.unwrap_or(limit).clamp(0, limit);
                                        plan_meters.push(QuotaMeter::finite(
                                            "Media views",
                                            limit - rem,
                                            limit,
                                            "view units",
                                        ));
                                    }
                                    None => {
                                        plan_meters.push(QuotaMeter::unlimited(
                                            "Media views",
                                            format!("Included with {plan_label} plan"),
                                        ));
                                    }
                                    _ => {}
                                }
                                if pcfg.searches_per_window > 0 {
                                    let limit = pcfg.searches_per_window;
                                    let rem = data
                                        .searches_remaining
                                        .unwrap_or(limit)
                                        .clamp(0, limit);
                                    plan_meters.push(QuotaMeter::finite(
                                        "AI searches",
                                        limit - rem,
                                        limit,
                                        "searches",
                                    ));
                                }
                            } else {
                                if let Some(rem) = data.views_remaining {
                                    plan_meters.push(QuotaMeter::unlimited(
                                        "Media views",
                                        format!("{} remaining this window", api::format_number(rem)),
                                    ));
                                }
                                if let Some(rem) = data.searches_remaining {
                                    plan_meters.push(QuotaMeter::unlimited(
                                        "AI searches",
                                        format!("{} remaining this window", api::format_number(rem)),
                                    ));
                                }
                            }
                        }

                        let daily_meters: Vec<QuotaMeter> = data
                            .pricing
                            .items
                            .iter()
                            .filter(|it| it.daily_free != 0 || it.price == 0)
                            .map(|it| {
                                if it.daily_free < 0 || it.price == 0 {
                                    QuotaMeter::unlimited(it.label.clone(), "No daily cap")
                                } else {
                                    let used = data
                                        .daily_free_used
                                        .get(&it.kind)
                                        .copied()
                                        .unwrap_or(0)
                                        .max(0);
                                    QuotaMeter::finite(it.label.clone(), used, it.daily_free, "")
                                }
                            })
                            .collect();

                        let free_media_exhausted = data.pricing.items.iter().any(|it| {
                            matches!(it.kind.as_str(), "image" | "video")
                                && it.daily_free > 0
                                && it.price > 0
                                && data
                                    .daily_free_used
                                    .get(&it.kind)
                                    .copied()
                                    .unwrap_or(0)
                                    >= it.daily_free
                        });
                        let has_balance_for_media = has_media_balance(&data);
                        let has_quota_panel = !plan_meters.is_empty() || !daily_meters.is_empty();
                        let plan_window_reset_label = match window_reset_text {
                            Some(t) => format!("Resets {t}"),
                            None => "Fresh 5-hour window".to_string(),
                        };
                        let daily_reset_label = match daily_reset_text {
                            Some(t) => format!("Resets {t} \u{00B7} 00:00 UTC"),
                            None => "Resets daily at 00:00 UTC".to_string(),
                        };

                        view! {
                            <div class="u-stack">
                                {data.banned.then(|| view! {
                                    <NoticeBanner
                                        content=NoticeContent::Text("This account has been suspended by an administrator.".into())
                                        tone=NoticeTone::Danger
                                        title="Account Suspended"
                                        dismissible=false
                                    />
                                })}

                                {move || {
                                    if quota_notice_dismissed.get() {
                                        return None;
                                    }
                                    let (title, body) = quota_notice.as_ref()?;
                                    Some(view! {
                                        <NoticeBanner
                                            content=NoticeContent::Text(body.clone())
                                            tone=NoticeTone::Warning
                                            title=title.to_string()
                                            dismissible=true
                                            on_dismiss=dismiss_quota_notice
                                        />
                                    })
                                }}

                                // 1. Overview Card
                                <section class="u-card">
                                    <div class="u-between">
                                        <div>
                                            <h1>"Your account"</h1>
                                            <div class="u-mono u-sub">{data.address.clone()}</div>
                                        </div>
                                        <div class="u-row">
                                            <span class=assur_cls>{assur_text}</span>
                                            {data.strict_age_ok.then(|| view! {
                                                <span class="u-badge u-badge--ok">"Strict 18+ Eligible"</span>
                                            })}
                                            {accepted_current_terms.then(|| view! {
                                                <span class="u-badge u-badge--ok">
                                                    {accepted_badge_text.clone()}
                                                </span>
                                            })}
                                            <a
                                                href="#billing-prefs"
                                                class=if data.allow_paid_media {
                                                    "u-badge u-badge--ok"
                                                } else {
                                                    "u-badge"
                                                }
                                            >
                                                {if data.allow_paid_media {
                                                    "Paid media: On"
                                                } else {
                                                    "Paid media: Off"
                                                }}
                                            </a>
                                        </div>
                                    </div>
                                    <div class="u-stats">
                                        <div class="u-stat">
                                            <div class="u-stat-label">"Balance"</div>
                                            <div class="u-stat-val">{api::format_points(data.balance)}</div>
                                        </div>
                                        <div class="u-stat">
                                            <div class="u-stat-label">"Plan"</div>
                                            <div class="u-stat-val">{plan_label.clone()}</div>
                                        </div>
                                        {(data.plan.is_some() && data.period_end > 0).then(|| view! {
                                            <div class="u-stat">
                                                <div class="u-stat-label">"Plan ends"</div>
                                                <div class="u-stat-val">{api::format_epoch_date(data.period_end)}</div>
                                            </div>
                                        })}
                                        <div class="u-stat">
                                            <div class="u-stat-label">"Total views"</div>
                                            <div class="u-stat-val">{api::format_number(data.total_views)}</div>
                                        </div>
                                    </div>

                                    {has_quota_panel.then(|| view! {
                                        <div class="u-quota-panel">
                                            {(!plan_meters.is_empty()).then(|| view! {
                                                <div class="u-quota-section">
                                                    <div class="u-quota-head">
                                                        <div class="u-quota-title-row">
                                                            <h2 class="u-quota-heading">"5-Hour Plan Quota"</h2>
                                                            <span class="u-badge">{format!("{plan_label} plan")}</span>
                                                        </div>
                                                        <span class="u-quota-reset">{plan_window_reset_label}</span>
                                                    </div>
                                                    <div class="u-quota-grid">
                                                        {plan_meters.into_iter().map(render_quota_meter).collect_view()}
                                                    </div>
                                                </div>
                                            })}

                                            {(!daily_meters.is_empty()).then(|| view! {
                                                <div class="u-quota-section">
                                                    <div class="u-quota-head">
                                                        <div class="u-quota-title-row">
                                                            <h2 class="u-quota-heading">"Daily Free Quota"</h2>
                                                        </div>
                                                        <span class="u-quota-reset">{daily_reset_label}</span>
                                                    </div>
                                                    <div class="u-quota-grid">
                                                        {daily_meters.into_iter().map(render_quota_meter).collect_view()}
                                                    </div>
                                                </div>
                                            })}

                                            {(data.plan.is_none() && free_media_exhausted).then(|| {
                                                if !data.allow_paid_media && has_balance_for_media {
                                                    view! {
                                                        <div class="u-quota-hint u-quota-hint--warn">
                                                            <span>"Daily free media quota reached. Credit spending is off \u{2014} "</span>
                                                            <a href="#billing-prefs">"enable pay-as-you-go below"</a>
                                                            <span>" to keep browsing with your points, or wait for 00:00 UTC."</span>
                                                        </div>
                                                    }.into_any()
                                                } else if !data.allow_paid_media {
                                                    view! {
                                                        <div class="u-quota-hint u-quota-hint--warn">
                                                            <span>"Daily free media quota reached. "</span>
                                                            <a href="#topup">"Top up points or choose a plan below"</a>
                                                            <span>", or wait for the daily reset at 00:00 UTC."</span>
                                                        </div>
                                                    }.into_any()
                                                } else {
                                                    view! {
                                                        <div class="u-quota-hint">
                                                            <span>"Daily free media quota reached \u{2014} additional images & videos now draw from your points balance ("</span>
                                                            <a href="#billing-prefs">"Pay-as-you-go is on"</a>
                                                            <span>")."</span>
                                                        </div>
                                                    }.into_any()
                                                }
                                            })}
                                        </div>
                                    })}
                                </section>

                                // 2. Terms & Age Verification Card
                                <section id="terms" class="u-card">
                                    <div class="u-between">
                                        <div>
                                            <h2>"Terms of Service & Age Assurance"</h2>
                                            <p class="u-sub">
                                                {if accepted_current_terms {
                                                    format!("You have accepted the current Terms (v{}).", current_terms_version)
                                                } else {
                                                    format!("Please review and accept Terms v{} to unlock Terms-gated content switchers.", terms_version.get())
                                                }}
                                            </p>
                                        </div>
                                        {accepted_current_terms.then(|| view! {
                                            <div class="u-row">
                                                <span class="u-badge u-badge--ok">
                                                    {accepted_badge_text.clone()}
                                                </span>
                                                <button
                                                    type="button"
                                                    class="u-btn u-btn--secondary u-btn--small"
                                                    on:click=move |_| {
                                                        age_gate_open.set(false);
                                                        show_terms_modal.set(true);
                                                    }
                                                >
                                                    "Review Terms"
                                                </button>
                                            </div>
                                        })}
                                    </div>

                                    // Always-visible 18+ confirmation callout whenever SelfAttestation mode is active
                                    // and caller has not confirmed 18+ yet — regardless of Terms status!
                                    {(is_self_attest_mode && !age_verified).then(|| view! {
                                        <div id="age-confirm" class="u-age-confirm-box">
                                            <div class="u-age-confirm-copy">
                                                <strong>"\u{26A0} Age 18+ confirmation required"</strong>
                                                <p>
                                                    "Confirm that you are 18 or older to unlock 18+ content switchers. You can confirm now regardless of whether you have accepted Terms."
                                                </p>
                                            </div>
                                            <button
                                                type="button"
                                                class="u-btn u-btn--age u-btn--small"
                                                disabled=move || busy.get()
                                                on:click=move |_| open_age_gate_modal.run((None, None))
                                            >
                                                "Confirm 18+ now"
                                            </button>
                                        </div>
                                    })}

                                    {age_verified.then(|| view! {
                                        <div id="age-confirm" class="u-row" style="margin-bottom:12px;">
                                            <span class="u-req-item u-req-item--ok">"\u{2713} Age 18+ confirmed"</span>
                                        </div>
                                    })}

                                    {(is_strict_18 && !age_verified).then(|| view! {
                                        <p id="age-confirm" class="u-sub">
                                            "Strict 18+ mode is enabled: self-attestation is disabled. Unlocking 18+ switchers requires signing in with a verified 18+ OIDC provider."
                                        </p>
                                    })}

                                    // When Terms are NOT yet accepted (or version/digest changed):
                                    // render the inline Accept Terms form.
                                    {(!accepted_current_terms).then(|| view! {
                                        <form on:submit=on_accept_terms style="margin-top:12px;">
                                            <div class="u-terms-box">{move || terms_md.get()}</div>
                                            {(is_self_attest_mode && !age_verified).then(|| view! {
                                                <label class="u-check-label">
                                                    <input
                                                        type="checkbox"
                                                        prop:checked=move || self_attest_checked.get()
                                                        on:change=move |ev| self_attest_checked.set(event_target_checked(&ev))
                                                    />
                                                    <span>"Also confirm that I am 18 years of age or older and legally permitted to view adult content in my jurisdiction."</span>
                                                </label>
                                            })}
                                            <button type="submit" class="u-btn" disabled=move || busy.get()>
                                                {move || format!("Accept Terms v{}", terms_version.get())}
                                            </button>
                                        </form>
                                    })}
                                </section>

                                // 3. Policy v3 Content Safety Switchers (Crystal-clear UX + ToggleSwitch + pref_version)
                                <section id="content-safety" class="u-card">
                                    <div>
                                        <h2>"Content Safety Switchers"</h2>
                                        <p class="u-sub">
                                            "Control which filtered categories stay hidden or blurred versus showing automatically. Changes sync across your open tabs immediately."
                                        </p>
                                    </div>
                                    {if switchers.is_empty() {
                                        view! { <p class="u-sub">"No optional content switchers are currently enabled by this site."</p> }.into_any()
                                    } else {
                                        view! {
                                            <div class="u-list">
                                                {switchers.into_iter().map(|rule| {
                                                    let pref = rule.policy_ref();
                                                    let pref_for_toggle = pref.clone();
                                                    let rule_name = rule.name.clone();
                                                    let rule_name_for_toggle = rule_name.clone();
                                                    let is_enabled = current_enabled.contains(&pref);
                                                    let is_effective = current_effective.contains(&pref);
                                                    let status = current_statuses
                                                        .iter()
                                                        .find(|s| s.id == rule.id && s.grant_generation == rule.grant_generation)
                                                        .cloned();
                                                    let missing = status
                                                        .as_ref()
                                                        .map(|s| s.missing_requirements.clone())
                                                        .unwrap_or_default();
                                                    let country_excluded = status
                                                        .as_ref()
                                                        .is_some_and(|s| s.country_excluded);
                                                    let list_for_toggle = current_enabled.clone();
                                                    let is_blur = rule.action == PolicyAction::Blur;
                                                    let (preset_text, preset_badge_cls, card_cls) =
                                                        preset_badge_meta(rule.preset);
                                                    let (state_text, state_badge_cls) =
                                                        switcher_state_badge(
                                                            rule.action,
                                                            is_enabled,
                                                            is_effective,
                                                            country_excluded,
                                                            !missing.is_empty(),
                                                        );
                                                    let toggle_label = if is_blur {
                                                        "Show clearly without blur (auto-reveal)"
                                                    } else {
                                                        "Show blocked content (bypass filter)"
                                                    };
                                                    let toggle_desc = if is_blur {
                                                        "OFF: blurred preview until clicked \u{00B7} ON: automatically show clear images"
                                                    } else {
                                                        "OFF: hidden behind a placeholder card \u{00B7} ON: automatically show matching items"
                                                    };
                                                    let require_age_18 = rule.bypass.require_age_18;
                                                    let require_current_terms = rule.bypass.require_current_terms;
                                                    let checked_sig = Signal::derive(move || is_enabled);
                                                    let disabled_sig = Signal::derive(move || {
                                                        busy.get() || (country_excluded && !is_enabled)
                                                    });

                                                    view! {
                                                        <div class=card_cls>
                                                            <div class="u-policy-header">
                                                                <div class="u-policy-header-left">
                                                                    <strong class="u-policy-title">{rule_name}</strong>
                                                                    <span class=preset_badge_cls>{preset_text}</span>
                                                                </div>
                                                                <span class=state_badge_cls>{state_text}</span>
                                                            </div>

                                                            <ToggleSwitch
                                                                checked=checked_sig
                                                                label=toggle_label
                                                                description=toggle_desc
                                                                disabled=disabled_sig
                                                                on_change=Callback::new(move |next_on: bool| {
                                                                    if next_on && require_age_18 && !age_verified {
                                                                        if is_self_attest_mode {
                                                                            open_age_gate_modal.run((
                                                                                Some(pref_for_toggle.clone()),
                                                                                Some(rule_name_for_toggle.clone()),
                                                                            ));
                                                                        } else if is_strict_18 {
                                                                            toasts.warning(
                                                                                "Verified 18+ identity required",
                                                                                Some(format!(
                                                                                    "Sign in with or link a verified 18+ OIDC provider to unlock {rule_name_for_toggle}."
                                                                                )),
                                                                            );
                                                                        } else {
                                                                            toasts.warning(
                                                                                "Age verification disabled",
                                                                                Some("18+ age verification is currently disabled by site policy.".into()),
                                                                            );
                                                                        }
                                                                        return;
                                                                    }
                                                                    let mut next_list = list_for_toggle.clone();
                                                                    if next_on {
                                                                        if !next_list.contains(&pref_for_toggle) {
                                                                            next_list.push(pref_for_toggle.clone());
                                                                        }
                                                                    } else {
                                                                        next_list.retain(|p| p != &pref_for_toggle);
                                                                    }
                                                                    save_prefs.run((
                                                                        next_list,
                                                                        rule_name_for_toggle.clone(),
                                                                        next_on,
                                                                    ));
                                                                })
                                                            />

                                                            <div class="u-reqs-row">
                                                                <span class="u-req-label">"Requirements:"</span>
                                                                <span class="u-req-item u-req-item--ok">
                                                                    "\u{2713} Signed in"
                                                                </span>

                                                                {require_current_terms.then(|| {
                                                                    if accepted_current_terms {
                                                                        view! {
                                                                            <span class="u-req-item u-req-item--ok">
                                                                                {format!("\u{2713} Terms v{current_terms_version} accepted")}
                                                                            </span>
                                                                        }.into_any()
                                                                    } else {
                                                                        view! {
                                                                            <span class="u-req-item u-req-item--warn">
                                                                                <span>"\u{26A0} Terms acceptance required"</span>
                                                                                <button
                                                                                    type="button"
                                                                                    class="u-req-action"
                                                                                    disabled=move || busy.get()
                                                                                    on:click=move |_| {
                                                                                        age_gate_open.set(false);
                                                                                        show_terms_modal.set(true);
                                                                                    }
                                                                                >
                                                                                    "Review & Accept Terms"
                                                                                </button>
                                                                            </span>
                                                                        }.into_any()
                                                                    }
                                                                })}

                                                                {require_age_18.then(|| {
                                                                    if age_verified {
                                                                        view! {
                                                                            <span class="u-req-item u-req-item--ok">
                                                                                "\u{2713} Age 18+ confirmed"
                                                                            </span>
                                                                        }.into_any()
                                                                    } else if is_self_attest_mode {
                                                                        view! {
                                                                            <span class="u-req-item u-req-item--warn">
                                                                                <span>"\u{26A0} Age 18+ confirmation required"</span>
                                                                                <button
                                                                                    type="button"
                                                                                    class="u-req-action"
                                                                                    disabled=move || busy.get()
                                                                                    on:click=move |_| open_age_gate_modal.run((None, None))
                                                                                >
                                                                                    "Confirm 18+ now"
                                                                                </button>
                                                                            </span>
                                                                        }.into_any()
                                                                    } else if is_strict_18 {
                                                                        view! {
                                                                            <span class="u-req-item u-req-item--warn">
                                                                                "\u{26A0} Verified 18+ identity (OIDC) required"
                                                                            </span>
                                                                        }.into_any()
                                                                    } else {
                                                                        view! {
                                                                            <span class="u-req-item u-req-item--warn">
                                                                                "\u{26A0} Age 18+ verification disabled by site policy"
                                                                            </span>
                                                                        }.into_any()
                                                                    }
                                                                })}

                                                                {country_excluded.then(|| view! {
                                                                    <span class="u-req-item u-req-item--danger">
                                                                        "\u{26A0} Not available in your region"
                                                                    </span>
                                                                })}
                                                            </div>
                                                        </div>
                                                    }
                                                }).collect_view()}
                                            </div>
                                        }.into_any()
                                    }}
                                </section>

                                // 4. Linked Identities & Payment Wallets
                                <section id="linked-identities" class="u-card">
                                    <h2>"Linked Identities & Payment Wallets"</h2>
                                    <p class="u-sub">
                                        "Sign-in methods are never auto-linked by email. You can link payment wallets anytime for crypto top-ups without changing your sign-in method."
                                    </p>

                                    <div class="u-list">
                                        {identities.into_iter().map(|ident| {
                                            let p = ident.provider_id.clone();
                                            let iss = ident.issuer.clone();
                                            let sub = ident.subject.clone();
                                            let label = ident.label.clone().unwrap_or_else(|| ident.provider_id.clone());
                                            view! {
                                                <div class="u-item-row">
                                                    <div>
                                                        <div class="u-row">
                                                            <strong>{label}</strong>
                                                            <span class="u-badge">{ident.provider_id.clone()}</span>
                                                            <span class="u-badge">{ident.purpose.clone()}</span>
                                                        </div>
                                                        <div class="u-mono u-sub">{ident.subject.clone()}</div>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        class="u-btn u-btn--danger u-btn--small"
                                                        disabled=move || busy.get()
                                                        on:click=move |_| unlink_identity.run((p.clone(), iss.clone(), sub.clone()))
                                                    >
                                                        "Unlink"
                                                    </button>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>

                                    <div class="u-divider">"Payment Wallets (Crypto Top-Up)"</div>
                                    <div class="u-row">
                                        <button
                                            type="button"
                                            class="u-btn u-btn--secondary u-btn--small"
                                            disabled=move || busy.get()
                                            on:click=on_link_eth_wallet
                                        >
                                            {if data.linked_eth_address.is_some() { "Update Ethereum Payment Wallet" } else { "Link Ethereum Payment Wallet" }}
                                        </button>
                                        <button
                                            type="button"
                                            class="u-btn u-btn--secondary u-btn--small"
                                            disabled=move || busy.get()
                                            on:click=on_link_sol_wallet
                                        >
                                            {if data.linked_solana_address.is_some() { "Update Solana Payment Wallet" } else { "Link Solana Payment Wallet" }}
                                        </button>
                                    </div>

                                    {has_any_linkable_login.then(|| view! {
                                        <div>
                                            <div class="u-divider">"Link Sign-in Method or Fuse Accounts"</div>
                                            <p class="u-sub">
                                                "Add another wallet or OAuth provider to sign in here. If that wallet or provider is already registered to a separate account, you\u{2019}ll be prompted to fuse both accounts into one (choosing which account & favorites to keep)."
                                            </p>
                                            {(!can_link).then(|| view! {
                                                <div class="u-quota-hint u-quota-hint--warn" style="margin-bottom:10px;">
                                                    <span>"For security, linking or fusing sign-in methods requires a fresh sign-in within the last 10 minutes. "</span>
                                                    <a href="/user/login?next=%2Fuser%2Faccount%23linked-identities">"Sign in again to unlock"</a>
                                                </div>
                                            })}
                                            <div class="u-row">
                                                {can_link_siwe.then(|| view! {
                                                    <button
                                                        type="button"
                                                        class="u-btn u-btn--secondary u-btn--small"
                                                        disabled=move || busy.get() || !can_link
                                                        on:click=move |_| on_link_or_merge_eth.run(())
                                                    >
                                                        "Link / Merge Ethereum (SIWE)"
                                                    </button>
                                                })}
                                                {can_link_siws.then(|| view! {
                                                    <button
                                                        type="button"
                                                        class="u-btn u-btn--secondary u-btn--small"
                                                        disabled=move || busy.get() || !can_link
                                                        on:click=move |_| on_link_or_merge_sol.run(())
                                                    >
                                                        "Link / Merge Solana (SIWS)"
                                                    </button>
                                                })}
                                                {linkable_oauth.into_iter().map(|prov| {
                                                    let slug = prov.id.as_str().to_string();
                                                    let title = prov.display_name.unwrap_or_else(|| slug.clone());
                                                    view! {
                                                        <button
                                                            type="button"
                                                            class="u-btn u-btn--secondary u-btn--small"
                                                            disabled=move || busy.get() || !can_link
                                                            on:click=move |_| link_oauth_provider.run(slug.clone())
                                                        >
                                                            {format!("Link / Merge {title}")}
                                                        </button>
                                                    }
                                                }).collect_view()}
                                            </div>
                                        </div>
                                    })}
                                </section>

                                // 5. Top-Up & Subscriptions
                                <section id="topup" class="u-card">
                                    <h2>"Top Up & Subscriptions"</h2>
                                    {move || {
                                        if quota_notice_dismissed.get() {
                                            return None;
                                        }
                                        let (title, body) = quota_notice_topup.as_ref()?;
                                        Some(view! {
                                            <div class="u-topup-notice">
                                                <NoticeBanner
                                                    content=NoticeContent::Text(body.clone())
                                                    tone=NoticeTone::Warning
                                                    title=title.to_string()
                                                    dismissible=true
                                                    on_dismiss=dismiss_quota_notice
                                                />
                                            </div>
                                        })
                                    }}

                                    {
                                        let allow_paid = data.allow_paid_media;
                                        let checked_paid = Signal::derive(move || allow_paid);
                                        let disabled_paid = Signal::derive(move || busy.get());
                                        let (badge_txt, badge_cls) = if allow_paid {
                                            ("ON \u{00B7} Credit spending enabled", "u-state-badge u-state-badge--on")
                                        } else {
                                            ("OFF \u{00B7} Balance protected", "u-state-badge u-state-badge--off")
                                        };
                                        let show_return_gallery = allow_paid
                                            && arrived_for_quota.get_value()
                                            && has_media_balance(&data);
                                        view! {
                                            <div id="billing-prefs" class="u-billing-toggle-box">
                                                <div class="u-policy-header">
                                                    <div class="u-policy-header-left">
                                                        <strong class="u-policy-title">"Credit Spending Protection"</strong>
                                                    </div>
                                                    <span class=badge_cls>{badge_txt}</span>
                                                </div>
                                                <ToggleSwitch
                                                    checked=checked_paid
                                                    label="Use credits to load images & videos after quota runs out"
                                                    description="OFF (default): stop loading paid images & videos once your daily free allowance and plan window run out, protecting your balance. ON: automatically spend points to keep loading media."
                                                    disabled=disabled_paid
                                                    on_change=Callback::new(move |next_on: bool| {
                                                        save_billing_prefs.run(next_on);
                                                    })
                                                />
                                                {show_return_gallery.then(|| view! {
                                                    <div class="u-billing-toggle-actions">
                                                        <a class="u-btn u-btn--small" href="/">
                                                            "Back to Gallery \u{2192}"
                                                        </a>
                                                    </div>
                                                })}
                                            </div>
                                        }
                                    }

                                    <p class="u-sub">
                                        {format!(
                                            "{} points per USD \u{00B7} Minimum top-up: {} \u{00B7} Repeat views within {}h are free.",
                                            data.pricing.points_per_usd,
                                            api::format_points(data.pricing.minimum_topup),
                                            data.pricing.dedupe_hours
                                        )}
                                    </p>

                                    {move || rates.get().map(|r| view! {
                                        <p class="u-sub u-mono">
                                            {format!("Live spot rates: ETH ${:.2} \u{00B7} SOL ${:.2}", r.eth_usd, r.sol_usd)}
                                        </p>
                                    })}

                                    <div class="u-grid-2">
                                        <div>
                                            <h3>"Crypto Top-Up"</h3>
                                            <form on:submit=on_wallet_topup>
                                                <div class="u-field">
                                                    <label class="u-label" for="u-asset-sel">"Asset"</label>
                                                    <select
                                                        id="u-asset-sel"
                                                        class="u-select"
                                                        prop:value=move || selected_asset.get()
                                                        on:change=move |ev| selected_asset.set(event_target_value(&ev))
                                                    >
                                                        <option value="ethereum:eth">"ETH (Ethereum)"</option>
                                                        <option value="ethereum:usdc">"USDC (Ethereum)"</option>
                                                        <option value="ethereum:usdt">"USDT (Ethereum)"</option>
                                                        <option value="solana:sol">"SOL (Solana)"</option>
                                                        <option value="solana:usdc">"USDC (Solana)"</option>
                                                        <option value="solana:usdt">"USDT (Solana)"</option>
                                                    </select>
                                                </div>
                                                <div class="u-field">
                                                    <label class="u-label" for="u-amt-in">"Amount"</label>
                                                    <input
                                                        id="u-amt-in"
                                                        type="text"
                                                        class="u-input"
                                                        prop:value=move || topup_amount.get()
                                                        on:input=move |ev| topup_amount.set(event_target_value(&ev))
                                                    />
                                                </div>
                                                <button type="submit" class="u-btn u-btn--full" disabled=move || busy.get()>
                                                    "Pay with linked wallet"
                                                </button>
                                            </form>
                                            {move || topup_status.get().map(|s| view! {
                                                <p class="u-sub" style="margin-top:8px;">{s}</p>
                                            })}

                                            <div class="u-divider">"Or verify an existing transaction hash"</div>
                                            <form on:submit=on_manual_topup class="u-row">
                                                <input
                                                    type="text"
                                                    class="u-input"
                                                    style="flex: 1;"
                                                    placeholder="0x... or Solana tx signature"
                                                    prop:value=move || manual_tx_hash.get()
                                                    on:input=move |ev| manual_tx_hash.set(event_target_value(&ev))
                                                />
                                                <button type="submit" class="u-btn u-btn--secondary" disabled=move || busy.get()>
                                                    "Verify"
                                                </button>
                                            </form>
                                        </div>

                                        <div>
                                            <h3>"Subscription Plans"</h3>
                                            <div class="u-list">
                                                {plans.into_iter().map(|p| {
                                                    let pid = p.id.clone();
                                                    let price = p.price_points;
                                                    let views = p.views_per_window.map_or_else(|| "Unlimited".into(), |v| v.to_string());
                                                    view! {
                                                        <div class="u-plan-card">
                                                            <div>
                                                                <strong>{pid.to_uppercase()}</strong>
                                                                <div class="u-sub">
                                                                    {format!(
                                                                        "{} \u{00B7} {} days \u{00B7} {} view units \u{00B7} {} searches/5h",
                                                                        api::format_points(price),
                                                                        p.period_days,
                                                                        views,
                                                                        p.searches_per_window
                                                                    )}
                                                                </div>
                                                            </div>
                                                            <button
                                                                type="button"
                                                                class="u-btn u-btn--small"
                                                                disabled=move || busy.get()
                                                                on:click=move |_| on_subscribe.run((pid.clone(), price))
                                                            >
                                                                "Subscribe"
                                                            </button>
                                                        </div>
                                                    }
                                                }).collect_view()}
                                                {data.plan.is_some().then(|| view! {
                                                    <button
                                                        type="button"
                                                        class="u-btn u-btn--danger u-btn--small"
                                                        disabled=move || busy.get()
                                                        on:click=on_unsubscribe
                                                    >
                                                        "Cancel plan & refund remainder"
                                                    </button>
                                                })}
                                            </div>

                                            <div class="u-divider">"Pay-as-you-go Pricing"</div>
                                            <div class="u-table-wrap">
                                                <table class="u-table">
                                                    <thead>
                                                        <tr><th>"Item"</th><th>"Points"</th><th>"Free / UTC day"</th></tr>
                                                    </thead>
                                                    <tbody>
                                                        {items.into_iter().map(|it| view! {
                                                            <tr>
                                                                <td>{it.label}</td>
                                                                <td>{it.price}</td>
                                                                <td>{if it.daily_free < 0 { "Unlimited".to_string() } else { it.daily_free.to_string() }}</td>
                                                            </tr>
                                                        }).collect_view()}
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="u-divider">"Payment History"</div>
                                    {move || {
                                        let rows = payments.get();
                                        if rows.is_empty() {
                                            view! { <p class="u-sub">"No deposits recorded yet."</p> }.into_any()
                                        } else {
                                            view! {
                                                <div class="u-table-wrap">
                                                    <table class="u-table">
                                                        <thead>
                                                            <tr><th>"Chain"</th><th>"Asset"</th><th>"Points"</th><th>"Status"</th><th>"Transaction"</th></tr>
                                                        </thead>
                                                        <tbody>
                                                            {rows.into_iter().map(|r| view! {
                                                                <tr>
                                                                    <td>{r.chain}</td>
                                                                    <td>{r.token.to_uppercase()}</td>
                                                                    <td>{r.points}</td>
                                                                    <td>{r.status}</td>
                                                                    <td class="u-mono">{r.tx_hash}</td>
                                                                </tr>
                                                            }).collect_view()}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            }.into_any()
                                        }
                                    }}
                                </section>

                                // 6. Device Transfer & Session Security
                                <section class="u-card">
                                    <h2>"Sessions & Cross-Device Transfer"</h2>
                                    <div class="u-row">
                                        <button
                                            type="button"
                                            class="u-btn u-btn--secondary u-btn--small"
                                            disabled=move || busy.get()
                                            on:click=on_create_transfer
                                        >
                                            "Create one-time transfer code"
                                        </button>
                                        <button
                                            type="button"
                                            class="u-btn u-btn--danger u-btn--small"
                                            disabled=move || busy.get()
                                            on:click=on_revoke_all
                                        >
                                            "Sign out of all devices"
                                        </button>
                                    </div>
                                    {move || transfer.get().map(|t| {
                                        let svg = t.qr.as_ref().map(|q| q.to_svg()).unwrap_or_default();
                                        let code = t.code.clone();
                                        view! {
                                            <div class="u-qr-box" style="margin-top:12px;">
                                                <div class="u-qr-svg" inner_html=svg />
                                                <div class="u-verify-code">{code}</div>
                                                <p class="u-sub">"Valid for 3 minutes (single-use)."</p>
                                                <button
                                                    type="button"
                                                    class="u-btn u-btn--secondary u-btn--small"
                                                    on:click=on_revoke_transfer
                                                >
                                                    "Revoke transfer code"
                                                </button>
                                            </div>
                                        }
                                    })}
                                </section>
                            </div>
                        }.into_any()
                    }
                }}
            </div>

            // Shared 18+ Age Confirmation Modal (mounted outside `me.get()` so updates never flicker/remount)
            <AgeGateModal
                open=age_gate_open
                title=Signal::derive(move || {
                    if let Some(name) = pending_switcher_label.get() {
                        format!("Confirm 18+ to Enable {name}")
                    } else {
                        "18+ Age Confirmation".to_string()
                    }
                })
                subtitle=Signal::derive(move || {
                    if let Some(name) = pending_switcher_label.get() {
                        format!(
                            "Your 18+ confirmation will be saved to your account and \"{name}\" will be turned on automatically."
                        )
                    } else {
                        "Your 18+ confirmation will be saved to your account preferences.".to_string()
                    }
                })
                is_authenticated=Signal::derive(|| true)
                submitting=Signal::derive(move || age_gate_submitting.get())
                error=Signal::derive(move || age_gate_error.get())
                on_confirm=on_age_gate_confirm
                on_leave=close_age_gate_modal
                on_close=close_age_gate_modal
            />

            // Terms Modal: read-only when already accepted (Close button ONLY);
            // Review & Accept form when Terms are still pending!
            {move || show_terms_modal.get().then(|| {
                let Some(data) = me.get() else {
                    return view! { <div></div> }.into_any();
                };
                let accepted = data.accepted_current_terms || data.terms_up_to_date;
                let badge = format_accepted_badge(
                    data.policy.legal.terms_version,
                    data.terms_accepted_at,
                );
                let is_self_attest = data.policy.age_policy == AgeVerificationPolicy::SelfAttestation;
                let age_verified = caller_satisfies_age_18(
                    data.policy.age_policy,
                    data.assurance_level,
                    data.strict_age_ok,
                );

                view! {
                    <div
                        class="u-modal-backdrop"
                        role="presentation"
                        on:click=move |_| {
                            if !busy.get_untracked() {
                                show_terms_modal.set(false);
                            }
                        }
                    >
                        <div
                            class="u-modal"
                            role="dialog"
                            aria-modal="true"
                            aria-labelledby="u-terms-modal-title"
                            on:click=move |ev: ev::MouseEvent| ev.stop_propagation()
                        >
                            <div class="u-modal-header">
                                <h2 id="u-terms-modal-title">
                                    {if accepted {
                                        "Terms of Service".to_string()
                                    } else {
                                        format!("Review & Accept Terms v{}", terms_version.get())
                                    }}
                                </h2>
                                {if accepted {
                                    view! { <span class="u-badge u-badge--ok">{badge}</span> }.into_any()
                                } else {
                                    view! { <span class="u-badge u-badge--warn">"Acceptance required"</span> }.into_any()
                                }}
                            </div>
                            <div class="u-modal-body">
                                <div class="u-terms-box u-terms-box--modal">
                                    {move || terms_md.get()}
                                </div>
                                {(!accepted && is_self_attest && !age_verified).then(|| view! {
                                    <label class="u-check-label" style="margin-top:12px;margin-bottom:0;">
                                        <input
                                            type="checkbox"
                                            prop:checked=move || self_attest_checked.get()
                                            on:change=move |ev| self_attest_checked.set(event_target_checked(&ev))
                                        />
                                        <span>"Also confirm that I am 18 years of age or older and legally permitted to view adult content in my jurisdiction."</span>
                                    </label>
                                })}
                            </div>
                            <div class="u-modal-footer">
                                {if accepted {
                                    view! {
                                        <button
                                            type="button"
                                            class="u-btn u-btn--secondary"
                                            on:click=move |_| show_terms_modal.set(false)
                                        >
                                            "Close"
                                        </button>
                                    }.into_any()
                                } else {
                                    view! {
                                        <button
                                            type="button"
                                            class="u-btn u-btn--secondary"
                                            disabled=move || busy.get()
                                            on:click=move |_| show_terms_modal.set(false)
                                        >
                                            "Cancel"
                                        </button>
                                        <button
                                            type="button"
                                            class="u-btn"
                                            disabled=move || busy.get()
                                            on:click=move |_| {
                                                let attest = self_attest_checked.get_untracked();
                                                submit_terms.run(attest);
                                            }
                                        >
                                            {move || format!("Accept Terms v{}", terms_version.get())}
                                        </button>
                                    }.into_any()
                                }}
                            </div>
                        </div>
                    </div>
                }.into_any()
            })}

            // Fuse Accounts Modal: choose kept account, favorites preservation, and inspect
            // exact paid credit + prorated subscription transfer before confirming.
            {move || merge_preview.get().map(|prev| {
                let cur = prev.current_account.clone();
                let oth = prev.other_account.clone();
                let keep_cur = prev.keep_current.clone();
                let keep_oth = prev.keep_other.clone();
                let cur_fav = cur.favorites_count;
                let oth_fav = oth.favorites_count;
                let cur_plan_label = cur.plan.as_deref().map(|p| plan_display_label(Some(p), false)).unwrap_or_else(|| "Free / None".into());
                let oth_plan_label = oth.plan.as_deref().map(|p| plan_display_label(Some(p), false)).unwrap_or_else(|| "Free / None".into());
                let cur_end = (cur.plan.is_some() && cur.period_end > 0)
                    .then(|| format!("ends {}", api::format_epoch_date(cur.period_end)));
                let oth_end = (oth.plan.is_some() && oth.period_end > 0)
                    .then(|| format!("ends {}", api::format_epoch_date(oth.period_end)));
                let cur_idents = cur.identities.clone();
                let oth_idents = oth.identities.clone();
                let cur_has_plan = cur.plan.is_some();
                let oth_has_plan = oth.plan.is_some();
                let cur_plan_name = cur_plan_label.clone();
                let oth_plan_name = oth_plan_label.clone();

                view! {
                    <div
                        class="u-modal-backdrop"
                        role="presentation"
                        on:click=move |_| {
                            if !merge_submitting.get_untracked() {
                                merge_preview.set(None);
                                merge_error.set(None);
                            }
                        }
                    >
                        <div
                            class="u-modal u-modal--wide"
                            role="dialog"
                            aria-modal="true"
                            aria-labelledby="u-merge-modal-title"
                            on:click=move |ev: ev::MouseEvent| ev.stop_propagation()
                        >
                            <div class="u-modal-header">
                                <h2 id="u-merge-modal-title">"Fuse Two Accounts"</h2>
                                <span class="u-badge u-badge--ok">"\u{2713} Both accounts verified"</span>
                            </div>
                            <div class="u-modal-body u-merge-body">
                                <div class="u-merge-section">
                                    <div class="u-merge-step-title">"1. Choose which account to keep"</div>
                                    <p class="u-sub" style="margin:0;">
                                        "All sign-in methods from both accounts will be combined onto the account you keep. Keeping an account preserves its active subscription, safety settings, and Terms status."
                                    </p>
                                    <div class="u-merge-accounts-grid">
                                        <button
                                            type="button"
                                            class=move || if merge_preserve.get() == "current" {
                                                "u-merge-acct-card is-selected"
                                            } else {
                                                "u-merge-acct-card"
                                            }
                                            disabled=move || merge_submitting.get()
                                            on:click=move |_| merge_preserve.set("current".to_string())
                                        >
                                            <div class="u-merge-acct-top">
                                                <span class="u-merge-radio">
                                                    {move || if merge_preserve.get() == "current" { "\u{25C9}" } else { "\u{25CB}" }}
                                                </span>
                                                <strong>"Current Account"</strong>
                                                <span class="u-badge">{move || if merge_preserve.get() == "current" { "Keep" } else { "Abandon" }}</span>
                                            </div>
                                            <div class="u-mono u-sub u-merge-acct-addr">{cur.display_address.clone()}</div>
                                            <div class="u-merge-ident-list">
                                                {cur_idents.into_iter().map(|i| view! {
                                                    <span class="u-badge">{i.provider_id}</span>
                                                }).collect_view()}
                                            </div>
                                            <div class="u-merge-acct-stats">
                                                <div><span>"Balance"</span><strong>{api::format_points(cur.balance)}</strong></div>
                                                <div><span>"Paid portion"</span><strong>{api::format_points(cur.paid_balance)}</strong></div>
                                                <div>
                                                    <span>"Plan"</span>
                                                    <strong>
                                                        {match cur_end.as_deref() {
                                                            Some(end) => format!("{cur_plan_label} ({end})"),
                                                            None => cur_plan_label.clone(),
                                                        }}
                                                    </strong>
                                                </div>
                                                <div><span>"Favorites"</span><strong>{api::format_number(cur_fav)}</strong></div>
                                            </div>
                                        </button>

                                        <button
                                            type="button"
                                            class=move || if merge_preserve.get() == "other" {
                                                "u-merge-acct-card is-selected"
                                            } else {
                                                "u-merge-acct-card"
                                            }
                                            disabled=move || merge_submitting.get()
                                            on:click=move |_| merge_preserve.set("other".to_string())
                                        >
                                            <div class="u-merge-acct-top">
                                                <span class="u-merge-radio">
                                                    {move || if merge_preserve.get() == "other" { "\u{25C9}" } else { "\u{25CB}" }}
                                                </span>
                                                <strong>"Other Account"</strong>
                                                <span class="u-badge">{move || if merge_preserve.get() == "other" { "Keep" } else { "Abandon" }}</span>
                                            </div>
                                            <div class="u-mono u-sub u-merge-acct-addr">{oth.display_address.clone()}</div>
                                            <div class="u-merge-ident-list">
                                                {oth_idents.into_iter().map(|i| view! {
                                                    <span class="u-badge">{i.provider_id}</span>
                                                }).collect_view()}
                                            </div>
                                            <div class="u-merge-acct-stats">
                                                <div><span>"Balance"</span><strong>{api::format_points(oth.balance)}</strong></div>
                                                <div><span>"Paid portion"</span><strong>{api::format_points(oth.paid_balance)}</strong></div>
                                                <div>
                                                    <span>"Plan"</span>
                                                    <strong>
                                                        {match oth_end.as_deref() {
                                                            Some(end) => format!("{oth_plan_label} ({end})"),
                                                            None => oth_plan_label.clone(),
                                                        }}
                                                    </strong>
                                                </div>
                                                <div><span>"Favorites"</span><strong>{api::format_number(oth_fav)}</strong></div>
                                            </div>
                                        </button>
                                    </div>
                                </div>

                                <div class="u-merge-section">
                                    <div class="u-merge-step-title">"2. Choose which favorites to preserve"</div>
                                    <div class="u-merge-fav-options">
                                        <button
                                            type="button"
                                            class=move || if merge_favorites.get() == "both" {
                                                "u-merge-fav-opt is-selected"
                                            } else {
                                                "u-merge-fav-opt"
                                            }
                                            disabled=move || merge_submitting.get()
                                            on:click=move |_| merge_favorites.set("both".to_string())
                                        >
                                            <strong>"Combine both (Recommended)"</strong>
                                            <span>{format!("Keep all unique favorites from both accounts ({} + {})", api::format_number(cur_fav), api::format_number(oth_fav))}</span>
                                        </button>
                                        <button
                                            type="button"
                                            class=move || if merge_favorites.get() == "keep_current" {
                                                "u-merge-fav-opt is-selected"
                                            } else {
                                                "u-merge-fav-opt"
                                            }
                                            disabled=move || merge_submitting.get()
                                            on:click=move |_| merge_favorites.set("keep_current".to_string())
                                        >
                                            <strong>"Current Account\u{2019}s favorites only"</strong>
                                            <span>{format!("Keep {} saved item(s); discard Other Account\u{2019}s", api::format_number(cur_fav))}</span>
                                        </button>
                                        <button
                                            type="button"
                                            class=move || if merge_favorites.get() == "keep_other" {
                                                "u-merge-fav-opt is-selected"
                                            } else {
                                                "u-merge-fav-opt"
                                            }
                                            disabled=move || merge_submitting.get()
                                            on:click=move |_| merge_favorites.set("keep_other".to_string())
                                        >
                                            <strong>"Other Account\u{2019}s favorites only"</strong>
                                            <span>{format!("Keep {} saved item(s); discard Current Account\u{2019}s", api::format_number(oth_fav))}</span>
                                        </button>
                                    </div>
                                </div>

                                <div class="u-merge-section">
                                    <div class="u-merge-step-title">"3. Credit & subscription transfer summary"</div>
                                    {move || {
                                        let keep_c = merge_preserve.get() == "current";
                                        let tr = if keep_c { &keep_cur } else { &keep_oth };
                                        let abandoned_has_plan = if keep_c { oth_has_plan } else { cur_has_plan };
                                        let abandoned_plan_label = if keep_c { &oth_plan_name } else { &cur_plan_name };
                                        view! {
                                            <div class="u-merge-summary">
                                                <div class="u-merge-summary-row">
                                                    <span>"Paid credits moved from abandoned account"</span>
                                                    <strong class="u-merge-val--pos">{format!("+{}", api::format_points(tr.paid_balance_moved))}</strong>
                                                </div>
                                                {(abandoned_has_plan || tr.plan_refund_moved > 0).then(|| view! {
                                                    <div class="u-merge-summary-row">
                                                        <span>{format!("Abandoned {abandoned_plan_label} plan converted to credits (prorated paid remainder)")}</span>
                                                        <strong class="u-merge-val--pos">{format!("+{}", api::format_points(tr.plan_refund_moved))}</strong>
                                                    </div>
                                                })}
                                                {(tr.free_credits_forfeited > 0).then(|| view! {
                                                    <div class="u-merge-summary-row">
                                                        <span>"Abandoned free signup credits forfeited"</span>
                                                        <strong class="u-merge-val--neg">{format!("-{}", api::format_points(tr.free_credits_forfeited))}</strong>
                                                    </div>
                                                })}
                                                <div class="u-merge-summary-row u-merge-summary-row--total">
                                                    <span>"New kept-account balance"</span>
                                                    <strong>
                                                        {format!(
                                                            "{} (+{} added)",
                                                            api::format_points(tr.resulting_balance),
                                                            api::format_points(tr.total_credits_added)
                                                        )}
                                                    </strong>
                                                </div>
                                            </div>
                                        }
                                    }}
                                </div>

                                <div class="u-merge-warn">
                                    "Fusing accounts is permanent. The abandoned account will be closed immediately, all of its active sessions signed out, and its unused free signup credits forfeited."
                                </div>

                                {move || merge_error.get().map(|err| view! {
                                    <NoticeBanner
                                        content=NoticeContent::Text(err)
                                        tone=NoticeTone::Danger
                                        title="Could not fuse accounts"
                                        dismissible=false
                                    />
                                })}
                            </div>
                            <div class="u-modal-footer">
                                <button
                                    type="button"
                                    class="u-btn u-btn--secondary"
                                    disabled=move || merge_submitting.get()
                                    on:click=move |_| {
                                        merge_preview.set(None);
                                        merge_error.set(None);
                                    }
                                >
                                    "Cancel"
                                </button>
                                <button
                                    type="button"
                                    class="u-btn"
                                    disabled=move || merge_submitting.get()
                                    on:click=move |_| on_confirm_merge.run(())
                                >
                                    {move || if merge_submitting.get() { "Fusing accounts..." } else { "Confirm & Fuse Accounts" }}
                                </button>
                            </div>
                        </div>
                    </div>
                }
            })}
        </div>
    }
}
