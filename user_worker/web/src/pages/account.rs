//! `/user/account` — Unified account dashboard: Policy v3 content switchers
//! (`ToggleSwitch` + `pref_version` optimistic concurrency), read-only accepted
//! Terms modal, versioned Terms/Age acceptance, linked identities & payment wallets,
//! crypto top-up & subscriptions, device transfer, and session revocation.

use leptos::{ev, prelude::*, task::spawn_local};
use lets_embed_ui::{
    FloatingHeader, HeaderVariant, NoticeBanner, NoticeContent, NoticeTone, ToggleSwitch,
    browser::use_window_keydown, use_toast_store,
};
use serde_json::json;
use site_access::{AgeVerificationPolicy, AssuranceLevel, AuthProviderId, PolicyAction, PolicyRef};

use crate::{
    api::{
        self, AcceptTermsConflictResp, AcceptTermsOkResp, BootstrapResp, LinkStartResp, MeResp,
        NonceResp, PaymentRow, PreferencesConflictResp, PreferencesResp, PrepareCheckoutResp,
        RatesResp, TopupResp, TransferCreateResp,
    },
    wallet,
};

fn assurance_label(level: AssuranceLevel) -> (&'static str, &'static str) {
    match level {
        AssuranceLevel::Verified18 => ("Verified 18+", "u-badge u-badge--ok"),
        AssuranceLevel::ProviderSelfReportedDob => {
            ("DOB Checked (Unverified)", "u-badge u-badge--warn")
        }
        AssuranceLevel::SelfAttestation => ("Self-Attested 18+", "u-badge"),
        AssuranceLevel::None => ("Unverified", "u-badge u-badge--warn"),
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

#[component]
pub fn AccountPage() -> impl IntoView {
    let toasts = use_toast_store();

    let me = RwSignal::new(None::<MeResp>);
    let boot = RwSignal::new(None::<BootstrapResp>);
    let payments = RwSignal::new(Vec::<PaymentRow>::new());
    let rates = RwSignal::new(None::<RatesResp>);

    let pref_version = RwSignal::new(1u64);
    let busy = RwSignal::new(false);

    // Terms state (updates dynamically on 409 Conflict!)
    let terms_version = RwSignal::new(0u32);
    let terms_digest = RwSignal::new(String::new());
    let terms_md = RwSignal::new(String::new());
    let self_attest_checked = RwSignal::new(false);
    // Read-only modal for reviewing ALREADY-accepted Terms (never has an Accept button!)
    let show_terms_modal = RwSignal::new(false);

    // Top-up checkout state
    let selected_asset = RwSignal::new("ethereum:eth".to_string());
    let topup_amount = RwSignal::new("0.01".to_string());
    let manual_tx_hash = RwSignal::new(String::new());
    let topup_status = RwSignal::new(None::<String>);

    // Device transfer state
    let transfer = RwSignal::new(None::<TransferCreateResp>);

    let reload_me = Callback::new(move |()| {
        spawn_local(async move {
            match api::get_json::<MeResp>("/user/api/me").await {
                Ok(data) => {
                    pref_version.set(data.pref_version.max(1));
                    terms_version.set(data.policy.legal.terms_version);
                    terms_digest.set(data.policy.legal.terms_digest.clone());
                    terms_md.set(data.policy.legal.terms_md.clone());
                    let accepted = data.accepted_current_terms || data.terms_up_to_date;
                    if !accepted {
                        show_terms_modal.set(false);
                    }
                    me.set(Some(data));
                }
                Err(e) if e.status == 401 => {
                    api::navigate_hard("/user/login?next=/user/account");
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

    // Escape closes the read-only Review Terms modal cleanly.
    use_window_keydown(false, move |ev: ev::KeyboardEvent| {
        if ev.key() == "Escape" && show_terms_modal.get_untracked() {
            ev.prevent_default();
            show_terms_modal.set(false);
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
        }
        if api::current_search_param("linked").is_some() {
            toasts.success(
                "Sign-in method linked",
                Some("Your new sign-in identity is now linked to this account.".into()),
            );
            api::broadcast_safety_invalidation("account_change");
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
    let submit_terms_or_age = Callback::new(move |(attest, is_age_only): (bool, bool)| {
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
                    api::broadcast_safety_invalidation("policy_change");
                    if is_age_only {
                        toasts.success(
                            "18+ age confirmation saved",
                            Some("Self-attestation 18+ has been recorded for your account.".into()),
                        );
                    } else {
                        toasts.success(
                            "Terms accepted",
                            Some(format!("Accepted Terms v{}.", resp.terms_version_accepted)),
                        );
                    }
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
        submit_terms_or_age.run((attest, false));
    };

    let on_confirm_age_18 = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        if !self_attest_checked.get_untracked() {
            toasts.warning(
                "Confirmation required",
                Some("Check the 18+ confirmation box before saving.".into()),
            );
            return;
        }
        submit_terms_or_age.run((true, true));
    };

    // Link OAuth/OIDC identity
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

    // Link Ethereum payment wallet (allowed anytime, zero login/age privilege)
    let on_link_eth_wallet = move |_| {
        let Some(b) = boot.get_untracked() else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            let nonce = match api::get_json::<NonceResp>("/user/api/nonce").await {
                Ok(n) => n.nonce,
                Err(e) => {
                    toasts.error("Could not link Ethereum wallet", Some(e.display()));
                    busy.set(false);
                    return;
                }
            };
            match wallet::connect_and_sign_siwe(
                "",
                &b.siwe_domain,
                b.chain_id,
                &nonce,
                "Link Ethereum wallet for crypto payments.",
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
            let nonce = match api::get_json::<NonceResp>("/user/api/nonce").await {
                Ok(n) => n.nonce,
                Err(e) => {
                    toasts.error("Could not link Solana wallet", Some(e.display()));
                    busy.set(false);
                    return;
                }
            };
            let challenge = format!("Link Solana wallet to {}\nNonce: {}", m.user_id, nonce);
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
                        let needs_age_confirm_only = accepted_current_terms
                            && is_self_attest_mode
                            && data.assurance_level == AssuranceLevel::None;
                        let linkable_oauth: Vec<_> = data
                            .available_providers
                            .iter()
                            .filter(|p| matches!(
                                p.id,
                                AuthProviderId::OidcAgeAssurance
                                    | AuthProviderId::Google
                                    | AuthProviderId::GitHub
                                    | AuthProviderId::X
                                    | AuthProviderId::Discord
                            ))
                            .cloned()
                            .collect();
                        let identities = data.identities.clone();
                        let plans = data.pricing.plans.clone();
                        let items = data.pricing.items.clone();
                        let can_link = data.can_link_identity_now;
                        let badge_for_modal = accepted_badge_text.clone();

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
                                        </div>
                                    </div>
                                    <div class="u-stats">
                                        <div class="u-stat">
                                            <div class="u-stat-label">"Balance"</div>
                                            <div class="u-stat-val">{api::format_points(data.balance)}</div>
                                        </div>
                                        <div class="u-stat">
                                            <div class="u-stat-label">"Plan"</div>
                                            <div class="u-stat-val">{data.plan.clone().unwrap_or_else(|| "Pay-as-you-go".into())}</div>
                                        </div>
                                        <div class="u-stat">
                                            <div class="u-stat-label">"Window views left"</div>
                                            <div class="u-stat-val">
                                                {data.views_remaining.map(|v| v.to_string()).unwrap_or_else(|| "—".into())}
                                            </div>
                                        </div>
                                        <div class="u-stat">
                                            <div class="u-stat-label">"Total views"</div>
                                            <div class="u-stat-val">{data.total_views}</div>
                                        </div>
                                    </div>
                                </section>

                                // 2. Terms & Age Verification Card
                                <section class="u-card">
                                    <div class="u-between">
                                        <div>
                                            <h2>"Terms of Service & Age Assurance"</h2>
                                            <p class="u-sub">
                                                {if accepted_current_terms {
                                                    format!("You have accepted the current Terms (v{}).", data.policy.legal.terms_version)
                                                } else {
                                                    format!("Please review and accept Terms v{} to unlock restricted content switchers.", terms_version.get())
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
                                                    on:click=move |_| show_terms_modal.set(true)
                                                >
                                                    "Review Terms"
                                                </button>
                                            </div>
                                        })}
                                    </div>

                                    // When Terms are NOT yet accepted (or version/digest changed):
                                    // render the normal Accept Terms form.
                                    {(!accepted_current_terms).then(|| view! {
                                        <form on:submit=on_accept_terms>
                                            <div class="u-terms-box">{move || terms_md.get()}</div>
                                            {is_self_attest_mode.then(|| view! {
                                                <label class="u-check-label">
                                                    <input
                                                        type="checkbox"
                                                        prop:checked=move || self_attest_checked.get()
                                                        on:change=move |ev| self_attest_checked.set(event_target_checked(&ev))
                                                    />
                                                    <span>"I confirm that I am 18 years of age or older and legally permitted to view adult content in my jurisdiction."</span>
                                                </label>
                                            })}
                                            {is_strict_18.then(|| view! {
                                                <p class="u-sub">
                                                    "Strict 18+ mode is enabled: self-attestation is disabled. Unlocking 18+ switchers requires signing in with a verified 18+ OIDC provider."
                                                </p>
                                            })}
                                            <button type="submit" class="u-btn" disabled=move || busy.get()>
                                                {move || format!("Accept Terms v{}", terms_version.get())}
                                            </button>
                                        </form>
                                    })}

                                    // Separate 18+ self-attestation box if user accepted Terms earlier
                                    // without confirming 18+ while SelfAttestation mode is active.
                                    {needs_age_confirm_only.then(|| view! {
                                        <form class="u-age-confirm-box" on:submit=on_confirm_age_18>
                                            <strong>"18+ Age Confirmation"</strong>
                                            <label class="u-check-label" style="margin-bottom:0;">
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || self_attest_checked.get()
                                                    on:change=move |ev| self_attest_checked.set(event_target_checked(&ev))
                                                />
                                                <span>"I confirm that I am 18 years of age or older and legally permitted to view adult content in my jurisdiction."</span>
                                            </label>
                                            <div>
                                                <button type="submit" class="u-btn u-btn--small" disabled=move || busy.get()>
                                                    "Confirm 18+ Age"
                                                </button>
                                            </div>
                                        </form>
                                    })}

                                    // Read-only modal for reviewing ALREADY-accepted Terms:
                                    // displays Terms Markdown + "✓ Accepted Terms v{N}" badge + ONLY a Close button!
                                    {move || (accepted_current_terms && show_terms_modal.get()).then(|| {
                                        let badge = badge_for_modal.clone();
                                        view! {
                                            <div
                                                class="u-modal-backdrop"
                                                role="presentation"
                                                on:click=move |_| show_terms_modal.set(false)
                                            >
                                                <div
                                                    class="u-modal"
                                                    role="dialog"
                                                    aria-modal="true"
                                                    aria-labelledby="u-terms-modal-title"
                                                    on:click=move |ev: ev::MouseEvent| ev.stop_propagation()
                                                >
                                                    <div class="u-modal-header">
                                                        <h2 id="u-terms-modal-title">"Terms of Service"</h2>
                                                        <span class="u-badge u-badge--ok">{badge}</span>
                                                    </div>
                                                    <div class="u-modal-body">
                                                        <div class="u-terms-box u-terms-box--modal">
                                                            {move || terms_md.get()}
                                                        </div>
                                                    </div>
                                                    <div class="u-modal-footer">
                                                        <button
                                                            type="button"
                                                            class="u-btn u-btn--secondary"
                                                            on:click=move |_| show_terms_modal.set(false)
                                                        >
                                                            "Close"
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        }
                                    })}
                                </section>

                                // 3. Policy v3 Content Safety Switchers (ToggleSwitch + pref_version)
                                <section class="u-card">
                                    <div class="u-between">
                                        <div>
                                            <h2>"Content Safety Switchers"</h2>
                                            <p class="u-sub">
                                                "Opt in to optional content categories below. Any change syncs across your open tabs immediately."
                                            </p>
                                        </div>
                                        <span class="u-chip">
                                            {move || format!("Prefs rev #{}", pref_version.get())}
                                        </span>
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
                                                    let desc = if is_blur {
                                                        "Blurred by default; turning this switcher on shows matching items clearly."
                                                    } else {
                                                        "Hidden behind a placeholder by default; turning this switcher on unlocks matching items."
                                                    };
                                                    let checked_sig = Signal::derive(move || is_enabled);
                                                    let disabled_sig = Signal::derive(move || busy.get());

                                                    view! {
                                                        <div class="u-policy-switcher">
                                                            <div class="u-policy-meta">
                                                                <span class=if is_blur { "u-pill u-pill--blur" } else { "u-pill u-pill--block" }>
                                                                    {if is_blur { "Blur" } else { "Block" }}
                                                                </span>
                                                                {rule.bypass.require_gallery_login.then(|| view! {
                                                                    <span class="u-chip">"Login"</span>
                                                                })}
                                                                {rule.bypass.require_age_18.then(|| view! {
                                                                    <span class="u-chip u-chip--age">"18+"</span>
                                                                })}
                                                                {rule.bypass.require_current_terms.then(|| view! {
                                                                    <span class="u-chip">"Terms"</span>
                                                                })}
                                                                {(!rule.bypass.exclude_countries.is_empty()).then(|| view! {
                                                                    <span class="u-chip u-chip--geo">"Region-limited"</span>
                                                                })}
                                                                <span class="u-chip">{format!("gen #{}", rule.grant_generation)}</span>
                                                                {if is_effective {
                                                                    view! { <span class="u-badge u-badge--ok">"Active"</span> }.into_any()
                                                                } else if is_enabled && country_excluded {
                                                                    view! { <span class="u-badge u-badge--danger">"Region restricted"</span> }.into_any()
                                                                } else if is_enabled && !missing.is_empty() {
                                                                    view! { <span class="u-badge u-badge--warn">"Requirements needed"</span> }.into_any()
                                                                } else if is_enabled {
                                                                    view! { <span class="u-badge u-badge--ok">"Enabled"</span> }.into_any()
                                                                } else {
                                                                    view! { <span class="u-badge">"Off"</span> }.into_any()
                                                                }}
                                                            </div>
                                                            <ToggleSwitch
                                                                checked=checked_sig
                                                                label=rule_name
                                                                description=desc
                                                                disabled=disabled_sig
                                                                on_change=Callback::new(move |next_on: bool| {
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
                                                            {(!missing.is_empty()).then(|| view! {
                                                                <p class="u-policy-reqs">
                                                                    {format!("Eligibility: {}", missing.join(" \u{00B7} "))}
                                                                </p>
                                                            })}
                                                        </div>
                                                    }
                                                }).collect_view()}
                                            </div>
                                        }.into_any()
                                    }}
                                </section>

                                // 4. Linked Identities & Payment Wallets
                                <section class="u-card">
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

                                    {(!linkable_oauth.is_empty()).then(|| view! {
                                        <div>
                                            <div class="u-divider">"Link Additional Sign-in Method"</div>
                                            {(!can_link).then(|| view! {
                                                <p class="u-sub">
                                                    "For security, linking a new sign-in provider requires a fresh sign-in within the last 10 minutes."
                                                </p>
                                            })}
                                            <div class="u-row">
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
                                                            {format!("Link {title}")}
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
        </div>
    }
}
