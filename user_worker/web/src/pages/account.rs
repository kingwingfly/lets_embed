//! `/user/account` — Unified account dashboard: safety switchers, Safe Mode,
//! versioned Terms/Age acceptance, linked identities & payment wallets,
//! crypto top-up & subscriptions, device transfer, and session revocation.

use leptos::{ev, prelude::*, task::spawn_local};
use lets_embed_ui::{
    FloatingHeader, HeaderVariant, NoticeBanner, NoticeContent, NoticeTone, SafeModeToggle,
};
use serde_json::json;
use site_access::{AgeVerificationPolicy, AssuranceLevel, AuthProviderId, RuleMode};

use crate::{
    api::{
        self, AcceptTermsConflictResp, AcceptTermsOkResp, BootstrapResp, LinkStartResp, MeResp,
        NonceResp, PaymentRow, PreferencesResp, PrepareCheckoutResp, RatesResp, TopupResp,
        TransferCreateResp,
    },
    wallet,
};

fn assurance_label(level: AssuranceLevel) -> (&'static str, &'static str) {
    match level {
        AssuranceLevel::Verified18 => ("Verified 18+", "u-badge u-badge--ok"),
        AssuranceLevel::ProviderSelfReportedDob => ("DOB Checked (Unverified)", "u-badge u-badge--warn"),
        AssuranceLevel::SelfAttestation => ("Self-Attested 18+", "u-badge"),
        AssuranceLevel::None => ("Unverified", "u-badge u-badge--warn"),
    }
}

#[component]
pub fn AccountPage() -> impl IntoView {
    let me = RwSignal::new(None::<MeResp>);
    let boot = RwSignal::new(None::<BootstrapResp>);
    let payments = RwSignal::new(Vec::<PaymentRow>::new());
    let rates = RwSignal::new(None::<RatesResp>);

    let safe_mode = RwSignal::new(false);
    let panic_epoch = RwSignal::new(0u64);
    let busy = RwSignal::new(false);
    let error_msg = RwSignal::new(api::current_search_param("error"));
    let info_msg = RwSignal::new(
        api::current_search_param("linked").map(|_| "New sign-in identity linked.".to_string()),
    );

    // Terms state (updates dynamically on 409 Conflict!)
    let terms_version = RwSignal::new(0u32);
    let terms_digest = RwSignal::new(String::new());
    let terms_md = RwSignal::new(String::new());
    let self_attest_checked = RwSignal::new(false);
    let show_terms_editor = RwSignal::new(false);

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
                    safe_mode.set(data.safe_mode);
                    terms_version.set(data.policy.legal.terms_version);
                    terms_digest.set(data.policy.legal.terms_digest.clone());
                    terms_md.set(data.policy.legal.terms_md.clone());
                    if !data.terms_up_to_date {
                        show_terms_editor.set(true);
                    }
                    me.set(Some(data));
                }
                Err(e) if e.status == 401 => {
                    api::navigate_hard("/user/login?next=/user/account");
                }
                Err(e) => error_msg.set(Some(e.display())),
            }
            if let Ok(rows) = api::get_json::<Vec<PaymentRow>>("/user/api/payments").await {
                payments.set(rows);
            }
        });
    });

    Effect::new(move |_| {
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

    // Persist preferences helper (switchers + safe_mode)
    let save_prefs = Callback::new(move |(switchers, next_safe): (Vec<String>, bool)| {
        busy.set(true);
        error_msg.set(None);
        spawn_local(async move {
            match api::post_json::<_, PreferencesResp>(
                "/user/api/preferences",
                &json!({
                    "enabled_switchers": switchers,
                    "safe_mode": next_safe,
                }),
            )
            .await
            {
                Ok(resp) => {
                    safe_mode.set(resp.safe_mode);
                    me.update(|opt| {
                        if let Some(m) = opt {
                            m.enabled_switchers = resp.enabled_switchers.clone();
                            m.effective_switchers = resp.effective_switchers.clone();
                            m.safe_mode = resp.safe_mode;
                        }
                    });
                }
                Err(e) => error_msg.set(Some(e.display())),
            }
            busy.set(false);
        });
    });

    let on_safe_toggle = Callback::new(move |next_safe: bool| {
        let cur_switchers = me
            .get_untracked()
            .map(|m| m.enabled_switchers)
            .unwrap_or_default();
        save_prefs.run((cur_switchers, next_safe));
    });

    // Accept Terms handler (handles 409 Conflict race cleanly!)
    let on_accept_terms = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        busy.set(true);
        error_msg.set(None);
        let ver = terms_version.get_untracked();
        let dig = terms_digest.get_untracked();
        let attest = self_attest_checked.get_untracked();
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
                Ok(_) => {
                    show_terms_editor.set(false);
                    info_msg.set(Some("Terms accepted and saved.".into()));
                    reload_me.run(());
                }
                Err(e) if e.status == 409 => {
                    if let Ok(conflict) = serde_json::from_str::<AcceptTermsConflictResp>(&e.body) {
                        terms_version.set(conflict.terms_version);
                        terms_digest.set(conflict.terms_digest);
                        terms_md.set(conflict.terms_md);
                        show_terms_editor.set(true);
                        error_msg.set(Some(conflict.error));
                    } else {
                        error_msg.set(Some(e.display()));
                    }
                }
                Err(e) => error_msg.set(Some(e.display())),
            }
            busy.set(false);
        });
    };

    // Link OAuth/OIDC identity
    let link_oauth_provider = Callback::new(move |provider_id: String| {
        busy.set(true);
        error_msg.set(None);
        spawn_local(async move {
            match api::post_json::<_, LinkStartResp>(
                "/user/api/identities/link/start",
                &json!({ "provider_id": provider_id }),
            )
            .await
            {
                Ok(resp) => api::navigate_hard(&resp.authorize_url),
                Err(e) => error_msg.set(Some(e.display())),
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
        error_msg.set(None);
        spawn_local(async move {
            let nonce = match api::get_json::<NonceResp>("/user/api/nonce").await {
                Ok(n) => n.nonce,
                Err(e) => {
                    error_msg.set(Some(e.display()));
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
                            info_msg.set(Some("Ethereum payment wallet linked.".into()));
                            reload_me.run(());
                        }
                        Err(e) => error_msg.set(Some(e.display())),
                    }
                }
                Err(msg) => error_msg.set(Some(msg)),
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
        error_msg.set(None);
        spawn_local(async move {
            let nonce = match api::get_json::<NonceResp>("/user/api/nonce").await {
                Ok(n) => n.nonce,
                Err(e) => {
                    error_msg.set(Some(e.display()));
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
                            info_msg.set(Some("Solana payment wallet linked.".into()));
                            reload_me.run(());
                        }
                        Err(e) => error_msg.set(Some(e.display())),
                    }
                }
                Err(msg) => error_msg.set(Some(msg)),
            }
            busy.set(false);
        });
    };

    // Unlink identity
    let unlink_identity = Callback::new(move |(provider_id, issuer, subject): (String, String, String)| {
        busy.set(true);
        error_msg.set(None);
        spawn_local(async move {
            match api::delete_json_empty(
                "/user/api/identities",
                &json!({ "provider_id": provider_id, "issuer": issuer, "subject": subject }),
            )
            .await
            {
                Ok(()) => {
                    info_msg.set(Some("Identity unlinked.".into()));
                    reload_me.run(());
                }
                Err(e) => error_msg.set(Some(e.display())),
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
        error_msg.set(None);
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
                    error_msg.set(Some(e.display()));
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
                    error_msg.set(Some(msg));
                    busy.set(false);
                    return;
                }
            };

            manual_tx_hash.set(tx_hash.clone());
            topup_status.set(Some(format!("Broadcasted ({tx_hash}). Waiting for confirmation...")));

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
                        info_msg.set(Some(format!(
                            "Credited {}! New balance: {}.",
                            api::format_points(done.credited_points),
                            api::format_points(done.balance)
                        )));
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
                        error_msg.set(Some(e.display()));
                        busy.set(false);
                        return;
                    }
                }
            }
            topup_status.set(Some(
                "Still awaiting finality — submit the transaction hash below once confirmed.".into(),
            ));
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
        error_msg.set(None);
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
                    info_msg.set(Some(format!(
                        "Credited {}! New balance: {}.",
                        api::format_points(done.credited_points),
                        api::format_points(done.balance)
                    )));
                    manual_tx_hash.set(String::new());
                    reload_me.run(());
                }
                Err(e) => error_msg.set(Some(e.display())),
            }
            busy.set(false);
        });
    };

    let on_subscribe = Callback::new(move |(plan_id, price): (String, i64)| {
        busy.set(true);
        error_msg.set(None);
        spawn_local(async move {
            match api::post_json_empty(
                "/user/api/subscribe",
                &json!({ "plan": plan_id, "expected_price": price }),
            )
            .await
            {
                Ok(()) => {
                    info_msg.set(Some(format!("Subscribed to {plan_id}.")));
                    reload_me.run(());
                }
                Err(e) => error_msg.set(Some(e.display())),
            }
            busy.set(false);
        });
    });

    let on_unsubscribe = move |_| {
        busy.set(true);
        error_msg.set(None);
        spawn_local(async move {
            match api::post_empty("/user/api/unsubscribe").await {
                Ok(()) => {
                    info_msg.set(Some("Subscription cancelled; prorated remainder refunded.".into()));
                    reload_me.run(());
                }
                Err(e) => error_msg.set(Some(e.display())),
            }
            busy.set(false);
        });
    };

    let on_create_transfer = move |_| {
        busy.set(true);
        error_msg.set(None);
        spawn_local(async move {
            match api::post_json::<_, TransferCreateResp>("/user/api/transfer/create", &json!({})).await {
                Ok(t) => transfer.set(Some(t)),
                Err(e) => error_msg.set(Some(e.display())),
            }
            busy.set(false);
        });
    };

    let on_revoke_transfer = move |_| {
        spawn_local(async move {
            let _ = api::post_empty("/user/api/transfer/revoke").await;
            transfer.set(None);
        });
    };

    let on_logout = move |_| {
        spawn_local(async move {
            let _ = api::post_empty("/user/api/logout").await;
            api::navigate_hard("/user/login");
        });
    };

    let on_revoke_all = move |_| {
        spawn_local(async move {
            let _ = api::post_empty("/user/api/sessions/revoke_all").await;
            api::navigate_hard("/user/login");
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
                        <SafeModeToggle
                            safe_mode=safe_mode
                            panic_epoch=panic_epoch
                            on_toggle=on_safe_toggle
                        />
                        <button type="button" class="u-btn u-btn--secondary u-btn--small" on:click=on_logout>
                            "Sign out"
                        </button>
                    </div>
                }.into_any()
            />

            <div class="u-stack">
                {move || error_msg.get().map(|msg| view! {
                    <NoticeBanner
                        content=NoticeContent::Text(msg)
                        tone=NoticeTone::Danger
                        dismissible=true
                        on_dismiss=Callback::new(move |_| error_msg.set(None))
                    />
                })}

                {move || info_msg.get().map(|msg| view! {
                    <NoticeBanner
                        content=NoticeContent::Text(msg)
                        tone=NoticeTone::Success
                        dismissible=true
                        on_dismiss=Callback::new(move |_| info_msg.set(None))
                    />
                })}

                {move || match me.get() {
                    None => view! {
                        <section class="u-card"><p class="u-sub">"Loading account..."</p></section>
                    }.into_any(),
                    Some(data) => {
                        let (assur_text, assur_cls) = assurance_label(data.assurance_level);
                        let switchers: Vec<_> = data
                            .policy
                            .rules
                            .iter()
                            .filter(|r| r.enabled && r.mode == RuleMode::Switcher)
                            .cloned()
                            .collect();
                        let current_enabled = data.enabled_switchers.clone();
                        let current_effective = data.effective_switchers.clone();
                        let is_self_attest_mode = data.policy.age_policy == AgeVerificationPolicy::SelfAttestation;
                        let is_strict_18 = data.policy.age_policy == AgeVerificationPolicy::StrictProviderVerified18;
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
                                            {data.terms_up_to_date.then(|| view! {
                                                <span class="u-badge u-badge--ok">
                                                    {format!("Terms v{} accepted", data.policy.legal.terms_version)}
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
                                                {if data.terms_up_to_date {
                                                    format!("You have accepted Terms v{}.", data.policy.legal.terms_version)
                                                } else {
                                                    format!("Please review and accept Terms v{} to unlock age-restricted switchers.", terms_version.get())
                                                }}
                                            </p>
                                        </div>
                                        {data.terms_up_to_date.then(|| view! {
                                            <button
                                                type="button"
                                                class="u-btn u-btn--secondary u-btn--small"
                                                on:click=move |_| show_terms_editor.update(|v| *v = !*v)
                                            >
                                                {move || if show_terms_editor.get() { "Hide Terms" } else { "Review Terms" }}
                                            </button>
                                        })}
                                    </div>

                                    {move || show_terms_editor.get().then(|| view! {
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
                                </section>

                                // 3. Content Safety Switchers & Safe Mode
                                <section class="u-card">
                                    <div class="u-between">
                                        <div>
                                            <h2>"Content Safety & Switchers"</h2>
                                            <p class="u-sub">
                                                "Safe Mode (Shift+S) immediately hides all switchers across all tabs without clearing your saved switcher preferences."
                                            </p>
                                        </div>
                                        <SafeModeToggle
                                            safe_mode=safe_mode
                                            panic_epoch=panic_epoch
                                            on_toggle=on_safe_toggle
                                        />
                                    </div>
                                    {if switchers.is_empty() {
                                        view! { <p class="u-sub">"No optional content switchers are configured."</p> }.into_any()
                                    } else {
                                        view! {
                                            <div class="u-list">
                                                {switchers.into_iter().map(|rule| {
                                                    let rid = rule.id.clone();
                                                    let rid_click = rid.clone();
                                                    let is_enabled = current_enabled.iter().any(|s| s == &rid);
                                                    let is_effective = current_effective.iter().any(|s| s == &rid);
                                                    let list_for_toggle = current_enabled.clone();
                                                    view! {
                                                        <div class="u-switch-row">
                                                            <div>
                                                                <div class="u-row">
                                                                    <strong>{rule.name.clone()}</strong>
                                                                    {if is_effective {
                                                                        view! { <span class="u-badge u-badge--ok">"Active"</span> }.into_any()
                                                                    } else if is_enabled && safe_mode.get() {
                                                                        view! { <span class="u-badge u-badge--warn">"Paused by Safe Mode"</span> }.into_any()
                                                                    } else if is_enabled {
                                                                        view! { <span class="u-badge u-badge--warn">"Requires Terms / 18+"</span> }.into_any()
                                                                    } else {
                                                                        view! { <span class="u-badge">"Hidden"</span> }.into_any()
                                                                    }}
                                                                </div>
                                                                <div class="u-sub">
                                                                    {format!(
                                                                        "{}{}{}",
                                                                        if rule.requires_login { "Login required · " } else { "" },
                                                                        if rule.requires_age_18 { "18+ required · " } else { "" },
                                                                        if rule.requires_login || rule.requires_age_18 { "Terms required" } else { "Optional filter" }
                                                                    )}
                                                                </div>
                                                            </div>
                                                            <button
                                                                type="button"
                                                                class=if is_enabled { "u-btn u-btn--small" } else { "u-btn u-btn--secondary u-btn--small" }
                                                                disabled=move || busy.get()
                                                                on:click=move |_| {
                                                                    let mut next_list = list_for_toggle.clone();
                                                                    if is_enabled {
                                                                        next_list.retain(|s| s != &rid_click);
                                                                    } else {
                                                                        next_list.push(rid_click.clone());
                                                                    }
                                                                    save_prefs.run((next_list, safe_mode.get_untracked()));
                                                                }
                                                            >
                                                                {if is_enabled { "Enabled" } else { "Enable" }}
                                                            </button>
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
                                            "{} points per USD · Minimum top-up: {} · Repeat views within {}h are free.",
                                            data.pricing.points_per_usd,
                                            api::format_points(data.pricing.minimum_topup),
                                            data.pricing.dedupe_hours
                                        )}
                                    </p>

                                    {move || rates.get().map(|r| view! {
                                        <p class="u-sub u-mono">
                                            {format!("Live spot rates: ETH ${:.2} · SOL ${:.2}", r.eth_usd, r.sol_usd)}
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
                                                                        "{} · {} days · {} view units · {} searches/5h",
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
