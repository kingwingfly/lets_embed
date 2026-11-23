//! `/user/login` — Multi-provider login SPA supporting OIDC Age Assurance,
//! Google, GitHub, X, Discord, Email Magic Link/OTP, Telegram, SIWE, SIWS,
//! cross-device QR handoff, and transfer code claiming.

use leptos::{ev, prelude::*, task::spawn_local};
use lets_embed_ui::{FloatingHeader, HeaderVariant, NoticeBanner, NoticeContent, NoticeTone};
use serde_json::json;
use site_access::{AgeVerificationPolicy, AuthProviderId, AuthProviderPublicConfig};

use crate::{
    api::{
        self, BootstrapResp, EmailStartResp, EmailVerifyResp, HandoffPollResp, HandoffStartResp,
        NonceResp,
    },
    wallet,
};

fn provider_slug(id: AuthProviderId) -> &'static str {
    id.as_str()
}

fn default_provider_label(id: AuthProviderId) -> &'static str {
    match id {
        AuthProviderId::OidcAgeAssurance => "18+ Verified Identity (OIDC)",
        AuthProviderId::Google => "Google",
        AuthProviderId::GitHub => "GitHub",
        AuthProviderId::X => "X (Twitter)",
        AuthProviderId::Discord => "Discord",
        AuthProviderId::EmailOtp => "Email Code / Magic Link",
        AuthProviderId::Telegram => "Telegram",
        AuthProviderId::Siwe => "Ethereum Wallet (SIWE)",
        AuthProviderId::Siws => "Solana Wallet (SIWS)",
    }
}

fn is_oauth_redirect_provider(id: AuthProviderId) -> bool {
    matches!(
        id,
        AuthProviderId::OidcAgeAssurance
            | AuthProviderId::Google
            | AuthProviderId::GitHub
            | AuthProviderId::X
            | AuthProviderId::Discord
    )
}

#[component]
pub fn LoginPage() -> impl IntoView {
    view! {
        <LoginView
            heading="Sign in"
            intro="Choose an authentication method to open your gallery account."
            default_next="/"
        />
    }
}

#[component]
pub fn LoginView(
    heading: &'static str,
    intro: &'static str,
    default_next: &'static str,
    #[prop(optional)] extra_header: Option<ViewFn>,
) -> impl IntoView {
    let next_url = StoredValue::new(api::sanitize_next(
        api::current_search_param("next")
            .as_deref()
            .or(Some(default_next)),
    ));

    let boot = RwSignal::new(None::<BootstrapResp>);
    let busy = RwSignal::new(false);
    let error_msg = RwSignal::new(api::current_search_param("error"));
    let info_msg = RwSignal::new(None::<String>);

    // Email OTP / Magic link state
    let email_input = RwSignal::new(api::current_search_param("email").unwrap_or_default());
    let otp_input = RwSignal::new(String::new());
    let email_code_sent = RwSignal::new(false);

    // QR Handoff state
    let handoff = RwSignal::new(None::<HandoffStartResp>);
    let handoff_polling = RwSignal::new(false);

    // Transfer code state
    let transfer_code = RwSignal::new(String::new());

    // Initial bootstrap + auto-handle magic link (`?email_token=`) or `#transfer=` fragment.
    Effect::new(move |_| {
        spawn_local(async move {
            match api::get_json::<BootstrapResp>("/user/api/bootstrap").await {
                Ok(b) => {
                    boot.set(Some(b));
                }
                Err(e) => error_msg.set(Some(e.display())),
            }

            // Magic-link email token landing
            if let (Some(email), Some(token)) = (
                api::current_search_param("email"),
                api::current_search_param("email_token"),
            ) {
                busy.set(true);
                info_msg.set(Some("Verifying your email sign-in link...".into()));
                match api::post_json::<_, EmailVerifyResp>(
                    "/user/auth/email/verify",
                    &json!({ "email": email, "token": token }),
                )
                .await
                {
                    Ok(resp) => {
                        api::navigate_hard(&api::sanitize_next(Some(&resp.next)));
                        return;
                    }
                    Err(e) => {
                        info_msg.set(None);
                        error_msg.set(Some(e.display()));
                    }
                }
                busy.set(false);
            }

            // Cross-device `#transfer=<token>` fragment landing
            let hash = api::current_hash();
            if let Some(tok) = hash.strip_prefix("#transfer=").filter(|s| !s.is_empty()) {
                busy.set(true);
                info_msg.set(Some("Claiming transfer token...".into()));
                match api::post_json_empty("/user/api/transfer/claim", &json!({ "token": tok }))
                    .await
                {
                    Ok(()) => {
                        api::navigate_hard(&next_url.get_value());
                        return;
                    }
                    Err(e) => {
                        info_msg.set(None);
                        error_msg.set(Some(e.display()));
                    }
                }
                busy.set(false);
            }
        });
    });

    // Mount Telegram Login Widget when Telegram is an eligible enabled provider.
    Effect::new(move |_| {
        let Some(b) = boot.get() else {
            return;
        };
        let tg = b
            .policy
            .effective_login_providers()
            .into_iter()
            .find(|p| p.id == AuthProviderId::Telegram);
        if let Some(cfg) = tg
            && let Some(bot) = cfg
                .public_client_id
                .as_deref()
                .filter(|s| !s.trim().is_empty())
        {
            let bot = bot.to_string();
            let dest = next_url.get_value();
            wallet::mount_telegram_widget("le-telegram-login-mount", &bot, move |payload_json| {
                let dest = dest.clone();
                busy.set(true);
                error_msg.set(None);
                spawn_local(async move {
                    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&payload_json);
                    match parsed {
                        Ok(val) => {
                            match api::post_json_empty("/user/auth/telegram/verify", &val).await {
                                Ok(()) => api::navigate_hard(&dest),
                                Err(e) => error_msg.set(Some(e.display())),
                            }
                        }
                        Err(_) => error_msg.set(Some("Invalid Telegram payload.".into())),
                    }
                    busy.set(false);
                });
            });
        }
    });

    // Email start handler
    let on_email_start = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get_untracked().trim().to_string();
        if email.is_empty() {
            return;
        }
        busy.set(true);
        error_msg.set(None);
        info_msg.set(None);
        let dest = next_url.get_value();
        spawn_local(async move {
            match api::post_json::<_, EmailStartResp>(
                "/user/auth/email/start",
                &json!({ "email": email, "next": dest, "action": "login" }),
            )
            .await
            {
                Ok(resp) => {
                    email_code_sent.set(true);
                    info_msg.set(Some(resp.message));
                }
                Err(e) => error_msg.set(Some(e.display())),
            }
            busy.set(false);
        });
    };

    // Email OTP verify handler
    let on_email_verify = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get_untracked().trim().to_string();
        let code = otp_input.get_untracked().trim().to_string();
        if email.is_empty() || code.is_empty() {
            return;
        }
        busy.set(true);
        error_msg.set(None);
        spawn_local(async move {
            match api::post_json::<_, EmailVerifyResp>(
                "/user/auth/email/verify",
                &json!({ "email": email, "code": code }),
            )
            .await
            {
                Ok(resp) => api::navigate_hard(&api::sanitize_next(Some(&resp.next))),
                Err(e) => error_msg.set(Some(e.display())),
            }
            busy.set(false);
        });
    };

    // SIWE sign-in
    let on_siwe_login = move |_| {
        let Some(b) = boot.get_untracked() else {
            return;
        };
        busy.set(true);
        error_msg.set(None);
        let dest = next_url.get_value();
        spawn_local(async move {
            let nonce_resp = match api::get_json::<NonceResp>("/user/api/nonce").await {
                Ok(n) => n,
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
                &nonce_resp.nonce,
                "Sign in to lets_embed gallery account.",
                None,
            )
            .await
            {
                Ok(sig) => {
                    match api::post_json_empty(
                        "/user/api/verify",
                        &json!({ "message": sig.message, "signature": sig.signature }),
                    )
                    .await
                    {
                        Ok(()) => api::navigate_hard(&dest),
                        Err(e) => error_msg.set(Some(e.display())),
                    }
                }
                Err(msg) => error_msg.set(Some(msg)),
            }
            busy.set(false);
        });
    };

    // SIWS sign-in
    let on_siws_login = move |_| {
        let Some(b) = boot.get_untracked() else {
            return;
        };
        busy.set(true);
        error_msg.set(None);
        let dest = next_url.get_value();
        spawn_local(async move {
            let nonce_resp = match api::get_json::<NonceResp>("/user/api/nonce").await {
                Ok(n) => n,
                Err(e) => {
                    error_msg.set(Some(e.display()));
                    busy.set(false);
                    return;
                }
            };
            let challenge = format!(
                "Sign in to lets_embed with Solana\nDomain: {}\nNonce: {}",
                b.siwe_domain, nonce_resp.nonce
            );
            match wallet::connect_and_sign_sol_message("", &challenge).await {
                Ok(sig) => {
                    match api::post_json_empty(
                        "/user/api/verify_solana",
                        &json!({
                            "solana_address": sig.address,
                            "signature": sig.signature,
                            "nonce": nonce_resp.nonce,
                            "signed_message": sig.signed_message,
                        }),
                    )
                    .await
                    {
                        Ok(()) => api::navigate_hard(&dest),
                        Err(e) => error_msg.set(Some(e.display())),
                    }
                }
                Err(msg) => error_msg.set(Some(msg)),
            }
            busy.set(false);
        });
    };

    // Start QR handoff & poll
    let on_start_handoff = move |_| {
        busy.set(true);
        error_msg.set(None);
        let dest = next_url.get_value();
        spawn_local(async move {
            match api::post_json::<_, HandoffStartResp>("/user/api/handoff/start", &json!({})).await
            {
                Ok(h) => {
                    let sid = h.session_id.clone();
                    let secret = h.poll_secret.clone();
                    handoff.set(Some(h));
                    handoff_polling.set(true);
                    busy.set(false);

                    // Poll up to 150 iterations (~5 minutes at 2s intervals)
                    for _ in 0..150 {
                        if !handoff_polling.get_untracked() {
                            break;
                        }
                        let delay = js_sys::Promise::new(&mut |resolve, _| {
                            if let Some(w) = web_sys::window() {
                                let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                                    &resolve, 2000,
                                );
                            }
                        });
                        let _ = wasm_bindgen_futures::JsFuture::from(delay).await;
                        if !handoff_polling.get_untracked() {
                            break;
                        }
                        match api::post_json::<_, HandoffPollResp>(
                            "/user/api/handoff/poll",
                            &json!({ "session_id": sid, "poll_secret": secret }),
                        )
                        .await
                        {
                            Ok(resp) if resp.status == "approved" => {
                                handoff_polling.set(false);
                                api::navigate_hard(&dest);
                                return;
                            }
                            Ok(resp) if resp.status == "pending" => continue,
                            Ok(_) => {
                                handoff_polling.set(false);
                                handoff.set(None);
                                error_msg.set(Some("QR sign-in expired. Please start again.".into()));
                                return;
                            }
                            Err(e) => {
                                handoff_polling.set(false);
                                error_msg.set(Some(e.display()));
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    error_msg.set(Some(e.display()));
                    busy.set(false);
                }
            }
        });
    };

    // Claim 8-char transfer code
    let on_claim_transfer = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let code = transfer_code.get_untracked().trim().to_string();
        if code.is_empty() {
            return;
        }
        busy.set(true);
        error_msg.set(None);
        let dest = next_url.get_value();
        spawn_local(async move {
            match api::post_json_empty("/user/api/transfer/claim", &json!({ "code": code })).await {
                Ok(()) => api::navigate_hard(&dest),
                Err(e) => error_msg.set(Some(e.display())),
            }
            busy.set(false);
        });
    };

    let render_providers = move |b: BootstrapResp| {
        let strict_18 = b.policy.age_policy == AgeVerificationPolicy::StrictProviderVerified18;
        let effective: Vec<AuthProviderPublicConfig> = b
            .policy
            .effective_login_providers()
            .into_iter()
            .cloned()
            .collect();

        let oauth_list: Vec<AuthProviderPublicConfig> = effective
            .iter()
            .filter(|p| is_oauth_redirect_provider(p.id))
            .cloned()
            .collect();
        let has_email = effective.iter().any(|p| p.id == AuthProviderId::EmailOtp);
        let has_telegram = effective.iter().any(|p| {
            p.id == AuthProviderId::Telegram
                && p.public_client_id
                    .as_deref()
                    .is_some_and(|u| !u.trim().is_empty())
        });
        let has_siwe = effective.iter().any(|p| p.id == AuthProviderId::Siwe);
        let has_siws = effective.iter().any(|p| p.id == AuthProviderId::Siws);
        let next_encoded = urlencoding::encode(&next_url.get_value()).into_owned();

        view! {
            <div class="u-stack">
                {strict_18.then(|| view! {
                    <NoticeBanner
                        content=NoticeContent::Text(
                            "Strict 18+ age verification is active on this site. Only verified 18+ identity providers are permitted for sign-in.".into()
                        )
                        tone=NoticeTone::Warning
                        title="Verified 18+ Required"
                        dismissible=false
                    />
                })}

                {effective.is_empty().then(|| view! {
                    <NoticeBanner
                        content=NoticeContent::Text(
                            "No authentication providers are currently enabled by the site administrator.".into()
                        )
                        tone=NoticeTone::Danger
                        dismissible=false
                    />
                })}

                {(!oauth_list.is_empty()).then(|| view! {
                    <div class="u-list">
                        {oauth_list.into_iter().map(|p| {
                            let label = p.display_name
                                .as_deref()
                                .filter(|s| !s.trim().is_empty())
                                .unwrap_or_else(|| default_provider_label(p.id))
                                .to_string();
                            let href = format!(
                                "/user/auth/{}/start?next={}",
                                provider_slug(p.id),
                                next_encoded
                            );
                            let is_verified = p.id == AuthProviderId::OidcAgeAssurance;
                            view! {
                                <a class="u-btn u-btn--full" href=href>
                                    {format!("Continue with {label}")}
                                    {is_verified.then(|| view! {
                                        <span class="u-badge u-badge--ok">"18+ Verified"</span>
                                    })}
                                </a>
                            }
                        }).collect_view()}
                    </div>
                })}

                {has_telegram.then(|| view! {
                    <div>
                        <div class="u-divider">"Telegram"</div>
                        <div id="le-telegram-login-mount" class="u-row"></div>
                    </div>
                })}

                {has_email.then(|| view! {
                    <div>
                        <div class="u-divider">"Email Magic Link or 6-Digit Code"</div>
                        <form on:submit=on_email_start>
                            <div class="u-field">
                                <label class="u-label" for="le-email-input">"Email address"</label>
                                <input
                                    id="le-email-input"
                                    type="email"
                                    class="u-input"
                                    placeholder="you@example.com"
                                    required=true
                                    prop:value=move || email_input.get()
                                    on:input=move |ev| email_input.set(event_target_value(&ev))
                                />
                            </div>
                            <button type="submit" class="u-btn u-btn--secondary u-btn--full" disabled=move || busy.get()>
                                "Send sign-in link & code"
                            </button>
                        </form>
                        {move || email_code_sent.get().then(|| view! {
                            <form class="u-stack" on:submit=on_email_verify>
                                <div class="u-field">
                                    <label class="u-label" for="le-otp-input">"6-digit code"</label>
                                    <input
                                        id="le-otp-input"
                                        type="text"
                                        inputmode="numeric"
                                        maxlength="6"
                                        class="u-input"
                                        placeholder="123456"
                                        required=true
                                        prop:value=move || otp_input.get()
                                        on:input=move |ev| otp_input.set(event_target_value(&ev))
                                    />
                                </div>
                                <button type="submit" class="u-btn u-btn--full" disabled=move || busy.get()>
                                    "Verify code & sign in"
                                </button>
                            </form>
                        })}
                    </div>
                })}

                {(has_siwe || has_siws).then(|| view! {
                    <div>
                        <div class="u-divider">"Crypto Wallets"</div>
                        <div class="u-list">
                            {has_siwe.then(|| view! {
                                <button
                                    type="button"
                                    class="u-btn u-btn--secondary u-btn--full"
                                    disabled=move || busy.get()
                                    on:click=on_siwe_login
                                >
                                    "Sign in with Ethereum (SIWE)"
                                </button>
                            })}
                            {has_siws.then(|| view! {
                                <button
                                    type="button"
                                    class="u-btn u-btn--secondary u-btn--full"
                                    disabled=move || busy.get()
                                    on:click=on_siws_login
                                >
                                    "Sign in with Solana (SIWS)"
                                </button>
                            })}
                        </div>

                        <div class="u-divider">"Other Device"</div>
                        <div class="u-stack">
                            {move || match handoff.get() {
                                None => view! {
                                    <button
                                        type="button"
                                        class="u-btn u-btn--secondary u-btn--full"
                                        disabled=move || busy.get()
                                        on:click=on_start_handoff
                                    >
                                        "Sign in with mobile wallet QR code"
                                    </button>
                                }.into_any(),
                                Some(h) => {
                                    let svg = h.qr.as_ref().map(|q| q.to_svg()).unwrap_or_default();
                                    let code = h.verify_code.clone();
                                    view! {
                                        <div class="u-qr-box">
                                            <div class="u-qr-svg" inner_html=svg />
                                            <div class="u-verify-code">{code}</div>
                                            <p class="u-sub">"Scan with your phone and verify this code matches."</p>
                                            <button
                                                type="button"
                                                class="u-btn u-btn--secondary u-btn--small"
                                                on:click=move |_| {
                                                    handoff_polling.set(false);
                                                    handoff.set(None);
                                                }
                                            >
                                                "Cancel"
                                            </button>
                                        </div>
                                    }.into_any()
                                }
                            }}

                            <form on:submit=on_claim_transfer class="u-row">
                                <input
                                    type="text"
                                    class="u-input"
                                    style="flex: 1;"
                                    placeholder="8-character transfer code (e.g. ABCD-EFGH)"
                                    prop:value=move || transfer_code.get()
                                    on:input=move |ev| transfer_code.set(event_target_value(&ev))
                                />
                                <button type="submit" class="u-btn u-btn--secondary" disabled=move || busy.get()>
                                    "Claim"
                                </button>
                            </form>
                        </div>
                    </div>
                })}
            </div>
        }
    };

    view! {
        <div class="u-shell u-shell--narrow">
            <FloatingHeader
                variant=HeaderVariant::Nav
                left=move || view! {
                    <nav class="u-nav-links">
                        <a class="u-nav-link" href="/">"Gallery"</a>
                        <a class="u-nav-link is-active" href="/user/login">"Sign in"</a>
                    </nav>
                }.into_any()
                right=move || view! {
                    <a class="u-nav-link" href="/terms">"Terms"</a>
                }.into_any()
            />

            <div class="u-stack">
                {extra_header.map(|f| f.run())}

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
                        tone=NoticeTone::Info
                        dismissible=true
                        on_dismiss=Callback::new(move |_| info_msg.set(None))
                    />
                })}

                <section class="u-card">
                    <h1>{heading}</h1>
                    <p class="u-sub">{intro}</p>
                    {move || match boot.get() {
                        None => view! { <p class="u-sub">"Loading available sign-in methods..."</p> }.into_any(),
                        Some(b) => render_providers(b).into_any(),
                    }}
                </section>
            </div>
        </div>
    }
}
