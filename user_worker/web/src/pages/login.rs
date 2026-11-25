//! `/user/login` — Multi-provider login SPA supporting OIDC Age Assurance,
//! Google, GitHub, X, Discord, Email Magic Link/OTP, Telegram, SIWE, SIWS,
//! cross-device QR handoff, and transfer code claiming.

use leptos::{ev, prelude::*, task::spawn_local};
use lets_embed_ui::{NoticeBanner, NoticeContent, NoticeTone, use_toast_store};
use serde_json::json;
use site_access::{AgeVerificationPolicy, AuthProviderId, AuthProviderPublicConfig};

use crate::{
    api::{
        self, BootstrapResp, EmailStartResp, EmailVerifyResp, HandoffPollResp, HandoffStartResp,
        NonceResp, TelegramStartResp,
    },
    wallet,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum CrossDeviceTab {
    Closed,
    Qr,
    Transfer,
}

fn provider_slug(id: AuthProviderId) -> &'static str {
    id.as_str()
}

fn default_provider_label(id: AuthProviderId) -> &'static str {
    match id {
        AuthProviderId::OidcAgeAssurance => "18+ Verified Identity",
        AuthProviderId::Google => "Google",
        AuthProviderId::GitHub => "GitHub",
        AuthProviderId::X => "X",
        AuthProviderId::Discord => "Discord",
        AuthProviderId::EmailOtp => "Email Code / Magic Link",
        AuthProviderId::Telegram => "Telegram",
        AuthProviderId::Siwe => "Ethereum",
        AuthProviderId::Siws => "Solana",
    }
}

fn provider_btn_class(id: AuthProviderId) -> &'static str {
    match id {
        AuthProviderId::OidcAgeAssurance => "u-provider-btn u-provider-btn--oidc",
        AuthProviderId::Google => "u-provider-btn u-provider-btn--google",
        AuthProviderId::GitHub => "u-provider-btn u-provider-btn--github",
        AuthProviderId::X => "u-provider-btn u-provider-btn--x",
        AuthProviderId::Discord => "u-provider-btn u-provider-btn--discord",
        _ => "u-provider-btn",
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

fn render_provider_icon(id: AuthProviderId) -> AnyView {
    match id {
        AuthProviderId::Google => view! {
            <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
                <path fill="#4285F4" d="M23.49 12.27c0-.79-.07-1.54-.2-2.27H12v4.51h6.44a5.51 5.51 0 0 1-2.39 3.62v3h3.87c2.26-2.08 3.57-5.15 3.57-8.86z"/>
                <path fill="#34A853" d="M12 24c3.24 0 5.95-1.07 7.93-2.9l-3.87-3c-1.07.72-2.44 1.15-4.06 1.15-3.12 0-5.77-2.11-6.72-4.95H1.29v3.1A12 12 0 0 0 12 24z"/>
                <path fill="#FBBC05" d="M5.28 14.3a7.18 7.18 0 0 1 0-4.6V6.6H1.29a12 12 0 0 0 0 10.8l3.99-3.1z"/>
                <path fill="#EA4335" d="M12 4.75c1.76 0 3.34.61 4.58 1.8l3.44-3.44C17.95 1.19 15.24 0 12 0A12 12 0 0 0 1.29 6.6l3.99 3.1c.95-2.84 3.6-4.95 6.72-4.95z"/>
            </svg>
        }
        .into_any(),
        AuthProviderId::GitHub => view! {
            <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" aria-hidden="true">
                <path d="M12 .5A11.5 11.5 0 0 0 .5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.55 0-.27-.01-1-.02-1.96-3.2.7-3.87-1.54-3.87-1.54-.52-1.33-1.28-1.69-1.28-1.69-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.19 1.76 1.19 1.03 1.76 2.69 1.25 3.35.96.1-.74.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.04 0 0 .97-.31 3.16 1.18a10.95 10.95 0 0 1 5.76 0c2.2-1.49 3.16-1.18 3.16-1.18.63 1.58.23 2.75.11 3.04.74.81 1.19 1.83 1.19 3.09 0 4.42-2.69 5.39-5.26 5.68.41.36.78 1.06.78 2.13 0 1.54-.01 2.78-.01 3.16 0 .31.21.67.8.55A11.5 11.5 0 0 0 23.5 12 11.5 11.5 0 0 0 12 .5z"/>
            </svg>
        }
        .into_any(),
        AuthProviderId::X => view! {
            <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true">
                <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
            </svg>
        }
        .into_any(),
        AuthProviderId::Discord => view! {
            <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" aria-hidden="true">
                <path d="M20.317 4.37a19.79 19.79 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
            </svg>
        }
        .into_any(),
        AuthProviderId::OidcAgeAssurance => view! {
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="m9 12 2 2 4-4"/>
            </svg>
        }
        .into_any(),
        _ => view! {
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="9"/>
                <path d="M9 12h6"/>
            </svg>
        }
        .into_any(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoginCalloutTone {
    Warn,
    Info,
}

fn login_reason_callout(
    reason: Option<&str>,
    next_url: &str,
    has_explicit_next: bool,
) -> Option<(LoginCalloutTone, &'static str, &'static str)> {
    match reason.map(str::trim) {
        Some("free_limit") => Some((
            LoginCalloutTone::Warn,
            "Daily free allowance reached",
            "You\u{2019}ve reached today\u{2019}s free viewing or search limit, or this item isn\u{2019}t covered by anonymous free access. Sign in to continue with your account\u{2019}s points or plan, or come back after 00:00 UTC.",
        )),
        Some("quota") => Some((
            LoginCalloutTone::Warn,
            "Quota or points limit reached",
            "Your current quota or points balance has run out. Sign in to check your balance, subscribe to a plan, or top up points.",
        )),
        Some("login_required") => Some((
            LoginCalloutTone::Info,
            "Sign in required",
            "This gallery requires an account to browse. Sign in below to continue.",
        )),
        Some("session_expired") => Some((
            LoginCalloutTone::Warn,
            "Session expired",
            "Your sign-in session has expired or was signed out. Please sign in again to continue.",
        )),
        Some("auth_required") => Some((
            LoginCalloutTone::Info,
            "Sign in required",
            "Sign in below to access your account, favorites, and saved preferences.",
        )),
        Some("age_confirm") => Some((
            LoginCalloutTone::Info,
            "Age confirmation required",
            "Sign in to confirm you are 18+ and manage age-restricted content settings.",
        )),
        _ if has_explicit_next => {
            if next_url.contains("#age-confirm") {
                Some((
                    LoginCalloutTone::Info,
                    "Age confirmation required",
                    "Sign in to confirm you are 18+ and manage age-restricted content settings.",
                ))
            } else if next_url.starts_with("/user/favorites") {
                Some((
                    LoginCalloutTone::Info,
                    "Sign in to view favorites",
                    "Sign in below to access and manage your saved favorites.",
                ))
            } else if next_url.starts_with("/user/account") {
                Some((
                    LoginCalloutTone::Info,
                    "Sign in to open Account Settings",
                    "Sign in below to manage your balance, subscription, and content preferences.",
                ))
            } else if next_url != "/" {
                Some((
                    LoginCalloutTone::Info,
                    "Sign in to continue",
                    "Sign in below and you\u{2019}ll be returned to the page you were viewing.",
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[component]
pub fn LoginPage() -> impl IntoView {
    view! {
        <LoginView
            heading="Sign in"
            intro="Access your saved favorites, content preferences, and gallery account."
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
    let raw_next = api::current_search_param("next");
    let has_explicit_next = raw_next.is_some();
    let next_url = StoredValue::new(api::sanitize_next(
        raw_next.as_deref().or(Some(default_next)),
    ));
    let reason_callout = if extra_header.is_none() {
        let reason = api::current_search_param("reason");
        login_reason_callout(reason.as_deref(), &next_url.get_value(), has_explicit_next)
    } else {
        None
    };

    let toasts = use_toast_store();
    let boot = RwSignal::new(None::<BootstrapResp>);
    let busy = RwSignal::new(false);

    // Email OTP / Magic link state
    let email_input = RwSignal::new(api::current_search_param("email").unwrap_or_default());
    let otp_input = RwSignal::new(String::new());
    let email_code_sent = RwSignal::new(false);

    // Cross-device drawer state (Mobile QR / Transfer Code)
    let cross_device = RwSignal::new(CrossDeviceTab::Closed);

    // QR Handoff state
    let handoff = RwSignal::new(None::<HandoffStartResp>);
    let handoff_starting = RwSignal::new(false);
    let handoff_polling = RwSignal::new(false);

    // Transfer code state
    let transfer_code = RwSignal::new(String::new());

    // Portable link confirmation states (F13): NEVER silently auto-redeem magic links or
    // `#transfer=` URLs on page load without explicit user confirmation!
    let pending_email_link = RwSignal::new(None::<(String, String)>);
    let pending_transfer_token = RwSignal::new(None::<String>);

    // Initial bootstrap + stage magic link (`?email_token=`) or `#transfer=` for confirmation.
    Effect::new(move |_| {
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            doc.set_title(&format!("{heading} — Let\u{2019}s Embed"));
        }
        if let Some(err) = api::current_search_param("error") {
            toasts.error("Sign-in failed", Some(err));
        }
        if let (Some(email), Some(token)) = (
            api::current_search_param("email"),
            api::current_search_param("email_token"),
        ) && !email.trim().is_empty()
            && !token.trim().is_empty()
        {
            pending_email_link.set(Some((email, token)));
        }
        let hash = api::current_hash();
        if let Some(tok) = hash.strip_prefix("#transfer=").filter(|s| !s.is_empty()) {
            pending_transfer_token.set(Some(tok.to_string()));
        }
        spawn_local(async move {
            match api::get_json::<BootstrapResp>("/user/api/bootstrap").await {
                Ok(b) => {
                    boot.set(Some(b));
                }
                Err(e) => {
                    toasts.error("Could not load sign-in options", Some(e.display()));
                }
            }
        });
    });

    // Confirm magic-link email sign-in explicitly
    let on_confirm_email_link = move |_| {
        let Some((email, token)) = pending_email_link.get_untracked() else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            match api::post_json::<_, EmailVerifyResp>(
                "/user/auth/email/verify",
                &json!({ "email": email, "token": token }),
            )
            .await
            {
                Ok(resp) => {
                    pending_email_link.set(None);
                    api::broadcast_safety_invalidation("account_change");
                    api::navigate_hard(&api::sanitize_next(Some(&resp.next)));
                    return;
                }
                Err(e) => {
                    toasts.error("Email sign-in failed", Some(e.display()));
                }
            }
            busy.set(false);
        });
    };

    // Confirm `#transfer=<token>` sign-in explicitly
    let on_confirm_transfer_link = move |_| {
        let Some(tok) = pending_transfer_token.get_untracked() else {
            return;
        };
        busy.set(true);
        let dest = next_url.get_value();
        spawn_local(async move {
            match api::post_json_empty("/user/api/transfer/claim", &json!({ "token": tok })).await {
                Ok(()) => {
                    pending_transfer_token.set(None);
                    api::broadcast_safety_invalidation("account_change");
                    api::navigate_hard(&dest);
                    return;
                }
                Err(e) => {
                    toasts.error("Transfer claim failed", Some(e.display()));
                }
            }
            busy.set(false);
        });
    };

    // Mount Telegram Login Widget using a browser-bound `state` + `__Host-auth_tx` cookie
    // obtained from `POST /user/auth/telegram/start` (F13).
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
                .map(|s| s.trim().trim_start_matches('@'))
                .filter(|s| !s.is_empty())
        {
            let bot_owned = bot.to_string();
            let dest = next_url.get_value();
            spawn_local(async move {
                match api::post_json::<_, TelegramStartResp>(
                    "/user/auth/telegram/start",
                    &json!({ "next": dest }),
                )
                .await
                {
                    Ok(resp) => {
                        wallet::mount_telegram_widget(
                            "le-telegram-login-mount",
                            &bot_owned,
                            &resp.auth_url,
                        );
                    }
                    Err(e) => {
                        if let Some(el) = web_sys::window()
                            .and_then(|w| w.document())
                            .and_then(|d| d.get_element_by_id("le-telegram-login-mount"))
                        {
                            let _ = el.set_attribute("data-tg-state", "unavailable");
                        }
                        toasts.error("Could not initialize Telegram login", Some(e.display()));
                    }
                }
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
                    toasts.success("Sign-in email sent", Some(resp.message));
                }
                Err(e) => {
                    toasts.error("Could not send email", Some(e.display()));
                }
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
        spawn_local(async move {
            match api::post_json::<_, EmailVerifyResp>(
                "/user/auth/email/verify",
                &json!({ "email": email, "code": code }),
            )
            .await
            {
                Ok(resp) => {
                    api::broadcast_safety_invalidation("account_change");
                    api::navigate_hard(&api::sanitize_next(Some(&resp.next)));
                }
                Err(e) => {
                    toasts.error("Code verification failed", Some(e.display()));
                }
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
        let dest = next_url.get_value();
        spawn_local(async move {
            let nonce_resp = match api::get_json::<NonceResp>("/user/api/nonce?purpose=login").await
            {
                Ok(n) => n,
                Err(e) => {
                    toasts.error("Sign-in failed", Some(e.display()));
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
                        Ok(()) => {
                            api::broadcast_safety_invalidation("account_change");
                            api::navigate_hard(&dest);
                        }
                        Err(e) => {
                            toasts.error("Ethereum sign-in failed", Some(e.display()));
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

    // SIWS sign-in
    let on_siws_login = move |_| {
        let Some(b) = boot.get_untracked() else {
            return;
        };
        busy.set(true);
        let dest = next_url.get_value();
        spawn_local(async move {
            let nonce_resp = match api::get_json::<NonceResp>("/user/api/nonce?purpose=login").await
            {
                Ok(n) => n,
                Err(e) => {
                    toasts.error("Sign-in failed", Some(e.display()));
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
                        Ok(()) => {
                            api::broadcast_safety_invalidation("account_change");
                            api::navigate_hard(&dest);
                        }
                        Err(e) => {
                            toasts.error("Solana sign-in failed", Some(e.display()));
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

    // Start QR handoff & poll
    let start_handoff = Callback::new(move |()| {
        if handoff_starting.get_untracked() || handoff.get_untracked().is_some() {
            return;
        }
        handoff_starting.set(true);
        let dest = next_url.get_value();
        spawn_local(async move {
            match api::post_json::<_, HandoffStartResp>("/user/api/handoff/start", &json!({})).await
            {
                Ok(h) => {
                    let sid = h.session_id.clone();
                    let secret = h.poll_secret.clone();
                    handoff.set(Some(h));
                    handoff_starting.set(false);
                    handoff_polling.set(true);

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
                                api::broadcast_safety_invalidation("account_change");
                                api::navigate_hard(&dest);
                                return;
                            }
                            Ok(resp) if resp.status == "pending" => continue,
                            Ok(_) => {
                                handoff_polling.set(false);
                                handoff.set(None);
                                cross_device.set(CrossDeviceTab::Closed);
                                toasts.warning(
                                    "QR sign-in expired",
                                    Some("Please start a new QR sign-in.".into()),
                                );
                                return;
                            }
                            Err(e) => {
                                handoff_polling.set(false);
                                handoff.set(None);
                                cross_device.set(CrossDeviceTab::Closed);
                                toasts.error("QR handoff failed", Some(e.display()));
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    handoff_starting.set(false);
                    cross_device.set(CrossDeviceTab::Closed);
                    toasts.error("Could not start QR sign-in", Some(e.display()));
                }
            }
        });
    });

    // Claim 8-char transfer code
    let on_claim_transfer = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let code = transfer_code.get_untracked().trim().to_string();
        if code.is_empty() {
            return;
        }
        busy.set(true);
        let dest = next_url.get_value();
        spawn_local(async move {
            match api::post_json_empty("/user/api/transfer/claim", &json!({ "code": code })).await {
                Ok(()) => {
                    api::broadcast_safety_invalidation("account_change");
                    api::navigate_hard(&dest);
                }
                Err(e) => {
                    toasts.error("Transfer code rejected", Some(e.display()));
                }
            }
            busy.set(false);
        });
    };

    let render_providers = move |b: BootstrapResp| {
        let strict_18 = b.policy.age_policy == AgeVerificationPolicy::StrictProviderVerified18;
        let effective: Vec<AuthProviderPublicConfig> = b.policy.effective_login_providers();

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
        let has_wallets = has_siwe || has_siws;
        let has_primary_social = !oauth_list.is_empty() || has_telegram;
        let next_encoded = urlencoding::encode(&next_url.get_value()).into_owned();

        let wallet_grid_cls = if has_siwe && has_siws {
            "u-wallet-grid"
        } else {
            "u-wallet-grid u-wallet-grid--single"
        };
        let alt_actions_cls = if has_wallets {
            "u-alt-actions"
        } else {
            "u-alt-actions u-alt-actions--single"
        };

        view! {
            <div class="u-login-body">
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

                {has_primary_social.then(|| view! {
                    <div class="u-provider-list">
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
                            let btn_cls = provider_btn_class(p.id);
                            let icon = render_provider_icon(p.id);
                            view! {
                                <a class=btn_cls href=href>
                                    <span class="u-provider-icon">{icon}</span>
                                    <span class="u-provider-label">
                                        {format!("Continue with {label}")}
                                        {is_verified.then(|| view! {
                                            <span class="u-badge u-badge--ok">"18+"</span>
                                        })}
                                    </span>
                                    <svg class="u-provider-chevron" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                        <path d="m7.5 5 5 5-5 5"/>
                                    </svg>
                                </a>
                            }
                        }).collect_view()}

                        {has_telegram.then(|| view! {
                            <div class="u-login-tg-slot">
                                <div id="le-telegram-login-mount" class="u-login-tg-mount" data-tg-state="loading"></div>
                            </div>
                        })}
                    </div>
                })}

                {has_email.then(|| view! {
                    <div>
                        {has_primary_social.then(|| view! {
                            <div class="u-login-divider">"or with email"</div>
                        })}
                        <form class="u-login-email-form" on:submit=on_email_start>
                            <div class="u-field" style="margin-bottom: 0;">
                                <label class="u-label" for="le-email-input">"Email address"</label>
                                <div class="u-input-wrap">
                                    <svg class="u-input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                        <rect x="2" y="4" width="20" height="16" rx="2"/>
                                        <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
                                    </svg>
                                    <input
                                        id="le-email-input"
                                        type="email"
                                        class="u-input u-input--with-icon"
                                        placeholder="you@example.com"
                                        autocomplete="email"
                                        required=true
                                        prop:value=move || email_input.get()
                                        on:input=move |ev| email_input.set(event_target_value(&ev))
                                    />
                                </div>
                            </div>
                            <button type="submit" class="u-btn u-btn--gradient u-btn--full" disabled=move || busy.get()>
                                "Send sign-in link & code"
                            </button>
                        </form>
                        {move || email_code_sent.get().then(|| view! {
                            <form class="u-login-drawer" style="margin-top: 12px;" on:submit=on_email_verify>
                                <div class="u-field" style="margin-bottom: 0;">
                                    <label class="u-label" for="le-otp-input">"Enter 6-digit verification code"</label>
                                    <input
                                        id="le-otp-input"
                                        type="text"
                                        inputmode="numeric"
                                        maxlength="6"
                                        class="u-input u-input--code"
                                        placeholder="123456"
                                        autocomplete="one-time-code"
                                        required=true
                                        prop:value=move || otp_input.get()
                                        on:input=move |ev| otp_input.set(event_target_value(&ev))
                                    />
                                </div>
                                <button type="submit" class="u-btn u-btn--gradient u-btn--full" disabled=move || busy.get()>
                                    "Verify code & sign in"
                                </button>
                            </form>
                        })}
                    </div>
                })}

                {has_wallets.then(|| view! {
                    <div>
                        {(has_primary_social || has_email).then(|| view! {
                            <div class="u-login-divider">"Web3 Wallets"</div>
                        })}
                        <div class=wallet_grid_cls style="margin-top: 10px;">
                            {has_siwe.then(|| view! {
                                <button
                                    type="button"
                                    class="u-wallet-btn"
                                    disabled=move || busy.get()
                                    on:click=on_siwe_login
                                >
                                    <span class="u-wallet-chip u-wallet-chip--eth" aria-hidden="true">
                                        <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
                                            <path d="M12 2 5.5 12.2 12 16l6.5-3.8L12 2zm0 15.6L5.5 13.8 12 22l6.5-8.2L12 17.6z"/>
                                        </svg>
                                    </span>
                                    <span class="u-wallet-meta">
                                        <span class="u-wallet-name">"Ethereum"</span>
                                        <span class="u-wallet-tag">"Sign in (SIWE)"</span>
                                    </span>
                                </button>
                            })}
                            {has_siws.then(|| view! {
                                <button
                                    type="button"
                                    class="u-wallet-btn"
                                    disabled=move || busy.get()
                                    on:click=on_siws_login
                                >
                                    <span class="u-wallet-chip u-wallet-chip--sol" aria-hidden="true">
                                        <svg viewBox="0 0 24 24" width="18" height="18" fill="none">
                                            <path d="M5.5 7.5h11.8l1.7-2H7.2l-1.7 2z" fill="#9945FF"/>
                                            <path d="M18.5 13H6.7L5 11h11.8l1.7 2z" fill="#2DD4BF"/>
                                            <path d="M5.5 18.5h11.8l1.7-2H7.2l-1.7 2z" fill="#14F195"/>
                                        </svg>
                                    </span>
                                    <span class="u-wallet-meta">
                                        <span class="u-wallet-name">"Solana"</span>
                                        <span class="u-wallet-tag">"Sign in (SIWS)"</span>
                                    </span>
                                </button>
                            })}
                        </div>
                    </div>
                })}

                {(!effective.is_empty()).then(|| view! {
                    <div class="u-alt-section">
                        <div class="u-alt-heading">"Signing in from another device?"</div>
                        <div class=alt_actions_cls>
                            {has_wallets.then(|| view! {
                                <button
                                    type="button"
                                    class=move || if cross_device.get() == CrossDeviceTab::Qr {
                                        "u-alt-pill is-active"
                                    } else {
                                        "u-alt-pill"
                                    }
                                    disabled=move || busy.get()
                                    on:click=move |_| {
                                        if cross_device.get_untracked() == CrossDeviceTab::Qr {
                                            handoff_polling.set(false);
                                            handoff.set(None);
                                            cross_device.set(CrossDeviceTab::Closed);
                                        } else {
                                            cross_device.set(CrossDeviceTab::Qr);
                                            start_handoff.run(());
                                        }
                                    }
                                >
                                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                        <rect x="3" y="3" width="7" height="7" rx="1"/>
                                        <rect x="14" y="3" width="7" height="7" rx="1"/>
                                        <rect x="3" y="14" width="7" height="7" rx="1"/>
                                        <path d="M14 14h3v3h-3zm4 4h3v3h-3zm-4 2h2m4-6h1"/>
                                    </svg>
                                    "Mobile Wallet QR"
                                </button>
                            })}
                            <button
                                type="button"
                                class=move || if cross_device.get() == CrossDeviceTab::Transfer {
                                    "u-alt-pill is-active"
                                } else {
                                    "u-alt-pill"
                                }
                                disabled=move || busy.get()
                                on:click=move |_| {
                                    if cross_device.get_untracked() == CrossDeviceTab::Transfer {
                                        cross_device.set(CrossDeviceTab::Closed);
                                    } else {
                                        handoff_polling.set(false);
                                        handoff.set(None);
                                        cross_device.set(CrossDeviceTab::Transfer);
                                    }
                                }
                            >
                                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                    <path d="M17 1l4 4-4 4"/>
                                    <path d="M3 11V9a4 4 0 0 1 4-4h14"/>
                                    <path d="M7 23l-4-4 4-4"/>
                                    <path d="M21 13v2a4 4 0 0 1-4 4H3"/>
                                </svg>
                                "Transfer Code"
                            </button>
                        </div>

                        {move || match cross_device.get() {
                            CrossDeviceTab::Closed => ().into_any(),
                            CrossDeviceTab::Qr => view! {
                                <div class="u-login-drawer">
                                    <div class="u-login-drawer-head">
                                        <h3 class="u-login-drawer-title">"Mobile wallet QR sign-in"</h3>
                                        <button
                                            type="button"
                                            class="u-btn u-btn--secondary u-btn--small"
                                            on:click=move |_| {
                                                handoff_polling.set(false);
                                                handoff.set(None);
                                                cross_device.set(CrossDeviceTab::Closed);
                                            }
                                        >
                                            "Cancel"
                                        </button>
                                    </div>
                                    {move || match handoff.get() {
                                        None => view! {
                                            <div class="u-login-qr-frame">
                                                <span class="u-login-qr-status">
                                                    <span class="u-login-pulse-dot"></span>
                                                    "Generating QR code\u{2026}"
                                                </span>
                                            </div>
                                        }.into_any(),
                                        Some(h) => {
                                            let svg = h.qr.as_ref().map(|q| q.to_svg()).unwrap_or_default();
                                            let code = h.verify_code.clone();
                                            view! {
                                                <div class="u-login-qr-frame">
                                                    <div class="u-qr-svg" inner_html=svg />
                                                    <div class="u-verify-code">{code}</div>
                                                    <span class="u-login-qr-status">
                                                        <span class="u-login-pulse-dot"></span>
                                                        "Scan on mobile and confirm this code"
                                                    </span>
                                                </div>
                                            }.into_any()
                                        }
                                    }}
                                </div>
                            }.into_any(),
                            CrossDeviceTab::Transfer => view! {
                                <form class="u-login-drawer" on:submit=on_claim_transfer>
                                    <div>
                                        <h3 class="u-login-drawer-title">"Device transfer code"</h3>
                                        <p class="u-login-drawer-desc">
                                            "Enter the 8-character code created from Account Settings on your signed-in device."
                                        </p>
                                    </div>
                                    <div class="u-login-transfer-row">
                                        <input
                                            type="text"
                                            class="u-input u-input--code"
                                            placeholder="ABCD-EFGH"
                                            autocomplete="off"
                                            spellcheck="false"
                                            prop:value=move || transfer_code.get()
                                            on:input=move |ev| transfer_code.set(event_target_value(&ev))
                                        />
                                        <button
                                            type="submit"
                                            class="u-btn u-btn--gradient"
                                            disabled=move || busy.get()
                                        >
                                            "Claim"
                                        </button>
                                    </div>
                                </form>
                            }.into_any(),
                        }}
                    </div>
                })}
            </div>
        }
    };

    view! {
        <div class="u-login-page">
            <header class="u-login-topbar">
                <a class="u-login-brand" href="/">"Let\u{2019}s Embed \u{2728}"</a>
                <a class="u-login-back" href="/">
                    <svg viewBox="0 0 20 20" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M12.5 15 7.5 10l5-5"/>
                    </svg>
                    "Gallery"
                </a>
            </header>

            <main class="u-login-main">
                {extra_header.map(|f| move || f.run())}

                {reason_callout.map(|(tone, title, message)| {
                    let cls = match tone {
                        LoginCalloutTone::Warn => "u-login-callout u-login-callout--warn",
                        LoginCalloutTone::Info => "u-login-callout u-login-callout--info",
                    };
                    let icon = match tone {
                        LoginCalloutTone::Warn => view! {
                            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                                <line x1="12" y1="9" x2="12" y2="13"/>
                                <line x1="12" y1="17" x2="12.01" y2="17"/>
                            </svg>
                        }.into_any(),
                        LoginCalloutTone::Info => view! {
                            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                <circle cx="12" cy="12" r="10"/>
                                <line x1="12" y1="16" x2="12" y2="12"/>
                                <line x1="12" y1="8" x2="12.01" y2="8"/>
                            </svg>
                        }.into_any(),
                    };
                    view! {
                        <aside class=cls role="status" aria-live="polite">
                            <span class="u-login-callout-icon">{icon}</span>
                            <div class="u-login-callout-body">
                                <strong class="u-login-callout-title">{title}</strong>
                                <p class="u-login-callout-text">{message}</p>
                            </div>
                        </aside>
                    }
                })}

                {move || pending_email_link.get().map(|(email, _)| view! {
                    <section class="u-login-card u-login-card--confirm">
                        <h2>"Confirm email sign-in"</h2>
                        <p class="u-sub">
                            {format!(
                                "You opened a one-time sign-in link for {email}. Confirm below only if you requested this link yourself — signing in will switch this browser to that account."
                            )}
                        </p>
                        <div class="u-row">
                            <button
                                type="button"
                                class="u-btn u-btn--gradient"
                                disabled=move || busy.get()
                                on:click=on_confirm_email_link
                            >
                                {format!("Continue as {email}")}
                            </button>
                            <button
                                type="button"
                                class="u-btn u-btn--secondary"
                                disabled=move || busy.get()
                                on:click=move |_| {
                                    pending_email_link.set(None);
                                    if let Some(w) = web_sys::window()
                                        && let Ok(h) = w.history()
                                    {
                                        let _ = h.replace_state_with_url(
                                            &wasm_bindgen::JsValue::NULL,
                                            "",
                                            Some("/user/login"),
                                        );
                                    }
                                }
                            >
                                "Cancel"
                            </button>
                        </div>
                    </section>
                })}

                {move || pending_transfer_token.get().map(|_| view! {
                    <section class="u-login-card u-login-card--confirm">
                        <h2>"Confirm device transfer sign-in"</h2>
                        <p class="u-sub">
                            "You opened a cross-device sign-in transfer link. Confirm below only if you generated this QR code on your own signed-in device — claiming it will switch this browser to that account."
                        </p>
                        <div class="u-row">
                            <button
                                type="button"
                                class="u-btn u-btn--gradient"
                                disabled=move || busy.get()
                                on:click=on_confirm_transfer_link
                            >
                                "Continue & Sign In"
                            </button>
                            <button
                                type="button"
                                class="u-btn u-btn--secondary"
                                disabled=move || busy.get()
                                on:click=move |_| {
                                    pending_transfer_token.set(None);
                                    if let Some(w) = web_sys::window()
                                        && let Ok(h) = w.history()
                                    {
                                        let _ = h.replace_state_with_url(
                                            &wasm_bindgen::JsValue::NULL,
                                            "",
                                            Some("/user/login"),
                                        );
                                    }
                                }
                            >
                                "Cancel"
                            </button>
                        </div>
                    </section>
                })}

                <section class="u-login-card">
                    <div class="u-login-hero">
                        <div class="u-login-emblem" aria-hidden="true">
                            <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M12 3 4 7.5v9L12 21l8-4.5v-9L12 3z"/>
                                <path d="m12 12 8-4.5M12 12v9M12 12 4 7.5"/>
                            </svg>
                        </div>
                        <h1 class="u-login-title">{heading}</h1>
                        <p class="u-login-subtitle">{intro}</p>
                    </div>

                    {move || match boot.get() {
                        None => view! {
                            <div class="u-login-skeleton" aria-label="Loading available sign-in methods">
                                <div class="u-login-skeleton-bar"></div>
                                <div class="u-login-skeleton-bar"></div>
                                <div class="u-login-skeleton-bar u-login-skeleton-bar--short"></div>
                            </div>
                        }.into_any(),
                        Some(b) => render_providers(b).into_any(),
                    }}
                </section>
            </main>

            <footer class="u-login-footer">
                <a href="/terms">"Terms"</a>
                <span class="u-login-footer-sep">"\u{00B7}"</span>
                <a href="/privacy">"Privacy"</a>
                <span class="u-login-footer-sep">"\u{00B7}"</span>
                <a href="/content-policy">"Content Policy"</a>
            </footer>
        </div>
    }
}
