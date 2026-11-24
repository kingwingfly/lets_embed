//! Auth Providers tab:
//! - Minimal, per-provider configuration showing only fields each provider actually uses
//! - Zero-config toggle-only cards for Ethereum (SIWE) and Solana (SIWS)
//! - Copyable OAuth / OIDC callback URLs for Google, GitHub, X, Discord, and Age-Assurance OIDC
//! - Inline setup hints (Telegram `@BotFather /setdomain`, Email OTP Resend default, OIDC Strict 18+)
//! - Masked write-only secrets encrypted via AES-256-GCM (HKDF-SHA256 from `SITE_SECRET`)
//! - Zero-downtime AES-256-GCM key rotation (`POST /admin/api/secrets/rotate`)
//! - Root-level persistent draft (`AdminDraftStore`) + GCP top-right toasts via `use_toast_store()`

use leptos::prelude::*;
use lets_embed_ui::{NoticeBanner, NoticeContent, NoticeTone, ToggleSwitch, use_toast_store};
use site_access::{AgeVerificationPolicy, AuthProviderId};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::{
    api::{
        ActivationResult, ProviderUpdateItem, ProvidersResp, RotateSecretsResp, SaveProvidersReq,
        SaveProvidersResp, copy_text_to_clipboard, format_ts_utc, get_json, post_json,
        post_json_activatable,
    },
    drafts::use_admin_drafts,
};

fn has_oauth_callback(id: AuthProviderId) -> bool {
    matches!(
        id,
        AuthProviderId::Google
            | AuthProviderId::GitHub
            | AuthProviderId::X
            | AuthProviderId::Discord
            | AuthProviderId::OidcAgeAssurance
    )
}

fn client_id_field(id: AuthProviderId) -> Option<(&'static str, &'static str)> {
    match id {
        AuthProviderId::Google => Some((
            "OAuth Client ID (public)",
            "1234567890-xxxx.apps.googleusercontent.com",
        )),
        AuthProviderId::GitHub => Some(("OAuth Client ID (public)", "Ov23li...")),
        AuthProviderId::X => Some(("OAuth 2.0 Client ID (public)", "X Client ID")),
        AuthProviderId::Discord => Some(("Application / Client ID (public)", "123456789012345678")),
        AuthProviderId::Telegram => Some(("Bot Username (public, without @)", "my_gallery_bot")),
        AuthProviderId::EmailOtp => Some(("Sender Email / From Address", "noreply@your-domain.com")),
        AuthProviderId::OidcAgeAssurance => Some(("OIDC Client ID (public)", "your-oidc-client-id")),
        AuthProviderId::Siwe | AuthProviderId::Siws => None,
    }
}

fn issuer_field(id: AuthProviderId) -> Option<(&'static str, &'static str)> {
    match id {
        AuthProviderId::OidcAgeAssurance => Some((
            "OIDC Issuer URL (https:// required, SSRF validated)",
            "https://oidc.provider.example.com",
        )),
        AuthProviderId::EmailOtp => Some((
            "Mail API Endpoint (optional — defaults to Resend)",
            "https://api.resend.com/emails",
        )),
        _ => None,
    }
}

fn secret_label(id: AuthProviderId, field_name: &str) -> String {
    match id {
        AuthProviderId::Telegram => format!("Bot Token ({field_name})"),
        AuthProviderId::EmailOtp => format!("Mail API Key ({field_name})"),
        _ => format!("Client Secret ({field_name})"),
    }
}

fn provider_sort_rank(id: AuthProviderId, strict_mode: bool) -> u8 {
    match id {
        AuthProviderId::OidcAgeAssurance => {
            if strict_mode {
                0
            } else {
                90
            }
        }
        AuthProviderId::Google => 10,
        AuthProviderId::GitHub => 20,
        AuthProviderId::Discord => 30,
        AuthProviderId::X => 40,
        AuthProviderId::EmailOtp => 50,
        AuthProviderId::Telegram => 60,
        AuthProviderId::Siwe => 70,
        AuthProviderId::Siws => 80,
    }
}

fn effective_public_origin(server_origin: &str) -> String {
    let trimmed = server_origin.trim().trim_end_matches('/');
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .map(|o| o.trim_end_matches('/').to_string())
        .unwrap_or_default()
}

fn host_from_origin(origin: &str) -> String {
    let stripped = origin
        .trim()
        .strip_prefix("https://")
        .or_else(|| origin.trim().strip_prefix("http://"))
        .unwrap_or(origin.trim());
    let host = stripped.split('/').next().unwrap_or("").trim();
    if host.is_empty() {
        "your-domain.com".to_string()
    } else {
        host.to_string()
    }
}

fn provider_summary(id: AuthProviderId) -> &'static str {
    match id {
        AuthProviderId::Google => "Sign in with Google OAuth 2.0 / OIDC (PKCE + ID token verification).",
        AuthProviderId::GitHub => "Sign in with GitHub OAuth App (minimal read:user scope).",
        AuthProviderId::X => "Sign in with X OAuth 2.0 Confidential Client (PKCE S256).",
        AuthProviderId::Discord => "Sign in with Discord OAuth2 API v10 (minimal identify scope).",
        AuthProviderId::Telegram => "Sign in with the official Telegram Login Widget (HMAC-SHA256 verified).",
        AuthProviderId::EmailOtp => "Passwordless 6-digit OTP & one-time magic link via a 3rd-party HTTP mail API (Resend by default).",
        AuthProviderId::Siwe => "Zero-config Ethereum wallet sign-in (MetaMask, Rabby, Coinbase Wallet) via EIP-4361 signatures.",
        AuthProviderId::Siws => "Zero-config Solana wallet sign-in (Phantom, Solflare, Backpack) via Ed25519 signatures.",
        AuthProviderId::OidcAgeAssurance => "Advanced / B2B: third-party verified 18+ identity via OIDC / OIDC4IDA. Only required for Strict Provider-Verified 18+ mode.",
    }
}

struct SetupGuide {
    portal_label: Option<&'static str>,
    portal_url: Option<&'static str>,
    steps: Vec<String>,
    note: Option<String>,
}

fn provider_setup_guide(id: AuthProviderId, origin: &str, host: &str) -> SetupGuide {
    let cb = format!("{origin}/user/auth/{}/callback", id.as_str());
    match id {
        AuthProviderId::Google => SetupGuide {
            portal_label: Some("Open Google Cloud Credentials"),
            portal_url: Some("https://console.cloud.google.com/apis/credentials"),
            steps: vec![
                "In Google Cloud Console, open APIs & Services → OAuth consent screen, choose External, and fill in your app name & support email.".to_string(),
                "Go to Credentials → Create Credentials → OAuth client ID → Application type: Web application.".to_string(),
                format!("Under Authorized redirect URIs, add {cb} and click Create."),
                "Paste the Client ID and Client Secret below, toggle Enabled ON, and click Save Auth Providers.".to_string(),
            ],
            note: Some(
                "Only needed if you turn on Optional soft birthday pre-check: enable the Google People API and add the user.birthday.read scope on your OAuth consent screen.".to_string(),
            ),
        },
        AuthProviderId::GitHub => SetupGuide {
            portal_label: Some("Open GitHub OAuth Apps"),
            portal_url: Some("https://github.com/settings/developers"),
            steps: vec![
                "Open GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.".to_string(),
                format!("Set Homepage URL to {origin} and Authorization callback URL to {cb}."),
                "Click Register application, then click Generate a new client secret.".to_string(),
                "Paste the Client ID and Client Secret below, toggle Enabled ON, and click Save Auth Providers.".to_string(),
            ],
            note: Some(
                "Requests only the read:user scope and identifies users by their immutable numeric GitHub user ID.".to_string(),
            ),
        },
        AuthProviderId::Discord => SetupGuide {
            portal_label: Some("Open Discord Developer Portal"),
            portal_url: Some("https://discord.com/developers/applications"),
            steps: vec![
                "In the Discord Developer Portal, click New Application and open it.".to_string(),
                format!("Go to OAuth2 → Redirects, add {cb}, and click Save Changes."),
                "On the same OAuth2 page, copy the Client ID and click Reset Secret to generate your Client Secret.".to_string(),
                "Paste both below, toggle Enabled ON, and click Save Auth Providers.".to_string(),
            ],
            note: Some(
                "Requests only the identify scope via Discord API v10 and identifies users by their immutable Snowflake ID.".to_string(),
            ),
        },
        AuthProviderId::X => SetupGuide {
            portal_label: Some("Open X Developer Portal"),
            portal_url: Some("https://developer.x.com/en/portal/dashboard"),
            steps: vec![
                "In the X Developer Portal, select your Project & App and open User authentication settings → Set up.".to_string(),
                "Enable OAuth 2.0, set App permissions to Read, and choose Type of App: Web App, Automated App or Bot (Confidential client).".to_string(),
                format!("Set Callback URI / Redirect URL to {cb} and Website URL to {origin}, then save."),
                "Copy the OAuth 2.0 Client ID and Client Secret (not the legacy API Key / Consumer Secret), paste below, enable X, and click Save Auth Providers.".to_string(),
            ],
            note: Some(
                "PKCE S256 and RFC 6749 HTTP Basic authentication are handled automatically by user_worker.".to_string(),
            ),
        },
        AuthProviderId::EmailOtp => SetupGuide {
            portal_label: Some("Open Resend Dashboard"),
            portal_url: Some("https://resend.com/domains"),
            steps: vec![
                "Create a Resend account (free tier: 3,000 emails/mo) — or use any HTTPS mail API/relay that accepts Resend's JSON format.".to_string(),
                format!("Add your sending domain (e.g. {host} or mail.{host}) and publish its DKIM, SPF, and MX records in Cloudflare DNS (gray cloud / DNS-only) until Verified."),
                "Create an API key with Sending access (re_...) for that domain.".to_string(),
                format!("Enter Sender Email (e.g. noreply@{host}), paste the Mail API Key below, leave Mail API Endpoint blank for Resend, toggle Enabled ON, and click Save Auth Providers."),
            ],
            note: Some(
                "Cloudflare Email Routing is inbound/forwarding-only and cannot deliver OTP emails to arbitrary users. Custom Mail API Endpoints must accept POST JSON { from, to, subject, text } with Authorization: Bearer <api_key>.".to_string(),
            ),
        },
        AuthProviderId::Telegram => SetupGuide {
            portal_label: Some("Open @BotFather"),
            portal_url: Some("https://t.me/BotFather"),
            steps: vec![
                "Open @BotFather in Telegram, send /newbot, pick a display name and a username ending in 'bot', and copy the HTTP API token.".to_string(),
                format!("Required: in @BotFather, send /setdomain, choose your bot, and send {host} (exact public HTTPS hostname — no https://, no path; localhost will not work)."),
                "Enter the Bot Username (public — loads Telegram's login button in the browser) and paste the Bot Token (secret — stays encrypted server-side to verify Telegram's HMAC-SHA256 signature).".to_string(),
                "Toggle Enabled ON and click Save Auth Providers.".to_string(),
            ],
            note: Some(
                "Leading '@' is stripped automatically. Telegram login replays are blocked atomically for 5 minutes via AuthChallengeDO.".to_string(),
            ),
        },
        AuthProviderId::Siwe => SetupGuide {
            portal_label: None,
            portal_url: None,
            steps: vec![
                "No external developer account, client ID, or API secret is required.".to_string(),
                format!("Verify SIWE_DOMAIN ({host}) and CHAIN_ID in user_worker/wrangler.toml match your live site."),
                "Toggle Enabled ON above and click Save Auth Providers. Visitors can immediately sign in with MetaMask, Rabby, Coinbase Wallet, or mobile wallet QR handoff.".to_string(),
            ],
            note: None,
        },
        AuthProviderId::Siws => SetupGuide {
            portal_label: None,
            portal_url: None,
            steps: vec![
                "No external developer account, client ID, or API secret is required.".to_string(),
                format!("Verify SIWE_DOMAIN ({host}) in user_worker/wrangler.toml matches your live site."),
                "Toggle Enabled ON above and click Save Auth Providers. Visitors can immediately sign in with Phantom, Solflare, Backpack, or mobile wallet QR handoff.".to_string(),
            ],
            note: None,
        },
        AuthProviderId::OidcAgeAssurance => SetupGuide {
            portal_label: None,
            portal_url: None,
            steps: vec![
                "Only needed if you set Age & Legal → Age Verification Policy to Strict Provider-Verified 18+. For Self-Attestation or Off, leave this disabled.".to_string(),
                "Obtain an OIDC / OIDC4IDA client from a certified age-assurance vendor (e.g. Yoti, Signicat, Idura) or a self-hosted OIDC broker that emits verified age_over_18 / verified_claims with acr or amr provenance.".to_string(),
                format!("Register {cb} as the Authorized Redirect URI in the vendor portal (Authorization Code + PKCE S256 + OIDC nonce)."),
                "Fill in the OIDC Issuer URL (must serve /.well-known/openid-configuration over public HTTPS), Client ID, Client Secret, and an optional Button Label (e.g. 'Verify 18+ with Yoti'), then toggle Enabled ON and click Save Auth Providers.".to_string(),
            ],
            note: Some(
                "Optional hardening: set OIDC_AGE_REQUIRED_ACR or OIDC_AGE_REQUIRED_AMR in user_worker environment variables to require a specific assurance level.".to_string(),
            ),
        },
    }
}

#[component]
pub fn ProvidersTab(
    refresh_epoch: RwSignal<u32>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let toasts = use_toast_store();
    let draft = use_admin_drafts().providers;

    let loading = RwSignal::new(false);
    let saving = RwSignal::new(false);
    let rotating = RwSignal::new(false);

    let fetch_providers = move |force_hydrate: bool| {
        loading.set(true);
        spawn_local(async move {
            match get_json::<ProvidersResp>("/admin/api/providers").await {
                Ok(resp) => {
                    if force_hydrate || !draft.dirty.get_untracked() {
                        draft.hydrate(&resp);
                        if force_hydrate {
                            draft.dirty.set(false);
                        }
                    } else {
                        draft.sync_server_metadata(&resp);
                    }
                }
                Err(err) => {
                    toasts.error("Failed to load auth providers", Some(err));
                }
            }
            loading.set(false);
        });
    };

    // Hydrate once on first mount; switching back to this tab preserves unsaved edits.
    // Re-sync metadata whenever another tab saves (via `refresh_epoch`).
    Effect::new(move |prev_epoch: Option<u32>| {
        let cur_epoch = refresh_epoch.get();
        if !draft.loaded.get_untracked() || prev_epoch.is_some_and(|p| p != cur_epoch) {
            fetch_providers(false);
        }
        cur_epoch
    });

    let ordered_rows = move || {
        let strict = draft.age_policy.get() == AgeVerificationPolicy::StrictProviderVerified18;
        let mut rows = draft.rows.get();
        rows.sort_by_key(|p| provider_sort_rank(p.id, strict));
        rows
    };

    let on_discard = move |_| {
        if let Some(snap) = draft.server_snapshot.get_untracked() {
            draft.hydrate(&snap);
            draft.dirty.set(false);
            toasts.info("Discarded unsaved Auth Providers changes", None);
        } else {
            fetch_providers(true);
        }
    };

    let on_save = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if saving.get_untracked() {
            return;
        }
        saving.set(true);

        let age_policy = draft.age_policy.get_untracked();
        let providers: Vec<ProviderUpdateItem> = draft
            .rows
            .get_untracked()
            .iter()
            .map(|row| row.to_update(age_policy))
            .collect();
        let req = SaveProvidersReq {
            revision: draft.revision.get_untracked(),
            providers,
        };

        spawn_local(async move {
            match post_json_activatable::<_, SaveProvidersResp>("/admin/api/providers", &req).await
            {
                Ok(ActivationResult::Active(resp)) => {
                    draft.dirty.set(false);
                    if resp.unchanged {
                        draft.revision.set(resp.revision);
                        toasts.info(format!("No changes to save (rev #{})", resp.revision), None);
                    } else {
                        draft.hydrate(&resp);
                        toasts.success(
                            format!("Saved Auth Providers rev #{}", resp.revision),
                            Some(
                                "Secrets encrypted with AES-256-GCM in provider_secrets and activated on SitePolicyDO."
                                    .to_string(),
                            ),
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
                    toasts.error("Failed to save auth providers", Some(err.message));
                }
            }
            saving.set(false);
        });
    };

    let on_rotate = move |_| {
        if rotating.get_untracked() {
            return;
        }
        rotating.set(true);
        spawn_local(async move {
            let empty = serde_json::json!({});
            match post_json::<_, RotateSecretsResp>("/admin/api/secrets/rotate", &empty).await {
                Ok(resp) => {
                    let detail = format!(
                        "kid={} · total={} · rotated={} · current={} · failed={}",
                        resp.current_kid,
                        resp.total_rows,
                        resp.rotated,
                        resp.skipped_current,
                        resp.failed
                    );
                    if resp.failed == 0 {
                        toasts.success("Secret rotation complete", Some(detail));
                    } else {
                        toasts.warning("Secret rotation completed with failures", Some(detail));
                    }
                    fetch_providers(false);
                }
                Err(err) => {
                    toasts.error("Secret rotation failed", Some(err));
                }
            }
            rotating.set(false);
        });
    };

    view! {
        <form class="adm-stack" on:submit=on_save>
            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Encrypted Secret Keyring (SITE_SECRET)"</h2>
                        <p class="adm-sub">
                            "Provider secrets are encrypted with AES-256-GCM (derived via HKDF-SHA256 from SITE_SECRET, or optional PROVIDER_SECRETS_KEY override) using fresh 96-bit CSPRNG nonces and deployment/provider/field AAD inside D1 provider_secrets."
                        </p>
                    </div>
                    <button
                        type="button"
                        class="adm-btn"
                        disabled=move || rotating.get()
                        on:click=on_rotate
                    >
                        {move || if rotating.get() { "Rotating…" } else { "Rotate Secrets to Active Key" }}
                    </button>
                </div>
                <div class="adm-chips">
                    <span class="adm-badge adm-badge--ok">
                        {move || format!("Active kid: {}", draft.current_kid.get())}
                    </span>
                    <span class="adm-badge">
                        {move || if draft.has_prev_key.get() {
                            "Previous rotation key configured (zero-downtime rotation ready)"
                        } else {
                            "Single active key (no PREV key set)"
                        }}
                    </span>
                </div>
            </section>

            {move || (draft.age_policy.get() == AgeVerificationPolicy::StrictProviderVerified18).then(|| view! {
                <NoticeBanner
                    tone=NoticeTone::Warning
                    title="Strict Provider-Verified 18+ Policy Enforced"
                    dismissible=false
                    content=NoticeContent::Text(
                        "Only Age-Assurance OIDC can be enabled for login/unlock while Strict Provider-Verified 18+ is active. All other providers are locked off below and enforced server-side."
                            .to_string()
                    )
                />
            })}

            <div class="adm-provider-grid">
                <For
                    each=ordered_rows
                    key=|p| p.id.as_str()
                    let(prov)
                >
                    {
                        let id = prov.id;
                        let supports_strict = prov.supports_strict;
                        let secret_field = prov.secret_field_name.clone();
                        let blocked_by_strict = Memo::new(move |_| {
                            draft.age_policy.get() == AgeVerificationPolicy::StrictProviderVerified18
                                && !supports_strict
                        });
                        let cid_meta = client_id_field(id);
                        let issuer_meta = issuer_field(id);
                        let show_callback = has_oauth_callback(id);
                        let copied_cb = RwSignal::new(false);

                        let on_copy_callback = move |_| {
                            let origin = effective_public_origin(&draft.public_origin.get_untracked());
                            let cb_url = format!("{origin}/user/auth/{}/callback", id.as_str());
                            spawn_local(async move {
                                match copy_text_to_clipboard(&cb_url).await {
                                    Ok(()) => {
                                        copied_cb.set(true);
                                        toasts.success(
                                            format!("Copied {} callback URL", id.display_name()),
                                            Some(cb_url),
                                        );
                                        let cb = wasm_bindgen::closure::Closure::once(move || {
                                            copied_cb.set(false);
                                        });
                                        if let Some(win) = web_sys::window() {
                                            let _ = win
                                                .set_timeout_with_callback_and_timeout_and_arguments_0(
                                                    cb.as_ref().unchecked_ref(),
                                                    2000,
                                                );
                                        }
                                        cb.forget();
                                    }
                                    Err(msg) => {
                                        toasts.error("Failed to copy callback URL", Some(msg));
                                    }
                                }
                            });
                        };

                        view! {
                            <section
                                data-provider=id.as_str()
                                class=move || if blocked_by_strict.get() {
                                    "adm-card adm-provider-card is-locked"
                                } else {
                                    "adm-card adm-provider-card"
                                }
                            >
                                <div class="adm-card-head">
                                    <div>
                                        <h3>{id.display_name()}</h3>
                                        <span class="adm-mono adm-sub">{id.as_str()}</span>
                                    </div>
                                    <ToggleSwitch
                                        checked=Signal::derive(move || prov.enabled.get() && !blocked_by_strict.get())
                                        on_change=Callback::new(move |v| {
                                            prov.enabled.set(v);
                                            draft.dirty.set(true);
                                        })
                                        disabled=Signal::derive(move || blocked_by_strict.get())
                                        label="Enabled"
                                        compact=true
                                    />
                                </div>

                                {move || blocked_by_strict.get().then(|| view! {
                                    <div class="adm-inline-warn">
                                        "Disabled under Strict Provider-Verified 18+ mode (does not provide verified age assurance)."
                                    </div>
                                })}

                                {supports_strict.then(|| view! {
                                    <div class="adm-chips">
                                        <span class="adm-badge adm-badge--ok">"Strict 18+ Eligible"</span>
                                        <span class="adm-badge">"Advanced / Optional"</span>
                                    </div>
                                })}

                                {matches!(id, AuthProviderId::Siwe | AuthProviderId::Siws).then(|| view! {
                                    <div class="adm-chips">
                                        <span class="adm-badge adm-badge--ok">"Zero-Config"</span>
                                    </div>
                                })}

                                <p class="adm-provider-note">
                                    {provider_summary(id)}
                                </p>

                                {move || {
                                    let origin = effective_public_origin(&draft.public_origin.get());
                                    let host = host_from_origin(&origin);
                                    let guide = provider_setup_guide(id, &origin, &host);
                                    let step_count = guide.steps.len();
                                    view! {
                                        <details class="adm-setup-guide">
                                            <summary class="adm-setup-summary">
                                                <span>{format!("Setup guide ({step_count} steps)")}</span>
                                                <span class="adm-setup-chevron">"▾"</span>
                                            </summary>
                                            <div class="adm-setup-body">
                                                <ol class="adm-setup-steps">
                                                    {guide.steps.into_iter().map(|step| view! {
                                                        <li>{step}</li>
                                                    }).collect_view()}
                                                </ol>
                                                {guide.note.map(|n| view! {
                                                    <p class="adm-setup-footnote">{n}</p>
                                                })}
                                                {guide.portal_url.zip(guide.portal_label).map(|(url, lbl)| view! {
                                                    <a
                                                        class="adm-link adm-setup-portal"
                                                        href=url
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                    >
                                                        {format!("{lbl} ↗")}
                                                    </a>
                                                })}
                                            </div>
                                        </details>
                                    }
                                }}

                                {show_callback.then(|| view! {
                                    <div class="adm-callback-box">
                                        <div class="adm-callback-head">
                                            <span>"Authorized Callback / Redirect URI"</span>
                                            <button
                                                type="button"
                                                class="adm-btn adm-btn--sm"
                                                on:click=on_copy_callback
                                            >
                                                {move || if copied_cb.get() { "Copied!" } else { "Copy URL" }}
                                            </button>
                                        </div>
                                        <code class="adm-callback-code">
                                            {move || {
                                                let origin = effective_public_origin(&draft.public_origin.get());
                                                format!("{origin}/user/auth/{}/callback", id.as_str())
                                            }}
                                        </code>
                                    </div>
                                })}

                                {(id == AuthProviderId::OidcAgeAssurance).then(|| view! {
                                    <label class="adm-field">
                                        <span>"Button Label (optional)"</span>
                                        <input
                                            type="text"
                                            placeholder="e.g. Verify 18+ with Yoti"
                                            prop:value=move || prov.display_name.get()
                                            on:input=move |ev| {
                                                prov.display_name.set(event_target_value(&ev));
                                                draft.dirty.set(true);
                                            }
                                        />
                                    </label>
                                })}

                                {issuer_meta.map(|(lbl, ph)| view! {
                                    <label class="adm-field">
                                        <span>{lbl}</span>
                                        <input
                                            type="url"
                                            placeholder=ph
                                            prop:value=move || prov.issuer.get()
                                            on:input=move |ev| {
                                                prov.issuer.set(event_target_value(&ev));
                                                draft.dirty.set(true);
                                            }
                                        />
                                    </label>
                                })}

                                {cid_meta.map(|(lbl, ph)| view! {
                                    <label class="adm-field">
                                        <span>{lbl}</span>
                                        <input
                                            type="text"
                                            placeholder=ph
                                            prop:value=move || prov.public_client_id.get()
                                            on:input=move |ev| {
                                                prov.public_client_id.set(event_target_value(&ev));
                                                draft.dirty.set(true);
                                            }
                                        />
                                    </label>
                                })}

                                {(id == AuthProviderId::Google).then(|| view! {
                                    <ToggleSwitch
                                        checked=Signal::derive(move || {
                                            prov.soft_birthday_check.get()
                                                && draft.age_policy.get() == AgeVerificationPolicy::SelfAttestation
                                        })
                                        on_change=Callback::new(move |v| {
                                            prov.soft_birthday_check.set(v);
                                            draft.dirty.set(true);
                                        })
                                        disabled=Signal::derive(move || draft.age_policy.get() != AgeVerificationPolicy::SelfAttestation)
                                        label="Optional soft birthday pre-check"
                                        description="Self-Attestation only; never grants Verified18."
                                    />
                                })}

                                {secret_field.map(|field_name| {
                                    let heading = secret_label(id, &field_name);
                                    view! {
                                        <div class="adm-secret-box">
                                            <div class="adm-secret-meta">
                                                <strong>{heading}</strong>
                                                <span class=move || if prov.has_client_secret.get() {
                                                    "adm-badge adm-badge--ok"
                                                } else {
                                                    "adm-badge"
                                                }>
                                                    {move || if prov.has_client_secret.get() { "Configured (masked)" } else { "Not set" }}
                                                </span>
                                            </div>
                                            {move || prov.kid.get().map(|k| view! {
                                                <div class="adm-sub adm-mono">
                                                    {format!(
                                                        "kid={} · updated {} by {}",
                                                        k,
                                                        prov.updated_at.get().map(format_ts_utc).unwrap_or_else(|| "—".into()),
                                                        prov.updated_by.get().unwrap_or_else(|| "—".into())
                                                    )}
                                                </div>
                                            })}
                                            <input
                                                type="password"
                                                autocomplete="new-password"
                                                placeholder=move || if prov.has_client_secret.get() {
                                                    "•••••••• (leave blank to keep existing secret)"
                                                } else {
                                                    "Enter write-only secret…"
                                                }
                                                prop:value=move || prov.secret_input.get()
                                                on:input=move |ev| {
                                                    let v = event_target_value(&ev);
                                                    if !v.is_empty() {
                                                        prov.clear_secret.set(false);
                                                    }
                                                    prov.secret_input.set(v);
                                                    draft.dirty.set(true);
                                                }
                                            />
                                            {move || prov.has_client_secret.get().then(|| view! {
                                                <ToggleSwitch
                                                    checked=Signal::derive(move || prov.clear_secret.get())
                                                    on_change=Callback::new(move |v| {
                                                        prov.clear_secret.set(v);
                                                        draft.dirty.set(true);
                                                    })
                                                    label="Delete stored secret on save"
                                                    compact=true
                                                />
                                            })}
                                        </div>
                                    }
                                })}
                            </section>
                        }
                    }
                </For>
            </div>

            <div class="adm-save-bar">
                <span class="adm-sub">
                    {move || if loading.get() { "Loading providers…" } else { "Plaintext secrets are write-only and never returned after save." }}
                </span>
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
                        {move || if saving.get() { "Saving…" } else { "Save Auth Providers" }}
                    </button>
                </div>
            </div>
        </form>
    }
}
