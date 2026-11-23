//! Auth Providers tab:
//! - Configure all pluggable auth providers with clean left-aligned cards & `<ToggleSwitch>`
//! - Inline disabled notice on non-age-capable providers under Strict Provider-Verified 18+
//! - Masked write-only secret inputs encrypted via HKDF(`SITE_SECRET`) / `PROVIDER_SECRETS_KEY`
//! - Zero-downtime AES-256-GCM key rotation trigger (`POST /admin/api/secrets/rotate`)
//! - GCP top-right toasts via `use_toast_store()`

use leptos::prelude::*;
use lets_embed_ui::{NoticeBanner, NoticeContent, NoticeTone, ToggleSwitch, use_toast_store};
use site_access::{AgeVerificationPolicy, AuthProviderId};
use wasm_bindgen_futures::spawn_local;

use crate::api::{
    ActivationResult, ProviderUpdateItem, ProviderView, ProvidersResp, RotateSecretsResp,
    SaveProvidersReq, format_ts_utc, get_json, post_json, post_json_activatable,
};

#[derive(Clone)]
struct EditableProvider {
    id: AuthProviderId,
    supports_strict: bool,
    secret_field_name: Option<String>,
    has_client_secret: RwSignal<bool>,
    kid: RwSignal<Option<String>>,
    updated_at: RwSignal<Option<i64>>,
    updated_by: RwSignal<Option<String>>,
    enabled: RwSignal<bool>,
    display_name: RwSignal<String>,
    issuer: RwSignal<String>,
    public_client_id: RwSignal<String>,
    soft_birthday_check: RwSignal<bool>,
    secret_input: RwSignal<String>,
    clear_secret: RwSignal<bool>,
}

impl EditableProvider {
    fn from_view(v: &ProviderView) -> Self {
        Self {
            id: v.config.id,
            supports_strict: v.supports_strict_age_verification,
            secret_field_name: v.secret_field_name.clone(),
            has_client_secret: RwSignal::new(v.has_client_secret),
            kid: RwSignal::new(v.kid.clone()),
            updated_at: RwSignal::new(v.updated_at),
            updated_by: RwSignal::new(v.updated_by.clone()),
            enabled: RwSignal::new(v.config.enabled),
            display_name: RwSignal::new(v.config.display_name.clone().unwrap_or_default()),
            issuer: RwSignal::new(v.config.issuer.clone().unwrap_or_default()),
            public_client_id: RwSignal::new(v.config.public_client_id.clone().unwrap_or_default()),
            soft_birthday_check: RwSignal::new(v.config.soft_birthday_check),
            secret_input: RwSignal::new(String::new()),
            clear_secret: RwSignal::new(false),
        }
    }

    fn to_update(&self) -> ProviderUpdateItem {
        let opt = |s: String| {
            let t = s.trim().to_string();
            (!t.is_empty()).then_some(t)
        };
        ProviderUpdateItem {
            id: self.id,
            enabled: self.enabled.get_untracked(),
            display_name: opt(self.display_name.get_untracked()),
            issuer: opt(self.issuer.get_untracked()),
            public_client_id: opt(self.public_client_id.get_untracked()),
            soft_birthday_check: self.soft_birthday_check.get_untracked(),
            secret_value: opt(self.secret_input.get_untracked()),
            clear_secret: self.clear_secret.get_untracked(),
        }
    }
}

fn client_id_label(id: AuthProviderId) -> &'static str {
    match id {
        AuthProviderId::Telegram => "Bot Username (public)",
        AuthProviderId::EmailOtp => "Sender Email / From Address",
        AuthProviderId::Siwe | AuthProviderId::Siws => "Optional Wallet Label",
        _ => "OAuth / OIDC Client ID (public)",
    }
}

fn issuer_label(id: AuthProviderId) -> Option<&'static str> {
    match id {
        AuthProviderId::OidcAgeAssurance => {
            Some("OIDC Issuer URL (https:// required, SSRF validated)")
        }
        AuthProviderId::EmailOtp => Some("HTTP Mail API Endpoint (https:// optional)"),
        AuthProviderId::Google
        | AuthProviderId::GitHub
        | AuthProviderId::X
        | AuthProviderId::Discord => {
            Some("Custom OIDC / OAuth Issuer Override (https:// optional)")
        }
        AuthProviderId::Siwe | AuthProviderId::Siws | AuthProviderId::Telegram => None,
    }
}

#[component]
pub fn ProvidersTab(
    refresh_epoch: RwSignal<u32>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let toasts = use_toast_store();

    let revision = RwSignal::new(0u64);
    let age_policy = RwSignal::new(AgeVerificationPolicy::Off);
    let current_kid = RwSignal::new(String::new());
    let has_prev_key = RwSignal::new(false);
    let rows = RwSignal::new(Vec::<EditableProvider>::new());

    let loading = RwSignal::new(false);
    let saving = RwSignal::new(false);
    let rotating = RwSignal::new(false);

    let load_providers = move || {
        loading.set(true);
        spawn_local(async move {
            match get_json::<ProvidersResp>("/admin/api/providers").await {
                Ok(resp) => {
                    revision.set(resp.revision);
                    age_policy.set(resp.age_policy);
                    current_kid.set(resp.current_kid);
                    has_prev_key.set(resp.has_prev_key);
                    rows.set(resp.providers.iter().map(EditableProvider::from_view).collect());
                }
                Err(err) => {
                    toasts.error("Failed to load auth providers", Some(err));
                }
            }
            loading.set(false);
        });
    };

    Effect::new(move |_| {
        let _ = refresh_epoch.get();
        load_providers();
    });

    let on_save = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if saving.get_untracked() {
            return;
        }
        saving.set(true);

        let providers: Vec<ProviderUpdateItem> = rows
            .get_untracked()
            .iter()
            .map(EditableProvider::to_update)
            .collect();
        let req = SaveProvidersReq {
            revision: revision.get_untracked(),
            providers,
        };

        spawn_local(async move {
            match post_json_activatable::<_, ProvidersResp>("/admin/api/providers", &req).await {
                Ok(ActivationResult::Active(resp)) => {
                    revision.set(resp.revision);
                    age_policy.set(resp.age_policy);
                    current_kid.set(resp.current_kid);
                    has_prev_key.set(resp.has_prev_key);
                    rows.set(resp.providers.iter().map(EditableProvider::from_view).collect());
                    toasts.success(
                        format!("Saved Auth Providers rev #{}", resp.revision),
                        Some(
                            "Secrets encrypted with AES-256-GCM in provider_secrets and activated on SitePolicyDO."
                                .to_string(),
                        ),
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
                    load_providers();
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
                        <h2>"Encrypted Secret Keyring (`SITE_SECRET` / `PROVIDER_SECRETS_KEY`)"</h2>
                        <p class="adm-sub">
                            "Provider secrets are encrypted with AES-256-GCM (derived via HKDF from `SITE_SECRET` or explicit `PROVIDER_SECRETS_KEY` / `SETTINGS_ENCRYPTION_KEY`), fresh 96-bit CSPRNG nonces, and deployment/provider/field AAD inside D1 `provider_secrets`."
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
                        {move || format!("Active kid: {}", current_kid.get())}
                    </span>
                    <span class="adm-badge">
                        {move || if has_prev_key.get() {
                            "Previous rotation key configured (zero-downtime rotation ready)"
                        } else {
                            "Single active key (no PREV key set)"
                        }}
                    </span>
                </div>
            </section>

            {move || (age_policy.get() == AgeVerificationPolicy::StrictProviderVerified18).then(|| view! {
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
                    each=move || rows.get()
                    key=|p| p.id.as_str()
                    let(prov)
                >
                    {
                        let id = prov.id;
                        let supports_strict = prov.supports_strict;
                        let secret_field = prov.secret_field_name.clone();
                        let blocked_by_strict = Memo::new(move |_| {
                            age_policy.get() == AgeVerificationPolicy::StrictProviderVerified18
                                && !supports_strict
                        });
                        let issuer_lbl = issuer_label(id);

                        view! {
                            <section class=move || if blocked_by_strict.get() {
                                "adm-card adm-provider-card is-locked"
                            } else {
                                "adm-card adm-provider-card"
                            }>
                                <div class="adm-card-head">
                                    <div>
                                        <h3>{id.display_name()}</h3>
                                        <span class="adm-mono adm-sub">{id.as_str()}</span>
                                    </div>
                                    <ToggleSwitch
                                        checked=Signal::derive(move || prov.enabled.get() && !blocked_by_strict.get())
                                        on_change=Callback::new(move |v| prov.enabled.set(v))
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
                                    </div>
                                })}

                                <label class="adm-field">
                                    <span>"Button Display Name Override (optional)"</span>
                                    <input
                                        type="text"
                                        placeholder=id.display_name()
                                        prop:value=move || prov.display_name.get()
                                        on:input=move |ev| prov.display_name.set(event_target_value(&ev))
                                    />
                                </label>

                                {issuer_lbl.map(|lbl| view! {
                                    <label class="adm-field">
                                        <span>{lbl}</span>
                                        <input
                                            type="url"
                                            placeholder="https://idp.example.com"
                                            prop:value=move || prov.issuer.get()
                                            on:input=move |ev| prov.issuer.set(event_target_value(&ev))
                                        />
                                    </label>
                                })}

                                <label class="adm-field">
                                    <span>{client_id_label(id)}</span>
                                    <input
                                        type="text"
                                        placeholder="Public client ID / username"
                                        prop:value=move || prov.public_client_id.get()
                                        on:input=move |ev| prov.public_client_id.set(event_target_value(&ev))
                                    />
                                </label>

                                {(id == AuthProviderId::Google).then(|| view! {
                                    <ToggleSwitch
                                        checked=Signal::derive(move || prov.soft_birthday_check.get())
                                        on_change=Callback::new(move |v| prov.soft_birthday_check.set(v))
                                        disabled=Signal::derive(move || age_policy.get() != AgeVerificationPolicy::SelfAttestation)
                                        label="Optional soft birthday pre-check"
                                        description="Self-Attestation only; never grants Verified18."
                                    />
                                })}

                                {secret_field.map(|field_name| view! {
                                    <div class="adm-secret-box">
                                        <div class="adm-secret-meta">
                                            <strong>{format!("Secret ({field_name})")}</strong>
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
                                            }
                                        />
                                        {move || prov.has_client_secret.get().then(|| view! {
                                            <ToggleSwitch
                                                checked=Signal::derive(move || prov.clear_secret.get())
                                                on_change=Callback::new(move |v| prov.clear_secret.set(v))
                                                label="Delete stored secret on save"
                                                compact=true
                                            />
                                        })}
                                    </div>
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
                <button type="submit" class="adm-btn adm-btn--primary" disabled=move || saving.get()>
                    {move || if saving.get() { "Saving…" } else { "Save Auth Providers" }}
                </button>
            </div>
        </form>
    }
}
