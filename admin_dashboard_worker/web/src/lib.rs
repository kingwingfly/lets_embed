//! Leptos 0.8 CSR Admin Dashboard SPA reusing `lets-embed-ui`
//! (`ToastHost`, `QueryBuilder`, `ScoreInput`, `ToggleSwitch`, `FloatingHeader`).

pub mod api;
pub mod drafts;
pub mod tabs;

use leptos::prelude::*;
use lets_embed_ui::{
    FloatingHeader, HeaderVariant, ToastHost, UI_CSS, provide_toast_store,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::{
    api::{
        ActivationResult, OverviewResp, ProvidersResp, RetryActivationResp, SafetyConfigResp,
        get_json, post_json_activatable,
    },
    drafts::provide_admin_drafts,
    tabs::{
        AdminTab, access::AccessTab, accounts::AccountsTab, age_legal::AgeLegalTab, geo::GeoTab,
        providers::ProvidersTab, reports::ReportsTab, safety::SafetyTab, similarity::SimilarityTab,
    },
};

fn initial_tab_from_window() -> AdminTab {
    web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .map(|h| AdminTab::from_hash(&h))
        .unwrap_or(AdminTab::Access)
}

fn set_window_hash(slug: &str) {
    if let Some(w) = web_sys::window() {
        let _ = w.location().set_hash(slug);
    }
}

#[component]
pub fn AdminApp() -> impl IntoView {
    // Provide global GCP-style top-right ToastStore and root-level cross-tab AdminDraftStore.
    let toasts = provide_toast_store();
    let drafts = provide_admin_drafts();

    let active_tab = RwSignal::new(initial_tab_from_window());
    let overview = RwSignal::new(Option::<OverviewResp>::None);
    let safety = RwSignal::new(Option::<SafetyConfigResp>::None);
    let load_err = RwSignal::new(Option::<String>::None);
    let retrying = RwSignal::new(false);
    let providers_refresh = RwSignal::new(0u32);

    let navigate_to = Callback::new(move |tab: AdminTab| {
        active_tab.set(tab);
        set_window_hash(tab.slug());
    });

    let refresh_core = move || {
        spawn_local(async move {
            match get_json::<OverviewResp>("/admin/api/overview").await {
                Ok(ov) => {
                    load_err.set(None);
                    overview.set(Some(ov));
                }
                Err(err) => {
                    load_err.set(Some(err.clone()));
                    toasts.error("Failed to load admin overview", Some(err));
                }
            }
        });
        spawn_local(async move {
            match get_json::<SafetyConfigResp>("/admin/api/safety").await {
                Ok(cfg) => safety.set(Some(cfg)),
                Err(err) => {
                    load_err.set(Some(err.clone()));
                    toasts.error("Failed to load Policy v3 configuration", Some(err));
                }
            }
        });
    };

    let refresh_providers_if_loaded = move || {
        if !drafts.providers.loaded.get_untracked() {
            return;
        }
        spawn_local(async move {
            if let Ok(resp) = get_json::<ProvidersResp>("/admin/api/providers").await {
                if drafts.providers.dirty.get_untracked() {
                    drafts.providers.sync_server_metadata(&resp);
                } else {
                    drafts.providers.hydrate(&resp);
                }
            }
        });
    };

    // Hydrate root drafts ONLY when `!tab.dirty` so tab switches & cross-tab saves
    // never overwrite unsaved edits. Always keep `revision` fresh to prevent stale-rev 409s.
    Effect::new(move |_| {
        if let Some(ov) = overview.get() {
            if !drafts.access.dirty.get_untracked() {
                drafts.access.hydrate(&ov);
            } else {
                drafts.access.revision.set(ov.revision);
            }
        }
    });

    Effect::new(move |_| {
        if let Some(cfg) = safety.get() {
            if !drafts.safety.dirty.get_untracked() {
                drafts.safety.hydrate(&cfg, true);
            } else {
                drafts.safety.sync_revision(&cfg);
            }

            if !drafts.geo.dirty.get_untracked() {
                drafts.geo.hydrate(&cfg);
            } else {
                drafts.geo.revision.set(cfg.revision);
            }

            if !drafts.similarity.dirty.get_untracked() {
                drafts.similarity.hydrate(&cfg);
            } else {
                drafts.similarity.revision.set(cfg.revision);
            }

            if !drafts.age_legal.dirty.get_untracked() {
                drafts.age_legal.hydrate(&cfg);
            } else {
                drafts.age_legal.revision.set(cfg.revision);
            }
        }
    });

    Effect::new(move |_| {
        refresh_core();
    });

    let on_settings_saved = Callback::new(move |()| {
        refresh_core();
        providers_refresh.update(|n| *n = n.saturating_add(1));
        refresh_providers_if_loaded();
    });

    let on_light_refresh = Callback::new(move |()| {
        refresh_core();
    });

    // Pending activation state derived from either overview or safety response.
    let pending_info = Memo::new(move |_| {
        if let Some(ov) = overview.get()
            && ov.activation_status != "active"
        {
            return Some((ov.revision, ov.policy_digest, ov.activation_status));
        }
        if let Some(cfg) = safety.get()
            && cfg.activation_status != "active"
        {
            return Some((cfg.revision, cfg.policy_digest, cfg.activation_status));
        }
        None
    });

    let legacy_notice = Memo::new(move |_| {
        overview
            .get()
            .and_then(|o| o.legacy_upgrade_notice)
            .or_else(|| safety.get().and_then(|s| s.legacy_upgrade_notice))
    });

    let on_retry_activation = move |_| {
        if retrying.get_untracked() {
            return;
        }
        retrying.set(true);
        spawn_local(async move {
            let empty = serde_json::json!({});
            match post_json_activatable::<_, RetryActivationResp>(
                "/admin/api/policy/retry-activation",
                &empty,
            )
            .await
            {
                Ok(ActivationResult::Active(resp)) => {
                    let short = resp.policy_digest.get(..12).unwrap_or(&resp.policy_digest);
                    toasts.success(
                        format!("Policy rev #{} activated on SitePolicyDO", resp.revision),
                        Some(format!(
                            "min_enforce_rev={} · digest {short}…",
                            resp.min_enforce_rev
                        )),
                    );
                    refresh_core();
                    providers_refresh.update(|n| *n = n.saturating_add(1));
                    refresh_providers_if_loaded();
                }
                Ok(ActivationResult::PendingActivation(pending)) => {
                    toasts.warning(
                        format!("Activation still pending for rev #{}", pending.revision),
                        Some(pending.error),
                    );
                    refresh_core();
                }
                Err(err) => {
                    toasts.error("Retry activation failed", Some(err.message));
                }
            }
            retrying.set(false);
        });
    };

    let header_left = ViewFn::from(move || {
        view! {
            <div class="adm-brand">
                <span class="adm-brand-dot" aria-hidden="true"></span>
                <div>
                    <div class="adm-brand-title">"Gallery Admin"</div>
                    <div class="adm-brand-sub">
                        {move || overview
                            .get()
                            .map(|o| o.admin_email)
                            .unwrap_or_else(|| "Cloudflare Access".to_string())}
                    </div>
                </div>
            </div>
        }
    });

    let header_right = ViewFn::from(move || {
        view! {
            <div class="adm-header-actions">
                {move || overview.get().map(|ov| view! {
                    <div class="adm-header-chips">
                        <span class="adm-chip">
                            {format!("rev #{} (min #{})", ov.revision, ov.min_enforce_rev)}
                        </span>
                        <span class=if ov.safety.safety_enabled {
                            "adm-chip adm-chip--ok"
                        } else {
                            "adm-chip"
                        }>
                            {if ov.safety.safety_enabled { "Safety ON" } else { "Safety OFF" }}
                        </span>
                        {(ov.activation_status != "active").then(|| view! {
                            <span class="adm-chip adm-chip--warn">"Pending Activation"</span>
                        })}
                        {(ov.open_report_count > 0).then(|| view! {
                            <span class="adm-chip adm-chip--warn">
                                {format!("{} open reports", ov.open_report_count)}
                            </span>
                        })}
                    </div>
                })}
                <a class="adm-btn adm-btn--primary" href="/admin/browse">
                    "Browse Gallery ↗"
                </a>
            </div>
        }
    });

    view! {
        <style>{UI_CSS}</style>
        <ToastHost />
        <div class="adm-page">
            <FloatingHeader
                variant=HeaderVariant::Nav
                sticky=true
                aria_label="Admin navigation"
                left=header_left
                right=header_right
            />

            <main class="adm-main">
                // Prominent Two-Phase Activation Pending Banner (visible across all tabs)
                {move || pending_info.get().map(|(rev, digest, status)| {
                    let short = digest.get(..12).unwrap_or(&digest).to_string();
                    view! {
                        <div class="adm-pending-banner" role="alert">
                            <div class="adm-pending-copy">
                                <div class="adm-pending-title">
                                    <span class="adm-badge adm-badge--warn">{status}</span>
                                    <strong>{format!("Policy activation pending for revision #{rev}")}</strong>
                                </div>
                                <p class="adm-pending-desc">
                                    {format!(
                                        "Revision #{rev} (digest {short}…) is saved in D1 but has not yet been acknowledged by SitePolicyDO. Edge workers continue enforcing the previously active revision until activation succeeds."
                                    )}
                                </p>
                            </div>
                            <button
                                type="button"
                                class="adm-btn adm-btn--warn"
                                disabled=move || retrying.get()
                                on:click=on_retry_activation
                            >
                                {move || if retrying.get() { "Retrying…" } else { "Retry Activation" }}
                            </button>
                        </div>
                    }
                })}

                {move || legacy_notice.get().map(|msg| view! {
                    <div class="adm-alert adm-alert--warn" role="status">
                        <strong>"Policy v3 Upgrade Notice: "</strong>
                        <span>{msg}</span>
                    </div>
                })}

                {move || load_err.get().map(|err| view! {
                    <div class="adm-alert adm-alert--err" role="alert">
                        <strong>"Admin API error: "</strong>
                        <span>{err}</span>
                    </div>
                })}

                <nav class="adm-tabs" role="tablist" aria-label="Admin sections">
                    {AdminTab::ALL.into_iter().map(|tab| {
                        view! {
                            <button
                                type="button"
                                role="tab"
                                class=move || if active_tab.get() == tab {
                                    "adm-tab is-active"
                                } else {
                                    "adm-tab"
                                }
                                aria-selected=move || (active_tab.get() == tab).to_string()
                                on:click=move |_| navigate_to.run(tab)
                            >
                                <span>{tab.label()}</span>
                                {move || drafts.is_tab_dirty(tab).then(|| view! {
                                    <span
                                        class="adm-dirty-dot"
                                        title="Unsaved draft changes"
                                        aria-label="Unsaved draft changes"
                                    >
                                        "•"
                                    </span>
                                })}
                                {(tab == AdminTab::Reports).then_some(move || {
                                    overview
                                        .get()
                                        .filter(|o| o.open_report_count > 0)
                                        .map(|o| {
                                            view! {
                                                <span class="adm-count">{o.open_report_count}</span>
                                            }
                                        })
                                })}
                            </button>
                        }
                    }).collect_view()}
                </nav>

                <div class="adm-stage">
                    {move || match active_tab.get() {
                        AdminTab::Access => view! {
                            <AccessTab overview=overview on_saved=on_settings_saved />
                        }.into_any(),
                        AdminTab::Accounts => view! {
                            <AccountsTab on_mutated=on_light_refresh />
                        }.into_any(),
                        AdminTab::Safety => view! {
                            <SafetyTab
                                safety=safety
                                on_saved=on_settings_saved
                                on_navigate=navigate_to
                            />
                        }.into_any(),
                        AdminTab::Geo => view! {
                            <GeoTab safety=safety on_saved=on_settings_saved />
                        }.into_any(),
                        AdminTab::AgeLegal => view! {
                            <AgeLegalTab safety=safety on_saved=on_settings_saved />
                        }.into_any(),
                        AdminTab::Similarity => view! {
                            <SimilarityTab safety=safety on_saved=on_settings_saved />
                        }.into_any(),
                        AdminTab::Providers => view! {
                            <ProvidersTab refresh_epoch=providers_refresh on_saved=on_settings_saved />
                        }.into_any(),
                        AdminTab::Reports => view! {
                            <ReportsTab on_resolved=on_light_refresh />
                        }.into_any(),
                    }}
                </div>
            </main>
        </div>
    }
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    if let Some(doc) = web_sys::window().and_then(|w| w.document())
        && let Some(root) = doc.get_element_by_id("admin-root")
        && let Ok(el) = root.dyn_into::<web_sys::HtmlElement>()
    {
        // Clear boot-loading centering class so the mounted SPA stays strictly left-aligned!
        el.set_class_name("adm-root-mounted");
        el.set_inner_text("");
        leptos::mount::mount_to(el, AdminApp).forget();
        return;
    }
    leptos::mount::mount_to_body(AdminApp);
}
