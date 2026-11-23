//! Leptos 0.8 CSR Admin Dashboard SPA reusing `lets-embed-ui`.

pub mod api;
pub mod tabs;

use leptos::prelude::*;
use lets_embed_ui::{FloatingHeader, HeaderVariant, UI_CSS};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::{
    api::{OverviewResp, SafetyConfigResp, get_json},
    tabs::{
        AdminTab, access::AccessTab, accounts::AccountsTab, age_legal::AgeLegalTab,
        providers::ProvidersTab, reports::ReportsTab, safety::SafetyTab,
        similarity_geo::SimilarityGeoTab,
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
    let active_tab = RwSignal::new(initial_tab_from_window());
    let overview = RwSignal::new(Option::<OverviewResp>::None);
    let safety = RwSignal::new(Option::<SafetyConfigResp>::None);
    let load_err = RwSignal::new(Option::<String>::None);
    let providers_refresh = RwSignal::new(0u32);

    let refresh_core = move || {
        spawn_local(async move {
            match get_json::<OverviewResp>("/admin/api/overview").await {
                Ok(ov) => {
                    load_err.set(None);
                    overview.set(Some(ov));
                }
                Err(err) => load_err.set(Some(err)),
            }
        });
        spawn_local(async move {
            match get_json::<SafetyConfigResp>("/admin/api/safety").await {
                Ok(cfg) => safety.set(Some(cfg)),
                Err(err) => load_err.set(Some(err)),
            }
        });
    };

    Effect::new(move |_| {
        refresh_core();
    });

    let on_settings_saved = Callback::new(move |()| {
        refresh_core();
        providers_refresh.update(|n| *n = n.saturating_add(1));
    });

    let on_light_refresh = Callback::new(move |()| {
        refresh_core();
    });

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
        <div class="adm-page">
            <FloatingHeader
                variant=HeaderVariant::Nav
                sticky=true
                aria_label="Admin navigation"
                left=header_left
                right=header_right
            />

            <main class="adm-main">
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
                                on:click=move |_| {
                                    active_tab.set(tab);
                                    set_window_hash(tab.slug());
                                }
                            >
                                <span>{tab.label()}</span>
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
                            <SafetyTab safety=safety on_saved=on_settings_saved />
                        }.into_any(),
                        AdminTab::SimilarityGeo => view! {
                            <SimilarityGeoTab safety=safety on_saved=on_settings_saved />
                        }.into_any(),
                        AdminTab::AgeLegal => view! {
                            <AgeLegalTab safety=safety on_saved=on_settings_saved />
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
        el.set_inner_text("");
        leptos::mount::mount_to(el, AdminApp).forget();
        return;
    }
    leptos::mount::mount_to_body(AdminApp);
}
