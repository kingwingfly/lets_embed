#![cfg_attr(test, recursion_limit = "256")]

pub mod components;
pub mod types;
pub mod util;

#[cfg(feature = "ssr")]
pub mod legal;
#[cfg(feature = "ssr")]
pub mod policy_sync;
#[cfg(feature = "ssr")]
pub mod state;

use crate::components::{ImageDetails, LikeStore, Results, SearchBar};
use crate::types::{SafetyUiState, SiteUiConfig, navigate_external};
use leptos::{prelude::*, task::spawn_local};
use leptos_meta::{HashedStylesheet, Link, Meta, MetaTags, provide_meta_context};
use leptos_router::{
    SsrMode,
    components::{ParentRoute, Route, Router, Routes},
    path,
};
use lets_embed_ui::{
    AgeGateModal, ReportDialog, ReportSubmission, ReportTargetKind, ToastHost,
    provide_toast_store, use_toast_store,
};
use site_access::{AgeGateTrigger, AgeVerificationPolicy};

pub const SITE_DESCRIPTION: &str = "Explore and search curated artwork and photo albums by title, artist, tags, CLIP descriptions, and visual similarity on Let's Embed.";

#[cfg(feature = "hydrate")]
const GUEST_AGE_SPLASH_SESSION_KEY: &str = "lets-embed:age-splash-ack";

pub fn shell(options: LeptosOptions) -> impl IntoView {
    // Emit RTA adult rating meta tags strictly in SSR `<head>` (outside the
    // Leptos-hydrated `<body><App /></body>` tree) so SSR and Hydrate DOM inside
    // `<App />` are 100% identical and never trigger hydration cast panics.
    #[cfg(feature = "ssr")]
    let rta_meta_enabled = build_site_ui_config_from_context().rta_meta_enabled;
    #[cfg(not(feature = "ssr"))]
    let rta_meta_enabled = false;

    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                {rta_meta_enabled.then(|| view! {
                    <meta name="rating" content="RTA-5042-1996-1400-1577-RTA"/>
                    <meta name="rating" content="adult"/>
                })}
                <AutoReload options=options.clone() />
                <HydrationScripts options=options.clone() />
                <MetaTags />
                <Link
                    rel="icon"
                    href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>💠</text></svg>"
                />
                <Link rel="preconnect" href="https://fonts.googleapis.com" />
                <Link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="" />
                <Link
                    rel="stylesheet"
                    href="https://fonts.googleapis.com/css2?family=Fredoka:wght@500;600;700&display=swap"
                />
                <style inner_html=lets_embed_ui::UI_CSS></style>
                <HashedStylesheet options />
                <script inner_html=include_str!("../../../assets/gallery-allowance.js")></script>
            </head>
            <body class="bg-sky-50 text-slate-700">
                <App />
            </body>
        </html>
    }
}

#[cfg(feature = "hydrate")]
async fn post_content_report(sub: &ReportSubmission) -> Result<String, String> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Headers, RequestInit, Response};

    let window = web_sys::window().ok_or("no window")?;
    let opts = RequestInit::new();
    opts.set_method("POST");

    let headers = Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set(site_access::USER_CSRF_HEADER, "1")
        .map_err(|e| format!("{e:?}"))?;
    opts.set_headers(&headers);

    let body = serde_json::json!({
        "target_kind": sub.target_kind.as_str(),
        "target_id": sub.target_id,
        "reason": sub.reason.as_str(),
        "note": sub.note,
    })
    .to_string();
    opts.set_body(&JsValue::from_str(&body));

    let resp = JsFuture::from(window.fetch_with_str_and_init("/user/api/reports", &opts))
        .await
        .map_err(|e| format!("Network error: {e:?}"))?;
    let resp: Response = resp
        .dyn_into()
        .map_err(|_| "Unexpected response type".to_string())?;

    if resp.status() == 401 {
        return Err("Please sign in to submit a content report.".to_string());
    }
    if resp.status() == 429 {
        return Err("Report rate limit reached — please try again later.".to_string());
    }
    if !resp.ok() {
        let text = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
            .await
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(ToOwned::to_owned))
            .unwrap_or_else(|| format!("Report failed (HTTP {})", resp.status()));
        return Err(msg);
    }
    Ok("Thank you — your report has been submitted for review.".to_string())
}

#[cfg(not(feature = "hydrate"))]
async fn post_content_report(_sub: &ReportSubmission) -> Result<String, String> {
    Err("Content reporting is only available in the browser.".to_string())
}

fn load_guest_age_splash_ack() -> bool {
    #[cfg(feature = "hydrate")]
    {
        web_sys::window()
            .and_then(|w| w.session_storage().ok().flatten())
            .and_then(|s| s.get_item(GUEST_AGE_SPLASH_SESSION_KEY).ok().flatten())
            .is_some_and(|v| v == "1")
    }
    #[cfg(not(feature = "hydrate"))]
    {
        false
    }
}

fn save_guest_age_splash_ack() {
    #[cfg(feature = "hydrate")]
    {
        if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok().flatten()) {
            let _ = storage.set_item(GUEST_AGE_SPLASH_SESSION_KEY, "1");
        }
    }
}

fn broadcast_safety_invalidation(reason: &str) {
    #[cfg(feature = "hydrate")]
    {
        use wasm_bindgen::JsValue;

        let ts = js_sys::Date::now();
        if let Ok(ch) = web_sys::BroadcastChannel::new(lets_embed_ui::browser::SAFETY_CHANNEL_NAME)
        {
            let payload = js_sys::Object::new();
            let _ = js_sys::Reflect::set(
                &payload,
                &JsValue::from_str("type"),
                &JsValue::from_str("invalidate"),
            );
            let _ = js_sys::Reflect::set(
                &payload,
                &JsValue::from_str("reason"),
                &JsValue::from_str(reason),
            );
            let _ = js_sys::Reflect::set(
                &payload,
                &JsValue::from_str("ts"),
                &JsValue::from_f64(ts),
            );
            let _ = ch.post_message(&payload);
            ch.close();
        }
        if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            let _ = storage.set_item("lets-embed:safety-invalidate", &format!("{reason}:{ts:.0}"));
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = reason;
    }
}

#[cfg(feature = "hydrate")]
async fn post_age_confirm() -> Result<(), (u16, String)> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Headers, RequestInit, Response};

    let window = web_sys::window().ok_or((0, "Browser window unavailable.".to_string()))?;
    let opts = RequestInit::new();
    opts.set_method("POST");

    let headers = Headers::new().map_err(|e| (0, format!("{e:?}")))?;
    headers
        .set("Accept", "application/json")
        .map_err(|e| (0, format!("{e:?}")))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| (0, format!("{e:?}")))?;
    headers
        .set("X-Requested-With", "fetch")
        .map_err(|e| (0, format!("{e:?}")))?;
    opts.set_headers(&headers);
    opts.set_body(&JsValue::from_str("{}"));

    let resp = JsFuture::from(window.fetch_with_str_and_init("/user/api/age-confirm", &opts))
        .await
        .map_err(|e| (0, format!("Network error: {e:?}")))?;
    let resp: Response = resp
        .dyn_into()
        .map_err(|_| (0, "Unexpected response type.".to_string()))?;
    let status = resp.status();
    if resp.ok() {
        return Ok(());
    }
    let text = JsFuture::from(resp.text().map_err(|e| (status, format!("{e:?}")))?)
        .await
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    let msg = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("error")
                .or_else(|| v.get("message"))
                .and_then(|e| e.as_str())
                .map(ToOwned::to_owned)
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| match status {
            401 => "Please sign in to save your 18+ confirmation.".to_string(),
            _ => format!("Age confirmation failed (HTTP {status})."),
        });
    Err((status, msg))
}

#[cfg(not(feature = "hydrate"))]
async fn post_age_confirm() -> Result<(), (u16, String)> {
    Err((
        0,
        "Age confirmation is only available in the browser.".to_string(),
    ))
}

#[component]
fn GlobalAgeGateModal() -> impl IntoView {
    let safety = expect_context::<SafetyUiState>();
    let toast = use_toast_store();
    let submitting = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let open = Signal::derive(move || safety.age_gate_open.get());
    let is_authenticated = Signal::derive(move || safety.caller_authenticated.get());
    let subtitle = Signal::derive(move || {
        if safety.caller_authenticated.get() {
            "Your 18+ confirmation will be saved to your account and the gallery will refresh immediately.".to_string()
        } else if safety.age_gate_from_card.get() {
            "Sign-in is required to record your 18+ confirmation on your account and unlock restricted cards. Confirming will take you to sign in.".to_string()
        } else {
            "Confirm for this browsing session, or sign in to save your 18+ confirmation on your account.".to_string()
        }
    });

    Effect::new(move |_| {
        if safety.age_gate_open.get() {
            submitting.set(false);
            error.set(None);
        }
    });

    let dismiss_modal = move || {
        if !safety.caller_authenticated.get_untracked() && !safety.age_gate_from_card.get_untracked()
        {
            save_guest_age_splash_ack();
        }
        safety.close_age_gate();
    };

    let on_close = Callback::new(move |()| dismiss_modal());
    let on_leave = Callback::new(move |()| dismiss_modal());

    let on_confirm = Callback::new(move |()| {
        if submitting.get_untracked() {
            return;
        }
        if !safety.caller_authenticated.get_untracked() {
            if safety.age_gate_from_card.get_untracked() {
                safety.close_age_gate();
                navigate_external("/user/login?next=/user/account%23age-confirm");
            } else {
                save_guest_age_splash_ack();
                safety.close_age_gate();
            }
            return;
        }
        submitting.set(true);
        error.set(None);
        spawn_local(async move {
            match post_age_confirm().await {
                Ok(()) => {
                    let _ = safety.caller_age_verified.try_set(true);
                    safety.close_age_gate();
                    toast.success(
                        "Age 18+ confirmed",
                        Some("Your 18+ confirmation has been saved.".to_string()),
                    );
                    broadcast_safety_invalidation("policy_change");
                    let _ = safety.reload_epoch.try_update(|e| *e = e.wrapping_add(1));
                }
                Err((status, msg)) => {
                    if status == 401 {
                        let _ = safety.caller_authenticated.try_set(false);
                    }
                    let _ = error.try_set(Some(msg.clone()));
                    toast.error("Age confirmation failed", Some(msg));
                }
            }
            let _ = submitting.try_set(false);
        });
    });

    view! {
        <AgeGateModal
            open=open
            subtitle=subtitle
            is_authenticated=is_authenticated
            submitting=Signal::derive(move || submitting.get())
            error=Signal::derive(move || error.get())
            on_confirm=on_confirm
            on_leave=on_leave
            on_close=on_close
        />
    }
}

#[component]
fn GlobalReportDialog() -> impl IntoView {
    let safety = expect_context::<SafetyUiState>();
    let submitting = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let success: RwSignal<Option<String>> = RwSignal::new(None);

    let open = Signal::derive(move || safety.report_target.with(Option::is_some));
    let target_kind = Signal::derive(move || {
        safety
            .report_target
            .with(|t| t.as_ref().map(|x| x.kind).unwrap_or(ReportTargetKind::Image))
    });
    let target_id = Signal::derive(move || {
        safety
            .report_target
            .with(|t| t.as_ref().map(|x| x.id).unwrap_or(0))
    });
    let target_label = Signal::derive(move || {
        safety
            .report_target
            .with(|t| t.as_ref().map(|x| x.label.clone()).unwrap_or_default())
    });

    Effect::new(move |_| {
        // Clear previous feedback whenever target changes.
        let _ = safety.report_target.get();
        submitting.set(false);
        error.set(None);
        success.set(None);
    });

    let on_close = Callback::new(move |()| {
        safety.report_target.set(None);
    });

    let on_submit = Callback::new(move |submission: ReportSubmission| {
        if !safety.is_managed.get_untracked() {
            error.set(Some(
                "Content reporting is only available in managed deployments.".to_string(),
            ));
            return;
        }
        submitting.set(true);
        error.set(None);
        success.set(None);
        spawn_local(async move {
            match post_content_report(&submission).await {
                Ok(msg) => {
                    let _ = success.try_set(Some(msg));
                }
                Err(err) => {
                    let _ = error.try_set(Some(err));
                }
            }
            let _ = submitting.try_set(false);
        });
    });

    view! {
        <ReportDialog
            open=open
            target_kind=target_kind
            target_id=target_id
            target_label=target_label
            submitting=Signal::derive(move || submitting.get())
            error=Signal::derive(move || error.get())
            success_message=Signal::derive(move || success.get())
            on_submit=on_submit
            on_close=on_close
        />
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    provide_toast_store();
    provide_context(crate::types::ImageQuery(RwSignal::new(None)));
    provide_context(crate::types::AdvancedUploads(RwSignal::new(None)));
    let density = crate::types::GalleryDensityState::new();
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        if let Some(saved) = crate::types::load_gallery_density() {
            density.0.set(saved);
        }
    });
    provide_context(density);
    provide_context(LikeStore::new());

    let safety_ui = SafetyUiState::new();
    provide_context(safety_ui);

    // Apply `SiteUiConfig` strictly inside a client `Effect` (never synchronously during
    // SSR or initial hydration) so NoticeBanner and AgeGateModal never diverge SSR/hydrate DOM.
    let site_config_res = OnceResource::new(async move { fetch_site_config().await.ok() });
    let site_wide_age_checked = StoredValue::new(false);
    Effect::new(move |_| {
        if let Some(Some(cfg)) = site_config_res.get() {
            safety_ui.apply_site_config(&cfg);
            if !site_wide_age_checked.get_value() {
                site_wide_age_checked.set_value(true);
                if cfg.age_policy == AgeVerificationPolicy::SelfAttestation
                    && cfg.age_gate_trigger == AgeGateTrigger::SiteWideSplash
                    && !cfg.caller_age_verified
                    && (cfg.caller_authenticated || !load_guest_age_splash_ack())
                {
                    safety_ui.open_age_gate_site_wide();
                }
            }
        }
    });

    // Re-sync SiteUiConfig on cross-tab auth / policy invalidations so caller flags stay fresh.
    #[cfg(feature = "hydrate")]
    {
        let last_inv = StoredValue::new(safety_ui.invalidation_epoch.get_untracked());
        Effect::new(move |_| {
            let cur = safety_ui.invalidation_epoch.get();
            if cur != last_inv.get_value() {
                last_inv.set_value(cur);
                spawn_local(async move {
                    if let Ok(cfg) = fetch_site_config().await {
                        safety_ui.apply_site_config(&cfg);
                    }
                });
            }
        });
    }

    view! {
        <Meta property="og:site_name" content="Let's Embed"/>
        <Meta name="twitter:card" content="summary_large_image"/>
        <Router>
            <div class="web-app-shell min-h-screen w-full flex flex-col overflow-x-clip bg-gradient-to-b from-sky-50 via-white to-sky-100">
                <main class="web-main flex-1 w-full">
                    <Routes fallback=|| "Page not found.".into_view()>
                        <ParentRoute path=path!("") view=SearchBar>
                            <Route path=path!("/details/:id") view=ImageDetails ssr=SsrMode::Async/>
                            <Route path=path!("") view=|| view! { <Results /> } ssr=SsrMode::Async/>
                        </ParentRoute>
                    </Routes>
                </main>
                <footer class="web-footer w-full py-4 px-4 border-t border-sky-200/70 bg-white/60 text-xs text-slate-500">
                    <div class="web-footer-inner max-w-[1640px] mx-auto flex flex-wrap items-center justify-between gap-2">
                        <span class="web-footer-brand font-medium text-sky-800/80">"Let\u{2019}s Embed"</span>
                        <nav aria-label="Legal and policies" class="web-footer-nav flex flex-wrap items-center gap-3">
                            <a href="/terms" rel="external" class="web-footer-link hover:text-sky-600 hover:underline">"Terms"</a>
                            <a href="/privacy" rel="external" class="web-footer-link hover:text-sky-600 hover:underline">"Privacy"</a>
                            <a href="/dmca" rel="external" class="web-footer-link hover:text-sky-600 hover:underline">"DMCA"</a>
                            <a href="/content-policy" rel="external" class="web-footer-link hover:text-sky-600 hover:underline">"Content Policy"</a>
                        </nav>
                    </div>
                </footer>
                <GlobalReportDialog />
                <GlobalAgeGateModal />
                <ToastHost />
            </div>
        </Router>
    }
}

#[cfg(feature = "ssr")]
fn build_site_ui_config(ctx: &state::RequestSafetyContext) -> SiteUiConfig {
    let pol = &ctx.policy.policy;
    let effective_notice_md = pol.legal.effective_notice_banner_md();
    let notice_html = effective_notice_md.map(legal::render_sanitized_markdown);
    let notice_key = effective_notice_md
        .map(site_access::compute_terms_digest)
        .unwrap_or_default();
    SiteUiConfig {
        is_managed: ctx.mode.is_managed(),
        safety_enabled: ctx.policy.is_enabled(),
        default_dinov3_min: pol.similarity.dinov3_min,
        default_siglip2_min: pol.similarity.siglip2_min,
        notice_banner_enabled: notice_html.is_some(),
        notice_banner_html: notice_html,
        notice_banner_key: notice_key,
        rta_meta_enabled: pol.legal.rta_meta_enabled,
        noindex_restricted: pol.legal.noindex_restricted,
        age_policy: pol.age_policy,
        age_gate_trigger: pol.age_gate_trigger,
        caller_authenticated: ctx.caller.is_authenticated(),
        caller_age_verified: ctx.caller.age_verified,
        caller_terms_accepted: ctx.caller.terms_accepted,
    }
}

#[cfg(feature = "ssr")]
fn build_site_ui_config_from_context() -> SiteUiConfig {
    if let Some(parts) = use_context::<axum::http::request::Parts>()
        && let Some(ctx) = parts.extensions.get::<state::RequestSafetyContext>()
    {
        return build_site_ui_config(ctx);
    }
    if let Some(st) = use_context::<state::AppState>()
        && let Ok(ctx) = state::RequestSafetyContext::from_leptos_context(&st)
    {
        return build_site_ui_config(&ctx);
    }
    SiteUiConfig::default()
}

#[server(endpoint = "site_config")]
pub async fn fetch_site_config() -> Result<SiteUiConfig, ServerFnError> {
    let Some(state) = use_context::<state::AppState>() else {
        return Ok(build_site_ui_config_from_context());
    };
    let ctx = state::RequestSafetyContext::from_leptos_context(&state)?;
    Ok(build_site_ui_config(&ctx))
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };

    #[tokio::test]
    async fn gallery_installs_the_allowance_listener_before_loading_media() {
        // Route discovery initializes the SSR runtime, as it does at server startup.
        leptos_axum::generate_route_list(App);
        let render = leptos_axum::render_app_to_stream(|| {
            shell(
                LeptosOptions::builder()
                    .output_name("lets-embed-web")
                    .build(),
            )
        });
        let response = render(Request::builder().uri("/").body(Body::empty()).unwrap()).await;
        let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        let (head, body) = html.split_once("</head>").expect("gallery document");
        assert!(head.contains(include_str!("../../../assets/gallery-allowance.js")));
        // Legal footer links are always present.
        assert!(body.contains(r#"href="/terms""#));
        assert!(body.contains(r#"href="/privacy""#));
        assert!(body.contains(r#"href="/dmca""#));
        assert!(body.contains(r#"href="/content-policy""#));
    }

    #[tokio::test]
    async fn ssr_title_never_interpolates_untrusted_query_parameters() {
        leptos_axum::generate_route_list(App);
        let render = leptos_axum::render_app_to_stream(|| {
            shell(
                LeptosOptions::builder()
                    .output_name("lets-embed-web")
                    .build(),
            )
        });
        let response = render(
            Request::builder()
                .uri("/?mode=tag&q=%3C%2Ftitle%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        let (head, _) = html.split_once("</head>").expect("gallery document");
        assert!(head.contains("<title>Let's Embed</title>"));
        assert!(!head.contains("<script>alert(1)</script>"));
    }

    #[tokio::test]
    async fn ssr_emits_rta_adult_meta_tags_in_shell_head_without_diverging_app_dom() {
        leptos_axum::generate_route_list(App);

        let render_with = |rta_enabled: bool, notice_enabled: bool| async move {
            let mut pol = site_access::PublicSitePolicy::default();
            pol.legal.rta_meta_enabled = rta_enabled;
            pol.legal.notice_banner_enabled = notice_enabled;
            pol.legal.notice_banner_md = String::new();
            pol.age_policy = AgeVerificationPolicy::SelfAttestation;
            pol.age_gate_trigger = AgeGateTrigger::SiteWideSplash;
            pol.refresh_policy_digest();
            let compiled = search_engine::CompiledPolicy::compile(pol).unwrap();
            let ctx = state::RequestSafetyContext::standalone(std::sync::Arc::new(compiled), false);

            let render = leptos_axum::render_app_to_stream(|| {
                shell(
                    LeptosOptions::builder()
                        .output_name("lets-embed-web")
                        .build(),
                )
            });
            let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
            req.extensions_mut().insert(ctx);
            let response = render(req).await;
            let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        };

        let html_on = render_with(true, true).await;
        let html_off = render_with(false, false).await;

        let (head_on, body_on) = html_on.split_once("</head>").expect("rta-on document");
        let (head_off, body_off) = html_off.split_once("</head>").expect("rta-off document");

        assert!(head_on.contains("RTA-5042-1996-1400-1577-RTA"));
        assert!(head_on.contains(r#"content="adult""#));
        assert!(!head_off.contains("RTA-5042-1996-1400-1577-RTA"));

        // Inside `<body>`, the `<App />` DOM before trailing `<script>` hydration payloads
        // MUST be 100% identical regardless of `rta_meta_enabled` / `notice_banner_enabled` /
        // `age_gate_trigger` so SSR and client hydration NEVER diverge!
        let app_dom_on = body_on.split("<script").next().unwrap_or(body_on);
        let app_dom_off = body_off.split("<script").next().unwrap_or(body_off);
        assert_eq!(app_dom_on, app_dom_off);
        assert!(!app_dom_on.contains("le-notice"));
        assert!(!app_dom_on.contains("le-age-gate-dialog"));
    }

    #[test]
    fn build_site_ui_config_uses_default_notice_banner_fallback_and_caller_flags() {
        let mut pol = site_access::PublicSitePolicy::default();
        pol.legal.notice_banner_enabled = true;
        pol.legal.notice_banner_md = "   ".to_string();
        pol.age_policy = AgeVerificationPolicy::SelfAttestation;
        pol.age_gate_trigger = AgeGateTrigger::JustInTime;
        pol.refresh_policy_digest();
        let compiled = std::sync::Arc::new(search_engine::CompiledPolicy::compile(pol).unwrap());

        let mut ctx = state::RequestSafetyContext::standalone(compiled, false);
        ctx.caller = search_engine::CallerContext {
            actor: site_access::ActorBinding::User {
                sub: "usr-42".into(),
                sid: "sid-42".into(),
            },
            age_verified: true,
            terms_accepted: false,
            ..search_engine::CallerContext::default()
        };

        let cfg = build_site_ui_config(&ctx);
        assert!(cfg.notice_banner_enabled);
        let html = cfg
            .notice_banner_html
            .as_deref()
            .expect("default notice banner HTML");
        assert!(html.contains("/content-policy"));
        assert!(html.contains("/user/account"));
        assert_eq!(
            cfg.notice_banner_key,
            site_access::compute_terms_digest(site_access::DEFAULT_NOTICE_BANNER_MD)
        );
        assert_eq!(cfg.age_policy, AgeVerificationPolicy::SelfAttestation);
        assert_eq!(cfg.age_gate_trigger, AgeGateTrigger::JustInTime);
        assert!(cfg.caller_authenticated);
        assert!(cfg.caller_age_verified);
        assert!(!cfg.caller_terms_accepted);
    }
}
