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
use crate::types::{SafetyUiState, SiteUiConfig};
use leptos::{prelude::*, task::spawn_local};
use leptos_meta::{HashedStylesheet, Link, Meta, MetaTags, provide_meta_context};
use leptos_router::{
    SsrMode,
    components::{ParentRoute, Route, Router, Routes},
    path,
};
use lets_embed_ui::{ReportDialog, ReportSubmission, ReportTargetKind};

pub const SITE_DESCRIPTION: &str = "Explore and search curated artwork and photo albums by title, artist, tags, CLIP descriptions, and visual similarity on Let's Embed.";

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
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
    #[cfg(feature = "ssr")]
    let initial_rta = build_site_ui_config_from_context().rta_meta_enabled;
    #[cfg(not(feature = "ssr"))]
    let initial_rta = false;

    provide_context(safety_ui);

    let site_config_res = OnceResource::new(async move { fetch_site_config().await.ok() });
    Effect::new(move |_| {
        if let Some(Some(cfg)) = site_config_res.get() {
            safety_ui.apply_site_config(&cfg);
        }
    });

    view! {
        <Meta property="og:site_name" content="Let's Embed"/>
        <Meta name="twitter:card" content="summary_large_image"/>
        {initial_rta.then(|| view! {
            <Meta name="rating" content="RTA-5042-1996-1400-1577-RTA"/>
            <Meta name="rating" content="adult"/>
        })}
        <Router>
            <div class="min-h-screen w-full flex flex-col overflow-x-clip bg-gradient-to-b from-sky-50 via-white to-sky-100">
                <main class="flex-1 w-full">
                    <Routes fallback=|| "Page not found.".into_view()>
                        <ParentRoute path=path!("") view=SearchBar>
                            <Route path=path!("/details/:id") view=ImageDetails ssr=SsrMode::Async/>
                            <Route path=path!("") view=|| view! { <Results /> } ssr=SsrMode::Async/>
                        </ParentRoute>
                    </Routes>
                </main>
                <footer class="w-full py-4 px-4 border-t border-sky-200/70 bg-white/60 text-xs text-slate-500">
                    <div class="max-w-[1640px] mx-auto flex flex-wrap items-center justify-between gap-2">
                        <span class="font-medium text-sky-800/80">"Let\u{2019}s Embed"</span>
                        <nav aria-label="Legal and policies" class="flex flex-wrap items-center gap-3">
                            <a href="/terms" rel="external" class="hover:text-sky-600 hover:underline">"Terms"</a>
                            <a href="/privacy" rel="external" class="hover:text-sky-600 hover:underline">"Privacy"</a>
                            <a href="/dmca" rel="external" class="hover:text-sky-600 hover:underline">"DMCA"</a>
                            <a href="/content-policy" rel="external" class="hover:text-sky-600 hover:underline">"Content Policy"</a>
                        </nav>
                    </div>
                </footer>
                <GlobalReportDialog />
            </div>
        </Router>
    }
}

#[cfg(feature = "ssr")]
fn build_site_ui_config(ctx: &state::RequestSafetyContext) -> SiteUiConfig {
    let pol = &ctx.policy.policy;
    let notice_html = if pol.legal.notice_banner_enabled && !pol.legal.notice_banner_md.trim().is_empty() {
        Some(legal::render_sanitized_markdown(&pol.legal.notice_banner_md))
    } else {
        None
    };
    let notice_key = if pol.legal.notice_banner_md.is_empty() {
        String::new()
    } else {
        site_access::compute_terms_digest(&pol.legal.notice_banner_md)
    };
    SiteUiConfig {
        is_managed: ctx.mode.is_managed(),
        safety_enabled: ctx.policy.is_enabled(),
        safe_mode: ctx.caller.safe_mode,
        default_dinov3_min: pol.similarity.dinov3_min,
        default_siglip2_min: pol.similarity.siglip2_min,
        notice_banner_enabled: pol.legal.notice_banner_enabled && notice_html.is_some(),
        notice_banner_html: notice_html,
        notice_banner_key: notice_key,
        rta_meta_enabled: pol.legal.rta_meta_enabled,
        noindex_restricted: pol.legal.noindex_restricted,
        panic_shortcut: pol.panic_shortcut.clone(),
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
    async fn ssr_emits_rta_adult_meta_tags_when_enabled_in_policy() {
        leptos_axum::generate_route_list(App);
        let mut pol = site_access::PublicSitePolicy::default();
        pol.legal.rta_meta_enabled = true;
        let compiled = search_engine::CompiledPolicy::compile_with_resolver(
            pol,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
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
        let html = std::str::from_utf8(&bytes).unwrap();
        let (head, _) = html.split_once("</head>").expect("gallery document");
        assert!(head.contains("RTA-5042-1996-1400-1577-RTA"));
        assert!(head.contains(r#"content="adult""#));
    }
}
