//! Policy v3 Click-to-Reveal card for `ProjectedImage::Blurred` and `ProjectedVideo::Blurred`.
//!
//! Zero clear URLs are ever present in SSR HTML or hydration state before an explicit
//! user click succeeds against `POST /api/safety/reveal` (with `X-Requested-With: fetch`).

use crate::types::{SafetyUiState, preset_to_ui};
use leptos::{ev, prelude::*, task::spawn_local};
use lets_embed_ui::use_toast_store;
use search_types::{MediaKind, PlaceholderPreset, RevealRequest, RevealResponse};

#[derive(Debug)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
enum RevealFetchError {
    PolicyStale(String),
    Message(String),
}

#[cfg(feature = "hydrate")]
async fn request_click_reveal(req: &RevealRequest) -> Result<RevealResponse, RevealFetchError> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Headers, RequestInit, Response};

    let window = web_sys::window()
        .ok_or_else(|| RevealFetchError::Message("Browser window unavailable".to_string()))?;

    let opts = RequestInit::new();
    opts.set_method("POST");

    let headers = Headers::new()
        .map_err(|_| RevealFetchError::Message("Failed creating request headers".to_string()))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|_| RevealFetchError::Message("Failed setting Content-Type".to_string()))?;
    headers
        .set("X-Requested-With", "fetch")
        .map_err(|_| RevealFetchError::Message("Failed setting CSRF header".to_string()))?;
    opts.set_headers(&headers);

    let body = serde_json::to_string(req)
        .map_err(|e| RevealFetchError::Message(format!("Failed serializing reveal request: {e}")))?;
    opts.set_body(&JsValue::from_str(&body));

    let resp_val = JsFuture::from(window.fetch_with_str_and_init("/api/safety/reveal", &opts))
        .await
        .map_err(|_| RevealFetchError::Message("Network error while revealing media".to_string()))?;
    let resp: Response = resp_val
        .dyn_into()
        .map_err(|_| RevealFetchError::Message("Unexpected response from server".to_string()))?;

    let status = resp.status();
    let text = JsFuture::from(
        resp.text()
            .map_err(|_| RevealFetchError::Message(format!("HTTP {status}")))?,
    )
    .await
    .ok()
    .and_then(|v| v.as_string())
    .unwrap_or_default();

    if status == 409 {
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .and_then(|m| m.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| "Safety policy updated; refreshing view.".to_string());
        return Err(RevealFetchError::PolicyStale(msg));
    }

    if !resp.ok() {
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .or_else(|| v.get("error"))
                    .and_then(|m| m.as_str())
                    .map(ToOwned::to_owned)
            })
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| match status {
                403 => "You do not have permission to reveal this item.".to_string(),
                404 => "This media item could not be found.".to_string(),
                429 => "Too many reveal requests — please wait a moment.".to_string(),
                _ => format!("Reveal failed (HTTP {status})."),
            });
        return Err(RevealFetchError::Message(msg));
    }

    serde_json::from_str::<RevealResponse>(&text)
        .map_err(|_| RevealFetchError::Message("Invalid reveal response payload".to_string()))
}

#[cfg(not(feature = "hydrate"))]
async fn request_click_reveal(_req: &RevealRequest) -> Result<RevealResponse, RevealFetchError> {
    Err(RevealFetchError::Message(
        "Click-to-reveal is only available in the browser.".to_string(),
    ))
}

/// Interactive Policy v3 blurred media card supporting both images and videos.
///
/// - Displays the fixed server-blurred `preview_url` (when available) or a frosted veil.
/// - On `"Click to reveal"`, calls `POST /api/safety/reveal` with `X-Requested-With: fetch`.
/// - On success, displays the freshly minted short-lived `clear_url` (and offers a `"Hide"` pill).
/// - On error, surfaces a GCP top-right floating toast via [`lets_embed_ui::ToastStore`].
/// - Automatically re-hides and evicts revealed URLs when `SafetyUiState.invalidation_epoch` bumps.
#[component]
pub fn BlurredMediaCard(
    kind: MediaKind,
    asset_id: i64,
    width: i32,
    height: i32,
    #[prop(optional)] preview_url: Option<String>,
    can_click_reveal: bool,
    policy_rev: u64,
    #[prop(into)] label: String,
    preset: PlaceholderPreset,
    #[prop(optional, into)] alt: String,
    #[prop(default = false)] compact: bool,
    #[prop(optional)] on_open: Option<Callback<()>>,
) -> impl IntoView {
    let safety = use_context::<SafetyUiState>();
    let toast = use_toast_store();

    let revealed_url: RwSignal<Option<String>> = RwSignal::new(None);
    let revealing = RwSignal::new(false);

    if let Some(s) = safety {
        let last_epoch = StoredValue::new(s.invalidation_epoch.get_untracked());
        Effect::new(move |_| {
            let cur = s.invalidation_epoch.get();
            if cur != last_epoch.get_value() {
                last_epoch.set_value(cur);
                revealed_url.set(None);
                revealing.set(false);
            }
        });
    }

    let (w, h) = if width > 0 && height > 0 {
        (width, height)
    } else if kind == MediaKind::Video {
        (16, 9)
    } else {
        (4, 3)
    };
    let aspect_style = format!("aspect-ratio:{w}/{h};");

    let ui_preset = preset_to_ui(preset);
    let badge_text = ui_preset.short_badge();
    let display_label = if label.trim().is_empty() {
        ui_preset.label().to_string()
    } else {
        label
    };
    let effective_alt = if alt.trim().is_empty() {
        match kind {
            MediaKind::Image => format!("Image #{asset_id}"),
            MediaKind::Video => format!("Video #{asset_id}"),
        }
    } else {
        alt
    };

    let on_reveal_click = move |ev: ev::MouseEvent| {
        ev.stop_propagation();
        if !can_click_reveal || revealing.get_untracked() {
            return;
        }
        revealing.set(true);
        let req = RevealRequest {
            kind,
            asset_id,
            policy_rev,
        };
        spawn_local(async move {
            match request_click_reveal(&req).await {
                Ok(resp) => {
                    let _ = revealed_url.try_set(Some(resp.clear_url));
                }
                Err(RevealFetchError::PolicyStale(msg)) => {
                    toast.warning("Safety policy updated", Some(msg));
                    if let Some(s) = safety {
                        let _ = s.reload_epoch.try_update(|e| *e = e.wrapping_add(1));
                    }
                }
                Err(RevealFetchError::Message(msg)) => {
                    toast.error("Unable to reveal media", Some(msg));
                }
            }
            let _ = revealing.try_set(false);
        });
    };

    let preview_stored = StoredValue::new(preview_url);
    let label_stored = StoredValue::new(display_label);
    let alt_stored = StoredValue::new(effective_alt);

    let root_cls = if compact {
        "le-spoiler le-spoiler--compact w-full relative overflow-hidden"
    } else {
        "le-spoiler w-full relative overflow-hidden"
    };

    view! {
        <div class=root_cls style=aspect_style>
            {move || {
                if let Some(clear_src) = revealed_url.get() {
                    let alt_text = alt_stored.get_value();
                    match kind {
                        MediaKind::Image => {
                            let img_view = if let Some(open_cb) = on_open {
                                view! {
                                    <button
                                        type="button"
                                        class="block w-full h-full p-0 border-0 bg-transparent cursor-zoom-in focus-visible:outline-2 focus-visible:outline-sky-400"
                                        on:click=move |ev: ev::MouseEvent| {
                                            ev.stop_propagation();
                                            open_cb.run(());
                                        }
                                    >
                                        <img
                                            loading="lazy"
                                            decoding="async"
                                            width=w
                                            height=h
                                            alt=alt_text
                                            src=clear_src
                                            class="block w-full h-full object-cover select-none"
                                        />
                                    </button>
                                }
                                .into_any()
                            } else {
                                view! {
                                    <img
                                        loading="lazy"
                                        decoding="async"
                                        width=w
                                        height=h
                                        alt=alt_text
                                        src=clear_src
                                        class="block w-full h-full object-cover select-none"
                                    />
                                }
                                .into_any()
                            };
                            view! {
                                <div class="relative w-full h-full">
                                    {img_view}
                                    <button
                                        type="button"
                                        title="Re-hide blurred media"
                                        class="absolute bottom-2 left-2 z-10 px-2.5 py-0.5 rounded-full text-[11px] font-semibold
                                               bg-slate-900/75 hover:bg-slate-900 text-white backdrop-blur-xs ring-1 ring-white/20
                                               transition-colors cursor-pointer"
                                        on:click=move |ev: ev::MouseEvent| {
                                            ev.stop_propagation();
                                            revealed_url.set(None);
                                        }
                                    >
                                        "Hide"
                                    </button>
                                </div>
                            }
                            .into_any()
                        }
                        MediaKind::Video => view! {
                            <div
                                class="relative w-full h-full bg-black"
                                on:click=|ev: ev::MouseEvent| ev.stop_propagation()
                            >
                                <video
                                    class="w-full h-full block bg-black object-contain select-none"
                                    controls
                                    playsinline
                                    preload="metadata"
                                    src=clear_src
                                />
                                <button
                                    type="button"
                                    title="Re-hide blurred video"
                                    class="absolute bottom-2 left-2 z-10 px-2.5 py-0.5 rounded-full text-[11px] font-semibold
                                           bg-slate-900/80 hover:bg-slate-900 text-white backdrop-blur-xs ring-1 ring-white/20
                                           transition-colors cursor-pointer"
                                    on:click=move |ev: ev::MouseEvent| {
                                        ev.stop_propagation();
                                        revealed_url.set(None);
                                    }
                                >
                                    "Hide"
                                </button>
                            </div>
                        }
                        .into_any(),
                    }
                } else {
                    let preview = preview_stored.get_value();
                    let lbl = label_stored.get_value();
                    let alt_text = alt_stored.get_value();
                    let preset_slug = ui_preset.as_str();
                    view! {
                        <div class="relative w-full h-full flex items-center justify-center bg-gradient-to-br from-slate-800 via-slate-900 to-sky-950 select-none">
                            {preview.filter(|u| !u.is_empty()).map(|purl| view! {
                                <img
                                    loading="lazy"
                                    decoding="async"
                                    src=purl
                                    alt=alt_text
                                    class="absolute inset-0 w-full h-full object-cover scale-105 opacity-90 pointer-events-none"
                                />
                            })}
                            <div class="absolute inset-0 bg-slate-950/45 backdrop-blur-sm pointer-events-none" />
                            <div class="relative z-10 flex flex-col items-center justify-center text-center gap-1.5 px-3 py-2 max-w-[92%]">
                                <span class=format!(
                                    "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide \
                                     bg-white/15 text-sky-100 ring-1 ring-white/25 backdrop-blur-xs le-blurred-badge--{preset_slug}"
                                )>
                                    {badge_text}
                                </span>
                                <span class="text-xs sm:text-sm font-semibold text-white drop-shadow-xs line-clamp-2">
                                    {lbl}
                                </span>
                                {if can_click_reveal {
                                    view! {
                                        <button
                                            type="button"
                                            prop:disabled=move || revealing.get()
                                            class="mt-1 inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-semibold
                                                   bg-white/95 hover:bg-white text-slate-900 shadow-md shadow-black/30
                                                   active:scale-95 disabled:opacity-65 disabled:cursor-wait transition-all cursor-pointer"
                                            on:click=on_reveal_click
                                        >
                                            {move || if revealing.get() {
                                                "Revealing\u{2026}"
                                            } else if kind == MediaKind::Video {
                                                "Click to reveal video"
                                            } else {
                                                "Click to reveal"
                                            }}
                                        </button>
                                    }
                                    .into_any()
                                } else {
                                    view! {
                                        <a
                                            href="/user/account"
                                            rel="external"
                                            class="mt-1 inline-flex items-center gap-1 px-3 py-1 rounded-full text-[11px] font-semibold
                                                   bg-white/15 hover:bg-white/25 text-white ring-1 ring-white/30 backdrop-blur-xs
                                                   transition-colors"
                                            on:click=|ev: ev::MouseEvent| ev.stop_propagation()
                                        >
                                            "Manage content settings"
                                        </a>
                                    }
                                    .into_any()
                                }}
                            </div>
                        </div>
                    }
                    .into_any()
                }
            }}
        </div>
    }
}
