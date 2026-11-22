use crate::components::LikeStore;
#[cfg(feature = "hydrate")]
use leptos::ev;
use leptos::{html, prelude::*, task::spawn_local};
#[cfg(feature = "hydrate")]
use leptos_use_event_listener::use_event_listener;

/// Parsed subset of the user worker's `StatusResp` (`GET /user/api/me`).
///
/// Only the fields the header widget renders are kept.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
struct Account {
    /// Authenticated wallet principal (lowercase eth address or Solana pubkey).
    address: Option<String>,
    /// Pay-as-you-go points balance.
    balance: String,
    /// Active plan name, or `None` when the user has no plan.
    plan: Option<String>,
    /// Remaining media views: `Some(n)` a hard count, `None` = unlimited (plan)
    /// or not-applicable (no plan). Interpretation depends on `plan`.
    views_remaining: Option<i64>,
    /// Remaining similarity searches, same semantics as `views_remaining`.
    searches_remaining: Option<i64>,
}

/// Outcome of resolving the account status in the browser.
#[derive(Clone)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
enum AccountState {
    /// 200 — signed in, stats resolved.
    Loaded(Account),
    /// 401 / network error — offer a sign-in link instead of stats.
    SignedOut,
}

/// Renders a JSON number as a compact string (integer when possible).
#[cfg(feature = "hydrate")]
fn fmt_num(v: &serde_json::Value) -> String {
    if let Some(i) = v.as_i64() {
        i.to_string()
    } else if let Some(f) = v.as_f64() {
        // Trim trailing zeros for a tidy display.
        let s = format!("{f:.4}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        "0".to_string()
    }
}

/// Same-origin fetch of the account status (browser only).
#[cfg(feature = "hydrate")]
async fn call_me_api() -> Result<AccountState, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestInit, Response};

    let window = web_sys::window().ok_or("no window")?;
    let opts = RequestInit::new();
    opts.set_method("GET");

    let resp = JsFuture::from(window.fetch_with_str_and_init("/user/api/me", &opts))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let resp: Response = resp
        .dyn_into()
        .map_err(|_| "fetch result is not a Response".to_string())?;

    if resp.status() == 401 {
        return Ok(AccountState::SignedOut);
    }
    if !resp.ok() {
        return Err(format!("unexpected status {}", resp.status()));
    }

    let text = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("{e:?}"))?
        .as_string()
        .unwrap_or_default();
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;

    let address = json
        .get("address")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let balance = json
        .get("balance")
        .map(fmt_num)
        .unwrap_or_else(|| "0".into());
    let plan = json
        .get("plan")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let views_remaining = json.get("views_remaining").and_then(|v| v.as_i64());
    let searches_remaining = json.get("searches_remaining").and_then(|v| v.as_i64());

    Ok(AccountState::Loaded(Account {
        address,
        balance,
        plan,
        views_remaining,
        searches_remaining,
    }))
}

/// Server / non-browser stub: never called (effects only run in the browser),
/// keeps the ssr target compiling without browser APIs.
#[cfg(not(feature = "hydrate"))]
async fn call_me_api() -> Result<AccountState, String> {
    Err("account API is only available in the browser".to_string())
}

/// Formats a usage line value given the plan context.
///
/// - `Some(n)` → the remaining count.
/// - `None` with an active plan → "unlimited".
/// - `None` with no plan → "—".
fn fmt_usage(remaining: Option<i64>, has_plan: bool) -> String {
    match remaining {
        Some(n) => n.to_string(),
        None if has_plan => "unlimited".to_string(),
        None => "\u{2014}".to_string(),
    }
}

/// Account entry for the site header: a compact points chip linking to
/// `/user/account`, with a click/tap-revealed float card showing points, plan and
/// remaining usage.
///
/// SSR renders a neutral placeholder; the browser resolves the real state
/// (signed-in stats or a sign-in link) and keeps [`LikeStore`] synced across
/// wallet switches or sign-in in another tab.
#[component]
pub fn AccountWidget() -> impl IntoView {
    let state: RwSignal<Option<AccountState>> = RwSignal::new(None);
    let open = RwSignal::new(false);
    let root_ref: NodeRef<html::Div> = NodeRef::new();
    let like_store = use_context::<LikeStore>();
    let last_refresh: StoredValue<f64> = StoredValue::new(0.0);

    let refresh = move |force: bool| {
        let now = js_sys::Date::now();
        if !force && now - last_refresh.get_value() < 2000.0 {
            return;
        }
        last_refresh.set_value(now);
        spawn_local(async move {
            let next = match call_me_api().await {
                Ok(s) => s,
                Err(e) => {
                    leptos::logging::error!("account status fetch failed: {e}");
                    AccountState::SignedOut
                }
            };
            if let Some(store) = like_store {
                match &next {
                    AccountState::Loaded(acc) => store.sync_principal(acc.address.clone()),
                    AccountState::SignedOut => store.sync_principal(None),
                }
            }
            let _ = state.try_set(Some(next));
        });
    };

    // Initial account resolve in browser.
    Effect::new(move |_| {
        refresh(true);
    });

    // Revalidate wallet session on tab focus / bfcache restore, and close the
    // dropdown when clicking/tapping anywhere outside `root_ref` or pressing Esc.
    // (Avoids a `fixed inset-0` backdrop, which would be trapped inside SearchBar's
    // `backdrop-blur-md` containing block.)
    #[cfg(feature = "hydrate")]
    {
        let _ = use_event_listener(window(), ev::focus, move |_| refresh(false));
        let _ = use_event_listener(window(), ev::pageshow, move |_| {
            open.set(false);
            refresh(false);
        });
        let _ = use_event_listener(window(), ev::pointerdown, move |ev: ev::PointerEvent| {
            if !open.get_untracked() {
                return;
            }
            use wasm_bindgen::JsCast;
            let inside = root_ref.get().is_some_and(|root| {
                ev.target()
                    .and_then(|t| t.dyn_into::<web_sys::Node>().ok())
                    .is_some_and(|node| root.contains(Some(&node)))
            });
            if !inside {
                open.set(false);
            }
        });
        let _ = use_event_listener(window(), ev::keydown, move |ev: ev::KeyboardEvent| {
            if open.get_untracked() && ev.key() == "Escape" {
                open.set(false);
            }
        });
    }

    let panel_cls = move || {
        let base = "absolute right-0 top-full pt-2 w-56 max-w-[calc(100vw-2rem)] z-50 \
            origin-top-right transition-all duration-150";
        if open.get() {
            format!("{base} opacity-100 scale-100 pointer-events-auto visible")
        } else {
            format!("{base} opacity-0 scale-95 pointer-events-none invisible")
        }
    };
    let card_cls = "bg-white/95 backdrop-blur-md rounded-2xl ring-1 ring-sky-200 \
        shadow-lg shadow-sky-200/50 p-4 text-sm text-slate-700";

    view! {
        <div node_ref=root_ref class="relative flex items-center gap-1.5 shrink-0">
            {move || matches!(state.get(), Some(AccountState::Loaded(_))).then(|| view! {
                <a
                    href="/user/favorites"
                    rel="external"
                    class="flex items-center gap-1 rounded-full py-1.5 sm:py-2 px-2.5 sm:px-3 bg-white/85 backdrop-blur-md
                        ring-1 ring-sky-200 shadow-sm shadow-sky-200/50 text-sky-600 font-medium
                        hover:ring-sky-300 hover:text-amber-500 hover:scale-105 transition-all whitespace-nowrap"
                    title="Favorites"
                    aria-label="Favorites"
                >
                    <span class="text-amber-500 leading-none select-none">"\u{2605}"</span>
                    <span class="hidden sm:inline text-sm">"Favorites"</span>
                </a>
            })}
            <button
                type="button"
                aria-haspopup="true"
                aria-expanded=move || open.get().to_string()
                aria-controls="account-menu-panel"
                on:click=move |_| open.update(|o| *o = !*o)
                class="flex items-center gap-1.5 rounded-full py-1.5 sm:py-2 px-2.5 sm:px-3 bg-white/80 backdrop-blur-md
                    ring-1 ring-sky-200 shadow-sm shadow-sky-200/50 text-sky-600 font-medium
                    hover:ring-sky-300 hover:scale-105 transition-all cursor-pointer whitespace-nowrap"
                title="Account"
            >
                <span class="text-base sm:text-lg leading-none select-none">"\u{1F464}"</span>
                {move || match state.get() {
                    Some(AccountState::Loaded(acc)) => view! {
                        <span class="tabular-nums text-sm">
                            <span class="select-none">"\u{1FA99} "</span>
                            {acc.balance.clone()}
                        </span>
                    }.into_any(),
                    Some(AccountState::SignedOut) => view! {
                        <span class="text-sky-500 text-sm">"Sign in"</span>
                    }.into_any(),
                    None => view! {
                        <span class="text-sky-300 select-none">"\u{2026}"</span>
                    }.into_any(),
                }}
            </button>

            <div
                id="account-menu-panel"
                class=panel_cls
                aria-hidden=move || (!open.get()).to_string()
                inert=move || !open.get()
            >
                <div class=card_cls>
                {move || match state.get() {
                    Some(AccountState::Loaded(acc)) => {
                        let has_plan = acc.plan.is_some();
                        let plan = acc.plan.clone().unwrap_or_else(|| "none".to_string());
                        let views = fmt_usage(acc.views_remaining, has_plan);
                        let searches = fmt_usage(acc.searches_remaining, has_plan);
                        view! {
                            <div class="flex items-center justify-between gap-2">
                                <span class="text-sky-500">"Points"</span>
                                <span class="font-semibold tabular-nums text-slate-800">
                                    {acc.balance.clone()}
                                </span>
                            </div>
                            <div class="flex items-center justify-between gap-2 mt-2">
                                <span class="text-sky-500">"Plan"</span>
                                <span class="font-medium text-slate-800 truncate max-w-[8rem]">
                                    {plan}
                                </span>
                            </div>
                            <div class="my-2 h-px bg-gradient-to-r from-transparent via-sky-200 to-transparent" />
                            <div class="flex items-center justify-between gap-2">
                                <span class="text-sky-500">"Views left"</span>
                                <span class="tabular-nums text-slate-800">{views}</span>
                            </div>
                            <div class="flex items-center justify-between gap-2 mt-1">
                                <span class="text-sky-500">"Searches left"</span>
                                <span class="tabular-nums text-slate-800">{searches}</span>
                            </div>
                            <a
                                href="/user/favorites"
                                rel="external"
                                on:click=move |_| open.set(false)
                                class="block text-center mt-3 bg-sky-50 ring-1 ring-sky-200
                                    text-sky-700 font-medium rounded-full py-1.5 px-4
                                    hover:bg-sky-100 transition-all"
                            >
                                "\u{2605} Favorites"
                            </a>
                            <a
                                href="/user/account#device-login"
                                rel="external"
                                on:click=move |_| open.set(false)
                                class="block text-center mt-2 bg-sky-50 ring-1 ring-sky-200
                                    text-sky-700 font-medium rounded-full py-1.5 px-4
                                    hover:bg-sky-100 transition-all"
                            >
                                "QR / Phone sign-in"
                            </a>
                            <a
                                href="/user/account"
                                rel="external"
                                on:click=move |_| open.set(false)
                                class="block text-center mt-2 bg-gradient-to-r from-sky-400 to-blue-500
                                    text-white font-medium rounded-full py-1.5 px-4 shadow-sm shadow-sky-300/60
                                    hover:from-sky-500 hover:to-blue-600 transition-all"
                            >
                                "Account details"
                            </a>
                        }.into_any()
                    }
                    Some(AccountState::SignedOut) => view! {
                        <div class="flex flex-col gap-2">
                            <span class="text-slate-600">"You\u{2019}re not signed in."</span>
                            <a
                                href="/user/login"
                                rel="external"
                                on:click=move |_| open.set(false)
                                class="text-center bg-gradient-to-r from-sky-400 to-blue-500 text-white
                                    font-medium rounded-full py-1.5 px-4 shadow-sm shadow-sky-300/60
                                    hover:from-sky-500 hover:to-blue-600 transition-all"
                            >
                                "Sign in"
                            </a>
                        </div>
                    }.into_any(),
                    None => view! {
                        <span class="text-sky-300">"Loading\u{2026}"</span>
                    }.into_any(),
                }}
                </div>
            </div>
        </div>
    }
}
