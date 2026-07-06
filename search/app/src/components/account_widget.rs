use leptos::{prelude::*, task::spawn_local};

/// Parsed subset of the user worker's `StatusResp` (`GET /user/api/me`).
///
/// Only the fields the header widget renders are kept.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
struct Account {
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

    let balance = json.get("balance").map(fmt_num).unwrap_or_else(|| "0".into());
    let plan = json
        .get("plan")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let views_remaining = json.get("views_remaining").and_then(|v| v.as_i64());
    let searches_remaining = json.get("searches_remaining").and_then(|v| v.as_i64());

    Ok(AccountState::Loaded(Account {
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
/// `/user/account`, with a hover-revealed float card showing points, plan and
/// remaining usage.
///
/// SSR renders a neutral placeholder; the browser resolves the real state
/// (signed-in stats or a sign-in link).
#[component]
pub fn AccountWidget() -> impl IntoView {
    // None = SSR placeholder / still loading in the browser.
    let state: RwSignal<Option<AccountState>> = RwSignal::new(None);

    // Effects only run in the browser, so this never fires on the server.
    Effect::new(move |_| {
        spawn_local(async move {
            let next = match call_me_api().await {
                Ok(s) => s,
                Err(e) => {
                    leptos::logging::error!("account status fetch failed: {e}");
                    AccountState::SignedOut
                }
            };
            // try_set: the component may have been disposed mid-flight.
            let _ = state.try_set(Some(next));
        });
    });

    // Shared card idiom for the float panel.
    // Outer wrapper handles positioning + hover reveal. Its `pt-2` is a
    // transparent bridge so moving the pointer from the chip into the card
    // doesn't cross a dead gap that would drop `group-hover`.
    let panel_cls = "absolute right-0 top-full pt-2 w-56 max-w-[calc(100vw-2rem)] z-50 \
        origin-top-right opacity-0 scale-95 pointer-events-none \
        group-hover:opacity-100 group-hover:scale-100 group-hover:pointer-events-auto \
        group-focus-within:opacity-100 group-focus-within:scale-100 \
        group-focus-within:pointer-events-auto transition-all duration-150";
    let card_cls = "bg-white/90 backdrop-blur-md rounded-2xl ring-1 ring-sky-200 \
        shadow-lg shadow-sky-200/50 p-4 text-sm text-slate-700";

    view! {
        <div class="relative group shrink-0">
            <a
                href="/user/account"
                rel="external"
                class="flex items-center gap-1.5 rounded-full py-2 px-3 bg-white/80 backdrop-blur-md
                    ring-1 ring-sky-200 shadow-sm shadow-sky-200/50 text-sky-600 font-medium
                    hover:ring-sky-300 hover:scale-105 transition-all cursor-pointer whitespace-nowrap"
                title="account"
            >
                <span class="text-lg leading-none select-none">"\u{1F464}"</span>
                {move || match state.get() {
                    Some(AccountState::Loaded(acc)) => view! {
                        <span class="tabular-nums">
                            <span class="select-none">"\u{1FA99} "</span>
                            {acc.balance.clone()}
                        </span>
                    }.into_any(),
                    Some(AccountState::SignedOut) => view! {
                        <span class="text-sky-500">"Sign in"</span>
                    }.into_any(),
                    None => view! {
                        <span class="text-sky-300 select-none">"\u{2026}"</span>
                    }.into_any(),
                }}
            </a>

            <div class=panel_cls>
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
                        }.into_any()
                    }
                    Some(AccountState::SignedOut) => view! {
                        <div class="flex flex-col gap-2">
                            <span class="text-slate-600">"You\u{2019}re not signed in."</span>
                            <a
                                href="/user/login"
                                rel="external"
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
