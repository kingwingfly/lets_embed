use crate::components::LikeStore;
use crate::types::SafetyUiState;
#[cfg(feature = "hydrate")]
use leptos::ev;
use leptos::{html, prelude::*, task::spawn_local};
#[cfg(feature = "hydrate")]
use leptos_use_event_listener::use_event_listener;
use lets_embed_ui::use_toast_store;
use site_access::AgeVerificationPolicy;

/// Parsed subset of the user worker's `MeResp` (`GET /user/api/me`).
///
/// Only the fields the header widget and account menu render are kept.
#[derive(Clone, Debug, PartialEq)]
struct Account {
    /// Authenticated wallet principal or fallback account identifier.
    address: Option<String>,
    /// Optional human-friendly display name (OAuth / Telegram / profile).
    display_name: Option<String>,
    /// Optional verified account email.
    email: Option<String>,
    /// Pay-as-you-go points balance.
    balance: String,
    /// Active plan name, or `None` when the user has no subscription plan.
    plan: Option<String>,
    /// Whether the user has opted into pay-as-you-go media credit spending.
    allow_paid_media: bool,
    /// Whether the account is currently restricted/banned.
    banned: bool,
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
    /// 401 / network error — offer a guest summary and sign-in link.
    SignedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlanTone {
    Active,
    PayAsYouGo,
    Free,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlanBadge {
    label: String,
    tone: PlanTone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AccountIdentity {
    primary: String,
    secondary: Option<String>,
    full_tooltip: Option<String>,
    avatar_initial: Option<char>,
    is_mono_primary: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UsageKind {
    Count,
    Depleted,
    Unlimited,
    NotApplicable,
}

/// Renders a JSON number as a compact string (integer when possible).
#[cfg_attr(not(any(feature = "hydrate", test)), allow(dead_code))]
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

/// Formats a numeric balance string with thousands separators (e.g. `"1250"` -> `"1,250"`).
fn fmt_points_display(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "0".to_string();
    }
    let (neg, unsigned) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };
    let (int_part, frac_part) = match unsigned.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (unsigned, None),
    };
    if !int_part.bytes().all(|b| b.is_ascii_digit()) || int_part.len() < 4 {
        return trimmed.to_string();
    }
    let mut grouped = String::with_capacity(int_part.len() + int_part.len() / 3 + 2);
    if neg {
        grouped.push('-');
    }
    let rem = int_part.len() % 3;
    for (idx, ch) in int_part.chars().enumerate() {
        if idx > 0 && (idx == rem || (idx > rem && (idx - rem) % 3 == 0)) {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    if let Some(frac) = frac_part {
        grouped.push('.');
        grouped.push_str(frac);
    }
    grouped
}

/// Formats a non-empty optional string field from JSON.
#[cfg_attr(not(any(feature = "hydrate", test)), allow(dead_code))]
fn json_non_empty_str(json: &serde_json::Value, key: &str) -> Option<String> {
    json.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// Parses `GET /user/api/me` JSON into [`Account`], tolerating minimal/legacy payloads.
#[cfg_attr(not(any(feature = "hydrate", test)), allow(dead_code))]
fn parse_account_json(text: &str) -> Result<Account, String> {
    let json: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let address = json_non_empty_str(&json, "address");
    let display_name = json_non_empty_str(&json, "display_name");
    let email = json_non_empty_str(&json, "email");
    let balance = json
        .get("balance")
        .map(fmt_num)
        .unwrap_or_else(|| "0".into());
    let plan = json_non_empty_str(&json, "plan");
    let allow_paid_media = json
        .get("allow_paid_media")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let banned = json
        .get("banned")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let views_remaining = json.get("views_remaining").and_then(|v| v.as_i64());
    let searches_remaining = json.get("searches_remaining").and_then(|v| v.as_i64());

    Ok(Account {
        address,
        display_name,
        email,
        balance,
        plan,
        allow_paid_media,
        banned,
        views_remaining,
        searches_remaining,
    })
}

/// Formats the subscription / billing tier badge label and tone (aligned with `/user/account`).
fn plan_badge_info(plan: Option<&str>, allow_paid_media: bool) -> PlanBadge {
    match plan.map(str::trim).filter(|s| !s.is_empty()) {
        Some(id) => {
            let mut chars = id.chars();
            let label = match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => "Free".to_string(),
            };
            PlanBadge {
                label,
                tone: PlanTone::Active,
            }
        }
        None if allow_paid_media => PlanBadge {
            label: "Pay-as-you-go".to_string(),
            tone: PlanTone::PayAsYouGo,
        },
        None => PlanBadge {
            label: "Free".to_string(),
            tone: PlanTone::Free,
        },
    }
}

/// Detects whether a principal string looks like a hex wallet, Solana pubkey, or opaque ID.
fn looks_like_wallet_or_id(raw: &str) -> bool {
    let s = raw.trim();
    if s.is_empty() || s.contains('@') || s.chars().any(char::is_whitespace) {
        return false;
    }
    if (s.starts_with("0x") || s.starts_with("0X")) && s.len() >= 16 {
        return true;
    }
    s.chars().count() > 18
}

/// Compacts long wallet addresses / opaque IDs (e.g. `0x71C7…89A2`) in a UTF-8-safe way.
fn shorten_principal(raw: &str) -> String {
    let s = raw.trim();
    if !looks_like_wallet_or_id(s) {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let head_len = if s.starts_with("0x") || s.starts_with("0X") {
        6
    } else {
        5
    };
    let tail_len = 4;
    if chars.len() <= head_len + tail_len + 1 {
        return s.to_string();
    }
    let head: String = chars[..head_len].iter().collect();
    let tail: String = chars[chars.len() - tail_len..].iter().collect();
    format!("{head}\u{2026}{tail}")
}

fn extract_avatar_initial(text: &str) -> Option<char> {
    let trimmed = text.trim();
    if looks_like_wallet_or_id(trimmed) {
        return None;
    }
    trimmed
        .chars()
        .find(|c| c.is_alphanumeric())
        .and_then(|c| c.to_uppercase().next())
}

/// Resolves display title, subtitle, tooltip, and avatar initial from an [`Account`].
fn resolve_identity(acc: &Account) -> AccountIdentity {
    let name = acc
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let email = acc
        .email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let addr = acc
        .address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(display_name) = name {
        let secondary = email
            .filter(|e| !e.eq_ignore_ascii_case(display_name))
            .map(ToOwned::to_owned)
            .or_else(|| {
                addr.filter(|a| !a.eq_ignore_ascii_case(display_name))
                    .map(shorten_principal)
            });
        let tooltip = addr
            .map(ToOwned::to_owned)
            .or_else(|| email.map(ToOwned::to_owned))
            .or_else(|| Some(display_name.to_string()));
        return AccountIdentity {
            primary: display_name.to_string(),
            secondary,
            full_tooltip: tooltip,
            avatar_initial: extract_avatar_initial(display_name)
                .or_else(|| email.and_then(extract_avatar_initial)),
            is_mono_primary: false,
        };
    }

    if let Some(mail) = email {
        let secondary = addr
            .filter(|a| !a.eq_ignore_ascii_case(mail))
            .map(shorten_principal);
        return AccountIdentity {
            primary: mail.to_string(),
            secondary,
            full_tooltip: Some(mail.to_string()),
            avatar_initial: extract_avatar_initial(mail),
            is_mono_primary: false,
        };
    }

    if let Some(raw_addr) = addr {
        let is_wallet = looks_like_wallet_or_id(raw_addr);
        return AccountIdentity {
            primary: shorten_principal(raw_addr),
            secondary: Some(if is_wallet {
                "Connected account".to_string()
            } else {
                "Signed in".to_string()
            }),
            full_tooltip: Some(raw_addr.to_string()),
            avatar_initial: extract_avatar_initial(raw_addr),
            is_mono_primary: is_wallet,
        };
    }

    AccountIdentity {
        primary: "My Account".to_string(),
        secondary: Some("Signed in".to_string()),
        full_tooltip: None,
        avatar_initial: None,
        is_mono_primary: false,
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

    if resp.status() == 401 || resp.status() == 404 {
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
    let account = parse_account_json(&text)?;
    Ok(AccountState::Loaded(account))
}

/// Server / non-browser stub: never called (effects only run in the browser),
/// keeps the ssr target compiling without browser APIs.
#[cfg(not(feature = "hydrate"))]
async fn call_me_api() -> Result<AccountState, String> {
    Err("account API is only available in the browser".to_string())
}

/// Same-origin sign-out call to `POST /user/api/logout` (browser only).
#[cfg(feature = "hydrate")]
async fn call_logout_api() -> Result<(), String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Headers, RequestInit, Response};

    let window = web_sys::window().ok_or("no window")?;
    let opts = RequestInit::new();
    opts.set_method("POST");

    let headers = Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Accept", "application/json")
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set(site_access::USER_CSRF_HEADER, "1")
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set("X-Requested-With", "fetch")
        .map_err(|e| format!("{e:?}"))?;
    opts.set_headers(&headers);

    let resp = JsFuture::from(window.fetch_with_str_and_init("/user/api/logout", &opts))
        .await
        .map_err(|e| format!("Network error: {e:?}"))?;
    let resp: Response = resp
        .dyn_into()
        .map_err(|_| "Unexpected response type".to_string())?;

    if resp.ok() || resp.status() == 401 {
        return Ok(());
    }

    let text = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    let msg = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.as_str())
                .map(ToOwned::to_owned)
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("Sign out failed (HTTP {})", resp.status()));
    Err(msg)
}

#[cfg(not(feature = "hydrate"))]
async fn call_logout_api() -> Result<(), String> {
    Err("sign out is only available in the browser".to_string())
}

/// Formats a usage line value given the plan context.
///
/// - `Some(n)` where `n > 0` → formatted remaining count.
/// - `Some(n)` where `n <= 0` → `"0"` with [`UsageKind::Depleted`].
/// - `None` with an active plan → `"Unlimited"`.
/// - `None` with no plan → `"—"`.
fn fmt_usage(remaining: Option<i64>, has_plan: bool) -> (String, UsageKind) {
    match remaining {
        Some(n) if n <= 0 => ("0".to_string(), UsageKind::Depleted),
        Some(n) => (fmt_points_display(&n.to_string()), UsageKind::Count),
        None if has_plan => ("Unlimited".to_string(), UsageKind::Unlimited),
        None => ("\u{2014}".to_string(), UsageKind::NotApplicable),
    }
}

/// Account entry for the site header: a compact points chip with a click/tap-revealed
/// frosted sky-glass popover card showing identity, tier, points, remaining usage,
/// grouped quick navigation, and sign-in/sign-out controls.
///
/// SSR renders a neutral placeholder; the browser resolves the real state
/// (signed-in stats or guest sign-in prompt) and keeps [`LikeStore`] synced across
/// wallet switches or sign-in in another tab.
#[component]
pub fn AccountWidget() -> impl IntoView {
    let state: RwSignal<Option<AccountState>> = RwSignal::new(None);
    let open = RwSignal::new(false);
    let signing_out = RwSignal::new(false);
    let root_ref: NodeRef<html::Div> = NodeRef::new();
    let trigger_ref: NodeRef<html::Button> = NodeRef::new();
    let like_store = use_context::<LikeStore>();
    let safety = use_context::<SafetyUiState>();
    let toast = use_toast_store();
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

    // Revalidate session on tab focus / bfcache restore, and close the dropdown when
    // clicking/tapping anywhere outside `root_ref` or pressing Esc.
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
            if open.get_untracked()
                && ev.key() == "Escape"
                && !ev.is_composing()
                && ev.key_code() != 229
            {
                open.set(false);
                if let Some(btn) = trigger_ref.get_untracked() {
                    let _ = btn.focus();
                }
            }
        });
    }

    let on_sign_out = move |_| {
        if signing_out.get_untracked() {
            return;
        }
        signing_out.set(true);
        spawn_local(async move {
            match call_logout_api().await {
                Ok(()) => {
                    if let Some(store) = like_store {
                        store.sync_principal(None);
                    }
                    #[cfg(feature = "hydrate")]
                    {
                        lets_embed_ui::browser::wipe_media_elements_in(None);
                    }
                    crate::broadcast_safety_invalidation("logout");
                    if let Some(s) = safety {
                        let _ = s.caller_authenticated.try_set(false);
                        let _ = s.caller_age_verified.try_set(false);
                        let _ = s.invalidation_epoch.try_update(|e| *e = e.wrapping_add(1));
                        let _ = s.reload_epoch.try_update(|e| *e = e.wrapping_add(1));
                    }
                    let _ = state.try_set(Some(AccountState::SignedOut));
                    let _ = open.try_set(false);
                    toast.info("Signed out", None);
                }
                Err(msg) => {
                    toast.error("Sign out failed", Some(msg));
                }
            }
            let _ = signing_out.try_set(false);
        });
    };

    let panel_cls = move || {
        let base = "absolute right-0 top-full pt-2.5 w-[min(320px,calc(100vw-1.5rem))] z-[60] \
            origin-top-right";
        if open.get() {
            format!("{base} opacity-100 translate-y-0 scale-100 pointer-events-auto visible")
        } else {
            format!("{base} opacity-0 -translate-y-1.5 scale-[0.97] pointer-events-none invisible")
        }
    };
    let card_cls = "web-account-menu-card relative rounded-2xl bg-white \
        border border-sky-200/80 overflow-hidden text-sm text-slate-700 \
        max-h-[calc(100dvh-5.5rem)] overflow-y-auto overscroll-contain";

    view! {
        <div node_ref=root_ref class="web-account-widget relative flex items-center gap-1.5 shrink-0">
            {move || matches!(state.get(), Some(AccountState::Loaded(_))).then(|| view! {
                <a
                    href="/user/favorites"
                    rel="external"
                    class="web-account-favorites-btn inline-flex items-center gap-1.5 rounded-full py-1.5 sm:py-2 px-2.5 sm:px-3
                        bg-white/85 backdrop-blur-md ring-1 ring-sky-200 shadow-xs shadow-sky-200/50
                        text-sky-700 font-medium hover:bg-amber-50/75 hover:ring-amber-300/80 hover:text-amber-600
                        active:scale-95 transition-all whitespace-nowrap"
                    title="Favorites"
                    aria-label="Favorites"
                >
                    <svg
                        class="w-3.5 h-3.5 text-amber-400 shrink-0"
                        viewBox="0 0 20 20"
                        fill="currentColor"
                        aria-hidden="true"
                    >
                        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                    </svg>
                    <span class="hidden sm:inline text-sm">"Favorites"</span>
                </a>
            })}
            <button
                node_ref=trigger_ref
                type="button"
                aria-haspopup="true"
                aria-expanded=move || open.get().to_string()
                aria-controls="account-menu-panel"
                on:click=move |_| open.update(|o| *o = !*o)
                class=move || {
                    let base = "web-account-trigger inline-flex items-center gap-1.5 rounded-full py-1 sm:py-1.5 pl-1.5 sm:pl-2 pr-2 sm:pr-2.5 \
                        backdrop-blur-md font-medium active:scale-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/80 \
                        transition-all cursor-pointer whitespace-nowrap";
                    if open.get() {
                        format!("{base} is-open bg-sky-50/95 ring-1 ring-sky-400 shadow-sm shadow-sky-200/70 text-sky-800")
                    } else {
                        format!("{base} bg-white/85 ring-1 ring-sky-200 shadow-xs shadow-sky-200/50 text-sky-700 hover:ring-sky-300 hover:bg-sky-50/60")
                    }
                }
                title="Account"
            >
                {move || match state.get() {
                    Some(AccountState::Loaded(acc)) => {
                        let identity = resolve_identity(&acc);
                        let balance_txt = fmt_points_display(&acc.balance);
                        view! {
                            <span class="w-6 h-6 rounded-full bg-gradient-to-br from-sky-400 via-blue-500 to-indigo-500 text-white
                                flex items-center justify-center shrink-0 shadow-xs shadow-sky-300/50">
                                {match identity.avatar_initial {
                                    Some(ch) => view! {
                                        <span class="font-display text-[11px] font-bold leading-none select-none">
                                            {ch.to_string()}
                                        </span>
                                    }.into_any(),
                                    None => view! {
                                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" aria-hidden="true">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0" />
                                        </svg>
                                    }.into_any(),
                                }}
                            </span>
                            <span class="web-account-balance inline-flex items-center gap-1 tabular-nums text-xs sm:text-sm font-semibold text-sky-900">
                                <svg class="w-3.5 h-3.5 text-amber-500 shrink-0" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm.75-11.25a.75.75 0 00-1.5 0v.336a2.75 2.75 0 00-.45 5.39l1.39.348a1.25 1.25 0 01-.19 2.463h-.5a1.25 1.25 0 01-1.158-.782.75.75 0 10-1.39.564A2.75 2.75 0 009.25 16.71v.29a.75.75 0 001.5 0v-.336a2.75 2.75 0 00.45-5.39l-1.39-.348a1.25 1.25 0 01.19-2.463h.5c.51 0 .969.308 1.158.782a.75.75 0 001.39-.564 2.75 2.75 0 00-2.298-1.641v-.29z" clip-rule="evenodd" />
                                </svg>
                                <span>{balance_txt}</span>
                            </span>
                        }.into_any()
                    }
                    Some(AccountState::SignedOut) => view! {
                        <span class="w-6 h-6 rounded-full bg-sky-100 text-sky-600 flex items-center justify-center shrink-0">
                            <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0" />
                            </svg>
                        </span>
                        <span class="web-account-signin-label text-sky-600 text-xs sm:text-sm font-semibold">"Sign in"</span>
                    }.into_any(),
                    None => view! {
                        <span class="w-6 h-6 rounded-full bg-sky-100/90 text-sky-400 flex items-center justify-center shrink-0">
                            <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0" />
                            </svg>
                        </span>
                        <span class="web-account-loading text-sky-300 select-none text-sm leading-none">"\u{2026}"</span>
                    }.into_any(),
                }}
                <svg
                    class=move || {
                        let rot = if open.get() { "rotate-180 text-sky-600" } else { "text-sky-400" };
                        format!("w-3 h-3 shrink-0 transition-transform duration-200 {rot}")
                    }
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2.4"
                    aria-hidden="true"
                >
                    <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
            </button>

            <div
                id="account-menu-panel"
                class=move || format!("web-account-menu {}", panel_cls())
                aria-hidden=move || (!open.get()).to_string()
                inert=move || !open.get()
            >
                <div class=card_cls>
                {move || match state.get() {
                    Some(AccountState::Loaded(acc)) => {
                        let has_plan = acc.plan.is_some();
                        let plan_badge = plan_badge_info(acc.plan.as_deref(), acc.allow_paid_media);
                        let identity = resolve_identity(&acc);
                        let balance_txt = fmt_points_display(&acc.balance);
                        let (views_txt, views_kind) = fmt_usage(acc.views_remaining, has_plan);
                        let (searches_txt, searches_kind) = fmt_usage(acc.searches_remaining, has_plan);
                        let banned = acc.banned;

                        let plan_badge_cls = match plan_badge.tone {
                            PlanTone::Active => {
                                "web-account-row web-account-row--plan inline-flex items-center gap-1 px-2 py-0.5 rounded-full \
                                 text-[10.5px] font-semibold bg-gradient-to-r from-sky-100 to-indigo-100 text-sky-800 \
                                 ring-1 ring-sky-300/75 whitespace-nowrap"
                            }
                            PlanTone::PayAsYouGo => {
                                "web-account-row web-account-row--plan inline-flex items-center gap-1 px-2 py-0.5 rounded-full \
                                 text-[10.5px] font-semibold bg-sky-100/85 text-sky-700 \
                                 ring-1 ring-sky-200/90 whitespace-nowrap"
                            }
                            PlanTone::Free => {
                                "web-account-row web-account-row--plan inline-flex items-center gap-1 px-2 py-0.5 rounded-full \
                                 text-[10.5px] font-medium bg-white/90 text-slate-600 \
                                 ring-1 ring-sky-200/80 whitespace-nowrap"
                            }
                        };

                        let primary_cls = if identity.is_mono_primary {
                            "text-[12.5px] font-mono font-semibold text-sky-950 truncate leading-snug"
                        } else {
                            "text-[13.5px] font-semibold text-sky-950 truncate leading-snug"
                        };

                        let views_val_cls = match views_kind {
                            UsageKind::Unlimited => "text-[13px] font-semibold text-emerald-600 leading-tight",
                            UsageKind::Count => "text-[14px] font-bold tabular-nums text-sky-950 leading-tight",
                            UsageKind::Depleted => "text-[14px] font-bold tabular-nums text-amber-600 leading-tight",
                            UsageKind::NotApplicable => "text-[13.5px] font-medium text-slate-400 leading-tight",
                        };
                        let searches_val_cls = match searches_kind {
                            UsageKind::Unlimited => "text-[13px] font-semibold text-emerald-600 leading-tight",
                            UsageKind::Count => "text-[14px] font-bold tabular-nums text-sky-950 leading-tight",
                            UsageKind::Depleted => "text-[14px] font-bold tabular-nums text-amber-600 leading-tight",
                            UsageKind::NotApplicable => "text-[13.5px] font-medium text-slate-400 leading-tight",
                        };

                        let dot_cls = if banned {
                            "absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-rose-500 ring-2 ring-white"
                        } else {
                            "absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-emerald-400 ring-2 ring-white"
                        };

                        let show_safety = safety.is_some_and(|s| s.safety_enabled.get());
                        let age_policy = safety
                            .map(|s| s.age_policy.get())
                            .unwrap_or(AgeVerificationPolicy::Off);
                        let age_verified = safety.is_some_and(|s| s.caller_age_verified.get());
                        let show_age_chip = show_safety && age_policy != AgeVerificationPolicy::Off;

                        view! {
                            // Frosted Sky Identity & Summary Header
                            <div class="web-account-header px-4 pt-4 pb-3.5 border-b border-sky-100/90">
                                <div class="flex items-center gap-3 min-w-0">
                                    <div class="web-account-avatar relative w-10 h-10 rounded-full shrink-0
                                        bg-gradient-to-br from-sky-400 via-blue-500 to-indigo-500 text-white
                                        shadow-sm shadow-sky-300/60 ring-2 ring-white flex items-center justify-center">
                                        {match identity.avatar_initial {
                                            Some(ch) => view! {
                                                <span class="font-display text-base font-bold leading-none select-none">
                                                    {ch.to_string()}
                                                </span>
                                            }.into_any(),
                                            None => view! {
                                                <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                                    <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0" />
                                                </svg>
                                            }.into_any(),
                                        }}
                                        <span class=dot_cls aria-hidden="true" />
                                    </div>

                                    <div class="min-w-0 flex-1">
                                        <div class=primary_cls title=identity.full_tooltip.clone()>
                                            {identity.primary}
                                        </div>
                                        {identity.secondary.map(|sub| view! {
                                            <div class="text-[11.5px] text-slate-500 truncate leading-tight mt-0.5">
                                                {sub}
                                            </div>
                                        })}
                                        <div class="flex flex-wrap items-center gap-1.5 mt-1.5">
                                            <span class=plan_badge_cls>
                                                {(plan_badge.tone == PlanTone::Active).then(|| view! {
                                                    <svg class="w-2.5 h-2.5 text-sky-600 shrink-0" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                                                    </svg>
                                                })}
                                                <span>{plan_badge.label}</span>
                                            </span>
                                            {(show_age_chip && age_verified).then(|| view! {
                                                <span class="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-semibold
                                                    bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200/80 whitespace-nowrap">
                                                    "18+"
                                                </span>
                                            })}
                                            {banned.then(|| view! {
                                                <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold
                                                    bg-rose-50 text-rose-700 ring-1 ring-rose-200/80 whitespace-nowrap">
                                                    "Restricted"
                                                </span>
                                            })}
                                        </div>
                                    </div>
                                </div>

                                // Points Balance Highlight Card
                                <div class="web-account-row web-account-row--points web-account-stat-tile mt-3 flex items-center justify-between gap-2 px-3 py-2 rounded-xl">
                                    <div class="flex items-center gap-2 min-w-0">
                                        <span class="w-7 h-7 rounded-lg bg-amber-50 ring-1 ring-amber-200/75 text-amber-500 flex items-center justify-center shrink-0">
                                            <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm.75-11.25a.75.75 0 00-1.5 0v.336a2.75 2.75 0 00-.45 5.39l1.39.348a1.25 1.25 0 01-.19 2.463h-.5a1.25 1.25 0 01-1.158-.782.75.75 0 10-1.39.564A2.75 2.75 0 009.25 16.71v.29a.75.75 0 001.5 0v-.336a2.75 2.75 0 00.45-5.39l-1.39-.348a1.25 1.25 0 01.19-2.463h.5c.51 0 .969.308 1.158.782a.75.75 0 001.39-.564 2.75 2.75 0 00-2.298-1.641v-.29z" clip-rule="evenodd" />
                                            </svg>
                                        </span>
                                        <div class="min-w-0">
                                            <div class="text-[11px] font-medium text-sky-700/75 leading-tight">"Points"</div>
                                            <div class="text-[15px] font-bold tabular-nums text-sky-950 leading-tight mt-0.5">
                                                {balance_txt}
                                            </div>
                                        </div>
                                    </div>
                                    <a
                                        href="/user/account#topup"
                                        rel="external"
                                        on:click=move |_| open.set(false)
                                        class="web-account-action web-account-action--topup shrink-0 inline-flex items-center gap-1 px-2.5 py-1
                                            rounded-full text-[11px] font-semibold text-sky-700 bg-sky-50/95 hover:bg-sky-100
                                            ring-1 ring-sky-200/90 hover:ring-sky-300 transition-colors whitespace-nowrap"
                                    >
                                        <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
                                        </svg>
                                        <span>"Top up"</span>
                                    </a>
                                </div>

                                // 2-Column Allowance Summary Tiles
                                <div class="mt-2 grid grid-cols-2 gap-2">
                                    <div class="web-account-row web-account-row--views web-account-stat-tile rounded-xl px-2.5 py-2 flex flex-col gap-1 min-w-0">
                                        <div class="flex items-center gap-1 text-[11px] font-medium text-slate-500">
                                            <svg class="w-3.5 h-3.5 text-sky-500 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                            </svg>
                                            <span class="truncate">"Views left"</span>
                                        </div>
                                        <span class=views_val_cls>{views_txt}</span>
                                    </div>

                                    <div class="web-account-row web-account-row--searches web-account-stat-tile rounded-xl px-2.5 py-2 flex flex-col gap-1 min-w-0">
                                        <div class="flex items-center gap-1 text-[11px] font-medium text-slate-500">
                                            <svg class="w-3.5 h-3.5 text-indigo-500 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                                            </svg>
                                            <span class="truncate">"Searches left"</span>
                                        </div>
                                        <span class=searches_val_cls>{searches_txt}</span>
                                    </div>
                                </div>
                            </div>

                            // Grouped Navigation Rows
                            <nav aria-label="Account navigation" class="web-account-nav p-2 flex flex-col gap-0.5">
                                <a
                                    href="/user/favorites"
                                    rel="external"
                                    on:click=move |_| open.set(false)
                                    class="web-account-action web-account-action--favorites group flex items-center gap-2.5 px-2.5 py-2 rounded-xl
                                        text-[13px] font-medium text-slate-700 hover:bg-sky-50/90 hover:text-sky-900 transition-colors"
                                >
                                    <span class="w-7 h-7 rounded-lg bg-amber-50 text-amber-500 group-hover:bg-amber-100/90
                                        flex items-center justify-center shrink-0 transition-colors">
                                        <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                                        </svg>
                                    </span>
                                    <span class="flex-1 truncate">"Favorites"</span>
                                    <svg class="w-3.5 h-3.5 text-slate-300 group-hover:text-sky-500 group-hover:translate-x-0.5 transition-all shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true">
                                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7" />
                                    </svg>
                                </a>

                                <a
                                    href="/user/account#device-login"
                                    rel="external"
                                    on:click=move |_| open.set(false)
                                    class="web-account-action web-account-action--device-login group flex items-center gap-2.5 px-2.5 py-2 rounded-xl
                                        text-[13px] font-medium text-slate-700 hover:bg-sky-50/90 hover:text-sky-900 transition-colors"
                                >
                                    <span class="w-7 h-7 rounded-lg bg-sky-50 text-sky-600 group-hover:bg-sky-100/90
                                        flex items-center justify-center shrink-0 transition-colors">
                                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" aria-hidden="true">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 006 3.75v16.5a2.25 2.25 0 002.25 2.25h7.5A2.25 2.25 0 0018 20.25V3.75a2.25 2.25 0 00-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" />
                                        </svg>
                                    </span>
                                    <span class="flex-1 truncate">"QR / Phone sign-in"</span>
                                    <svg class="w-3.5 h-3.5 text-slate-300 group-hover:text-sky-500 group-hover:translate-x-0.5 transition-all shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true">
                                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7" />
                                    </svg>
                                </a>

                                {show_safety.then(|| view! {
                                    <a
                                        href="/user/account#content-safety"
                                        rel="external"
                                        on:click=move |_| open.set(false)
                                        class="web-account-action web-account-action--safety group flex items-center gap-2.5 px-2.5 py-2 rounded-xl
                                            text-[13px] font-medium text-slate-700 hover:bg-sky-50/90 hover:text-sky-900 transition-colors"
                                    >
                                        <span class="w-7 h-7 rounded-lg bg-indigo-50 text-indigo-500 group-hover:bg-indigo-100/90
                                            flex items-center justify-center shrink-0 transition-colors">
                                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" aria-hidden="true">
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                                            </svg>
                                        </span>
                                        <span class="flex-1 truncate">"Content & safety"</span>
                                        {show_age_chip.then(|| if age_verified {
                                            view! {
                                                <span class="px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200/80 whitespace-nowrap">
                                                    "18+ on"
                                                </span>
                                            }.into_any()
                                        } else {
                                            view! {
                                                <span class="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-sky-50 text-sky-700 ring-1 ring-sky-200/80 whitespace-nowrap">
                                                    "Verify 18+"
                                                </span>
                                            }.into_any()
                                        })}
                                        <svg class="w-3.5 h-3.5 text-slate-300 group-hover:text-sky-500 group-hover:translate-x-0.5 transition-all shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7" />
                                        </svg>
                                    </a>
                                })}
                            </nav>

                            <div class="mx-3 h-px bg-gradient-to-r from-transparent via-sky-200/80 to-transparent" />

                            // Primary CTA & Sign-out Footer
                            <div class="web-account-footer p-2.5 flex flex-col gap-1.5">
                                <a
                                    href="/user/account"
                                    rel="external"
                                    on:click=move |_| open.set(false)
                                    class="web-account-action web-account-action--details w-full flex items-center justify-center gap-2
                                        rounded-xl py-2 px-4 text-[13px] font-semibold text-white
                                        bg-gradient-to-r from-sky-400 via-blue-500 to-indigo-500
                                        shadow-sm shadow-sky-300/60 hover:brightness-105 active:scale-[0.98] transition-all"
                                >
                                    <svg class="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                        <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 6h9.75M10.5 6a1.5 1.5 0 11-3 0m3 0a1.5 1.5 0 10-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-9.75 0h9.75" />
                                    </svg>
                                    <span>"Account details"</span>
                                </a>

                                <button
                                    type="button"
                                    disabled=move || signing_out.get()
                                    on:click=on_sign_out
                                    class="web-account-action web-account-action--signout w-full flex items-center justify-center gap-1.5
                                        rounded-xl py-1.5 px-3 text-xs font-medium text-slate-500
                                        hover:bg-rose-50/90 hover:text-rose-600 active:scale-[0.99]
                                        disabled:opacity-50 disabled:cursor-not-allowed transition-colors cursor-pointer"
                                >
                                    {move || if signing_out.get() {
                                        view! {
                                            <span
                                                class="inline-block w-3.5 h-3.5 rounded-full border-2 border-rose-300 border-t-rose-500 animate-spin"
                                                aria-hidden="true"
                                            />
                                            <span>"Signing out\u{2026}"</span>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
                                            </svg>
                                            <span>"Sign out"</span>
                                        }.into_any()
                                    }}
                                </button>
                            </div>
                        }.into_any()
                    }
                    Some(AccountState::SignedOut) => view! {
                        <div class="web-account-signed-out">
                            <div class="web-account-header px-4 pt-4 pb-3.5 border-b border-sky-100/90">
                                <div class="flex items-center gap-3">
                                    <div class="web-account-avatar w-10 h-10 rounded-full shrink-0
                                        bg-gradient-to-br from-sky-100 to-indigo-100 text-sky-600
                                        ring-2 ring-white shadow-xs flex items-center justify-center">
                                        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" aria-hidden="true">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0" />
                                        </svg>
                                    </div>
                                    <div class="min-w-0 flex-1">
                                        <div class="flex items-center gap-1.5 flex-wrap">
                                            <span class="font-display font-semibold text-sky-950 text-[15px] leading-tight">
                                                "Guest"
                                            </span>
                                            <span class="px-2 py-0.5 rounded-full text-[10.5px] font-medium bg-white/90 text-slate-500 ring-1 ring-sky-200/80">
                                                "Not signed in"
                                            </span>
                                        </div>
                                        <p class="text-xs text-slate-500 leading-relaxed mt-1 mb-0">
                                            "Sign in to save favorites, check points, and sync across devices."
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <div class="p-3 flex flex-col gap-2.5">
                                <div class="grid grid-cols-2 gap-1.5 text-[11.5px] text-slate-600">
                                    <div class="web-account-stat-tile flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl">
                                        <svg class="w-3.5 h-3.5 text-amber-400 shrink-0" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                                        </svg>
                                        <span class="truncate font-medium">"Save favorites"</span>
                                    </div>
                                    <div class="web-account-stat-tile flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl">
                                        <svg class="w-3.5 h-3.5 text-sky-500 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 006 3.75v16.5a2.25 2.25 0 002.25 2.25h7.5A2.25 2.25 0 0018 20.25V3.75a2.25 2.25 0 00-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3" />
                                        </svg>
                                        <span class="truncate font-medium">"Device sync"</span>
                                    </div>
                                </div>

                                <a
                                    href="/user/login"
                                    rel="external"
                                    on:click=move |_| open.set(false)
                                    class="web-account-action web-account-action--signin w-full flex items-center justify-center gap-2
                                        rounded-xl py-2.5 px-4 text-[13.5px] font-semibold text-white
                                        bg-gradient-to-r from-sky-400 via-blue-500 to-indigo-500
                                        shadow-sm shadow-sky-300/60 hover:brightness-105 active:scale-[0.98] transition-all"
                                >
                                    <svg class="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" />
                                    </svg>
                                    <span>"Sign in"</span>
                                </a>
                            </div>
                        </div>
                    }.into_any(),
                    None => view! {
                        <div class="web-account-loading" role="status" aria-live="polite">
                            <div class="web-account-header px-4 pt-4 pb-3.5 border-b border-sky-100/80">
                                <div class="flex items-center gap-3 animate-pulse">
                                    <div class="w-10 h-10 rounded-full bg-sky-200/70 shrink-0" />
                                    <div class="flex-1 space-y-2">
                                        <div class="h-3.5 w-28 rounded-full bg-sky-200/70" />
                                        <div class="h-2.5 w-16 rounded-full bg-sky-100" />
                                    </div>
                                </div>
                            </div>
                            <div class="p-3.5 flex items-center gap-2 text-xs text-sky-600/80">
                                <span
                                    class="inline-block w-3.5 h-3.5 rounded-full border-2 border-sky-200 border-t-sky-500 animate-spin shrink-0"
                                    aria-hidden="true"
                                />
                                <span>"Loading account\u{2026}"</span>
                            </div>
                        </div>
                    }.into_any(),
                }}
                </div>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_points_with_thousands_separators_and_decimals() {
        assert_eq!(fmt_points_display("0"), "0");
        assert_eq!(fmt_points_display("42"), "42");
        assert_eq!(fmt_points_display("999"), "999");
        assert_eq!(fmt_points_display("1000"), "1,000");
        assert_eq!(fmt_points_display("12500"), "12,500");
        assert_eq!(fmt_points_display("1234567.25"), "1,234,567.25");
        assert_eq!(fmt_points_display("-2500"), "-2,500");
        assert_eq!(fmt_points_display("  "), "0");
    }

    #[test]
    fn formats_plan_badges_for_active_payg_and_free() {
        assert_eq!(
            plan_badge_info(Some("pro"), false),
            PlanBadge {
                label: "Pro".to_string(),
                tone: PlanTone::Active,
            }
        );
        assert_eq!(
            plan_badge_info(None, true),
            PlanBadge {
                label: "Pay-as-you-go".to_string(),
                tone: PlanTone::PayAsYouGo,
            }
        );
        assert_eq!(
            plan_badge_info(None, false),
            PlanBadge {
                label: "Free".to_string(),
                tone: PlanTone::Free,
            }
        );
        assert_eq!(
            plan_badge_info(Some("   "), false),
            PlanBadge {
                label: "Free".to_string(),
                tone: PlanTone::Free,
            }
        );
    }

    #[test]
    fn formats_usage_counts_depleted_unlimited_and_na() {
        assert_eq!(fmt_usage(Some(1250), true), ("1,250".to_string(), UsageKind::Count));
        assert_eq!(fmt_usage(Some(0), true), ("0".to_string(), UsageKind::Depleted));
        assert_eq!(fmt_usage(None, true), ("Unlimited".to_string(), UsageKind::Unlimited));
        assert_eq!(fmt_usage(None, false), ("\u{2014}".to_string(), UsageKind::NotApplicable));
    }

    #[test]
    fn parses_legacy_and_full_me_json_payloads() {
        let legacy = r#"{"address":"0x71C7656EC7ab88b098defB751B7401B5f6d8976F","balance":1200,"plan":null,"views_remaining":25,"searches_remaining":null}"#;
        let acc = parse_account_json(legacy).expect("legacy me json parses");
        assert_eq!(acc.balance, "1200");
        assert_eq!(acc.plan, None);
        assert!(!acc.allow_paid_media);
        assert!(!acc.banned);
        assert_eq!(acc.views_remaining, Some(25));
        assert_eq!(acc.searches_remaining, None);

        let full = r#"{
            "address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
            "display_name": "Kira",
            "email": "kira@example.com",
            "balance": 4500.5,
            "plan": "plus",
            "allow_paid_media": true,
            "banned": false,
            "views_remaining": null,
            "searches_remaining": 40
        }"#;
        let acc = parse_account_json(full).expect("full me json parses");
        assert_eq!(acc.display_name.as_deref(), Some("Kira"));
        assert_eq!(acc.email.as_deref(), Some("kira@example.com"));
        assert_eq!(acc.balance, "4500.5");
        assert_eq!(acc.plan.as_deref(), Some("plus"));
        assert!(acc.allow_paid_media);
        assert_eq!(acc.views_remaining, None);
        assert_eq!(acc.searches_remaining, Some(40));
    }

    #[test]
    fn resolves_friendly_identity_and_compacts_wallets() {
        let eth_only = Account {
            address: Some("0x71C7656EC7ab88b098defB751B7401B5f6d8976F".into()),
            display_name: None,
            email: None,
            balance: "0".into(),
            plan: None,
            allow_paid_media: false,
            banned: false,
            views_remaining: None,
            searches_remaining: None,
        };
        let id = resolve_identity(&eth_only);
        assert_eq!(id.primary, "0x71C7\u{2026}976F");
        assert_eq!(id.secondary.as_deref(), Some("Connected account"));
        assert_eq!(id.avatar_initial, None);
        assert!(id.is_mono_primary);

        let named = Account {
            address: Some("0x71C7656EC7ab88b098defB751B7401B5f6d8976F".into()),
            display_name: Some("kira".into()),
            email: Some("kira@example.com".into()),
            balance: "100".into(),
            plan: Some("pro".into()),
            allow_paid_media: false,
            banned: false,
            views_remaining: None,
            searches_remaining: None,
        };
        let id = resolve_identity(&named);
        assert_eq!(id.primary, "kira");
        assert_eq!(id.secondary.as_deref(), Some("kira@example.com"));
        assert_eq!(id.avatar_initial, Some('K'));
        assert!(!id.is_mono_primary);
    }
}
