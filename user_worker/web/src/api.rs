//! Typed HTTP client & DTOs for `user_worker` APIs and `/api/like_previews`.
#![allow(dead_code)]

use leptos::prelude::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use site_access::{AssuranceLevel, AuthProviderPublicConfig, PolicyRef, PublicSitePolicy};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCredentials, RequestInit, RequestMode, Response};

pub const SAFETY_INVALIDATE_STORAGE_KEY: &str = "lets-embed:safety-invalidate";

#[derive(Clone, Debug)]
pub struct ApiErr {
    pub status: u16,
    pub message: String,
    pub body: String,
}

impl ApiErr {
    pub fn display(&self) -> String {
        if self.message.is_empty() {
            format!("Request failed (HTTP {})", self.status)
        } else {
            self.message.clone()
        }
    }
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    #[serde(default)]
    error: Option<String>,
}

async fn send_request(
    method: &str,
    url: &str,
    json_body: Option<String>,
) -> Result<(u16, String), ApiErr> {
    let win = web_sys::window().ok_or_else(|| ApiErr {
        status: 0,
        message: "Browser window unavailable.".into(),
        body: String::new(),
    })?;
    let init = RequestInit::new();
    init.set_method(method);
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::SameOrigin);

    let headers = Headers::new().map_err(|_| ApiErr {
        status: 0,
        message: "Failed to construct request headers.".into(),
        body: String::new(),
    })?;
    let _ = headers.set("Accept", "application/json");
    let _ = headers.set("X-Requested-With", "fetch");
    if let Some(body) = json_body {
        let _ = headers.set("Content-Type", "application/json");
        init.set_body(&wasm_bindgen::JsValue::from_str(&body));
    }
    init.set_headers(&headers);

    let req = Request::new_with_str_and_init(url, &init).map_err(|_| ApiErr {
        status: 0,
        message: "Failed to build HTTP request.".into(),
        body: String::new(),
    })?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|_| ApiErr {
            status: 0,
            message: "Network error — please check your connection.".into(),
            body: String::new(),
        })?;
    let resp: Response = resp_val.dyn_into().map_err(|_| ApiErr {
        status: 0,
        message: "Invalid HTTP response.".into(),
        body: String::new(),
    })?;
    let status = resp.status();
    let text = match resp.text() {
        Ok(p) => JsFuture::from(p)
            .await
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default(),
        Err(_) => String::new(),
    };
    if !(200..300).contains(&status) {
        let msg = serde_json::from_str::<ErrorEnvelope>(&text)
            .ok()
            .and_then(|e| e.error)
            .unwrap_or_else(|| {
                if text.trim().is_empty() {
                    format!("Request failed (HTTP {status})")
                } else {
                    text.trim().chars().take(200).collect()
                }
            });
        return Err(ApiErr {
            status,
            message: msg,
            body: text,
        });
    }
    Ok((status, text))
}

pub async fn get_json<T: DeserializeOwned>(url: &str) -> Result<T, ApiErr> {
    let (status, text) = send_request("GET", url, None).await?;
    serde_json::from_str(&text).map_err(|e| ApiErr {
        status,
        message: format!("Failed to decode response: {e}"),
        body: text,
    })
}

pub async fn post_json<B: Serialize, T: DeserializeOwned>(url: &str, body: &B) -> Result<T, ApiErr> {
    let payload = serde_json::to_string(body).map_err(|e| ApiErr {
        status: 0,
        message: format!("Failed to encode request: {e}"),
        body: String::new(),
    })?;
    let (status, text) = send_request("POST", url, Some(payload)).await?;
    serde_json::from_str(&text).map_err(|e| ApiErr {
        status,
        message: format!("Failed to decode response: {e}"),
        body: text,
    })
}

pub async fn post_empty(url: &str) -> Result<(), ApiErr> {
    let _ = send_request("POST", url, None).await?;
    Ok(())
}

pub async fn post_json_empty<B: Serialize>(url: &str, body: &B) -> Result<(), ApiErr> {
    let payload = serde_json::to_string(body).map_err(|e| ApiErr {
        status: 0,
        message: format!("Failed to encode request: {e}"),
        body: String::new(),
    })?;
    let _ = send_request("POST", url, Some(payload)).await?;
    Ok(())
}

pub async fn delete_json<B: Serialize, T: DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<T, ApiErr> {
    let payload = serde_json::to_string(body).map_err(|e| ApiErr {
        status: 0,
        message: format!("Failed to encode request: {e}"),
        body: String::new(),
    })?;
    let (status, text) = send_request("DELETE", url, Some(payload)).await?;
    serde_json::from_str(&text).map_err(|e| ApiErr {
        status,
        message: format!("Failed to decode response: {e}"),
        body: text,
    })
}

pub async fn delete_json_empty<B: Serialize>(url: &str, body: &B) -> Result<(), ApiErr> {
    let payload = serde_json::to_string(body).map_err(|e| ApiErr {
        status: 0,
        message: format!("Failed to encode request: {e}"),
        body: String::new(),
    })?;
    let _ = send_request("DELETE", url, Some(payload)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// API Wire DTOs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct BootstrapResp {
    pub siwe_domain: String,
    pub public_url: String,
    pub chain_id: u64,
    pub policy: PublicSitePolicy,
    pub policy_digest: String,
    pub signed_in: bool,
    pub deposit_open: bool,
    pub points_per_usd: i64,
    pub minimum_topup: i64,
    #[serde(default)]
    pub signup_points: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NonceResp {
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdentityView {
    pub provider_id: String,
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub verified_email: Option<String>,
    #[serde(default)]
    pub assurance_level: AssuranceLevel,
    #[serde(default)]
    pub assurance_method: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PlanView {
    pub id: String,
    pub price_points: i64,
    pub views_per_window: Option<i64>,
    pub searches_per_window: i64,
    pub period_days: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PricingItemView {
    pub kind: String,
    pub label: String,
    pub price: i64,
    pub daily_free: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PricingSummary {
    pub points_per_usd: i64,
    pub minimum_topup: i64,
    pub signup_points: i64,
    pub dedupe_hours: u64,
    pub eth_deposit: String,
    pub sol_deposit: String,
    pub plans: Vec<PlanView>,
    pub items: Vec<PricingItemView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SwitcherEligibility {
    pub id: String,
    pub grant_generation: u64,
    pub opted_in: bool,
    pub effective: bool,
    pub country_excluded: bool,
    #[serde(default)]
    pub missing_requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MeResp {
    pub address: String,
    pub balance: i64,
    pub plan: Option<String>,
    pub period_end: u64,
    pub views_remaining: Option<i64>,
    pub searches_remaining: Option<i64>,
    pub window_reset: u64,
    pub banned: bool,
    pub total_views: i64,
    #[serde(default)]
    pub allow_paid_media: bool,
    pub user_id: String,
    pub account_do_key: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub identities: Vec<IdentityView>,
    pub linked_eth_address: Option<String>,
    pub linked_solana_address: Option<String>,
    #[serde(default)]
    pub enabled_switchers: Vec<PolicyRef>,
    #[serde(default)]
    pub effective_switchers: Vec<PolicyRef>,
    #[serde(default)]
    pub switcher_statuses: Vec<SwitcherEligibility>,
    #[serde(default = "default_pref_version")]
    pub pref_version: u64,
    pub terms_version_accepted: Option<u32>,
    pub terms_digest_accepted: Option<String>,
    pub terms_accepted_at: Option<u64>,
    pub terms_up_to_date: bool,
    #[serde(default)]
    pub accepted_current_terms: bool,
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
    pub session_auth_time: Option<u64>,
    pub can_link_identity_now: bool,
    pub available_providers: Vec<AuthProviderPublicConfig>,
    pub policy: PublicSitePolicy,
    pub pricing: PricingSummary,
}

fn default_pref_version() -> u64 {
    1
}

#[derive(Clone, Debug, Deserialize)]
pub struct QrMatrix {
    pub size: usize,
    pub bits: String,
}

impl QrMatrix {
    pub fn to_svg(&self) -> String {
        let quiet = 4usize;
        let dim = self.size + quiet * 2;
        let mut rects = String::new();
        let bytes = self.bits.as_bytes();
        for y in 0..self.size {
            let row_start = y * self.size;
            for x in 0..self.size {
                if bytes.get(row_start + x).is_some_and(|&b| b == b'1' || b == b'#') {
                    let rx = x + quiet;
                    let ry = y + quiet;
                    rects.push_str(&format!(
                        r##"<rect x="{rx}" y="{ry}" width="1" height="1" fill="#0c4a6e"/>"##
                    ));
                }
            }
        }
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges"><rect width="{dim}" height="{dim}" fill="#ffffff"/>{rects}</svg>"##
        )
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TelegramStartResp {
    pub auth_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HandoffStartResp {
    pub session_id: String,
    pub poll_secret: String,
    pub verify_code: String,
    pub approve_url: String,
    pub expires_in: u64,
    pub qr: Option<QrMatrix>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HandoffInfoResp {
    pub status: String,
    pub verify_code: String,
    pub approve_nonce: String,
    pub expires_in: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HandoffPollResp {
    pub status: String,
    #[serde(default)]
    pub address: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TransferCreateResp {
    pub code: String,
    pub expires_in: u64,
    pub qr: Option<QrMatrix>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EmailStartResp {
    pub sent: bool,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EmailVerifyResp {
    pub user_id: String,
    pub action: String,
    pub next: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AcceptTermsConflictResp {
    pub error: String,
    pub terms_version: u32,
    pub terms_digest: String,
    pub terms_md: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AcceptTermsOkResp {
    pub terms_version_accepted: u32,
    pub terms_digest_accepted: String,
    pub terms_accepted_at: u64,
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AgeConfirmResp {
    pub ok: bool,
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
    pub age_verified: bool,
    #[serde(default)]
    pub effective_switchers: Vec<PolicyRef>,
    #[serde(default)]
    pub switcher_statuses: Vec<SwitcherEligibility>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PreferencesResp {
    #[serde(default)]
    pub enabled_switchers: Vec<PolicyRef>,
    #[serde(default)]
    pub effective_switchers: Vec<PolicyRef>,
    #[serde(default = "default_pref_version")]
    pub pref_version: u64,
    #[serde(default)]
    pub switcher_statuses: Vec<SwitcherEligibility>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BillingPreferencesResp {
    pub allow_paid_media: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PreferencesConflictResp {
    pub error: String,
    pub pref_version: u64,
    #[serde(default)]
    pub enabled_switchers: Vec<PolicyRef>,
    #[serde(default)]
    pub effective_switchers: Vec<PolicyRef>,
    #[serde(default)]
    pub switcher_statuses: Vec<SwitcherEligibility>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RevealResponse {
    pub clear_url: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LinkStartResp {
    pub authorize_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PaymentRow {
    pub tx_hash: String,
    pub chain: String,
    pub token: String,
    pub amount: String,
    pub points: String,
    pub status: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RatesResp {
    pub eth_usd: f64,
    pub sol_usd: f64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrepareCheckoutResp {
    pub sender: String,
    pub recipient: String,
    pub network: String,
    pub transaction: serde_json::Value,
    pub estimated_points: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TopupResp {
    pub credited_points: i64,
    pub balance: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LikeRow {
    pub kind: String,
    pub target_id: i64,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LikesResp {
    pub items: Vec<LikeRow>,
    pub next_cursor: Option<i64>,
}

// ---------------------------------------------------------------------------
// Browser Navigation & Query Helpers
// ---------------------------------------------------------------------------

pub fn current_pathname() -> String {
    web_sys::window()
        .and_then(|w| w.location().pathname().ok())
        .unwrap_or_else(|| "/user/login".to_string())
}

pub fn current_search_param(name: &str) -> Option<String> {
    let search = web_sys::window()?.location().search().ok()?;
    let params = web_sys::UrlSearchParams::new_with_str(&search).ok()?;
    params.get(name).filter(|s| !s.trim().is_empty())
}

pub fn current_hash() -> String {
    web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .unwrap_or_default()
}

pub fn scroll_to_element(id: &str) {
    if let Some(el) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id(id))
    {
        el.scroll_into_view();
    }
}

pub fn clear_hash_if_matches(expected_hash: &str) {
    let Some(win) = web_sys::window() else {
        return;
    };
    let current = win.location().hash().unwrap_or_default();
    if !current.eq_ignore_ascii_case(expected_hash) {
        return;
    }
    let path = win.location().pathname().unwrap_or_default();
    let search = win.location().search().unwrap_or_default();
    let clean_url = format!("{path}{search}");
    if let Ok(hist) = win.history() {
        let _ = hist.replace_state_with_url(&JsValue::NULL, "", Some(&clean_url));
    }
}

pub fn use_hash_change_listener(on_hash: impl Fn(String) + Clone + 'static) {
    if let Some(win) = web_sys::window() {
        let cb = Closure::<dyn Fn(web_sys::Event)>::new(move |_ev: web_sys::Event| {
            on_hash(current_hash());
        });
        let _ = win.add_event_listener_with_callback("hashchange", cb.as_ref().unchecked_ref());
        let win_clean = win.clone();
        let _ = StoredValue::new_local(LocalCleanup(Some(Box::new(move || {
            let _ = win_clean
                .remove_event_listener_with_callback("hashchange", cb.as_ref().unchecked_ref());
            drop(cb);
        }))));
    }
}

pub fn current_origin() -> String {
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default()
}

pub fn sanitize_next(raw: Option<&str>) -> String {
    let Some(s) = raw.map(str::trim) else {
        return "/".to_string();
    };
    if !s.starts_with('/')
        || s.starts_with("//")
        || s.contains('\\')
        || s.chars().any(char::is_control)
        || s.len() > 512
    {
        return "/".to_string();
    }
    let origin = current_origin();
    if !origin.is_empty() {
        match web_sys::Url::new_with_base(s, &origin) {
            Ok(resolved) if resolved.origin() == origin => {}
            _ => return "/".to_string(),
        }
    }
    s.to_string()
}

pub fn navigate_hard(url: &str) {
    if let Some(win) = web_sys::window() {
        let _ = win.location().assign(url);
    }
}

pub fn clear_search_param(name: &str) {
    let Some(win) = web_sys::window() else {
        return;
    };
    let search = win.location().search().unwrap_or_default();
    let Ok(params) = web_sys::UrlSearchParams::new_with_str(&search) else {
        return;
    };
    if !params.has(name) {
        return;
    }
    params.delete(name);
    let path = win.location().pathname().unwrap_or_default();
    let hash = win.location().hash().unwrap_or_default();
    let next_search: String = params.to_string().into();
    let clean_url = if next_search.is_empty() {
        format!("{path}{hash}")
    } else {
        format!("{path}?{next_search}{hash}")
    };
    if let Ok(hist) = win.history() {
        let _ = hist.replace_state_with_url(&JsValue::NULL, "", Some(&clean_url));
    }
}

pub fn format_number(n: i64) -> String {
    let neg = n < 0;
    let digits = n.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + usize::from(neg));
    if neg {
        out.push('-');
    }
    for (idx, ch) in digits.chars().enumerate() {
        if idx > 0 && (digits.len() - idx).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub fn format_points(n: i64) -> String {
    if n == 1 {
        "1 point".to_string()
    } else {
        format!("{} points", format_number(n))
    }
}

/// Format remaining time until `epoch_secs` (e.g. `"in 2h 15m"`, `"in 18m"`).
/// Returns `None` if `epoch_secs == 0` or already elapsed.
pub fn format_time_until(epoch_secs: u64) -> Option<String> {
    if epoch_secs == 0 {
        return None;
    }
    let now_secs = (js_sys::Date::now() / 1000.0).floor().max(0.0) as u64;
    if epoch_secs <= now_secs {
        return None;
    }
    let rem = epoch_secs - now_secs;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;
    if hours > 0 && mins > 0 {
        Some(format!("in {hours}h {mins}m"))
    } else if hours > 0 {
        Some(format!("in {hours}h"))
    } else if mins > 0 {
        Some(format!("in {mins}m"))
    } else {
        Some("in under 1m".to_string())
    }
}

/// Format a UNIX epoch timestamp (seconds) as `YYYY-MM-DD` (UTC).
pub fn format_epoch_date(epoch_secs: u64) -> String {
    let ms = (epoch_secs as f64) * 1000.0;
    let d = js_sys::Date::new(&JsValue::from_f64(ms));
    let y = d.get_utc_full_year();
    let m = d.get_utc_month() + 1;
    let day = d.get_utc_date();
    format!("{y:04}-{m:02}-{day:02}")
}

// ---------------------------------------------------------------------------
// Cross-Tab Safety & Session Invalidation (`BroadcastChannel` + `localStorage`)
// ---------------------------------------------------------------------------

struct LocalCleanup(Option<Box<dyn FnOnce()>>);

impl Drop for LocalCleanup {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// Broadcast a cross-tab invalidation event (`logout`, `account_change`,
/// `opt_out`, `prefs_change`, `policy_change`) via both
/// `BroadcastChannel("lets_embed_safety")` and `localStorage` fallback.
pub fn broadcast_safety_invalidation(reason: &str) {
    let ts = js_sys::Date::now();
    if let Ok(ch) =
        web_sys::BroadcastChannel::new(lets_embed_ui::browser::SAFETY_CHANNEL_NAME)
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
        let _ = storage.set_item(SAFETY_INVALIDATE_STORAGE_KEY, &format!("{reason}:{ts:.0}"));
    }
}

/// Subscribe to cross-tab safety invalidation events (`BroadcastChannel("lets_embed_safety")`
/// + `storage` events on `SAFETY_INVALIDATE_STORAGE_KEY`). Cleans up automatically on unmount.
pub fn use_safety_invalidation_listener(on_invalidate: impl Fn(String) + Clone + 'static) {
    if let Ok(ch) =
        web_sys::BroadcastChannel::new(lets_embed_ui::browser::SAFETY_CHANNEL_NAME)
    {
        let on_bc = on_invalidate.clone();
        let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |ev: web_sys::MessageEvent| {
            let data = ev.data();
            if !data.is_object() {
                return;
            }
            let kind = js_sys::Reflect::get(&data, &JsValue::from_str("type"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default();
            if matches!(
                kind.as_str(),
                "invalidate" | "logout" | "account_change" | "opt_out" | "prefs_change" | "policy_change"
            ) {
                let reason = js_sys::Reflect::get(&data, &JsValue::from_str("reason"))
                    .ok()
                    .and_then(|v| v.as_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or(kind);
                on_bc(reason);
            }
        });
        ch.set_onmessage(Some(cb.as_ref().unchecked_ref()));
        let _ = StoredValue::new_local(LocalCleanup(Some(Box::new(move || {
            ch.set_onmessage(None);
            ch.close();
            drop(cb);
        }))));
    }

    if let Some(win) = web_sys::window() {
        let on_st = on_invalidate;
        let cb = Closure::<dyn Fn(web_sys::StorageEvent)>::new(move |ev: web_sys::StorageEvent| {
            if ev.key().as_deref() == Some(SAFETY_INVALIDATE_STORAGE_KEY)
                && let Some(raw) = ev.new_value()
            {
                let reason = raw.split(':').next().unwrap_or("invalidate").to_string();
                on_st(reason);
            }
        });
        let _ = win.add_event_listener_with_callback("storage", cb.as_ref().unchecked_ref());
        let win_clean = win.clone();
        let _ = StoredValue::new_local(LocalCleanup(Some(Box::new(move || {
            let _ = win_clean
                .remove_event_listener_with_callback("storage", cb.as_ref().unchecked_ref());
            drop(cb);
        }))));
    }
}
