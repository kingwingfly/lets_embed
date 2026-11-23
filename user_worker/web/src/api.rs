//! Typed HTTP client & DTOs for `user_worker` APIs and `/api/like_previews`.
#![allow(dead_code)]

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use site_access::{AssuranceLevel, AuthProviderPublicConfig, PublicSitePolicy};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCredentials, RequestInit, RequestMode, Response};

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
    pub user_id: String,
    pub account_do_key: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub identities: Vec<IdentityView>,
    pub linked_eth_address: Option<String>,
    pub linked_solana_address: Option<String>,
    pub enabled_switchers: Vec<String>,
    pub effective_switchers: Vec<String>,
    pub safe_mode: bool,
    pub terms_version_accepted: Option<u32>,
    pub terms_digest_accepted: Option<String>,
    pub terms_accepted_at: Option<u64>,
    pub terms_up_to_date: bool,
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
    pub session_auth_time: Option<u64>,
    pub can_link_identity_now: bool,
    pub available_providers: Vec<AuthProviderPublicConfig>,
    pub policy: PublicSitePolicy,
    pub pricing: PricingSummary,
}

#[derive(Clone, Debug, Deserialize)]
pub struct QrMatrix {
    pub size: usize,
    pub rows: Vec<String>,
}

impl QrMatrix {
    pub fn to_svg(&self) -> String {
        let quiet = 4usize;
        let dim = self.size + quiet * 2;
        let mut rects = String::new();
        for (y, row) in self.rows.iter().enumerate() {
            for (x, ch) in row.chars().enumerate() {
                if ch == '1' || ch == '#' {
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
pub struct PreferencesResp {
    pub enabled_switchers: Vec<String>,
    pub safe_mode: bool,
    pub effective_switchers: Vec<String>,
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

pub fn current_origin() -> String {
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default()
}

pub fn sanitize_next(raw: Option<&str>) -> String {
    let Some(s) = raw.map(str::trim) else {
        return "/".to_string();
    };
    if !s.starts_with('/') || s.starts_with("//") || s.contains('\\') || s.len() > 512 {
        return "/".to_string();
    }
    s.to_string()
}

pub fn navigate_hard(url: &str) {
    if let Some(win) = web_sys::window() {
        let _ = win.location().assign(url);
    }
}

pub fn format_points(n: i64) -> String {
    if n == 1 {
        "1 point".to_string()
    } else {
        format!("{n} points")
    }
}
