//! Typed browser fetch client for `/admin/api/*`.
//!
//! Attaches `X-Admin-CSRF: 1` (`site_access::ADMIN_CSRF_HEADER`) and same-origin
//! credentials on every mutation request.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use site_access::{
    ADMIN_CSRF_HEADER, AgeGateTrigger, AgeVerificationPolicy, AuthProviderId,
    AuthProviderPublicConfig, GeoPolicy, LegalDocConfig, SafetyRuleConfig, SimilarityDefaults,
    UnclassifiedMode,
};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCredentials, RequestInit, RequestMode, Response};

// ---------------------------------------------------------------------------
// Shared Wire DTOs (mirrors admin_dashboard_worker/src/api.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct ApiErrorBody {
    error: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemPricing {
    pub price: i64,
    pub daily_free: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanTerms {
    pub price: i64,
    pub views: Option<i64>,
    pub searches: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub login_required: bool,
    pub free_media_folders: Vec<String>,
    pub items: [ItemPricing; 5],
    pub plans: [PlanTerms; 2],
    pub signup_points: i64,
    pub points_per_usd: i64,
    pub minimum_topup: i64,
    pub eth_deposit: String,
    pub sol_deposit: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountsSummary {
    pub total: i64,
    pub active: i64,
    pub banned: i64,
    pub basic: i64,
    pub pro: i64,
    pub eth: i64,
    pub sol: i64,
    pub multi_auth: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PaymentsSummary {
    pub total_count: i64,
    pub credited_count: i64,
    pub total_points: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyOverview {
    pub safety_enabled: bool,
    pub rule_count: usize,
    pub active_switcher_count: usize,
    pub age_policy: AgeVerificationPolicy,
    pub age_gate_trigger: AgeGateTrigger,
    pub blocked_country_count: usize,
    pub cloudflare_images_blur: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewResp {
    pub admin_email: String,
    pub revision: u32,
    pub min_enforce_rev: u32,
    pub policy_digest: String,
    pub access: AccessPolicy,
    pub safety: SafetyOverview,
    pub accounts_summary: AccountsSummary,
    pub payments_summary: PaymentsSummary,
    pub open_report_count: i64,
    pub legacy_unclassified_note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SaveAccessReq {
    pub revision: u32,
    pub access: AccessPolicy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveAccessResp {
    pub revision: u32,
    pub min_enforce_rev: u32,
    pub digest: String,
    pub access: AccessPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoStatusResp {
    pub address: String,
    pub balance: i64,
    pub plan: Option<String>,
    pub period_end: u64,
    pub views_remaining: Option<i64>,
    pub searches_remaining: Option<i64>,
    pub window_reset: u64,
    pub banned: bool,
    pub total_views: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySummary {
    pub provider_id: String,
    pub issuer: String,
    pub subject: String,
    pub purpose: String,
    pub label: Option<String>,
    pub verified_email: Option<String>,
    pub assurance_level: String,
    pub assurance_method: Option<String>,
    pub assurance_verified_at: Option<i64>,
    pub assurance_expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntryResp {
    pub id: String,
    pub account_do_key: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub created_at: i64,
    pub last_login: i64,
    pub plan: Option<String>,
    pub banned: bool,
    pub terms_version_accepted: Option<i64>,
    pub terms_accepted_at: Option<i64>,
    pub topup_count: i64,
    pub topup_points: String,
    pub like_count: i64,
    pub identities: Vec<IdentitySummary>,
    pub live_status: Option<DoStatusResp>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountsListResp {
    pub summary: AccountsSummary,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub accounts: Vec<AccountEntryResp>,
    pub selected: Option<AccountEntryResp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminPlanMutationReq {
    pub user_id: String,
    pub plan: String,
    pub days: Option<u32>,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminPlanMutationResp {
    pub user_id: String,
    pub plan: Option<String>,
    pub period_end: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminCreditMutationReq {
    pub user_id: String,
    pub points: i64,
    pub reason: String,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminCreditMutationResp {
    pub user_id: String,
    pub balance: i64,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminBanMutationReq {
    pub user_id: String,
    pub banned: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminBanMutationResp {
    pub user_id: String,
    pub banned: bool,
    pub sessions_revoked: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRecordResp {
    pub tx_hash: String,
    pub address: String,
    pub chain: String,
    pub token: String,
    pub amount: String,
    pub points: String,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentsListResp {
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    pub payments: Vec<PaymentRecordResp>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SafetyConfigResp {
    pub revision: u32,
    pub min_enforce_rev: u32,
    pub digest: String,
    pub safety_enabled: bool,
    pub rules: Vec<SafetyRuleConfig>,
    pub presets: Vec<SafetyRuleConfig>,
    pub unclassified_mode: UnclassifiedMode,
    pub cloudflare_images_blur: bool,
    pub age_policy: AgeVerificationPolicy,
    pub age_gate_trigger: AgeGateTrigger,
    pub similarity: SimilarityDefaults,
    pub geo: GeoPolicy,
    pub legal: LegalDocConfig,
    pub panic_shortcut: String,
    pub legacy_unclassified_note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SaveSafetyReq {
    pub revision: u32,
    pub safety_enabled: bool,
    pub rules: Vec<SafetyRuleConfig>,
    pub unclassified_mode: UnclassifiedMode,
    pub cloudflare_images_blur: bool,
    pub age_policy: AgeVerificationPolicy,
    pub age_gate_trigger: AgeGateTrigger,
    pub similarity: SimilarityDefaults,
    pub geo: GeoPolicy,
    pub legal: LegalDocConfig,
    pub panic_shortcut: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveSafetyResp {
    pub revision: u32,
    pub min_enforce_rev: u32,
    pub tightened: bool,
    pub terms_bumped: bool,
    pub auto_disabled_providers: Vec<AuthProviderId>,
    pub digest: String,
    pub legal: LegalDocConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderView {
    pub config: AuthProviderPublicConfig,
    pub supports_strict_age_verification: bool,
    pub allowed_under_age_policy: bool,
    pub secret_field_name: Option<String>,
    pub has_client_secret: bool,
    pub kid: Option<String>,
    pub updated_at: Option<i64>,
    pub updated_by: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvidersResp {
    pub revision: u32,
    pub min_enforce_rev: u32,
    pub digest: String,
    pub age_policy: AgeVerificationPolicy,
    pub current_kid: String,
    pub has_prev_key: bool,
    pub providers: Vec<ProviderView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderUpdateItem {
    pub id: AuthProviderId,
    pub enabled: bool,
    pub display_name: Option<String>,
    pub issuer: Option<String>,
    pub public_client_id: Option<String>,
    pub soft_birthday_check: bool,
    pub secret_value: Option<String>,
    pub clear_secret: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SaveProvidersReq {
    pub revision: u32,
    pub providers: Vec<ProviderUpdateItem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RotateSecretsResp {
    pub current_kid: String,
    pub total_rows: usize,
    pub rotated: usize,
    pub skipped_current: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportCounts {
    pub open: i64,
    pub reviewing: i64,
    pub resolved: i64,
    pub dismissed: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContentReportItem {
    pub id: String,
    pub reporter_key: String,
    pub reporter_user_id: Option<String>,
    pub target_kind: String,
    pub target_id: i64,
    pub reason: String,
    pub note: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReportsListResp {
    pub status: String,
    pub counts: ReportCounts,
    pub reports: Vec<ContentReportItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolveReportReq {
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResolveReportResp {
    pub id: String,
    pub status: String,
    pub resolved_at: i64,
    pub resolved_by: String,
}

// ---------------------------------------------------------------------------
// Low-level Fetch Helpers
// ---------------------------------------------------------------------------

async fn send_request<T: DeserializeOwned>(
    method: &str,
    url: &str,
    body_json: Option<String>,
) -> Result<T, String> {
    let window = web_sys::window().ok_or_else(|| "Browser window unavailable".to_string())?;

    let init = RequestInit::new();
    init.set_method(method);
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::SameOrigin);

    let headers = Headers::new().map_err(|e| format!("Failed to construct headers: {e:?}"))?;
    headers
        .set("Accept", "application/json")
        .map_err(|e| format!("Header error: {e:?}"))?;

    if method != "GET" && method != "HEAD" {
        headers
            .set(ADMIN_CSRF_HEADER, "1")
            .map_err(|e| format!("CSRF header error: {e:?}"))?;
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| format!("Content-Type header error: {e:?}"))?;
    }

    init.set_headers(&headers);
    if let Some(json) = body_json {
        init.set_body(&wasm_bindgen::JsValue::from_str(&json));
    }

    let request = Request::new_with_str_and_init(url, &init)
        .map_err(|e| format!("Failed to build request: {e:?}"))?;

    let resp_val = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("Network request failed: {e:?}"))?;
    let resp: Response = resp_val
        .dyn_into()
        .map_err(|_| "Unexpected response object".to_string())?;

    let status = resp.status();
    let text_promise = resp
        .text()
        .map_err(|e| format!("Failed to read response body: {e:?}"))?;
    let text = JsFuture::from(text_promise)
        .await
        .map_err(|e| format!("Failed to await response text: {e:?}"))?
        .as_string()
        .unwrap_or_default();

    if !(200..300).contains(&status) {
        if let Ok(api_err) = serde_json::from_str::<ApiErrorBody>(&text) {
            return Err(format!("HTTP {status}: {}", api_err.error));
        }
        let msg = if text.trim().is_empty() {
            format!("HTTP {status}")
        } else {
            format!("HTTP {status}: {}", text.trim())
        };
        return Err(msg);
    }

    serde_json::from_str::<T>(&text)
        .map_err(|e| format!("Failed to decode JSON response: {e}"))
}

pub async fn get_json<T: DeserializeOwned>(url: &str) -> Result<T, String> {
    send_request("GET", url, None).await
}

pub async fn post_json<B: Serialize, T: DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<T, String> {
    let encoded =
        serde_json::to_string(body).map_err(|e| format!("Failed to serialize request: {e}"))?;
    send_request("POST", url, Some(encoded)).await
}

pub fn url_encode_component(raw: &str) -> String {
    js_sys::encode_uri_component(raw)
        .as_string()
        .unwrap_or_default()
}

pub fn format_ts_utc(secs: i64) -> String {
    if secs <= 0 {
        return "—".to_string();
    }
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02} UTC")
}
