//! Client helpers for the `UserAccount` Durable Object.
//! All internal DO requests use the synthetic origin `https://do` — only the path is meaningful.

use serde::{Deserialize, Serialize};
use site_access::{AssuranceLevel, PolicyRef, SessionContext};
use worker::{Env, Method, Request, RequestInit, Response, Result};

use crate::types::{BalanceResp, CreditReq, InitReq, StatusResp};

pub const DO_BINDING: &str = "USER_ACCOUNT";

// ---------------------------------------------------------------------------
// Session, Preferences, Terms & Preview Budget DO Wire Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContextReq {
    #[serde(default)]
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIssueReq {
    pub sid: String,
    pub auth_method: String,
    pub identity_key: String,
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
    pub expires_at: u64,
    /// Optional preserved original authentication timestamp (e.g. for cross-device
    /// transfers so claiming a transfer never refreshes `created_at` / recent-auth checks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIssueResp {
    pub sid: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRevokeReq {
    pub sid: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionRevokeAllReq {
    pub identity_key: Option<String>,
    pub strict_only: bool,
    /// Optional specific caller `sid` to revoke atomically alongside other filters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_sid: Option<String>,
    /// When `true`, also bumps `revoked_all_before` so legacy cutover cookies
    /// (`sid: None`) are invalidated atomically.
    #[serde(default)]
    pub invalidate_legacy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRevokeAllResp {
    pub revoked: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfoResp {
    pub sid: String,
    pub auth_method: String,
    pub identity_key: String,
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefsUpdateReq {
    pub enabled_switchers: Vec<PolicyRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_pref_version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoPrefsConflictResp {
    pub error: String,
    pub pref_version: u64,
    pub enabled_switchers: Vec<PolicyRef>,
}

#[derive(Debug, Clone)]
pub enum DoPrefsUpdateOutcome {
    Updated(SessionContext),
    Conflict(DoPrefsConflictResp),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermsAcceptReq {
    pub terms_version: u32,
    pub terms_digest: String,
    pub accepted_at: u64,
    #[serde(default)]
    pub self_attestation: Option<bool>,
    #[serde(default)]
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgeConfirmReq {
    #[serde(default)]
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BillingPrefsReq {
    pub allow_paid_media: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BillingPrefsResp {
    pub allow_paid_media: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewBudgetReq {
    #[serde(default, alias = "path")]
    pub key: String,
    #[serde(default)]
    pub head: bool,
    #[serde(default)]
    pub guest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewBudgetResp {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_secs: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeCreditBreakdown {
    pub balance: i64,
    pub paid_balance_transfer: i64,
    pub free_balance_forfeited: i64,
    pub plan_refund_total: i64,
    pub plan_refund_paid: i64,
    pub plan_free_forfeited: i64,
    pub total_transferable: i64,
    pub total_free_forfeited: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergePreviewDoReq {
    pub legacy_paid_deposits: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergePreviewDoResp {
    pub balance: i64,
    pub plan: Option<String>,
    pub period_end: u64,
    pub total_views: i64,
    pub banned: bool,
    pub suspended: bool,
    pub merged_into: Option<String>,
    pub credits: MergeCreditBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeDrainDoReq {
    pub merge_id: String,
    pub preserved_do_key: String,
    pub legacy_paid_deposits: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeDrainDoResp {
    pub merge_id: String,
    pub credits: MergeCreditBreakdown,
    pub total_views_transferred: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeReceiveDoReq {
    pub merge_id: String,
    pub paid_points: i64,
    pub total_views: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeReceiveDoResp {
    pub balance: i64,
    pub total_views: i64,
    pub applied: bool,
}

// ---------------------------------------------------------------------------
// Low-level & Typed DO Clients
// ---------------------------------------------------------------------------

/// Low-level call to a user's Durable Object keyed by `do_key` (`users_v2.account_do_key`).
pub async fn call_do<B: Serialize>(
    env: &Env,
    do_key: &str,
    method: Method,
    path: &str,
    body: Option<&B>,
) -> Result<Response> {
    let stub = env
        .durable_object(DO_BINDING)?
        .id_from_name(do_key)?
        .get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(method);
    if let Some(b) = body {
        let json = serde_json::to_string(b).map_err(|e| worker::Error::RustError(e.to_string()))?;
        init.headers.set("content-type", "application/json")?;
        init.with_body(Some(json.into()));
    }
    let req = Request::new_with_init(&format!("https://do{path}"), &init)?;
    stub.fetch_with_request(req).await
}

fn expect_ok(resp: &Response, what: &str) -> Result<()> {
    match resp.status_code() {
        200 => Ok(()),
        code => Err(worker::Error::RustError(format!("{what} failed: {code}"))),
    }
}

pub async fn do_status(env: &Env, do_key: &str) -> Result<StatusResp> {
    let mut resp = call_do::<()>(env, do_key, Method::Get, "/status", None).await?;
    expect_ok(&resp, "do status")?;
    resp.json().await
}

/// Idempotent: applies the free grant on first touch, no-op afterwards.
pub async fn do_init(env: &Env, do_key: &str) -> Result<StatusResp> {
    let body = InitReq {
        address: do_key.to_string(),
    };
    let mut resp = call_do(env, do_key, Method::Post, "/init", Some(&body)).await?;
    expect_ok(&resp, "do init")?;
    resp.json().await
}

pub async fn do_credit(env: &Env, do_key: &str, req: &CreditReq) -> Result<BalanceResp> {
    let mut resp = call_do(env, do_key, Method::Post, "/credit", Some(req)).await?;
    expect_ok(&resp, "do credit")?;
    resp.json().await
}

pub async fn payment_applied(env: &Env, do_key: &str, hash: &str) -> Result<bool> {
    let mut resp = call_do(env, do_key, Method::Post, "/payment-applied", Some(&hash)).await?;
    expect_ok(&resp, "payment lookup")?;
    resp.json().await
}

pub async fn do_session_context(
    env: &Env,
    do_key: &str,
    sid: Option<&str>,
) -> Result<SessionContext> {
    let req = SessionContextReq {
        sid: sid.map(str::to_string),
    };
    let mut resp = call_do(env, do_key, Method::Post, "/session-context", Some(&req)).await?;
    expect_ok(&resp, "do session-context")?;
    resp.json().await
}

pub async fn do_session_issue(
    env: &Env,
    do_key: &str,
    req: &SessionIssueReq,
) -> Result<SessionIssueResp> {
    let mut resp = call_do(env, do_key, Method::Post, "/session-issue", Some(req)).await?;
    expect_ok(&resp, "do session-issue")?;
    resp.json().await
}

pub async fn do_session_revoke(env: &Env, do_key: &str, sid: &str) -> Result<()> {
    let req = SessionRevokeReq {
        sid: sid.to_string(),
    };
    let resp = call_do(env, do_key, Method::Post, "/session-revoke", Some(&req)).await?;
    expect_ok(&resp, "do session-revoke")
}

pub async fn do_session_revoke_all(
    env: &Env,
    do_key: &str,
    req: &SessionRevokeAllReq,
) -> Result<SessionRevokeAllResp> {
    let mut resp = call_do(env, do_key, Method::Post, "/session-revoke-all", Some(req)).await?;
    expect_ok(&resp, "do session-revoke-all")?;
    resp.json().await
}

pub async fn do_session_info(
    env: &Env,
    do_key: &str,
    sid: &str,
) -> Result<Option<SessionInfoResp>> {
    let req = SessionRevokeReq {
        sid: sid.to_string(),
    };
    let mut resp = call_do(env, do_key, Method::Post, "/session-info", Some(&req)).await?;
    match resp.status_code() {
        200 => Ok(Some(resp.json().await?)),
        404 => Ok(None),
        code => Err(worker::Error::RustError(format!(
            "do session-info failed: {code}"
        ))),
    }
}

pub async fn do_prefs_update(
    env: &Env,
    do_key: &str,
    req: &PrefsUpdateReq,
) -> Result<DoPrefsUpdateOutcome> {
    let mut resp = call_do(env, do_key, Method::Post, "/prefs-update", Some(req)).await?;
    match resp.status_code() {
        200 => Ok(DoPrefsUpdateOutcome::Updated(resp.json().await?)),
        409 => Ok(DoPrefsUpdateOutcome::Conflict(resp.json().await?)),
        code => Err(worker::Error::RustError(format!(
            "do prefs-update failed: {code}"
        ))),
    }
}

pub async fn do_terms_accept(env: &Env, do_key: &str, req: &TermsAcceptReq) -> Result<()> {
    let resp = call_do(env, do_key, Method::Post, "/terms-accept", Some(req)).await?;
    expect_ok(&resp, "do terms-accept")
}

pub async fn do_age_confirm(env: &Env, do_key: &str, req: &AgeConfirmReq) -> Result<()> {
    let resp = call_do(env, do_key, Method::Post, "/age-confirm", Some(req)).await?;
    expect_ok(&resp, "do age-confirm")
}

pub async fn do_billing_prefs(
    env: &Env,
    do_key: &str,
    allow_paid_media: bool,
) -> Result<BillingPrefsResp> {
    let req = BillingPrefsReq { allow_paid_media };
    let mut resp = call_do(env, do_key, Method::Post, "/billing-prefs", Some(&req)).await?;
    expect_ok(&resp, "do billing-prefs")?;
    resp.json().await
}

pub async fn do_merge_preview(
    env: &Env,
    do_key: &str,
    legacy_paid_deposits: i64,
) -> Result<MergePreviewDoResp> {
    let req = MergePreviewDoReq {
        legacy_paid_deposits,
    };
    let mut resp = call_do(env, do_key, Method::Post, "/merge-preview", Some(&req)).await?;
    expect_ok(&resp, "do merge-preview")?;
    resp.json().await
}

pub async fn do_merge_drain(
    env: &Env,
    do_key: &str,
    req: &MergeDrainDoReq,
) -> Result<MergeDrainDoResp> {
    let mut resp = call_do(env, do_key, Method::Post, "/merge-drain", Some(req)).await?;
    match resp.status_code() {
        200 => resp.json().await,
        code => {
            let msg = resp.text().await.unwrap_or_default();
            Err(worker::Error::RustError(format!(
                "do merge-drain failed ({code}): {msg}"
            )))
        }
    }
}

pub async fn do_merge_receive(
    env: &Env,
    do_key: &str,
    req: &MergeReceiveDoReq,
) -> Result<MergeReceiveDoResp> {
    let mut resp = call_do(env, do_key, Method::Post, "/merge-receive", Some(req)).await?;
    match resp.status_code() {
        200 => resp.json().await,
        code => {
            let msg = resp.text().await.unwrap_or_default();
            Err(worker::Error::RustError(format!(
                "do merge-receive failed ({code}): {msg}"
            )))
        }
    }
}
