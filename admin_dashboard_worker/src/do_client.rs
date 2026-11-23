//! Durable Object clients for `USER_ACCOUNT` (`UserAccount`) and `SITE_POLICY` (`SitePolicyDO`),
//! plus optional origin catalog validation (`POST {APP_ORIGIN}/internal/validate-safety-catalog`).

use serde::{Deserialize, Serialize};
use site_access::PublicSitePolicy;
use worker::{Env, Fetch, Method, Request, RequestInit, Response, Result};

use crate::{api::DoStatusResp, security::resolve_internal_api_secret};

pub const USER_ACCOUNT_DO_BINDING: &str = "USER_ACCOUNT";
pub const SITE_POLICY_DO_BINDING: &str = "SITE_POLICY";
pub const SITE_POLICY_SINGLETON_NAME: &str = "global";
pub const APP_ORIGIN_BINDING: &str = "APP_ORIGIN";

#[derive(Debug, Serialize)]
pub struct DoCreditReq {
    pub points: i64,
    pub key: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct DoBalanceResp {
    pub balance: i64,
    pub applied: bool,
}

#[derive(Debug, Serialize)]
pub struct DoAdminPlanReq {
    pub plan: String,
    pub days: u32,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct DoBanReq {
    pub banned: bool,
}

#[derive(Debug, Serialize)]
struct PublishSitePolicyReq<'a> {
    policy: &'a PublicSitePolicy,
    digest: &'a str,
    policy_digest: &'a str,
}

/// Verified acknowledgement from `SitePolicyDO` confirming exact `(revision, policy_digest)` activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoActivationAck {
    pub revision: u64,
    pub policy_digest: String,
}

#[derive(Debug, Deserialize)]
struct RawDoAckResp {
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    revision: Option<u64>,
    #[serde(default)]
    policy_digest: Option<String>,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    policy: Option<RawDoAckPolicy>,
}

#[derive(Debug, Deserialize)]
struct RawDoAckPolicy {
    revision: u64,
    #[serde(default)]
    policy_digest: Option<String>,
}

/// Strictly verifies a `SitePolicyDO` activation response body against the exact
/// expected `(revision, policy_digest)`.
///
/// Accepts both the compact v3 ACK shape (`{ ok: true, revision, policy_digest }`)
/// and envelope shape (`{ policy: { revision, policy_digest }, digest }`).
pub fn verify_do_activation_ack(
    raw_body: &str,
    expected_revision: u64,
    expected_digest: &str,
) -> std::result::Result<DoActivationAck, String> {
    let parsed: RawDoAckResp = serde_json::from_str(raw_body)
        .map_err(|e| format!("invalid SitePolicyDO ACK JSON: {e}"))?;

    if parsed.ok == Some(false) {
        return Err("SitePolicyDO returned ok=false".to_string());
    }

    let ack_rev = parsed
        .revision
        .or_else(|| parsed.policy.as_ref().map(|p| p.revision))
        .ok_or_else(|| "SitePolicyDO ACK missing revision".to_string())?;

    if let Some(ref p) = parsed.policy
        && p.revision != ack_rev
    {
        return Err(format!(
            "SitePolicyDO ACK inconsistent revision ({ack_rev} vs policy.revision={})",
            p.revision
        ));
    }

    if ack_rev != expected_revision {
        return Err(format!(
            "SitePolicyDO ACK revision mismatch (expected {expected_revision}, got {ack_rev})"
        ));
    }

    let ack_digest = parsed
        .policy_digest
        .as_deref()
        .or(parsed.digest.as_deref())
        .or_else(|| {
            parsed
                .policy
                .as_ref()
                .and_then(|p| p.policy_digest.as_deref())
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "SitePolicyDO ACK missing policy_digest".to_string())?;

    if !ack_digest.eq_ignore_ascii_case(expected_digest) {
        return Err(format!(
            "SitePolicyDO ACK policy_digest mismatch (expected {expected_digest}, got {ack_digest})"
        ));
    }

    // Cross-check nested policy.policy_digest if present alongside top-level digest.
    if let Some(inner_digest) = parsed
        .policy
        .as_ref()
        .and_then(|p| p.policy_digest.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && !inner_digest.eq_ignore_ascii_case(expected_digest)
    {
        return Err("SitePolicyDO ACK nested policy_digest mismatch".to_string());
    }

    Ok(DoActivationAck {
        revision: ack_rev,
        policy_digest: expected_digest.to_string(),
    })
}

async fn call_named_do<B: Serialize>(
    env: &Env,
    binding: &str,
    name: &str,
    method: Method,
    path: &str,
    body: Option<&B>,
) -> Result<Response> {
    let stub = env.durable_object(binding)?.id_from_name(name)?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(method);
    if let Some(b) = body {
        let json =
            serde_json::to_string(b).map_err(|e| worker::Error::RustError(e.to_string()))?;
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

pub async fn user_status(env: &Env, do_key: &str) -> Result<DoStatusResp> {
    let mut resp =
        call_named_do::<()>(env, USER_ACCOUNT_DO_BINDING, do_key, Method::Get, "/status", None)
            .await?;
    expect_ok(&resp, "user DO status")?;
    resp.json().await
}

pub async fn user_credit(env: &Env, do_key: &str, req: &DoCreditReq) -> Result<DoBalanceResp> {
    let mut resp = call_named_do(
        env,
        USER_ACCOUNT_DO_BINDING,
        do_key,
        Method::Post,
        "/credit",
        Some(req),
    )
    .await?;
    expect_ok(&resp, "user DO credit")?;
    resp.json().await
}

pub async fn user_admin_plan(
    env: &Env,
    do_key: &str,
    req: &DoAdminPlanReq,
) -> Result<DoStatusResp> {
    let mut resp = call_named_do(
        env,
        USER_ACCOUNT_DO_BINDING,
        do_key,
        Method::Post,
        "/admin-plan",
        Some(req),
    )
    .await?;
    expect_ok(&resp, "user DO admin-plan")?;
    resp.json().await
}

pub async fn user_ban(env: &Env, do_key: &str, banned: bool) -> Result<()> {
    let resp = call_named_do(
        env,
        USER_ACCOUNT_DO_BINDING,
        do_key,
        Method::Post,
        "/ban",
        Some(&DoBanReq { banned }),
    )
    .await?;
    expect_ok(&resp, "user DO ban")
}

/// Revokes all active revocable `v2` sessions inside the user's `UserAccount` DO.
pub async fn user_revoke_all_sessions(env: &Env, do_key: &str) -> Result<()> {
    let empty = serde_json::json!({});
    let resp = call_named_do(
        env,
        USER_ACCOUNT_DO_BINDING,
        do_key,
        Method::Post,
        "/session-revoke-all",
        Some(&empty),
    )
    .await?;
    expect_ok(&resp, "user DO session-revoke-all")
}

/// Activates a Policy v3 revision on the singleton `SITE_POLICY` DO and strictly
/// verifies that the DO acknowledges the exact `(policy.revision, digest)`.
pub async fn activate_site_policy(
    env: &Env,
    policy: &PublicSitePolicy,
    digest: &str,
) -> Result<DoActivationAck> {
    let body = PublishSitePolicyReq {
        policy,
        digest,
        policy_digest: digest,
    };

    let mut resp = call_named_do(
        env,
        SITE_POLICY_DO_BINDING,
        SITE_POLICY_SINGLETON_NAME,
        Method::Post,
        "/publish",
        Some(&body),
    )
    .await?;

    // Compatibility fallback if the DO exposes `/internal/policy/activate` instead of `/publish`.
    if resp.status_code() == 404 {
        resp = call_named_do(
            env,
            SITE_POLICY_DO_BINDING,
            SITE_POLICY_SINGLETON_NAME,
            Method::Post,
            "/internal/policy/activate",
            Some(&body),
        )
        .await?;
    }

    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    if status != 200 {
        let detail = text.trim();
        return Err(worker::Error::RustError(if detail.is_empty() {
            format!("SitePolicyDO activation failed with HTTP {status}")
        } else {
            format!("SitePolicyDO activation failed (HTTP {status}): {detail}")
        }));
    }

    verify_do_activation_ack(&text, policy.revision, digest)
        .map_err(worker::Error::RustError)
}

// ---------------------------------------------------------------------------
// Origin Catalog Validation (`POST {APP_ORIGIN}/internal/validate-safety-catalog`)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct CatalogValidationReq<'a> {
    post_tags: &'a [String],
    authors: &'a [String],
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct CatalogValidationResp {
    pub unknown_post_tags: Vec<String>,
    pub unknown_authors: Vec<String>,
}

fn read_secret_or_var(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|s| s.to_string())
        .or_else(|| env.var(name).ok().map(|v| v.to_string()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Calls `POST {APP_ORIGIN}/internal/validate-safety-catalog` when `APP_ORIGIN`
/// (either a Worker service binding or an env var URL) is configured and at least
/// one `post_tag:` or `author:` reference exists in the PolicySet.
///
/// Returns `Ok(None)` when `APP_ORIGIN` is not configured or both slices are empty.
/// Fails closed (`Err`) when `APP_ORIGIN` is configured and the call fails or
/// returns a non-200 status.
pub async fn validate_safety_catalog_remote(
    env: &Env,
    post_tags: &[String],
    authors: &[String],
) -> Result<Option<CatalogValidationResp>> {
    if post_tags.is_empty() && authors.is_empty() {
        return Ok(None);
    }

    let service_binding = env.service(APP_ORIGIN_BINDING).ok();
    let origin_url = env
        .var(APP_ORIGIN_BINDING)
        .ok()
        .map(|v| v.to_string().trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty());

    if service_binding.is_none() && origin_url.is_none() {
        return Ok(None);
    }

    let payload = serde_json::to_string(&CatalogValidationReq { post_tags, authors })
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(payload.into()));
    init.headers.set("content-type", "application/json")?;
    init.headers.set("accept", "application/json")?;

    let explicit_internal = read_secret_or_var(env, "INTERNAL_API_SECRET");
    let site_secret = read_secret_or_var(env, "SITE_SECRET");
    if let Ok(internal_secret) =
        resolve_internal_api_secret(explicit_internal.as_deref(), site_secret.as_deref())
    {
        init.headers
            .set("authorization", &format!("Bearer {internal_secret}"))?;
        init.headers.set("x-internal-api-secret", &internal_secret)?;
    }

    if let (Some(cf_id), Some(cf_secret)) = (
        read_secret_or_var(env, "CF_ACCESS_CLIENT_ID"),
        read_secret_or_var(env, "CF_ACCESS_CLIENT_SECRET"),
    ) {
        init.headers.set("cf-access-client-id", &cf_id)?;
        init.headers.set("cf-access-client-secret", &cf_secret)?;
    }

    let mut resp: Response = if let Some(svc) = service_binding {
        let req = Request::new_with_init(
            "https://app-origin.internal/internal/validate-safety-catalog",
            &init,
        )?;
        svc.fetch_request(req).await?.try_into()?
    } else {
        let base = origin_url.expect("checked above");
        let url = format!("{base}/internal/validate-safety-catalog");
        let req = Request::new_with_init(&url, &init)?;
        Fetch::Request(req).send().await?
    };

    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    if status != 200 {
        let detail = text.trim();
        return Err(worker::Error::RustError(if detail.is_empty() {
            format!("Origin catalog validation failed with HTTP {status}")
        } else {
            format!("Origin catalog validation failed (HTTP {status}): {detail}")
        }));
    }

    let parsed: CatalogValidationResp = serde_json::from_str(&text).map_err(|e| {
        worker::Error::RustError(format!("Invalid origin catalog validation JSON: {e}"))
    })?;
    Ok(Some(parsed))
}
