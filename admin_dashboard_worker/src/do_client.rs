//! Durable Object clients for `USER_ACCOUNT` (`UserAccount`) and `SITE_POLICY` (`SitePolicyDO`).

use serde::{Deserialize, Serialize};
use site_access::PublicSitePolicy;
use worker::{Env, Method, Request, RequestInit, Response, Result};

use crate::api::DoStatusResp;

pub const USER_ACCOUNT_DO_BINDING: &str = "USER_ACCOUNT";
pub const SITE_POLICY_DO_BINDING: &str = "SITE_POLICY";
pub const SITE_POLICY_SINGLETON_NAME: &str = "global";

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

/// Immediately publishes `{ policy, digest }` to the singleton `SITE_POLICY` DO.
pub async fn publish_site_policy(
    env: &Env,
    policy: &PublicSitePolicy,
    digest: &str,
) -> Result<()> {
    let body = PublishSitePolicyReq { policy, digest };
    let resp = call_named_do(
        env,
        SITE_POLICY_DO_BINDING,
        SITE_POLICY_SINGLETON_NAME,
        Method::Post,
        "/publish",
        Some(&body),
    )
    .await?;
    expect_ok(&resp, "SitePolicyDO publish")
}
