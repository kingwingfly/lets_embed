//! FROZEN SCAFFOLD (fully implemented): client helpers for the UserAccount
//! Durable Object. All internal DO requests use the synthetic origin
//! `https://do` — only the path is meaningful.

use serde::Serialize;
use worker::{Env, Method, Request, RequestInit, Response, Result};

use crate::types::{BalanceResp, CreditReq, InitReq, StatusResp};

pub const DO_BINDING: &str = "USER_ACCOUNT";

/// Low-level call to a user's Durable Object. `address` must be lowercase.
pub async fn call_do<B: Serialize>(
    env: &Env,
    address: &str,
    method: Method,
    path: &str,
    body: Option<&B>,
) -> Result<Response> {
    let stub = env
        .durable_object(DO_BINDING)?
        .id_from_name(address)?
        .get_stub()?;
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

pub async fn do_status(env: &Env, address: &str) -> Result<StatusResp> {
    let mut resp = call_do::<()>(env, address, Method::Get, "/status", None).await?;
    expect_ok(&resp, "do status")?;
    resp.json().await
}

/// Idempotent: applies the free grant on first touch, no-op afterwards.
pub async fn do_init(env: &Env, address: &str) -> Result<StatusResp> {
    let body = InitReq {
        address: address.to_string(),
    };
    let mut resp = call_do(env, address, Method::Post, "/init", Some(&body)).await?;
    expect_ok(&resp, "do init")?;
    resp.json().await
}

pub async fn do_credit(env: &Env, address: &str, req: &CreditReq) -> Result<BalanceResp> {
    let mut resp = call_do(env, address, Method::Post, "/credit", Some(req)).await?;
    expect_ok(&resp, "do credit")?;
    resp.json().await
}
