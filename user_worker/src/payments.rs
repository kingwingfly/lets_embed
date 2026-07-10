//! UNIT 3: crypto top-up (on-chain verification) + subscription passthrough.
//!
//! - POST /user/api/topup Json(TopupReq{chain, token, tx_hash}) -> 200
//!   Json(TopupResp) | 400 | 401 | 403 (tx sender != claimant) | 409 (already
//!   submitted) | 425 (not enough confirmations / not finalized yet).
//!   Points are computed from the on-chain amount via a Chainlink USD price
//!   (`rates::points_for`); stablecoins price at $1. A credit below
//!   `MIN_TOPUP_POINTS` is rejected.
//!   Row lifecycle (unchanged): 'rejected' only for tx-intrinsic failures
//!   (wrong recipient, dust, reverted) — invalid for any submitter, so the PK
//!   replay lock then answers 409 forever. Transient / submitter-relative
//!   failures DELETE the pending row so resubmission works.
//! - GET  /user/api/payments -> 200 Json(Vec<PaymentRow>) (newest 50) | 401.
//! - POST /user/api/subscribe Json(SubscribeReq) -> passthrough to DO
//!   /subscribe; on 200 mirror `users.plan` in D1.
//!
//! SCAFFOLD STATE: only the Ethereum-native (ETH) path is wired, and it depends
//! on `rates::chainlink_price` which UNIT 2 implements. UNIT 3 adds the ERC-20
//! (USDT/USDC) receipt-log path and dispatches Solana to `crate::solana`.

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tower_cookies::Cookies;
use wasm_bindgen::JsValue;
use worker::{Env, Fetch, Method, Request, RequestInit};

use crate::AppState;
use crate::config::{self, Chain, MIN_CONFIRMATIONS, MIN_TOPUP_POINTS};
use crate::rates;
use crate::solana::{self, SolOutcome};
use crate::types::{ApiError, CreditReq, PaymentRow, SubscribeReq, TopupReq, TopupResp};
use crate::{do_client, session};

// ---------------------------------------------------------------------------
// JSON-RPC over worker::Fetch (no alloy/ethers)
// ---------------------------------------------------------------------------

/// Single JSON-RPC call; returns the `result` field. A non-2xx HTTP response
/// or a JSON-RPC-level `error` is turned into `Err`.
async fn rpc(
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> worker::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.headers.set("content-type", "application/json")?;
    init.with_body(Some(body.to_string().into()));
    let req = Request::new_with_init(url, &init)?;
    let mut resp = Fetch::Request(req).send().await?;
    let code = resp.status_code();
    if !(200..300).contains(&code) {
        return Err(worker::Error::RustError(format!(
            "rpc {method}: http {code}"
        )));
    }
    let v: serde_json::Value = resp.json().await?;
    if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
        return Err(worker::Error::RustError(format!("rpc {method} error: {e}")));
    }
    Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

/// Ethereum quantity ("0x"-prefixed hex) -> u128.
pub fn hex_to_u128(s: &str) -> Option<u128> {
    u128::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

/// Ethereum quantity ("0x"-prefixed hex) -> u64.
pub fn hex_to_u64(s: &str) -> Option<u64> {
    hex_to_u128(s)?.try_into().ok()
}

/// Lowercase 0x-prefixed 32-byte tx hash (`^0x[0-9a-f]{64}$`).
pub fn valid_tx_hash(s: &str) -> bool {
    s.len() == 66
        && s.starts_with("0x")
        && s[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `eth_getTransactionByHash` result (fields we care about).
#[derive(Debug, Deserialize)]
struct RpcTx {
    from: String,
    /// None for contract-creation transactions.
    to: Option<String>,
    value: String,
}

/// `eth_getTransactionReceipt` result (fields we care about).
#[derive(Debug, Deserialize)]
struct RpcReceipt {
    /// "0x1" success, "0x0" reverted (may be absent on pre-Byzantium chains).
    status: Option<String>,
    #[serde(rename = "blockNumber")]
    block_number: Option<String>,
    /// Event logs emitted by the tx (used to verify ERC-20 `Transfer`s). The
    /// native-ETH path ignores these, so default to empty when absent.
    #[serde(default)]
    logs: Vec<RpcLog>,
}

/// One entry of `receipt.logs[]` (fields we care about for an ERC-20 transfer).
#[derive(Debug, Deserialize)]
struct RpcLog {
    /// Emitting contract address (0x, possibly EIP-55 mixed-case).
    address: String,
    /// Indexed event params. `Transfer`: [keccak(sig), from, to].
    topics: Vec<String>,
    /// ABI-encoded non-indexed params. `Transfer`: the uint256 value.
    data: String,
}

/// keccak256("Transfer(address,address,uint256)") — the ERC-20 `Transfer`
/// event signature (`topics[0]`).
const TRANSFER_TOPIC0: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// The 20-byte address packed into a 32-byte indexed topic: strip `0x`, take
/// the low 40 hex nibbles, lowercased. Robust to nodes that omit zero padding.
fn topic_address(topic: &str) -> String {
    let h = topic.strip_prefix("0x").unwrap_or(topic).to_lowercase();
    match h.len().checked_sub(40) {
        Some(off) => h[off..].to_string(),
        None => h,
    }
}

/// Scan `logs` for the FIRST ERC-20 `Transfer(from=sender, to=deposit)` emitted
/// by `token_addr`, returning the transferred amount. Pure; host-tested.
/// `token_addr` is lowercase 0x; `deposit_no0x`/`sender_no0x` are lowercase
/// 40-hex addresses without the `0x` prefix.
fn match_transfer_log(
    logs: &[RpcLog],
    token_addr: &str,
    deposit_no0x: &str,
    sender_no0x: &str,
) -> Option<u128> {
    logs.iter().find_map(|log| {
        if log.address.to_lowercase() != token_addr || log.topics.len() < 3 {
            return None;
        }
        if log.topics[0].to_lowercase() != TRANSFER_TOPIC0 {
            return None;
        }
        if topic_address(&log.topics[2]) != deposit_no0x
            || topic_address(&log.topics[1]) != sender_no0x
        {
            return None;
        }
        // data = the uint256 value (`0x` + up to 64 hex); parse as the amount.
        hex_to_u128(&log.data)
    })
}

/// Verify a native-ETH transfer and return its value in wei. Only checks
/// tx-intrinsic properties (recipient) — failures here are permanent for any
/// submitter. The minimum is enforced later, in points.
fn verify_native_tx(tx: &RpcTx, deposit_address: &str) -> Result<u128, &'static str> {
    let to = tx
        .to
        .as_deref()
        .ok_or("tx has no recipient")?
        .to_lowercase();
    if to != deposit_address {
        return Err("tx recipient is not the deposit address");
    }
    hex_to_u128(&tx.value).ok_or("bad tx value")
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn api_err(code: StatusCode, msg: &str) -> Response {
    (code, Json(ApiError { error: msg.into() })).into_response()
}

async fn d1_exec(env: &Env, sql: &str, binds: &[JsValue]) -> worker::Result<()> {
    env.d1(crate::D1_BINDING)?
        .prepare(sql)
        .bind(binds)?
        .run()
        .await?;
    Ok(())
}

/// Permanent, tx-intrinsic failure: mark the payment row rejected, answer 400.
async fn reject(env: &Env, tx_hash: &str, msg: &str) -> Response {
    if let Err(e) = d1_exec(
        env,
        "UPDATE payments SET status='rejected' WHERE tx_hash=?",
        &[tx_hash.into()],
    )
    .await
    {
        worker::console_error!("payments reject update failed for {tx_hash}: {e:?}");
    }
    api_err(StatusCode::BAD_REQUEST, msg)
}

/// Transient failure: release the replay lock so the tx can be resubmitted.
async fn delete_pending(env: &Env, tx_hash: &str) {
    if let Err(e) = d1_exec(
        env,
        "DELETE FROM payments WHERE tx_hash=? AND status='pending'",
        &[tx_hash.into()],
    )
    .await
    {
        worker::console_error!("payments pending delete failed for {tx_hash}: {e:?}");
    }
}

/// RPC transport failure mid-flow: release the lock and let the client retry.
async fn rpc_unavailable(env: &Env, tx_hash: &str, method: &str, e: worker::Error) -> Response {
    worker::console_error!("{method} failed for {tx_hash}: {e:?}");
    delete_pending(env, tx_hash).await;
    api_err(StatusCode::BAD_GATEWAY, "rpc unavailable, retry later")
}

/// Not mined / not enough confirmations: release the lock and ask the client
/// to retry once the chain has caught up.
async fn too_early(env: &Env, tx_hash: &str) -> Response {
    delete_pending(env, tx_hash).await;
    api_err(
        StatusCode::TOO_EARLY,
        "not enough confirmations yet, retry later",
    )
}

/// Forward a subscription change to the user's DO, relay its status + JSON
/// body, and on 200 mirror the display-only `users.plan` column in D1.
async fn plan_passthrough(
    st: &AppState,
    addr: &str,
    path: &str,
    body: Option<&SubscribeReq>,
    plan: Option<&str>,
) -> Response {
    let mut resp = match do_client::call_do(&st.env, addr, Method::Post, path, body).await {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("do {path} failed: {e:?}");
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "subscription update failed",
            );
        }
    };
    let code = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    if code == 200 {
        let (sql, binds): (&str, Vec<JsValue>) = match plan {
            Some(p) => (
                "UPDATE users SET plan = ? WHERE address = ?",
                vec![p.into(), addr.into()],
            ),
            None => (
                "UPDATE users SET plan = NULL WHERE address = ?",
                vec![addr.into()],
            ),
        };
        if let Err(e) = d1_exec(&st.env, sql, &binds).await {
            worker::console_error!("users.plan mirror failed: {e:?}");
        }
    }
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, [(header::CONTENT_TYPE, "application/json")], text).into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[worker::send]
pub async fn topup(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(req): Json<TopupReq>,
) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };

    // Resolve the requested asset from the registry.
    let Some(chain) = Chain::parse(&req.chain) else {
        return api_err(StatusCode::BAD_REQUEST, "unsupported chain");
    };
    let symbol = req.token.trim().to_lowercase();
    let Some(spec) = config::token(chain, &symbol) else {
        return api_err(StatusCode::BAD_REQUEST, "unsupported token");
    };

    match chain {
        Chain::Ethereum => topup_ethereum(&st, &addr, spec, &req.tx_hash).await,
        Chain::Solana => topup_solana(&st, &addr, spec, &req.tx_hash).await,
    }
}

/// The token's USD price with 8 decimals, or `None` for a $1 stablecoin.
/// Chainlink feeds live on Ethereum mainnet, so this always uses `rpc_url`
/// (even to price SOL). On RPC failure returns a ready retry-later response.
async fn resolve_price(
    st: &AppState,
    spec: &config::TokenSpec,
    tx_hash: &str,
) -> Result<Option<u128>, Response> {
    match spec.feed {
        None => Ok(None),
        Some(feed) => match rates::chainlink_price(&st.rpc_url, feed, session::now_secs()).await {
            Ok(p) => Ok(Some(p)),
            Err(e) => Err(rpc_unavailable(&st.env, tx_hash, "chainlink_price", e).await),
        },
    }
}

/// The user's linked Solana wallet (base58), if any.
async fn linked_solana(env: &Env, addr: &str) -> worker::Result<Option<String>> {
    #[derive(Deserialize)]
    struct Row {
        solana_address: Option<String>,
    }
    let row = env
        .d1(crate::D1_BINDING)?
        .prepare("SELECT solana_address FROM users WHERE address = ?")
        .bind(&[addr.into()])?
        .first::<Row>(None)
        .await?;
    Ok(row.and_then(|r| r.solana_address))
}

/// Solana top-up (native SOL + SPL USDT/USDC). Verification lives in
/// `crate::solana::topup_solana`; this runs the payment-row lifecycle + credit.
async fn topup_solana(
    st: &AppState,
    addr: &str,
    spec: &config::TokenSpec,
    signature_in: &str,
) -> Response {
    // 1) validate the signature
    let sig = signature_in.trim().to_string();
    if !solana::valid_signature(&sig) {
        return api_err(StatusCode::BAD_REQUEST, "invalid transaction signature");
    }

    // 2) the top-up must originate from a linked Solana wallet — or, for a
    //    standalone Solana (SIWS) account, from the account's own principal.
    let linked = match linked_solana(&st.env, addr).await {
        Ok(Some(l)) => l,
        Ok(None) if session::is_sol_principal(addr) => addr.to_string(),
        Ok(None) => {
            return api_err(
                StatusCode::BAD_REQUEST,
                "link a Solana wallet before topping up with SOL/SPL",
            );
        }
        Err(e) => {
            worker::console_error!("linked_solana lookup failed: {e:?}");
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error, retry later",
            );
        }
    };

    // 3) replay lock (signature is the payments PK)
    if let Err(e) = d1_exec(
        &st.env,
        "INSERT INTO payments (tx_hash, address, chain, token, created_at) VALUES (?, ?, ?, ?, ?)",
        &[
            sig.as_str().into(),
            addr.into(),
            spec.chain.as_str().into(),
            spec.symbol.into(),
            (session::now_secs() as f64).into(),
        ],
    )
    .await
    {
        if format!("{e:?}").to_lowercase().contains("constraint") {
            return api_err(StatusCode::CONFLICT, "tx already submitted");
        }
        worker::console_error!("payments insert failed for {sig}: {e:?}");
        return api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error, retry later",
        );
    }

    // 4) fetch + verify on-chain
    let amount = match solana::topup_solana(
        &st.sol_rpc_url,
        spec,
        &st.sol_deposit_address,
        &linked,
        &sig,
    )
    .await
    {
        SolOutcome::Credited { amount } => amount,
        SolOutcome::Reject(msg) => return reject(&st.env, &sig, msg).await,
        SolOutcome::WrongSender => {
            delete_pending(&st.env, &sig).await;
            return api_err(
                StatusCode::FORBIDDEN,
                "tx sender is not your linked Solana wallet",
            );
        }
        SolOutcome::TooEarly => return too_early(&st.env, &sig).await,
        SolOutcome::RpcError(e) => {
            worker::console_error!("solana verify failed for {sig}: {e}");
            delete_pending(&st.env, &sig).await;
            return api_err(StatusCode::BAD_GATEWAY, "rpc unavailable, retry later");
        }
    };

    // 5) price + points
    let price = match resolve_price(st, spec, &sig).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let points = rates::points_for(amount, spec.decimals, price);
    if points < MIN_TOPUP_POINTS {
        return reject(&st.env, &sig, "amount below minimum top-up").await;
    }

    finalize_credit(st, addr, &sig, amount, points).await
}

/// Ethereum top-up. SCAFFOLD: native ETH only; UNIT 3 adds the ERC-20 path for
/// `spec.contract.is_some()` (Transfer-log verification).
async fn topup_ethereum(
    st: &AppState,
    addr: &str,
    spec: &config::TokenSpec,
    tx_hash_in: &str,
) -> Response {
    if let Some(contract) = spec.contract {
        return topup_erc20(st, addr, spec, contract, tx_hash_in).await;
    }

    // 1) normalize + validate the hash
    let tx_hash = tx_hash_in.trim().to_lowercase();
    if !valid_tx_hash(&tx_hash) {
        return api_err(StatusCode::BAD_REQUEST, "invalid tx hash");
    }

    // 2) replay lock: tx_hash is the payments PK.
    if let Err(e) = d1_exec(
        &st.env,
        "INSERT INTO payments (tx_hash, address, chain, token, created_at) VALUES (?, ?, ?, ?, ?)",
        &[
            tx_hash.as_str().into(),
            addr.into(),
            spec.chain.as_str().into(),
            spec.symbol.into(),
            (session::now_secs() as f64).into(),
        ],
    )
    .await
    {
        if format!("{e:?}").to_lowercase().contains("constraint") {
            return api_err(StatusCode::CONFLICT, "tx already submitted");
        }
        worker::console_error!("payments insert failed for {tx_hash}: {e:?}");
        return api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error, retry later",
        );
    }

    // 3) the transaction itself: sender + recipient + value
    let tx_json = match rpc(
        &st.rpc_url,
        "eth_getTransactionByHash",
        serde_json::json!([tx_hash]),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionByHash", e).await,
    };
    if tx_json.is_null() {
        delete_pending(&st.env, &tx_hash).await;
        return api_err(StatusCode::BAD_REQUEST, "tx not found");
    }
    let tx: RpcTx = match serde_json::from_value(tx_json) {
        Ok(t) => t,
        Err(e) => {
            let e = worker::Error::RustError(e.to_string());
            return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionByHash decode", e).await;
        }
    };
    let amount = match verify_native_tx(&tx, &st.deposit_address) {
        Ok(w) => w,
        Err(msg) => return reject(&st.env, &tx_hash, msg).await,
    };
    if tx.from.to_lowercase() != addr {
        delete_pending(&st.env, &tx_hash).await;
        return api_err(
            StatusCode::FORBIDDEN,
            "tx sender does not match logged-in address",
        );
    }

    // 4) receipt: mined + successful
    let receipt_json = match rpc(
        &st.rpc_url,
        "eth_getTransactionReceipt",
        serde_json::json!([tx_hash]),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionReceipt", e).await,
    };
    let receipt: Option<RpcReceipt> = if receipt_json.is_null() {
        None
    } else {
        match serde_json::from_value(receipt_json) {
            Ok(r) => Some(r),
            Err(e) => {
                let e = worker::Error::RustError(e.to_string());
                return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionReceipt decode", e)
                    .await;
            }
        }
    };
    let block = match receipt {
        Some(RpcReceipt {
            status: Some(s), ..
        }) if s != "0x1" => {
            return reject(&st.env, &tx_hash, "tx failed on-chain").await;
        }
        Some(RpcReceipt {
            status: Some(_),
            block_number: Some(b),
            ..
        }) => match hex_to_u64(&b) {
            Some(b) => b,
            None => {
                let e = worker::Error::RustError(format!("bad receipt blockNumber: {b}"));
                return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionReceipt", e).await;
            }
        },
        _ => return too_early(&st.env, &tx_hash).await,
    };

    // 5) confirmations
    let head = match rpc(&st.rpc_url, "eth_blockNumber", serde_json::json!([])).await {
        Ok(v) => v.as_str().and_then(hex_to_u64),
        Err(e) => return rpc_unavailable(&st.env, &tx_hash, "eth_blockNumber", e).await,
    };
    let confirmed = head
        .and_then(|h| h.checked_sub(block))
        .is_some_and(|d| d + 1 >= MIN_CONFIRMATIONS);
    if !confirmed {
        return too_early(&st.env, &tx_hash).await;
    }

    // 6) price + points
    let price = match resolve_price(st, spec, &tx_hash).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let points = rates::points_for(amount, spec.decimals, price);
    if points < MIN_TOPUP_POINTS {
        return reject(&st.env, &tx_hash, "amount below minimum top-up").await;
    }

    finalize_credit(st, addr, &tx_hash, amount, points).await
}

/// Ethereum ERC-20 top-up (USDT/USDC). Mirrors the native path but verifies a
/// `Transfer(from=sender, to=deposit)` event log in the receipt instead of
/// `tx.value`. `contract` is the token's (lowercase) address from the registry.
async fn topup_erc20(
    st: &AppState,
    addr: &str,
    spec: &config::TokenSpec,
    contract: &str,
    tx_hash_in: &str,
) -> Response {
    // 1) normalize + validate the hash
    let tx_hash = tx_hash_in.trim().to_lowercase();
    if !valid_tx_hash(&tx_hash) {
        return api_err(StatusCode::BAD_REQUEST, "invalid tx hash");
    }

    // 2) replay lock: tx_hash is the payments PK.
    if let Err(e) = d1_exec(
        &st.env,
        "INSERT INTO payments (tx_hash, address, chain, token, created_at) VALUES (?, ?, ?, ?, ?)",
        &[
            tx_hash.as_str().into(),
            addr.into(),
            spec.chain.as_str().into(),
            spec.symbol.into(),
            (session::now_secs() as f64).into(),
        ],
    )
    .await
    {
        if format!("{e:?}").to_lowercase().contains("constraint") {
            return api_err(StatusCode::CONFLICT, "tx already submitted");
        }
        worker::console_error!("payments insert failed for {tx_hash}: {e:?}");
        return api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error, retry later",
        );
    }

    // 3) the transaction itself: existence + sender. `value` is irrelevant for
    //    an ERC-20 transfer (the token move lives in the receipt logs).
    let tx_json = match rpc(
        &st.rpc_url,
        "eth_getTransactionByHash",
        serde_json::json!([tx_hash]),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionByHash", e).await,
    };
    if tx_json.is_null() {
        delete_pending(&st.env, &tx_hash).await;
        return api_err(StatusCode::BAD_REQUEST, "tx not found");
    }
    let tx: RpcTx = match serde_json::from_value(tx_json) {
        Ok(t) => t,
        Err(e) => {
            let e = worker::Error::RustError(e.to_string());
            return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionByHash decode", e).await;
        }
    };
    if tx.from.to_lowercase() != addr {
        delete_pending(&st.env, &tx_hash).await;
        return api_err(
            StatusCode::FORBIDDEN,
            "tx sender does not match logged-in address",
        );
    }

    // 4) receipt: mined + successful, then the Transfer-log verification.
    let receipt_json = match rpc(
        &st.rpc_url,
        "eth_getTransactionReceipt",
        serde_json::json!([tx_hash]),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionReceipt", e).await,
    };
    if receipt_json.is_null() {
        return too_early(&st.env, &tx_hash).await;
    }
    let receipt: RpcReceipt = match serde_json::from_value(receipt_json) {
        Ok(r) => r,
        Err(e) => {
            let e = worker::Error::RustError(e.to_string());
            return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionReceipt decode", e).await;
        }
    };
    let block = match receipt {
        RpcReceipt {
            status: Some(s), ..
        } if s != "0x1" => {
            return reject(&st.env, &tx_hash, "tx failed on-chain").await;
        }
        RpcReceipt {
            status: Some(_),
            block_number: Some(ref b),
            ..
        } => match hex_to_u64(b) {
            Some(b) => b,
            None => {
                let e = worker::Error::RustError(format!("bad receipt blockNumber: {b}"));
                return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionReceipt", e).await;
            }
        },
        _ => return too_early(&st.env, &tx_hash).await,
    };

    // Find the token Transfer into the deposit address from this sender.
    let deposit_no0x = st
        .deposit_address
        .strip_prefix("0x")
        .unwrap_or(&st.deposit_address);
    let sender_no0x = addr.strip_prefix("0x").unwrap_or(addr);
    let amount = match match_transfer_log(&receipt.logs, contract, deposit_no0x, sender_no0x) {
        Some(a) => a,
        None => return reject(&st.env, &tx_hash, "no matching token transfer").await,
    };

    // 5) confirmations
    let head = match rpc(&st.rpc_url, "eth_blockNumber", serde_json::json!([])).await {
        Ok(v) => v.as_str().and_then(hex_to_u64),
        Err(e) => return rpc_unavailable(&st.env, &tx_hash, "eth_blockNumber", e).await,
    };
    let confirmed = head
        .and_then(|h| h.checked_sub(block))
        .is_some_and(|d| d + 1 >= MIN_CONFIRMATIONS);
    if !confirmed {
        return too_early(&st.env, &tx_hash).await;
    }

    // 6) price + points (stablecoins have no feed -> price None -> $1)
    let price = match resolve_price(st, spec, &tx_hash).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let points = rates::points_for(amount, spec.decimals, price);
    if points < MIN_TOPUP_POINTS {
        return reject(&st.env, &tx_hash, "amount below minimum top-up").await;
    }

    finalize_credit(st, addr, &tx_hash, amount, points).await
}

/// Credit points via the DO ("tx:{hash}" idempotency key), then finalize the
/// payment row. Shared by every chain/token path.
async fn finalize_credit(
    st: &AppState,
    addr: &str,
    tx_hash: &str,
    amount: u128,
    points: i64,
) -> Response {
    let credit = CreditReq {
        points,
        key: format!("tx:{tx_hash}"),
        reason: "topup".into(),
    };
    let bal = match do_client::do_credit(&st.env, addr, &credit).await {
        Ok(b) => b,
        Err(e) => {
            worker::console_error!("do_credit failed for {tx_hash}: {e:?}");
            delete_pending(&st.env, tx_hash).await;
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credit failed, retry later",
            );
        }
    };

    if let Err(e) = d1_exec(
        &st.env,
        "UPDATE payments SET amount=?, points=?, status='credited' WHERE tx_hash=?",
        &[
            amount.to_string().into(),
            (points as f64).into(),
            tx_hash.into(),
        ],
    )
    .await
    {
        worker::console_error!("payments finalize failed for {tx_hash}: {e:?}");
    }

    Json(TopupResp {
        credited_points: points,
        balance: bal.balance,
    })
    .into_response()
}

#[worker::send]
pub async fn list_payments(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };

    let stmt = st.env.d1(crate::D1_BINDING).and_then(|db| {
        db.prepare(
            "SELECT tx_hash, chain, token, amount, points, status, created_at \
             FROM payments WHERE address = ? ORDER BY created_at DESC LIMIT 50",
        )
        .bind(&[addr.as_str().into()])
    });
    let rows = match stmt {
        Ok(s) => s.all().await.and_then(|r| r.results::<PaymentRow>()),
        Err(e) => Err(e),
    };
    match rows {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => {
            worker::console_error!("payments list failed: {e:?}");
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "failed to load payments")
        }
    }
}

#[worker::send]
pub async fn subscribe(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(req): Json<SubscribeReq>,
) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };
    plan_passthrough(&st, &addr, "/subscribe", Some(&req), Some(&req.plan)).await
}

#[worker::send]
pub async fn unsubscribe(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };
    // No body / no plan: the DO refunds the prorated remainder and lapses to
    // PAYG; the passthrough mirrors `users.plan = NULL` in D1 on success.
    plan_passthrough(&st, &addr, "/unsubscribe", None, None).await
}

// ---------------------------------------------------------------------------
// Host unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const DEPOSIT: &str = "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc";
    const SENDER: &str = "0xa7d9ddbe1f17865597fbd27ec712455208b6b76d";

    fn tx(to: Option<&str>, value: &str) -> RpcTx {
        RpcTx {
            from: SENDER.into(),
            to: to.map(Into::into),
            value: value.into(),
        }
    }

    #[test]
    fn hex_quantity_parsing() {
        assert_eq!(hex_to_u128("0x0"), Some(0));
        assert_eq!(
            hex_to_u128("0xde0b6b3a7640000"),
            Some(1_000_000_000_000_000_000)
        );
        assert_eq!(hex_to_u128("de0b6b3a7640000"), None); // missing 0x
        assert_eq!(hex_to_u128("0x"), None); // empty digits
        assert_eq!(hex_to_u128("0xzz"), None); // garbage
        assert_eq!(hex_to_u64("0x151234"), Some(0x151234));
        assert_eq!(hex_to_u64("0x10000000000000000"), None); // > u64::MAX
    }

    #[test]
    fn tx_hash_validation() {
        let ok = format!("0x{}", "ab12".repeat(16));
        assert_eq!(ok.len(), 66);
        assert!(valid_tx_hash(&ok));
        assert!(!valid_tx_hash(&ok.to_uppercase())); // must be normalized first
        assert!(!valid_tx_hash("0x1234")); // too short
        assert!(!valid_tx_hash(&format!("0x{}", "g".repeat(64)))); // non-hex
        assert!(!valid_tx_hash(&"a".repeat(66))); // no 0x prefix
    }

    #[test]
    fn native_tx_recipient_check() {
        let good = tx(Some(DEPOSIT), "0xde0b6b3a7640000");
        assert_eq!(verify_native_tx(&good, DEPOSIT), Ok(10u128.pow(18)));
        // wrong recipient rejected
        assert!(verify_native_tx(&good, "0x0000000000000000000000000000000000000001").is_err());
        // checksummed `to` still matches (verification lowercases)
        let mixed = tx(
            Some("0x9965507D1a55bcc2695C58ba16FB37d819B0A4dc"),
            "0xde0b6b3a7640000",
        );
        assert_eq!(verify_native_tx(&mixed, DEPOSIT), Ok(10u128.pow(18)));
        // contract creation (no `to`) rejected
        assert!(verify_native_tx(&tx(None, "0x1"), DEPOSIT).is_err());
    }

    // USDC on Ethereum mainnet.
    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    fn log(address: &str, topic0: &str, from_no0x: &str, to_no0x: &str, data: &str) -> RpcLog {
        RpcLog {
            address: address.into(),
            topics: vec![
                topic0.into(),
                format!("0x{}{from_no0x}", "0".repeat(24)),
                format!("0x{}{to_no0x}", "0".repeat(24)),
            ],
            data: data.into(),
        }
    }

    /// A well-formed USDC `Transfer(SENDER -> DEPOSIT)` of `amount` base units.
    fn transfer_log(amount: u128) -> RpcLog {
        log(
            USDC,
            TRANSFER_TOPIC0,
            &SENDER[2..],
            &DEPOSIT[2..],
            &format!("0x{amount:064x}"),
        )
    }

    #[test]
    fn transfer_log_match_and_amount() {
        // 1 USDC (6 decimals).
        let logs = vec![transfer_log(1_000_000)];
        assert_eq!(
            match_transfer_log(&logs, USDC, &DEPOSIT[2..], &SENDER[2..]),
            Some(1_000_000)
        );
    }

    #[test]
    fn transfer_log_wrong_contract_ignored() {
        // Same Transfer, but emitted by USDT — not the token we expect.
        let usdt = "0xdac17f958d2ee523a2206206994597c13d831ec7";
        let logs = vec![log(
            usdt,
            TRANSFER_TOPIC0,
            &SENDER[2..],
            &DEPOSIT[2..],
            &format!("0x{:064x}", 1_000_000u128),
        )];
        assert_eq!(
            match_transfer_log(&logs, USDC, &DEPOSIT[2..], &SENDER[2..]),
            None
        );
    }

    #[test]
    fn transfer_log_wrong_topic0_ignored() {
        // Approval, not Transfer, in the USDC contract.
        let approval = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
        let logs = vec![log(
            USDC,
            approval,
            &SENDER[2..],
            &DEPOSIT[2..],
            &format!("0x{:064x}", 1_000_000u128),
        )];
        assert_eq!(
            match_transfer_log(&logs, USDC, &DEPOSIT[2..], &SENDER[2..]),
            None
        );
    }

    #[test]
    fn transfer_log_wrong_recipient_ignored() {
        // Transfer to some other address, not our deposit address.
        let other = "1111111111111111111111111111111111111111";
        let logs = vec![log(
            USDC,
            TRANSFER_TOPIC0,
            &SENDER[2..],
            other,
            &format!("0x{:064x}", 1_000_000u128),
        )];
        assert_eq!(
            match_transfer_log(&logs, USDC, &DEPOSIT[2..], &SENDER[2..]),
            None
        );
    }

    #[test]
    fn transfer_log_wrong_sender_ignored() {
        // Correct recipient/contract, but a different `from`.
        let other = "2222222222222222222222222222222222222222";
        let logs = vec![log(
            USDC,
            TRANSFER_TOPIC0,
            other,
            &DEPOSIT[2..],
            &format!("0x{:064x}", 1_000_000u128),
        )];
        assert_eq!(
            match_transfer_log(&logs, USDC, &DEPOSIT[2..], &SENDER[2..]),
            None
        );
    }

    #[test]
    fn transfer_log_skips_noise_and_matches_later() {
        // A non-Transfer log precedes the real one; it must be skipped.
        let approval = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
        let noise = log(USDC, approval, &SENDER[2..], &DEPOSIT[2..], "0x0");
        let logs = vec![noise, transfer_log(2_500_000)];
        assert_eq!(
            match_transfer_log(&logs, USDC, &DEPOSIT[2..], &SENDER[2..]),
            Some(2_500_000)
        );
    }

    #[test]
    fn transfer_log_checksummed_contract_matches() {
        // Node returns an EIP-55 mixed-case `log.address`; we still match.
        let mut lg = transfer_log(1_000_000);
        lg.address = "0xA0b86991c6218b36c1D19D4a2e9Eb0cE3606eB48".into();
        assert_eq!(
            match_transfer_log(&[lg], USDC, &DEPOSIT[2..], &SENDER[2..]),
            Some(1_000_000)
        );
    }
}
