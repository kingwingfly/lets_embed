//! UNIT 4: crypto top-up (on-chain verification) + subscription passthrough.
//!
//! - POST /user/api/topup Json(TopupReq) -> 200 Json(TopupResp) | 400 | 401 |
//!   403 (tx sender != session address) | 409 (tx already submitted) |
//!   425 (not mined / not enough confirmations yet, retry).
//!   Flow: validate hash -> INSERT payments 'pending' (PK conflict -> 409) ->
//!   eth_getTransactionByHash (from == session address, to == deposit_address,
//!   value >= MIN_TOPUP_WEI) -> eth_getTransactionReceipt (status 0x1) ->
//!   eth_blockNumber (>= MIN_CONFIRMATIONS) -> points =
//!   wei * POINTS_PER_ETH / 1e18 (u128) -> do_credit key "tx:{hash}" ->
//!   UPDATE row to 'credited'. JSON-RPC: hand-rolled over worker::Fetch
//!   against st.rpc_url.
//!   Row lifecycle: 'rejected' is written only for tx-intrinsic failures
//!   (wrong recipient, dust value, reverted) — those are invalid for any
//!   submitter, and the PK replay lock then answers 409 forever. Transient
//!   or submitter-relative failures (tx not visible yet, unmined, sender
//!   mismatch, RPC/DO outages) DELETE the pending row so resubmission works.
//! - GET  /user/api/payments -> 200 Json(Vec<PaymentRow>) (newest 50) | 401.
//! - POST /user/api/subscribe Json(SubscribeReq) -> passthrough to DO
//!   /subscribe; on 200 mirror `users.plan` in D1. 400/402/409 pass through.
//! - POST /user/api/unsubscribe -> DO /unsubscribe; mirror plan=NULL.

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
use crate::config::{MIN_CONFIRMATIONS, MIN_TOPUP_WEI, POINTS_PER_ETH};
use crate::types::{ApiError, CreditReq, PaymentRow, SubscribeReq, TopupReq, TopupResp};
use crate::{do_client, session};

// ---------------------------------------------------------------------------
// JSON-RPC over worker::Fetch (no alloy/ethers)
// ---------------------------------------------------------------------------

/// Single JSON-RPC call; returns the `result` field. A non-2xx HTTP response
/// or a JSON-RPC-level `error` is turned into `Err`.
async fn rpc(url: &str, method: &str, params: serde_json::Value) -> worker::Result<serde_json::Value> {
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
        // A rate-limited / erroring endpoint must not be mistaken for a
        // valid null result ("tx not found").
        return Err(worker::Error::RustError(format!("rpc {method}: http {code}")));
    }
    let v: serde_json::Value = resp.json().await?;
    if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
        return Err(worker::Error::RustError(format!("rpc {method} error: {e}")));
    }
    Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

/// Ethereum quantity ("0x"-prefixed hex) -> u128.
fn hex_to_u128(s: &str) -> Option<u128> {
    u128::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

/// Ethereum quantity ("0x"-prefixed hex) -> u64.
fn hex_to_u64(s: &str) -> Option<u64> {
    hex_to_u128(s)?.try_into().ok()
}

/// Wei -> points. Saturates instead of wrapping/truncating so an exotic
/// chain's absurd `value` can never become a negative (debiting) credit.
fn wei_to_points(wei: u128) -> i64 {
    wei.checked_mul(POINTS_PER_ETH)
        .map(|p| p / 10u128.pow(18))
        .map_or(i64::MAX, |p| i64::try_from(p).unwrap_or(i64::MAX))
}

/// Lowercase 0x-prefixed 32-byte tx hash (`^0x[0-9a-f]{64}$`).
fn valid_tx_hash(s: &str) -> bool {
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
}

/// Verify a native-ETH transfer and return its value in wei. Only checks
/// tx-intrinsic properties (recipient, amount) — failures here are permanent
/// for any submitter. An ERC-20 variant would instead decode the receipt's
/// `Transfer` logs and check the token contract / recipient — keep the
/// `Result<wei, reason>` shape so it can slot in next to this.
fn verify_native_tx(tx: &RpcTx, deposit_address: &str) -> Result<u128, &'static str> {
    let to = tx.to.as_deref().ok_or("tx has no recipient")?.to_lowercase();
    if to != deposit_address {
        return Err("tx recipient is not the deposit address");
    }
    let wei = hex_to_u128(&tx.value).ok_or("bad tx value")?;
    if wei < MIN_TOPUP_WEI {
        return Err("amount below minimum top-up");
    }
    Ok(wei)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn api_err(code: StatusCode, msg: &str) -> Response {
    (code, Json(ApiError { error: msg.into() })).into_response()
}

async fn d1_exec(env: &Env, sql: &str, binds: &[JsValue]) -> worker::Result<()> {
    env.d1(crate::D1_BINDING)?.prepare(sql).bind(binds)?.run().await?;
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
    api_err(StatusCode::TOO_EARLY, "not enough confirmations yet, retry later")
}

/// Forward a subscription change to the user's DO, relay its status + JSON
/// body, and on 200 mirror the display-only `users.plan` column in D1
/// (the DO stays the authority).
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
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "subscription update failed");
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

    // 1) normalize + validate the hash
    let tx_hash = req.tx_hash.trim().to_lowercase();
    if !valid_tx_hash(&tx_hash) {
        return api_err(StatusCode::BAD_REQUEST, "invalid tx hash");
    }

    // 2) replay lock: tx_hash is the payments PK; a constraint conflict means
    //    this tx was already submitted (by anyone).
    if let Err(e) = d1_exec(
        &st.env,
        "INSERT INTO payments (tx_hash, address, created_at) VALUES (?, ?, ?)",
        &[
            tx_hash.as_str().into(),
            addr.as_str().into(),
            (session::now_secs() as f64).into(),
        ],
    )
    .await
    {
        if format!("{e:?}").to_lowercase().contains("constraint") {
            return api_err(StatusCode::CONFLICT, "tx already submitted");
        }
        worker::console_error!("payments insert failed for {tx_hash}: {e:?}");
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "database error, retry later");
    }

    // 3) the transaction itself: sender + recipient + value
    let tx_json = match rpc(&st.rpc_url, "eth_getTransactionByHash", serde_json::json!([tx_hash])).await {
        Ok(v) => v,
        Err(e) => return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionByHash", e).await,
    };
    if tx_json.is_null() {
        // Bad hash — or propagation lag right after broadcast. Release the
        // replay lock (instead of writing a 'rejected' row) so a valid hash
        // can be resubmitted once our RPC node sees it.
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
    let wei = match verify_native_tx(&tx, &st.deposit_address) {
        Ok(w) => w,
        Err(msg) => return reject(&st.env, &tx_hash, msg).await,
    };
    // The claimer must be the on-chain sender, otherwise anyone watching the
    // chain could steal a deposit by submitting its hash first. The mismatch
    // is submitter-relative (the rightful sender must still be able to
    // claim), so release the replay lock rather than rejecting the row.
    if tx.from.to_lowercase() != addr {
        delete_pending(&st.env, &tx_hash).await;
        return api_err(StatusCode::FORBIDDEN, "tx sender does not match logged-in address");
    }

    // 4) the receipt: must be mined and have executed successfully
    let receipt_json =
        match rpc(&st.rpc_url, "eth_getTransactionReceipt", serde_json::json!([tx_hash])).await {
            Ok(v) => v,
            Err(e) => return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionReceipt", e).await,
        };
    let receipt: Option<RpcReceipt> = if receipt_json.is_null() {
        None // known tx without a receipt: in the mempool, not mined yet
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
        // reverted on-chain: permanently invalid for any submitter
        Some(RpcReceipt { status: Some(s), .. }) if s != "0x1" => {
            return reject(&st.env, &tx_hash, "tx failed on-chain").await;
        }
        Some(RpcReceipt {
            status: Some(_),
            block_number: Some(b),
        }) => match hex_to_u64(&b) {
            Some(b) => b,
            None => {
                let e = worker::Error::RustError(format!("bad receipt blockNumber: {b}"));
                return rpc_unavailable(&st.env, &tx_hash, "eth_getTransactionReceipt", e).await;
            }
        },
        // no receipt / no status / no block: not mined => 0 confirmations,
        // just the strongest form of "not enough confirmations yet".
        _ => return too_early(&st.env, &tx_hash).await,
    };

    // 5) confirmations; not enough yet is retryable, so release the lock
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

    // 6) credit via the DO ("tx:{hash}" idempotency key makes retries no-ops)
    let points = wei_to_points(wei);
    let credit = CreditReq {
        points,
        key: format!("tx:{tx_hash}"),
        reason: "topup".into(),
    };
    let bal = match do_client::do_credit(&st.env, &addr, &credit).await {
        Ok(b) => b,
        Err(e) => {
            worker::console_error!("do_credit failed for {tx_hash}: {e:?}");
            delete_pending(&st.env, &tx_hash).await;
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "credit failed, retry later");
        }
    };

    // 7) finalize the payment row. The credit already happened, so a mirror
    //    failure only degrades the history listing — log and answer 200.
    if let Err(e) = d1_exec(
        &st.env,
        "UPDATE payments SET amount_wei=?, points=?, status='credited' WHERE tx_hash=?",
        &[
            wei.to_string().into(),
            (points as f64).into(),
            tx_hash.as_str().into(),
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
            "SELECT tx_hash, amount_wei, token, points, status, created_at \
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
        assert_eq!(hex_to_u128("0xde0b6b3a7640000"), Some(1_000_000_000_000_000_000));
        assert_eq!(hex_to_u128("de0b6b3a7640000"), None); // missing 0x
        assert_eq!(hex_to_u128("0x"), None); // empty digits
        assert_eq!(hex_to_u128("0xzz"), None); // garbage
        assert_eq!(hex_to_u128("garbage"), None);

        assert_eq!(hex_to_u64("0x0"), Some(0));
        assert_eq!(hex_to_u64("0x151234"), Some(0x151234));
        assert_eq!(hex_to_u64("0xffffffffffffffff"), Some(u64::MAX));
        assert_eq!(hex_to_u64("0x10000000000000000"), None); // > u64::MAX
        assert_eq!(hex_to_u64("151234"), None); // missing 0x
        assert_eq!(hex_to_u64("0xg"), None); // garbage
    }

    #[test]
    fn points_conversion() {
        // 1 ETH -> POINTS_PER_ETH
        assert_eq!(wei_to_points(10u128.pow(18)), POINTS_PER_ETH as i64);
        // MIN_TOPUP_WEI (0.001 ETH) -> 100 points
        assert_eq!(
            wei_to_points(MIN_TOPUP_WEI),
            (MIN_TOPUP_WEI * POINTS_PER_ETH / 10u128.pow(18)) as i64
        );
        assert_eq!(wei_to_points(MIN_TOPUP_WEI), 100);
        // sub-point remainders truncate
        let wei_per_point = 10u128.pow(18) / POINTS_PER_ETH;
        assert_eq!(wei_to_points(wei_per_point - 1), 0);
        assert_eq!(wei_to_points(wei_per_point), 1);
        assert_eq!(wei_to_points(0), 0);
        // absurd values saturate instead of wrapping to a negative credit
        assert_eq!(wei_to_points(u128::MAX), i64::MAX);
        assert!(wei_to_points(u128::MAX / 2) >= 0);
    }

    #[test]
    fn tx_hash_validation() {
        let ok = format!("0x{}", "ab12".repeat(16));
        assert_eq!(ok.len(), 66);
        assert!(valid_tx_hash(&ok));
        // uppercase must be normalized before the check
        assert!(!valid_tx_hash(&ok.to_uppercase()));
        assert!(valid_tx_hash(&ok.to_uppercase().to_lowercase()));
        assert!(!valid_tx_hash("0x1234")); // too short
        assert!(!valid_tx_hash(&format!("0x{}", "g".repeat(64)))); // non-hex
        assert!(!valid_tx_hash(&"a".repeat(66))); // no 0x prefix
        assert!(!valid_tx_hash(&format!("0x{}", "a".repeat(65)))); // too long
    }

    #[test]
    fn canned_tx_deserialization_and_verification() {
        // eth_getTransactionByHash result (1 ETH to the deposit address)
        let tx_json = serde_json::json!({
            "blockHash": "0x8243343df08b9751f5ca0c5f8c9c0460d8a9b6351066fae0acbd4d3e776de8bb",
            "blockNumber": "0x151234",
            "from": SENDER,
            "gas": "0x5208",
            "gasPrice": "0x3b9aca00",
            "hash": "0x88df016429689c079f3b2f6ad39fa052532c56795b733da78a91ebe6a713944b",
            "input": "0x",
            "nonce": "0x15",
            "to": DEPOSIT,
            "transactionIndex": "0x1",
            "value": "0xde0b6b3a7640000",
            "v": "0x25",
            "r": "0x1b5e176d927f8e9ab405058b2d2457392da3e20f328b16ddabcebc33eaac5fea",
            "s": "0x4ba69724e8f69de52f0125ad8b3c5c2cef33019bac3249e2c0a2192766d1721c"
        });
        let parsed: RpcTx = serde_json::from_value(tx_json).expect("tx deserializes");
        assert_eq!(parsed.from, SENDER);
        assert_eq!(parsed.to.as_deref(), Some(DEPOSIT));
        assert_eq!(verify_native_tx(&parsed, DEPOSIT), Ok(10u128.pow(18)));

        // wrong recipient rejected
        assert!(verify_native_tx(&parsed, "0x0000000000000000000000000000000000000001").is_err());
        // below-minimum value rejected
        let dust = tx(Some(DEPOSIT), &format!("0x{:x}", MIN_TOPUP_WEI - 1));
        assert!(verify_native_tx(&dust, DEPOSIT).is_err());
        // checksummed `to` still matches (verification lowercases)
        let mixed = tx(
            Some("0x9965507D1a55bcc2695C58ba16FB37d819B0A4dc"),
            "0xde0b6b3a7640000",
        );
        assert_eq!(verify_native_tx(&mixed, DEPOSIT), Ok(10u128.pow(18)));
        // contract creation (no `to`) rejected
        let create = tx(None, "0xde0b6b3a7640000");
        assert!(verify_native_tx(&create, DEPOSIT).is_err());

        // eth_getTransactionReceipt result
        let receipt_json = serde_json::json!({
            "transactionHash": "0x88df016429689c079f3b2f6ad39fa052532c56795b733da78a91ebe6a713944b",
            "transactionIndex": "0x1",
            "blockHash": "0x8243343df08b9751f5ca0c5f8c9c0460d8a9b6351066fae0acbd4d3e776de8bb",
            "blockNumber": "0x151234",
            "from": SENDER,
            "to": DEPOSIT,
            "cumulativeGasUsed": "0x33bc",
            "gasUsed": "0x5208",
            "contractAddress": null,
            "logs": [],
            "logsBloom": "0x00",
            "status": "0x1"
        });
        let receipt: RpcReceipt = serde_json::from_value(receipt_json).expect("receipt deserializes");
        assert_eq!(receipt.status.as_deref(), Some("0x1"));
        assert_eq!(receipt.block_number.as_deref().and_then(hex_to_u64), Some(0x151234));

        // pending receipt (null fields) still deserializes without success
        let pending: RpcReceipt =
            serde_json::from_value(serde_json::json!({"status": null, "blockNumber": null}))
                .expect("pending receipt deserializes");
        assert!(pending.status.is_none());
        assert!(pending.block_number.is_none());
    }
}
