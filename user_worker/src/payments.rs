//! Ethereum and Solana deposits, payment history and wallet subscriptions.
//! Confirmed transfers use the receiving address, points rate and minimum at their
//! block time. The transaction hash is the D1 replay lock and the account credit key.

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
use crate::config::{self, Chain, MIN_CONFIRMATIONS};
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

/// Read the indexed 20-byte address, accepting RPC nodes that omit ABI padding.
fn topic_address(topic: &str) -> Option<&str> {
    let hex = topic.strip_prefix("0x")?;
    let address = match hex.len() {
        64 => hex.strip_prefix("000000000000000000000000")?,
        40 => hex,
        _ => return None,
    };
    address
        .bytes()
        .all(|c| c.is_ascii_hexdigit())
        .then_some(address)
}

/// A single transaction can carry several transfers of the selected asset.
fn match_transfer_log(
    logs: &[RpcLog],
    token_addr: &str,
    deposit_no0x: &str,
    sender_no0x: &str,
) -> Option<u128> {
    if sender_no0x.eq_ignore_ascii_case(deposit_no0x) {
        return None;
    }
    let mut total = None;
    for log in logs {
        if !log.address.eq_ignore_ascii_case(token_addr)
            || log.topics.len() != 3
            || !log.topics[0].eq_ignore_ascii_case(TRANSFER_TOPIC0)
            || !topic_address(&log.topics[1]).is_some_and(|a| a.eq_ignore_ascii_case(sender_no0x))
            || !topic_address(&log.topics[2]).is_some_and(|a| a.eq_ignore_ascii_case(deposit_no0x))
        {
            continue;
        }
        total = Some(
            total
                .unwrap_or(0u128)
                .checked_add(hex_to_u128(&log.data)?)?,
        );
    }
    total
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
    if tx.from.eq_ignore_ascii_case(deposit_address) {
        return Err("sender and deposit address are the same");
    }
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

struct Deposit<'a> {
    address: &'a str,
    hash: &'a str,
    token: &'a config::TokenSpec,
}

impl Deposit<'_> {
    // A positive pending quote was verified and saved before contacting the DO.
    // Legacy pending rows have zero points and still need on-chain verification.
    async fn resume(&self, st: &AppState) -> worker::Result<Option<Response>> {
        #[derive(Deserialize)]
        struct Receipt {
            address: String,
            chain: String,
            token: String,
            status: String,
            points: String,
        }
        let row = st.env.d1(crate::D1_BINDING)?
            .prepare("SELECT address, chain, token, status, CAST(points AS TEXT) AS points FROM payments WHERE tx_hash=?")
            .bind(&[self.hash.into()])?.first::<Receipt>(None).await?;
        let Some(row) = row else { return Ok(None) };
        if row.status == "rejected" {
            return Ok(None);
        }
        if row.status == "pending" {
            if row.points == "0" {
                // Older Workers saved only a boolean in the account. A new quote
                // could misstate an earlier credit if its ledger write failed.
                if !do_client::payment_applied(&st.env, &row.address, self.hash).await? {
                    return Ok(None);
                }
                if row.address == self.address {
                    return Ok(Some(api_err(
                        StatusCode::CONFLICT,
                        "This payment was already credited. If it still shows as pending, contact support to reconcile the original receipt.",
                    )));
                }
            } else if row.address == self.address
                && row.token == self.token.symbol
                && row.chain == self.token.chain.as_str()
            {
                let points = row
                    .points
                    .parse::<i64>()
                    .map_err(|e| worker::Error::RustError(e.to_string()))?;
                return Ok(Some(
                    finalize_credit(st, self.address, self.hash, points).await,
                ));
            }
        }
        Ok(Some(api_err(StatusCode::CONFLICT, "tx already submitted")))
    }

    async fn reject(&self, env: &Env, msg: &str) -> Response {
        if let Err(e) = d1_exec(env,
            "INSERT INTO payments(tx_hash,address,chain,token,created_at,status) VALUES(?,?,?,?,unixepoch(),'rejected') ON CONFLICT(tx_hash) DO NOTHING",
            &[self.hash.into(), self.address.into(), self.token.chain.as_str().into(), self.token.symbol.into()],
        ).await {
            worker::console_error!("recording rejected payment failed: {e:?}");
        }
        api_err(StatusCode::BAD_REQUEST, msg)
    }

    async fn credit_verified(&self, st: &AppState, amount: u128, points: i64) -> Response {
        // The first verified claimant fixes the wallet, asset and quote. A retry
        // can finish that same credit even if the market price has since changed.
        let write = d1_exec(
            &st.env,
            "INSERT INTO payments(tx_hash,address,chain,token,amount,points,created_at,status)
             VALUES(?,?,?,?,?,?,unixepoch(),'pending') ON CONFLICT(tx_hash) DO UPDATE SET
             address=excluded.address, chain=excluded.chain, token=excluded.token,
             amount=excluded.amount, points=excluded.points, status='pending'
             WHERE payments.status='rejected' OR
             (payments.status='pending' AND payments.points=0)",
            &[
                self.hash.into(),
                self.address.into(),
                self.token.chain.as_str().into(),
                self.token.symbol.into(),
                amount.to_string().into(),
                points.to_string().into(),
            ],
        )
        .await;
        if let Err(e) = write {
            return payment_db_error(e);
        }
        match self.resume(st).await {
            Ok(Some(response)) => response,
            Ok(None) => api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "Retry the verified payment",
            ),
            Err(e) => payment_db_error(e),
        }
    }
}

fn payment_db_error(e: worker::Error) -> Response {
    worker::console_error!("payment database error: {e:?}");
    api_err(
        StatusCode::SERVICE_UNAVAILABLE,
        "database unavailable, retry later",
    )
}

fn rpc_unavailable(method: &str, e: worker::Error) -> Response {
    worker::console_error!("{method} failed: {e:?}");
    api_err(StatusCode::BAD_GATEWAY, "rpc unavailable, retry later")
}

fn too_early() -> Response {
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

    let hash = match chain {
        Chain::Ethereum => {
            let hash = req.tx_hash.trim().to_ascii_lowercase();
            if !valid_tx_hash(&hash) {
                return api_err(StatusCode::BAD_REQUEST, "invalid tx hash");
            }
            hash
        }
        Chain::Solana => {
            let sig = req.tx_hash.trim();
            if !solana::valid_signature(sig) {
                return api_err(StatusCode::BAD_REQUEST, "invalid transaction signature");
            }
            sig.to_owned()
        }
    };
    let deposit = Deposit {
        address: &addr,
        hash: &hash,
        token: spec,
    };
    match deposit.resume(&st).await {
        Ok(Some(response)) => return response,
        Err(e) => return payment_db_error(e),
        Ok(None) => {}
    }
    match chain {
        Chain::Ethereum => topup_ethereum(&st, &deposit).await,
        Chain::Solana => topup_solana(&st, &deposit).await,
    }
}

/// The token's USD price with 8 decimals, or `None` for a $1 stablecoin.
/// Chainlink feeds live on Ethereum mainnet, so this always uses `rpc_url`
/// (even to price SOL). On RPC failure returns a ready retry-later response.
async fn resolve_price(st: &AppState, spec: &config::TokenSpec) -> Result<Option<u128>, Response> {
    match spec.feed {
        None => Ok(None),
        Some(feed) => match rates::chainlink_price(&st.rpc_url, feed, session::now_secs()).await {
            Ok(p) => Ok(Some(p)),
            Err(e) => Err(rpc_unavailable("chainlink_price", e)),
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
/// `crate::solana`. This handler owns the payment row and account credit.
async fn topup_solana(st: &AppState, deposit: &Deposit<'_>) -> Response {
    let (addr, sig, spec) = (deposit.address, deposit.hash, deposit.token);
    // Standalone Solana accounts can deposit from their own principal.
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

    let tx = match solana::get_transaction(&st.sol_rpc_url, sig).await {
        Ok(tx) if tx.is_null() => return too_early(),
        Ok(tx) => tx,
        Err(e) => return rpc_unavailable("getTransaction", e),
    };
    let Some(timestamp) = tx["blockTime"].as_u64() else {
        return too_early();
    };
    let policy = match deposit_terms(st, timestamp).await {
        Ok(p) => p,
        Err(response) => return response,
    };
    if policy.sol_deposit.is_empty() {
        return deposit
            .reject(&st.env, "Deposits disabled at transfer time")
            .await;
    }
    let amount = match solana::verify_solana(&tx, spec, &policy.sol_deposit, &linked) {
        SolOutcome::Credited { amount } => amount,
        SolOutcome::Reject(msg) => return deposit.reject(&st.env, msg).await,
        SolOutcome::WrongSender => {
            return api_err(
                StatusCode::FORBIDDEN,
                "tx sender is not your linked Solana wallet",
            );
        }
        SolOutcome::RpcError(e) => {
            return rpc_unavailable("getTransaction decode", worker::Error::RustError(e));
        }
    };

    let price = match resolve_price(st, spec).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let points = rates::points_at_rate(amount, spec.decimals, price, policy.points_per_usd);
    if points < policy.minimum_topup {
        return deposit.reject(&st.env, "amount below minimum top-up").await;
    }

    deposit.credit_verified(st, amount, points).await
}

async fn deposit_terms(st: &AppState, timestamp: u64) -> Result<crate::settings::Policy, Response> {
    match crate::settings::Published::at_block(&st.env, timestamp).await {
        Ok(policy) => Ok(policy),
        Err(e) => {
            worker::console_error!("Could not load payment terms: {e}");
            Err(api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "Payment settings unavailable, retry later",
            ))
        }
    }
}

/// Native ETH and ERC-20 share the same sender, receipt, confirmation and block-time checks.
async fn topup_ethereum(st: &AppState, deposit: &Deposit<'_>) -> Response {
    let (addr, tx_hash, spec) = (deposit.address, deposit.hash, deposit.token);
    let tx_json = match rpc(
        &st.rpc_url,
        "eth_getTransactionByHash",
        serde_json::json!([tx_hash]),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return rpc_unavailable("eth_getTransactionByHash", e),
    };
    if tx_json.is_null() {
        return api_err(StatusCode::BAD_REQUEST, "tx not found");
    }
    let tx: RpcTx = match serde_json::from_value(tx_json) {
        Ok(t) => t,
        Err(e) => {
            let e = worker::Error::RustError(e.to_string());
            return rpc_unavailable("eth_getTransactionByHash decode", e);
        }
    };
    if tx.from.to_lowercase() != addr {
        return api_err(
            StatusCode::FORBIDDEN,
            "tx sender does not match logged-in address",
        );
    }

    let receipt_json = match rpc(
        &st.rpc_url,
        "eth_getTransactionReceipt",
        serde_json::json!([tx_hash]),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return rpc_unavailable("eth_getTransactionReceipt", e),
    };
    let receipt: Option<RpcReceipt> = if receipt_json.is_null() {
        None
    } else {
        match serde_json::from_value(receipt_json) {
            Ok(r) => Some(r),
            Err(e) => {
                let e = worker::Error::RustError(e.to_string());
                return rpc_unavailable("eth_getTransactionReceipt decode", e);
            }
        }
    };
    let block = match &receipt {
        Some(RpcReceipt {
            status: Some(s), ..
        }) if s != "0x1" => {
            return deposit.reject(&st.env, "tx failed on-chain").await;
        }
        Some(RpcReceipt {
            status: Some(_),
            block_number: Some(b),
            ..
        }) => match hex_to_u64(b) {
            Some(b) => b,
            None => {
                let e = worker::Error::RustError(format!("bad receipt blockNumber: {b}"));
                return rpc_unavailable("eth_getTransactionReceipt", e);
            }
        },
        _ => return too_early(),
    };

    let head = match rpc(&st.rpc_url, "eth_blockNumber", serde_json::json!([])).await {
        Ok(v) => v.as_str().and_then(hex_to_u64),
        Err(e) => return rpc_unavailable("eth_blockNumber", e),
    };
    let confirmed = head
        .and_then(|h| h.checked_sub(block))
        .is_some_and(|d| d + 1 >= MIN_CONFIRMATIONS);
    if !confirmed {
        return too_early();
    }

    let block_time = match rpc(
        &st.rpc_url,
        "eth_getBlockByNumber",
        serde_json::json!([format!("0x{block:x}"), false]),
    )
    .await
    {
        Ok(v) => v["timestamp"].as_str().and_then(hex_to_u64),
        Err(e) => return rpc_unavailable("eth_getBlockByNumber", e),
    };
    let Some(timestamp) = block_time else {
        return too_early();
    };
    let policy = match deposit_terms(st, timestamp).await {
        Ok(p) => p,
        Err(response) => return response,
    };
    let amount = match spec.contract {
        Some(contract) => {
            let recipient = policy.eth_deposit.strip_prefix("0x").unwrap_or("");
            let sender = addr.strip_prefix("0x").unwrap_or(addr);
            let logs = &receipt.as_ref().expect("confirmed receipt").logs;
            if recipient.is_empty() {
                return deposit
                    .reject(&st.env, "Deposits disabled at transfer time")
                    .await;
            }
            match match_transfer_log(logs, contract, recipient, sender) {
                Some(amount) => amount,
                None => return deposit.reject(&st.env, "no matching token transfer").await,
            }
        }
        None => match verify_native_tx(&tx, &policy.eth_deposit) {
            Ok(amount) => amount,
            Err(msg) => return deposit.reject(&st.env, msg).await,
        },
    };

    let price = match resolve_price(st, spec).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let points = rates::points_at_rate(amount, spec.decimals, price, policy.points_per_usd);
    if points < policy.minimum_topup {
        return deposit.reject(&st.env, "amount below minimum top-up").await;
    }

    deposit.credit_verified(st, amount, points).await
}

/// Credit points via the DO ("tx:{hash}" idempotency key), then finalize the
/// payment row. Shared by every chain/token path.
async fn finalize_credit(st: &AppState, addr: &str, tx_hash: &str, points: i64) -> Response {
    let credit = CreditReq {
        points,
        key: format!("tx:{tx_hash}"),
        reason: "topup".into(),
    };
    let bal = match do_client::do_credit(&st.env, addr, &credit).await {
        Ok(b) => b,
        Err(e) => {
            worker::console_error!("do_credit failed for {tx_hash}: {e:?}");
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credit failed, retry later",
            );
        }
    };

    if let Err(e) = d1_exec(
        &st.env,
        "UPDATE payments SET status='credited' WHERE tx_hash=? AND address=? AND status='pending'",
        &[tx_hash.into(), addr.into()],
    )
    .await
    {
        return payment_db_error(e);
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
    fn multiple_transfers_in_one_payment_are_added() {
        let logs = [transfer_log(30), transfer_log(70)];
        assert_eq!(
            match_transfer_log(&logs, USDC, &DEPOSIT[2..], &SENDER[2..]),
            Some(100)
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
