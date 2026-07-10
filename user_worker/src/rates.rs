//! UNIT 2: Chainlink USD price feeds + amount→points conversion.
//!
//! - `chainlink_price` reads a Chainlink aggregator's `latestRoundData` via
//!   `eth_call` (over the Ethereum `RPC_URL`) and returns the USD price with
//!   8 decimals, rejecting non-positive or stale answers.
//! - `points_for` converts a raw on-chain amount into points at
//!   `POINTS_PER_USD`. Pure and host-tested.
//! - GET /user/api/rates -> 200 Json(RatesResp) for the account UI.
//!
//! SCAFFOLD STATE: `points_for` is fully implemented (pure). `chainlink_price`
//! and the `rates` handler are stubs — UNIT 2 implements the eth_call decode.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use worker::{Fetch, Method, Request, RequestInit};

use crate::AppState;
use crate::config::{self, POINTS_PER_USD};
use crate::session;
use crate::types::{ApiError, RatesResp};

/// Convert a raw on-chain amount (`amount_raw`, in the token's base units with
/// `decimals` decimals) into points. `price_8dec` is the token's USD price with
/// 8 decimals, or `None` for a $1 stablecoin. Saturating and ordered so the
/// intermediate product cannot overflow `u128` for realistic values.
pub fn points_for(amount_raw: u128, decimals: u32, price_8dec: Option<u128>) -> i64 {
    // usd_1e8 = amount_raw * price_8dec / 10^decimals   (stable: price = 1e8)
    let price = price_8dec.unwrap_or(100_000_000); // 1.0 with 8 decimals
    let Some(scaled) = amount_raw.checked_mul(price) else {
        return i64::MAX;
    };
    let usd_1e8 = scaled / 10u128.pow(decimals);
    // points = usd_1e8 * POINTS_PER_USD / 1e8
    let Some(num) = usd_1e8.checked_mul(POINTS_PER_USD as u128) else {
        return i64::MAX;
    };
    let points = num / 100_000_000;
    i64::try_from(points).unwrap_or(i64::MAX)
}

// ---------------------------------------------------------------------------
// Chainlink latestRoundData over worker::Fetch (no alloy/ethers)
// ---------------------------------------------------------------------------

/// `latestRoundData()` function selector.
const LATEST_ROUND_DATA: &str = "0xfeaf968c";

/// Single `eth_call` JSON-RPC POST; returns the `result` hex string. A non-2xx
/// HTTP response, a JSON-RPC-level `error`, or a missing/non-string `result`
/// becomes `Err`. Private to this module (mirrors `payments::rpc`).
async fn eth_call(rpc_url: &str, to: &str, data: &str) -> worker::Result<String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{ "to": to, "data": data }, "latest"],
    });
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.headers.set("content-type", "application/json")?;
    init.with_body(Some(body.to_string().into()));
    let req = Request::new_with_init(rpc_url, &init)?;
    let mut resp = Fetch::Request(req).send().await?;
    let code = resp.status_code();
    if !(200..300).contains(&code) {
        return Err(worker::Error::RustError(format!("eth_call: http {code}")));
    }
    let v: serde_json::Value = resp.json().await?;
    if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
        return Err(worker::Error::RustError(format!("eth_call error: {e}")));
    }
    v.get("result")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| worker::Error::RustError("eth_call: missing result".into()))
}

/// Parse one 32-byte ABI word (64 hex chars) as an unsigned integer that must
/// fit in `u128`: the high 128 bits (first 32 hex chars) must be zero.
fn word_to_u128(word: &str) -> Result<u128, &'static str> {
    let (high, low) = word.split_at(32);
    if high.bytes().any(|b| b != b'0') {
        return Err("word exceeds u128");
    }
    u128::from_str_radix(low, 16).map_err(|_| "bad hex word")
}

/// Pure decode of a `latestRoundData()` `eth_call` result. `result_hex` is the
/// `0x...` string: `0x` + 320 hex chars = five 32-byte words
/// `[roundId, answer, startedAt, updatedAt, answeredInRound]`. Returns `answer`
/// (word 1, int256 USD price with 8 decimals) as `u128`, rejecting a negative,
/// zero, or stale price.
fn decode_latest_round_data(result_hex: &str, now: u64) -> Result<u128, &'static str> {
    let hex = result_hex
        .strip_prefix("0x")
        .ok_or("result not 0x-prefixed")?;
    if hex.len() != 320 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("result is not 0x + 320 hex chars");
    }
    let word = |i: usize| &hex[i * 64..(i + 1) * 64];

    let answer_word = word(1);
    // int256 sign lives in the top bit: the first hex nibble >= 8 means negative.
    let top = (answer_word.as_bytes()[0] as char)
        .to_digit(16)
        .ok_or("bad answer word")?;
    if top >= 8 {
        return Err("chainlink answer is negative");
    }
    let answer = word_to_u128(answer_word)?;
    if answer == 0 {
        return Err("chainlink answer is zero");
    }

    let updated_at = u64::try_from(word_to_u128(word(3))?).map_err(|_| "updatedAt exceeds u64")?;
    if now.saturating_sub(updated_at) > config::CHAINLINK_MAX_STALE_SECS {
        return Err("chainlink price is stale");
    }

    Ok(answer)
}

/// Read a Chainlink aggregator's latest USD price (8 decimals) over `rpc_url`.
///
/// Calls `latestRoundData()` via `eth_call { to: feed, data: 0xfeaf968c }`,
/// decodes the 5 x 32-byte words, takes `answer` (word 1, rejecting <= 0), and
/// rejects if `updatedAt` (word 3) is older than `CHAINLINK_MAX_STALE_SECS`.
pub async fn chainlink_price(rpc_url: &str, feed: &str, now: u64) -> worker::Result<u128> {
    let result = eth_call(rpc_url, feed, LATEST_ROUND_DATA).await?;
    decode_latest_round_data(&result, now)
        .map_err(|e| worker::Error::RustError(format!("chainlink {feed}: {e}")))
}

#[worker::send]
pub async fn rates(State(st): State<AppState>) -> Response {
    let now = session::now_secs();
    let eth = chainlink_price(&st.rpc_url, config::FEED_ETH_USD, now).await;
    let sol = chainlink_price(&st.rpc_url, config::FEED_SOL_USD, now).await;
    match (eth, sol) {
        (Ok(eth), Ok(sol)) => Json(RatesResp {
            eth_usd: eth as f64 / 1e8,
            sol_usd: sol as f64 / 1e8,
        })
        .into_response(),
        (Err(e), _) | (_, Err(e)) => {
            worker::console_error!("rates: chainlink price failed: {e:?}");
            (
                StatusCode::BAD_GATEWAY,
                Json(ApiError {
                    error: "price feed unavailable".into(),
                }),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stablecoin_one_to_one_usd() {
        // 1 USDC (6 decimals), $1 -> POINTS_PER_USD points
        assert_eq!(points_for(1_000_000, 6, None), POINTS_PER_USD);
        // 2.5 USDT
        assert_eq!(points_for(2_500_000, 6, None), POINTS_PER_USD * 25 / 10);
    }

    #[test]
    fn volatile_priced_by_feed() {
        // 1 ETH (18 decimals) at $3000.00000000 -> 3000 * POINTS_PER_USD
        let price = 3000 * 100_000_000; // 8-decimal
        assert_eq!(
            points_for(10u128.pow(18), 18, Some(price)),
            3000 * POINTS_PER_USD
        );
        // 1 SOL (9 decimals) at $150
        let sol = 150 * 100_000_000;
        assert_eq!(
            points_for(10u128.pow(9), 9, Some(sol)),
            150 * POINTS_PER_USD
        );
    }

    #[test]
    fn absurd_amount_saturates_not_wraps() {
        assert_eq!(points_for(u128::MAX, 0, Some(u128::MAX)), i64::MAX);
        assert!(points_for(u128::MAX / 2, 18, Some(100_000_000)) >= 0);
    }

    // --- decode_latest_round_data --------------------------------------------

    const NOW: u64 = 1_700_000_000;

    /// Build a synthetic `latestRoundData()` result: `0x` + five 32-byte words.
    fn round_data(answer: u128, updated_at: u64) -> String {
        format!(
            "0x{:064x}{:064x}{:064x}{:064x}{:064x}",
            1u128,              // roundId
            answer,             // answer
            2u128,              // startedAt
            updated_at as u128, // updatedAt
            1u128,              // answeredInRound
        )
    }

    #[test]
    fn decode_fresh_price() {
        let price = 3000u128 * 100_000_000; // $3000.00000000
        let hex = round_data(price, NOW);
        assert_eq!(hex.len(), 2 + 320);
        assert_eq!(decode_latest_round_data(&hex, NOW), Ok(price));
        // slightly stale but within the window still decodes
        let recent = round_data(price, NOW - config::CHAINLINK_MAX_STALE_SECS);
        assert_eq!(decode_latest_round_data(&recent, NOW), Ok(price));
    }

    #[test]
    fn decode_rejects_stale() {
        let price = 3000u128 * 100_000_000;
        let hex = round_data(price, NOW - config::CHAINLINK_MAX_STALE_SECS - 1);
        assert!(decode_latest_round_data(&hex, NOW).is_err());
    }

    #[test]
    fn decode_rejects_zero_answer() {
        let hex = round_data(0, NOW);
        assert!(decode_latest_round_data(&hex, NOW).is_err());
    }

    #[test]
    fn decode_rejects_negative_answer() {
        // int256 with the top bit set (leading nibble `f`) is negative.
        let mut hex = String::from("0x");
        hex.push_str(&format!("{:064x}", 1u128)); // roundId
        hex.push_str(&"f".repeat(64)); // answer = -1
        hex.push_str(&format!("{:064x}", 2u128)); // startedAt
        hex.push_str(&format!("{:064x}", NOW as u128)); // updatedAt
        hex.push_str(&format!("{:064x}", 1u128)); // answeredInRound
        assert!(decode_latest_round_data(&hex, NOW).is_err());
    }

    #[test]
    fn decode_rejects_short_string() {
        assert!(decode_latest_round_data("0x1234", NOW).is_err());
        assert!(decode_latest_round_data("", NOW).is_err());
        // right length, no 0x prefix
        assert!(decode_latest_round_data(&"a".repeat(322), NOW).is_err());
        // 0x + 320 non-hex chars
        assert!(decode_latest_round_data(&format!("0x{}", "z".repeat(320)), NOW).is_err());
    }
}
