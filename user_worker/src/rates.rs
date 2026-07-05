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

use axum::{Json, extract::State, response::{IntoResponse, Response}};

use crate::AppState;
use crate::config::POINTS_PER_USD;

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

/// Read a Chainlink aggregator's latest USD price (8 decimals) over `rpc_url`.
///
/// UNIT 2: implement `eth_call { to: feed, data: 0xfeaf968c }` (latestRoundData),
/// decode 5 x 32-byte words, take `answer` (word[1], reject <= 0), and reject if
/// `updatedAt` (word[3]) is older than `CHAINLINK_MAX_STALE_SECS`.
#[allow(unused_variables)]
pub async fn chainlink_price(rpc_url: &str, feed: &str, now: u64) -> worker::Result<u128> {
    Err(worker::Error::RustError("chainlink_price: not implemented".into()))
}

#[worker::send]
pub async fn rates(State(_st): State<AppState>) -> Response {
    // UNIT 2: fetch ETH/USD and SOL/USD via `chainlink_price` and return
    // `RatesResp`. Stubbed as 501 until then.
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(crate::types::ApiError {
            error: "rates not implemented".into(),
        }),
    )
        .into_response()
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
        assert_eq!(points_for(10u128.pow(18), 18, Some(price)), 3000 * POINTS_PER_USD);
        // 1 SOL (9 decimals) at $150
        let sol = 150 * 100_000_000;
        assert_eq!(points_for(10u128.pow(9), 9, Some(sol)), 150 * POINTS_PER_USD);
    }

    #[test]
    fn absurd_amount_saturates_not_wraps() {
        assert_eq!(points_for(u128::MAX, 0, Some(u128::MAX)), i64::MAX);
        assert!(points_for(u128::MAX / 2, 18, Some(100_000_000)) >= 0);
    }
}
