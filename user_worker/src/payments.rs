//! UNIT 4: crypto top-up (on-chain verification) + subscription passthrough.
//!
//! STUB: implement topup / list_payments / subscribe / unsubscribe. Contracts:
//! - POST /user/api/topup Json(TopupReq) -> 200 Json(TopupResp) | 400 | 401 |
//!   409 (tx already submitted) | 425 (not enough confirmations yet, retry).
//!   Flow: validate hash -> INSERT payments 'pending' (PK conflict -> 409) ->
//!   eth_getTransactionByHash (to == deposit_address, value >= MIN_TOPUP_WEI)
//!   -> eth_getTransactionReceipt (status 0x1) -> eth_blockNumber
//!   (>= MIN_CONFIRMATIONS, else DELETE pending row + 425) -> points =
//!   wei * POINTS_PER_ETH / 1e18 (u128) -> do_credit key "tx:{hash}" ->
//!   UPDATE row to 'credited'. JSON-RPC: hand-rolled over worker::Fetch
//!   against st.rpc_url.
//! - GET  /user/api/payments -> 200 Json(Vec<PaymentRow>) (newest 50) | 401.
//! - POST /user/api/subscribe Json(SubscribeReq) -> passthrough to DO
//!   /subscribe; on 200 mirror `users.plan` in D1. 400/402/409 pass through.
//! - POST /user/api/unsubscribe -> DO /unsubscribe; mirror plan=NULL.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tower_cookies::Cookies;

use crate::AppState;
use crate::types::{SubscribeReq, TopupReq};

#[worker::send]
pub async fn topup(
    State(_st): State<AppState>,
    _cookies: Cookies,
    Json(_req): Json<TopupReq>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn list_payments(State(_st): State<AppState>, _cookies: Cookies) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn subscribe(
    State(_st): State<AppState>,
    _cookies: Cookies,
    Json(_req): Json<SubscribeReq>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn unsubscribe(State(_st): State<AppState>, _cookies: Cookies) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}
