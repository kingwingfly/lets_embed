//! FROZEN SCAFFOLD: wire contracts.
//!
//! The "DO internal protocol" section is duplicated verbatim in
//! `gateway_worker` (deliberate: it is a wire contract between two separately
//! deployed workers, not shared Rust). Do not change field names or status
//! codes without updating both sides.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// UserAccount Durable Object internal protocol
//
// Routes (dispatched in `account_do::UserAccount::fetch`):
//   POST /charge      ChargeReq   -> 200 ChargeResp | 402 ChargeResp | 403
//   POST /credit      CreditReq   -> 200 BalanceResp
//   GET  /status                  -> 200 StatusResp
//   POST /init        InitReq     -> 200 StatusResp
//   POST /subscribe   SubscribeReq-> 200 StatusResp | 400 | 402 | 409
//   POST /unsubscribe             -> 200 StatusResp
//   POST /ban         BanReq      -> 200 StatusResp
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaKind {
    Image,
    Video,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeReq {
    /// Full request path, e.g. "/images/abc.webp" — the dedupe key.
    pub path: String,
    pub kind: MediaKind,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeResp {
    /// false = deduped (seen within the window) or refused; nothing deducted.
    pub charged: bool,
    pub cost: i64,
    /// PAYG points after the charge.
    pub balance: i64,
    /// Subscription quota after the charge.
    pub quota_remaining: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreditReq {
    /// May be negative (admin deduction); balance clamps at >= 0.
    pub points: i64,
    /// Idempotency key: "tx:{tx_hash}" or "admin:{uuid}". Replays are no-ops.
    pub key: String,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BalanceResp {
    pub balance: i64,
    /// false = the idempotency key was already applied.
    pub applied: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitReq {
    /// Lowercase 0x address; stored by the DO for /status and admin listings.
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubscribeReq {
    pub plan: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BanReq {
    pub banned: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StatusResp {
    pub address: String,
    pub balance: i64,
    pub plan: Option<String>,
    pub quota_remaining: i64,
    /// Epoch secs; 0 = no active subscription.
    pub period_end: u64,
    pub banned: bool,
    pub total_views: i64,
}

// ---------------------------------------------------------------------------
// Public HTTP API bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct VerifyReq {
    pub message: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResp {
    /// EIP-55 checksummed for display.
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct NonceResp {
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct TopupReq {
    pub tx_hash: String,
}

#[derive(Debug, Serialize)]
pub struct TopupResp {
    pub credited_points: i64,
    pub balance: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentRow {
    pub tx_hash: String,
    pub amount_wei: String,
    pub token: String,
    pub points: i64,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct LikeReq {
    /// "post" | "image" | "video"
    pub kind: String,
    pub target_id: i64,
}

#[derive(Debug, Serialize)]
pub struct LikedResp {
    pub liked: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LikeRow {
    pub kind: String,
    pub target_id: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct LikesResp {
    pub items: Vec<LikeRow>,
    /// Pass back as `cursor` to fetch the next page (keyset on created_at).
    pub next_cursor: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
}

pub fn valid_like_kind(kind: &str) -> bool {
    matches!(kind, "post" | "image" | "video")
}
