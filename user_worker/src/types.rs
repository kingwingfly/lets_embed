//! Wire contracts for the wallet API and the account Durable Object.
//! Gateway metering types are shared through `site_access`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// UserAccount Durable Object internal protocol
//
// Routes (dispatched in `account_do::UserAccount::fetch`):
//   POST /charge        ChargeReq -> 200 ChargeResp | 402 ChargeResp | 403
//   POST /can-charge    ChargeReq -> 200 | 402 ChargeResp | 403
//   POST /reserve       ChargeReq -> 200 HoldResp | 402 ChargeResp | 403
//   POST /commit        HoldReq   -> 200
//   POST /release       HoldReq   -> 200
//   POST /guest         GuestReq  -> 200 | 401 | 402
//   POST /reserve-guest GuestReq  -> 200 HoldResp | 401 | 402
//   POST /commit-guest  HoldReq   -> 200
//   POST /release-guest HoldReq   -> 200
//   POST /credit        CreditReq -> 200 BalanceResp
//   GET  /status                  -> 200 StatusResp
//   POST /init          InitReq   -> 200 StatusResp
//   POST /subscribe     SubscribeReq -> 200 StatusResp | 400 | 402
//   POST /unsubscribe             -> 200 StatusResp
//   POST /ban           BanReq    -> 200 StatusResp
//   POST /billing-prefs BillingPrefsReq -> 200 BillingPrefsResp
// ---------------------------------------------------------------------------

pub use site_access::{ChargeKind, ChargeReq, HoldReq, HoldResp};

#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeResp {
    /// false = deduped (seen within the window) or refused; nothing deducted.
    pub charged: bool,
    pub cost: i64,
    /// PAYG points after the charge.
    pub balance: i64,
    /// Remaining view-units in the current window; `None` = no active plan or
    /// unlimited (pro).
    pub views_remaining: Option<i64>,
    /// Remaining searches in the current window; `None` = no active plan.
    pub searches_remaining: Option<i64>,
    /// Epoch secs when the current usage window resets; 0 = no active window.
    pub window_reset: u64,
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
    #[serde(default)]
    pub expected_price: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminPlanReq {
    pub plan: String,
    pub days: u32,
    pub token: String,
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
    /// Epoch secs; 0 = no active subscription.
    pub period_end: u64,
    /// Remaining view-units this window; `None` = no plan / unlimited (pro).
    pub views_remaining: Option<i64>,
    /// Remaining searches this window; `None` = no active plan.
    pub searches_remaining: Option<i64>,
    /// Epoch secs when the usage window resets; 0 = no active window.
    pub window_reset: u64,
    pub banned: bool,
    pub total_views: i64,
    /// Opt-in flag: only when `true` may billable image/video loads deduct from
    /// the PAYG points balance after daily free quota & plan windows run out.
    #[serde(default)]
    pub allow_paid_media: bool,
    /// Number of daily free items consumed today (UTC) per `ChargeKind` name
    /// (e.g. `"image"`, `"video"`, `"similar"`, `"upload"`, `"description"`).
    #[serde(default)]
    pub daily_free_used: std::collections::HashMap<String, i64>,
    /// Epoch secs of the next UTC midnight when daily free counters reset.
    #[serde(default)]
    pub daily_free_reset: u64,
}

// ---------------------------------------------------------------------------
// Public HTTP API bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct VerifyReq {
    pub message: String,
    pub signature: String,
}

/// Sign-In-With-Solana login: the wallet signs the server's nonce challenge.
#[derive(Debug, Deserialize)]
pub struct SiwsReq {
    /// base58 Solana address (ed25519 public key) — becomes the account principal.
    pub solana_address: String,
    /// base58 ed25519 signature over the SIWS challenge.
    pub signature: String,
    /// The nonce embedded in the signed challenge (single-use, from /api/nonce).
    pub nonce: String,
    /// Optional base64-encoded bytes actually signed by a Wallet Standard wallet
    /// (e.g. a Solana off-chain message envelope wrapping the exact challenge).
    #[serde(default)]
    pub signed_message: Option<String>,
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
    /// The account page includes its principal so a different session in
    /// another tab cannot take over a pending checkout.
    pub account: Option<String>,
    /// "ethereum" | "solana".
    pub chain: String,
    /// Token symbol, lowercase: "eth" | "sol" | "usdt" | "usdc".
    pub token: String,
    /// Ethereum 0x tx hash, or Solana base58 transaction signature.
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
    pub chain: String,
    pub token: String,
    /// Raw base units (wei / lamports / token minor units), decimal string.
    pub amount: String,
    /// Exact decimal string so credits above `2^53 - 1` survive D1/JS conversion.
    pub points: String,
    pub status: String,
    pub created_at: i64,
}

/// Spot USD prices for the volatile top-up assets (for the account UI).
#[derive(Debug, Serialize, Deserialize)]
pub struct RatesResp {
    pub eth_usd: f64,
    pub sol_usd: f64,
}

/// Link a Solana wallet to the (ETH) session so its top-ups can be attributed.
#[derive(Debug, Deserialize)]
pub struct LinkSolReq {
    /// base58 Solana address (ed25519 public key).
    pub solana_address: String,
    /// base58 ed25519 signature over the link challenge.
    pub signature: String,
    /// The nonce embedded in the signed challenge (single-use, from /api/nonce).
    pub nonce: String,
    /// Optional base64-encoded bytes actually signed by a Wallet Standard wallet.
    #[serde(default)]
    pub signed_message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LinkSolResp {
    pub solana_address: String,
}

/// Current Solana wallet linked to the session, if any (GET /user/api/link_solana).
#[derive(Debug, Serialize)]
pub struct LinkStatusResp {
    pub solana_address: Option<String>,
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
