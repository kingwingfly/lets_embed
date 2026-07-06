//! FROZEN SCAFFOLD: pricing / limits configuration + payment-token registry.
//!
//! Points are anchored to USD: `POINTS_PER_USD` points buy one dollar of usage,
//! and one image view costs one point. All money-in paths (crypto top-ups)
//! convert to points at this rate. Subscription plans are bought FROM the points
//! balance and do NOT auto-renew — they lapse to PAYG at period end and the user
//! re-subscribes ("Renew") to extend. Values are placeholders the operator tunes.

// ---------------------------------------------------------------------------
// Pricing
// ---------------------------------------------------------------------------

/// Points per US dollar of top-up ($1 = 10k points; 1 point = 1 image view).
pub const POINTS_PER_USD: i64 = 10_000;
/// Points consumed by one image view.
pub const COST_IMAGE_VIEW: i64 = 1;
/// Points consumed by one video view (bandwidth-weighted).
pub const COST_VIDEO_VIEW: i64 = 5;
/// Points consumed by one upload-image similarity search (PAYG; $0.01). This
/// runs dinov3 ONNX inference on the uploaded bytes — the expensive path.
pub const COST_SIM_SEARCH: i64 = 100;
/// Points consumed by one by-id similarity search (PAYG; $0.001). This reuses a
/// stored dinov3 embedding (a pgvector query, no inference) — the cheap path, so
/// it is a view-class charge drawn from the abundant view budget rather than the
/// scarce inference-search quota.
pub const COST_EMBED_SEARCH: i64 = 10;
/// Points granted to a brand-new account on first touch ($0.30).
pub const FREE_GRANT_POINTS: i64 = 3_000;
/// Minimum top-up accepted, in points ($0.10); smaller credits are rejected.
pub const MIN_TOPUP_POINTS: i64 = 1_000;

// ---------------------------------------------------------------------------
// Windows / timeouts
// ---------------------------------------------------------------------------

/// Rolling usage window for subscription quotas (5 hours, Claude-style).
pub const WINDOW_SECS: u64 = 5 * 3600;
/// Repeat views/searches of the same key within this window are free.
pub const DEDUPE_WINDOW_SECS: u64 = 86_400;
/// Session cookie lifetime.
pub const SESSION_TTL_SECS: u64 = 7 * 86_400;
/// SIWE / wallet-link nonce validity (KV TTL).
pub const NONCE_TTL_SECS: u64 = 300;
/// Max allowed |now - Issued At| of a SIWE message.
pub const SIWE_MAX_AGE_SECS: u64 = 600;

// ---------------------------------------------------------------------------
// On-chain verification
// ---------------------------------------------------------------------------

/// Confirmations required before an Ethereum top-up is credited.
/// (Solana uses the `finalized` commitment instead of a confirmation count.)
pub const MIN_CONFIRMATIONS: u64 = 6;
/// Reject a Chainlink price whose `updatedAt` is older than this.
pub const CHAINLINK_MAX_STALE_SECS: u64 = 86_400;

// ---------------------------------------------------------------------------
// Subscription plans
// ---------------------------------------------------------------------------

/// A subscription plan. Purchased from the PAYG points balance for one period;
/// does not auto-renew. While active, views/searches draw from the per-window
/// quota first, then fall back to the PAYG balance.
pub struct Plan {
    pub id: &'static str,
    /// Deducted from the PAYG balance at purchase / renewal.
    pub price_points: i64,
    /// Media view-units allowed per `WINDOW_SECS`; `None` = unlimited.
    pub views_per_window: Option<i64>,
    /// Similarity searches allowed per `WINDOW_SECS`.
    pub searches_per_window: i64,
    pub period_secs: u64,
}

pub const PLANS: &[Plan] = &[
    // basic — $2 / 30d
    Plan {
        id: "basic",
        price_points: 20_000,
        views_per_window: Some(2_000),
        searches_per_window: 10,
        period_secs: 30 * 86_400,
    },
    // pro — $5 / 30d, unlimited views
    Plan {
        id: "pro",
        price_points: 50_000,
        views_per_window: None,
        searches_per_window: 50,
        period_secs: 30 * 86_400,
    },
];

pub fn plan(id: &str) -> Option<&'static Plan> {
    PLANS.iter().find(|p| p.id == id)
}

// ---------------------------------------------------------------------------
// Payment-token registry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Ethereum,
    Solana,
}

impl Chain {
    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Ethereum => "ethereum",
            Chain::Solana => "solana",
        }
    }
    pub fn parse(s: &str) -> Option<Chain> {
        match s {
            "ethereum" => Some(Chain::Ethereum),
            "solana" => Some(Chain::Solana),
            _ => None,
        }
    }
}

/// One accepted top-up asset. `contract` is `None` for the chain's native coin,
/// otherwise the ERC-20 address (Ethereum, lowercase) or SPL mint (Solana).
/// `feed` is the Chainlink USD aggregator (on Ethereum mainnet) used to price a
/// volatile asset; `None` marks a $1 stablecoin.
pub struct TokenSpec {
    pub chain: Chain,
    pub symbol: &'static str,
    pub decimals: u32,
    pub contract: Option<&'static str>,
    pub feed: Option<&'static str>,
}

/// Chainlink ETH/USD aggregator (Ethereum mainnet).
pub const FEED_ETH_USD: &str = "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419";
/// Chainlink SOL/USD aggregator (Ethereum mainnet).
pub const FEED_SOL_USD: &str = "0x4ffc43a60e009b551865a93d232e33fce9f01507";

pub const TOKENS: &[TokenSpec] = &[
    TokenSpec {
        chain: Chain::Ethereum,
        symbol: "eth",
        decimals: 18,
        contract: None,
        feed: Some(FEED_ETH_USD),
    },
    TokenSpec {
        chain: Chain::Ethereum,
        symbol: "usdt",
        decimals: 6,
        contract: Some("0xdac17f958d2ee523a2206206994597c13d831ec7"),
        feed: None,
    },
    TokenSpec {
        chain: Chain::Ethereum,
        symbol: "usdc",
        decimals: 6,
        contract: Some("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        feed: None,
    },
    TokenSpec {
        chain: Chain::Solana,
        symbol: "sol",
        decimals: 9,
        contract: None,
        feed: Some(FEED_SOL_USD),
    },
    TokenSpec {
        chain: Chain::Solana,
        symbol: "usdt",
        decimals: 6,
        contract: Some("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"),
        feed: None,
    },
    TokenSpec {
        chain: Chain::Solana,
        symbol: "usdc",
        decimals: 6,
        contract: Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        feed: None,
    },
];

/// Look up an accepted `(chain, symbol)` top-up asset. `symbol` is lowercase.
pub fn token(chain: Chain, symbol: &str) -> Option<&'static TokenSpec> {
    TOKENS
        .iter()
        .find(|t| t.chain == chain && t.symbol == symbol)
}
