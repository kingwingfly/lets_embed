//! FROZEN SCAFFOLD: pricing / limits configuration.
//! All values are placeholders the operator tunes before launch.

/// Points consumed by one image view.
pub const COST_IMAGE_VIEW: i64 = 1;
/// Points consumed by one video view.
pub const COST_VIDEO_VIEW: i64 = 5;
/// Points granted to a brand-new account on first touch.
pub const FREE_GRANT_POINTS: i64 = 3_000;
/// Repeat views of the same media path within this window are free.
pub const DEDUPE_WINDOW_SECS: u64 = 86_400;
/// Session cookie lifetime.
pub const SESSION_TTL_SECS: u64 = 7 * 86_400;
/// SIWE nonce validity (KV TTL).
pub const NONCE_TTL_SECS: u64 = 300;
/// Max allowed |now - Issued At| of a SIWE message.
pub const SIWE_MAX_AGE_SECS: u64 = 600;
/// Confirmations required before a top-up tx is credited.
pub const MIN_CONFIRMATIONS: u64 = 6;
/// Points credited per 1 ETH (1e18 wei).
pub const POINTS_PER_ETH: u128 = 100_000;
/// Minimum accepted top-up (0.001 ETH).
pub const MIN_TOPUP_WEI: u128 = 1_000_000_000_000_000;

/// A subscription plan. Purchased and auto-renewed from the PAYG balance;
/// views draw from `quota_points` first, then fall back to the balance.
pub struct Plan {
    pub id: &'static str,
    /// Deducted from the PAYG balance at purchase and at each renewal.
    pub price_points: i64,
    /// Per-period view quota; resets on renewal.
    pub quota_points: i64,
    pub period_secs: u64,
}

pub const PLANS: &[Plan] = &[
    Plan {
        id: "basic",
        price_points: 1_000,
        quota_points: 5_000,
        period_secs: 30 * 86_400,
    },
    Plan {
        id: "pro",
        price_points: 3_000,
        quota_points: 20_000,
        period_secs: 30 * 86_400,
    },
];

pub fn plan(id: &str) -> Option<&'static Plan> {
    PLANS.iter().find(|p| p.id == id)
}
