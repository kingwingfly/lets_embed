//! Session verification, live `UserAccount` DO context handling, and switcher
//! eligibility computation.

use serde::{Deserialize, Serialize};
use site_access::{
    PublicSitePolicy, RuleMode, SESSION_COOKIE, SessionContext, VerifiedSession,
};

/// Subject identifier stamped into `X-Gateway-Assertion` and expected in
/// admin-minted `MediaCapability` tokens when an administrator is browsing
/// via `__Host-ue_admin_view` (or Access identity) without a personal user session.
pub(crate) const ADMIN_VIEW_SUB: &str = "admin";

/// Request payload sent to `USER_ACCOUNT` DO (`POST /session-context`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionContextReq {
    pub(crate) sid: Option<String>,
}

/// Verified, live-checked caller session together with the eligible switcher IDs
/// computed from the current [`PublicSitePolicy`].
#[derive(Debug, Clone)]
pub(crate) struct LiveSession {
    pub(crate) session: VerifiedSession,
    pub(crate) ctx: SessionContext,
    pub(crate) eligible_switchers: Vec<String>,
}

/// `Set-Cookie` header value that immediately expires a revoked or invalid
/// `ue_session` cookie.
pub(crate) fn clear_session_cookie_header() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
}

/// Computes the set of Switcher rule IDs that an authenticated session is
/// currently eligible to unlock under `policy`.
///
/// Delegates directly to [`SessionContext::effective_switchers`] so
/// `gateway_worker` and `user_worker` enforce the exact same Terms, age-policy,
/// and Safe Mode rules without duplicated drift.
pub(crate) fn compute_eligible_switchers(
    ctx: &SessionContext,
    policy: &PublicSitePolicy,
) -> Vec<String> {
    ctx.effective_switchers(policy)
}

/// Computes the Switcher rule IDs available to an administrator using the
/// admin browse pass (`is_admin_view`) without a separate user session.
pub(crate) fn admin_eligible_switchers(policy: &PublicSitePolicy) -> Vec<String> {
    if !policy.safety_enabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    for rule in &policy.rules {
        if rule.enabled
            && rule.mode == RuleMode::Switcher
            && !out.iter().any(|existing| existing == &rule.id)
        {
            out.push(rule.id.clone());
        }
    }
    out
}
