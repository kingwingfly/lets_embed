//! Session verification, live `UserAccount` DO context handling, and switcher
//! eligibility computation.

use serde::{Deserialize, Serialize};
use site_access::{
    AgeGateTrigger, PublicSitePolicy, RuleMode, SESSION_COOKIE, SessionContext, VerifiedSession,
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
/// Rules enforced:
/// - If `!policy.safety_enabled`, `!ctx.is_authenticated()`, or `ctx.safe_mode`,
///   returns `[]`.
/// - Only enabled `RuleMode::Switcher` rules requested in `ctx.enabled_switchers`
///   are considered (deduplicated in policy order).
/// - When `policy.legal.terms_version > 0` and the rule requires login, requires
///   18+, or site-wide/JIT Terms gating is active (`age_gate_trigger != Off`),
///   both `terms_version_accepted` and `terms_digest_accepted` must match
///   `policy.legal`.
/// - When `rule.requires_age_18`:
///   - `StrictProviderVerified18` requires `ctx.strict_age_ok` and
///     `ctx.assurance_level == AssuranceLevel::Verified18`.
///   - `SelfAttestation` requires `ctx.assurance_level != AssuranceLevel::None`.
///   - `Off` imposes no age check.
pub(crate) fn compute_eligible_switchers(
    ctx: &SessionContext,
    policy: &PublicSitePolicy,
) -> Vec<String> {
    if !policy.safety_enabled || !ctx.is_authenticated() || ctx.safe_mode {
        return Vec::new();
    }
    let terms_ok = policy.legal.terms_version == 0 || ctx.satisfies_terms(&policy.legal);
    let age_ok = ctx.satisfies_age_policy(policy.age_policy);
    let global_terms_gate = policy.age_gate_trigger != AgeGateTrigger::Off;

    let mut out = Vec::new();
    for rule in &policy.rules {
        if !rule.enabled || rule.mode != RuleMode::Switcher {
            continue;
        }
        if !ctx.enabled_switchers.iter().any(|s| s == &rule.id) {
            continue;
        }
        let requires_terms = policy.legal.terms_version > 0
            && (rule.requires_login || rule.requires_age_18 || global_terms_gate);
        if requires_terms && !terms_ok {
            continue;
        }
        if rule.requires_age_18 && !age_ok {
            continue;
        }
        if !out.iter().any(|existing| existing == &rule.id) {
            out.push(rule.id.clone());
        }
    }
    out
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
