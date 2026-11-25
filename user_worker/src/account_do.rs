//! Wallet and guest metering in the account Durable Object. Wallet instances own
//! balances, subscriptions and usage. Guest instances enforce the published
//! daily free allowances for a pseudonymous client IP.

use std::collections::{HashMap, HashSet};

use serde::de::DeserializeOwned;
use worker::{Date, DurableObject, Env, Method, Request, Response, Result, State, durable_object};

use crate::types::{
    BalanceResp, BanReq, ChargeKind, ChargeReq, ChargeResp, CreditReq, HoldReq, HoldResp, InitReq,
    StatusResp, SubscribeReq,
};
use crate::{
    config,
    do_client::{
        AgeConfirmReq, BillingPrefsReq, BillingPrefsResp, DoPrefsConflictResp,
        MergeCreditBreakdown, MergeDrainDoReq, MergeDrainDoResp, MergePreviewDoReq,
        MergePreviewDoResp, MergeReceiveDoReq, MergeReceiveDoResp, PrefsUpdateReq,
        PreviewBudgetReq, PreviewBudgetResp, SessionContextReq, SessionInfoResp, SessionIssueReq,
        SessionIssueResp, SessionRevokeAllReq, SessionRevokeAllResp, SessionRevokeReq,
        TermsAcceptReq,
    },
    identity::{assurance_from_str, assurance_to_str},
    settings::{self, Policy},
};
use site_access::{AssuranceLevel, GuestReq, PolicyRef, SessionContext};

// ---------------------------------------------------------------------------
// Pure decision logic (host-testable)
// ---------------------------------------------------------------------------

#[cfg(test)]
fn view_cost(kind: ChargeKind) -> i64 {
    Policy::default().item(kind).price
}

/// A repeat charge is free if the key was first seen within the dedupe window.
fn is_recent_view(path: &str, now: u64, maps: [&HashMap<String, u64>; 2]) -> bool {
    let cutoff = now.saturating_sub(config::DEDUPE_WINDOW_SECS);
    maps.iter()
        .any(|m| m.get(path).is_some_and(|&first_seen| first_seen > cutoff))
}

/// Whether a new usage window should be opened: none yet, or the current one has
/// elapsed (`now` reached `win_start + WINDOW_SECS`).
fn should_roll(win_start: Option<u64>, now: u64) -> bool {
    match win_start {
        None => true,
        Some(start) => now >= start + config::WINDOW_SECS,
    }
}

/// Where a (non-deduped) charge draws from once the plan + window are consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChargeSource {
    /// Pro plan media view — unlimited; deduct nothing, just record the view.
    FreeUnlimited,
    /// Draw from the subscription window quota (no balance change).
    Window,
    /// Pay-as-you-go: deduct `cost` from the points balance.
    Balance,
    /// No quota and the balance is too low — refuse (402).
    Refuse,
}

/// Decide how one charge is satisfied given plan, window usage and balance.
/// Pure (plain values + caller-provided window counters) so it is host-testable.
/// `win_views` / `win_search` are the counters for the *current* (already rolled)
/// window.
#[allow(clippy::too_many_arguments)]
fn decide_charge(
    plan: Option<&config::Plan>,
    active: bool,
    kind: ChargeKind,
    win_views: i64,
    win_search: i64,
    balance: i64,
    cost: i64,
    allow_paid_media: bool,
) -> ChargeSource {
    if active && let Some(plan) = plan {
        match kind {
            // View-class kinds (incl. the cheap by-id embed search) draw from the
            // media view budget; pro's unlimited views cover them for free.
            ChargeKind::Image | ChargeKind::Video | ChargeKind::EmbedSearch => {
                match plan.views_per_window {
                    None => return ChargeSource::FreeUnlimited,
                    Some(limit) => {
                        if win_views + cost <= limit {
                            return ChargeSource::Window;
                        }
                    }
                }
            }
            // The expensive upload-image search draws from the scarce search quota.
            ChargeKind::Search | ChargeKind::Description => {
                if win_search < plan.searches_per_window {
                    return ChargeSource::Window;
                }
            }
        }
    }
    // No plan, or the window quota is exhausted: fall back to PAYG.
    // Loading images & videos using PAYG credits requires explicit opt-in (`allow_paid_media`).
    let paid_media_blocked =
        !allow_paid_media && matches!(kind, ChargeKind::Image | ChargeKind::Video);
    if !paid_media_blocked && balance >= cost {
        ChargeSource::Balance
    } else {
        ChargeSource::Refuse
    }
}

/// Remaining media view-units this window; `None` = no active plan or unlimited
/// (pro). `win_views` is the current window's consumed count.
fn views_remaining(plan: Option<&config::Plan>, active: bool, win_views: i64) -> Option<i64> {
    if !active {
        return None;
    }
    plan?
        .views_per_window
        .map(|limit| (limit - win_views).max(0))
}

/// Remaining searches this window; `None` = no active plan.
fn searches_remaining(plan: Option<&config::Plan>, active: bool, win_search: i64) -> Option<i64> {
    if !active {
        return None;
    }
    Some((plan?.searches_per_window - win_search).max(0))
}

/// Points refunded for the unused remainder of a subscription period. The
/// refund is the plan price prorated by the fraction of the period still
/// unspent (floored): `price * remaining / period`. `remaining_secs` is clamped
/// to the period length so it can never over-refund. Pure (host-testable).
fn prorated_refund(price_points: i64, period_secs: u64, remaining_secs: u64) -> i64 {
    if period_secs == 0 {
        return 0;
    }
    let remaining = remaining_secs.min(period_secs);
    ((price_points as i128 * remaining as i128) / period_secs as i128) as i64
}

/// Epoch secs when the current window resets; 0 = no active/open window.
fn window_reset(active: bool, win_start: Option<u64>, now: u64) -> u64 {
    match win_start {
        Some(start) if active && now < start + config::WINDOW_SECS => start + config::WINDOW_SECS,
        _ => 0,
    }
}

/// Epoch secs of the next UTC midnight when daily free counters reset.
fn next_utc_day_reset(now: u64) -> u64 {
    (now / 86_400).saturating_add(1).saturating_mul(86_400)
}

/// Deduct `cost` from `balance`, consuming `free_balance` first so genuinely paid
/// credits remain preserved for account merges while free signup points cannot be farmed.
fn spend_free_first(balance: i64, free_balance: i64, cost: i64) -> (i64, i64) {
    let cost = cost.max(0);
    let clamped_free = free_balance.clamp(0, balance.max(0));
    let new_balance = balance.saturating_sub(cost).max(0);
    let new_free = clamped_free.saturating_sub(cost).min(new_balance);
    (new_balance, new_free)
}

/// Split funding for a subscription purchase/switch of `target_price` given existing
/// `(balance, free_balance)` and an incoming prorated plan refund `(prev_refund_total, prev_refund_paid)`.
/// Uses paid funds first so free signup credits can NEVER be laundered into transferable
/// paid subscription refunds during account merges.
/// Returns `(new_balance, new_free_balance, new_plan_paid_real)`.
fn subscribe_split_funding(
    balance: i64,
    free_balance: i64,
    prev_refund_total: i64,
    prev_refund_paid: i64,
    target_price: i64,
) -> (i64, i64, i64) {
    let target = target_price.max(0);
    let prev_total = prev_refund_total.max(0);
    let prev_paid = prev_refund_paid.clamp(0, prev_total);
    let prev_free = prev_total.saturating_sub(prev_paid);

    let clamped_free = free_balance.clamp(0, balance.max(0));
    let paid_bal = balance.saturating_sub(clamped_free).max(0);

    let total_paid_avail = paid_bal.saturating_add(prev_paid);
    let total_free_avail = clamped_free.saturating_add(prev_free);

    let plan_paid_real = target.min(total_paid_avail);
    let plan_free_used = target.saturating_sub(plan_paid_real).min(total_free_avail);

    let new_paid_bal = total_paid_avail.saturating_sub(plan_paid_real);
    let new_free_bal = total_free_avail.saturating_sub(plan_free_used);
    let new_balance = new_paid_bal.saturating_add(new_free_bal);
    (new_balance, new_free_bal, plan_paid_real)
}

/// Pure, host-testable computation of paid vs. free credit breakdown for merging/abandoning
/// an account. Handles BOTH tracked accounts (`tracked_free_balance: Some(...)`) AND legacy
/// pre-upgrade accounts (`tracked_free_balance: None`) capped against D1 `legacy_paid_deposits`
/// plus any prior `merged_paid_in`.
#[allow(clippy::too_many_arguments)]
fn compute_merge_credit_breakdown(
    initialized: bool,
    balance: i64,
    tracked_free_balance: Option<i64>,
    signup_points: i64,
    legacy_paid_in: i64,
    plan_active: bool,
    plan_paid: i64,
    tracked_plan_paid_real: Option<i64>,
    plan_period_secs: u64,
    plan_remaining_secs: u64,
) -> MergeCreditBreakdown {
    let balance = balance.max(0);
    let signup_points = signup_points.max(0);
    let legacy_paid_in = legacy_paid_in.max(0);
    let plan_paid = if plan_active { plan_paid.max(0) } else { 0 };
    let plan_refund_total = if plan_active {
        prorated_refund(plan_paid, plan_period_secs, plan_remaining_secs)
    } else {
        0
    };

    let (paid_balance_transfer, plan_paid_real) = match tracked_free_balance {
        Some(fb) => {
            let clamped_free = fb.clamp(0, balance);
            let paid_bal = balance.saturating_sub(clamped_free);
            let real_plan = if plan_active {
                tracked_plan_paid_real
                    .unwrap_or_else(|| plan_paid.min(legacy_paid_in))
                    .clamp(0, plan_paid)
            } else {
                0
            };
            (paid_bal, real_plan)
        }
        None => {
            if legacy_paid_in == 0 {
                (0, 0)
            } else {
                let free_grant = if initialized { signup_points } else { 0 };
                let current_assets = balance.saturating_add(plan_paid);
                let total_in = free_grant.saturating_add(legacy_paid_in);
                let spent = total_in.saturating_sub(current_assets);
                let est_free_remaining = free_grant.saturating_sub(spent).clamp(0, balance);
                let paid_bal = balance
                    .saturating_sub(est_free_remaining)
                    .min(legacy_paid_in);
                let remaining_paid_cap = legacy_paid_in.saturating_sub(paid_bal);
                let real_plan = plan_paid.min(remaining_paid_cap);
                (paid_bal, real_plan)
            }
        }
    };

    let plan_refund_paid = if plan_active {
        prorated_refund(plan_paid_real, plan_period_secs, plan_remaining_secs)
            .min(plan_refund_total)
    } else {
        0
    };
    let free_balance_forfeited = balance.saturating_sub(paid_balance_transfer);
    let plan_free_forfeited = plan_refund_total.saturating_sub(plan_refund_paid);
    let total_transferable = paid_balance_transfer.saturating_add(plan_refund_paid);
    let total_free_forfeited = free_balance_forfeited.saturating_add(plan_free_forfeited);

    MergeCreditBreakdown {
        balance,
        paid_balance_transfer,
        free_balance_forfeited,
        plan_refund_total,
        plan_refund_paid,
        plan_free_forfeited,
        total_transferable,
        total_free_forfeited,
    }
}

/// Pure refund math for a released `Window`-sourced hold.
/// Only adjusts counters when the window that was charged is still the active window.
fn refund_window_counters(
    kind: &str,
    cost: i64,
    current_win_start: Option<u64>,
    hold_win_start: i64,
    win_views: i64,
    win_search: i64,
) -> Option<(i64, i64)> {
    if hold_win_start < 0 || current_win_start != Some(hold_win_start as u64) {
        return None;
    }
    match kind {
        "upload" | "description" => Some((win_views, (win_search - 1).max(0))),
        "image" | "video" | "similar" => Some(((win_views - cost.max(0)).max(0), win_search)),
        _ => None,
    }
}

const HOLD_TTL_SECS: i64 = 600;
const PREVIEW_BUDGET_WINDOW_SECS: i64 = 300;
const PREVIEW_BUDGET_MAX_PER_WINDOW: u32 = 240;
const PREVIEW_ITEM_MAX_HITS_PER_WINDOW: u32 = 4;

/// Pure session-context evaluator (host-testable).
#[derive(Debug, Clone)]
pub(crate) struct StoredSessionSnapshot {
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

/// Raw row loaded from DO SQLite `user_safety_state` BEFORE cold-load legacy Safe Mode migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawStoredSafetyRow {
    pub enabled_switchers: Vec<PolicyRef>,
    pub legacy_safe_mode: bool,
    pub pref_version: u64,
    pub terms_version: Option<u32>,
    pub terms_digest: Option<String>,
    pub self_attested_18: bool,
    pub revoked_all_before: u64,
}

/// Active Policy v3 user safety state (Safe Mode removed; monotonic `pref_version`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredSafetyState {
    pub enabled_switchers: Vec<PolicyRef>,
    pub pref_version: u64,
    pub terms_version: Option<u32>,
    pub terms_digest: Option<String>,
    pub self_attested_18: bool,
    pub revoked_all_before: u64,
}

impl Default for StoredSafetyState {
    fn default() -> Self {
        Self {
            enabled_switchers: Vec::new(),
            pref_version: 1,
            terms_version: None,
            terms_digest: None,
            self_attested_18: false,
            revoked_all_before: 0,
        }
    }
}

/// Parse persisted `enabled_switchers_json` into validated, deduplicated `Vec<PolicyRef>`.
///
/// Accepts canonical `{"id": "...", "grant_generation": N}` objects AND compact `"<id>@<gen>"`
/// strings. Legacy unversioned v2 policy IDs (without `grant_generation`) are dropped fail-closed
/// so prior v2 opt-ins never silently grant v3 bypasses.
pub(crate) fn parse_stored_policy_refs(raw_json: &str) -> Vec<PolicyRef> {
    let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(raw_json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        let parsed = if let Some(s) = item.as_str() {
            PolicyRef::from_key(s.trim()).ok()
        } else {
            serde_json::from_value::<PolicyRef>(item)
                .ok()
                .filter(|p| p.validate().is_ok())
        };
        if let Some(pref) = parsed
            && !out.contains(&pref)
        {
            out.push(pref);
        }
    }
    out
}

/// Cold-load Safe Mode wipe migration (Codex MEDIUM #6):
///
/// If legacy `safe_mode == true`, atomically clears `enabled_switchers = []`,
/// clears legacy `safe_mode = false`, increments `pref_version`, and returns
/// `(migrated_state, needs_persist = true)` so the DO persists immediately
/// BEFORE serving any `SessionContext`!
pub(crate) fn migrate_legacy_safe_mode_on_load(
    raw: RawStoredSafetyRow,
) -> (StoredSafetyState, bool) {
    let base_ver = raw.pref_version.max(1);
    if raw.legacy_safe_mode {
        (
            StoredSafetyState {
                enabled_switchers: Vec::new(),
                pref_version: base_ver.saturating_add(1),
                terms_version: raw.terms_version,
                terms_digest: raw.terms_digest,
                self_attested_18: raw.self_attested_18,
                revoked_all_before: raw.revoked_all_before,
            },
            true,
        )
    } else {
        (
            StoredSafetyState {
                enabled_switchers: raw.enabled_switchers,
                pref_version: base_ver,
                terms_version: raw.terms_version,
                terms_digest: raw.terms_digest,
                self_attested_18: raw.self_attested_18,
                revoked_all_before: raw.revoked_all_before,
            },
            false,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrefsUpdateOutcome {
    Updated(StoredSafetyState),
    VersionConflict { current: StoredSafetyState },
}

/// Pure optimistic-concurrency state transition for `UserAccount` DO `/prefs-update`.
///
/// When `expected_pref_version` is supplied and differs from `current.pref_version`,
/// rejects with `VersionConflict` carrying fresh state without mutating.
/// On success, atomically replaces `enabled_switchers` and increments `pref_version`.
pub(crate) fn apply_prefs_update(
    current: &StoredSafetyState,
    enabled_switchers: Vec<PolicyRef>,
    expected_pref_version: Option<u64>,
) -> PrefsUpdateOutcome {
    let cur_ver = current.pref_version.max(1);
    if let Some(expected) = expected_pref_version
        && expected != cur_ver
    {
        return PrefsUpdateOutcome::VersionConflict {
            current: StoredSafetyState {
                pref_version: cur_ver,
                ..current.clone()
            },
        };
    }
    let mut deduped = Vec::with_capacity(enabled_switchers.len());
    for pref in enabled_switchers {
        if pref.validate().is_ok() && !deduped.contains(&pref) {
            deduped.push(pref);
        }
    }
    PrefsUpdateOutcome::Updated(StoredSafetyState {
        enabled_switchers: deduped,
        pref_version: cur_ver.saturating_add(1),
        ..current.clone()
    })
}

pub(crate) fn compute_session_context(
    banned: bool,
    suspended: bool,
    requested_sid: Option<&str>,
    session_row: Option<&StoredSessionSnapshot>,
    safety: &StoredSafetyState,
    now: u64,
) -> SessionContext {
    let pref_version = safety.pref_version.max(1);
    if banned || suspended {
        return SessionContext {
            active: false,
            banned,
            suspended,
            sid_valid: false,
            assurance_level: AssuranceLevel::None,
            strict_age_ok: false,
            terms_version_accepted: safety.terms_version,
            terms_digest_accepted: safety.terms_digest.clone(),
            enabled_switchers: Vec::new(),
            pref_version,
        };
    }

    match requested_sid {
        Some(_) => {
            let Some(row) = session_row else {
                return SessionContext {
                    active: true,
                    banned: false,
                    suspended: false,
                    sid_valid: false,
                    assurance_level: AssuranceLevel::None,
                    strict_age_ok: false,
                    terms_version_accepted: safety.terms_version,
                    terms_digest_accepted: safety.terms_digest.clone(),
                    enabled_switchers: Vec::new(),
                    pref_version,
                };
            };
            let valid = row.revoked_at.is_none() && row.expires_at > now;
            if !valid {
                return SessionContext {
                    active: true,
                    banned: false,
                    suspended: false,
                    sid_valid: false,
                    assurance_level: AssuranceLevel::None,
                    strict_age_ok: false,
                    terms_version_accepted: safety.terms_version,
                    terms_digest_accepted: safety.terms_digest.clone(),
                    enabled_switchers: Vec::new(),
                    pref_version,
                };
            }
            let effective_assurance = match row.assurance_level {
                AssuranceLevel::None if safety.self_attested_18 => AssuranceLevel::SelfAttestation,
                other => other,
            };
            let strict_age_ok = row.strict_age_ok && effective_assurance == AssuranceLevel::Verified18;
            SessionContext {
                active: true,
                banned: false,
                suspended: false,
                sid_valid: true,
                assurance_level: effective_assurance,
                strict_age_ok,
                terms_version_accepted: safety.terms_version,
                terms_digest_accepted: safety.terms_digest.clone(),
                enabled_switchers: safety.enabled_switchers.clone(),
                pref_version,
            }
        }
        None => {
            // Legacy wallet cutover token (no `sid`): honored only if not banned and
            // `session-revoke-all` has not invalidated prior sessions. Never grants strict_age_ok.
            let legacy_valid = safety.revoked_all_before == 0;
            let assurance = if safety.self_attested_18 {
                AssuranceLevel::SelfAttestation
            } else {
                AssuranceLevel::None
            };
            SessionContext {
                active: true,
                banned: false,
                suspended: false,
                sid_valid: legacy_valid,
                assurance_level: assurance,
                strict_age_ok: false,
                terms_version_accepted: safety.terms_version,
                terms_digest_accepted: safety.terms_digest.clone(),
                enabled_switchers: if !legacy_valid {
                    Vec::new()
                } else {
                    safety.enabled_switchers.clone()
                },
                pref_version,
            }
        }
    }
}

/// Pure preview transform rate budget decision (separate from clear-view billing).
/// Enforces per-window unique item cap, per-item repeat hit cap, and total hits cap
/// so repeating a single preview URL can never cause unbounded origin/transform load (Cycle 3 H7).
pub(crate) fn decide_preview_budget(
    item_hits: u32,
    unique_count: u32,
    total_hits: u32,
    max_unique: u32,
    max_item_hits: u32,
) -> (bool, u32) {
    let max_total_hits = max_unique.saturating_mul(2);
    if item_hits >= max_item_hits || total_hits >= max_total_hits {
        return (false, 0);
    }
    if item_hits == 0 && unique_count >= max_unique {
        return (false, 0);
    }
    let next_unique = if item_hits == 0 {
        unique_count.saturating_add(1)
    } else {
        unique_count
    };
    let next_total = total_hits.saturating_add(1);
    let rem_unique = max_unique.saturating_sub(next_unique);
    let rem_total = max_total_hits.saturating_sub(next_total);
    (true, rem_unique.min(rem_total))
}

/// Pure helper determining whether a `SessionRevokeAllReq` targets a selective subset
/// (including legacy-only invalidation) rather than revoking every active `v2` session (Cycle 3 H3).
pub(crate) fn is_selective_revoke(req: &SessionRevokeAllReq) -> bool {
    req.identity_key.is_some()
        || req.strict_only
        || req.revoke_sid.is_some()
        || req.invalidate_legacy
}

struct RefundGuard<'a> {
    set: &'a std::cell::RefCell<HashSet<String>>,
    key: String,
}

impl Drop for RefundGuard<'_> {
    fn drop(&mut self) {
        self.set.borrow_mut().remove(&self.key);
    }
}

enum FreeOutcome {
    NotCovered,
    AlreadyCovered,
    Reserved(Vec<u8>),
}

struct ChargeHold {
    kind: String,
    source: String,
    cost: i64,
    day: i64,
    path: String,
    win_start: i64,
    free_hash: Vec<u8>,
}

fn now_secs() -> u64 {
    Date::now().as_millis() / 1000
}

fn json<T: serde::Serialize>(v: &T, status: u16) -> Result<Response> {
    Ok(Response::from_json(v)?.with_status(status))
}

// ---------------------------------------------------------------------------
// Durable Object
// ---------------------------------------------------------------------------

#[durable_object]
pub struct UserAccount {
    state: State,
    env: Env,
    handoff_schema_ready: std::cell::Cell<bool>,
    handoff_last_purge: std::cell::Cell<i64>,
    holds_schema_ready: std::cell::Cell<bool>,
    holds_last_purge: std::cell::Cell<i64>,
    refunding_holds: std::cell::RefCell<HashSet<String>>,
    sessions_schema_ready: std::cell::Cell<bool>,
    sessions_last_purge: std::cell::Cell<i64>,
}

impl DurableObject for UserAccount {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            handoff_schema_ready: std::cell::Cell::new(false),
            handoff_last_purge: std::cell::Cell::new(0),
            holds_schema_ready: std::cell::Cell::new(false),
            holds_last_purge: std::cell::Cell::new(0),
            refunding_holds: std::cell::RefCell::new(HashSet::new()),
            sessions_schema_ready: std::cell::Cell::new(false),
            sessions_last_purge: std::cell::Cell::new(0),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        // Routes that use DO SQLite/storage directly and do not need site policy loading.
        match (req.method(), path.as_str()) {
            (Method::Post, "/session-context") => {
                let text = req.text().await.unwrap_or_default();
                let body: SessionContextReq = if text.trim().is_empty() {
                    SessionContextReq { sid: None }
                } else {
                    serde_json::from_str(&text)
                        .map_err(|e| worker::Error::RustError(e.to_string()))?
                };
                return self.session_context(body).await;
            }
            (Method::Post, "/session-issue") => {
                return self.session_issue(req.json().await?).await;
            }
            (Method::Post, "/session-revoke") => {
                return self.session_revoke(req.json().await?);
            }
            (Method::Post, "/session-revoke-all") => {
                let text = req.text().await.unwrap_or_default();
                let body: SessionRevokeAllReq = if text.trim().is_empty() {
                    SessionRevokeAllReq::default()
                } else {
                    serde_json::from_str(&text)
                        .map_err(|e| worker::Error::RustError(e.to_string()))?
                };
                return self.session_revoke_all(body);
            }
            (Method::Post, "/session-info") => {
                return self.session_info(req.json().await?);
            }
            (Method::Post, "/prefs-update") => {
                return self.prefs_update(req.json().await?).await;
            }
            (Method::Post, "/billing-prefs") => {
                return self.billing_prefs(req.json().await?).await;
            }
            (Method::Post, "/terms-accept") => {
                return self.terms_accept(req.json().await?);
            }
            (Method::Post, "/age-confirm") => {
                return self.age_confirm(req.json().await?);
            }
            (Method::Post, "/handoff-start") => {
                return self.handoff_start(req.json().await?);
            }
            (Method::Post, "/handoff-info") => {
                return self.handoff_info(req.json().await?);
            }
            (Method::Post, "/handoff-approve") => {
                return self.handoff_approve(req.json().await?);
            }
            (Method::Post, "/handoff-poll") => {
                return self.handoff_poll(req.json().await?);
            }
            (Method::Post, "/handoff-consume") => {
                return self.handoff_consume(req.json().await?);
            }
            (Method::Post, "/transfer-create") => {
                return self.transfer_create(req.json().await?);
            }
            (Method::Post, "/transfer-claim") => {
                return self.transfer_claim(req.json().await?);
            }
            (Method::Post, "/transfer-revoke") => {
                return self.transfer_revoke(req.json().await?);
            }
            (Method::Post, "/commit") => {
                return self.commit(req.json().await?).await;
            }
            (Method::Post, "/release") => {
                return self.release(req.json().await?).await;
            }
            (Method::Post, "/commit-guest") => {
                return self.commit_guest(req.json().await?).await;
            }
            (Method::Post, "/release-guest") => {
                return self.release_guest(req.json().await?).await;
            }
            _ => {}
        }
        let policy = settings::load(&self.env).await?;
        match (req.method(), path.as_str()) {
            (Method::Post, "/init") => self.init(req.json().await?, &policy).await,
            (Method::Post, "/charge") => self.charge(req.json().await?, &policy, false).await,
            (Method::Post, "/can-charge") => self.charge(req.json().await?, &policy, true).await,
            (Method::Post, "/reserve") => self.reserve(req.json().await?, &policy).await,
            (Method::Post, "/credit") => self.credit(req.json().await?, &policy).await,
            (Method::Post, "/payment-applied") => {
                let hash: String = req.json().await?;
                let applied = self.get_or(&format!("credit:tx:{hash}"), false).await?;
                json(&applied, 200)
            }
            (Method::Get, "/status") => json(&self.status_resp(&policy).await?, 200),
            (Method::Post, "/check-active") => {
                if self.get_or("banned", false).await? || self.get_or("suspended", false).await? {
                    Response::error("banned or suspended", 403)
                } else {
                    Response::ok("")
                }
            }
            (Method::Post, "/subscribe") => self.subscribe(req.json().await?, &policy).await,
            (Method::Post, "/unsubscribe") => self.unsubscribe(&policy).await,
            (Method::Post, "/ban") => self.ban(req.json().await?, &policy).await,
            (Method::Post, "/guest") => self.guest(req.json().await?, &policy).await,
            (Method::Post, "/reserve-guest") => self.reserve_guest(req.json().await?, &policy).await,
            (Method::Post, "/preview-budget") => self.preview_budget(req.json().await?, &policy).await,
            (Method::Post, "/admin-plan") => self.admin_plan(req.json().await?, &policy).await,
            (Method::Post, "/merge-preview") => self.merge_preview(req.json().await?, &policy).await,
            (Method::Post, "/merge-drain") => self.merge_drain(req.json().await?, &policy).await,
            (Method::Post, "/merge-receive") => self.merge_receive(req.json().await?, &policy).await,
            _ => Response::error("not found", 404),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        let storage = self.state.storage();
        let now = now_secs();
        // Reclaim and refund any expired uncommitted charge holds (Cycle 2 D-3 / Cycle 3 H4).
        // Propagate errors so the Workers runtime retries the alarm rather than dropping refunds.
        self.reclaim_expired_holds(now as i64, true).await?;
        if storage.get::<String>("plan").await?.is_some() {
            let period_end: u64 = self.get_or("period_end", 0).await?;
            if period_end <= now {
                // An inactive plan already hides its allowances. Keep the counters in
                // case the user subscribes again during the same five-hour window.
                storage.delete("plan").await?;
            }
        }
        self.schedule_next_alarm(now).await?;
        Response::ok("")
    }
}

impl UserAccount {
    async fn write_fields(&self, fields: serde_json::Value) -> Result<()> {
        // DO multi-put takes a plain JS object. BigInt preserves exact i64 balances.
        let serializer = serde_wasm_bindgen::Serializer::new()
            .serialize_maps_as_objects(true)
            .serialize_large_number_types_as_bigints(true);
        let object = serde::Serialize::serialize(&fields, &serializer)?;
        self.state.storage().put_multiple_raw(object.into()).await
    }

    async fn write_plan(&self, mut fields: serde_json::Value, end: u64, now: u64) -> Result<()> {
        fields["period_end"] = end.into();
        let storage = self.state.storage();
        if end > now && should_roll(storage.get("win_start").await?, now) {
            fields["win_start"] = now.into();
            fields["win_views"] = 0.into();
            fields["win_search"] = 0.into();
        }
        self.write_fields(fields).await?;
        if end <= now {
            storage.delete("plan").await?;
        }
        self.schedule_next_alarm(now).await?;
        Ok(())
    }

    /// Schedules the DO alarm for the earliest pending expiry across active
    /// subscriptions and uncommitted `charge_holds`.
    async fn schedule_next_alarm(&self, now: u64) -> Result<()> {
        let storage = self.state.storage();
        let mut earliest: Option<u64> = None;

        if storage.get::<String>("plan").await?.is_some() {
            let period_end: u64 = self.get_or("period_end", 0).await?;
            if period_end > now {
                earliest = Some(period_end);
            }
        }

        if let Ok(db) = self.ensure_holds_table() {
            #[derive(serde::Deserialize)]
            struct MinRow {
                min_created: Option<i64>,
            }
            if let Ok(rows) = db
                .exec(
                    "SELECT MIN(\
                        MAX(\
                            h.created_at,\
                            COALESCE((SELECT MAX(l.created_at) FROM hold_leases l WHERE l.hold_id = h.hold_id), h.created_at)\
                        )\
                     ) AS min_created FROM charge_holds h",
                    None,
                )
                .and_then(|c| c.to_array::<MinRow>())
                && let Some(min_created) = rows.first().and_then(|r| r.min_created)
            {
                let hold_exp = min_created.saturating_add(HOLD_TTL_SECS).max(0) as u64;
                earliest = Some(match earliest {
                    Some(cur) => cur.min(hold_exp),
                    None => hold_exp,
                });
            }
        }

        if let Some(target) = earliest {
            let delta_secs = target.saturating_sub(now).max(1);
            storage.set_alarm((delta_secs.saturating_mul(1000)) as i64).await?;
        } else {
            storage.delete_alarm().await?;
        }
        Ok(())
    }

    // Refund the historical price actually paid. Legacy subscriptions were
    // sold at the compile-time price. Admin-granted periods have zero basis.
    async fn refund(&self, id: Option<&str>, end: u64, now: u64) -> Result<i64> {
        let Some(plan) = id.and_then(config::plan).filter(|_| end > now) else {
            return Ok(0);
        };
        let paid = self.get_or("plan_paid", plan.price_points).await?;
        Ok(prorated_refund(paid, plan.period_secs, end - now))
    }

    async fn refund_paid_only(&self, id: Option<&str>, end: u64, now: u64) -> Result<i64> {
        let Some(plan) = id.and_then(config::plan).filter(|_| end > now) else {
            return Ok(0);
        };
        let paid = self.get_or("plan_paid", plan.price_points).await?;
        let paid_real: i64 = self.get_or("plan_paid_real", paid).await?.clamp(0, paid);
        Ok(prorated_refund(paid_real, plan.period_secs, end - now))
    }

    fn ensure_holds_table(&self) -> Result<worker::SqlStorage> {
        let db = self.state.storage().sql();
        if !self.holds_schema_ready.get() {
            db.exec(
                "CREATE TABLE IF NOT EXISTS charge_holds (\
                    hold_id TEXT PRIMARY KEY,\
                    is_guest INTEGER NOT NULL,\
                    kind TEXT NOT NULL,\
                    source TEXT NOT NULL,\
                    cost INTEGER NOT NULL,\
                    day INTEGER NOT NULL,\
                    path TEXT NOT NULL,\
                    win_start INTEGER NOT NULL,\
                    free_hash BLOB NOT NULL,\
                    created_at INTEGER NOT NULL\
                )",
                None,
            )?;
            db.exec(
                "CREATE TABLE IF NOT EXISTS hold_leases (\
                    lease_id TEXT PRIMARY KEY,\
                    hold_id TEXT NOT NULL,\
                    is_guest INTEGER NOT NULL,\
                    created_at INTEGER NOT NULL\
                )",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_charge_holds_created ON charge_holds(created_at)",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_charge_holds_guest_path ON charge_holds(is_guest, path)",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_hold_leases_hold ON hold_leases(hold_id)",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_hold_leases_created ON hold_leases(created_at)",
                None,
            )?;
            self.holds_schema_ready.set(true);
        }
        Ok(db)
    }

    /// Finds an active in-flight parent hold that still has at least one unexpired lease
    /// so concurrent identical requests coalesce via per-participant `hold_leases` (Cycle 3 H1 / Cycle 4 I2-I3).
    fn find_in_flight_hold(
        db: &worker::SqlStorage,
        is_guest: bool,
        kind: &str,
        path: &str,
        cutoff: i64,
    ) -> Result<Option<String>> {
        #[derive(serde::Deserialize)]
        struct HoldIdRow {
            hold_id: String,
        }
        let guest_flag: i64 = if is_guest { 1 } else { 0 };
        let rows: Vec<HoldIdRow> = db
            .exec(
                "SELECT h.hold_id FROM charge_holds h \
                 WHERE h.is_guest = ?1 AND h.kind = ?2 AND h.path = ?3 \
                   AND EXISTS (SELECT 1 FROM hold_leases l WHERE l.hold_id = h.hold_id AND l.created_at > ?4) \
                 LIMIT 1",
                vec![guest_flag.into(), kind.into(), path.into(), cutoff.into()],
            )?
            .to_array()?;
        Ok(rows.into_iter().next().map(|r| r.hold_id))
    }

    fn attach_hold_lease(
        db: &worker::SqlStorage,
        parent_hold_id: &str,
        is_guest: bool,
        now: i64,
    ) -> Result<String> {
        let lease_id = uuid::Uuid::new_v4().to_string();
        let guest_flag: i64 = if is_guest { 1 } else { 0 };
        db.exec(
            "INSERT INTO hold_leases (lease_id, hold_id, is_guest, created_at) VALUES (?1, ?2, ?3, ?4)",
            vec![
                lease_id.clone().into(),
                parent_hold_id.into(),
                guest_flag.into(),
                now.into(),
            ],
        )?;
        Ok(lease_id)
    }

    /// Resolves a caller-supplied `lease_id` (or legacy pre-deploy `hold_id` without lease rows)
    /// to `(parent_hold_id, had_lease_row)`.
    fn resolve_lease_hold_id(
        db: &worker::SqlStorage,
        lease_or_hold_id: &str,
        is_guest: bool,
    ) -> Result<Option<(String, bool)>> {
        #[derive(serde::Deserialize)]
        struct HoldIdRow {
            hold_id: String,
        }
        let guest_flag: i64 = if is_guest { 1 } else { 0 };
        let lease_rows: Vec<HoldIdRow> = db
            .exec(
                "SELECT hold_id FROM hold_leases WHERE lease_id = ?1 AND is_guest = ?2",
                vec![lease_or_hold_id.into(), guest_flag.into()],
            )?
            .to_array()?;
        if let Some(row) = lease_rows.into_iter().next() {
            return Ok(Some((row.hold_id, true)));
        }
        // Fallback for any in-flight hold created right before `hold_leases` rollout.
        let legacy_rows: Vec<HoldIdRow> = db
            .exec(
                "SELECT h.hold_id FROM charge_holds h \
                 WHERE h.hold_id = ?1 AND h.is_guest = ?2 \
                   AND NOT EXISTS (SELECT 1 FROM hold_leases l WHERE l.hold_id = h.hold_id)",
                vec![lease_or_hold_id.into(), guest_flag.into()],
            )?
            .to_array()?;
        Ok(legacy_rows.into_iter().next().map(|r| (r.hold_id, false)))
    }

    fn peek_charge_hold(
        db: &worker::SqlStorage,
        hold_id: &str,
        is_guest: bool,
    ) -> Result<Option<ChargeHold>> {
        #[derive(serde::Deserialize)]
        struct RawHoldRow {
            kind: String,
            source: String,
            cost: i64,
            day: i64,
            path: String,
            win_start: i64,
            free_hash_hex: String,
        }
        let guest_flag: i64 = if is_guest { 1 } else { 0 };
        let rows: Vec<RawHoldRow> = db
            .exec(
                "SELECT kind, source, cost, day, path, win_start, hex(free_hash) AS free_hash_hex \
                 FROM charge_holds WHERE hold_id = ?1 AND is_guest = ?2",
                vec![hold_id.into(), guest_flag.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let free_hash = if row.free_hash_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(&row.free_hash_hex)
                .map_err(|e| worker::Error::RustError(format!("invalid hold free_hash: {e}")))?
        };
        Ok(Some(ChargeHold {
            kind: row.kind,
            source: row.source,
            cost: row.cost,
            day: row.day,
            path: row.path,
            win_start: row.win_start,
            free_hash,
        }))
    }

    /// Crash-safe exact-once refund & deletion of a parent `charge_holds` row (Cycle 3 H4).
    ///
    /// 1. Synchronously removes `hold_leases` for `hold_id` and records `hold_id` in
    ///    `refunding_holds` before any `.await` so no concurrent `reserve` can coalesce onto
    ///    it and no concurrent alarm/release can double-refund it.
    /// 2. Guards KV refunds (`balance` / `win_*`) with an atomic `"rf:{hold_id}"` marker
    ///    written in the same `write_fields` call so a crash after KV write and before SQLite
    ///    delete can never double-refund on retry, while a KV write failure leaves
    ///    `charge_holds` intact for alarm retry instead of permanently losing funds.
    /// 3. Deletes `charge_holds` in SQLite and then best-effort deletes the temporary KV marker.
    async fn refund_and_delete_hold(
        &self,
        db: &worker::SqlStorage,
        hold_id: &str,
        hold: ChargeHold,
        is_guest: bool,
    ) -> Result<()> {
        // Synchronously detach all leases before any `.await` so no concurrent `reserve`
        // can attach a new lease to this dying hold.
        db.exec(
            "DELETE FROM hold_leases WHERE hold_id = ?1",
            vec![hold_id.into()],
        )?;
        if !self.refunding_holds.borrow_mut().insert(hold_id.to_string()) {
            return Ok(());
        }
        let _guard = RefundGuard {
            set: &self.refunding_holds,
            key: hold_id.to_string(),
        };

        if !hold.free_hash.is_empty() {
            db.exec(
                "DELETE FROM free_usage WHERE day = ?1 AND kind = ?2 AND resource = ?3",
                vec![
                    hold.day.into(),
                    hold.kind.clone().into(),
                    hold.free_hash.into(),
                ],
            )?;
        }

        let mut used_kv_marker: Option<String> = None;
        if !is_guest {
            match hold.source.as_str() {
                "balance" => {
                    let marker = format!("rf:{hold_id}");
                    if self.state.storage().get::<bool>(&marker).await?.is_none() {
                        let balance: i64 = self.get_or("balance", 0).await?;
                        self.write_fields(serde_json::json!({
                            "balance": balance.saturating_add(hold.cost.max(0)),
                            (marker.clone()): true,
                        }))
                        .await?;
                    }
                    used_kv_marker = Some(marker);
                }
                "window" => {
                    let marker = format!("rf:{hold_id}");
                    if self.state.storage().get::<bool>(&marker).await?.is_none() {
                        let current_win_start: Option<u64> =
                            self.state.storage().get("win_start").await?;
                        let win_views: i64 = self.get_or("win_views", 0).await?;
                        let win_search: i64 = self.get_or("win_search", 0).await?;
                        if let Some((next_views, next_search)) = refund_window_counters(
                            &hold.kind,
                            hold.cost,
                            current_win_start,
                            hold.win_start,
                            win_views,
                            win_search,
                        ) {
                            self.write_fields(serde_json::json!({
                                "win_views": next_views,
                                "win_search": next_search,
                                (marker.clone()): true,
                            }))
                            .await?;
                            used_kv_marker = Some(marker);
                        }
                    } else {
                        used_kv_marker = Some(marker);
                    }
                }
                _ => {}
            }
        }

        db.exec(
            "DELETE FROM hold_leases WHERE hold_id = ?1",
            vec![hold_id.into()],
        )?;
        db.exec(
            "DELETE FROM charge_holds WHERE hold_id = ?1",
            vec![hold_id.into()],
        )?;
        if let Some(marker) = used_kv_marker {
            let _ = self.state.storage().delete(&marker).await;
        }
        Ok(())
    }

    /// Targeted expiry reclaim for a single `(is_guest, kind, path)` key bypassing the 30s
    /// `holds_last_purge` throttle, so `eval_free_item` can never observe a stale `free_usage`
    /// row belonging to an expired uncommitted hold ignored by `find_in_flight_hold` (Cycle 4 I3).
    async fn reclaim_expired_holds_for_item(
        &self,
        db: &worker::SqlStorage,
        is_guest: bool,
        kind: &str,
        path: &str,
        cutoff: i64,
    ) -> Result<usize> {
        let guest_flag: i64 = if is_guest { 1 } else { 0 };
        db.exec(
            "DELETE FROM hold_leases WHERE created_at <= ?1 AND hold_id IN (\
                SELECT hold_id FROM charge_holds \
                WHERE is_guest = ?2 AND kind = ?3 AND path = ?4 AND created_at <= ?1\
             )",
            vec![cutoff.into(), guest_flag.into(), kind.into(), path.into()],
        )?;
        #[derive(serde::Deserialize)]
        struct ExpiredItemHoldRow {
            hold_id: String,
            kind: String,
            source: String,
            cost: i64,
            day: i64,
            path: String,
            win_start: i64,
            free_hash_hex: String,
        }
        let expired: Vec<ExpiredItemHoldRow> = db
            .exec(
                "SELECT h.hold_id, h.kind, h.source, h.cost, h.day, h.path, h.win_start, hex(h.free_hash) AS free_hash_hex \
                 FROM charge_holds h \
                 WHERE h.is_guest = ?1 AND h.kind = ?2 AND h.path = ?3 AND h.created_at <= ?4 \
                   AND NOT EXISTS (SELECT 1 FROM hold_leases l WHERE l.hold_id = h.hold_id)",
                vec![guest_flag.into(), kind.into(), path.into(), cutoff.into()],
            )?
            .to_array()?;
        let mut reclaimed = 0usize;
        for row in expired {
            let free_hash = if row.free_hash_hex.is_empty() {
                Vec::new()
            } else {
                hex::decode(&row.free_hash_hex).unwrap_or_default()
            };
            let hold = ChargeHold {
                kind: row.kind,
                source: row.source,
                cost: row.cost,
                day: row.day,
                path: row.path,
                win_start: row.win_start,
                free_hash,
            };
            self.refund_and_delete_hold(db, &row.hold_id, hold, is_guest)
                .await?;
            reclaimed += 1;
        }
        Ok(reclaimed)
    }

    /// Reclaims and refunds all uncommitted `charge_holds` older than `HOLD_TTL_SECS` that have
    /// no remaining live `hold_leases` (Cycle 2 D-3 / Cycle 3 H4 / Cycle 4 I2).
    /// Returns the number of expired holds reclaimed. Updates `holds_last_purge` ONLY after the sweep succeeds.
    async fn reclaim_expired_holds(&self, now: i64, force: bool) -> Result<usize> {
        if !force && now.saturating_sub(self.holds_last_purge.get()) < 30 {
            return Ok(0);
        }
        let db = self.ensure_holds_table()?;
        let cutoff = now.saturating_sub(HOLD_TTL_SECS);
        // 1. Delete expired leases first so newly attached live leases protect their parent
        //    hold for their full TTL (Cycle 4 I2).
        db.exec(
            "DELETE FROM hold_leases WHERE created_at <= ?1",
            vec![cutoff.into()],
        )?;
        #[derive(serde::Deserialize)]
        struct ExpiredHoldRow {
            hold_id: String,
            is_guest: i64,
            kind: String,
            source: String,
            cost: i64,
            day: i64,
            path: String,
            win_start: i64,
            free_hash_hex: String,
        }
        // 2. Only reclaim expired parent holds with zero remaining live leases.
        let expired: Vec<ExpiredHoldRow> = db
            .exec(
                "SELECT h.hold_id, h.is_guest, h.kind, h.source, h.cost, h.day, h.path, h.win_start, hex(h.free_hash) AS free_hash_hex \
                 FROM charge_holds h \
                 WHERE h.created_at <= ?1 \
                   AND NOT EXISTS (SELECT 1 FROM hold_leases l WHERE l.hold_id = h.hold_id)",
                vec![cutoff.into()],
            )?
            .to_array()?;
        let mut reclaimed = 0usize;
        for row in expired {
            let free_hash = if row.free_hash_hex.is_empty() {
                Vec::new()
            } else {
                hex::decode(&row.free_hash_hex).unwrap_or_default()
            };
            let hold = ChargeHold {
                kind: row.kind,
                source: row.source,
                cost: row.cost,
                day: row.day,
                path: row.path,
                win_start: row.win_start,
                free_hash,
            };
            self.refund_and_delete_hold(&db, &row.hold_id, hold, row.is_guest != 0)
                .await?;
            reclaimed += 1;
        }
        self.holds_last_purge.set(now);
        Ok(reclaimed)
    }

    fn take_charge_hold(
        db: &worker::SqlStorage,
        hold_id: &str,
        is_guest: bool,
    ) -> Result<Option<ChargeHold>> {
        let Some(hold) = Self::peek_charge_hold(db, hold_id, is_guest)? else {
            return Ok(None);
        };
        let guest_flag: i64 = if is_guest { 1 } else { 0 };
        db.exec(
            "DELETE FROM charge_holds WHERE hold_id = ?1 AND is_guest = ?2",
            vec![hold_id.into(), guest_flag.into()],
        )?;
        Ok(Some(hold))
    }

    fn eval_free_item(
        &self,
        req: &ChargeReq,
        limit: i64,
        day: u64,
        check_only: bool,
    ) -> Result<FreeOutcome> {
        if limit == 0 {
            return Ok(FreeOutcome::NotCovered);
        }
        if limit < 0 {
            return Ok(FreeOutcome::AlreadyCovered);
        }
        // Synchronous DO SQLite calls complete before another request can enter.
        // Store single resource hashes rather than an ever-growing KV value.
        use sha2::{Digest, Sha256};
        #[derive(serde::Deserialize)]
        struct Usage {
            seen: i64,
            used: i64,
        }
        let db = self.state.storage().sql();
        db.exec(
            "CREATE TABLE IF NOT EXISTS free_usage (day INTEGER,kind TEXT,resource BLOB, PRIMARY KEY(day,kind,resource)) WITHOUT ROWID",
            None,
        )?;
        if !check_only {
            db.exec(
                "DELETE FROM free_usage WHERE day < ?",
                vec![(day as i64).into()],
            )?;
        }
        let hash = Sha256::digest(req.path.as_bytes()).to_vec();
        let kind = req.kind.name();
        let used: Usage = db
            .exec(
                "SELECT EXISTS(SELECT 1 FROM free_usage WHERE day=?1 AND kind=?2 AND resource=?3) AS seen, COUNT(*) AS used FROM free_usage WHERE day=?1 AND kind=?2",
                vec![(day as i64).into(), kind.into(), hash.clone().into()],
            )?
            .one()?;
        if used.seen != 0 {
            return Ok(FreeOutcome::AlreadyCovered);
        }
        if used.used >= limit {
            return Ok(FreeOutcome::NotCovered);
        }
        if !check_only {
            db.exec(
                "INSERT INTO free_usage VALUES(?,?,?)",
                vec![(day as i64).into(), kind.into(), hash.clone().into()],
            )?;
            return Ok(FreeOutcome::Reserved(hash));
        }
        Ok(FreeOutcome::AlreadyCovered)
    }

    fn free_item(&self, req: &ChargeReq, limit: i64, day: u64, check_only: bool) -> Result<bool> {
        Ok(!matches!(
            self.eval_free_item(req, limit, day, check_only)?,
            FreeOutcome::NotCovered
        ))
    }

    /// Count today's (UTC) consumed daily free allowances per `ChargeKind` name.
    /// Returns an empty map if `free_usage` has not been created yet.
    fn daily_free_usage(&self, day: u64) -> HashMap<String, i64> {
        #[derive(serde::Deserialize)]
        struct KindUsage {
            kind: String,
            used: i64,
        }
        let db = self.state.storage().sql();
        let Ok(cursor) = db.exec(
            "SELECT kind, COUNT(*) AS used FROM free_usage WHERE day = ?1 GROUP BY kind",
            vec![(day as i64).into()],
        ) else {
            return HashMap::new();
        };
        let Ok(rows) = cursor.to_array::<KindUsage>() else {
            return HashMap::new();
        };
        rows.into_iter()
            .filter(|r| r.used > 0)
            .map(|r| (r.kind, r.used))
            .collect()
    }

    async fn guest(&self, req: GuestReq, policy: &Policy) -> Result<Response> {
        if policy.login_required {
            return Response::error("Login required", 401);
        }
        let now = now_secs();
        let _ = self.reclaim_expired_holds(now as i64, false).await;
        if let Some(item) = req.item {
            let holds_db = self.ensure_holds_table()?;
            let cutoff = (now as i64).saturating_sub(HOLD_TTL_SECS);
            self.reclaim_expired_holds_for_item(
                &holds_db,
                true,
                item.kind.name(),
                &item.path,
                cutoff,
            )
            .await?;
            let limit = policy.item(item.kind).daily_free;
            let in_scope = policy.free_media_in_scope(&item);
            let mut ok = in_scope && self.free_item(&item, limit, now / 86_400, req.head)?;
            if !ok
                && in_scope
                && self.reclaim_expired_holds(now as i64, true).await? > 0
            {
                ok = self.free_item(&item, limit, now / 86_400, req.head)?;
            }
            if !ok {
                return Response::error(
                    "Sign in to access this item or continue beyond the daily free allowance",
                    402,
                );
            }
        }
        Response::ok("")
    }

    async fn reserve_guest(&self, req: GuestReq, policy: &Policy) -> Result<Response> {
        if policy.login_required {
            return Response::error("Login required", 401);
        }
        let Some(item) = req.item else {
            return json(&HoldResp { hold_id: None }, 200);
        };
        let now = now_secs();
        let _ = self.reclaim_expired_holds(now as i64, false).await;
        let day = now / 86_400;
        let limit = policy.item(item.kind).daily_free;
        if !policy.free_media_in_scope(&item) {
            return Response::error(
                "Sign in to access this item or continue beyond the daily free allowance",
                402,
            );
        }
        let holds_db = self.ensure_holds_table()?;
        let cutoff = (now as i64).saturating_sub(HOLD_TTL_SECS);
        // Reclaim any expired lease-free hold for this exact item (bypassing the 30s sweep
        // throttle) so `eval_free_item` never observes an uncommitted `free_usage` row (Cycle 4 I3).
        self.reclaim_expired_holds_for_item(
            &holds_db,
            true,
            item.kind.name(),
            &item.path,
            cutoff,
        )
        .await?;
        // Check for an active in-flight guest hold BEFORE `eval_free_item` so concurrent
        // requests for the same path attach their own lease instead of bypassing lease tracking
        // via `FreeOutcome::AlreadyCovered` (Cycle 3 H1).
        if !req.head
            && let Some(parent_hold_id) =
                Self::find_in_flight_hold(&holds_db, true, item.kind.name(), &item.path, cutoff)?
        {
            let lease_id = Self::attach_hold_lease(&holds_db, &parent_hold_id, true, now as i64)?;
            return json(
                &HoldResp {
                    hold_id: Some(lease_id),
                },
                200,
            );
        }
        let mut outcome = self.eval_free_item(&item, limit, day, req.head)?;
        if matches!(outcome, FreeOutcome::NotCovered)
            && self.reclaim_expired_holds(now as i64, true).await? > 0
        {
            outcome = self.eval_free_item(&item, limit, day, req.head)?;
        }
        match outcome {
            FreeOutcome::NotCovered => Response::error(
                "Sign in to access this item or continue beyond the daily free allowance",
                402,
            ),
            FreeOutcome::AlreadyCovered => json(&HoldResp { hold_id: None }, 200),
            FreeOutcome::Reserved(free_hash) => {
                let hold_id = uuid::Uuid::new_v4().to_string();
                holds_db.exec(
                    "INSERT INTO charge_holds \
                     (hold_id, is_guest, kind, source, cost, day, path, win_start, free_hash, created_at) \
                     VALUES (?1, 1, ?2, 'free', 0, ?3, ?4, 0, ?5, ?6)",
                    vec![
                        hold_id.clone().into(),
                        item.kind.name().into(),
                        (day as i64).into(),
                        item.path.into(),
                        free_hash.into(),
                        (now as i64).into(),
                    ],
                )?;
                holds_db.exec(
                    "INSERT INTO hold_leases (lease_id, hold_id, is_guest, created_at) \
                     VALUES (?1, ?2, 1, ?3)",
                    vec![
                        hold_id.clone().into(),
                        hold_id.clone().into(),
                        (now as i64).into(),
                    ],
                )?;
                let _ = self.schedule_next_alarm(now).await;
                json(
                    &HoldResp {
                        hold_id: Some(hold_id),
                    },
                    200,
                )
            }
        }
    }

    async fn commit_guest(&self, req: HoldReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_holds_table()?;
        // Resolve and consume `req.hold_id` BEFORE background expiry reclamation so a
        // valid commit on the TTL boundary can never self-refund the hold being committed (Cycle 4 I2).
        if let Some((parent_hold_id, _)) = Self::resolve_lease_hold_id(&db, &req.hold_id, true)? {
            db.exec(
                "DELETE FROM hold_leases WHERE hold_id = ?1",
                vec![parent_hold_id.clone().into()],
            )?;
            db.exec(
                "DELETE FROM charge_holds WHERE hold_id = ?1 AND is_guest = 1",
                vec![parent_hold_id.into()],
            )?;
        }
        let _ = self.reclaim_expired_holds(now, false).await;
        Response::ok("")
    }

    async fn release_guest(&self, req: HoldReq) -> Result<Response> {
        let now = now_secs() as i64;
        let _ = self.reclaim_expired_holds(now, false).await;
        let db = self.ensure_holds_table()?;
        let Some((parent_hold_id, had_lease)) =
            Self::resolve_lease_hold_id(&db, &req.hold_id, true)?
        else {
            return Response::ok("");
        };
        if had_lease {
            db.exec(
                "DELETE FROM hold_leases WHERE lease_id = ?1 AND is_guest = 1",
                vec![req.hold_id.into()],
            )?;
            #[derive(serde::Deserialize)]
            struct CountRow {
                n: i64,
            }
            let remaining: Vec<CountRow> = db
                .exec(
                    "SELECT COUNT(*) AS n FROM hold_leases WHERE hold_id = ?1",
                    vec![parent_hold_id.clone().into()],
                )?
                .to_array()?;
            if remaining.first().is_some_and(|r| r.n > 0) {
                return Response::ok("");
            }
        }
        let Some(hold) = Self::peek_charge_hold(&db, &parent_hold_id, true)? else {
            return Response::ok("");
        };
        self.refund_and_delete_hold(&db, &parent_hold_id, hold, true)
            .await?;
        Response::ok("")
    }

    async fn admin_plan(
        &self,
        req: crate::types::AdminPlanReq,
        policy: &Policy,
    ) -> Result<Response> {
        let storage = self.state.storage();
        let marker = format!("admin-plan:{}", req.token);
        if storage.get::<bool>(&marker).await?.is_some() {
            return json(&self.status_resp(policy).await?, 200);
        }
        let now = now_secs();
        let (id, end) = match req.plan.as_str() {
            "none" => ("", 0),
            id => match policy.plan(id) {
                Some(p) if (1..=3650).contains(&req.days) => {
                    (p.id, now + u64::from(req.days) * 86_400)
                }
                _ => return Response::error("Unknown plan", 400),
            },
        };
        let current: Option<String> = storage.get("plan").await?;
        let previous_end = self.get_or("period_end", 0).await?;
        let refund = self.refund(current.as_deref(), previous_end, now).await?;
        let balance: i64 = self.get_or("balance", 0).await?;
        self.write_plan(
            serde_json::json!({"plan":id,"plan_paid":0,"plan_paid_real":0,"balance":balance.saturating_add(refund),(marker):true}),
            end, now,
        )
        .await?;
        json(&self.status_resp(policy).await?, 200)
    }

    async fn get_or<T: DeserializeOwned>(&self, key: &str, default: T) -> Result<T> {
        Ok(self.state.storage().get(key).await?.unwrap_or(default))
    }

    /// First touch of a brand-new account: grant the free points.
    async fn ensure_init(&self, policy: &Policy) -> Result<()> {
        let storage = self.state.storage();
        if storage.get::<bool>("init").await?.is_none() {
            let existing: i64 = self.get_or("balance", 0).await?;
            let existing_free: i64 = self.get_or("free_balance", 0).await?;
            self.write_fields(serde_json::json!({
                "init": true,
                "balance": existing.saturating_add(policy.signup_points),
                "free_balance": existing_free.saturating_add(policy.signup_points),
            }))
            .await?;
        }
        Ok(())
    }

    /// Whether a subscription period is currently active.
    async fn plan_active(&self, now: u64) -> Result<bool> {
        let period_end: u64 = self.get_or("period_end", 0).await?;
        Ok(self.state.storage().get::<String>("plan").await?.is_some() && period_end > now)
    }

    /// Report the current window's remaining view/search quota and reset time
    /// from stored state, WITHOUT rolling/persisting. An elapsed (or never
    /// opened) window reports a fresh window: full quota, `window_reset == 0`.
    async fn window_fields(
        &self,
        active: bool,
        plan: Option<&config::Plan>,
        now: u64,
    ) -> Result<(Option<i64>, Option<i64>, u64)> {
        let win_start: Option<u64> = self.state.storage().get("win_start").await?;
        let open = active && !should_roll(win_start, now);
        let (win_views, win_search) = if open {
            (
                self.get_or("win_views", 0).await?,
                self.get_or("win_search", 0).await?,
            )
        } else {
            (0, 0)
        };
        Ok((
            views_remaining(plan, active, win_views),
            searches_remaining(plan, active, win_search),
            window_reset(active, win_start, now),
        ))
    }

    async fn billing_prefs(&self, req: BillingPrefsReq) -> Result<Response> {
        self.state
            .storage()
            .put("allow_paid_media", req.allow_paid_media)
            .await?;
        json(
            &BillingPrefsResp {
                allow_paid_media: req.allow_paid_media,
            },
            200,
        )
    }

    async fn status_resp(&self, policy: &Policy) -> Result<StatusResp> {
        let now = now_secs();
        let _ = self.reclaim_expired_holds(now as i64, false).await;
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active = self.plan_active(now).await?;
        let plan_id: Option<String> = self.state.storage().get("plan").await?;
        let plan_cfg = plan_id.as_deref().and_then(|id| policy.plan(id));
        let (views_remaining, searches_remaining, window_reset) =
            self.window_fields(active, plan_cfg.as_ref(), now).await?;
        let day = now / 86_400;
        Ok(StatusResp {
            address: self.get_or("address", String::new()).await?,
            balance: self.get_or("balance", 0).await?,
            plan: plan_id.filter(|_| active),
            period_end: if active { period_end } else { 0 },
            views_remaining,
            searches_remaining,
            window_reset,
            banned: self.get_or("banned", false).await?,
            total_views: self.get_or("total_views", 0).await?,
            allow_paid_media: self.get_or("allow_paid_media", false).await?,
            daily_free_used: self.daily_free_usage(day),
            daily_free_reset: next_utc_day_reset(now),
        })
    }

    async fn init(&self, req: InitReq, policy: &Policy) -> Result<Response> {
        self.ensure_init(policy).await?;
        self.state.storage().put("address", &req.address).await?;
        json(&self.status_resp(policy).await?, 200)
    }

    async fn charge(&self, req: ChargeReq, policy: &Policy, check_only: bool) -> Result<Response> {
        if !check_only {
            self.ensure_init(policy).await?;
        }
        if self.get_or("banned", false).await? || self.get_or("suspended", false).await? {
            return Response::error("banned or suspended", 403);
        }
        let storage = self.state.storage();
        let now = now_secs();
        let _ = self.reclaim_expired_holds(now as i64, false).await;
        let day = now / 86_400;
        let today_key = format!("seen:{day}");
        let today: Option<HashMap<String, u64>> = storage.get(&today_key).await?;
        let yesterday: HashMap<String, u64> = self
            .get_or(&format!("seen:{}", day - 1), HashMap::new())
            .await?;

        let rule = policy.item(req.kind);
        let cost = rule.price;
        let active = self.plan_active(now).await?;
        let plan_cfg = if active {
            storage
                .get::<String>("plan")
                .await?
                .as_deref()
                .and_then(|id| policy.plan(id))
        } else {
            None
        };

        let new_day = today.is_none();
        let mut today_map = today.unwrap_or_default();

        // Deduped repeats within the window cost nothing and touch no state; they
        // still report the current window figures.
        if is_recent_view(&req.path, now, [&today_map, &yesterday]) {
            let mut balance: i64 = self.get_or("balance", 0).await?;
            if check_only && storage.get::<bool>("init").await?.is_none() {
                balance = balance.saturating_add(policy.signup_points);
            }
            let (views_remaining, searches_remaining, window_reset) =
                self.window_fields(active, plan_cfg.as_ref(), now).await?;
            return json(
                &ChargeResp {
                    charged: false,
                    cost,
                    balance,
                    views_remaining,
                    searches_remaining,
                    window_reset,
                },
                200,
            );
        }

        // Reclaim any expired lease-free hold for this exact item (bypassing the 30s sweep
        // throttle) so `free_item` never observes an uncommitted `free_usage` row (Cycle 4 I3).
        let holds_db = self.ensure_holds_table()?;
        self.reclaim_expired_holds_for_item(
            &holds_db,
            false,
            req.kind.name(),
            &req.path,
            (now as i64).saturating_sub(HOLD_TTL_SECS),
        )
        .await?;

        // Evaluate funding; if refused (402), force-reclaim expired holds once and retry
        // before returning 402 so stale holds never cause spurious payment errors (Cycle 3 H4).
        let mut reclaimed_once = false;
        let (mut balance, win_start, mut win_views, mut win_search, mut window_dirty, included, source) = loop {
            // A first GET receives the signup grant. A HEAD can evaluate it without creating a wallet.
            let mut balance: i64 = self.get_or("balance", 0).await?;
            if check_only && storage.get::<bool>("init").await?.is_none() {
                balance = balance.saturating_add(policy.signup_points);
            }

            // Roll the usage window if the plan is active and the current one elapsed
            // (or was never opened).
            let mut win_start: Option<u64> = storage.get("win_start").await?;
            let mut win_views: i64 = self.get_or("win_views", 0).await?;
            let mut win_search: i64 = self.get_or("win_search", 0).await?;
            let allow_paid_media: bool = self.get_or("allow_paid_media", false).await?;
            let mut window_dirty = false;
            if active && should_roll(win_start, now) {
                win_start = Some(now);
                win_views = 0;
                win_search = 0;
                window_dirty = true;
            }

            let included = cost == 0
                || (policy.free_media_in_scope(&req)
                    && self.free_item(&req, rule.daily_free, day, check_only)?);
            let source = if included {
                ChargeSource::FreeUnlimited
            } else {
                decide_charge(
                    plan_cfg.as_ref(),
                    active,
                    req.kind,
                    win_views,
                    win_search,
                    balance,
                    cost,
                    allow_paid_media,
                )
            };
            // Force-reclaim expired holds once before falling back to a costlier funding
            // tier or refusing (402), so expired holds on other items never overcharge
            // PAYG balance or subscription window quota during the 30s purge throttle (Cycle 5 J4).
            let should_reclaim = source == ChargeSource::Refuse
                || (source == ChargeSource::Balance && active && plan_cfg.is_some())
                || (!included
                    && cost > 0
                    && policy.free_media_in_scope(&req)
                    && rule.daily_free > 0);
            if !reclaimed_once
                && should_reclaim
                && self.reclaim_expired_holds(now as i64, true).await? > 0
            {
                reclaimed_once = true;
                continue;
            }
            if source == ChargeSource::Refuse {
                let views_remaining = views_remaining(plan_cfg.as_ref(), active, win_views);
                let searches_remaining = searches_remaining(plan_cfg.as_ref(), active, win_search);
                let window_reset = window_reset(active, win_start, now);
                return json(
                    &ChargeResp {
                        charged: false,
                        cost,
                        balance,
                        views_remaining,
                        searches_remaining,
                        window_reset,
                    },
                    402,
                );
            }
            break (
                balance,
                win_start,
                win_views,
                win_search,
                window_dirty,
                included,
                source,
            );
        };
        if check_only {
            return Response::ok("");
        }
        let mut next_free_balance: Option<i64> = None;
        match source {
            ChargeSource::FreeUnlimited => {} // pro media view: deduct nothing
            ChargeSource::Window => {
                match req.kind {
                    ChargeKind::Search | ChargeKind::Description => win_search += 1,
                    ChargeKind::Image | ChargeKind::Video | ChargeKind::EmbedSearch => {
                        win_views += cost
                    }
                }
                window_dirty = true;
            }
            ChargeSource::Balance => {
                if let Some(fb) = storage.get::<i64>("free_balance").await? {
                    let (nb, nf) = spend_free_first(balance, fb, cost);
                    balance = nb;
                    next_free_balance = Some(nf);
                } else {
                    balance -= cost;
                }
            }
            ChargeSource::Refuse => unreachable!("handled above"),
        }

        if new_day {
            // drop the map that fell out of the dedupe horizon (bounded storage)
            storage.delete(&format!("seen:{}", day - 2)).await?;
        }
        today_map.insert(req.path, now);
        let total_views: i64 = self.get_or("total_views", 0).await? + 1;
        let mut fields = serde_json::json!({(today_key): today_map, "balance":balance, "total_views":total_views});
        if let Some(nf) = next_free_balance {
            fields["free_balance"] = nf.into();
        }
        if window_dirty {
            fields["win_start"] = win_start.expect("active window has a start").into();
            fields["win_views"] = win_views.into();
            fields["win_search"] = win_search.into();
        }
        self.write_fields(fields).await?;

        let views_remaining = views_remaining(plan_cfg.as_ref(), active, win_views);
        let searches_remaining = searches_remaining(plan_cfg.as_ref(), active, win_search);
        let window_reset = window_reset(active, win_start, now);
        json(
            &ChargeResp {
                charged: !included,
                cost: if included { 0 } else { cost },
                balance,
                views_remaining,
                searches_remaining,
                window_reset,
            },
            200,
        )
    }

    async fn reserve(&self, req: ChargeReq, policy: &Policy) -> Result<Response> {
        self.ensure_init(policy).await?;
        if self.get_or("banned", false).await? || self.get_or("suspended", false).await? {
            return Response::error("banned or suspended", 403);
        }
        let storage = self.state.storage();
        let now = now_secs();
        let _ = self.reclaim_expired_holds(now as i64, false).await;
        let day = now / 86_400;
        let today: HashMap<String, u64> =
            self.get_or(&format!("seen:{day}"), HashMap::new()).await?;
        let yesterday: HashMap<String, u64> = self
            .get_or(&format!("seen:{}", day.saturating_sub(1)), HashMap::new())
            .await?;

        if is_recent_view(&req.path, now, [&today, &yesterday]) {
            return json(&HoldResp { hold_id: None }, 200);
        }

        // Coalesce concurrent identical paid requests via per-participant `hold_leases`
        // so parallel requests never double-charge AND a failing request cannot trigger
        // a refund while a sibling request is still in flight or succeeded (Cycle 3 H1).
        let holds_db = self.ensure_holds_table()?;
        let cutoff = (now as i64).saturating_sub(HOLD_TTL_SECS);
        // Reclaim any expired lease-free hold for this exact item (bypassing the 30s sweep
        // throttle) so `eval_free_item` never observes an uncommitted `free_usage` row (Cycle 4 I3).
        self.reclaim_expired_holds_for_item(
            &holds_db,
            false,
            req.kind.name(),
            &req.path,
            cutoff,
        )
        .await?;
        if let Some(parent_hold_id) =
            Self::find_in_flight_hold(&holds_db, false, req.kind.name(), &req.path, cutoff)?
        {
            let lease_id =
                Self::attach_hold_lease(&holds_db, &parent_hold_id, false, now as i64)?;
            return json(
                &HoldResp {
                    hold_id: Some(lease_id),
                },
                200,
            );
        }

        let rule = policy.item(req.kind);
        let cost = rule.price;
        let active = self.plan_active(now).await?;
        let plan_cfg = if active {
            storage
                .get::<String>("plan")
                .await?
                .as_deref()
                .and_then(|id| policy.plan(id))
        } else {
            None
        };

        let mut reclaimed_once = false;
        let (mut balance, win_start, mut win_views, mut win_search, mut window_dirty, free_hash, source) = loop {
            let balance: i64 = self.get_or("balance", 0).await?;
            let mut win_start: Option<u64> = storage.get("win_start").await?;
            let mut win_views: i64 = self.get_or("win_views", 0).await?;
            let mut win_search: i64 = self.get_or("win_search", 0).await?;
            let allow_paid_media: bool = self.get_or("allow_paid_media", false).await?;
            let mut window_dirty = false;
            if active && should_roll(win_start, now) {
                win_start = Some(now);
                win_views = 0;
                win_search = 0;
                window_dirty = true;
            }

            // Re-check synchronously right before charging in case a sibling request created
            // a hold while we awaited KV reads. Everything from here through `eval_free_item`
            // and `decide_charge` MUST stay synchronous (no `.await`) to preserve hold coalescing.
            if let Some(parent_hold_id) =
                Self::find_in_flight_hold(&holds_db, false, req.kind.name(), &req.path, cutoff)?
            {
                let lease_id =
                    Self::attach_hold_lease(&holds_db, &parent_hold_id, false, now as i64)?;
                return json(
                    &HoldResp {
                        hold_id: Some(lease_id),
                    },
                    200,
                );
            }

            let (included, free_hash) = if cost == 0 {
                (true, Vec::new())
            } else if policy.free_media_in_scope(&req) {
                match self.eval_free_item(&req, rule.daily_free, day, false)? {
                    FreeOutcome::NotCovered => (false, Vec::new()),
                    FreeOutcome::AlreadyCovered => (true, Vec::new()),
                    FreeOutcome::Reserved(hash) => (true, hash),
                }
            } else {
                (false, Vec::new())
            };

            let source = if included {
                ChargeSource::FreeUnlimited
            } else {
                decide_charge(
                    plan_cfg.as_ref(),
                    active,
                    req.kind,
                    win_views,
                    win_search,
                    balance,
                    cost,
                    allow_paid_media,
                )
            };
            // Force-reclaim expired holds once before falling back to a costlier funding
            // tier or refusing (402), so expired holds on other items never overcharge
            // PAYG balance or subscription window quota during the 30s purge throttle (Cycle 5 J4).
            let should_reclaim = source == ChargeSource::Refuse
                || (source == ChargeSource::Balance && active && plan_cfg.is_some())
                || (!included
                    && cost > 0
                    && policy.free_media_in_scope(&req)
                    && rule.daily_free > 0);
            if !reclaimed_once
                && should_reclaim
                && self.reclaim_expired_holds(now as i64, true).await? > 0
            {
                reclaimed_once = true;
                continue;
            }
            if source == ChargeSource::Refuse {
                let views_remaining = views_remaining(plan_cfg.as_ref(), active, win_views);
                let searches_remaining = searches_remaining(plan_cfg.as_ref(), active, win_search);
                let window_reset = window_reset(active, win_start, now);
                return json(
                    &ChargeResp {
                        charged: false,
                        cost,
                        balance,
                        views_remaining,
                        searches_remaining,
                        window_reset,
                    },
                    402,
                );
            }
            break (
                balance,
                win_start,
                win_views,
                win_search,
                window_dirty,
                free_hash,
                source,
            );
        };

        let source_name = match source {
            ChargeSource::FreeUnlimited => "free",
            ChargeSource::Window => {
                match req.kind {
                    ChargeKind::Search | ChargeKind::Description => win_search += 1,
                    ChargeKind::Image | ChargeKind::Video | ChargeKind::EmbedSearch => {
                        win_views += cost
                    }
                }
                window_dirty = true;
                "window"
            }
            ChargeSource::Balance => {
                balance -= cost;
                "balance"
            }
            ChargeSource::Refuse => unreachable!("handled above"),
        };

        if source == ChargeSource::Balance || window_dirty {
            let mut fields = serde_json::Map::new();
            if source == ChargeSource::Balance {
                fields.insert("balance".into(), balance.into());
            }
            if window_dirty {
                fields.insert(
                    "win_start".into(),
                    win_start.expect("active window has a start").into(),
                );
                fields.insert("win_views".into(), win_views.into());
                fields.insert("win_search".into(), win_search.into());
            }
            self.write_fields(serde_json::Value::Object(fields)).await?;
        }

        let hold_id = uuid::Uuid::new_v4().to_string();
        let hold_cost = if source == ChargeSource::FreeUnlimited {
            0
        } else {
            cost
        };
        let hold_win_start = if source == ChargeSource::Window {
            win_start.unwrap_or(0) as i64
        } else {
            0
        };
        holds_db.exec(
            "INSERT INTO charge_holds \
             (hold_id, is_guest, kind, source, cost, day, path, win_start, free_hash, created_at) \
             VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            vec![
                hold_id.clone().into(),
                req.kind.name().into(),
                source_name.into(),
                hold_cost.into(),
                (day as i64).into(),
                req.path.into(),
                hold_win_start.into(),
                free_hash.into(),
                (now as i64).into(),
            ],
        )?;
        holds_db.exec(
            "INSERT INTO hold_leases (lease_id, hold_id, is_guest, created_at) \
             VALUES (?1, ?2, 0, ?3)",
            vec![
                hold_id.clone().into(),
                hold_id.clone().into(),
                (now as i64).into(),
            ],
        )?;
        let _ = self.schedule_next_alarm(now).await;

        json(
            &HoldResp {
                hold_id: Some(hold_id),
            },
            200,
        )
    }

    async fn commit(&self, req: HoldReq) -> Result<Response> {
        let now = now_secs();
        let db = self.ensure_holds_table()?;
        // Resolve and consume `req.hold_id` BEFORE background expiry reclamation so a
        // valid commit on the TTL boundary can never self-refund the hold being committed (Cycle 4 I2).
        let Some((parent_hold_id, _)) = Self::resolve_lease_hold_id(&db, &req.hold_id, false)?
        else {
            let _ = self.reclaim_expired_holds(now as i64, false).await;
            return Response::ok("");
        };
        db.exec(
            "DELETE FROM hold_leases WHERE hold_id = ?1",
            vec![parent_hold_id.clone().into()],
        )?;
        let Some(hold) = Self::take_charge_hold(&db, &parent_hold_id, false)? else {
            let _ = self.reclaim_expired_holds(now as i64, false).await;
            return Response::ok("");
        };

        let hold_day = hold.day.max(0) as u64;
        let day_key = format!("seen:{hold_day}");
        let storage = self.state.storage();
        let existing: Option<HashMap<String, u64>> = storage.get(&day_key).await?;
        let new_day = existing.is_none();
        let mut day_map = existing.unwrap_or_default();
        if new_day && hold_day >= 2 {
            storage.delete(&format!("seen:{}", hold_day - 2)).await?;
        }
        day_map.insert(hold.path, now);
        let total_views: i64 = self.get_or("total_views", 0).await? + 1;
        let mut fields = serde_json::json!({
            (day_key): day_map,
            "total_views": total_views,
        });
        if hold.source == "balance"
            && hold.cost > 0
            && let Some(fb) = storage.get::<i64>("free_balance").await?
        {
            let cur_bal: i64 = self.get_or("balance", 0).await?;
            let next_fb = fb.saturating_sub(hold.cost).clamp(0, cur_bal.max(0));
            fields["free_balance"] = next_fb.into();
        }
        self.write_fields(fields).await?;
        let _ = self.reclaim_expired_holds(now as i64, false).await;
        Response::ok("")
    }

    async fn release(&self, req: HoldReq) -> Result<Response> {
        let now = now_secs() as i64;
        let _ = self.reclaim_expired_holds(now, false).await;
        let db = self.ensure_holds_table()?;
        let Some((parent_hold_id, had_lease)) =
            Self::resolve_lease_hold_id(&db, &req.hold_id, false)?
        else {
            return Response::ok("");
        };
        if had_lease {
            db.exec(
                "DELETE FROM hold_leases WHERE lease_id = ?1 AND is_guest = 0",
                vec![req.hold_id.into()],
            )?;
            #[derive(serde::Deserialize)]
            struct CountRow {
                n: i64,
            }
            let remaining: Vec<CountRow> = db
                .exec(
                    "SELECT COUNT(*) AS n FROM hold_leases WHERE hold_id = ?1",
                    vec![parent_hold_id.clone().into()],
                )?
                .to_array()?;
            if remaining.first().is_some_and(|r| r.n > 0) {
                return Response::ok("");
            }
        }
        let Some(hold) = Self::peek_charge_hold(&db, &parent_hold_id, false)? else {
            return Response::ok("");
        };
        self.refund_and_delete_hold(&db, &parent_hold_id, hold, false)
            .await?;
        Response::ok("")
    }

    async fn credit(&self, req: CreditReq, policy: &Policy) -> Result<Response> {
        self.ensure_init(policy).await?;
        let storage = self.state.storage();
        let marker = format!("credit:{}", req.key);
        let balance: i64 = self.get_or("balance", 0).await?;
        if storage.get::<bool>(&marker).await?.is_some() {
            return json(
                &BalanceResp {
                    balance,
                    applied: false,
                },
                200,
            );
        }
        let balance = balance.saturating_add(req.points).max(0);
        self.write_fields(serde_json::json!({"balance":balance, (marker):true}))
            .await?;
        json(
            &BalanceResp {
                balance,
                applied: true,
            },
            200,
        )
    }

    /// Subscribe to / renew / switch plans. Any currently active plan is
    /// prorated: its unused remainder is refunded, and the target plan is then
    /// bought for a fresh full period. So the active period is always *at most*
    /// one plan period (30d) — clicking Subscribe repeatedly no longer stacks
    /// days — and switching (upgrade/downgrade/renew) only charges the
    /// difference net of the refund. A pure renew (same plan) costs ~0 net.
    async fn subscribe(&self, req: SubscribeReq, policy: &Policy) -> Result<Response> {
        if self.get_or("banned", false).await? || self.get_or("suspended", false).await? {
            return Response::error("account banned or suspended", 403);
        }
        let Some(target) = policy.plan(&req.plan) else {
            return Response::error("unknown plan", 400);
        };
        if req
            .expected_price
            .is_some_and(|price| price != target.price_points)
        {
            return Response::error(
                "Plan price changed. Reload your account to review the current price.",
                409,
            );
        }
        let storage = self.state.storage();
        let now = now_secs();
        // Force-reclaim any expired uncommitted holds before checking balance for a
        // subscription purchase so stale holds never cause spurious 402s (Cycle 3 H4).
        self.reclaim_expired_holds(now as i64, true).await?;
        let current: Option<String> = storage.get("plan").await?;
        let period_end: u64 = self.get_or("period_end", 0).await?;

        let refund = self.refund(current.as_deref(), period_end, now).await?;
        let refund_paid = self
            .refund_paid_only(current.as_deref(), period_end, now)
            .await?;

        let balance: i64 = self.get_or("balance", 0).await?;
        // Net cost of the switch: full target price offset by the refund. May be
        // negative when downgrading (the user is credited the difference).
        let net_cost = target.price_points - refund;
        if net_cost > 0 && balance < net_cost {
            return Response::error("insufficient balance", 402);
        }
        let tracked_free: Option<i64> = storage.get("free_balance").await?;
        let (new_balance, next_free, new_plan_paid_real) = match tracked_free {
            Some(fb) => {
                let (nb, nf, pr) =
                    subscribe_split_funding(balance, fb, refund, refund_paid, target.price_points);
                (nb, Some(nf), Some(pr))
            }
            None => (balance.saturating_sub(net_cost).max(0), None, None),
        };
        // Always a fresh full period from now — never stacks past one period.
        let new_end = now + target.period_secs;

        let mut fields = serde_json::json!({
            "balance": new_balance,
            "plan": target.id,
            "plan_paid": target.price_points,
        });
        if let Some(nf) = next_free {
            fields["free_balance"] = nf.into();
        }
        if let Some(pr) = new_plan_paid_real {
            fields["plan_paid_real"] = pr.into();
        }
        self.write_plan(fields, new_end, now).await?;
        json(&self.status_resp(policy).await?, 200)
    }

    /// Cancel the active plan, refunding the unused (prorated) remainder to the
    /// PAYG balance and lapsing to pay-as-you-go immediately. Idempotent: with
    /// no active plan it just clears any stale state and returns 200.
    async fn unsubscribe(&self, policy: &Policy) -> Result<Response> {
        if self.get_or("banned", false).await? || self.get_or("suspended", false).await? {
            return Response::error("account banned or suspended", 403);
        }
        let storage = self.state.storage();
        let now = now_secs();
        // Force-reclaim any expired uncommitted holds so the returned balance is up to date.
        self.reclaim_expired_holds(now as i64, true).await?;
        let current: Option<String> = storage.get("plan").await?;
        let period_end: u64 = self.get_or("period_end", 0).await?;

        let refund = self.refund(current.as_deref(), period_end, now).await?;
        let refund_paid = self
            .refund_paid_only(current.as_deref(), period_end, now)
            .await?;
        let balance: i64 = self.get_or("balance", 0).await?;
        let new_balance = balance.saturating_add(refund);
        let mut fields = serde_json::json!({
            "balance": new_balance,
            "plan_paid": 0,
            "plan_paid_real": 0,
        });
        if let Some(fb) = storage.get::<i64>("free_balance").await? {
            let refund_free = refund.saturating_sub(refund_paid).max(0);
            fields["free_balance"] = fb.saturating_add(refund_free).min(new_balance).into();
        }
        self.write_plan(fields, 0, now).await?;
        json(&self.status_resp(policy).await?, 200)
    }

    async fn compute_account_credit_breakdown(
        &self,
        policy: &Policy,
        legacy_paid_deposits: i64,
        now: u64,
    ) -> Result<(Option<String>, u64, MergeCreditBreakdown)> {
        let storage = self.state.storage();
        let initialized = storage.get::<bool>("init").await?.is_some();
        let balance: i64 = self.get_or("balance", 0).await?;
        let tracked_free: Option<i64> = storage.get("free_balance").await?;
        let merged_paid_in: i64 = self.get_or("merged_paid_in", 0).await?;
        let plan_id: Option<String> = storage.get("plan").await?;
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active_plan = plan_id
            .as_deref()
            .filter(|_| period_end > now)
            .and_then(|id| config::plan(id));
        let (plan_active, plan_paid, tracked_plan_paid_real, period_secs, remaining_secs) =
            if let Some(plan) = active_plan {
                let paid: i64 = self.get_or("plan_paid", plan.price_points).await?;
                let paid_real: Option<i64> = storage.get("plan_paid_real").await?;
                (
                    true,
                    paid,
                    paid_real,
                    plan.period_secs,
                    period_end.saturating_sub(now),
                )
            } else {
                (false, 0, None, 0, 0)
            };
        let legacy_paid_total = legacy_paid_deposits.max(0).saturating_add(merged_paid_in.max(0));
        let credits = compute_merge_credit_breakdown(
            initialized,
            balance,
            tracked_free,
            policy.signup_points,
            legacy_paid_total,
            plan_active,
            plan_paid,
            tracked_plan_paid_real,
            period_secs,
            remaining_secs,
        );
        Ok((
            plan_id.filter(|_| period_end > now),
            if period_end > now { period_end } else { 0 },
            credits,
        ))
    }

    async fn merge_preview(&self, req: MergePreviewDoReq, policy: &Policy) -> Result<Response> {
        let now = now_secs();
        let _ = self.reclaim_expired_holds(now as i64, false).await;
        let banned = self.get_or("banned", false).await?;
        let suspended = self.get_or("suspended", false).await?;
        let merged_into: Option<String> = self.state.storage().get("merged_into").await?;
        let total_views: i64 = self.get_or("total_views", 0).await?;
        let (plan, period_end, credits) = self
            .compute_account_credit_breakdown(policy, req.legacy_paid_deposits, now)
            .await?;
        json(
            &MergePreviewDoResp {
                balance: credits.balance,
                plan,
                period_end,
                total_views,
                banned,
                suspended,
                merged_into,
                credits,
            },
            200,
        )
    }

    /// Atomically freeze & drain an abandoned account during fusion.
    /// Idempotent per `merge_id` so crash/retry can safely finish crediting the preserved DO.
    async fn merge_drain(&self, req: MergeDrainDoReq, policy: &Policy) -> Result<Response> {
        let storage = self.state.storage();
        if let Some(prev) = storage.get::<MergeDrainDoResp>("merge_drain").await? {
            if prev.merge_id == req.merge_id {
                return json(&prev, 200);
            }
            return Response::error("account was already merged", 409);
        }
        if self.get_or("banned", false).await? {
            return Response::error("banned account cannot be merged", 403);
        }
        if self.get_or("suspended", false).await?
            || storage.get::<String>("merged_into").await?.is_some()
        {
            return Response::error("suspended or merged account cannot be merged", 409);
        }

        let now = now_secs();
        self.reclaim_expired_holds(now as i64, true).await?;
        let total_views: i64 = self.get_or("total_views", 0).await?;
        let (_, _, credits) = self
            .compute_account_credit_breakdown(policy, req.legacy_paid_deposits, now)
            .await?;

        let resp = MergeDrainDoResp {
            merge_id: req.merge_id.clone(),
            credits,
            total_views_transferred: total_views.max(0),
        };
        self.write_fields(serde_json::json!({
            "balance": 0,
            "free_balance": 0,
            "period_end": 0,
            "plan_paid": 0,
            "plan_paid_real": 0,
            "suspended": true,
            "merged_into": req.preserved_do_key,
            "merge_drain": resp,
        }))
        .await?;
        let _ = storage.delete("plan").await;
        let _ = storage.delete_alarm().await;
        // Immediately revoke ALL active revocable sessions AND legacy cutover cookies.
        let _ = self.revoke_all_sessions_internal(&SessionRevokeAllReq {
            invalidate_legacy: true,
            ..SessionRevokeAllReq::default()
        })?;
        json(&resp, 200)
    }

    /// Idempotently credit paid points + total views from a drained account into the preserved account.
    async fn merge_receive(&self, req: MergeReceiveDoReq, policy: &Policy) -> Result<Response> {
        if self.get_or("banned", false).await? || self.get_or("suspended", false).await? {
            return Response::error("preserved account is banned or suspended", 403);
        }
        self.ensure_init(policy).await?;
        let storage = self.state.storage();
        let marker = format!("merge_in:{}", req.merge_id);
        let balance: i64 = self.get_or("balance", 0).await?;
        let total_views: i64 = self.get_or("total_views", 0).await?;
        if storage.get::<bool>(&marker).await?.is_some() {
            return json(
                &MergeReceiveDoResp {
                    balance,
                    total_views,
                    applied: false,
                },
                200,
            );
        }
        let add_points = req.paid_points.max(0);
        let add_views = req.total_views.max(0);
        let next_balance = balance.saturating_add(add_points);
        let next_views = total_views.saturating_add(add_views);
        let merged_paid_in: i64 = self.get_or("merged_paid_in", 0).await?;
        self.write_fields(serde_json::json!({
            "balance": next_balance,
            "total_views": next_views,
            "merged_paid_in": merged_paid_in.saturating_add(add_points),
            (marker): true,
        }))
        .await?;
        json(
            &MergeReceiveDoResp {
                balance: next_balance,
                total_views: next_views,
                applied: true,
            },
            200,
        )
    }

    async fn ban(&self, req: BanReq, policy: &Policy) -> Result<Response> {
        self.state.storage().put("banned", req.banned).await?;
        if req.banned {
            // Immediately revoke ALL active revocable `v2` sessions on ban (H8).
            let _ = self.revoke_all_sessions_internal(&SessionRevokeAllReq::default())?;
        }
        json(&self.status_resp(policy).await?, 200)
    }

    // -----------------------------------------------------------------------
    // Revocable `v2` sessions, content safety prefs, Terms & Preview Budget
    // -----------------------------------------------------------------------

    fn ensure_session_tables(&self, now: i64) -> Result<worker::SqlStorage> {
        let db = self.state.storage().sql();
        if !self.sessions_schema_ready.get() {
            db.exec(
                "CREATE TABLE IF NOT EXISTS sessions (\
                    sid TEXT PRIMARY KEY,\
                    auth_method TEXT NOT NULL,\
                    identity_key TEXT NOT NULL,\
                    assurance_level TEXT NOT NULL,\
                    strict_age_ok INTEGER NOT NULL DEFAULT 0,\
                    created_at INTEGER NOT NULL,\
                    expires_at INTEGER NOT NULL,\
                    revoked_at INTEGER\
                )",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at)",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_sessions_ident ON sessions(identity_key)",
                None,
            )?;
            db.exec(
                "CREATE TABLE IF NOT EXISTS user_safety_state (\
                    id INTEGER PRIMARY KEY CHECK (id = 1),\
                    enabled_switchers_json TEXT NOT NULL DEFAULT '[]',\
                    safe_mode INTEGER NOT NULL DEFAULT 0,\
                    pref_version INTEGER NOT NULL DEFAULT 1,\
                    terms_version INTEGER,\
                    terms_digest TEXT,\
                    terms_accepted_at INTEGER,\
                    self_attested_18 INTEGER NOT NULL DEFAULT 0,\
                    revoked_all_before INTEGER NOT NULL DEFAULT 0\
                )",
                None,
            )?;
            // Upgrade pre-v3 DOs that created `user_safety_state` before `pref_version` existed.
            #[derive(serde::Deserialize)]
            struct ColInfo {
                name: String,
            }
            let cols: Vec<ColInfo> = db
                .exec("PRAGMA table_info(user_safety_state)", None)?
                .to_array()?;
            if !cols.iter().any(|c| c.name == "pref_version") {
                db.exec(
                    "ALTER TABLE user_safety_state ADD COLUMN pref_version INTEGER NOT NULL DEFAULT 1",
                    None,
                )?;
            }
            db.exec(
                "CREATE TABLE IF NOT EXISTS preview_budget (\
                    window_start INTEGER NOT NULL,\
                    item_key TEXT NOT NULL,\
                    hits INTEGER NOT NULL DEFAULT 1,\
                    PRIMARY KEY (window_start, item_key)\
                ) WITHOUT ROWID",
                None,
            )?;
            let pcols: Vec<ColInfo> = db
                .exec("PRAGMA table_info(preview_budget)", None)?
                .to_array()?;
            if !pcols.iter().any(|c| c.name == "hits") {
                db.exec(
                    "ALTER TABLE preview_budget ADD COLUMN hits INTEGER NOT NULL DEFAULT 1",
                    None,
                )?;
            }
            self.sessions_schema_ready.set(true);
        }
        if now.saturating_sub(self.sessions_last_purge.get()) >= 300 {
            let _ = db.exec(
                "DELETE FROM sessions WHERE expires_at <= ?1",
                vec![(now.saturating_sub(3600)).into()],
            );
            let current_window = now / PREVIEW_BUDGET_WINDOW_SECS;
            let _ = db.exec(
                "DELETE FROM preview_budget WHERE window_start < ?1",
                vec![current_window.into()],
            );
            self.sessions_last_purge.set(now);
        }
        Ok(db)
    }

    fn read_safety_state(&self, db: &worker::SqlStorage) -> Result<StoredSafetyState> {
        #[derive(serde::Deserialize)]
        struct Row {
            enabled_switchers_json: String,
            safe_mode: i64,
            pref_version: i64,
            terms_version: Option<i64>,
            terms_digest: Option<String>,
            self_attested_18: i64,
            revoked_all_before: i64,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT enabled_switchers_json, safe_mode, pref_version, terms_version, terms_digest, \
                 self_attested_18, revoked_all_before FROM user_safety_state WHERE id = 1",
                None,
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(StoredSafetyState::default());
        };
        let raw = RawStoredSafetyRow {
            enabled_switchers: parse_stored_policy_refs(&row.enabled_switchers_json),
            legacy_safe_mode: row.safe_mode != 0,
            pref_version: row.pref_version.max(1) as u64,
            terms_version: row.terms_version.and_then(|v| u32::try_from(v).ok()),
            terms_digest: row.terms_digest,
            self_attested_18: row.self_attested_18 != 0,
            revoked_all_before: row.revoked_all_before.max(0) as u64,
        };
        let (migrated, needs_persist) = migrate_legacy_safe_mode_on_load(raw);
        if needs_persist {
            // Cold-load legacy Safe Mode wipe migration (Codex MEDIUM #6):
            // persist cleared `enabled_switchers = []`, `safe_mode = 0`, and incremented
            // `pref_version` immediately BEFORE serving any `SessionContext`!
            db.exec(
                "UPDATE user_safety_state \
                 SET enabled_switchers_json = '[]', safe_mode = 0, pref_version = ?1 \
                 WHERE id = 1",
                vec![(migrated.pref_version as i64).into()],
            )?;
        }
        Ok(migrated)
    }

    async fn session_context(&self, req: SessionContextReq) -> Result<Response> {
        let now = now_secs();
        let banned = self.get_or("banned", false).await?;
        let suspended = self.get_or("suspended", false).await?;
        let db = self.ensure_session_tables(now as i64)?;
        let safety = self.read_safety_state(&db)?;

        let session_row = if let Some(sid) = req.sid.as_deref() {
            #[derive(serde::Deserialize)]
            struct SRow {
                assurance_level: String,
                strict_age_ok: i64,
                expires_at: i64,
                revoked_at: Option<i64>,
            }
            let rows: Vec<SRow> = db
                .exec(
                    "SELECT assurance_level, strict_age_ok, expires_at, revoked_at \
                     FROM sessions WHERE sid = ?1",
                    vec![sid.into()],
                )?
                .to_array()?;
            rows.into_iter().next().map(|r| StoredSessionSnapshot {
                assurance_level: assurance_from_str(&r.assurance_level),
                strict_age_ok: r.strict_age_ok != 0,
                expires_at: r.expires_at.max(0) as u64,
                revoked_at: r.revoked_at.map(|v| v.max(0) as u64),
            })
        } else {
            None
        };

        let ctx = compute_session_context(
            banned,
            suspended,
            req.sid.as_deref(),
            session_row.as_ref(),
            &safety,
            now,
        );
        json(&ctx, 200)
    }

    async fn session_issue(&self, req: SessionIssueReq) -> Result<Response> {
        if self.get_or("banned", false).await? {
            return Response::error("banned", 403);
        }
        let now = now_secs();
        let effective_created_at = req.auth_time.map_or(now, |t| t.min(now));
        let db = self.ensure_session_tables(now as i64)?;
        let strict_flag: i64 =
            if req.strict_age_ok && req.assurance_level == AssuranceLevel::Verified18 {
                1
            } else {
                0
            };
        db.exec(
            "INSERT OR REPLACE INTO sessions \
             (sid, auth_method, identity_key, assurance_level, strict_age_ok, created_at, expires_at, revoked_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
            vec![
                req.sid.clone().into(),
                req.auth_method.into(),
                req.identity_key.into(),
                assurance_to_str(req.assurance_level).into(),
                strict_flag.into(),
                (effective_created_at as i64).into(),
                (req.expires_at as i64).into(),
            ],
        )?;
        json(
            &SessionIssueResp {
                sid: req.sid,
                created_at: effective_created_at,
                expires_at: req.expires_at,
            },
            200,
        )
    }

    fn session_revoke(&self, req: SessionRevokeReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_session_tables(now)?;
        db.exec(
            "UPDATE sessions SET revoked_at = ?1 WHERE sid = ?2 AND revoked_at IS NULL",
            vec![now.into(), req.sid.into()],
        )?;
        Response::ok("")
    }

    fn revoke_all_sessions_internal(&self, req: &SessionRevokeAllReq) -> Result<u64> {
        let now = now_secs() as i64;
        let legacy_cutoff = now.max(1);
        let db = self.ensure_session_tables(now)?;
        #[derive(serde::Deserialize)]
        struct CountRow {
            n: i64,
        }
        #[derive(serde::Deserialize)]
        struct LegacyRow {
            revoked_all_before: i64,
        }
        let mut count: u64 = 0;
        let has_selective = is_selective_revoke(req);

        if !has_selective {
            let c: Vec<CountRow> = db
                .exec(
                    "SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL",
                    None,
                )?
                .to_array()?;
            db.exec(
                "UPDATE sessions SET revoked_at = ?1 WHERE revoked_at IS NULL",
                vec![now.into()],
            )?;
            // Also invalidate any legacy cutover sessions that lack a `sid`.
            let prior: Vec<LegacyRow> = db
                .exec(
                    "SELECT revoked_all_before FROM user_safety_state WHERE id = 1",
                    None,
                )?
                .to_array()?;
            let legacy_was_active = prior
                .first()
                .is_none_or(|r| r.revoked_all_before == 0);
            db.exec(
                "INSERT INTO user_safety_state (id, revoked_all_before) VALUES (1, ?1) \
                 ON CONFLICT(id) DO UPDATE SET \
                    revoked_all_before = MAX(user_safety_state.revoked_all_before, excluded.revoked_all_before)",
                vec![legacy_cutoff.into()],
            )?;
            count = c.first().map_or(0, |r| r.n.max(0) as u64);
            if legacy_was_active && count == 0 {
                count = 1;
            }
        } else {
            // Apply all requested selective revocations atomically in one DO turn (Cycle 2 B-2 / Cycle 3 H3).
            if let Some(ident) = req.identity_key.as_deref() {
                let c: Vec<CountRow> = db
                    .exec(
                        "SELECT COUNT(*) AS n FROM sessions WHERE identity_key = ?1 AND revoked_at IS NULL",
                        vec![ident.into()],
                    )?
                    .to_array()?;
                db.exec(
                    "UPDATE sessions SET revoked_at = ?1 WHERE identity_key = ?2 AND revoked_at IS NULL",
                    vec![now.into(), ident.into()],
                )?;
                count = count.saturating_add(c.first().map_or(0, |r| r.n.max(0) as u64));
            }
            if req.strict_only {
                let c: Vec<CountRow> = db
                    .exec(
                        "SELECT COUNT(*) AS n FROM sessions WHERE strict_age_ok != 0 AND revoked_at IS NULL",
                        None,
                    )?
                    .to_array()?;
                db.exec(
                    "UPDATE sessions SET revoked_at = ?1 WHERE strict_age_ok != 0 AND revoked_at IS NULL",
                    vec![now.into()],
                )?;
                count = count.saturating_add(c.first().map_or(0, |r| r.n.max(0) as u64));
            }
            if let Some(sid) = req.revoke_sid.as_deref() {
                let c: Vec<CountRow> = db
                    .exec(
                        "SELECT COUNT(*) AS n FROM sessions WHERE sid = ?1 AND revoked_at IS NULL",
                        vec![sid.into()],
                    )?
                    .to_array()?;
                db.exec(
                    "UPDATE sessions SET revoked_at = ?1 WHERE sid = ?2 AND revoked_at IS NULL",
                    vec![now.into(), sid.into()],
                )?;
                count = count.saturating_add(c.first().map_or(0, |r| r.n.max(0) as u64));
            }
            if req.invalidate_legacy {
                let prior: Vec<LegacyRow> = db
                    .exec(
                        "SELECT revoked_all_before FROM user_safety_state WHERE id = 1",
                        None,
                    )?
                    .to_array()?;
                let legacy_was_active = prior
                    .first()
                    .is_none_or(|r| r.revoked_all_before == 0);
                db.exec(
                    "INSERT INTO user_safety_state (id, revoked_all_before) VALUES (1, ?1) \
                     ON CONFLICT(id) DO UPDATE SET \
                        revoked_all_before = MAX(user_safety_state.revoked_all_before, excluded.revoked_all_before)",
                    vec![legacy_cutoff.into()],
                )?;
                if legacy_was_active {
                    count = count.saturating_add(1);
                }
            }
        }
        Ok(count)
    }

    fn session_revoke_all(&self, req: SessionRevokeAllReq) -> Result<Response> {
        let revoked = self.revoke_all_sessions_internal(&req)?;
        json(&SessionRevokeAllResp { revoked }, 200)
    }

    fn session_info(&self, req: SessionRevokeReq) -> Result<Response> {
        let now = now_secs();
        let db = self.ensure_session_tables(now as i64)?;
        #[derive(serde::Deserialize)]
        struct SRow {
            sid: String,
            auth_method: String,
            identity_key: String,
            assurance_level: String,
            strict_age_ok: i64,
            created_at: i64,
            expires_at: i64,
            revoked_at: Option<i64>,
        }
        let rows: Vec<SRow> = db
            .exec(
                "SELECT sid, auth_method, identity_key, assurance_level, strict_age_ok, \
                 created_at, expires_at, revoked_at FROM sessions WHERE sid = ?1",
                vec![req.sid.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Response::error("session not found", 404);
        };
        let active = row.revoked_at.is_none() && (row.expires_at.max(0) as u64) > now;
        json(
            &SessionInfoResp {
                sid: row.sid,
                auth_method: row.auth_method,
                identity_key: row.identity_key,
                assurance_level: assurance_from_str(&row.assurance_level),
                strict_age_ok: row.strict_age_ok != 0,
                created_at: row.created_at.max(0) as u64,
                expires_at: row.expires_at.max(0) as u64,
                active,
            },
            200,
        )
    }

    async fn prefs_update(&self, req: PrefsUpdateReq) -> Result<Response> {
        for pref in &req.enabled_switchers {
            if let Err(e) = pref.validate() {
                return Response::error(format!("invalid switcher ref: {e}"), 400);
            }
        }
        let now = now_secs();
        let db = self.ensure_session_tables(now as i64)?;
        let current = self.read_safety_state(&db)?;
        let next = match apply_prefs_update(
            &current,
            req.enabled_switchers,
            req.expected_pref_version,
        ) {
            PrefsUpdateOutcome::Updated(n) => n,
            PrefsUpdateOutcome::VersionConflict { current } => {
                return json(
                    &DoPrefsConflictResp {
                        error: "Preferences were updated in another tab; refreshed to latest state."
                            .to_string(),
                        pref_version: current.pref_version,
                        enabled_switchers: current.enabled_switchers,
                    },
                    409,
                );
            }
        };
        let sw_json = serde_json::to_string(&next.enabled_switchers)
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        db.exec(
            "INSERT INTO user_safety_state (id, enabled_switchers_json, safe_mode, pref_version) \
             VALUES (1, ?1, 0, ?2) \
             ON CONFLICT(id) DO UPDATE SET \
                enabled_switchers_json = excluded.enabled_switchers_json, \
                safe_mode = 0, \
                pref_version = excluded.pref_version",
            vec![sw_json.into(), (next.pref_version as i64).into()],
        )?;
        let banned = self.get_or("banned", false).await?;
        let suspended = self.get_or("suspended", false).await?;
        let safety = self.read_safety_state(&db)?;
        let ctx = compute_session_context(banned, suspended, None, None, &safety, now);
        json(&ctx, 200)
    }

    fn terms_accept(&self, req: TermsAcceptReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_session_tables(now)?;
        let self_attest_flag: i64 = if req.self_attestation == Some(true) {
            1
        } else {
            0
        };
        db.exec(
            "INSERT INTO user_safety_state \
             (id, terms_version, terms_digest, terms_accepted_at, self_attested_18) \
             VALUES (1, ?1, ?2, ?3, ?4) \
             ON CONFLICT(id) DO UPDATE SET \
                terms_version = excluded.terms_version, \
                terms_digest = excluded.terms_digest, \
                terms_accepted_at = excluded.terms_accepted_at, \
                self_attested_18 = MAX(user_safety_state.self_attested_18, excluded.self_attested_18)",
            vec![
                i64::from(req.terms_version).into(),
                req.terms_digest.into(),
                (req.accepted_at as i64).into(),
                self_attest_flag.into(),
            ],
        )?;
        if req.self_attestation == Some(true)
            && let Some(sid) = req.sid.as_deref()
        {
            // Self-attestation upgrades `none` -> `self_attestation` ONLY (NEVER `verified_18`!).
            db.exec(
                "UPDATE sessions SET assurance_level = 'self_attestation' \
                 WHERE sid = ?1 AND assurance_level = 'none'",
                vec![sid.into()],
            )?;
        }
        Response::ok("")
    }

    /// Record standalone 18+ self-attestation without modifying Terms acceptance state.
    fn age_confirm(&self, req: AgeConfirmReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_session_tables(now)?;
        let _ = self.read_safety_state(&db)?;
        db.exec(
            "INSERT INTO user_safety_state (id, self_attested_18) \
             VALUES (1, 1) \
             ON CONFLICT(id) DO UPDATE SET self_attested_18 = 1",
            None,
        )?;
        if let Some(sid) = req.sid.as_deref() {
            // Self-attestation upgrades `none` -> `self_attestation` ONLY (NEVER `verified_18`!).
            db.exec(
                "UPDATE sessions SET assurance_level = 'self_attestation' \
                 WHERE sid = ?1 AND assurance_level = 'none'",
                vec![sid.into()],
            )?;
        }
        Response::ok("")
    }

    /// Separate preview transform rate budget — NEVER touches clear-view `balance`,
    /// `seen:{day}`, `free_usage`, `charge_holds`, `win_views`, or `total_views` (M1)!
    /// Enforces `policy.login_required` for guests (Cycle 2 A-3).
    async fn preview_budget(&self, req: PreviewBudgetReq, policy: &Policy) -> Result<Response> {
        if req.guest && policy.login_required {
            return Response::error("Login required", 401);
        }
        if !req.guest && self.get_or("banned", false).await? {
            return Response::error("banned", 403);
        }
        let now = now_secs() as i64;
        let db = self.ensure_session_tables(now)?;
        let window_start = now / PREVIEW_BUDGET_WINDOW_SECS;
        let retry_after = ((window_start + 1) * PREVIEW_BUDGET_WINDOW_SECS - now).max(1) as u64;
        let item_key = if req.key.trim().is_empty() {
            format!("preview:anon:{now}")
        } else {
            req.key
        };

        #[derive(serde::Deserialize)]
        struct Stats {
            item_hits: i64,
            unique_cnt: i64,
            total_hits: i64,
        }
        let stats: Stats = db
            .exec(
                "SELECT \
                    COALESCE((SELECT hits FROM preview_budget WHERE window_start = ?1 AND item_key = ?2), 0) AS item_hits, \
                    COUNT(*) AS unique_cnt, \
                    COALESCE(SUM(hits), 0) AS total_hits \
                 FROM preview_budget WHERE window_start = ?1",
                vec![window_start.into(), item_key.clone().into()],
            )?
            .one()?;

        let item_hits = stats.item_hits.max(0) as u32;
        let unique_count = stats.unique_cnt.max(0) as u32;
        let total_hits = stats.total_hits.max(0) as u32;
        let limit = if req.guest {
            PREVIEW_BUDGET_MAX_PER_WINDOW / 2
        } else {
            PREVIEW_BUDGET_MAX_PER_WINDOW
        };
        let (allowed, remaining) = decide_preview_budget(
            item_hits,
            unique_count,
            total_hits,
            limit,
            PREVIEW_ITEM_MAX_HITS_PER_WINDOW,
        );
        if !allowed {
            return json(
                &PreviewBudgetResp {
                    allowed: false,
                    remaining: 0,
                    retry_after_secs: retry_after,
                },
                429,
            );
        }
        if !req.head {
            db.exec(
                "INSERT INTO preview_budget (window_start, item_key, hits) VALUES (?1, ?2, 1) \
                 ON CONFLICT(window_start, item_key) DO UPDATE SET hits = hits + 1",
                vec![window_start.into(), item_key.into()],
            )?;
        }
        json(
            &PreviewBudgetResp {
                allowed: true,
                remaining,
                retry_after_secs: retry_after,
            },
            200,
        )
    }

    // -----------------------------------------------------------------------
    // Strongly-consistent auth handoff & cross-device transfer (DO SQLite)
    // -----------------------------------------------------------------------

    fn ensure_handoff_tables(&self, now: i64) -> Result<worker::SqlStorage> {
        let db = self.state.storage().sql();
        if !self.handoff_schema_ready.get() {
            db.exec(
                "CREATE TABLE IF NOT EXISTS handoff_sessions_v2 (\
                    session_id TEXT PRIMARY KEY,\
                    poll_secret_hash TEXT NOT NULL,\
                    verify_code TEXT NOT NULL,\
                    approve_nonce TEXT NOT NULL,\
                    status TEXT NOT NULL,\
                    principal TEXT,\
                    created_at INTEGER NOT NULL,\
                    expires_at INTEGER NOT NULL\
                )",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_handoff_exp ON handoff_sessions_v2(expires_at)",
                None,
            )?;
            db.exec(
                "CREATE TABLE IF NOT EXISTS transfer_codes (\
                    id INTEGER PRIMARY KEY AUTOINCREMENT,\
                    owner_id TEXT NOT NULL DEFAULT '',\
                    principal TEXT NOT NULL,\
                    code_hash TEXT NOT NULL UNIQUE,\
                    token_hash TEXT NOT NULL UNIQUE,\
                    expires_at INTEGER NOT NULL\
                )",
                None,
            )?;
            #[derive(serde::Deserialize)]
            struct TransferCol {
                name: String,
            }
            let tcols: Vec<TransferCol> = db
                .exec("PRAGMA table_info(transfer_codes)", None)?
                .to_array()?;
            if !tcols.iter().any(|c| c.name == "owner_id") {
                db.exec(
                    "ALTER TABLE transfer_codes ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''",
                    None,
                )?;
            }
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_transfer_exp ON transfer_codes(expires_at)",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_transfer_principal ON transfer_codes(principal)",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_transfer_owner ON transfer_codes(owner_id)",
                None,
            )?;
            db.exec(
                "CREATE TABLE IF NOT EXISTS auth_rate_limits (\
                    bucket TEXT PRIMARY KEY,\
                    count INTEGER NOT NULL,\
                    window_end INTEGER NOT NULL\
                )",
                None,
            )?;
            db.exec(
                "CREATE INDEX IF NOT EXISTS idx_rl_exp ON auth_rate_limits(window_end)",
                None,
            )?;
            self.handoff_schema_ready.set(true);
        }
        // Throttle expired-row sweeps to once per 60s so 2s polls avoid write amplification.
        if now.saturating_sub(self.handoff_last_purge.get()) >= 60 {
            db.exec(
                "DELETE FROM handoff_sessions_v2 WHERE expires_at <= ?",
                vec![now.into()],
            )?;
            db.exec(
                "DELETE FROM transfer_codes WHERE expires_at <= ?",
                vec![now.into()],
            )?;
            db.exec(
                "DELETE FROM auth_rate_limits WHERE window_end <= ?",
                vec![now.into()],
            )?;
            self.handoff_last_purge.set(now);
        }
        Ok(db)
    }

    fn rate_limit_hit(
        db: &worker::SqlStorage,
        bucket: &str,
        now: i64,
        window_secs: i64,
        max_hits: i64,
    ) -> Result<bool> {
        #[derive(serde::Deserialize)]
        struct Row {
            count: i64,
        }
        let existing: Vec<Row> = db
            .exec(
                "SELECT count FROM auth_rate_limits WHERE bucket = ?1 AND window_end > ?2",
                vec![bucket.into(), now.into()],
            )?
            .to_array()?;
        let cur = existing.first().map(|r| r.count).unwrap_or(0);
        if cur >= max_hits {
            return Ok(false);
        }
        if existing.is_empty() {
            db.exec(
                "INSERT OR REPLACE INTO auth_rate_limits (bucket, count, window_end) VALUES (?1, 1, ?2)",
                vec![bucket.into(), (now + window_secs).into()],
            )?;
        } else {
            db.exec(
                "UPDATE auth_rate_limits SET count = count + 1 WHERE bucket = ?1",
                vec![bucket.into()],
            )?;
        }
        Ok(true)
    }

    fn rate_limit_blocked(
        db: &worker::SqlStorage,
        bucket: &str,
        now: i64,
        max_hits: i64,
    ) -> Result<bool> {
        #[derive(serde::Deserialize)]
        struct Row {
            count: i64,
        }
        let existing: Vec<Row> = db
            .exec(
                "SELECT count FROM auth_rate_limits WHERE bucket = ?1 AND window_end > ?2",
                vec![bucket.into(), now.into()],
            )?
            .to_array()?;
        Ok(existing.first().is_some_and(|r| r.count >= max_hits))
    }

    fn handoff_start(&self, req: crate::handoff::DoHandoffStartReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_handoff_tables(now)?;
        let bucket = format!("hs:{}", req.ip_key);
        if !Self::rate_limit_hit(&db, &bucket, now, 600, 30)? {
            return Response::error("too many sign-in attempts — wait a few minutes", 429);
        }
        db.exec(
            "INSERT INTO handoff_sessions_v2 \
             (session_id, poll_secret_hash, verify_code, approve_nonce, status, principal, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, 'pending', NULL, ?5, ?6)",
            vec![
                req.session_id.into(),
                req.poll_secret_hash.into(),
                req.verify_code.into(),
                req.approve_nonce.into(),
                now.into(),
                (req.expires_at as i64).into(),
            ],
        )?;
        Response::ok("")
    }

    fn handoff_info(&self, req: crate::handoff::DoHandoffInfoReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_handoff_tables(now)?;
        if let Some(ip_key) = req.ip_key.as_deref() {
            let bucket = format!("hi:{ip_key}");
            if !Self::rate_limit_hit(&db, &bucket, now, 600, 120)? {
                return Response::error("too many requests — wait a few minutes", 429);
            }
        }
        #[derive(serde::Deserialize)]
        struct Row {
            status: String,
            verify_code: String,
            approve_nonce: String,
            expires_at: i64,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT status, verify_code, approve_nonce, expires_at \
                 FROM handoff_sessions_v2 WHERE session_id = ?1 AND expires_at > ?2",
                vec![req.session_id.into(), now.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Response::error("sign-in session expired or not found", 410);
        };
        json(
            &crate::handoff::DoHandoffInfoResp {
                status: row.status,
                verify_code: row.verify_code,
                approve_nonce: row.approve_nonce,
                expires_at: row.expires_at.max(0) as u64,
            },
            200,
        )
    }

    fn handoff_approve(&self, req: crate::handoff::DoHandoffApproveReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_handoff_tables(now)?;
        #[derive(serde::Deserialize)]
        struct Row {
            status: String,
            approve_nonce: String,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT status, approve_nonce FROM handoff_sessions_v2 \
                 WHERE session_id = ?1 AND expires_at > ?2",
                vec![req.session_id.clone().into(), now.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Response::error("sign-in session expired or not found", 410);
        };
        if row.status != "pending" {
            return Response::error("sign-in session already approved", 409);
        }
        if !crate::handoff::ct_eq(row.approve_nonce.as_bytes(), req.approve_nonce.as_bytes()) {
            return Response::error("nonce mismatch", 401);
        }
        db.exec(
            "UPDATE handoff_sessions_v2 SET status = 'approved', principal = ?1 \
             WHERE session_id = ?2 AND status = 'pending'",
            vec![req.principal.into(), req.session_id.into()],
        )?;
        Response::ok("")
    }

    fn handoff_poll(&self, req: crate::handoff::DoHandoffPollReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_handoff_tables(now)?;
        let bucket = format!("hp:{}", req.ip_key);
        if !Self::rate_limit_hit(&db, &bucket, now, 600, 450)? {
            return Response::error("too many poll requests", 429);
        }
        #[derive(serde::Deserialize)]
        struct Row {
            poll_secret_hash: String,
            status: String,
            principal: Option<String>,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT poll_secret_hash, status, principal FROM handoff_sessions_v2 \
                 WHERE session_id = ?1 AND expires_at > ?2",
                vec![req.session_id.into(), now.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Response::error("sign-in session expired", 410);
        };
        if !crate::handoff::ct_eq(
            row.poll_secret_hash.as_bytes(),
            req.poll_secret_hash.as_bytes(),
        ) {
            return Response::error("invalid poll secret", 401);
        }
        if row.status == "approved"
            && let Some(principal) = row.principal
        {
            return json(
                &crate::handoff::DoHandoffPollResp {
                    status: "approved".to_string(),
                    principal: Some(principal),
                },
                200,
            );
        }
        json(
            &crate::handoff::DoHandoffPollResp {
                status: "pending".to_string(),
                principal: None,
            },
            200,
        )
    }

    fn handoff_consume(&self, req: crate::handoff::DoHandoffPollReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_handoff_tables(now)?;
        #[derive(serde::Deserialize)]
        struct Row {
            poll_secret_hash: String,
            status: String,
            principal: Option<String>,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT poll_secret_hash, status, principal FROM handoff_sessions_v2 \
                 WHERE session_id = ?1 AND expires_at > ?2",
                vec![req.session_id.clone().into(), now.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Response::error("sign-in session expired", 410);
        };
        if !crate::handoff::ct_eq(
            row.poll_secret_hash.as_bytes(),
            req.poll_secret_hash.as_bytes(),
        ) {
            return Response::error("invalid poll secret", 401);
        }
        if row.status != "approved" || row.principal.is_none() {
            return Response::error("sign-in session not ready", 409);
        }
        db.exec(
            "DELETE FROM handoff_sessions_v2 WHERE session_id = ?1",
            vec![req.session_id.into()],
        )?;
        json(
            &crate::handoff::DoHandoffPollResp {
                status: "approved".to_string(),
                principal: row.principal,
            },
            200,
        )
    }

    fn transfer_create(&self, req: crate::handoff::DoTransferCreateReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_handoff_tables(now)?;
        let owner = req
            .owner_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&req.principal)
            .to_string();
        let bucket = format!("tc:{owner}");
        if !Self::rate_limit_hit(&db, &bucket, now, 600, 15)? {
            return Response::error("too many codes generated — wait a few minutes", 429);
        }
        // Keep at most one active code per user across ALL sessions so regenerating
        // from any browser immediately revokes the old one (Cycle 2 B-4).
        db.exec(
            "DELETE FROM transfer_codes WHERE owner_id = ?1 OR principal = ?2",
            vec![owner.clone().into(), req.principal.clone().into()],
        )?;
        db.exec(
            "INSERT INTO transfer_codes (owner_id, principal, code_hash, token_hash, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![
                owner.into(),
                req.principal.into(),
                req.code_hash.into(),
                req.token_hash.into(),
                (req.expires_at as i64).into(),
            ],
        )?;
        Response::ok("")
    }

    fn transfer_claim(&self, req: crate::handoff::DoTransferClaimReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_handoff_tables(now)?;
        let bucket = format!("tf:{}", req.ip_key);
        if Self::rate_limit_blocked(&db, &bucket, now, 10)? {
            return Response::error("too many failed code attempts — wait 10 minutes", 429);
        }
        #[derive(serde::Deserialize)]
        struct Row {
            id: i64,
            principal: String,
        }
        let rows: Vec<Row> = if let Some(code_hash) = req.code_hash {
            db.exec(
                "SELECT id, principal FROM transfer_codes WHERE code_hash = ?1 AND expires_at > ?2",
                vec![code_hash.into(), now.into()],
            )?
            .to_array()?
        } else if let Some(token_hash) = req.token_hash {
            db.exec(
                "SELECT id, principal FROM transfer_codes WHERE token_hash = ?1 AND expires_at > ?2",
                vec![token_hash.into(), now.into()],
            )?
            .to_array()?
        } else {
            return Response::error("missing code or token", 400);
        };

        let Some(row) = rows.into_iter().next() else {
            let _ = Self::rate_limit_hit(&db, &bucket, now, 600, 100);
            return Response::error("invalid or expired code", 401);
        };
        // Atomically consume both the short code and QR token together.
        db.exec(
            "DELETE FROM transfer_codes WHERE id = ?1",
            vec![row.id.into()],
        )?;
        json(
            &crate::handoff::DoTransferClaimResp {
                principal: row.principal,
            },
            200,
        )
    }

    fn transfer_revoke(&self, req: crate::handoff::DoTransferRevokeReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_handoff_tables(now)?;
        let owner = req
            .owner_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&req.principal);
        db.exec(
            "DELETE FROM transfer_codes WHERE owner_id = ?1 OR principal = ?2",
            vec![owner.into(), req.principal.into()],
        )?;
        Response::ok("")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_750_000_000;

    fn map(entries: &[(&str, u64)]) -> HashMap<String, u64> {
        entries.iter().map(|&(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn dedupe_hits_today_and_yesterday_within_window() {
        let today = map(&[("/images/a.webp", NOW - 10)]);
        let yesterday = map(&[("/images/b.webp", NOW - config::DEDUPE_WINDOW_SECS + 1)]);
        let empty = HashMap::new();
        assert!(is_recent_view("/images/a.webp", NOW, [&today, &empty]));
        assert!(is_recent_view("/images/b.webp", NOW, [&empty, &yesterday]));
    }

    #[test]
    fn dedupe_misses_unknown_path_and_expired_entry() {
        let yesterday = map(&[("/images/old.webp", NOW - config::DEDUPE_WINDOW_SECS)]);
        let empty = HashMap::new();
        assert!(!is_recent_view(
            "/images/new.webp",
            NOW,
            [&empty, &yesterday]
        ));
        // first_seen exactly at the cutoff is no longer free
        assert!(!is_recent_view(
            "/images/old.webp",
            NOW,
            [&empty, &yesterday]
        ));
    }

    #[test]
    fn view_costs_match_config() {
        assert_eq!(view_cost(ChargeKind::Image), config::COST_IMAGE_VIEW);
        assert_eq!(view_cost(ChargeKind::Video), config::COST_VIDEO_VIEW);
        assert_eq!(view_cost(ChargeKind::Search), config::COST_SEARCH);
        assert_eq!(
            view_cost(ChargeKind::EmbedSearch),
            config::COST_EMBED_SEARCH
        );
    }

    fn basic() -> &'static config::Plan {
        config::plan("basic").expect("basic plan")
    }
    fn pro() -> &'static config::Plan {
        config::plan("pro").expect("pro plan")
    }

    #[test]
    fn prorated_refund_matches_examples() {
        let day = 86_400u64;
        let basic_price = basic().price_points; // 20_000 over 30d
        let pro_price = pro().price_points; // 50_000 over 30d
        let period = basic().period_secs; // 30d (same for both)

        // Used 15 of 30 days of basic → 10_000 unused refund (the "off" on an upgrade).
        assert_eq!(prorated_refund(basic_price, period, 15 * day), 10_000);
        // Used 15 of 30 days of pro → 25_000 back on unsubscribe.
        assert_eq!(prorated_refund(pro_price, period, 15 * day), 25_000);
        // Boundaries: brand-new period refunds ~full; fully-spent refunds 0.
        assert_eq!(prorated_refund(pro_price, period, period), pro_price);
        assert_eq!(prorated_refund(pro_price, period, 0), 0);
        // Over-long remaining is clamped to the period (never over-refunds).
        assert_eq!(
            prorated_refund(pro_price, period, period + 999 * day),
            pro_price
        );
        // Degenerate period never divides by zero.
        assert_eq!(prorated_refund(pro_price, 0, day), 0);
    }

    #[test]
    fn should_roll_unset_or_elapsed() {
        assert!(should_roll(None, NOW));
        assert!(should_roll(Some(NOW), NOW + config::WINDOW_SECS));
        assert!(should_roll(Some(NOW), NOW + config::WINDOW_SECS + 1));
        assert!(!should_roll(Some(NOW), NOW));
        assert!(!should_roll(Some(NOW), NOW + config::WINDOW_SECS - 1));
    }

    #[test]
    fn pro_media_views_are_free_unlimited() {
        let c = view_cost(ChargeKind::Image);
        assert_eq!(
            decide_charge(Some(pro()), true, ChargeKind::Image, 0, 0, 0, c, false),
            ChargeSource::FreeUnlimited
        );
        // still free with a huge accumulated count and zero balance (even with paid media toggle OFF)
        assert_eq!(
            decide_charge(
                Some(pro()),
                true,
                ChargeKind::Video,
                1_000_000,
                0,
                0,
                c,
                false
            ),
            ChargeSource::FreeUnlimited
        );
    }

    #[test]
    fn basic_media_within_window_consumes_quota() {
        let c = view_cost(ChargeKind::Image);
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Image, 0, 0, 0, c, false),
            ChargeSource::Window
        );
        // exactly at the limit boundary (limit - cost) still fits even with paid media toggle OFF
        let limit = basic().views_per_window.unwrap();
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::Image,
                limit - c,
                0,
                0,
                c,
                false
            ),
            ChargeSource::Window
        );
    }

    #[test]
    fn basic_media_exhausted_falls_back_to_balance_then_refuses() {
        let c = view_cost(ChargeKind::Video);
        let limit = basic().views_per_window.unwrap();
        // window full + paid media toggle OFF: refuse even with ample balance
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::Video,
                limit,
                0,
                100,
                c,
                false
            ),
            ChargeSource::Refuse
        );
        // window full + paid media toggle ON: fall back to PAYG when the balance covers it
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::Video,
                limit,
                0,
                100,
                c,
                true
            ),
            ChargeSource::Balance
        );
        // window full AND broke: refuse even when toggle ON
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::Video,
                limit,
                0,
                c - 1,
                c,
                true
            ),
            ChargeSource::Refuse
        );
    }

    #[test]
    fn search_uses_window_then_payg() {
        let c = view_cost(ChargeKind::Search);
        let limit = basic().searches_per_window;
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Search, 0, 0, 0, c, false),
            ChargeSource::Window
        );
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::Search,
                0,
                limit - 1,
                0,
                c,
                false
            ),
            ChargeSource::Window
        );
        // window searches exhausted: PAYG if funded, else refuse
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::Search,
                0,
                limit,
                c,
                c,
                false
            ),
            ChargeSource::Balance
        );
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::Search,
                0,
                limit,
                c - 1,
                c,
                false
            ),
            ChargeSource::Refuse
        );
    }

    #[test]
    fn embed_search_is_view_class_not_search_quota() {
        let c = view_cost(ChargeKind::EmbedSearch);
        assert_eq!(c, config::COST_EMBED_SEARCH);
        // cheaper than the inference search
        assert!(c < view_cost(ChargeKind::Search));
        // pro's unlimited views cover it for free (does not touch search quota)
        assert_eq!(
            decide_charge(
                Some(pro()),
                true,
                ChargeKind::EmbedSearch,
                0,
                pro().searches_per_window,
                0,
                c,
                false
            ),
            ChargeSource::FreeUnlimited
        );
        // basic draws it from the VIEW window (win_views), regardless of search usage
        let vlimit = basic().views_per_window.unwrap();
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::EmbedSearch,
                vlimit - c,
                basic().searches_per_window,
                0,
                c,
                false
            ),
            ChargeSource::Window
        );
        // view window exhausted → PAYG, even though search slots remain
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::EmbedSearch,
                vlimit,
                0,
                c,
                c,
                false
            ),
            ChargeSource::Balance
        );
    }

    #[test]
    fn no_plan_is_payg_for_all_kinds() {
        for kind in [
            ChargeKind::Image,
            ChargeKind::Video,
            ChargeKind::Search,
            ChargeKind::EmbedSearch,
        ] {
            let c = view_cost(kind);
            assert_eq!(
                decide_charge(None, false, kind, 0, 0, c, c, true),
                ChargeSource::Balance
            );
            assert_eq!(
                decide_charge(None, false, kind, 0, 0, c - 1, c, true),
                ChargeSource::Refuse
            );
        }
        // an inactive plan behaves like no plan (when paid media opt-in is enabled)
        assert_eq!(
            decide_charge(Some(basic()), false, ChargeKind::Image, 0, 0, 1, 1, true),
            ChargeSource::Balance
        );
    }

    #[test]
    fn paid_media_toggle_gates_payg_image_and_video_loads() {
        // OFF (default): images & videos MUST NOT deduct from balance after quota runs out
        for kind in [ChargeKind::Image, ChargeKind::Video] {
            let c = view_cost(kind);
            assert_eq!(
                decide_charge(None, false, kind, 0, 0, 10_000, c, false),
                ChargeSource::Refuse
            );
            assert_eq!(
                decide_charge(Some(basic()), false, kind, 0, 0, 10_000, c, false),
                ChargeSource::Refuse
            );
            // ON: images & videos spend credits from balance when sufficient
            assert_eq!(
                decide_charge(None, false, kind, 0, 0, 10_000, c, true),
                ChargeSource::Balance
            );
        }
        // Explicit searches still draw from balance when funded regardless of media toggle
        for kind in [ChargeKind::Search, ChargeKind::Description] {
            let c = view_cost(kind);
            assert_eq!(
                decide_charge(None, false, kind, 0, 0, 10_000, c, false),
                ChargeSource::Balance
            );
        }
    }

    #[test]
    fn remaining_reflects_plan_and_usage() {
        // no active plan → None
        assert_eq!(views_remaining(None, false, 0), None);
        assert_eq!(searches_remaining(None, false, 0), None);
        // pro views unlimited → None; searches still counted
        assert_eq!(views_remaining(Some(pro()), true, 5), None);
        assert_eq!(
            searches_remaining(Some(pro()), true, 3),
            Some(pro().searches_per_window - 3)
        );
        // basic clamps at zero, never negative
        let vlimit = basic().views_per_window.unwrap();
        assert_eq!(
            views_remaining(Some(basic()), true, 100),
            Some(vlimit - 100)
        );
        assert_eq!(views_remaining(Some(basic()), true, vlimit + 50), Some(0));
        assert_eq!(
            searches_remaining(Some(basic()), true, basic().searches_per_window + 5),
            Some(0)
        );
    }

    #[test]
    fn window_reset_zero_unless_active_and_open() {
        assert_eq!(window_reset(false, Some(NOW), NOW), 0);
        assert_eq!(window_reset(true, None, NOW), 0);
        assert_eq!(
            window_reset(true, Some(NOW), NOW),
            NOW + config::WINDOW_SECS
        );
        // elapsed window is no longer open
        assert_eq!(window_reset(true, Some(NOW), NOW + config::WINDOW_SECS), 0);
    }

    #[test]
    fn refund_window_counters_restores_matching_window_and_clamps() {
        // Matching window: search-class kinds decrement win_search by 1.
        assert_eq!(
            refund_window_counters("description", 100, Some(NOW), NOW as i64, 50, 3),
            Some((50, 2))
        );
        assert_eq!(
            refund_window_counters("upload", 100, Some(NOW), NOW as i64, 50, 0),
            Some((50, 0))
        );
        // Matching window: view-class kinds decrement win_views by cost, clamped >= 0.
        assert_eq!(
            refund_window_counters("similar", 10, Some(NOW), NOW as i64, 25, 2),
            Some((15, 2))
        );
        assert_eq!(
            refund_window_counters("similar", 10, Some(NOW), NOW as i64, 5, 2),
            Some((0, 2))
        );
        // Different or missing current window: no-op.
        assert_eq!(
            refund_window_counters("description", 100, Some(NOW + 1), NOW as i64, 50, 3),
            None
        );
        assert_eq!(
            refund_window_counters("description", 100, None, NOW as i64, 50, 3),
            None
        );
    }

    #[test]
    fn session_context_enforces_revocation_ban_suspension_and_strict_age() {
        let safety = StoredSafetyState {
            enabled_switchers: vec![PolicyRef::new("r18", 2), PolicyRef::new("blood", 1)],
            pref_version: 3,
            terms_version: Some(2),
            terms_digest: Some("abcd".into()),
            self_attested_18: true,
            revoked_all_before: 0,
        };
        let active_verified = StoredSessionSnapshot {
            assurance_level: AssuranceLevel::Verified18,
            strict_age_ok: true,
            expires_at: NOW + 3600,
            revoked_at: None,
        };

        // Active verified session
        let ctx = compute_session_context(
            false,
            false,
            Some("sid1"),
            Some(&active_verified),
            &safety,
            NOW,
        );
        assert!(ctx.active && !ctx.banned && !ctx.suspended && ctx.sid_valid && ctx.strict_age_ok);
        assert_eq!(ctx.assurance_level, AssuranceLevel::Verified18);
        assert_eq!(
            ctx.enabled_switchers,
            vec![PolicyRef::new("r18", 2), PolicyRef::new("blood", 1)]
        );
        assert_eq!(ctx.pref_version, 3);

        // Revoked session immediately fails sid_valid and clears switchers
        let revoked = StoredSessionSnapshot {
            revoked_at: Some(NOW - 1),
            ..active_verified.clone()
        };
        let ctx_rev =
            compute_session_context(false, false, Some("sid1"), Some(&revoked), &safety, NOW);
        assert!(!ctx_rev.sid_valid);
        assert!(!ctx_rev.strict_age_ok);
        assert!(ctx_rev.enabled_switchers.is_empty());

        // Expired session immediately fails sid_valid
        let expired = StoredSessionSnapshot {
            expires_at: NOW,
            ..active_verified.clone()
        };
        assert!(
            !compute_session_context(false, false, Some("sid1"), Some(&expired), &safety, NOW)
                .sid_valid
        );

        // Banned account forces active=false, sid_valid=false, empty switchers
        let ctx_ban = compute_session_context(
            true,
            false,
            Some("sid1"),
            Some(&active_verified),
            &safety,
            NOW,
        );
        assert!(!ctx_ban.active && ctx_ban.banned && !ctx_ban.sid_valid);
        assert!(ctx_ban.enabled_switchers.is_empty());

        // Suspended account forces active=false, suspended=true, empty switchers
        let ctx_susp = compute_session_context(
            false,
            true,
            Some("sid1"),
            Some(&active_verified),
            &safety,
            NOW,
        );
        assert!(!ctx_susp.active && ctx_susp.suspended && !ctx_susp.sid_valid);
        assert!(ctx_susp.enabled_switchers.is_empty());

        // Self-attestation upgrades `None` -> `SelfAttestation`, NEVER `Verified18` or `strict_age_ok`
        let plain_session = StoredSessionSnapshot {
            assurance_level: AssuranceLevel::None,
            strict_age_ok: true, // even if mistakenly set, invariant enforces false!
            expires_at: NOW + 3600,
            revoked_at: None,
        };
        let ctx_self = compute_session_context(
            false,
            false,
            Some("sid2"),
            Some(&plain_session),
            &safety,
            NOW,
        );
        assert!(ctx_self.sid_valid);
        assert_eq!(ctx_self.assurance_level, AssuranceLevel::SelfAttestation);
        assert!(!ctx_self.strict_age_ok);
    }

    #[test]
    fn preview_budget_dedupes_and_caps_separately_from_clear_balance() {
        // First hit on new item consumes 1 unique slot and 1 total hit.
        assert_eq!(decide_preview_budget(0, 0, 0, 240, 4), (true, 239));
        // Repeat hits on an already-seen item are allowed up to `max_item_hits` (4), even
        // when unique slots are full, then denied on the 5th hit (Cycle 3 H7).
        assert_eq!(decide_preview_budget(1, 240, 240, 240, 4), (true, 0));
        assert_eq!(decide_preview_budget(3, 240, 242, 240, 4), (true, 0));
        assert_eq!(decide_preview_budget(4, 240, 243, 240, 4), (false, 0));
        assert_eq!(decide_preview_budget(4, 1, 4, 240, 4), (false, 0));
        // New unique item rejected once unique cap reached.
        assert_eq!(decide_preview_budget(0, 240, 240, 240, 4), (false, 0));
        // Total hits cap (`max_unique * 2 = 480`) stops repeat amplification across items.
        assert_eq!(decide_preview_budget(1, 200, 480, 240, 4), (false, 0));
    }

    #[test]
    fn selective_revoke_recognizes_legacy_invalidation_without_wiping_v2_sessions() {
        assert!(!is_selective_revoke(&SessionRevokeAllReq::default()));
        assert!(is_selective_revoke(&SessionRevokeAllReq {
            invalidate_legacy: true,
            ..SessionRevokeAllReq::default()
        }));
        assert!(is_selective_revoke(&SessionRevokeAllReq {
            revoke_sid: Some("sid-1".into()),
            ..SessionRevokeAllReq::default()
        }));
    }

    #[test]
    fn cold_load_legacy_safe_mode_wipes_switchers_and_bumps_pref_version() {
        let active_verified = StoredSessionSnapshot {
            assurance_level: AssuranceLevel::Verified18,
            strict_age_ok: true,
            expires_at: NOW + 3600,
            revoked_at: None,
        };

        // Case 1: Legacy safe_mode == true with previously saved switchers MUST wipe switchers
        // to [] AND bump pref_version AND request immediate persistence BEFORE serving SessionContext!
        let legacy_safe_on = RawStoredSafetyRow {
            enabled_switchers: vec![PolicyRef::new("r18", 1), PolicyRef::new("blood", 1)],
            legacy_safe_mode: true,
            pref_version: 4,
            terms_version: Some(1),
            terms_digest: Some("abcd".into()),
            self_attested_18: true,
            revoked_all_before: 0,
        };
        let (migrated, needs_persist) = migrate_legacy_safe_mode_on_load(legacy_safe_on);
        assert!(needs_persist);
        assert!(migrated.enabled_switchers.is_empty());
        assert_eq!(migrated.pref_version, 5);
        assert_eq!(migrated.terms_version, Some(1));

        let ctx = compute_session_context(
            false,
            false,
            Some("sid1"),
            Some(&active_verified),
            &migrated,
            NOW,
        );
        assert!(ctx.enabled_switchers.is_empty());
        assert_eq!(ctx.pref_version, 5);

        // Case 2: Legacy safe_mode == false preserves PolicyRef switchers without bumping pref_version
        let legacy_safe_off = RawStoredSafetyRow {
            enabled_switchers: vec![PolicyRef::new("r18", 2)],
            legacy_safe_mode: false,
            pref_version: 4,
            terms_version: Some(1),
            terms_digest: Some("abcd".into()),
            self_attested_18: true,
            revoked_all_before: 0,
        };
        let (kept, needs_persist2) = migrate_legacy_safe_mode_on_load(legacy_safe_off);
        assert!(!needs_persist2);
        assert_eq!(kept.enabled_switchers, vec![PolicyRef::new("r18", 2)]);
        assert_eq!(kept.pref_version, 4);
    }

    #[test]
    fn prefs_update_enforces_monotonic_pref_version_and_rejects_stale_tab_409() {
        let initial = StoredSafetyState {
            enabled_switchers: vec![PolicyRef::new("r18", 1)],
            pref_version: 3,
            terms_version: Some(1),
            terms_digest: Some("abcd".into()),
            self_attested_18: true,
            revoked_all_before: 0,
        };

        // Tab A submits matching expected_pref_version == 3 -> succeeds and bumps pref_version to 4
        let updated = match apply_prefs_update(&initial, vec![], Some(3)) {
            PrefsUpdateOutcome::Updated(s) => s,
            other => panic!("expected Updated, got {other:?}"),
        };
        assert!(updated.enabled_switchers.is_empty());
        assert_eq!(updated.pref_version, 4);

        // Stale Tab B still thinks pref_version == 3 and tries to re-enable r18 -> VersionConflict (409)!
        match apply_prefs_update(&updated, vec![PolicyRef::new("r18", 1)], Some(3)) {
            PrefsUpdateOutcome::VersionConflict { current } => {
                assert_eq!(current.pref_version, 4);
                assert!(current.enabled_switchers.is_empty());
            }
            other => panic!("expected VersionConflict, got {other:?}"),
        }

        // Future expected_pref_version (99) also rejected with VersionConflict!
        assert!(matches!(
            apply_prefs_update(&updated, vec![PolicyRef::new("r18", 1)], Some(99)),
            PrefsUpdateOutcome::VersionConflict { .. }
        ));

        // Omitting expected_pref_version succeeds and still bumps monotonically (4 -> 5)
        let bumped = match apply_prefs_update(
            &updated,
            vec![PolicyRef::new("r18", 2), PolicyRef::new("r18", 2)],
            None,
        ) {
            PrefsUpdateOutcome::Updated(s) => s,
            other => panic!("expected Updated, got {other:?}"),
        };
        assert_eq!(bumped.pref_version, 5);
        assert_eq!(bumped.enabled_switchers, vec![PolicyRef::new("r18", 2)]);
    }

    #[test]
    fn parse_stored_policy_refs_accepts_v3_and_drops_unversioned_legacy_strings() {
        let raw = r#"[{"id":"r18","grant_generation":2},"blood@1","legacy_unversioned",{"id":"bad","grant_generation":0},"r18@2"]"#;
        let parsed = parse_stored_policy_refs(raw);
        assert_eq!(
            parsed,
            vec![PolicyRef::new("r18", 2), PolicyRef::new("blood", 1)]
        );
    }

    #[test]
    fn standalone_age_confirm_sets_self_attestation_without_requiring_terms() {
        let safety = StoredSafetyState {
            enabled_switchers: Vec::new(),
            pref_version: 1,
            terms_version: None,
            terms_digest: None,
            self_attested_18: true,
            revoked_all_before: 0,
        };
        let plain_session = StoredSessionSnapshot {
            assurance_level: AssuranceLevel::None,
            strict_age_ok: false,
            expires_at: NOW + 3600,
            revoked_at: None,
        };
        let ctx = compute_session_context(
            false,
            false,
            Some("sid-age"),
            Some(&plain_session),
            &safety,
            NOW,
        );
        assert!(ctx.sid_valid);
        assert_eq!(ctx.assurance_level, AssuranceLevel::SelfAttestation);
        assert!(!ctx.strict_age_ok);
        assert_eq!(ctx.terms_version_accepted, None);
        assert_eq!(ctx.terms_digest_accepted, None);
    }

    #[test]
    fn next_utc_day_reset_rolls_at_utc_midnight() {
        assert_eq!(next_utc_day_reset(0), 86_400);
        assert_eq!(next_utc_day_reset(86_399), 86_400);
        assert_eq!(next_utc_day_reset(86_400), 172_800);
        // 2026-01-01T12:30:00Z = 1_767_270_600 -> 2026-01-02T00:00:00Z = 1_767_312_000
        assert_eq!(next_utc_day_reset(1_767_270_600), 1_767_312_000);
    }

    #[test]
    fn merge_credit_accounting_forfeits_free_credits_and_preserves_paid_and_prorated_plans() {
        const PERIOD: u64 = 30 * 86_400;
        const HALF: u64 = 15 * 86_400;

        // 1. Free-only tracked account -> 0 transferable, all 3,000 free forfeited.
        let free_only = compute_merge_credit_breakdown(
            true,
            3_000,
            Some(3_000),
            3_000,
            0,
            false,
            0,
            None,
            0,
            0,
        );
        assert_eq!(free_only.total_transferable, 0);
        assert_eq!(free_only.total_free_forfeited, 3_000);

        // 2. Paid deposit (20,000) + untouched free (3,000) -> 20,000 transferred, 3,000 forfeited.
        let paid_untouched = compute_merge_credit_breakdown(
            true,
            23_000,
            Some(3_000),
            3_000,
            20_000,
            false,
            0,
            None,
            0,
            0,
        );
        assert_eq!(paid_untouched.paid_balance_transfer, 20_000);
        assert_eq!(paid_untouched.total_free_forfeited, 3_000);
        assert_eq!(paid_untouched.total_transferable, 20_000);

        // 3. PAYG spending consumes free balance first.
        let (bal_after, free_after) = spend_free_first(23_000, 3_000, 2_000);
        assert_eq!((bal_after, free_after), (21_000, 1_000));
        let after_payg = compute_merge_credit_breakdown(
            true,
            bal_after,
            Some(free_after),
            3_000,
            20_000,
            false,
            0,
            None,
            0,
            0,
        );
        assert_eq!(after_payg.total_transferable, 20_000);
        assert_eq!(after_payg.total_free_forfeited, 1_000);

        // 4. Subscription uses paid funds first so free signup credits cannot be laundered!
        let (sub_bal, sub_free, sub_plan_real) =
            subscribe_split_funding(23_000, 3_000, 0, 0, 20_000);
        assert_eq!((sub_bal, sub_free, sub_plan_real), (3_000, 3_000, 20_000));
        let sub_half = compute_merge_credit_breakdown(
            true,
            sub_bal,
            Some(sub_free),
            3_000,
            20_000,
            true,
            20_000,
            Some(sub_plan_real),
            PERIOD,
            HALF,
        );
        assert_eq!(sub_half.paid_balance_transfer, 0);
        assert_eq!(sub_half.plan_refund_paid, 10_000);
        assert_eq!(sub_half.total_transferable, 10_000);
        assert_eq!(sub_half.total_free_forfeited, 3_000);

        // 5. Subscription funded with mix of 17,000 paid + 3,000 free -> only paid portion prorates!
        let (mix_bal, mix_free, mix_plan_real) =
            subscribe_split_funding(20_000, 3_000, 0, 0, 20_000);
        assert_eq!((mix_bal, mix_free, mix_plan_real), (0, 0, 17_000));
        let mix_half = compute_merge_credit_breakdown(
            true,
            mix_bal,
            Some(mix_free),
            3_000,
            17_000,
            true,
            20_000,
            Some(mix_plan_real),
            PERIOD,
            HALF,
        );
        assert_eq!(mix_half.plan_refund_total, 10_000);
        assert_eq!(mix_half.plan_refund_paid, 8_500);
        assert_eq!(mix_half.plan_free_forfeited, 1_500);
        assert_eq!(mix_half.total_transferable, 8_500);

        // 6. Admin-granted plan (`plan_paid = 0`) on free-only account -> 0 transferred!
        let admin_plan = compute_merge_credit_breakdown(
            true,
            3_000,
            Some(3_000),
            3_000,
            0,
            true,
            0,
            Some(0),
            PERIOD,
            HALF,
        );
        assert_eq!(admin_plan.total_transferable, 0);

        // 7. Legacy untracked accounts (`tracked_free_balance: None`) with D1 deposit history.
        let legacy_free = compute_merge_credit_breakdown(
            true, 3_000, None, 3_000, 0, false, 0, None, 0, 0,
        );
        assert_eq!(legacy_free.total_transferable, 0);
        let legacy_paid_spent = compute_merge_credit_breakdown(
            true, 18_000, None, 3_000, 20_000, false, 0, None, 0, 0,
        );
        assert_eq!(legacy_paid_spent.total_transferable, 18_000);
        let legacy_sub = compute_merge_credit_breakdown(
            true, 3_000, None, 3_000, 20_000, true, 20_000, None, PERIOD, HALF,
        );
        assert_eq!(legacy_sub.paid_balance_transfer, 0);
        assert_eq!(legacy_sub.plan_refund_paid, 10_000);
        assert_eq!(legacy_sub.total_transferable, 10_000);
        assert_eq!(legacy_sub.total_free_forfeited, 3_000);
    }
}
