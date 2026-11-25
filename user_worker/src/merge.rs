//! Explicit dual-proof Account Linking & Account Fusion (merging 2 accounts into 1).
//!
//! Security & accounting invariants:
//! - Both accounts must prove ownership: current account via active session + recent auth
//!   (`<= 600s`) + same-origin CSRF; second account via fresh cryptographic wallet signature
//!   (purpose-scoped single-use nonce) or fresh browser-bound OAuth/OIDC callback.
//! - Payment-only wallets (`purpose = 'payment'`) NEVER confer account ownership or merge rights.
//! - Banned or suspended accounts CANNOT be merged (prevents ban evasion / credit laundering).
//! - Free signup credits on the abandoned account are forfeited; ONLY verified paid credits
//!   and the prorated paid remainder of any active subscription transfer to the preserved account.
//! - Crash-safe & idempotent via `merge_id`: abandoned DO drains & freezes atomically first,
//!   preserved DO credits idempotently (`merge_in:{merge_id}`), then D1 moves identities,
//!   favorites (per user choice), and payment history in one atomic `db.batch`, tombstoning
//!   the abandoned `users_v2` row so legacy wallet accounts can never be re-adopted.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use site_access::{AgeVerificationPolicy, AssuranceLevel, AuthProviderId, PublicSitePolicy};
use tower_cookies::Cookies;
use wasm_bindgen::JsValue;

use crate::{
    AppState, auth,
    challenge_do::{self, MergeTicketIssueReq},
    config,
    do_client::{self, MergeCreditBreakdown, MergeDrainDoReq, MergeReceiveDoReq},
    identity::{self, ActiveSession, IdentityView, ResolvedAccount, VerifiedExternalIdentity},
    policy_do, session, siwe, solana_link,
};

const MERGE_TICKET_TTL_SECS: u64 = 600;

/// Expected EIP-4361 statement for linking/merging an Ethereum wallet with `user_id`.
pub fn expected_siwe_merge_statement(user_id: &str) -> String {
    format!("Link or merge Ethereum wallet with account {user_id}.")
}

/// Expected Solana off-chain challenge for linking/merging a Solana wallet with `user_id`.
pub fn expected_sol_merge_challenge(user_id: &str, nonce: &str) -> String {
    format!("Link or merge Solana wallet with {user_id}\nNonce: {nonce}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreserveTarget {
    Current,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FavoritesChoice {
    Both,
    KeepCurrent,
    KeepOther,
}

/// Canonical D1 favorites mode relative to `(preserved, abandoned)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbFavoritesMode {
    Both,
    KeepPreserved,
    KeepAbandoned,
}

impl DbFavoritesMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::KeepPreserved => "keep_preserved",
            Self::KeepAbandoned => "keep_abandoned",
        }
    }
}

/// Map UI `(preserve, favorites)` selections into canonical DB mode relative to
/// `(preserved_user_id, abandoned_user_id)`.
pub fn resolve_favorites_mode(
    preserve: PreserveTarget,
    favorites: FavoritesChoice,
) -> DbFavoritesMode {
    match (preserve, favorites) {
        (_, FavoritesChoice::Both) => DbFavoritesMode::Both,
        (PreserveTarget::Current, FavoritesChoice::KeepCurrent)
        | (PreserveTarget::Other, FavoritesChoice::KeepOther) => DbFavoritesMode::KeepPreserved,
        (PreserveTarget::Current, FavoritesChoice::KeepOther)
        | (PreserveTarget::Other, FavoritesChoice::KeepCurrent) => DbFavoritesMode::KeepAbandoned,
    }
}

fn assurance_rank(level: AssuranceLevel) -> u8 {
    match level {
        AssuranceLevel::None => 0,
        AssuranceLevel::SelfAttestation => 1,
        AssuranceLevel::ProviderSelfReportedDob => 2,
        AssuranceLevel::Verified18 => 3,
    }
}

/// Compute post-merge session `(assurance_level, strict_age_ok)` without EVER
/// promoting a caller to `Verified18` unless either their active session OR the
/// freshly verified secondary identity actually proved `Verified18 + strict_age_ok`.
pub fn resolve_merge_session_assurance(
    policy: &PublicSitePolicy,
    cur_assurance: AssuranceLevel,
    cur_strict: bool,
    other_assurance: AssuranceLevel,
    other_strict: bool,
) -> (AssuranceLevel, bool) {
    let strict_ok = (cur_strict && cur_assurance == AssuranceLevel::Verified18)
        || (other_strict && other_assurance == AssuranceLevel::Verified18);
    let mut best = if assurance_rank(other_assurance) > assurance_rank(cur_assurance) {
        other_assurance
    } else {
        cur_assurance
    };
    if best == AssuranceLevel::Verified18 && !strict_ok {
        best = AssuranceLevel::None;
    }
    if policy.age_policy == AgeVerificationPolicy::Off && best == AssuranceLevel::SelfAttestation {
        best = AssuranceLevel::None;
    }
    (best, strict_ok && best == AssuranceLevel::Verified18)
}

// ---------------------------------------------------------------------------
// API DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StartWalletMergeReq {
    /// `"siwe"` (Ethereum) or `"siws"` (Solana)
    pub provider_id: String,
    // SIWE fields
    #[serde(default)]
    pub message: Option<String>,
    pub signature: String,
    // SIWS fields
    #[serde(default)]
    pub solana_address: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub signed_message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MergeAccountSummary {
    pub user_id: String,
    pub display_address: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub identities: Vec<IdentityView>,
    pub balance: i64,
    pub paid_balance: i64,
    pub free_balance: i64,
    pub plan: Option<String>,
    pub period_end: u64,
    pub plan_refund_paid: i64,
    pub favorites_count: i64,
    pub payments_count: i64,
    pub total_views: i64,
}

#[derive(Debug, Serialize)]
pub struct MergeTransferPreview {
    pub paid_balance_moved: i64,
    pub plan_refund_moved: i64,
    pub total_credits_added: i64,
    pub free_credits_forfeited: i64,
    pub resulting_balance: i64,
}

#[derive(Debug, Serialize)]
pub struct MergePreviewResp {
    pub merge_ticket: String,
    pub expires_at: u64,
    pub current_account: MergeAccountSummary,
    pub other_account: MergeAccountSummary,
    /// Preview if keeping `current_account` and abandoning `other_account`.
    pub keep_current: MergeTransferPreview,
    /// Preview if keeping `other_account` and abandoning `current_account`.
    pub keep_other: MergeTransferPreview,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum StartWalletMergeResp {
    Linked {
        provider_id: String,
        subject: String,
    },
    MergeRequired {
        merge_ticket: String,
        preview: Box<MergePreviewResp>,
    },
}

#[derive(Debug, Deserialize)]
pub struct PreviewMergeReq {
    pub merge_ticket: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmMergeReq {
    pub merge_ticket: String,
    pub preserve: PreserveTarget,
    pub favorites: FavoritesChoice,
}

#[derive(Debug, Serialize)]
pub struct ConfirmMergeResp {
    pub merge_id: String,
    pub preserved_user_id: String,
    pub abandoned_user_id: String,
    pub paid_balance_moved: i64,
    pub plan_refund_moved: i64,
    pub total_credits_added: i64,
    pub free_credits_forfeited: i64,
    pub new_balance: i64,
    pub favorites_count: i64,
    pub identities_count: usize,
}

// ---------------------------------------------------------------------------
// Shared Lookup / Ticket / Preview Helpers
// ---------------------------------------------------------------------------

/// Look up the current owner `(user_id, purpose)` of an exact `(provider_id, issuer, subject)`
/// in `user_identities`.
pub async fn find_identity_owner(
    st: &AppState,
    provider_id: &str,
    issuer: &str,
    subject: &str,
) -> Result<Option<(String, String)>, Response> {
    #[derive(Deserialize)]
    struct Row {
        user_id: String,
        purpose: String,
    }
    let db = st
        .env
        .d1(crate::D1_BINDING)
        .map_err(|_| auth::internal_error())?;
    let row = db
        .prepare(
            "SELECT user_id, purpose FROM user_identities \
             WHERE provider_id = ?1 AND issuer = ?2 AND subject = ?3",
        )
        .bind(&[provider_id.into(), issuer.into(), subject.into()])
        .map_err(|_| auth::internal_error())?
        .first::<Row>(None)
        .await
        .map_err(|e| {
            worker::console_error!("find_identity_owner failed: {e:?}");
            auth::internal_error()
        })?;
    Ok(row.map(|r| (r.user_id, r.purpose)))
}

async fn query_account_d1_stats(
    st: &AppState,
    user_id: &str,
    do_key: &str,
) -> Result<(i64, i64, i64), Response> {
    #[derive(Deserialize)]
    struct CountRow {
        n: i64,
    }
    #[derive(Deserialize)]
    struct PayStatsRow {
        cnt: i64,
        paid_sum: i64,
    }
    let db = st
        .env
        .d1(crate::D1_BINDING)
        .map_err(|_| auth::internal_error())?;
    let fav_cnt = db
        .prepare("SELECT COUNT(*) AS n FROM likes WHERE address = ?1")
        .bind(&[user_id.into()])
        .map_err(|_| auth::internal_error())?
        .first::<CountRow>(None)
        .await
        .map_err(|e| {
            worker::console_error!("merge likes count failed: {e:?}");
            auth::internal_error()
        })?
        .map_or(0, |r| r.n.max(0));

    let pay_stats = db
        .prepare(
            "SELECT COUNT(*) AS cnt, \
             COALESCE(SUM(CASE WHEN status = 'credited' THEN points ELSE 0 END), 0) AS paid_sum \
             FROM payments WHERE address = ?1 OR address = ?2",
        )
        .bind(&[user_id.into(), do_key.into()])
        .map_err(|_| auth::internal_error())?
        .first::<PayStatsRow>(None)
        .await
        .map_err(|e| {
            worker::console_error!("merge payment stats failed: {e:?}");
            auth::internal_error()
        })?;
    let (pay_cnt, paid_sum) = pay_stats.map_or((0, 0), |r| (r.cnt.max(0), r.paid_sum.max(0)));
    Ok((fav_cnt, pay_cnt, paid_sum))
}

fn format_account_label(acct: &ResolvedAccount, identities: &[IdentityView]) -> String {
    if session::is_valid_principal(&acct.account_do_key) {
        return auth::display_address(&acct.account_do_key);
    }
    if let Some(name) = acct
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return name.to_string();
    }
    if let Some(email) = acct
        .email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return email.to_string();
    }
    if let Some(first) = identities.first() {
        if let Some(lbl) = first
            .label
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return lbl.to_string();
        }
        return auth::display_address(&first.subject);
    }
    acct.user_id.clone()
}

fn transfer_preview(
    kept_balance: i64,
    abandoned_credits: &MergeCreditBreakdown,
) -> MergeTransferPreview {
    MergeTransferPreview {
        paid_balance_moved: abandoned_credits.paid_balance_transfer,
        plan_refund_moved: abandoned_credits.plan_refund_paid,
        total_credits_added: abandoned_credits.total_transferable,
        free_credits_forfeited: abandoned_credits.total_free_forfeited,
        resulting_balance: kept_balance.saturating_add(abandoned_credits.total_transferable),
    }
}

async fn load_account_preview(
    st: &AppState,
    user_id: &str,
) -> Result<(ResolvedAccount, MergeAccountSummary, MergeCreditBreakdown), Response> {
    let Some(acct) = identity::load_account_by_id(st, user_id).await? else {
        return Err(auth::api_error(StatusCode::NOT_FOUND, "account not found"));
    };
    if acct.banned {
        return Err(auth::api_error(
            StatusCode::FORBIDDEN,
            "banned accounts cannot be merged",
        ));
    }
    let identities = identity::list_user_identities(st, user_id).await?;
    let (favorites_count, payments_count, paid_deposits) =
        query_account_d1_stats(st, &acct.user_id, &acct.account_do_key).await?;
    let do_prev = do_client::do_merge_preview(&st.env, &acct.account_do_key, paid_deposits)
        .await
        .map_err(|e| {
            worker::console_error!("do_merge_preview failed for {}: {e:?}", acct.account_do_key);
            auth::api_error(
                StatusCode::BAD_GATEWAY,
                "account service unavailable; please retry",
            )
        })?;
    if do_prev.banned {
        return Err(auth::api_error(
            StatusCode::FORBIDDEN,
            "banned accounts cannot be merged",
        ));
    }
    if do_prev.suspended || do_prev.merged_into.is_some() {
        return Err(auth::api_error(
            StatusCode::CONFLICT,
            "one of these accounts is suspended or has already been merged",
        ));
    }
    let summary = MergeAccountSummary {
        user_id: acct.user_id.clone(),
        display_address: format_account_label(&acct, &identities),
        display_name: acct.display_name.clone(),
        email: acct.email.clone(),
        identities,
        balance: do_prev.balance,
        paid_balance: do_prev.credits.paid_balance_transfer,
        free_balance: do_prev.credits.free_balance_forfeited,
        plan: do_prev.plan,
        period_end: do_prev.period_end,
        plan_refund_paid: do_prev.credits.plan_refund_paid,
        favorites_count,
        payments_count,
        total_views: do_prev.total_views,
    };
    Ok((acct, summary, do_prev.credits))
}

pub async fn build_merge_preview(
    st: &AppState,
    current_user_id: &str,
    other_user_id: &str,
    merge_ticket: &str,
    expires_at: u64,
) -> Result<MergePreviewResp, Response> {
    if current_user_id == other_user_id {
        return Err(auth::api_error(
            StatusCode::CONFLICT,
            "This sign-in method is already linked to your current account.",
        ));
    }
    let (_, current_account, cur_credits) = load_account_preview(st, current_user_id).await?;
    let (_, other_account, other_credits) = load_account_preview(st, other_user_id).await?;
    let keep_current = transfer_preview(current_account.balance, &other_credits);
    let keep_other = transfer_preview(other_account.balance, &cur_credits);
    Ok(MergePreviewResp {
        merge_ticket: merge_ticket.to_string(),
        expires_at,
        current_account,
        other_account,
        keep_current,
        keep_other,
    })
}

fn generate_merge_ticket() -> Result<String, Response> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|_| auth::internal_error())?;
    Ok(format!("mrg_{}", B64.encode(bytes)))
}

/// Issue a short-lived single-use merge ticket in `AuthChallengeDO` after caller proves
/// ownership of a second account (`other_user_id`) via SIWE, SIWS, or OAuth/OIDC.
pub async fn issue_ticket_for_verified_identity(
    st: &AppState,
    active: &ActiveSession,
    other_user_id: &str,
    ident: &VerifiedExternalIdentity,
) -> Result<(String, u64), Response> {
    if other_user_id == active.user_id {
        return Err(auth::api_error(
            StatusCode::CONFLICT,
            "This sign-in method is already linked to your current account.",
        ));
    }
    // Validate both accounts are eligible (active, not banned/suspended/already merged).
    let _ = load_account_preview(st, &active.user_id).await?;
    let _ = load_account_preview(st, other_user_id).await?;

    let ticket = generate_merge_ticket()?;
    let now = session::now_secs();
    let expires_at = now.saturating_add(MERGE_TICKET_TTL_SECS);
    challenge_do::issue_merge_ticket(
        &st.env,
        &MergeTicketIssueReq {
            ticket: ticket.clone(),
            initiator_user_id: active.user_id.clone(),
            other_user_id: other_user_id.to_string(),
            verified_provider: ident.provider_id.as_str().to_string(),
            verified_identity_key: ident.identity_key(),
            verified_assurance: identity::assurance_to_str(ident.assurance_level).to_string(),
            verified_strict_age_ok: ident.is_strict_age_verified(now),
            ttl_secs: MERGE_TICKET_TTL_SECS,
        },
    )
    .await
    .map_err(|e| {
        worker::console_error!("issue_merge_ticket DO failed: {e:?}");
        auth::internal_error()
    })?;
    Ok((ticket, expires_at))
}

// ---------------------------------------------------------------------------
// POST /user/api/account/merge/start/wallet
// ---------------------------------------------------------------------------

#[worker::send]
pub async fn start_wallet(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<StartWalletMergeReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = identity::require_recent_auth(&st, &active).await {
        return r;
    }

    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(_) => return auth::internal_error(),
    };
    let Some(pid) = identity::provider_from_str(req.provider_id.trim()) else {
        return auth::api_error(
            StatusCode::BAD_REQUEST,
            "provider_id must be 'siwe' or 'siws'",
        );
    };
    if !matches!(pid, AuthProviderId::Siwe | AuthProviderId::Siws) {
        return auth::api_error(
            StatusCode::BAD_REQUEST,
            "provider_id must be 'siwe' or 'siws'",
        );
    }
    if let Err(msg) = identity::check_login_provider_eligibility(&policy, pid, None) {
        return auth::api_error(StatusCode::FORBIDDEN, msg);
    }

    let (ident, display_subject) = match pid {
        AuthProviderId::Siwe => {
            let Some(raw_msg) = req.message.as_deref() else {
                return auth::api_error(StatusCode::BAD_REQUEST, "missing SIWE message");
            };
            let msg = match siwe::parse_siwe(raw_msg) {
                Ok(m) => m,
                Err(e) => return auth::api_error(StatusCode::BAD_REQUEST, e.to_string()),
            };
            if msg.domain != *st.siwe_domain || msg.version != "1" || msg.chain_id != st.chain_id {
                return auth::api_error(StatusCode::UNAUTHORIZED, "SIWE domain or chain mismatch");
            }
            let expected_stmt = expected_siwe_merge_statement(&active.user_id);
            if msg.uri.contains("/user/login/approve")
                || msg.statement.as_deref() != Some(expected_stmt.as_str())
            {
                return auth::api_error(
                    StatusCode::UNAUTHORIZED,
                    "SIWE statement must exactly match the account link/merge challenge",
                );
            }
            let now = session::now_secs();
            let Some(iat) = siwe::parse_rfc3339_epoch(&msg.issued_at) else {
                return auth::api_error(StatusCode::UNAUTHORIZED, "invalid issued-at timestamp");
            };
            if now.abs_diff(iat) > config::SIWE_MAX_AGE_SECS {
                return auth::api_error(StatusCode::UNAUTHORIZED, "message issued-at out of range");
            }
            if let Some(exp_str) = &msg.expiration_time {
                let Some(exp) = siwe::parse_rfc3339_epoch(exp_str) else {
                    return auth::api_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid expiration timestamp",
                    );
                };
                if exp <= now {
                    return auth::api_error(StatusCode::UNAUTHORIZED, "message expired");
                }
            }
            match challenge_do::consume_nonce(&st.env, &msg.nonce, auth::NONCE_PURPOSE_MERGE_ACCOUNT)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return auth::api_error(StatusCode::UNAUTHORIZED, "unknown or expired nonce");
                }
                Err(_) => return auth::internal_error(),
            }
            let addr = match siwe::recover_address(raw_msg, &req.signature) {
                Ok(a) => a,
                Err(e) => return auth::api_error(StatusCode::UNAUTHORIZED, e.to_string()),
            };
            if addr != msg.address.to_lowercase() {
                return auth::api_error(
                    StatusCode::UNAUTHORIZED,
                    "signature does not match address",
                );
            }
            let ident = VerifiedExternalIdentity {
                provider_id: AuthProviderId::Siwe,
                issuer: format!("eip155:{}", st.chain_id),
                subject: addr.clone(),
                label: Some("Ethereum wallet".into()),
                verified_email: None,
                assurance_level: AssuranceLevel::None,
                assurance_method: None,
                assurance_verified_at: None,
                assurance_expires_at: None,
            };
            (ident, siwe::to_checksum(&addr))
        }
        AuthProviderId::Siws => {
            let (Some(sol_addr), Some(nonce)) =
                (req.solana_address.as_deref(), req.nonce.as_deref())
            else {
                return auth::api_error(
                    StatusCode::BAD_REQUEST,
                    "missing solana_address or nonce",
                );
            };
            if !session::is_sol_principal(sol_addr) {
                return auth::api_error(StatusCode::BAD_REQUEST, "invalid Solana address");
            }
            match challenge_do::consume_nonce(&st.env, nonce, auth::NONCE_PURPOSE_MERGE_ACCOUNT)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return auth::api_error(StatusCode::UNAUTHORIZED, "unknown or expired nonce");
                }
                Err(_) => return auth::internal_error(),
            }
            let expected = expected_sol_merge_challenge(&active.user_id, nonce);
            if !solana_link::verify_ed25519_challenge(
                sol_addr,
                &req.signature,
                &expected,
                req.signed_message.as_deref(),
            ) {
                return auth::api_error(
                    StatusCode::UNAUTHORIZED,
                    "signature verification failed",
                );
            }
            let ident = VerifiedExternalIdentity {
                provider_id: AuthProviderId::Siws,
                issuer: "solana:mainnet".to_string(),
                subject: sol_addr.to_string(),
                label: Some("Solana wallet".into()),
                verified_email: None,
                assurance_level: AssuranceLevel::None,
                assurance_method: None,
                assurance_verified_at: None,
                assurance_expires_at: None,
            };
            (ident, sol_addr.to_string())
        }
        _ => unreachable!(),
    };

    let owner = match find_identity_owner(
        &st,
        ident.provider_id.as_str(),
        &ident.issuer,
        &ident.subject,
    )
    .await
    {
        Ok(o) => o,
        Err(r) => return r,
    };

    match owner {
        None => {
            // Unclaimed wallet -> link directly as a `login` identity on the current account.
            if let Err(r) =
                identity::link_identity_atomic(&st, &active.user_id, &ident, "login").await
            {
                return r;
            }
            if let Err(r) =
                identity::rotate_session_on_identity_link(&st, &cookies, &active, &ident).await
            {
                return r;
            }
            (
                [(header::CACHE_CONTROL, "private, no-store")],
                Json(StartWalletMergeResp::Linked {
                    provider_id: ident.provider_id.as_str().to_string(),
                    subject: display_subject,
                }),
            )
                .into_response()
        }
        Some((owner_id, purpose)) if owner_id == active.user_id => {
            if purpose == "payment" {
                // Upgrade own payment-only wallet to a full `login` identity!
                let db = match st.env.d1(crate::D1_BINDING) {
                    Ok(db) => db,
                    Err(_) => return auth::internal_error(),
                };
                let stmt = match db
                    .prepare(
                        "UPDATE user_identities SET purpose = 'login', label = ?1 \
                         WHERE user_id = ?2 AND provider_id = ?3 AND issuer = ?4 AND subject = ?5",
                    )
                    .bind(&[
                        ident.label.as_deref().unwrap_or("Wallet").into(),
                        active.user_id.as_str().into(),
                        ident.provider_id.as_str().into(),
                        ident.issuer.as_str().into(),
                        ident.subject.as_str().into(),
                    ]) {
                    Ok(s) => s,
                    Err(_) => return auth::internal_error(),
                };
                if let Err(e) = stmt.run().await {
                    worker::console_error!("wallet upgrade to login failed: {e:?}");
                    return auth::internal_error();
                }
                if let Err(r) =
                    identity::rotate_session_on_identity_link(&st, &cookies, &active, &ident).await
                {
                    return r;
                }
                return (
                    [(header::CACHE_CONTROL, "private, no-store")],
                    Json(StartWalletMergeResp::Linked {
                        provider_id: ident.provider_id.as_str().to_string(),
                        subject: display_subject,
                    }),
                )
                    .into_response();
            }
            auth::api_error(
                StatusCode::CONFLICT,
                "This wallet is already linked as a sign-in method on your current account.",
            )
        }
        Some((_, purpose)) if purpose != "login" => auth::api_error(
            StatusCode::CONFLICT,
            "This wallet is linked as a payment-only wallet on another account. Unlink it there first.",
        ),
        Some((other_user_id, _)) => {
            // Owned by another existing account -> issue single-use merge ticket & return preview!
            let (ticket, expires_at) =
                match issue_ticket_for_verified_identity(&st, &active, &other_user_id, &ident).await
                {
                    Ok(t) => t,
                    Err(r) => return r,
                };
            let preview = match build_merge_preview(
                &st,
                &active.user_id,
                &other_user_id,
                &ticket,
                expires_at,
            )
            .await
            {
                Ok(p) => p,
                Err(r) => return r,
            };
            (
                [(header::CACHE_CONTROL, "private, no-store")],
                Json(StartWalletMergeResp::MergeRequired {
                    merge_ticket: ticket,
                    preview: Box::new(preview),
                }),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// POST /user/api/account/merge/preview
// ---------------------------------------------------------------------------

#[worker::send]
pub async fn preview(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<PreviewMergeReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let ticket_str = req.merge_ticket.trim();
    if ticket_str.is_empty() {
        return auth::api_error(StatusCode::BAD_REQUEST, "missing merge_ticket");
    }
    let rec = match challenge_do::peek_merge_ticket(&st.env, ticket_str, &active.user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return auth::api_error(
                StatusCode::UNAUTHORIZED,
                "Merge session expired or invalid. Please verify the other account again.",
            );
        }
        Err(e) => {
            worker::console_error!("peek_merge_ticket failed: {e:?}");
            return auth::internal_error();
        }
    };
    match build_merge_preview(
        &st,
        &active.user_id,
        &rec.other_user_id,
        &rec.ticket,
        rec.expires_at,
    )
    .await
    {
        Ok(p) => ([(header::CACHE_CONTROL, "private, no-store")], Json(p)).into_response(),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------------------
// POST /user/api/account/merge/confirm
// ---------------------------------------------------------------------------

#[worker::send]
pub async fn confirm(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<ConfirmMergeReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = identity::require_recent_auth(&st, &active).await {
        return r;
    }

    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(_) => return auth::internal_error(),
    };

    // Inspect caller's live session BEFORE consuming ticket so we preserve `auth_time`
    // and enforce session assurance caps accurately.
    let cur_info = if let Some(sid) = active.sid.as_deref() {
        match do_client::do_session_info(&st.env, &active.do_key, sid).await {
            Ok(Some(ci)) if ci.active => Some(ci),
            Ok(_) => {
                cookies.add(session::clear_session_cookie());
                return auth::api_error(StatusCode::UNAUTHORIZED, "session revoked or expired");
            }
            Err(e) => {
                worker::console_error!("merge confirm session-info failed: {e:?}");
                return auth::api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "account service unavailable; please retry",
                );
            }
        }
    } else {
        None
    };

    let ticket_str = req.merge_ticket.trim();
    if ticket_str.is_empty() {
        return auth::api_error(StatusCode::BAD_REQUEST, "missing merge_ticket");
    }

    // Atomically consume the single-use merge ticket (prevents concurrent/duplicate merges!).
    let ticket = match challenge_do::consume_merge_ticket(&st.env, ticket_str, &active.user_id).await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return auth::api_error(
                StatusCode::UNAUTHORIZED,
                "Merge session expired or already used. Please verify the other account again.",
            );
        }
        Err(e) => {
            worker::console_error!("consume_merge_ticket failed: {e:?}");
            return auth::internal_error();
        }
    };

    if ticket.other_user_id == active.user_id {
        return auth::api_error(
            StatusCode::CONFLICT,
            "Cannot merge an account with itself.",
        );
    }

    let (cur_acct, _, _) = match load_account_preview(&st, &active.user_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (other_acct, _, _) = match load_account_preview(&st, &ticket.other_user_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let (preserved, abandoned) = match req.preserve {
        PreserveTarget::Current => (cur_acct, other_acct),
        PreserveTarget::Other => (other_acct, cur_acct),
    };
    let fav_mode = resolve_favorites_mode(req.preserve, req.favorites);

    let (_, _, abandoned_paid_deposits) =
        match query_account_d1_stats(&st, &abandoned.user_id, &abandoned.account_do_key).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    let abandoned_identities = match identity::list_user_identities(&st, &abandoned.user_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let merge_id = format!("mrg_{}", uuid::Uuid::new_v4().simple());
    let now = session::now_secs();
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(_) => return auth::internal_error(),
    };

    // Best-effort audit insert before draining (safe even during rolling deploy before 0006).
    let audit_started = if let Ok(stmt) = db
        .prepare(
            "INSERT INTO account_merges \
             (merge_id, preserved_user_id, abandoned_user_id, preserved_do_key, abandoned_do_key, \
              favorites_mode, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'started', ?7)",
        )
        .bind(&[
            merge_id.as_str().into(),
            preserved.user_id.as_str().into(),
            abandoned.user_id.as_str().into(),
            preserved.account_do_key.as_str().into(),
            abandoned.account_do_key.as_str().into(),
            fav_mode.as_str().into(),
            (now as f64).into(),
        ])
    {
        stmt.run().await.is_ok()
    } else {
        false
    };

    // Phase 1: Atomically freeze & drain the abandoned DO (reclaims holds, computes exact paid
    // balance + prorated paid subscription refund, zeroes balance/plan, suspends, revokes sessions).
    let drained = match do_client::do_merge_drain(
        &st.env,
        &abandoned.account_do_key,
        &MergeDrainDoReq {
            merge_id: merge_id.clone(),
            preserved_do_key: preserved.account_do_key.clone(),
            legacy_paid_deposits: abandoned_paid_deposits,
        },
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            worker::console_error!("merge_drain failed for {}: {e:?}", abandoned.account_do_key);
            return auth::api_error(
                StatusCode::CONFLICT,
                "Could not finalize draining the abandoned account (it may already be merged or suspended).",
            );
        }
    };

    // Phase 2: Idempotently credit paid points + total views into the preserved DO.
    let received = match do_client::do_merge_receive(
        &st.env,
        &preserved.account_do_key,
        &MergeReceiveDoReq {
            merge_id: merge_id.clone(),
            paid_points: drained.credits.total_transferable,
            total_views: drained.total_views_transferred,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!(
                "merge_receive failed for {} (merge_id={merge_id}): {e:?}",
                preserved.account_do_key
            );
            return auth::api_error(
                StatusCode::BAD_GATEWAY,
                "Failed to credit merged balance to preserved account; contact support with merge ID.",
            );
        }
    };

    // Phase 3: Atomic D1 batch — migrate favorites, identities, payment history, and clear plan mirror.
    let mut stmts = Vec::new();
    match fav_mode {
        DbFavoritesMode::Both => {
            if let Ok(s1) = db
                .prepare(
                    "INSERT OR IGNORE INTO likes (address, kind, target_id, created_at) \
                     SELECT ?1, kind, target_id, created_at FROM likes WHERE address = ?2",
                )
                .bind(&[preserved.user_id.as_str().into(), abandoned.user_id.as_str().into()])
            {
                stmts.push(s1);
            }
            if let Ok(s2) = db
                .prepare("DELETE FROM likes WHERE address = ?1")
                .bind(&[abandoned.user_id.as_str().into()])
            {
                stmts.push(s2);
            }
        }
        DbFavoritesMode::KeepPreserved => {
            if let Ok(s) = db
                .prepare("DELETE FROM likes WHERE address = ?1")
                .bind(&[abandoned.user_id.as_str().into()])
            {
                stmts.push(s);
            }
        }
        DbFavoritesMode::KeepAbandoned => {
            if let Ok(s1) = db
                .prepare("DELETE FROM likes WHERE address = ?1")
                .bind(&[preserved.user_id.as_str().into()])
            {
                stmts.push(s1);
            }
            if let Ok(s2) = db
                .prepare("UPDATE likes SET address = ?1 WHERE address = ?2")
                .bind(&[preserved.user_id.as_str().into(), abandoned.user_id.as_str().into()])
            {
                stmts.push(s2);
            }
        }
    }

    // Move all identities (login + payment) from abandoned account to preserved account.
    if let Ok(s) = db
        .prepare("UPDATE user_identities SET user_id = ?1 WHERE user_id = ?2")
        .bind(&[preserved.user_id.as_str().into(), abandoned.user_id.as_str().into()])
    {
        stmts.push(s);
    }

    // Re-attribute payment receipts to preserved account.
    if let Ok(s) = db
        .prepare("UPDATE payments SET address = ?1 WHERE address = ?2 OR address = ?3")
        .bind(&[
            preserved.user_id.as_str().into(),
            abandoned.user_id.as_str().into(),
            abandoned.account_do_key.as_str().into(),
        ])
    {
        stmts.push(s);
    }

    // Backfill display_name / email on preserved account if blank; clear abandoned plan mirror.
    let abandoned_name_js: JsValue = abandoned
        .display_name
        .as_deref()
        .map_or(JsValue::NULL, Into::into);
    let abandoned_email_js: JsValue = abandoned
        .email
        .as_deref()
        .map_or(JsValue::NULL, Into::into);
    if let Ok(s) = db
        .prepare(
            "UPDATE users_v2 SET \
                display_name = COALESCE(display_name, ?1), \
                email = COALESCE(email, ?2), \
                last_login = ?3 \
             WHERE id = ?4",
        )
        .bind(&[
            abandoned_name_js,
            abandoned_email_js,
            (now as f64).into(),
            preserved.user_id.as_str().into(),
        ])
    {
        stmts.push(s);
    }
    if let Ok(s) = db
        .prepare("UPDATE users_v2 SET plan = NULL WHERE id = ?1")
        .bind(&[abandoned.user_id.as_str().into()])
    {
        stmts.push(s);
    }
    if session::is_valid_principal(&abandoned.account_do_key)
        && let Ok(s) = db
            .prepare("UPDATE users SET plan = NULL, solana_address = NULL WHERE address = ?1")
            .bind(&[abandoned.account_do_key.as_str().into()])
    {
        stmts.push(s);
    }

    if let Err(e) = db.batch(stmts).await {
        worker::console_error!("merge D1 batch failed (merge_id={merge_id}): {e:?}");
        return auth::internal_error();
    }

    // Best-effort tombstone column & audit ledger completion (requires migration 0006).
    if let Ok(stmt) = db
        .prepare("UPDATE users_v2 SET merged_into = ?1 WHERE id = ?2")
        .bind(&[preserved.user_id.as_str().into(), abandoned.user_id.as_str().into()])
    {
        let _ = stmt.run().await;
    }
    if audit_started
        && let Ok(stmt) = db
            .prepare(
                "UPDATE account_merges SET \
                    paid_credits_moved = ?1, \
                    plan_refund_moved = ?2, \
                    free_credits_forfeited = ?3, \
                    identities_moved = ?4, \
                    status = 'completed', \
                    completed_at = ?5 \
                 WHERE merge_id = ?6",
            )
            .bind(&[
                (drained.credits.paid_balance_transfer as f64).into(),
                (drained.credits.plan_refund_paid as f64).into(),
                (drained.credits.total_free_forfeited as f64).into(),
                (abandoned_identities.len() as f64).into(),
                (now as f64).into(),
                merge_id.as_str().into(),
            ])
    {
        let _ = stmt.run().await;
    }

    // Phase 4: Rotate or switch caller session onto `preserved` without ever promoting assurance.
    let (cur_assurance, cur_strict, preserved_auth_time) = match cur_info.as_ref() {
        Some(ci) => (ci.assurance_level, ci.strict_age_ok, Some(ci.created_at)),
        None => (active.ctx.assurance_level, active.ctx.strict_age_ok, None),
    };
    let other_assurance = identity::assurance_from_str(&ticket.verified_assurance);
    let (final_assurance, final_strict) = resolve_merge_session_assurance(
        &policy,
        cur_assurance,
        cur_strict,
        other_assurance,
        ticket.verified_strict_age_ok,
    );

    if preserved.user_id == active.user_id
        && let Some(sid) = active.sid.as_deref()
    {
        let _ = do_client::do_session_revoke(&st.env, &active.do_key, sid).await;
    }
    let (auth_method, identity_key) = if preserved.user_id == active.user_id {
        if let Some(ci) = cur_info {
            (ci.auth_method, ci.identity_key)
        } else {
            (ticket.verified_provider.clone(), ticket.verified_identity_key.clone())
        }
    } else {
        (ticket.verified_provider.clone(), ticket.verified_identity_key.clone())
    };

    if let Err(r) = identity::issue_v2_session_with_auth_time(
        &st,
        &cookies,
        &preserved,
        &auth_method,
        &identity_key,
        final_assurance,
        final_strict,
        preserved_auth_time,
    )
    .await
    {
        cookies.add(session::clear_session_cookie());
        return r;
    }

    let (favorites_count, _, _) = query_account_d1_stats(
        &st,
        &preserved.user_id,
        &preserved.account_do_key,
    )
    .await
    .unwrap_or((0, 0, 0));
    let final_identities = identity::list_user_identities(&st, &preserved.user_id)
        .await
        .unwrap_or_default();

    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(ConfirmMergeResp {
            merge_id,
            preserved_user_id: preserved.user_id,
            abandoned_user_id: abandoned.user_id,
            paid_balance_moved: drained.credits.paid_balance_transfer,
            plan_refund_moved: drained.credits.plan_refund_paid,
            total_credits_added: drained.credits.total_transferable,
            free_credits_forfeited: drained.credits.total_free_forfeited,
            new_balance: received.balance,
            favorites_count,
            identities_count: final_identities.len(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn favorites_mode_maps_preserve_and_choice_accurately() {
        assert_eq!(
            resolve_favorites_mode(PreserveTarget::Current, FavoritesChoice::Both),
            DbFavoritesMode::Both
        );
        assert_eq!(
            resolve_favorites_mode(PreserveTarget::Other, FavoritesChoice::Both),
            DbFavoritesMode::Both
        );
        assert_eq!(
            resolve_favorites_mode(PreserveTarget::Current, FavoritesChoice::KeepCurrent),
            DbFavoritesMode::KeepPreserved
        );
        assert_eq!(
            resolve_favorites_mode(PreserveTarget::Current, FavoritesChoice::KeepOther),
            DbFavoritesMode::KeepAbandoned
        );
        assert_eq!(
            resolve_favorites_mode(PreserveTarget::Other, FavoritesChoice::KeepOther),
            DbFavoritesMode::KeepPreserved
        );
        assert_eq!(
            resolve_favorites_mode(PreserveTarget::Other, FavoritesChoice::KeepCurrent),
            DbFavoritesMode::KeepAbandoned
        );
    }

    #[test]
    fn merge_session_assurance_never_forges_verified_18() {
        let strict = PublicSitePolicy {
            age_policy: AgeVerificationPolicy::StrictProviderVerified18,
            ..Default::default()
        };
        // Two non-verified sessions stay non-verified.
        assert_eq!(
            resolve_merge_session_assurance(
                &strict,
                AssuranceLevel::SelfAttestation,
                false,
                AssuranceLevel::None,
                false
            ),
            (AssuranceLevel::SelfAttestation, false)
        );
        // Unverified Verified18 flag without strict_age_ok is demoted to None.
        assert_eq!(
            resolve_merge_session_assurance(
                &strict,
                AssuranceLevel::Verified18,
                false,
                AssuranceLevel::None,
                false
            ),
            (AssuranceLevel::None, false)
        );
        // Freshly verified OIDC 18+ preserves Verified18 + strict_age_ok.
        assert_eq!(
            resolve_merge_session_assurance(
                &strict,
                AssuranceLevel::None,
                false,
                AssuranceLevel::Verified18,
                true
            ),
            (AssuranceLevel::Verified18, true)
        );
    }
}
