//! Unified identity layer (`users_v2` + `user_identities`) & revocable `v2` sessions
//! (fixes H7, H8, H9, H10).
//!
//! Security invariants:
//! - Legacy DO key preservation: ALWAYS address `UserAccount` DO via `users_v2.account_do_key`
//!   (`legacy_address` for migrated wallet users; `"usr:<uuid>"` for new accounts).
//! - ZERO email auto-linking: verified email is contact metadata only!
//! - Explicit linking requires an active recently-authenticated session (`auth_time <= 600s`),
//!   CSRF same-origin check, and atomic `INSERT` (conflict -> 409, never stealing ownership!).
//! - Payment-only wallets (`purpose = 'payment'`) NEVER confer login or age privilege!
//! - Unlinking a verified identity immediately revokes strict 18+ sessions and rotates session!

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use site_access::{
    AgeVerificationPolicy, AssuranceLevel, AuthProviderId, PolicyRef, PublicSitePolicy,
    SESSION_V2_VERSION, SessionContext, SessionV2Claims, sign_session_v2,
};
use tower_cookies::Cookies;
use wasm_bindgen::JsValue;

use crate::{
    AppState, config,
    do_client::{self, SessionIssueReq, SessionRevokeAllReq, TermsAcceptReq},
    session,
    types::ApiError,
};

/// Maximum session age allowed for sensitive identity linking mutations (10 minutes).
pub const REAUTH_MAX_AGE_SECS: u64 = 600;

fn api_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ApiError { error: msg.into() })).into_response()
}

fn internal_err() -> Response {
    api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

// ---------------------------------------------------------------------------
// Data Models
// ---------------------------------------------------------------------------

/// Verified active caller session backed by live `UserAccount` DO state.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub user_id: String,
    pub do_key: String,
    pub sid: Option<String>,
    pub ctx: SessionContext,
}

#[derive(Debug, Clone)]
pub struct VerifiedExternalIdentity {
    pub provider_id: AuthProviderId,
    pub issuer: String,
    pub subject: String,
    pub label: Option<String>,
    pub verified_email: Option<String>,
    pub assurance_level: AssuranceLevel,
    pub assurance_method: Option<String>,
    pub assurance_verified_at: Option<u64>,
    pub assurance_expires_at: Option<u64>,
}

impl VerifiedExternalIdentity {
    pub fn identity_key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.provider_id.as_str(),
            self.issuer,
            self.subject
        )
    }

    pub fn is_strict_age_verified(&self, now: u64) -> bool {
        self.provider_id.supports_strict_age_verification()
            && self.assurance_level == AssuranceLevel::Verified18
            && self.assurance_expires_at.is_none_or(|exp| exp > now)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedAccount {
    pub user_id: String,
    pub account_do_key: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub terms_version_accepted: Option<u32>,
    pub terms_digest_accepted: Option<String>,
    pub terms_accepted_at: Option<u64>,
    pub content_prefs_json: String,
    pub pref_version: u64,
    pub plan: Option<String>,
    pub banned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityView {
    pub provider_id: String,
    pub issuer: String,
    pub subject: String,
    pub purpose: String,
    pub label: Option<String>,
    pub verified_email: Option<String>,
    pub assurance_level: AssuranceLevel,
    pub assurance_method: Option<String>,
    pub assurance_verified_at: Option<u64>,
    pub assurance_expires_at: Option<u64>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredContentPrefs {
    pub enabled_switchers: Vec<PolicyRef>,
}

pub fn assurance_to_str(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::None => "none",
        AssuranceLevel::SelfAttestation => "self_attestation",
        AssuranceLevel::ProviderSelfReportedDob => "provider_self_reported_dob",
        AssuranceLevel::Verified18 => "verified_18",
    }
}

pub fn assurance_from_str(raw: &str) -> AssuranceLevel {
    match raw.trim() {
        "self_attestation" => AssuranceLevel::SelfAttestation,
        "provider_self_reported_dob" => AssuranceLevel::ProviderSelfReportedDob,
        "verified_18" => AssuranceLevel::Verified18,
        _ => AssuranceLevel::None,
    }
}

pub fn provider_from_str(raw: &str) -> Option<AuthProviderId> {
    match raw.trim() {
        "oidc_age_assurance" => Some(AuthProviderId::OidcAgeAssurance),
        "google" => Some(AuthProviderId::Google),
        "github" => Some(AuthProviderId::GitHub),
        "x" => Some(AuthProviderId::X),
        "discord" => Some(AuthProviderId::Discord),
        "email_otp" => Some(AuthProviderId::EmailOtp),
        "telegram" => Some(AuthProviderId::Telegram),
        "siwe" => Some(AuthProviderId::Siwe),
        "siws" => Some(AuthProviderId::Siws),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Pure Policy / Gating / Account Resolution Decisions (host-testable)
// ---------------------------------------------------------------------------

/// Checks whether a provider is currently enabled in `policy`.
/// On fresh zero-config deployments (`enabled_providers` empty and
/// `age_policy != StrictProviderVerified18`), SIWE and SIWS remain enabled
/// by default under both `Off` and `SelfAttestation`.
pub fn is_provider_enabled_in_policy(policy: &PublicSitePolicy, provider: AuthProviderId) -> bool {
    if policy.enabled_providers.is_empty() {
        return policy.age_policy != AgeVerificationPolicy::StrictProviderVerified18
            && matches!(provider, AuthProviderId::Siwe | AuthProviderId::Siws);
    }
    policy
        .enabled_providers
        .iter()
        .any(|p| p.id == provider && p.enabled)
}

/// Uniform login/unlock eligibility enforcement across ALL auth paths
/// (OAuth/OIDC, Email, Telegram, SIWE, SIWS, QR handoff, transfer claim).
pub fn check_login_provider_eligibility(
    policy: &PublicSitePolicy,
    provider: AuthProviderId,
    assurance_after_verify: Option<AssuranceLevel>,
) -> Result<(), &'static str> {
    if !provider.is_allowed_under(policy.age_policy) {
        return Err(
            "This sign-in provider is disabled under Strict Provider-Verified 18+ mode. \
             Use a configured Age-Assurance OIDC provider instead.",
        );
    }
    if !is_provider_enabled_in_policy(policy, provider) {
        return Err("This sign-in provider is not enabled by the site administrator.");
    }
    if policy.age_policy == AgeVerificationPolicy::StrictProviderVerified18
        && let Some(level) = assurance_after_verify
        && level != AssuranceLevel::Verified18
    {
        return Err(
            "Provider did not supply verified 18+ age assurance required by site policy.",
        );
    }
    Ok(())
}

/// Pure decision verifying whether an existing identity row may be used for login.
/// Enforces:
/// 1. Payment-only wallets (`purpose = 'payment'`) NEVER confer login or age privilege.
/// 2. Zero email auto-linking: matching only occurs on exact `(provider_id, issuer, subject)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginResolutionAction {
    UseExistingAccount(String),
    CreateNewAccount,
    RejectPaymentOnlyWallet,
}

pub fn decide_login_identity_resolution(
    exact_identity_match: Option<(&str, &str)>, // (user_id, purpose)
    _other_account_with_same_email: Option<&str>,
) -> LoginResolutionAction {
    // Intentionally ignore `_other_account_with_same_email`: ZERO email auto-linking!
    match exact_identity_match {
        Some((_, "payment")) => LoginResolutionAction::RejectPaymentOnlyWallet,
        Some((user_id, "login")) => LoginResolutionAction::UseExistingAccount(user_id.to_string()),
        Some(_) => LoginResolutionAction::RejectPaymentOnlyWallet,
        None => LoginResolutionAction::CreateNewAccount,
    }
}

/// Pure check for whether a session is fresh enough for sensitive identity linking.
pub fn is_recent_auth(session_created_at: u64, now: u64) -> bool {
    now.saturating_sub(session_created_at) <= REAUTH_MAX_AGE_SECS
}

/// Pure check for whether unlinking an identity requires revoking strict 18+ sessions.
pub fn unlink_requires_strict_revocation(
    unlinked_assurance: AssuranceLevel,
    unlinked_identity_key: &str,
    current_session_identity_key: Option<&str>,
) -> bool {
    unlinked_assurance == AssuranceLevel::Verified18
        || current_session_identity_key.is_some_and(|k| k == unlinked_identity_key)
}

// ---------------------------------------------------------------------------
// Live Session Enforcement & Issuance
// ---------------------------------------------------------------------------

/// Verify `ue_session` cookie AND check live `UserAccount` DO `/session-context`.
/// Clears cookie on revoked/invalid `sid` (`401`); returns `403` on banned account.
pub async fn require_active_session(
    st: &AppState,
    cookies: &Cookies,
) -> Result<ActiveSession, Response> {
    let Some(verified) = session::verify_cookie_session(
        cookies,
        &st.session_v2_secret,
        st.legacy_jwt_secret.as_deref().map(Vec::as_slice),
    ) else {
        return Err(api_err(StatusCode::UNAUTHORIZED, "not signed in"));
    };

    let ctx = match do_client::do_session_context(&st.env, verified.do_key(), verified.sid()).await
    {
        Ok(c) => c,
        Err(e) => {
            worker::console_error!("session-context DO failed: {e:?}");
            return Err(api_err(
                StatusCode::BAD_GATEWAY,
                "account service unavailable",
            ));
        }
    };

    if !ctx.active || ctx.banned || ctx.suspended {
        return Err(api_err(StatusCode::FORBIDDEN, "account banned or suspended"));
    }
    if !ctx.sid_valid {
        cookies.add(session::clear_session_cookie());
        return Err(api_err(StatusCode::UNAUTHORIZED, "session revoked or expired"));
    }

    Ok(ActiveSession {
        user_id: verified.user_id().to_string(),
        do_key: verified.do_key().to_string(),
        sid: verified.sid().map(str::to_string),
        ctx,
    })
}

/// Optional live session lookup (returns `None` when unauthenticated or revoked).
pub async fn optional_active_session(st: &AppState, cookies: &Cookies) -> Option<ActiveSession> {
    require_active_session(st, cookies).await.ok()
}

/// Generate a high-entropy random session ID.
pub fn generate_sid() -> Result<String, Response> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|e| {
        worker::console_error!("getrandom sid failed: {e:?}");
        internal_err()
    })?;
    Ok(format!("sid_{}", B64.encode(bytes)))
}

/// Issue a revocable `v2.` session in `UserAccount` DO (addressed by `account.account_do_key`)
/// and attach the signed `ue_session` cookie.
pub async fn issue_v2_session(
    st: &AppState,
    cookies: &Cookies,
    account: &ResolvedAccount,
    auth_method: &str,
    identity_key: &str,
    assurance_level: AssuranceLevel,
    strict_age_ok: bool,
) -> Result<String, Response> {
    issue_v2_session_with_auth_time(
        st,
        cookies,
        account,
        auth_method,
        identity_key,
        assurance_level,
        strict_age_ok,
        None,
    )
    .await
}

/// Same as [`issue_v2_session`], optionally preserving an earlier authentication timestamp
/// `auth_time` (used by device transfers so claiming a transfer never bypasses recent-auth checks, F8).
#[allow(clippy::too_many_arguments)]
pub async fn issue_v2_session_with_auth_time(
    st: &AppState,
    cookies: &Cookies,
    account: &ResolvedAccount,
    auth_method: &str,
    identity_key: &str,
    assurance_level: AssuranceLevel,
    strict_age_ok: bool,
    auth_time: Option<u64>,
) -> Result<String, Response> {
    if account.banned {
        return Err(api_err(StatusCode::FORBIDDEN, "account banned"));
    }
    let now = session::now_secs();
    let expires_at = now + config::SESSION_TTL_SECS;
    let sid = generate_sid()?;

    // Ensure DO exists & has signup grant applied (keyed strictly by account_do_key!).
    if let Err(e) = do_client::do_init(&st.env, &account.account_do_key).await {
        worker::console_error!("do_init failed for {}: {e:?}", account.account_do_key);
        return Err(internal_err());
    }

    let strict_flag = strict_age_ok && assurance_level == AssuranceLevel::Verified18;
    let issue_req = SessionIssueReq {
        sid: sid.clone(),
        auth_method: auth_method.to_string(),
        identity_key: identity_key.to_string(),
        assurance_level,
        strict_age_ok: strict_flag,
        expires_at,
        auth_time,
    };
    if let Err(e) = do_client::do_session_issue(&st.env, &account.account_do_key, &issue_req).await
    {
        worker::console_error!("do_session_issue failed: {e:?}");
        return Err(api_err(StatusCode::FORBIDDEN, "account banned or unavailable"));
    }

    // Mirror D1 accepted terms / prefs into DO if present (keeps DO authoritative on cold start).
    if let (Some(ver), Some(digest)) = (
        account.terms_version_accepted,
        account.terms_digest_accepted.as_ref(),
    ) {
        let _ = do_client::do_terms_accept(
            &st.env,
            &account.account_do_key,
            &TermsAcceptReq {
                terms_version: ver,
                terms_digest: digest.clone(),
                accepted_at: account.terms_accepted_at.unwrap_or(now),
                self_attestation: None,
                sid: Some(sid.clone()),
            },
        )
        .await;
    }

    let claims = SessionV2Claims {
        v: SESSION_V2_VERSION,
        sub: account.user_id.clone(),
        do_key: account.account_do_key.clone(),
        sid: sid.clone(),
        iat: now,
        exp: expires_at,
    };
    let token = sign_session_v2(&claims, &st.session_v2_secret).map_err(|e| {
        worker::console_error!("sign_session_v2 failed: {e:?}");
        internal_err()
    })?;
    cookies.add(session::make_session_cookie(
        token,
        config::SESSION_TTL_SECS as i64,
    ));
    Ok(sid)
}

// ---------------------------------------------------------------------------
// D1 Account & Identity Operations (`users_v2` + `user_identities`)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UserV2Row {
    id: String,
    account_do_key: String,
    display_name: Option<String>,
    email: Option<String>,
    terms_version_accepted: Option<i64>,
    terms_digest_accepted: Option<String>,
    terms_accepted_at: Option<i64>,
    content_prefs_json: String,
    #[serde(default = "default_pref_version_i64")]
    pref_version: i64,
    plan: Option<String>,
    banned: i64,
}

fn default_pref_version_i64() -> i64 {
    1
}

impl From<UserV2Row> for ResolvedAccount {
    fn from(r: UserV2Row) -> Self {
        Self {
            user_id: r.id,
            account_do_key: r.account_do_key,
            display_name: r.display_name,
            email: r.email,
            terms_version_accepted: r
                .terms_version_accepted
                .and_then(|v| u32::try_from(v).ok()),
            terms_digest_accepted: r.terms_digest_accepted,
            terms_accepted_at: r.terms_accepted_at.and_then(|v| u64::try_from(v).ok()),
            content_prefs_json: r.content_prefs_json,
            pref_version: r.pref_version.max(1) as u64,
            plan: r.plan,
            banned: r.banned != 0,
        }
    }
}

pub async fn load_account_by_id(
    st: &AppState,
    user_id: &str,
) -> Result<Option<ResolvedAccount>, Response> {
    let db = st.env.d1(crate::D1_BINDING).map_err(|e| {
        worker::console_error!("d1 binding failed: {e:?}");
        internal_err()
    })?;
    let row = db
        .prepare(
            "SELECT id, account_do_key, display_name, email, terms_version_accepted, \
             terms_digest_accepted, terms_accepted_at, content_prefs_json, pref_version, plan, banned \
             FROM users_v2 WHERE id = ?1",
        )
        .bind(&[user_id.into()])
        .map_err(|e| {
            worker::console_error!("load_account bind failed: {e:?}");
            internal_err()
        })?
        .first::<UserV2Row>(None)
        .await
        .map_err(|e| {
            worker::console_error!("load_account query failed: {e:?}");
            internal_err()
        })?;
    Ok(row.map(ResolvedAccount::from))
}

/// Resolve or create a `users_v2` account for a verified external login identity.
///
/// - Enforces `AgeVerificationPolicy` & provider enablement.
/// - Preserves legacy `account_do_key` for migrated wallet users.
/// - Refuses payment-only wallets (`purpose = 'payment'`) as login identities.
/// - NEVER auto-links accounts by email!
pub async fn resolve_or_create_login_account(
    st: &AppState,
    policy: &PublicSitePolicy,
    ident: &VerifiedExternalIdentity,
) -> Result<ResolvedAccount, Response> {
    if let Err(msg) = check_login_provider_eligibility(
        policy,
        ident.provider_id,
        Some(ident.assurance_level),
    ) {
        return Err(api_err(StatusCode::FORBIDDEN, msg));
    }

    let db = st.env.d1(crate::D1_BINDING).map_err(|e| {
        worker::console_error!("d1 binding failed: {e:?}");
        internal_err()
    })?;
    let now = session::now_secs();

    #[derive(Deserialize)]
    struct IdentMatchRow {
        user_id: String,
        purpose: String,
    }
    let existing = db
        .prepare(
            "SELECT user_id, purpose FROM user_identities \
             WHERE provider_id = ?1 AND issuer = ?2 AND subject = ?3",
        )
        .bind(&[
            ident.provider_id.as_str().into(),
            ident.issuer.as_str().into(),
            ident.subject.as_str().into(),
        ])
        .map_err(|_| internal_err())?
        .first::<IdentMatchRow>(None)
        .await
        .map_err(|e| {
            worker::console_error!("identity lookup failed: {e:?}");
            internal_err()
        })?;

    match decide_login_identity_resolution(
        existing
            .as_ref()
            .map(|r| (r.user_id.as_str(), r.purpose.as_str())),
        None,
    ) {
        LoginResolutionAction::RejectPaymentOnlyWallet => {
            return Err(api_err(
                StatusCode::CONFLICT,
                "this wallet is linked as a payment wallet on another account — unlink it there first",
            ));
        }
        LoginResolutionAction::UseExistingAccount(user_id) => {
            let Some(account) = load_account_by_id(st, &user_id).await? else {
                return Err(internal_err());
            };
            if account.banned {
                return Err(api_err(StatusCode::FORBIDDEN, "account banned"));
            }
            // Refresh last_login and identity provenance/assurance columns.
            let _ = db
                .prepare("UPDATE users_v2 SET last_login = ?1 WHERE id = ?2")
                .bind(&[(now as f64).into(), user_id.as_str().into()])
                .map_err(|_| internal_err())?
                .run()
                .await;
            let _ = db
                .prepare(
                    "UPDATE user_identities SET \
                        label = COALESCE(?1, label), \
                        verified_email = COALESCE(?2, verified_email), \
                        assurance_level = ?3, \
                        assurance_method = COALESCE(?4, assurance_method), \
                        assurance_verified_at = COALESCE(?5, assurance_verified_at), \
                        assurance_expires_at = ?6 \
                     WHERE provider_id = ?7 AND issuer = ?8 AND subject = ?9",
                )
                .bind(&[
                    opt_str_js(ident.label.as_deref()),
                    opt_str_js(ident.verified_email.as_deref()),
                    assurance_to_str(ident.assurance_level).into(),
                    opt_str_js(ident.assurance_method.as_deref()),
                    opt_u64_js(ident.assurance_verified_at),
                    opt_u64_js(ident.assurance_expires_at),
                    ident.provider_id.as_str().into(),
                    ident.issuer.as_str().into(),
                    ident.subject.as_str().into(),
                ])
                .map_err(|_| internal_err())?
                .run()
                .await;
            if session::is_valid_principal(&account.account_do_key)
                && let Ok(stmt) = db
                    .prepare("UPDATE users SET last_login = ?1 WHERE address = ?2")
                    .bind(&[(now as f64).into(), account.account_do_key.as_str().into()])
            {
                let _ = stmt.run().await;
            }
            return Ok(account);
        }
        LoginResolutionAction::CreateNewAccount => {}
    }

    // Legacy coexistence check for Solana wallets still linked in legacy `users.solana_address`.
    if ident.provider_id == AuthProviderId::Siws {
        #[derive(Deserialize)]
        struct LegacyLinkRow {
            #[allow(dead_code)]
            address: String,
        }
        if let Ok(Some(_)) = db
            .prepare("SELECT address FROM users WHERE solana_address = ?1")
            .bind(&[ident.subject.as_str().into()])
            .map_err(|_| internal_err())?
            .first::<LegacyLinkRow>(None)
            .await
        {
            return Err(api_err(
                StatusCode::CONFLICT,
                "this wallet is linked as a payment wallet on another account — unlink it there first",
            ));
        }
    }

    // Check if a legacy `users` row exists for this wallet (not yet backfilled into `users_v2`)
    // so we NEVER split a legacy wallet from its existing `UserAccount` DO!
    let (user_id, account_do_key, plan, banned, created_at) = if matches!(
        ident.provider_id,
        AuthProviderId::Siwe | AuthProviderId::Siws
    ) {
        #[derive(Deserialize)]
        struct LegacyUser {
            address: String,
            created_at: i64,
            plan: Option<String>,
            banned: i64,
        }
        // Adopt a legacy `users` row ONLY if it has NEVER been migrated into `users_v2`!
        // Once migrated (`users_v2.id = address` or `account_do_key = address`), intentionally
        // unlinking that wallet removes its `user_identities` row and MUST NOT allow re-adoption (F2).
        let legacy = db
            .prepare(
                "SELECT u.address, u.created_at, u.plan, u.banned \
                 FROM users u \
                 WHERE u.address = ?1 \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM users_v2 v \
                     WHERE v.id = u.address OR v.account_do_key = u.address \
                   )",
            )
            .bind(&[ident.subject.as_str().into()])
            .map_err(|_| internal_err())?
            .first::<LegacyUser>(None)
            .await
            .map_err(|_| internal_err())?;
        if let Some(lu) = legacy {
            if lu.banned != 0 {
                return Err(api_err(StatusCode::FORBIDDEN, "account banned"));
            }
            (
                lu.address.clone(),
                lu.address,
                lu.plan,
                false,
                lu.created_at.max(0) as u64,
            )
        } else {
            let new_id = uuid::Uuid::new_v4().to_string();
            let do_key = format!("usr:{new_id}");
            (new_id, do_key, None, false, now)
        }
    } else {
        // Brand-new non-wallet account: disjoint `usr:<uuid>` DO key, ZERO email auto-linking!
        let new_id = uuid::Uuid::new_v4().to_string();
        let do_key = format!("usr:{new_id}");
        (new_id, do_key, None, false, now)
    };

    // Atomically insert `users_v2` + `user_identities`.
    db.prepare(
        "INSERT OR IGNORE INTO users_v2 \
         (id, account_do_key, display_name, email, created_at, last_login, content_prefs_json, plan, banned) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, '{}', ?7, ?8)",
    )
    .bind(&[
        user_id.as_str().into(),
        account_do_key.as_str().into(),
        opt_str_js(ident.label.as_deref()),
        opt_str_js(ident.verified_email.as_deref()),
        (created_at as f64).into(),
        (now as f64).into(),
        opt_str_js(plan.as_deref()),
        if banned { 1.0 } else { 0.0 }.into(),
    ])
    .map_err(|_| internal_err())?
    .run()
    .await
    .map_err(|e| {
        worker::console_error!("users_v2 insert failed: {e:?}");
        internal_err()
    })?;

    let insert_ident = db
        .prepare(
            "INSERT INTO user_identities \
             (provider_id, issuer, subject, user_id, purpose, label, verified_email, \
              assurance_level, assurance_method, assurance_verified_at, assurance_expires_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, 'login', ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(&[
            ident.provider_id.as_str().into(),
            ident.issuer.as_str().into(),
            ident.subject.as_str().into(),
            user_id.as_str().into(),
            opt_str_js(ident.label.as_deref()),
            opt_str_js(ident.verified_email.as_deref()),
            assurance_to_str(ident.assurance_level).into(),
            opt_str_js(ident.assurance_method.as_deref()),
            opt_u64_js(ident.assurance_verified_at),
            opt_u64_js(ident.assurance_expires_at),
            (now as f64).into(),
        ])
        .map_err(|_| internal_err())?
        .run()
        .await;

    if let Err(e) = insert_ident {
        // Concurrent first-time login race: re-fetch existing owner cleanly.
        let msg = format!("{e:?}").to_lowercase();
        if msg.contains("constraint") || msg.contains("unique") {
            let row = db
                .prepare(
                    "SELECT user_id, purpose FROM user_identities \
                     WHERE provider_id = ?1 AND issuer = ?2 AND subject = ?3",
                )
                .bind(&[
                    ident.provider_id.as_str().into(),
                    ident.issuer.as_str().into(),
                    ident.subject.as_str().into(),
                ])
                .map_err(|_| internal_err())?
                .first::<IdentMatchRow>(None)
                .await
                .map_err(|_| internal_err())?;
            if let Some(r) = row {
                if r.purpose != "login" {
                    return Err(api_err(
                        StatusCode::CONFLICT,
                        "identity is linked as a payment wallet",
                    ));
                }
                if let Some(acct) = load_account_by_id(st, &r.user_id).await? {
                    if acct.banned {
                        return Err(api_err(StatusCode::FORBIDDEN, "account banned"));
                    }
                    return Ok(acct);
                }
            }
        }
        worker::console_error!("user_identities insert failed: {e:?}");
        return Err(internal_err());
    }

    Ok(ResolvedAccount {
        user_id,
        account_do_key,
        display_name: ident.label.clone(),
        email: ident.verified_email.clone(),
        terms_version_accepted: None,
        terms_digest_accepted: None,
        terms_accepted_at: None,
        content_prefs_json: "{}".to_string(),
        pref_version: 1,
        plan,
        banned,
    })
}

/// Verify caller has recently authenticated (`auth_time <= 600s`) before linking identities.
pub async fn require_recent_auth(
    st: &AppState,
    active: &ActiveSession,
) -> Result<(), Response> {
    let Some(sid) = active.sid.as_deref() else {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Please sign in again with a fresh session before linking a new identity.",
        ));
    };
    let info = do_client::do_session_info(&st.env, &active.do_key, sid)
        .await
        .map_err(|e| {
            worker::console_error!("session-info lookup failed: {e:?}");
            internal_err()
        })?;
    let Some(info) = info else {
        return Err(api_err(
            StatusCode::UNAUTHORIZED,
            "session expired; sign in again",
        ));
    };
    if !info.active || !is_recent_auth(info.created_at, session::now_secs()) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Recent authentication (within 10 minutes) is required to link a new identity. Sign in again and retry.",
        ));
    }
    Ok(())
}

/// Atomically link an additional identity (`purpose = 'login'` or `'payment'`) to `user_id`.
/// NEVER steals ownership from another account (UNIQUE PK conflict -> `409 Conflict`).
pub async fn link_identity_atomic(
    st: &AppState,
    user_id: &str,
    ident: &VerifiedExternalIdentity,
    purpose: &str,
) -> Result<(), Response> {
    if !matches!(purpose, "login" | "payment") {
        return Err(api_err(StatusCode::BAD_REQUEST, "invalid identity purpose"));
    }
    if purpose == "payment" && !ident.provider_id.is_payment_wallet() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "only Ethereum or Solana wallets may be linked as payment wallets",
        ));
    }

    let db = st.env.d1(crate::D1_BINDING).map_err(|_| internal_err())?;
    let now = session::now_secs();

    // Payment wallets NEVER store age assurance claims.
    let (assurance_str, assurance_method, verified_at, expires_at) = if purpose == "payment" {
        ("none", None, None, None)
    } else {
        (
            assurance_to_str(ident.assurance_level),
            ident.assurance_method.as_deref(),
            ident.assurance_verified_at,
            ident.assurance_expires_at,
        )
    };

    let res = db
        .prepare(
            "INSERT INTO user_identities \
             (provider_id, issuer, subject, user_id, purpose, label, verified_email, \
              assurance_level, assurance_method, assurance_verified_at, assurance_expires_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )
        .bind(&[
            ident.provider_id.as_str().into(),
            ident.issuer.as_str().into(),
            ident.subject.as_str().into(),
            user_id.into(),
            purpose.into(),
            opt_str_js(ident.label.as_deref()),
            opt_str_js(ident.verified_email.as_deref()),
            assurance_str.into(),
            opt_str_js(assurance_method),
            opt_u64_js(verified_at),
            opt_u64_js(expires_at),
            (now as f64).into(),
        ])
        .map_err(|_| internal_err())?
        .run()
        .await;

    if let Err(e) = res {
        let msg = format!("{e:?}").to_lowercase();
        if msg.contains("constraint") || msg.contains("unique") {
            return Err(api_err(
                StatusCode::CONFLICT,
                "This wallet or identity is already registered to another account. Use \"Link or Merge Sign-in Method\" below to fuse both accounts into one.",
            ));
        }
        worker::console_error!("link_identity_atomic failed: {e:?}");
        return Err(internal_err());
    }
    Ok(())
}

/// List all identities linked to `user_id`.
pub async fn list_user_identities(
    st: &AppState,
    user_id: &str,
) -> Result<Vec<IdentityView>, Response> {
    #[derive(Deserialize)]
    struct Row {
        provider_id: String,
        issuer: String,
        subject: String,
        purpose: String,
        label: Option<String>,
        verified_email: Option<String>,
        assurance_level: String,
        assurance_method: Option<String>,
        assurance_verified_at: Option<i64>,
        assurance_expires_at: Option<i64>,
        created_at: i64,
    }
    let db = st.env.d1(crate::D1_BINDING).map_err(|_| internal_err())?;
    let rows = db
        .prepare(
            "SELECT provider_id, issuer, subject, purpose, label, verified_email, \
             assurance_level, assurance_method, assurance_verified_at, assurance_expires_at, created_at \
             FROM user_identities WHERE user_id = ?1 ORDER BY created_at ASC",
        )
        .bind(&[user_id.into()])
        .map_err(|_| internal_err())?
        .all()
        .await
        .map_err(|e| {
            worker::console_error!("list_user_identities failed: {e:?}");
            internal_err()
        })?
        .results::<Row>()
        .map_err(|_| internal_err())?;

    Ok(rows
        .into_iter()
        .map(|r| IdentityView {
            provider_id: r.provider_id,
            issuer: r.issuer,
            subject: r.subject,
            purpose: r.purpose,
            label: r.label,
            verified_email: r.verified_email,
            assurance_level: assurance_from_str(&r.assurance_level),
            assurance_method: r.assurance_method,
            assurance_verified_at: r.assurance_verified_at.and_then(|v| u64::try_from(v).ok()),
            assurance_expires_at: r.assurance_expires_at.and_then(|v| u64::try_from(v).ok()),
            created_at: r.created_at.max(0) as u64,
        })
        .collect())
}

/// Select a remaining `purpose == "login"` identity eligible under the live `SitePolicy`
/// for session rotation after unlinking an identity (fixes H7/H8, F6).
///
/// Security invariant (F6): rotation NEVER promotes session assurance above the caller's
/// prior active session `(prev_assurance, prev_strict_age_ok)`. A caller who signed in
/// with a wallet (`None`, `false`) MUST re-authenticate with their OIDC identity rather
/// than receiving a promoted `Verified18` session by unlinking their wallet.
pub fn select_rotation_fallback<'a>(
    policy: &PublicSitePolicy,
    remaining_login: &'a [&IdentityView],
    now: u64,
    prev_assurance: AssuranceLevel,
    prev_strict_age_ok: bool,
) -> Option<(&'a IdentityView, AssuranceLevel, bool)> {
    let mut candidate: Option<(&'a IdentityView, AssuranceLevel, bool)> = None;
    for ident in remaining_login {
        let Some(pid) = provider_from_str(&ident.provider_id) else {
            continue;
        };
        let ident_strict_ok = pid.supports_strict_age_verification()
            && ident.assurance_level == AssuranceLevel::Verified18
            && ident.assurance_expires_at.is_none_or(|e| e > now);
        let ident_assurance = if ident_strict_ok {
            AssuranceLevel::Verified18
        } else if ident.assurance_level == AssuranceLevel::Verified18 {
            AssuranceLevel::None
        } else {
            ident.assurance_level
        };

        // Cap strictly at caller's previous active session's assurance & strictness (F6).
        let capped_strict = ident_strict_ok && prev_strict_age_ok;
        let mut capped_assurance =
            if assurance_rank(ident_assurance) > assurance_rank(prev_assurance) {
                prev_assurance
            } else {
                ident_assurance
            };
        if capped_assurance == AssuranceLevel::Verified18 && !capped_strict {
            capped_assurance = AssuranceLevel::None;
        }

        if check_login_provider_eligibility(policy, pid, Some(capped_assurance)).is_ok() {
            if capped_strict {
                return Some((ident, capped_assurance, true));
            }
            if candidate.is_none() {
                candidate = Some((ident, capped_assurance, false));
            }
        }
    }
    candidate
}

fn assurance_rank(level: AssuranceLevel) -> u8 {
    match level {
        AssuranceLevel::None => 0,
        AssuranceLevel::SelfAttestation => 1,
        AssuranceLevel::ProviderSelfReportedDob => 2,
        AssuranceLevel::Verified18 => 3,
    }
}

/// Rotate the caller's session after linking a `purpose == "login"` identity (fixes H8 / Cycle 2 B-5):
/// verifies live `session-info`, requires acknowledged DO revocation of the old `active.sid` (503 on
/// failure), issues a fresh `v2.` session preserving `auth_time` unless freshly verified 18+, and
/// never misbinds `Verified18`/`strict_age_ok` to a non-OIDC identity on transient DO errors.
pub async fn rotate_session_on_identity_link(
    st: &AppState,
    cookies: &Cookies,
    active: &ActiveSession,
    linked_ident: &VerifiedExternalIdentity,
) -> Result<(), Response> {
    let cur_info = if let Some(sid) = active.sid.as_deref() {
        let info = do_client::do_session_info(&st.env, &active.do_key, sid)
            .await
            .map_err(|e| {
                worker::console_error!("link session-info failed: {e:?}");
                api_err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "account service unavailable; please retry",
                )
            })?;
        match info {
            Some(ci) if ci.active => Some(ci),
            _ => {
                cookies.add(session::clear_session_cookie());
                return Err(api_err(StatusCode::UNAUTHORIZED, "session revoked or expired"));
            }
        }
    } else {
        None
    };

    let Some(account) = load_account_by_id(st, &active.user_id).await? else {
        cookies.add(session::clear_session_cookie());
        return Err(api_err(StatusCode::UNAUTHORIZED, "account not found"));
    };

    if let Some(sid) = active.sid.as_deref() {
        do_client::do_session_revoke(&st.env, &active.do_key, sid)
            .await
            .map_err(|e| {
                worker::console_error!("link session-revoke failed: {e:?}");
                api_err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "could not rotate session cleanly; please retry",
                )
            })?;
    }

    let now = session::now_secs();
    let linked_strict = linked_ident.is_strict_age_verified(now);
    let (auth_method, identity_key, assurance_level, strict_age_ok, preserved_auth_time) =
        if linked_strict {
            (
                linked_ident.provider_id.as_str().to_string(),
                linked_ident.identity_key(),
                AssuranceLevel::Verified18,
                true,
                None,
            )
        } else if let Some(ci) = cur_info {
            let best_assurance = if assurance_rank(linked_ident.assurance_level)
                > assurance_rank(ci.assurance_level)
            {
                linked_ident.assurance_level
            } else {
                ci.assurance_level
            };
            (
                ci.auth_method,
                ci.identity_key,
                best_assurance,
                ci.strict_age_ok && best_assurance == AssuranceLevel::Verified18,
                Some(ci.created_at),
            )
        } else {
            // Legacy cutover cookie (`sid: None`) has no `strict_age_ok` OIDC provenance.
            (
                linked_ident.provider_id.as_str().to_string(),
                linked_ident.identity_key(),
                linked_ident.assurance_level,
                false,
                None,
            )
        };

    issue_v2_session_with_auth_time(
        st,
        cookies,
        &account,
        &auth_method,
        &identity_key,
        assurance_level,
        strict_age_ok,
        preserved_auth_time,
    )
    .await?;
    Ok(())
}

/// Unlink an identity from `user_id`, atomically refusing to remove the last remaining
/// login identity (F14). Requires acknowledged DO session revocation (F10 — retryable if
/// a prior attempt deleted the D1 row before DO failed), and rotates the caller's session
/// ONLY onto a remaining login identity without ever promoting session assurance (F6).
pub async fn unlink_identity(
    st: &AppState,
    cookies: &Cookies,
    active: &ActiveSession,
    provider_id: &str,
    issuer: &str,
    subject: &str,
) -> Result<bool, Response> {
    let identities = list_user_identities(st, &active.user_id).await?;
    let unlinked_key = format!("{provider_id}|{issuer}|{subject}");

    let Some(target) = identities.iter().find(|i| {
        i.provider_id == provider_id && i.issuer == issuer && i.subject == subject
    }) else {
        // Retryable revocation path (F10): if an earlier unlink deleted the D1 row
        // and then failed to reach `UserAccount` DO, repeating the unlink completes
        // revoking any lingering active sessions bound to `unlinked_key` atomically!
        let is_oidc_strict = provider_id == AuthProviderId::OidcAgeAssurance.as_str();
        let rev = do_client::do_session_revoke_all(
            &st.env,
            &active.do_key,
            &SessionRevokeAllReq {
                identity_key: Some(unlinked_key.clone()),
                strict_only: is_oidc_strict,
                revoke_sid: if is_oidc_strict {
                    active.sid.clone()
                } else {
                    None
                },
                invalidate_legacy: subject == active.do_key,
            },
        )
        .await
        .map_err(|e| {
            worker::console_error!("unlink retry DO session revoke failed: {e:?}");
            api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "could not revoke sessions for unlinked identity; please retry",
            )
        })?;
        if rev.revoked > 0 {
            if let Some(sid) = active.sid.as_deref()
                && do_client::do_session_info(&st.env, &active.do_key, sid)
                    .await
                    .ok()
                    .flatten()
                    .is_none_or(|info| !info.active)
            {
                cookies.add(session::clear_session_cookie());
                return Ok(true);
            }
            return Ok(false);
        }
        return Err(api_err(StatusCode::NOT_FOUND, "linked identity not found"));
    };

    if target.purpose == "login" {
        let login_count = identities.iter().filter(|i| i.purpose == "login").count();
        if login_count <= 1 {
            return Err(api_err(
                StatusCode::CONFLICT,
                "cannot unlink your only sign-in method",
            ));
        }
    }

    // Fetch current session metadata BEFORE deleting/revoking so we know whether caller's
    // own session is affected and its exact pre-rotation assurance cap (F6).
    let cur_info = if let Some(sid) = active.sid.as_deref() {
        do_client::do_session_info(&st.env, &active.do_key, sid)
            .await
            .map_err(|e| {
                worker::console_error!("unlink session-info failed: {e:?}");
                api_err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "account service unavailable; please retry",
                )
            })?
    } else {
        None
    };

    // Atomic guarded DELETE (F14): concurrent unlinks can NEVER delete the final login identity!
    let db = st.env.d1(crate::D1_BINDING).map_err(|_| internal_err())?;
    let del_res = db
        .prepare(
            "DELETE FROM user_identities \
             WHERE user_id = ?1 AND provider_id = ?2 AND issuer = ?3 AND subject = ?4 \
               AND ( \
                 purpose != 'login' \
                 OR (SELECT COUNT(*) FROM user_identities WHERE user_id = ?1 AND purpose = 'login') > 1 \
               )",
        )
        .bind(&[
            active.user_id.as_str().into(),
            provider_id.into(),
            issuer.into(),
            subject.into(),
        ])
        .map_err(|_| internal_err())?
        .run()
        .await
        .map_err(|e| {
            worker::console_error!("unlink_identity delete failed: {e:?}");
            internal_err()
        })?;

    let deleted_rows = del_res
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.changes)
        .unwrap_or(0);
    if deleted_rows == 0 {
        if target.purpose == "login" {
            return Err(api_err(
                StatusCode::CONFLICT,
                "cannot unlink your only sign-in method",
            ));
        }
        return Err(api_err(StatusCode::NOT_FOUND, "linked identity not found"));
    }

    // Keep legacy `users.solana_address` column clean if unlinking a payment Solana wallet.
    if provider_id == "siws"
        && target.purpose == "payment"
        && let Ok(stmt) = db
            .prepare(
                "UPDATE users SET solana_address = NULL WHERE address = ?1 AND solana_address = ?2",
            )
            .bind(&[active.user_id.as_str().into(), subject.into()])
    {
        let _ = stmt.run().await;
    }

    let needs_rotation = unlink_requires_strict_revocation(
        target.assurance_level,
        &unlinked_key,
        cur_info.as_ref().map(|i| i.identity_key.as_str()),
    );
    let revoke_identity_key = (target.purpose == "login").then(|| unlinked_key.clone());
    let revoke_strict = needs_rotation && target.assurance_level == AssuranceLevel::Verified18;
    let revoke_caller_sid = if needs_rotation {
        active.sid.clone()
    } else {
        None
    };
    let invalidate_legacy = target.purpose == "login" && subject == active.do_key;

    // Perform ALL required DO session revocations (bound identity, strict 18+, caller's
    // active sid on rotation, and legacy cutover cookies when unlinking the legacy wallet)
    // in ONE atomic DO RPC (Cycle 2 B-2 / F10).
    if revoke_identity_key.is_some()
        || revoke_strict
        || revoke_caller_sid.is_some()
        || invalidate_legacy
    {
        do_client::do_session_revoke_all(
            &st.env,
            &active.do_key,
            &SessionRevokeAllReq {
                identity_key: revoke_identity_key,
                strict_only: revoke_strict,
                revoke_sid: revoke_caller_sid,
                invalidate_legacy,
            },
        )
        .await
        .map_err(|e| {
            worker::console_error!("unlink DO atomic revoke failed: {e:?}");
            api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity removed, but session revocation failed; retry the unlink to complete revocation",
            )
        })?;
    }

    if needs_rotation {
        // Rotate the caller's session ONLY onto a remaining login identity permitted by live
        // SitePolicyDO, strictly capped at caller's previous session assurance (F6), and
        // preserving original `auth_time` so unlinking never refreshes recent-auth (Cycle 2 B-2)!
        let now = session::now_secs();
        let remaining_login: Vec<&IdentityView> = identities
            .iter()
            .filter(|i| {
                i.purpose == "login"
                    && !(i.provider_id == provider_id
                        && i.issuer == issuer
                        && i.subject == subject)
            })
            .collect();

        let (prev_assurance, prev_strict) = match cur_info.as_ref() {
            Some(ci) => (ci.assurance_level, ci.strict_age_ok),
            None => (active.ctx.assurance_level, active.ctx.strict_age_ok),
        };
        let preserved_auth_time = cur_info.as_ref().map(|ci| ci.created_at);

        let live_policy = crate::policy_do::load_site_policy(&st.env)
            .await
            .ok()
            .map(|e| e.policy);

        if let Some(policy) = live_policy.as_ref()
            && let Some(account) = load_account_by_id(st, &active.user_id).await?
            && let Some((fallback, eff_assurance, fallback_strict)) = select_rotation_fallback(
                policy,
                &remaining_login,
                now,
                prev_assurance,
                prev_strict,
            )
        {
            let fallback_key = format!(
                "{}|{}|{}",
                fallback.provider_id, fallback.issuer, fallback.subject
            );
            if issue_v2_session_with_auth_time(
                st,
                cookies,
                &account,
                &fallback.provider_id,
                &fallback_key,
                eff_assurance,
                fallback_strict,
                preserved_auth_time,
            )
            .await
            .is_err()
            {
                cookies.add(session::clear_session_cookie());
            }
        } else {
            cookies.add(session::clear_session_cookie());
        }
        return Ok(true);
    }

    Ok(false)
}

/// Find the user's linked Ethereum wallet address (login OR payment purpose) for ETH/ERC-20 top-ups.
/// For migrated `users_v2` accounts, `user_identities` is authoritative so unlinked legacy wallets
/// can NEVER steal another user's deposits (Cycle 2 B-1).
pub async fn linked_eth_wallet(st: &AppState, user_id: &str) -> worker::Result<Option<String>> {
    #[derive(Deserialize)]
    struct Row {
        subject: String,
    }
    #[derive(Deserialize)]
    struct ExistsRow {
        #[allow(dead_code)]
        found: i64,
    }
    let db = st.env.d1(crate::D1_BINDING)?;
    let row = db
        .prepare(
            "SELECT subject FROM user_identities \
             WHERE user_id = ?1 AND provider_id = 'siwe' \
             ORDER BY CASE WHEN purpose = 'payment' THEN 0 ELSE 1 END, created_at DESC LIMIT 1",
        )
        .bind(&[user_id.into()])?
        .first::<Row>(None)
        .await?;
    if let Some(r) = row {
        return Ok(Some(r.subject));
    }
    // Migrated `users_v2` accounts must have an active `user_identities` row.
    let in_v2 = db
        .prepare("SELECT 1 AS found FROM users_v2 WHERE id = ?1 LIMIT 1")
        .bind(&[user_id.into()])?
        .first::<ExistsRow>(None)
        .await?
        .is_some();
    if in_v2 {
        return Ok(None);
    }
    if session::is_eth_address(user_id) {
        let claimed = db
            .prepare("SELECT 1 AS found FROM user_identities WHERE provider_id = 'siwe' AND subject = ?1 LIMIT 1")
            .bind(&[user_id.into()])?
            .first::<ExistsRow>(None)
            .await?
            .is_some();
        if !claimed {
            return Ok(Some(user_id.to_string()));
        }
    }
    Ok(None)
}

/// Find the user's linked Solana wallet address (login OR payment purpose) for SOL/SPL top-ups.
/// For migrated `users_v2` accounts, `user_identities` is authoritative so unlinked legacy wallets
/// can NEVER steal another user's deposits (Cycle 2 B-1).
pub async fn linked_solana_wallet(st: &AppState, user_id: &str) -> worker::Result<Option<String>> {
    #[derive(Deserialize)]
    struct Row {
        subject: String,
    }
    #[derive(Deserialize)]
    struct ExistsRow {
        #[allow(dead_code)]
        found: i64,
    }
    let db = st.env.d1(crate::D1_BINDING)?;
    let row = db
        .prepare(
            "SELECT subject FROM user_identities \
             WHERE user_id = ?1 AND provider_id = 'siws' \
             ORDER BY CASE WHEN purpose = 'payment' THEN 0 ELSE 1 END, created_at DESC LIMIT 1",
        )
        .bind(&[user_id.into()])?
        .first::<Row>(None)
        .await?;
    if let Some(r) = row {
        return Ok(Some(r.subject));
    }
    // Migrated `users_v2` accounts must have an active `user_identities` row.
    let in_v2 = db
        .prepare("SELECT 1 AS found FROM users_v2 WHERE id = ?1 LIMIT 1")
        .bind(&[user_id.into()])?
        .first::<ExistsRow>(None)
        .await?
        .is_some();
    if in_v2 {
        return Ok(None);
    }
    let legacy_candidate = if session::is_sol_principal(user_id) {
        Some(user_id.to_string())
    } else {
        crate::solana_link::linked_address(&st.env, user_id).await?
    };
    if let Some(addr) = legacy_candidate {
        let claimed = db
            .prepare("SELECT 1 AS found FROM user_identities WHERE provider_id = 'siws' AND subject = ?1 LIMIT 1")
            .bind(&[addr.as_str().into()])?
            .first::<ExistsRow>(None)
            .await?
            .is_some();
        if !claimed {
            return Ok(Some(addr));
        }
    }
    Ok(None)
}

fn opt_str_js(v: Option<&str>) -> JsValue {
    match v {
        Some(s) => s.into(),
        None => JsValue::NULL,
    }
}

fn opt_u64_js(v: Option<u64>) -> JsValue {
    match v {
        Some(n) => (n as f64).into(),
        None => JsValue::NULL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use site_access::AuthProviderPublicConfig;

    fn policy_with_all_enabled(age_policy: AgeVerificationPolicy) -> PublicSitePolicy {
        PublicSitePolicy {
            age_policy,
            enabled_providers: AuthProviderId::ALL
                .into_iter()
                .map(|id| AuthProviderPublicConfig {
                    id,
                    enabled: true,
                    display_name: None,
                    issuer: Some("https://id.example.com".into()),
                    public_client_id: Some("cid".into()),
                    soft_birthday_check: false,
                })
                .collect(),
            ..PublicSitePolicy::default()
        }
    }

    #[test]
    fn strict_18_rejects_google_github_x_discord_email_telegram_siwe_siws() {
        let policy = policy_with_all_enabled(AgeVerificationPolicy::StrictProviderVerified18);

        for provider in AuthProviderId::ALL {
            if provider == AuthProviderId::OidcAgeAssurance {
                // OidcAgeAssurance allowed only when verified 18+
                assert!(
                    check_login_provider_eligibility(
                        &policy,
                        provider,
                        Some(AssuranceLevel::Verified18)
                    )
                    .is_ok()
                );
                // OidcAgeAssurance without Verified18 claim MUST be rejected
                assert!(
                    check_login_provider_eligibility(&policy, provider, Some(AssuranceLevel::None))
                        .is_err()
                );
                assert!(
                    check_login_provider_eligibility(
                        &policy,
                        provider,
                        Some(AssuranceLevel::SelfAttestation)
                    )
                    .is_err()
                );
            } else {
                // Google (even with DOB), GitHub, X, Discord, Email, Telegram, SIWE, SIWS MUST fail!
                assert!(
                    check_login_provider_eligibility(&policy, provider, None).is_err(),
                    "{provider:?} must be rejected under StrictProviderVerified18"
                );
                assert!(
                    check_login_provider_eligibility(
                        &policy,
                        provider,
                        Some(AssuranceLevel::ProviderSelfReportedDob)
                    )
                    .is_err(),
                    "{provider:?} with ProviderSelfReportedDob must be rejected under StrictProviderVerified18"
                );
            }
        }
    }

    #[test]
    fn zero_email_auto_linking_and_payment_wallet_rejection() {
        // Even when another account owns the exact same verified email, a new provider
        // identity MUST create a distinct new account (NEVER auto-link!).
        assert_eq!(
            decide_login_identity_resolution(None, Some("existing-user-with-same-email")),
            LoginResolutionAction::CreateNewAccount
        );

        // Payment-only wallet (`purpose = 'payment'`) MUST NEVER confer login privilege!
        assert_eq!(
            decide_login_identity_resolution(Some(("user-1", "payment")), None),
            LoginResolutionAction::RejectPaymentOnlyWallet
        );

        // Exact `(provider_id, issuer, subject)` with `purpose = 'login'` logs into that user.
        assert_eq!(
            decide_login_identity_resolution(Some(("user-1", "login")), None),
            LoginResolutionAction::UseExistingAccount("user-1".to_string())
        );
    }

    #[test]
    fn unlink_verified_identity_triggers_strict_revocation() {
        assert!(unlink_requires_strict_revocation(
            AssuranceLevel::Verified18,
            "oidc_age_assurance|https://id.example.com|sub1",
            Some("google|https://accounts.google.com|g1")
        ));
        assert!(unlink_requires_strict_revocation(
            AssuranceLevel::None,
            "github|https://github.com|42",
            Some("github|https://github.com|42")
        ));
        assert!(!unlink_requires_strict_revocation(
            AssuranceLevel::None,
            "siws|solana:mainnet|7Np...",
            Some("google|https://accounts.google.com|g1")
        ));
    }

    #[test]
    fn reauth_window_enforces_600s_limit() {
        assert!(is_recent_auth(1000, 1000));
        assert!(is_recent_auth(1000, 1600));
        assert!(!is_recent_auth(1000, 1601));
    }

    #[test]
    fn unlink_rotation_enforces_live_policy_and_strict_18() {
        let github = IdentityView {
            provider_id: "github".into(),
            issuer: "https://github.com".into(),
            subject: "gh-1".into(),
            purpose: "login".into(),
            label: None,
            verified_email: None,
            assurance_level: AssuranceLevel::None,
            assurance_method: None,
            assurance_verified_at: None,
            assurance_expires_at: None,
            created_at: 100,
        };
        let oidc_valid = IdentityView {
            provider_id: "oidc_age_assurance".into(),
            issuer: "https://age.example.com".into(),
            subject: "age-2".into(),
            purpose: "login".into(),
            label: None,
            verified_email: None,
            assurance_level: AssuranceLevel::Verified18,
            assurance_method: Some("age_over_18".into()),
            assurance_verified_at: Some(900),
            assurance_expires_at: Some(2000),
            created_at: 200,
        };
        let oidc_expired = IdentityView {
            assurance_expires_at: Some(999),
            ..oidc_valid.clone()
        };

        let strict_policy = PublicSitePolicy {
            age_policy: AgeVerificationPolicy::StrictProviderVerified18,
            enabled_providers: vec![
                AuthProviderPublicConfig {
                    id: AuthProviderId::GitHub,
                    enabled: true,
                    display_name: None,
                    issuer: None,
                    public_client_id: Some("gh".into()),
                    soft_birthday_check: false,
                },
                AuthProviderPublicConfig {
                    id: AuthProviderId::OidcAgeAssurance,
                    enabled: true,
                    display_name: None,
                    issuer: Some("https://age.example.com".into()),
                    public_client_id: Some("oidc".into()),
                    soft_birthday_check: false,
                },
            ],
            ..Default::default()
        };

        // Under Strict 18+, GitHub-only remaining identity MUST NOT receive a rotated session.
        assert!(
            select_rotation_fallback(
                &strict_policy,
                &[&github],
                1000,
                AssuranceLevel::Verified18,
                true
            )
            .is_none()
        );
        // Expired Verified18 OIDC MUST also be rejected under Strict 18+.
        assert!(
            select_rotation_fallback(
                &strict_policy,
                &[&oidc_expired],
                1000,
                AssuranceLevel::Verified18,
                true
            )
            .is_none()
        );
        // Already-verified session with another unexpired Verified18 OIDC keeps Verified18.
        let both = [&github, &oidc_valid];
        let picked = select_rotation_fallback(
            &strict_policy,
            &both,
            1000,
            AssuranceLevel::Verified18,
            true,
        );
        assert!(matches!(picked, Some((_, AssuranceLevel::Verified18, true))));

        // F6: Unlinking a wallet/unverified session (`None, false`) MUST NEVER promote to
        // Verified18 even when a verified OIDC identity is linked! Under Strict 18+, returns None
        // (clearing session cookie to force fresh OIDC login); under SelfAttestation, caps at None/false!
        assert!(
            select_rotation_fallback(&strict_policy, &both, 1000, AssuranceLevel::None, false)
                .is_none(),
            "wallet session must NOT be promoted to Verified18 under Strict 18+"
        );
        let mut self_attest_policy = strict_policy.clone();
        self_attest_policy.age_policy = AgeVerificationPolicy::SelfAttestation;
        let oidc_only = [&oidc_valid];
        let capped = select_rotation_fallback(
            &self_attest_policy,
            &oidc_only,
            1000,
            AssuranceLevel::None,
            false,
        );
        assert!(
            matches!(capped, Some((_, AssuranceLevel::None, false))),
            "unverified session rotated onto OIDC must be capped at (None, false), got {capped:?}"
        );

        // Under Off mode, a disabled provider MUST NOT be rotated onto.
        let disabled_policy = PublicSitePolicy {
            age_policy: AgeVerificationPolicy::Off,
            enabled_providers: vec![],
            ..Default::default()
        };
        assert!(
            select_rotation_fallback(
                &disabled_policy,
                &[&github],
                1000,
                AssuranceLevel::None,
                false
            )
            .is_none()
        );
    }
}
