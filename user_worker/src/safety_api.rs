//! Public policy, user safety preferences, versioned Terms acceptance,
//! rate-limited content reports, and explicit identity link/unlink endpoints.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderName, StatusCode, header},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use site_access::{
    AgeVerificationPolicy, AssuranceLevel, AuthProviderId, PublicSitePolicy, RuleMode,
    canonical_policy_json,
};
use tower_cookies::Cookies;

use crate::{
    AppState, auth, challenge_do, config,
    do_client::{self, PrefsUpdateReq, SessionRevokeAllReq, TermsAcceptReq},
    identity::{self, StoredContentPrefs, VerifiedExternalIdentity},
    policy_do,
    providers::oauth::begin_oauth_flow,
    session, settings, siwe, solana_link,
    types::ApiError,
};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_REPORT_NOTE_CHARS: usize = 500;
pub const REPORT_RATE_LIMIT_PER_HOUR: u32 = 5;
pub const ALLOWED_REPORT_REASONS: &[&str] = &[
    "illegal_content",
    "underage",
    "non_consensual",
    "violence_gore",
    "copyright_dmca",
    "misclassified_safety",
    "spam_other",
];

// ---------------------------------------------------------------------------
// Pure Validation Logic (host-testable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermsAcceptDecision {
    Accepted { self_attested: bool },
    VersionOrDigestMismatch,
}

/// Pure version + digest race check for `POST /user/api/accept_terms`.
pub fn evaluate_terms_acceptance(
    policy: &PublicSitePolicy,
    req_version: u32,
    req_digest: &str,
    req_self_attestation: Option<bool>,
) -> TermsAcceptDecision {
    if req_version != policy.legal.terms_version
        || !req_digest
            .trim()
            .eq_ignore_ascii_case(policy.legal.terms_digest.trim())
    {
        return TermsAcceptDecision::VersionOrDigestMismatch;
    }
    let self_attested = req_self_attestation == Some(true)
        && policy.age_policy == AgeVerificationPolicy::SelfAttestation;
    TermsAcceptDecision::Accepted { self_attested }
}

/// Pure validation for `POST /user/api/reports`.
pub fn validate_report_input(
    target_kind: &str,
    target_id: i64,
    reason: &str,
    note: Option<&str>,
) -> Result<Option<String>, &'static str> {
    if !matches!(target_kind, "post" | "image" | "video") {
        return Err("invalid target_kind (must be post, image, or video)");
    }
    if target_id <= 0 {
        return Err("target_id must be positive");
    }
    if !ALLOWED_REPORT_REASONS.contains(&reason.trim()) {
        return Err("invalid report reason");
    }
    let cleaned_note = match note {
        None => None,
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.chars().count() > MAX_REPORT_NOTE_CHARS {
                return Err("report note exceeds 500 characters");
            } else if trimmed
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
            {
                return Err("report note contains disallowed control characters");
            } else {
                Some(trimmed.to_string())
            }
        }
    };
    Ok(cleaned_note)
}

/// Filter requested switcher IDs strictly against enabled Switcher rules in `policy`.
pub fn filter_valid_switchers(policy: &PublicSitePolicy, requested: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in requested {
        let trimmed = id.trim();
        if policy
            .rules
            .iter()
            .any(|r| r.enabled && r.mode == RuleMode::Switcher && r.id == trimmed)
            && !out.iter().any(|s| s == trimmed)
        {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn salted_reporter_key(secret: &[u8], user_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(b"report-key/v1\0");
    mac.update(user_id.as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..16])
}

// ---------------------------------------------------------------------------
// GET /user/api/policy (Public allowlist + POLICY_URL for lets-embed-web)
// ---------------------------------------------------------------------------

#[worker::send]
pub async fn get_policy(State(st): State<AppState>) -> Response {
    let env = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e,
        Err(e) => {
            worker::console_error!("get_policy: SitePolicyDO failed: {e:?}");
            return auth::api_error(StatusCode::SERVICE_UNAVAILABLE, "site policy unavailable");
        }
    };
    let canonical = canonical_policy_json(&env.policy);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8".to_string()),
            (header::CACHE_CONTROL, "private, no-store".to_string()),
            (HeaderName::from_static("x-policy-digest"), env.digest),
        ],
        canonical,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /user/api/bootstrap (Public SPA config for /user/login & /user/upgrade)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct BootstrapResp {
    siwe_domain: String,
    public_url: String,
    chain_id: u64,
    policy: PublicSitePolicy,
    policy_digest: String,
    signed_in: bool,
    deposit_open: bool,
    points_per_usd: i64,
    minimum_topup: i64,
}

#[worker::send]
pub async fn bootstrap(State(st): State<AppState>, cookies: Cookies) -> Response {
    let env = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e,
        Err(e) => {
            worker::console_error!("bootstrap: SitePolicyDO failed: {e:?}");
            return auth::api_error(StatusCode::SERVICE_UNAVAILABLE, "site policy unavailable");
        }
    };
    let access_policy = settings::load(&st.env).await.unwrap_or_default();
    let deposit_open = settings::valid_deposit_address(config::Chain::Ethereum, &access_policy.eth_deposit)
        || settings::valid_deposit_address(config::Chain::Solana, &access_policy.sol_deposit);
    let signed_in = identity::optional_active_session(&st, &cookies).await.is_some();

    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(BootstrapResp {
            siwe_domain: st.siwe_domain.as_ref().clone(),
            public_url: st.public_origin().to_string(),
            chain_id: st.chain_id,
            policy: env.policy,
            policy_digest: env.digest,
            signed_in,
            deposit_open,
            points_per_usd: access_policy.points_per_usd,
            minimum_topup: access_policy.minimum_topup,
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /user/api/preferences
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PreferencesReq {
    #[serde(default)]
    pub enabled_switchers: Option<Vec<String>>,
    #[serde(default)]
    pub safe_mode: Option<bool>,
}

/// Parse persisted `StoredContentPrefs` from D1 `users_v2.content_prefs_json`.
pub fn parse_stored_content_prefs(raw: Option<&str>) -> Option<StoredContentPrefs> {
    let json = raw?.trim();
    if json.is_empty() {
        return None;
    }
    serde_json::from_str::<StoredContentPrefs>(json).ok()
}

/// Resolve the user's saved `enabled_switchers` filtered against the live `policy`.
///
/// Reads persisted D1 `users_v2.content_prefs_json` so saved switchers survive
/// Safe Mode (when `SessionContext.enabled_switchers` is fail-closed `[]`),
/// falling back to `ctx_switchers` only when no persisted D1 row exists (or an
/// uninitialized `{}` D1 row coexists with non-empty live DO switchers).
pub fn resolve_saved_switchers(
    policy: &PublicSitePolicy,
    content_prefs_json: Option<&str>,
    ctx_switchers: &[String],
) -> Vec<String> {
    let raw = match parse_stored_content_prefs(content_prefs_json) {
        Some(prefs) => {
            if prefs.enabled_switchers.is_empty() && !ctx_switchers.is_empty() {
                ctx_switchers.to_vec()
            } else {
                prefs.enabled_switchers
            }
        }
        None => ctx_switchers.to_vec(),
    };
    filter_valid_switchers(policy, &raw)
}

/// Pure partial-update resolver for `POST /user/api/preferences`:
/// omitting `enabled_switchers` (e.g. Safe Mode panic toggle sending `{"safe_mode": true}`)
/// preserves existing saved switchers; omitting `safe_mode` preserves existing `safe_mode`.
pub fn resolve_preferences_update(
    policy: &PublicSitePolicy,
    existing_switchers: &[String],
    existing_safe_mode: bool,
    req: &PreferencesReq,
) -> (Vec<String>, bool) {
    let raw_switchers = req
        .enabled_switchers
        .as_deref()
        .unwrap_or(existing_switchers);
    let filtered = filter_valid_switchers(policy, raw_switchers);
    let next_safe = req.safe_mode.unwrap_or(existing_safe_mode);
    (filtered, next_safe)
}

#[derive(Debug, Serialize)]
struct PreferencesResp {
    enabled_switchers: Vec<String>,
    safe_mode: bool,
    effective_switchers: Vec<String>,
}

#[worker::send]
pub async fn update_preferences(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<PreferencesReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(e) => {
            worker::console_error!("preferences: policy load failed: {e:?}");
            return auth::internal_error();
        }
    };

    // Load persisted `users_v2.content_prefs_json` from D1 so toggling Safe Mode
    // (`true -> false`) never uses the fail-closed empty `active.ctx.enabled_switchers`
    // to wipe saved switchers. Fail closed on D1 read errors to avoid silent data loss.
    let account = match identity::load_account_by_id(&st, &active.user_id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let existing_switchers = resolve_saved_switchers(
        &policy,
        account.as_ref().map(|a| a.content_prefs_json.as_str()),
        &active.ctx.enabled_switchers,
    );

    let (filtered, next_safe) = resolve_preferences_update(
        &policy,
        &existing_switchers,
        active.ctx.safe_mode,
        &req,
    );
    let prefs_json = match serde_json::to_string(&StoredContentPrefs {
        enabled_switchers: filtered.clone(),
        safe_mode: next_safe,
    }) {
        Ok(s) => s,
        Err(_) => return auth::internal_error(),
    };

    // Persist in D1 `users_v2` AND update live `UserAccount` DO immediately!
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("preferences D1 binding failed: {e:?}");
            return auth::internal_error();
        }
    };
    let stmt = match db
        .prepare("UPDATE users_v2 SET content_prefs_json = ?1 WHERE id = ?2")
        .bind(&[prefs_json.into(), active.user_id.as_str().into()])
    {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("preferences D1 bind failed: {e:?}");
            return auth::internal_error();
        }
    };
    if let Err(e) = stmt.run().await {
        worker::console_error!("preferences D1 write failed: {e:?}");
        return auth::internal_error();
    }

    // If this is a partial Safe Mode toggle for a legacy session with no `users_v2` row,
    // omit `enabled_switchers` on DO `/prefs-update` so DO preserves `user_safety_state`.
    let preserve_do_switchers = req.enabled_switchers.is_none() && account.is_none();
    if preserve_do_switchers {
        let partial_body = serde_json::json!({ "safe_mode": next_safe });
        match do_client::call_do(
            &st.env,
            &active.do_key,
            worker::Method::Post,
            "/prefs-update",
            Some(&partial_body),
        )
        .await
        {
            Ok(resp) if resp.status_code() == 200 => {}
            Ok(resp) => {
                worker::console_error!(
                    "preferences partial DO update failed: HTTP {}",
                    resp.status_code()
                );
                return auth::internal_error();
            }
            Err(e) => {
                worker::console_error!("preferences partial DO update failed: {e:?}");
                return auth::internal_error();
            }
        }
    } else if let Err(e) = do_client::do_prefs_update(
        &st.env,
        &active.do_key,
        &PrefsUpdateReq {
            enabled_switchers: filtered.clone(),
            safe_mode: next_safe,
        },
    )
    .await
    {
        worker::console_error!("preferences DO update failed: {e:?}");
        return auth::internal_error();
    }

    // Re-read authoritative session context to report effective unlocked switchers.
    let updated_ctx = do_client::do_session_context(&st.env, &active.do_key, active.sid.as_deref())
        .await
        .unwrap_or(active.ctx);
    let saved_switchers = if preserve_do_switchers && !next_safe {
        filter_valid_switchers(&policy, &updated_ctx.enabled_switchers)
    } else {
        filtered
    };
    let effective_switchers = updated_ctx.effective_switchers(&policy);

    Json(PreferencesResp {
        enabled_switchers: saved_switchers,
        safe_mode: next_safe,
        effective_switchers,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// POST /user/api/accept_terms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AcceptTermsReq {
    pub terms_version: u32,
    pub terms_digest: String,
    #[serde(default)]
    pub self_attestation: Option<bool>,
}

#[derive(Debug, Serialize)]
struct AcceptTermsConflictResp {
    error: &'static str,
    terms_version: u32,
    terms_digest: String,
    terms_md: String,
}

#[derive(Debug, Serialize)]
struct AcceptTermsOkResp {
    terms_version_accepted: u32,
    terms_digest_accepted: String,
    terms_accepted_at: u64,
    assurance_level: AssuranceLevel,
    strict_age_ok: bool,
}

#[worker::send]
pub async fn accept_terms(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<AcceptTermsReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(e) => {
            worker::console_error!("accept_terms: policy load failed: {e:?}");
            return auth::internal_error();
        }
    };

    let self_attested = match evaluate_terms_acceptance(
        &policy,
        req.terms_version,
        &req.terms_digest,
        req.self_attestation,
    ) {
        TermsAcceptDecision::VersionOrDigestMismatch => {
            return (
                StatusCode::CONFLICT,
                Json(AcceptTermsConflictResp {
                    error: "Terms have changed; please review and accept the latest version.",
                    terms_version: policy.legal.terms_version,
                    terms_digest: policy.legal.terms_digest,
                    terms_md: policy.legal.terms_md,
                }),
            )
                .into_response();
        }
        TermsAcceptDecision::Accepted { self_attested } => self_attested,
    };

    let now = session::now_secs();
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(_) => return auth::internal_error(),
    };
    let stmt = match db
        .prepare(
            "UPDATE users_v2 SET \
                terms_version_accepted = ?1, \
                terms_digest_accepted = ?2, \
                terms_accepted_at = ?3 \
             WHERE id = ?4",
        )
        .bind(&[
            f64::from(policy.legal.terms_version).into(),
            policy.legal.terms_digest.as_str().into(),
            (now as f64).into(),
            active.user_id.as_str().into(),
        ]) {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("accept_terms D1 bind failed: {e:?}");
            return auth::internal_error();
        }
    };
    if let Err(e) = stmt.run().await {
        worker::console_error!("accept_terms D1 update failed: {e:?}");
        return auth::internal_error();
    }

    if let Err(e) = do_client::do_terms_accept(
        &st.env,
        &active.do_key,
        &TermsAcceptReq {
            terms_version: policy.legal.terms_version,
            terms_digest: policy.legal.terms_digest.clone(),
            accepted_at: now,
            self_attestation: Some(self_attested),
            sid: active.sid.clone(),
        },
    )
    .await
    {
        worker::console_error!("accept_terms DO update failed: {e:?}");
        return auth::internal_error();
    }

    let updated = do_client::do_session_context(&st.env, &active.do_key, active.sid.as_deref())
        .await
        .unwrap_or(active.ctx);

    Json(AcceptTermsOkResp {
        terms_version_accepted: policy.legal.terms_version,
        terms_digest_accepted: policy.legal.terms_digest,
        terms_accepted_at: now,
        assurance_level: updated.assurance_level,
        strict_age_ok: updated.strict_age_ok,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// POST /user/api/reports
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateReportReq {
    pub target_kind: String,
    pub target_id: i64,
    pub reason: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateReportResp {
    id: String,
    status: &'static str,
}

#[worker::send]
pub async fn create_report(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<CreateReportReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    let cleaned_note = match validate_report_input(
        req.target_kind.trim(),
        req.target_id,
        req.reason.trim(),
        req.note.as_deref(),
    ) {
        Ok(n) => n,
        Err(msg) => return auth::api_error(StatusCode::BAD_REQUEST, msg),
    };

    let reporter_key = salted_reporter_key(&st.session_v2_secret, &active.user_id);
    let bucket = format!("report:{reporter_key}");
    match challenge_do::hit_rate_limit(&st.env, &bucket, 3600, REPORT_RATE_LIMIT_PER_HOUR).await {
        Ok(rl) if !rl.allowed => {
            return auth::api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "Report rate limit reached (max 5 per hour). Please try again later.",
            );
        }
        Ok(_) => {}
        Err(e) => {
            worker::console_error!("report rate-limit DO failed: {e:?}");
            return auth::internal_error();
        }
    }

    let report_id = uuid::Uuid::new_v4().to_string();
    let now = session::now_secs();
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(_) => return auth::internal_error(),
    };
    let note_js = match cleaned_note.as_deref() {
        Some(s) => s.into(),
        None => wasm_bindgen::JsValue::NULL,
    };
    let insert = db
        .prepare(
            "INSERT INTO content_reports \
             (id, reporter_key, reporter_user_id, target_kind, target_id, reason, note, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, CAST(?5 AS INTEGER), ?6, ?7, 'open', ?8)",
        )
        .bind(&[
            report_id.as_str().into(),
            reporter_key.as_str().into(),
            active.user_id.as_str().into(),
            req.target_kind.trim().into(),
            req.target_id.to_string().into(),
            req.reason.trim().into(),
            note_js,
            (now as f64).into(),
        ]);

    match insert {
        Ok(stmt) => match stmt.run().await {
            Ok(_) => (
                StatusCode::CREATED,
                Json(CreateReportResp {
                    id: report_id,
                    status: "open",
                }),
            )
                .into_response(),
            Err(e) => {
                let msg = format!("{e:?}").to_lowercase();
                if msg.contains("constraint") || msg.contains("unique") {
                    return (
                        StatusCode::CONFLICT,
                        Json(ApiError {
                            error: "You already have an open report for this item.".into(),
                        }),
                    )
                        .into_response();
                }
                worker::console_error!("content_reports insert failed: {e:?}");
                auth::internal_error()
            }
        },
        Err(e) => {
            worker::console_error!("content_reports bind failed: {e:?}");
            auth::internal_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Explicit Identity Linking / Unlinking & Session Management
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LinkStartReq {
    pub provider_id: String,
}

#[derive(Debug, Serialize)]
struct LinkStartResp {
    authorize_url: String,
}

#[worker::send]
pub async fn identity_link_start(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<LinkStartReq>,
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
    let Some(provider) = identity::provider_from_str(&req.provider_id) else {
        return auth::api_error(StatusCode::BAD_REQUEST, "unknown provider_id");
    };
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(_) => return auth::internal_error(),
    };
    match begin_oauth_flow(
        &st,
        &headers,
        &cookies,
        &policy,
        provider,
        "link",
        Some(active.user_id),
        "/user/account".to_string(),
    )
    .await
    {
        Ok(authorize_url) => Json(LinkStartResp { authorize_url }).into_response(),
        Err(r) => r,
    }
}

#[derive(Debug, Deserialize)]
pub struct LinkWalletReq {
    /// `"siwe"` (Ethereum) or `"siws"` (Solana)
    pub provider_id: String,
    /// `"payment"` (default, allowed anytime — zero login/age privilege) or `"login"`
    #[serde(default)]
    pub purpose: Option<String>,
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
struct LinkWalletResp {
    provider_id: String,
    subject: String,
    purpose: String,
}

#[worker::send]
pub async fn identity_link_wallet(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<LinkWalletReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let purpose = match req.purpose.as_deref() {
        Some("login") => "login",
        None | Some("payment") => "payment",
        _ => return auth::api_error(StatusCode::BAD_REQUEST, "invalid purpose"),
    };

    if purpose == "login" {
        if let Err(r) = identity::require_recent_auth(&st, &active).await {
            return r;
        }
        let policy = match policy_do::load_site_policy(&st.env).await {
            Ok(e) => e.policy,
            Err(_) => return auth::internal_error(),
        };
        let Some(pid) = identity::provider_from_str(&req.provider_id) else {
            return auth::api_error(StatusCode::BAD_REQUEST, "invalid provider_id");
        };
        if let Err(msg) = identity::check_login_provider_eligibility(&policy, pid, None) {
            return auth::api_error(StatusCode::FORBIDDEN, msg);
        }
    }

    match req.provider_id.trim() {
        "siwe" => {
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
            if msg.uri.contains("/user/login/approve")
                || msg
                    .statement
                    .as_deref()
                    .is_some_and(|s| s.starts_with("Approve sign-in for another browser"))
            {
                return auth::api_error(
                    StatusCode::UNAUTHORIZED,
                    "handoff approval signature cannot be used for wallet linking",
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
            match challenge_do::consume_nonce(&st.env, &msg.nonce, "wallet").await {
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
                label: Some(if purpose == "payment" {
                    "Linked Ethereum payment wallet".into()
                } else {
                    "Ethereum wallet".into()
                }),
                verified_email: None,
                assurance_level: AssuranceLevel::None,
                assurance_method: None,
                assurance_verified_at: None,
                assurance_expires_at: None,
            };
            if let Err(r) =
                identity::link_identity_atomic(&st, &active.user_id, &ident, purpose).await
            {
                return r;
            }
            if purpose == "login"
                && let Err(r) =
                    identity::rotate_session_on_identity_link(&st, &cookies, &active, &ident).await
            {
                return r;
            }
            Json(LinkWalletResp {
                provider_id: "siwe".into(),
                subject: siwe::to_checksum(&addr),
                purpose: purpose.into(),
            })
            .into_response()
        }
        "siws" => {
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
            match challenge_do::consume_nonce(&st.env, nonce, "wallet").await {
                Ok(true) => {}
                Ok(false) => {
                    return auth::api_error(StatusCode::UNAUTHORIZED, "unknown or expired nonce");
                }
                Err(_) => return auth::internal_error(),
            }
            let expected = solana_link::challenge_message(&active.user_id, nonce);
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
                label: Some(if purpose == "payment" {
                    "Linked Solana payment wallet".into()
                } else {
                    "Solana wallet".into()
                }),
                verified_email: None,
                assurance_level: AssuranceLevel::None,
                assurance_method: None,
                assurance_verified_at: None,
                assurance_expires_at: None,
            };
            if let Err(r) =
                identity::link_identity_atomic(&st, &active.user_id, &ident, purpose).await
            {
                return r;
            }
            if purpose == "login"
                && let Err(r) =
                    identity::rotate_session_on_identity_link(&st, &cookies, &active, &ident).await
            {
                return r;
            }
            Json(LinkWalletResp {
                provider_id: "siws".into(),
                subject: sol_addr.to_string(),
                purpose: purpose.into(),
            })
            .into_response()
        }
        _ => auth::api_error(
            StatusCode::BAD_REQUEST,
            "provider_id must be 'siwe' or 'siws'",
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct UnlinkIdentityReq {
    pub provider_id: String,
    pub issuer: String,
    pub subject: String,
}

#[derive(Debug, Serialize)]
struct UnlinkIdentityResp {
    unlinked: bool,
    session_rotated: bool,
}

#[worker::send]
pub async fn identity_unlink(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<UnlinkIdentityReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match identity::unlink_identity(
        &st,
        &cookies,
        &active,
        &req.provider_id,
        &req.issuer,
        &req.subject,
    )
    .await
    {
        Ok(session_rotated) => Json(UnlinkIdentityResp {
            unlinked: true,
            session_rotated,
        })
        .into_response(),
        Err(r) => r,
    }
}

#[worker::send]
pub async fn revoke_all_sessions(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let _ = do_client::do_session_revoke_all(
        &st.env,
        &active.do_key,
        &SessionRevokeAllReq::default(),
    )
    .await;
    cookies.add(session::clear_session_cookie());
    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_acceptance_detects_version_or_digest_mismatch_for_409() {
        let mut policy = PublicSitePolicy {
            age_policy: AgeVerificationPolicy::SelfAttestation,
            ..Default::default()
        };
        policy.legal.terms_version = 3;
        policy.legal.terms_digest = "aaaa1111".repeat(8);

        // Matching version + digest -> accepted with self-attestation
        assert_eq!(
            evaluate_terms_acceptance(&policy, 3, &policy.legal.terms_digest, Some(true)),
            TermsAcceptDecision::Accepted {
                self_attested: true
            }
        );

        // Stale version -> 409 mismatch
        assert_eq!(
            evaluate_terms_acceptance(&policy, 2, &policy.legal.terms_digest, Some(true)),
            TermsAcceptDecision::VersionOrDigestMismatch
        );

        // Same version, edited Terms text (different digest) -> 409 mismatch
        assert_eq!(
            evaluate_terms_acceptance(&policy, 3, &"bbbb2222".repeat(8), Some(true)),
            TermsAcceptDecision::VersionOrDigestMismatch
        );

        // Under StrictProviderVerified18, self_attestation checkbox MUST NOT set self_attested
        policy.age_policy = AgeVerificationPolicy::StrictProviderVerified18;
        assert_eq!(
            evaluate_terms_acceptance(&policy, 3, &policy.legal.terms_digest, Some(true)),
            TermsAcceptDecision::Accepted {
                self_attested: false
            }
        );
    }

    #[test]
    fn report_validation_enforces_allowlist_and_500_char_cap() {
        assert_eq!(
            validate_report_input("image", 42, "misclassified_safety", Some("  missing tag  ")),
            Ok(Some("missing tag".to_string()))
        );
        assert_eq!(
            validate_report_input("post", 1, "illegal_content", Some(&"a".repeat(500))),
            Ok(Some("a".repeat(500)))
        );
        assert!(validate_report_input("post", 1, "illegal_content", Some(&"a".repeat(501))).is_err());
        assert!(validate_report_input("post", 1, "made_up_reason", None).is_err());
        assert!(validate_report_input("comment", 1, "spam_other", None).is_err());
        assert!(validate_report_input("image", 0, "spam_other", None).is_err());
        assert!(validate_report_input("image", 5, "spam_other", Some("bad\0note")).is_err());
    }

    #[test]
    fn partial_preferences_update_preserves_existing_switchers_and_safe_mode() {
        let policy = PublicSitePolicy {
            rules: vec![
                site_access::SafetyRuleConfig {
                    id: "r18".into(),
                    name: "R-18".into(),
                    mode: RuleMode::Switcher,
                    query: "tag:explicit".into(),
                    default_min_score: 0.5,
                    preset: site_access::PlaceholderPreset::R18,
                    requires_login: true,
                    requires_age_18: true,
                    enabled: true,
                },
                site_access::SafetyRuleConfig {
                    id: "gore".into(),
                    name: "Gore".into(),
                    mode: RuleMode::Switcher,
                    query: "tag:blood".into(),
                    default_min_score: 0.5,
                    preset: site_access::PlaceholderPreset::Blood,
                    requires_login: true,
                    requires_age_18: true,
                    enabled: true,
                },
            ],
            ..Default::default()
        };
        let existing = vec!["r18".to_string(), "gore".to_string()];

        // Panic toggle sending `{"safe_mode": true}` MUST preserve existing switchers!
        let panic_on: PreferencesReq = serde_json::from_str(r#"{"safe_mode": true}"#).unwrap();
        let (sw, safe) = resolve_preferences_update(&policy, &existing, false, &panic_on);
        assert_eq!(sw, existing);
        assert!(safe);

        // Exiting Safe Mode (`{"safe_mode": false}`) STILL preserves existing switchers!
        let panic_off: PreferencesReq = serde_json::from_str(r#"{"safe_mode": false}"#).unwrap();
        let (sw2, safe2) = resolve_preferences_update(&policy, &existing, true, &panic_off);
        assert_eq!(sw2, existing);
        assert!(!safe2);

        // Updating only `enabled_switchers` preserves existing `safe_mode`.
        let only_sw: PreferencesReq =
            serde_json::from_str(r#"{"enabled_switchers": ["r18"]}"#).unwrap();
        let (sw3, safe3) = resolve_preferences_update(&policy, &existing, true, &only_sw);
        assert_eq!(sw3, vec!["r18".to_string()]);
        assert!(safe3);

        // Explicit empty `enabled_switchers` clears switchers.
        let clear_sw: PreferencesReq =
            serde_json::from_str(r#"{"enabled_switchers": [], "safe_mode": false}"#).unwrap();
        let (sw4, safe4) = resolve_preferences_update(&policy, &existing, true, &clear_sw);
        assert!(sw4.is_empty());
        assert!(!safe4);
    }

    #[test]
    fn safe_mode_cycle_preserves_saved_switchers_across_d1_do_and_me() {
        use crate::account_do::{
            StoredSafetyState, StoredSessionSnapshot, apply_prefs_update, compute_session_context,
        };

        let mut policy = PublicSitePolicy {
            safety_enabled: true,
            age_policy: AgeVerificationPolicy::StrictProviderVerified18,
            rules: vec![
                site_access::SafetyRuleConfig {
                    id: "r18".into(),
                    name: "R-18".into(),
                    mode: RuleMode::Switcher,
                    query: "tag:explicit".into(),
                    default_min_score: 0.5,
                    preset: site_access::PlaceholderPreset::R18,
                    requires_login: true,
                    requires_age_18: true,
                    enabled: true,
                },
                site_access::SafetyRuleConfig {
                    id: "disabled_sw".into(),
                    name: "Disabled".into(),
                    mode: RuleMode::Switcher,
                    query: "tag:old".into(),
                    default_min_score: 0.5,
                    preset: site_access::PlaceholderPreset::Custom,
                    requires_login: false,
                    requires_age_18: false,
                    enabled: false,
                },
            ],
            ..Default::default()
        };
        policy.legal.terms_version = 1;

        let now = 1_750_000_000u64;
        let session_row = StoredSessionSnapshot {
            assurance_level: AssuranceLevel::Verified18,
            strict_age_ok: true,
            expires_at: now + 3600,
            revoked_at: None,
        };

        // Initial persisted state: saved = ["r18"], safe_mode = false in both D1 and DO.
        let mut d1_prefs_json = serde_json::to_string(&StoredContentPrefs {
            enabled_switchers: vec!["r18".into(), "disabled_sw".into()],
            safe_mode: false,
        })
        .unwrap();
        let mut do_state = StoredSafetyState {
            enabled_switchers: vec!["r18".into()],
            safe_mode: false,
            terms_version: Some(policy.legal.terms_version),
            terms_digest: Some(policy.legal.terms_digest.clone()),
            self_attested_18: false,
            revoked_all_before: 0,
        };

        let ctx0 = compute_session_context(false, Some("sid1"), Some(&session_row), &do_state, now);
        assert_eq!(ctx0.enabled_switchers, vec!["r18"]);
        assert_eq!(ctx0.effective_switchers(&policy), vec!["r18"]);
        assert_eq!(
            auth::compute_me_switchers(&policy, Some(&d1_prefs_json), &ctx0),
            (vec!["r18".to_string()], vec!["r18".to_string()])
        );

        // Step 1: POST /user/api/preferences {"safe_mode": true}
        let req_on: PreferencesReq = serde_json::from_str(r#"{"safe_mode": true}"#).unwrap();
        let existing1 =
            resolve_saved_switchers(&policy, Some(&d1_prefs_json), &ctx0.enabled_switchers);
        let (filtered1, next_safe1) =
            resolve_preferences_update(&policy, &existing1, ctx0.safe_mode, &req_on);
        assert_eq!(filtered1, vec!["r18"]);
        assert!(next_safe1);

        d1_prefs_json = serde_json::to_string(&StoredContentPrefs {
            enabled_switchers: filtered1.clone(),
            safe_mode: next_safe1,
        })
        .unwrap();
        do_state = apply_prefs_update(&do_state, Some(filtered1), next_safe1);
        assert_eq!(do_state.enabled_switchers, vec!["r18"]);
        assert!(do_state.safe_mode);

        // SessionContext MUST remain fail-closed (enabled_switchers = [], effective = []),
        // while GET /user/api/me still returns saved enabled_switchers = ["r18"] and effective = []!
        let ctx1 = compute_session_context(false, Some("sid1"), Some(&session_row), &do_state, now);
        assert!(ctx1.safe_mode);
        assert!(ctx1.enabled_switchers.is_empty());
        assert!(ctx1.effective_switchers(&policy).is_empty());
        assert_eq!(
            auth::compute_me_switchers(&policy, Some(&d1_prefs_json), &ctx1),
            (vec!["r18".to_string()], Vec::<String>::new())
        );

        // Step 2: POST /user/api/preferences {"safe_mode": false} (while ctx1.enabled_switchers is [])
        let req_off: PreferencesReq = serde_json::from_str(r#"{"safe_mode": false}"#).unwrap();
        let existing2 =
            resolve_saved_switchers(&policy, Some(&d1_prefs_json), &ctx1.enabled_switchers);
        let (filtered2, next_safe2) =
            resolve_preferences_update(&policy, &existing2, ctx1.safe_mode, &req_off);
        assert_eq!(filtered2, vec!["r18"]);
        assert!(!next_safe2);

        d1_prefs_json = serde_json::to_string(&StoredContentPrefs {
            enabled_switchers: filtered2.clone(),
            safe_mode: next_safe2,
        })
        .unwrap();
        do_state = apply_prefs_update(&do_state, Some(filtered2), next_safe2);
        assert_eq!(do_state.enabled_switchers, vec!["r18"]);
        assert!(!do_state.safe_mode);

        // SessionContext AND /user/api/me now restore saved=["r18"] and effective=["r18"]!
        let ctx2 = compute_session_context(false, Some("sid1"), Some(&session_row), &do_state, now);
        assert!(!ctx2.safe_mode);
        assert_eq!(ctx2.enabled_switchers, vec!["r18"]);
        assert_eq!(ctx2.effective_switchers(&policy), vec!["r18"]);
        assert_eq!(
            auth::compute_me_switchers(&policy, Some(&d1_prefs_json), &ctx2),
            (vec!["r18".to_string()], vec!["r18".to_string()])
        );
    }
}
