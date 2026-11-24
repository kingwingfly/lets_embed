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
    AgeVerificationPolicy, AssuranceLevel, AuthProviderId, PolicyCallerContext, PolicyRef,
    PublicSitePolicy, SessionContext, canonical_policy_json, compute_policy_access,
};
use tower_cookies::Cookies;

use crate::{
    AppState, auth, challenge_do, config,
    do_client::{
        self, AgeConfirmReq, DoPrefsUpdateOutcome, PrefsUpdateReq, SessionRevokeAllReq,
        TermsAcceptReq,
    },
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

/// Pure policy check for standalone `POST /user/api/age-confirm`.
///
/// Works independently of Terms acceptance so signed-in users can confirm 18+
/// before or after accepting current Terms whenever `AgeVerificationPolicy::SelfAttestation`
/// is active. Fails closed under `StrictProviderVerified18` (403) and `Off` (400).
pub fn evaluate_age_confirm_policy(
    policy: &PublicSitePolicy,
) -> Result<(), (StatusCode, &'static str)> {
    match policy.age_policy {
        AgeVerificationPolicy::SelfAttestation => Ok(()),
        AgeVerificationPolicy::StrictProviderVerified18 => Err((
            StatusCode::FORBIDDEN,
            "Self-attestation is disabled under Strict Provider-Verified 18+ mode. Sign in with a verified 18+ OIDC provider instead.",
        )),
        AgeVerificationPolicy::Off => Err((
            StatusCode::BAD_REQUEST,
            "18+ age verification is currently disabled by site policy.",
        )),
    }
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

/// Extracts normalized uppercase Cloudflare country code from `CF-IPCountry` header.
pub fn extract_cf_country(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cf-ipcountry")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_uppercase)
}

/// Wire input for a Policy v3 switcher opt-in (`{"id":"r18","grant_generation":2}` or `"r18@2"`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PolicyRefInput {
    Object(PolicyRef),
    Key(String),
}

impl PolicyRefInput {
    pub fn into_policy_ref(self) -> Result<PolicyRef, String> {
        match self {
            Self::Object(p) => {
                p.validate().map_err(|e| e.to_string())?;
                Ok(p)
            }
            Self::Key(raw) => PolicyRef::from_key(raw.trim()).map_err(|e| e.to_string()),
        }
    }
}

/// Per-switcher eligibility status surfaced to `/user/account` so users see exact
/// requirements (`18+`, `Terms`, `Login`, `Region`) for each Policy v3 switcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitcherEligibility {
    pub id: String,
    pub grant_generation: u64,
    pub opted_in: bool,
    pub effective: bool,
    pub country_excluded: bool,
    pub missing_requirements: Vec<String>,
}

/// Filter stored `PolicyRef` opt-ins strictly against active Policy v3 switcher policies
/// (`policy.enabled && policy.bypass.include_switcher` AND exact `grant_generation` match).
///
/// Any policy whose `grant_generation` was bumped in `/admin` is automatically invalidated
/// until the user explicitly re-opts in against the new generation!
pub fn filter_active_policy_refs(policy: &PublicSitePolicy, stored: &[PolicyRef]) -> Vec<PolicyRef> {
    let mut out = Vec::new();
    for pref in stored {
        if policy.policies.iter().any(|p| {
            p.enabled
                && p.bypass.include_switcher
                && p.id == pref.id
                && p.grant_generation == pref.grant_generation
        }) && !out.contains(pref)
        {
            out.push(pref.clone());
        }
    }
    out
}

/// Validate requested switcher opt-ins against active Policy v3 (`policy.enabled &&
/// policy.bypass.include_switcher` AND exact `grant_generation` match), returning
/// `(validated_refs, warnings)`.
pub fn validate_requested_switchers(
    policy: &PublicSitePolicy,
    requested: &[PolicyRefInput],
) -> (Vec<PolicyRef>, Vec<String>) {
    let mut valid = Vec::new();
    let mut warnings = Vec::new();
    for item in requested {
        let pref = match item.clone().into_policy_ref() {
            Ok(p) => p,
            Err(msg) => {
                warnings.push(format!("Ignored invalid switcher reference ({msg})."));
                continue;
            }
        };
        let Some(rule) = policy.policies.iter().find(|p| p.id == pref.id) else {
            warnings.push(format!("Ignored unknown content policy '{}'.", pref.id));
            continue;
        };
        if !rule.enabled {
            warnings.push(format!("Policy '{}' is currently disabled.", rule.name));
            continue;
        }
        if !rule.bypass.include_switcher {
            warnings.push(format!(
                "Policy '{}' does not permit user switcher opt-in.",
                rule.name
            ));
            continue;
        }
        if rule.grant_generation != pref.grant_generation {
            warnings.push(format!(
                "Policy '{}' was updated to generation #{}; please reload and re-confirm.",
                rule.name, rule.grant_generation
            ));
            continue;
        }
        if !valid.contains(&pref) {
            valid.push(pref);
        }
    }
    (valid, warnings)
}

/// Evaluate effective direct switcher grants and per-policy eligibility reasons
/// (`require_gallery_login`, `require_age_18`, `require_current_terms`, `exclude_countries`).
pub fn evaluate_switcher_eligibilities(
    policy: &PublicSitePolicy,
    ctx: &SessionContext,
    country: Option<&str>,
) -> (Vec<PolicyRef>, Vec<SwitcherEligibility>) {
    let caller = PolicyCallerContext {
        session: Some(ctx.clone()),
        session_revoked_or_invalid: false,
        live_admin_email: None,
        country: country.map(str::to_string),
    };
    let access = compute_policy_access(policy, &caller);
    let mut statuses = Vec::new();

    for rule in &policy.policies {
        if !rule.enabled || !rule.bypass.include_switcher {
            continue;
        }
        let pref = rule.policy_ref();
        let opted_in = ctx.enabled_switchers.contains(&pref);
        let effective = access.direct_grants.contains(&pref);
        let country_excluded = rule.bypass.is_country_excluded(country);
        let mut missing_requirements = Vec::new();

        if rule.bypass.require_gallery_login && !ctx.is_authenticated() {
            missing_requirements.push("Active gallery sign-in required".to_string());
        }
        if rule.bypass.require_age_18 {
            match policy.age_policy {
                AgeVerificationPolicy::Off => {
                    missing_requirements.push(
                        "18+ age verification is currently disabled by site policy".to_string(),
                    );
                }
                AgeVerificationPolicy::SelfAttestation => {
                    if !ctx.satisfies_age_18(policy.age_policy) {
                        missing_requirements.push("18+ age confirmation required".to_string());
                    }
                }
                AgeVerificationPolicy::StrictProviderVerified18 => {
                    if !ctx.satisfies_age_18(policy.age_policy) {
                        missing_requirements
                            .push("Verified 18+ identity (OIDC) required".to_string());
                    }
                }
            }
        }
        if rule.bypass.require_current_terms && !ctx.satisfies_terms(&policy.legal) {
            missing_requirements.push(format!(
                "Accept Terms v{} required",
                policy.legal.terms_version
            ));
        }
        if country_excluded {
            missing_requirements.push("Unavailable in your country/region".to_string());
        }

        statuses.push(SwitcherEligibility {
            id: rule.id.clone(),
            grant_generation: rule.grant_generation,
            opted_in,
            effective,
            country_excluded,
            missing_requirements,
        });
    }

    (access.direct_grants, statuses)
}

fn salted_reporter_key(secret: &[u8], user_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(b"report-key/v1\0");
    mac.update(user_id.as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..16])
}

// ---------------------------------------------------------------------------
// POST /internal/policy/activate & /internal/policy/refresh
// ---------------------------------------------------------------------------

async fn handle_internal_policy_forward(
    st: &AppState,
    headers: &HeaderMap,
    do_path: &str,
    body: String,
) -> Response {
    if st.internal_api_secret.is_none() {
        return auth::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "internal API secret not configured",
        );
    }
    if !crate::verify_internal_api_auth(
        headers,
        st.internal_api_secret.as_deref().map(Vec::as_slice),
    ) {
        return auth::api_error(StatusCode::UNAUTHORIZED, "unauthorized internal request");
    }
    match policy_do::forward_policy_activation(&st.env, do_path, body).await {
        Ok((code, text)) => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY);
            (
                status,
                [
                    (
                        header::CONTENT_TYPE,
                        "application/json; charset=utf-8".to_string(),
                    ),
                    (header::CACHE_CONTROL, "private, no-store".to_string()),
                ],
                text,
            )
                .into_response()
        }
        Err(e) => {
            worker::console_error!("internal policy forward {do_path} failed: {e:?}");
            auth::api_error(StatusCode::SERVICE_UNAVAILABLE, "site policy DO unavailable")
        }
    }
}

#[worker::send]
pub async fn internal_policy_activate(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    handle_internal_policy_forward(&st, &headers, "/internal/policy/activate", body).await
}

#[worker::send]
pub async fn internal_policy_refresh(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    handle_internal_policy_forward(&st, &headers, "/internal/policy/refresh", body).await
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
// POST /user/api/preferences (Policy v3 — Safe Mode removed, pref_version CAS)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PreferencesReq {
    pub enabled_switchers: Vec<PolicyRefInput>,
    #[serde(default)]
    pub expected_pref_version: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct PreferencesResp {
    pub enabled_switchers: Vec<PolicyRef>,
    pub effective_switchers: Vec<PolicyRef>,
    pub pref_version: u64,
    pub switcher_statuses: Vec<SwitcherEligibility>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PreferencesConflictResp {
    pub error: &'static str,
    pub pref_version: u64,
    pub enabled_switchers: Vec<PolicyRef>,
    pub effective_switchers: Vec<PolicyRef>,
    pub switcher_statuses: Vec<SwitcherEligibility>,
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
            return auth::api_error(StatusCode::SERVICE_UNAVAILABLE, "site policy unavailable");
        }
    };
    let country = extract_cf_country(&headers);
    let (filtered, warnings) = validate_requested_switchers(&policy, &req.enabled_switchers);

    // Authoritative optimistic-concurrency write in single-threaded `UserAccount` DO first!
    let do_outcome = match do_client::do_prefs_update(
        &st.env,
        &active.do_key,
        &PrefsUpdateReq {
            enabled_switchers: filtered.clone(),
            expected_pref_version: req.expected_pref_version,
        },
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            worker::console_error!("preferences DO update failed: {e:?}");
            return auth::internal_error();
        }
    };

    let (authoritative_version, updated_ctx) = match do_outcome {
        DoPrefsUpdateOutcome::Conflict(conflict) => {
            let fresh_ctx = do_client::do_session_context(
                &st.env,
                &active.do_key,
                active.sid.as_deref(),
            )
            .await
            .unwrap_or_else(|_| SessionContext {
                enabled_switchers: conflict.enabled_switchers.clone(),
                pref_version: conflict.pref_version,
                ..active.ctx.clone()
            });
            let fresh_saved = filter_active_policy_refs(&policy, &fresh_ctx.enabled_switchers);
            let (fresh_effective, fresh_statuses) =
                evaluate_switcher_eligibilities(&policy, &fresh_ctx, country.as_deref());
            return (
                StatusCode::CONFLICT,
                [(header::CACHE_CONTROL, "private, no-store")],
                Json(PreferencesConflictResp {
                    error: "Preferences were updated in another tab; refreshed to latest state.",
                    pref_version: fresh_ctx.pref_version.max(1),
                    enabled_switchers: fresh_saved,
                    effective_switchers: fresh_effective,
                    switcher_statuses: fresh_statuses,
                }),
            )
                .into_response();
        }
        DoPrefsUpdateOutcome::Updated(updated) => {
            // Capture the exact `pref_version` assigned to `filtered` by the single-threaded DO
            // so the D1 mirror NEVER pairs `filtered` with a newer concurrent update's version (F18)!
            let auth_ver = updated.pref_version.max(1);
            // Re-read authoritative session context WITH caller's live `sid` for the HTTP response
            // so `assurance_level` / `strict_age_ok` reflect this session accurately.
            let fresh_ctx =
                do_client::do_session_context(&st.env, &active.do_key, active.sid.as_deref())
                    .await
                    .unwrap_or_else(|_| SessionContext {
                        enabled_switchers: filtered.clone(),
                        pref_version: auth_ver,
                        ..active.ctx.clone()
                    });
            (auth_ver, fresh_ctx)
        }
    };

    let prefs_json = match serde_json::to_string(&StoredContentPrefs {
        enabled_switchers: filtered.clone(),
    }) {
        Ok(s) => s,
        Err(_) => return auth::internal_error(),
    };

    // Mirror `(filtered, authoritative_version)` to D1 `users_v2` with monotonic `pref_version` guard.
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("preferences D1 binding failed: {e:?}");
            return auth::internal_error();
        }
    };
    let stmt = match db
        .prepare(
            "UPDATE users_v2 \
             SET content_prefs_json = ?1, pref_version = ?2 \
             WHERE id = ?3 AND pref_version < ?2",
        )
        .bind(&[
            prefs_json.into(),
            (authoritative_version as f64).into(),
            active.user_id.as_str().into(),
        ]) {
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

    let saved_switchers = filter_active_policy_refs(&policy, &updated_ctx.enabled_switchers);
    let (effective_switchers, switcher_statuses) =
        evaluate_switcher_eligibilities(&policy, &updated_ctx, country.as_deref());

    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(PreferencesResp {
            enabled_switchers: saved_switchers,
            effective_switchers,
            pref_version: updated_ctx.pref_version.max(1),
            switcher_statuses,
            warnings,
        }),
    )
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
// POST /user/api/age-confirm (Standalone 18+ self-attestation — independent of Terms!)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AgeConfirmResp {
    pub ok: bool,
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
    pub age_verified: bool,
    pub effective_switchers: Vec<PolicyRef>,
    pub switcher_statuses: Vec<SwitcherEligibility>,
}

#[worker::send]
pub async fn confirm_age(
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
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(e) => {
            worker::console_error!("age_confirm: policy load failed: {e:?}");
            return auth::api_error(StatusCode::SERVICE_UNAVAILABLE, "site policy unavailable");
        }
    };
    if let Err((status, msg)) = evaluate_age_confirm_policy(&policy) {
        return auth::api_error(status, msg);
    }

    if let Err(e) = do_client::do_age_confirm(
        &st.env,
        &active.do_key,
        &AgeConfirmReq {
            sid: active.sid.clone(),
        },
    )
    .await
    {
        worker::console_error!("age_confirm DO update failed: {e:?}");
        return auth::internal_error();
    }

    let updated = do_client::do_session_context(&st.env, &active.do_key, active.sid.as_deref())
        .await
        .unwrap_or(SessionContext {
            assurance_level: match active.ctx.assurance_level {
                AssuranceLevel::None => AssuranceLevel::SelfAttestation,
                other => other,
            },
            ..active.ctx
        });
    let country = extract_cf_country(&headers);
    let (effective_switchers, switcher_statuses) =
        evaluate_switcher_eligibilities(&policy, &updated, country.as_deref());
    let age_verified = updated.satisfies_age_18(policy.age_policy);

    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(AgeConfirmResp {
            ok: true,
            assurance_level: updated.assurance_level,
            strict_age_ok: updated.strict_age_ok,
            age_verified,
            effective_switchers,
            switcher_statuses,
        }),
    )
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

/// Expected EIP-4361 statement for linking an Ethereum wallet, binding BOTH
/// target account (`user_id`) and link purpose (`"payment"` or `"login"`) (F7).
pub fn expected_siwe_link_statement(user_id: &str, purpose: &str) -> String {
    format!("Link Ethereum wallet for {purpose} to account {user_id}.")
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
    let nonce_purpose = if purpose == "login" {
        auth::NONCE_PURPOSE_LINK_LOGIN
    } else {
        auth::NONCE_PURPOSE_LINK_PAYMENT
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
            let expected_stmt = expected_siwe_link_statement(&active.user_id, purpose);
            if msg.uri.contains("/user/login/approve")
                || msg.statement.as_deref() != Some(expected_stmt.as_str())
            {
                return auth::api_error(
                    StatusCode::UNAUTHORIZED,
                    "SIWE statement must exactly match the wallet-link account and purpose",
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
            match challenge_do::consume_nonce(&st.env, &msg.nonce, nonce_purpose).await {
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
            match challenge_do::consume_nonce(&st.env, nonce, nonce_purpose).await {
                Ok(true) => {}
                Ok(false) => {
                    return auth::api_error(StatusCode::UNAUTHORIZED, "unknown or expired nonce");
                }
                Err(_) => return auth::internal_error(),
            }
            let expected =
                solana_link::challenge_message_for_purpose(&active.user_id, purpose, nonce);
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
    if let Err(r) = identity::require_recent_auth(&st, &active).await {
        return r;
    }
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
    if let Err(e) = do_client::do_session_revoke_all(
        &st.env,
        &active.do_key,
        &SessionRevokeAllReq::default(),
    )
    .await
    {
        worker::console_error!("revoke_all_sessions DO failed: {e:?}");
        return auth::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "could not revoke sessions; please retry",
        );
    }
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
    fn switcher_validation_enforces_enabled_include_switcher_and_grant_generation() {
        use site_access::{ContentPolicy, PlaceholderPreset, PolicyAction, PolicyBypass};

        let mut policy = PublicSitePolicy {
            revision: 3,
            min_enforce_rev: 3,
            safety_enabled: true,
            age_policy: AgeVerificationPolicy::SelfAttestation,
            policies: vec![
                ContentPolicy {
                    id: "r18".into(),
                    grant_generation: 2,
                    enabled: true,
                    priority: 10,
                    name: "NSFW / Explicit".into(),
                    preset: PlaceholderPreset::R18,
                    match_expr: "tag:explicit".into(),
                    except_expr: None,
                    default_tag_min: 0.45,
                    action: PolicyAction::Block,
                    bypass: PolicyBypass {
                        include_switcher: true,
                        require_gallery_login: true,
                        require_age_18: true,
                        require_current_terms: true,
                        exclude_anonymous: true,
                        exclude_countries: vec!["GB".into()],
                        ..Default::default()
                    },
                },
                ContentPolicy {
                    id: "hard_block".into(),
                    grant_generation: 1,
                    enabled: true,
                    priority: 5,
                    name: "Always Blocked".into(),
                    preset: PlaceholderPreset::Blood,
                    match_expr: "tag:blood".into(),
                    except_expr: None,
                    default_tag_min: 0.45,
                    action: PolicyAction::Block,
                    bypass: PolicyBypass {
                        include_switcher: false,
                        ..Default::default()
                    },
                },
                ContentPolicy {
                    id: "disabled_sw".into(),
                    grant_generation: 1,
                    enabled: false,
                    priority: 30,
                    name: "Disabled".into(),
                    preset: PlaceholderPreset::Custom,
                    match_expr: "tag:sensitive".into(),
                    except_expr: None,
                    default_tag_min: 0.45,
                    action: PolicyAction::Blur,
                    bypass: PolicyBypass {
                        include_switcher: true,
                        ..Default::default()
                    },
                },
            ],
            ..PublicSitePolicy::fresh_bootstrap()
        };
        policy.refresh_policy_digest();

        // Stale grant_generation (r18@1), non-switcher (hard_block@1), disabled (disabled_sw@1),
        // and unknown policies are all rejected with clear warnings!
        let requested = vec![
            PolicyRefInput::Key("r18@1".into()),
            PolicyRefInput::Object(PolicyRef::new("hard_block", 1)),
            PolicyRefInput::Key("disabled_sw@1".into()),
            PolicyRefInput::Key("nonexistent@1".into()),
        ];
        let (valid, warnings) = validate_requested_switchers(&policy, &requested);
        assert!(valid.is_empty());
        assert_eq!(warnings.len(), 4);
        assert!(warnings[0].contains("generation #2"));

        // Exact matching (r18@2) passes cleanly (both object and compact key deduplicated)
        let ok_req = vec![
            PolicyRefInput::Object(PolicyRef::new("r18", 2)),
            PolicyRefInput::Key("r18@2".into()),
        ];
        let (valid2, warnings2) = validate_requested_switchers(&policy, &ok_req);
        assert_eq!(valid2, vec![PolicyRef::new("r18", 2)]);
        assert!(warnings2.is_empty());

        // Bumping grant_generation in policy invalidates prior saved opt-in automatically!
        assert_eq!(
            filter_active_policy_refs(&policy, &[PolicyRef::new("r18", 2)]),
            vec![PolicyRef::new("r18", 2)]
        );
        policy.policies[0].grant_generation = 3;
        policy.refresh_policy_digest();
        assert!(filter_active_policy_refs(&policy, &[PolicyRef::new("r18", 2)]).is_empty());
    }

    #[test]
    fn switcher_eligibility_reports_age_terms_country_and_strict_mode_messages() {
        use site_access::{ContentPolicy, PlaceholderPreset, PolicyAction, PolicyBypass};

        let mut policy = PublicSitePolicy {
            revision: 1,
            min_enforce_rev: 1,
            safety_enabled: true,
            age_policy: AgeVerificationPolicy::StrictProviderVerified18,
            policies: vec![ContentPolicy {
                id: "r18".into(),
                grant_generation: 1,
                enabled: true,
                priority: 10,
                name: "NSFW".into(),
                preset: PlaceholderPreset::R18,
                match_expr: "tag:explicit".into(),
                except_expr: None,
                default_tag_min: 0.45,
                action: PolicyAction::Block,
                bypass: PolicyBypass {
                    include_switcher: true,
                    require_gallery_login: true,
                    require_age_18: true,
                    require_current_terms: true,
                    exclude_anonymous: true,
                    exclude_countries: vec!["GB".into()],
                    ..Default::default()
                },
            }],
            ..PublicSitePolicy::fresh_bootstrap()
        };
        policy.legal.terms_version = 4;
        policy.refresh_policy_digest();

        // User opted in, but missing strict 18+, missing Terms v4, and in excluded country GB
        let ctx_missing = SessionContext {
            active: true,
            banned: false,
            suspended: false,
            sid_valid: true,
            assurance_level: AssuranceLevel::SelfAttestation,
            strict_age_ok: false,
            terms_version_accepted: Some(3),
            terms_digest_accepted: Some(policy.legal.terms_digest.clone()),
            enabled_switchers: vec![PolicyRef::new("r18", 1)],
            pref_version: 2,
        };
        let (eff, statuses) = evaluate_switcher_eligibilities(&policy, &ctx_missing, Some("GB"));
        assert!(eff.is_empty());
        assert_eq!(statuses.len(), 1);
        assert!(statuses[0].opted_in);
        assert!(!statuses[0].effective);
        assert!(statuses[0].country_excluded);
        assert!(statuses[0]
            .missing_requirements
            .iter()
            .any(|m| m.contains("OIDC")));
        assert!(statuses[0]
            .missing_requirements
            .iter()
            .any(|m| m.contains("Terms v4")));
        assert!(statuses[0]
            .missing_requirements
            .iter()
            .any(|m| m.contains("country")));

        // Missing/unknown country ("XX" / None) is ALSO denied when exclude_countries is non-empty!
        let ctx_ok = SessionContext {
            assurance_level: AssuranceLevel::Verified18,
            strict_age_ok: true,
            terms_version_accepted: Some(4),
            ..ctx_missing
        };
        let (eff_none, st_none) = evaluate_switcher_eligibilities(&policy, &ctx_ok, None);
        assert!(eff_none.is_empty());
        assert!(st_none[0].country_excluded);

        let (eff_us, st_us) = evaluate_switcher_eligibilities(&policy, &ctx_ok, Some("US"));
        assert_eq!(eff_us, vec![PolicyRef::new("r18", 1)]);
        assert!(st_us[0].effective);
        assert!(st_us[0].missing_requirements.is_empty());
    }

    #[test]
    fn legacy_safe_mode_only_payload_rejected_by_v3_preferences_req() {
        // Policy v3 removes Safe Mode completely: legacy `{"safe_mode": true}` without
        // `enabled_switchers` MUST fail deserialization cleanly instead of mutating preferences!
        assert!(serde_json::from_str::<PreferencesReq>(r#"{"safe_mode": true}"#).is_err());

        // Valid v3 payload with expected_pref_version parses cleanly
        let parsed: PreferencesReq = serde_json::from_str(
            r#"{"enabled_switchers":[{"id":"r18","grant_generation":2}],"expected_pref_version":7}"#,
        )
        .unwrap();
        assert_eq!(parsed.expected_pref_version, Some(7));
        assert_eq!(parsed.enabled_switchers.len(), 1);
    }

    #[test]
    fn age_confirm_policy_allows_self_attestation_and_decouples_from_terms() {
        use site_access::{ContentPolicy, PlaceholderPreset, PolicyAction, PolicyBypass};

        let mut policy = PublicSitePolicy {
            revision: 1,
            min_enforce_rev: 1,
            safety_enabled: true,
            age_policy: AgeVerificationPolicy::SelfAttestation,
            policies: vec![ContentPolicy {
                id: "r18".into(),
                grant_generation: 1,
                enabled: true,
                priority: 10,
                name: "NSFW / Explicit".into(),
                preset: PlaceholderPreset::R18,
                match_expr: "tag:explicit".into(),
                except_expr: None,
                default_tag_min: 0.45,
                action: PolicyAction::Block,
                bypass: PolicyBypass {
                    include_switcher: true,
                    require_gallery_login: true,
                    require_age_18: true,
                    require_current_terms: true,
                    exclude_anonymous: true,
                    ..Default::default()
                },
            }],
            ..PublicSitePolicy::fresh_bootstrap()
        };
        policy.legal.terms_version = 2;
        policy.refresh_policy_digest();

        // SelfAttestation allows standalone POST /user/api/age-confirm
        assert!(evaluate_age_confirm_policy(&policy).is_ok());

        // User confirms 18+ BEFORE accepting Terms: age requirement is now satisfied,
        // while Terms v2 remains clearly reported until accepted!
        let ctx_age_only = SessionContext {
            active: true,
            banned: false,
            suspended: false,
            sid_valid: true,
            assurance_level: AssuranceLevel::SelfAttestation,
            strict_age_ok: false,
            terms_version_accepted: None,
            terms_digest_accepted: None,
            enabled_switchers: vec![PolicyRef::new("r18", 1)],
            pref_version: 2,
        };
        assert!(ctx_age_only.satisfies_age_18(policy.age_policy));
        assert!(!ctx_age_only.satisfies_terms(&policy.legal));
        let (eff_before_terms, st_before_terms) =
            evaluate_switcher_eligibilities(&policy, &ctx_age_only, Some("US"));
        assert!(eff_before_terms.is_empty());
        assert!(!st_before_terms[0]
            .missing_requirements
            .iter()
            .any(|m| m.contains("18+")));
        assert!(st_before_terms[0]
            .missing_requirements
            .iter()
            .any(|m| m.contains("Terms v2")));

        // StrictProviderVerified18 rejects self-attestation with 403 Forbidden
        policy.age_policy = AgeVerificationPolicy::StrictProviderVerified18;
        let strict_err = evaluate_age_confirm_policy(&policy).unwrap_err();
        assert_eq!(strict_err.0, StatusCode::FORBIDDEN);

        // Off rejects self-attestation with 400 Bad Request
        policy.age_policy = AgeVerificationPolicy::Off;
        let off_err = evaluate_age_confirm_policy(&policy).unwrap_err();
        assert_eq!(off_err.0, StatusCode::BAD_REQUEST);
    }
}
