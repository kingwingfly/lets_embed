//! SIWE, SIWS, logout, nonce issuance (atomic `AuthChallengeDO`), and `/user/api/me`.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use site_access::{
    AssuranceLevel, AuthProviderId, AuthProviderPublicConfig, PolicyRef, PublicSitePolicy,
};
use tower_cookies::Cookies;

use crate::{
    AppState, challenge_do, config, do_client,
    identity::{self, IdentityView, VerifiedExternalIdentity},
    policy_do,
    safety_api::{self, SwitcherEligibility},
    session, settings, siwe, solana_link,
    types::{ApiError, NonceResp, SiwsReq, VerifyReq, VerifyResp},
};

pub(crate) fn api_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(ApiError { error: msg.into() }),
    )
        .into_response()
}

pub(crate) fn internal_error() -> Response {
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

pub(crate) fn display_address(addr: &str) -> String {
    if session::is_eth_address(addr) {
        siwe::to_checksum(addr)
    } else {
        addr.to_string()
    }
}

fn single_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut vals = headers.get_all(name).iter();
    let Some(first) = vals.next() else {
        return Ok(None);
    };
    if vals.next().is_some() {
        // Duplicate Origin or Sec-Fetch-Site headers are rejected fail-closed.
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

/// Verify an `Origin` (or `Sec-Fetch-Site: same-origin` when `Origin` is absent
/// or serialized as `"null"`, e.g. under a strict referrer policy) against
/// `siwe_domain` / `public_url` to block cross-site / sibling-subdomain POST CSRF.
/// Rejects duplicate `Origin` or `Sec-Fetch-Site` headers fail-closed.
pub(crate) fn same_origin(headers: &HeaderMap, domain: &str, public_origin: Option<&str>) -> bool {
    let Ok(sec_fetch) = single_header_str(headers, "sec-fetch-site") else {
        return false;
    };
    let Ok(origin_opt) = single_header_str(headers, "origin") else {
        return false;
    };
    if let Some(origin) = origin_opt {
        if origin.eq_ignore_ascii_case("null") {
            return sec_fetch.is_some_and(|v| v.eq_ignore_ascii_case("same-origin"));
        }
        let origin_ok = public_origin
            .map(|p| p.trim_end_matches('/'))
            .filter(|p| !p.is_empty())
            .is_some_and(|p| origin.eq_ignore_ascii_case(p))
            || origin.eq_ignore_ascii_case(&format!("https://{domain}"))
            || (domain
                .split(':')
                .next()
                .is_some_and(|h| matches!(h, "localhost" | "127.0.0.1"))
                && origin.eq_ignore_ascii_case(&format!("http://{domain}")));
        return origin_ok && sec_fetch.is_none_or(|v| v.eq_ignore_ascii_case("same-origin"));
    }
    sec_fetch.is_some_and(|v| v.eq_ignore_ascii_case("same-origin"))
}

pub(crate) fn require_same_origin(st: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if !same_origin(headers, &st.siwe_domain, Some(st.public_origin())) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "cross-origin request rejected",
        ));
    }
    Ok(())
}

/// Issue a single-use wallet nonce atomically in `AuthChallengeDO` (eliminates KV race H12).
#[worker::send]
pub async fn nonce(State(st): State<AppState>) -> Response {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    if let Err(e) = challenge_do::issue_nonce(&st.env, &nonce, "wallet", config::NONCE_TTL_SECS).await
    {
        worker::console_error!("AuthChallengeDO nonce issue failed: {e:?}");
        return internal_error();
    }
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(NonceResp { nonce }),
    )
        .into_response()
}

/// Verify an EIP-4361 SIWE direct-login payload, atomically consume its single-use
/// nonce from `AuthChallengeDO`, enforce `AgeVerificationPolicy`, resolve/create
/// the `users_v2` account, and return `(ResolvedAccount, VerifiedExternalIdentity)`.
pub(crate) async fn verify_siwe_and_ensure_user(
    st: &AppState,
    req: &VerifyReq,
) -> Result<(identity::ResolvedAccount, VerifiedExternalIdentity), Response> {
    let policy = policy_do::load_site_policy(&st.env)
        .await
        .map_err(|e| {
            worker::console_error!("siwe: policy load failed: {e:?}");
            internal_error()
        })?
        .policy;
    if let Err(msg) = identity::check_login_provider_eligibility(&policy, AuthProviderId::Siwe, None)
    {
        return Err(api_error(StatusCode::FORBIDDEN, msg));
    }

    let msg = siwe::parse_siwe(&req.message)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e.to_string()))?;

    if msg.domain != *st.siwe_domain {
        return Err(api_error(StatusCode::UNAUTHORIZED, "domain mismatch"));
    }
    if msg.version != "1" {
        return Err(api_error(StatusCode::UNAUTHORIZED, "unsupported version"));
    }
    if msg.chain_id != st.chain_id {
        return Err(api_error(StatusCode::UNAUTHORIZED, "chain id mismatch"));
    }
    if msg.uri.contains("/user/login/approve")
        || msg
            .statement
            .as_deref()
            .is_some_and(|s| s.starts_with("Approve sign-in for another browser"))
    {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "handoff approval signature cannot be used for direct sign-in",
        ));
    }

    let now = session::now_secs();
    let Some(iat) = siwe::parse_rfc3339_epoch(&msg.issued_at) else {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid issued-at timestamp",
        ));
    };
    if now.abs_diff(iat) > config::SIWE_MAX_AGE_SECS {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "message issued-at out of range",
        ));
    }
    if let Some(exp_str) = &msg.expiration_time {
        let Some(exp) = siwe::parse_rfc3339_epoch(exp_str) else {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "invalid expiration timestamp",
            ));
        };
        if exp <= now {
            return Err(api_error(StatusCode::UNAUTHORIZED, "message expired"));
        }
    }

    // Atomic single-use nonce consumption in `AuthChallengeDO`!
    match challenge_do::consume_nonce(&st.env, &msg.nonce, "wallet").await {
        Ok(true) => {}
        Ok(false) => {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "unknown or expired nonce",
            ));
        }
        Err(e) => {
            worker::console_error!("siwe nonce consume failed: {e:?}");
            return Err(internal_error());
        }
    }

    let addr = siwe::recover_address(&req.message, &req.signature)
        .map_err(|e| api_error(StatusCode::UNAUTHORIZED, e.to_string()))?;
    if addr != msg.address.to_lowercase() {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "signature does not match address",
        ));
    }

    let ident = VerifiedExternalIdentity {
        provider_id: AuthProviderId::Siwe,
        issuer: format!("eip155:{}", st.chain_id),
        subject: addr.clone(),
        label: Some("Ethereum wallet".to_string()),
        verified_email: None,
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    };
    let account = identity::resolve_or_create_login_account(st, &policy, &ident).await?;
    Ok((account, ident))
}

/// The exact challenge a Solana wallet signs to log in (SIWS).
pub fn siws_challenge(domain: &str, nonce: &str) -> String {
    format!("Sign in to lets_embed with Solana\nDomain: {domain}\nNonce: {nonce}")
}

/// Verify a SIWS login payload, atomically consume its nonce from `AuthChallengeDO`,
/// enforce `AgeVerificationPolicy`, and resolve/create the `users_v2` account.
pub(crate) async fn verify_siws_and_ensure_user(
    st: &AppState,
    req: &SiwsReq,
) -> Result<(identity::ResolvedAccount, VerifiedExternalIdentity), Response> {
    let policy = policy_do::load_site_policy(&st.env)
        .await
        .map_err(|e| {
            worker::console_error!("siws: policy load failed: {e:?}");
            internal_error()
        })?
        .policy;
    if let Err(msg) = identity::check_login_provider_eligibility(&policy, AuthProviderId::Siws, None)
    {
        return Err(api_error(StatusCode::FORBIDDEN, msg));
    }

    if !session::is_sol_principal(&req.solana_address) {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid solana address"));
    }

    match challenge_do::consume_nonce(&st.env, &req.nonce, "wallet").await {
        Ok(true) => {}
        Ok(false) => {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "unknown or expired nonce",
            ));
        }
        Err(e) => {
            worker::console_error!("siws nonce consume failed: {e:?}");
            return Err(internal_error());
        }
    }

    let msg = siws_challenge(st.siwe_domain.as_str(), &req.nonce);
    if !solana_link::verify_ed25519_challenge(
        &req.solana_address,
        &req.signature,
        &msg,
        req.signed_message.as_deref(),
    ) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "signature verification failed",
        ));
    }

    let ident = VerifiedExternalIdentity {
        provider_id: AuthProviderId::Siws,
        issuer: "solana:mainnet".to_string(),
        subject: req.solana_address.clone(),
        label: Some("Solana wallet".to_string()),
        verified_email: None,
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    };
    let account = identity::resolve_or_create_login_account(st, &policy, &ident).await?;
    Ok((account, ident))
}

#[worker::send]
pub async fn verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<VerifyReq>,
) -> Response {
    if let Err(r) = require_same_origin(&st, &headers) {
        return r;
    }
    let (account, ident) = match verify_siwe_and_ensure_user(&st, &req).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    if let Err(r) = identity::issue_v2_session(
        &st,
        &cookies,
        &account,
        AuthProviderId::Siwe.as_str(),
        &ident.identity_key(),
        AssuranceLevel::None,
        false,
    )
    .await
    {
        return r;
    }
    Json(VerifyResp {
        address: display_address(&ident.subject),
    })
    .into_response()
}

#[worker::send]
pub async fn verify_solana(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<SiwsReq>,
) -> Response {
    if let Err(r) = require_same_origin(&st, &headers) {
        return r;
    }
    let (account, ident) = match verify_siws_and_ensure_user(&st, &req).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    if let Err(r) = identity::issue_v2_session(
        &st,
        &cookies,
        &account,
        AuthProviderId::Siws.as_str(),
        &ident.identity_key(),
        AssuranceLevel::None,
        false,
    )
    .await
    {
        return r;
    }
    Json(VerifyResp {
        address: ident.subject,
    })
    .into_response()
}

#[worker::send]
pub async fn logout(State(st): State<AppState>, headers: HeaderMap, cookies: Cookies) -> Response {
    if let Err(r) = require_same_origin(&st, &headers) {
        return r;
    }
    // Revoke active `sid` in `UserAccount` DO immediately (H8).
    if let Some(verified) = session::verify_cookie_session(
        &cookies,
        &st.session_v2_secret,
        st.legacy_jwt_secret.as_deref().map(Vec::as_slice),
    ) && let Some(sid) = verified.sid()
    {
        let _ = do_client::do_session_revoke(&st.env, verified.do_key(), sid).await;
    }
    cookies.add(session::clear_session_cookie());
    StatusCode::OK.into_response()
}

#[derive(Serialize)]
struct PricingItemView {
    kind: &'static str,
    label: &'static str,
    price: i64,
    daily_free: i64,
}

#[derive(Serialize)]
struct PlanView {
    id: &'static str,
    price_points: i64,
    views_per_window: Option<i64>,
    searches_per_window: i64,
    period_days: u64,
}

#[derive(Serialize)]
struct PricingSummary {
    points_per_usd: i64,
    minimum_topup: i64,
    signup_points: i64,
    dedupe_hours: u64,
    eth_deposit: String,
    sol_deposit: String,
    plans: Vec<PlanView>,
    items: Vec<PricingItemView>,
}

#[derive(Serialize)]
struct MeResp {
    // Existing StatusResp fields preserved 100% for backwards compatibility
    address: String,
    balance: i64,
    plan: Option<String>,
    period_end: u64,
    views_remaining: Option<i64>,
    searches_remaining: Option<i64>,
    window_reset: u64,
    banned: bool,
    total_views: i64,
    // Unified multi-auth + safety fields
    user_id: String,
    account_do_key: String,
    display_name: Option<String>,
    email: Option<String>,
    identities: Vec<IdentityView>,
    linked_eth_address: Option<String>,
    linked_solana_address: Option<String>,
    enabled_switchers: Vec<PolicyRef>,
    effective_switchers: Vec<PolicyRef>,
    switcher_statuses: Vec<SwitcherEligibility>,
    pref_version: u64,
    terms_version_accepted: Option<u32>,
    terms_digest_accepted: Option<String>,
    terms_accepted_at: Option<u64>,
    terms_up_to_date: bool,
    accepted_current_terms: bool,
    assurance_level: AssuranceLevel,
    strict_age_ok: bool,
    session_auth_time: Option<u64>,
    can_link_identity_now: bool,
    available_providers: Vec<AuthProviderPublicConfig>,
    policy: PublicSitePolicy,
    pricing: PricingSummary,
}

/// Compute `(enabled_switchers, effective_switchers, switcher_statuses)` for `GET /user/api/me`
/// from authoritative live Policy v3 and `SessionContext` (post-Safe-Mode wipe migration).
pub(crate) fn compute_me_switchers(
    policy: &PublicSitePolicy,
    ctx: &site_access::SessionContext,
    country: Option<&str>,
) -> (Vec<PolicyRef>, Vec<PolicyRef>, Vec<SwitcherEligibility>) {
    let enabled_switchers = safety_api::filter_active_policy_refs(policy, &ctx.enabled_switchers);
    let (effective_switchers, switcher_statuses) =
        safety_api::evaluate_switcher_eligibilities(policy, ctx, country);
    (enabled_switchers, effective_switchers, switcher_statuses)
}

#[worker::send]
pub async fn me(State(st): State<AppState>, headers: HeaderMap, cookies: Cookies) -> Response {
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    let status = match do_client::do_status(&st.env, &active.do_key).await {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("do status failed: {e:?}");
            return internal_error();
        }
    };
    let account = identity::load_account_by_id(&st, &active.user_id)
        .await
        .ok()
        .flatten();
    let identities = identity::list_user_identities(&st, &active.user_id)
        .await
        .unwrap_or_default();
    let linked_eth = identity::linked_eth_wallet(&st, &active.user_id)
        .await
        .ok()
        .flatten();
    let linked_sol = identity::linked_solana_wallet(&st, &active.user_id)
        .await
        .ok()
        .flatten();

    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(e) => {
            worker::console_error!("me: SitePolicyDO failed: {e:?}");
            return internal_error();
        }
    };
    let access_policy = settings::load(&st.env).await.unwrap_or_default();

    let session_info = if let Some(sid) = active.sid.as_deref() {
        do_client::do_session_info(&st.env, &active.do_key, sid)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let now = session::now_secs();
    let session_auth_time = session_info.as_ref().map(|s| s.created_at);
    let can_link_identity_now =
        session_auth_time.is_some_and(|t| identity::is_recent_auth(t, now));

    let country = safety_api::extract_cf_country(&headers);
    let (enabled_switchers, effective_switchers, switcher_statuses) =
        compute_me_switchers(&policy, &active.ctx, country.as_deref());
    let terms_up_to_date = active.ctx.satisfies_terms(&policy.legal);
    let available_providers: Vec<AuthProviderPublicConfig> = policy
        .effective_login_providers()
        .into_iter()
        .cloned()
        .collect();

    let display_addr = if !status.address.is_empty() && session::is_valid_principal(&status.address)
    {
        display_address(&status.address)
    } else if let Some(ref eth) = linked_eth {
        display_address(eth)
    } else if let Some(ref sol) = linked_sol {
        sol.clone()
    } else {
        account
            .as_ref()
            .and_then(|a| a.display_name.clone())
            .unwrap_or_else(|| active.user_id.clone())
    };

    let eth_deposit =
        if settings::valid_deposit_address(config::Chain::Ethereum, &access_policy.eth_deposit) {
            access_policy.eth_deposit.clone()
        } else {
            String::new()
        };
    let sol_deposit =
        if settings::valid_deposit_address(config::Chain::Solana, &access_policy.sol_deposit) {
            access_policy.sol_deposit.clone()
        } else {
            String::new()
        };

    let plans: Vec<PlanView> = config::PLANS
        .iter()
        .filter_map(|p| access_policy.plan(p.id))
        .map(|p| PlanView {
            id: p.id,
            price_points: p.price_points,
            views_per_window: p.views_per_window,
            searches_per_window: p.searches_per_window,
            period_days: p.period_secs / 86_400,
        })
        .collect();
    let items: Vec<PricingItemView> = site_access::ChargeKind::ALL
        .into_iter()
        .map(|kind| {
            let item = access_policy.item(kind);
            PricingItemView {
                kind: kind.name(),
                label: kind.label(),
                price: item.price,
                daily_free: item.daily_free,
            }
        })
        .collect();

    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(MeResp {
            address: display_addr,
            balance: status.balance,
            plan: status.plan,
            period_end: status.period_end,
            views_remaining: status.views_remaining,
            searches_remaining: status.searches_remaining,
            window_reset: status.window_reset,
            banned: status.banned,
            total_views: status.total_views,
            user_id: active.user_id,
            account_do_key: active.do_key,
            display_name: account.as_ref().and_then(|a| a.display_name.clone()),
            email: account.as_ref().and_then(|a| a.email.clone()),
            identities,
            linked_eth_address: linked_eth.map(|a| display_address(&a)),
            linked_solana_address: linked_sol,
            enabled_switchers,
            effective_switchers,
            switcher_statuses,
            pref_version: active.ctx.pref_version.max(1),
            terms_version_accepted: active.ctx.terms_version_accepted,
            terms_digest_accepted: active.ctx.terms_digest_accepted,
            terms_accepted_at: account.as_ref().and_then(|a| a.terms_accepted_at),
            terms_up_to_date,
            accepted_current_terms: terms_up_to_date,
            assurance_level: active.ctx.assurance_level,
            strict_age_ok: active.ctx.strict_age_ok,
            session_auth_time,
            can_link_identity_now,
            available_providers,
            policy,
            pricing: PricingSummary {
                points_per_usd: access_policy.points_per_usd,
                minimum_topup: access_policy.minimum_topup,
                signup_points: access_policy.signup_points,
                dedupe_hours: config::DEDUPE_WINDOW_SECS / 3600,
                eth_deposit,
                sol_deposit,
                plans,
                items,
            },
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn siws_challenge_is_deterministic() {
        assert_eq!(
            siws_challenge("app.example.com", "n1"),
            "Sign in to lets_embed with Solana\nDomain: app.example.com\nNonce: n1"
        );
    }

    #[test]
    fn siws_signature_roundtrip_verifies() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk_b58 = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        assert!(session::is_sol_principal(&pk_b58));

        let msg = siws_challenge("app.example.com", "nonce-xyz");
        let sig_b58 = bs58::encode(sk.sign(msg.as_bytes()).to_bytes()).into_string();
        assert!(solana_link::verify_ed25519_b58(&pk_b58, &sig_b58, &msg));

        let other = siws_challenge("evil.example.com", "nonce-xyz");
        assert!(!solana_link::verify_ed25519_b58(&pk_b58, &sig_b58, &other));
    }

    #[test]
    fn same_origin_rejects_duplicate_headers_and_accepts_public_origin() {
        use axum::http::HeaderValue;

        let mut ok = HeaderMap::new();
        ok.insert("origin", HeaderValue::from_static("https://pub.example.com"));
        ok.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(same_origin(
            &ok,
            "siwe.example.com",
            Some("https://pub.example.com")
        ));

        // Duplicate Origin header MUST fail closed
        let mut dup_origin = HeaderMap::new();
        dup_origin.append("origin", HeaderValue::from_static("https://siwe.example.com"));
        dup_origin.append("origin", HeaderValue::from_static("https://evil.example.com"));
        assert!(!same_origin(&dup_origin, "siwe.example.com", None));

        // Duplicate Sec-Fetch-Site header MUST fail closed
        let mut dup_sfs = HeaderMap::new();
        dup_sfs.append("sec-fetch-site", HeaderValue::from_static("same-origin"));
        dup_sfs.append("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(!same_origin(&dup_sfs, "siwe.example.com", None));
    }

    #[test]
    fn me_switchers_enforce_policy_v3_grant_generation_and_eligibility() {
        let mut policy = PublicSitePolicy {
            revision: 2,
            min_enforce_rev: 2,
            safety_enabled: true,
            age_policy: site_access::AgeVerificationPolicy::SelfAttestation,
            policies: vec![site_access::ContentPolicy {
                id: "r18".into(),
                grant_generation: 2,
                enabled: true,
                priority: 10,
                name: "R-18".into(),
                preset: site_access::PlaceholderPreset::R18,
                match_expr: "tag:explicit".into(),
                except_expr: None,
                default_tag_min: 0.45,
                action: site_access::PolicyAction::Block,
                bypass: site_access::PolicyBypass {
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
        policy.legal.terms_version = 1;
        policy.refresh_policy_digest();

        // Stale grant_generation (gen 1) is automatically invalidated when policy bumped to gen 2!
        let ctx_stale = site_access::SessionContext {
            active: true,
            banned: false,
            suspended: false,
            sid_valid: true,
            assurance_level: AssuranceLevel::SelfAttestation,
            strict_age_ok: false,
            terms_version_accepted: Some(1),
            terms_digest_accepted: Some(policy.legal.terms_digest.clone()),
            enabled_switchers: vec![PolicyRef::new("r18", 1)],
            pref_version: 2,
        };
        let (saved_stale, eff_stale, statuses_stale) =
            compute_me_switchers(&policy, &ctx_stale, Some("US"));
        assert!(saved_stale.is_empty());
        assert!(eff_stale.is_empty());
        assert_eq!(statuses_stale.len(), 1);
        assert!(!statuses_stale[0].opted_in);
        assert!(!statuses_stale[0].effective);

        // Current gen 2 in US succeeds; same gen 2 in excluded country GB is denied with reason!
        let ctx_cur = site_access::SessionContext {
            enabled_switchers: vec![PolicyRef::new("r18", 2)],
            ..ctx_stale
        };
        let (saved_us, eff_us, statuses_us) = compute_me_switchers(&policy, &ctx_cur, Some("US"));
        assert_eq!(saved_us, vec![PolicyRef::new("r18", 2)]);
        assert_eq!(eff_us, vec![PolicyRef::new("r18", 2)]);
        assert!(statuses_us[0].effective);
        assert!(statuses_us[0].missing_requirements.is_empty());

        let (saved_gb, eff_gb, statuses_gb) = compute_me_switchers(&policy, &ctx_cur, Some("GB"));
        assert_eq!(saved_gb, vec![PolicyRef::new("r18", 2)]);
        assert!(eff_gb.is_empty());
        assert!(statuses_gb[0].country_excluded);
        assert!(!statuses_gb[0].effective);
        assert!(!statuses_gb[0].missing_requirements.is_empty());
    }
}
