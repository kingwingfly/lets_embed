//! OAuth 2.0 & OIDC providers (`OidcAgeAssurance`, `Google`, `GitHub`, `X`, `Discord`)
//! (fixes H7, H11, H12, L2).
//!
//! Security properties:
//! - Every flow uses PKCE `S256`, `state`, OIDC `nonce`, and a browser-bound
//!   `__Host-auth_tx` cookie verified atomically in `AuthChallengeDO`.
//! - Fixed registered callback URI derived strictly from pinned `PUBLIC_URL` / `SIWE_DOMAIN` (L2).
//! - Callback re-checks provider enablement AND `AgeVerificationPolicy` before issuing session!
//! - Google optional `user.birthday.read` People API check records strictly
//!   `AssuranceLevel::ProviderSelfReportedDob` (NEVER `Verified18`, auto-rejected in Strict 18+!).
//! - `OidcAgeAssurance` sets `AssuranceLevel::Verified18` ONLY when discovery/JWKS/claims +
//!   verified 18+ proof pass!

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use site_access::{
    AgeVerificationPolicy, AssuranceLevel, AuthProviderId, AuthProviderPublicConfig,
    PublicSitePolicy,
};
use tower_cookies::Cookies;
use worker::Method;

use crate::{
    AppState, auth,
    challenge_do::{self, OAuthTxConsumeReq, OAuthTxStartReq},
    identity::{self, VerifiedExternalIdentity},
    policy_do,
    providers::{
        ip_rate_key, pkce_s256_challenge, random_b64url, sanitize_next_url, sha256_hex,
        ssrf::{fetch_https_no_redirect, validate_oidc_url},
    },
    secrets, session,
};

use super::oidc::{
    evaluate_verified_18_claims, is_dob_at_least_18, load_oidc_material, verify_id_token,
};

const OAUTH_TX_TTL_SECS: u64 = 600;

#[derive(Debug, Deserialize)]
pub struct StartQuery {
    #[serde(default)]
    pub next: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

fn parse_oauth_provider(slug: &str) -> Option<AuthProviderId> {
    match slug.trim() {
        "oidc_age_assurance" => Some(AuthProviderId::OidcAgeAssurance),
        "google" => Some(AuthProviderId::Google),
        "github" => Some(AuthProviderId::GitHub),
        "x" => Some(AuthProviderId::X),
        "discord" => Some(AuthProviderId::Discord),
        _ => None,
    }
}

fn find_provider_config(
    policy: &PublicSitePolicy,
    provider: AuthProviderId,
) -> Option<&AuthProviderPublicConfig> {
    policy.enabled_providers.iter().find(|p| p.id == provider)
}

fn fallback_secret_env_name(provider: AuthProviderId) -> &'static [&'static str] {
    match provider {
        AuthProviderId::OidcAgeAssurance => &["OIDC_AGE_CLIENT_SECRET"],
        AuthProviderId::Google => &["GOOGLE_CLIENT_SECRET"],
        AuthProviderId::GitHub => &["GITHUB_CLIENT_SECRET"],
        AuthProviderId::X => &["X_CLIENT_SECRET"],
        AuthProviderId::Discord => &["DISCORD_CLIENT_SECRET"],
        _ => &[],
    }
}

fn redirect_with_error(dest: &str, message: &str) -> Response {
    let target = format!("{dest}?error={}", urlencoding::encode(message));
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, target),
            (header::CACHE_CONTROL, "private, no-store".to_string()),
        ],
    )
        .into_response()
}

/// Begin an OAuth/OIDC transaction (for either `"login"` or `"link"`), persist it
/// atomically in `AuthChallengeDO`, set the browser-bound `__Host-auth_tx` cookie,
/// and return the provider's `authorization_url`.
#[allow(clippy::too_many_arguments)]
pub async fn begin_oauth_flow(
    st: &AppState,
    headers: &HeaderMap,
    cookies: &Cookies,
    policy: &PublicSitePolicy,
    provider: AuthProviderId,
    action: &str,
    initiator_user_id: Option<String>,
    next_url: String,
) -> Result<String, Response> {
    if let Err(msg) = identity::check_login_provider_eligibility(policy, provider, None) {
        return Err(auth::api_error(StatusCode::FORBIDDEN, msg));
    }

    let Some(cfg) = find_provider_config(policy, provider) else {
        return Err(auth::api_error(
            StatusCode::FORBIDDEN,
            "provider is not configured",
        ));
    };
    let Some(client_id) = cfg
        .public_client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(auth::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider client_id is not configured",
        ));
    };

    let tx_id = random_b64url(16)?;
    let tx_cookie_secret = random_b64url(24)?;
    let state = random_b64url(24)?;
    let pkce_verifier = random_b64url(32)?;
    let pkce_challenge = pkce_s256_challenge(&pkce_verifier);
    let nonce = random_b64url(24)?;
    let redirect_uri = format!(
        "{}/user/auth/{}/callback",
        st.public_origin(),
        provider.as_str()
    );

    let (auth_endpoint, scope) = match provider {
        AuthProviderId::OidcAgeAssurance => {
            let Some(issuer) = cfg.issuer.as_deref().map(str::trim).filter(|s| !s.is_empty())
            else {
                return Err(auth::api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "OIDC age-assurance issuer URL is not configured",
                ));
            };
            let mat = load_oidc_material(&st.env, issuer, false)
                .await
                .map_err(|e| {
                    worker::console_error!("OIDC discovery failed: {e}");
                    auth::api_error(
                        StatusCode::BAD_GATEWAY,
                        "Age-assurance OIDC discovery failed",
                    )
                })?;
            (
                mat.endpoints.authorization_endpoint,
                "openid profile age_over_18".to_string(),
            )
        }
        AuthProviderId::Google => {
            let mut scopes = String::from("openid email profile");
            if cfg.soft_birthday_check
                && policy.age_policy == AgeVerificationPolicy::SelfAttestation
            {
                scopes.push_str(" https://www.googleapis.com/auth/user.birthday.read");
            }
            (
                "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                scopes,
            )
        }
        AuthProviderId::GitHub => (
            "https://github.com/login/oauth/authorize".to_string(),
            "read:user".to_string(),
        ),
        AuthProviderId::X => (
            "https://x.com/i/oauth2/authorize".to_string(),
            "users.read tweet.read".to_string(),
        ),
        AuthProviderId::Discord => (
            "https://discord.com/api/v10/oauth2/authorize".to_string(),
            "identify".to_string(),
        ),
        _ => {
            return Err(auth::api_error(
                StatusCode::BAD_REQUEST,
                "provider does not use OAuth redirect flow",
            ));
        }
    };

    let now = session::now_secs();
    let ip_bucket = format!("oauth:{}", ip_rate_key(headers, &st.session_v2_secret));
    match challenge_do::hit_rate_limit(&st.env, &ip_bucket, 600, 40).await {
        Ok(rl) if !rl.allowed => {
            return Err(auth::api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many sign-in attempts; retry later",
            ));
        }
        Ok(_) => {}
        Err(e) => {
            worker::console_error!("oauth ip rate limit DO failed: {e:?}");
            return Err(auth::internal_error());
        }
    }
    let (status, msg) = challenge_do::start_oauth_tx(
        &st.env,
        &OAuthTxStartReq {
            tx_id: tx_id.clone(),
            tx_cookie_hash: sha256_hex(&tx_cookie_secret),
            provider_id: provider.as_str().to_string(),
            action: action.to_string(),
            initiator_user_id,
            redirect_uri: redirect_uri.clone(),
            state: state.clone(),
            pkce_verifier,
            nonce: nonce.clone(),
            next_url,
            expires_at: now + OAUTH_TX_TTL_SECS,
            ip_bucket: None,
        },
    )
    .await
    .map_err(|e| {
        worker::console_error!("oauth start DO failed: {e:?}");
        auth::internal_error()
    })?;
    if status == 429 {
        return Err(auth::api_error(StatusCode::TOO_MANY_REQUESTS, msg));
    }
    if status != 200 {
        worker::console_error!("oauth start DO status {status}: {msg}");
        return Err(auth::internal_error());
    }

    cookies.add(session::make_auth_tx_cookie(
        format!("{tx_id}.{tx_cookie_secret}"),
        OAUTH_TX_TTL_SECS as i64,
    ));

    let mut params = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.to_string()),
        ("redirect_uri", redirect_uri),
        ("scope", scope),
        ("state", state),
        ("code_challenge", pkce_challenge),
        ("code_challenge_method", "S256".to_string()),
    ];
    if matches!(
        provider,
        AuthProviderId::OidcAgeAssurance | AuthProviderId::Google
    ) {
        params.push(("nonce", nonce));
    }
    let query_str: String = params
        .into_iter()
        .map(|(k, v)| format!("{k}={}", urlencoding::encode(&v)))
        .collect::<Vec<_>>()
        .join("&");

    let sep = if auth_endpoint.contains('?') { '&' } else { '?' };
    Ok(format!("{auth_endpoint}{sep}{query_str}"))
}

/// `GET /user/auth/:provider/start`
#[worker::send]
pub async fn start(
    State(st): State<AppState>,
    Path(provider_slug): Path<String>,
    Query(q): Query<StartQuery>,
    headers: HeaderMap,
    cookies: Cookies,
) -> Response {
    let Some(provider) = parse_oauth_provider(&provider_slug) else {
        return auth::api_error(StatusCode::NOT_FOUND, "unknown auth provider");
    };
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(env) => env.policy,
        Err(e) => {
            worker::console_error!("oauth start: policy load failed: {e:?}");
            return auth::internal_error();
        }
    };
    let next_url = sanitize_next_url(q.next.as_deref());
    match begin_oauth_flow(
        &st, &headers, &cookies, &policy, provider, "login", None, next_url,
    )
    .await
    {
        Ok(url) => (
            StatusCode::FOUND,
            [
                (header::LOCATION, url),
                (header::CACHE_CONTROL, "private, no-store".to_string()),
            ],
        )
            .into_response(),
        Err(r) => r,
    }
}

/// `GET /user/auth/:provider/callback`
#[worker::send]
pub async fn callback(
    State(st): State<AppState>,
    Path(provider_slug): Path<String>,
    Query(q): Query<CallbackQuery>,
    cookies: Cookies,
) -> Response {
    let Some(provider) = parse_oauth_provider(&provider_slug) else {
        return auth::api_error(StatusCode::NOT_FOUND, "unknown auth provider");
    };

    // Always clear `__Host-auth_tx` immediately regardless of outcome.
    let raw_tx_cookie = cookies
        .get(session::AUTH_TX_COOKIE)
        .map(|c| c.value().to_string());
    cookies.add(session::clear_auth_tx_cookie());

    if let Some(err_code) = q.error.as_deref().filter(|s| !s.is_empty()) {
        return redirect_with_error("/user/login", &format!("Sign-in canceled ({err_code})"));
    }

    let (Some(code), Some(state), Some(tx_cookie)) = (
        q.code.as_deref().filter(|s| !s.is_empty()),
        q.state.as_deref().filter(|s| !s.is_empty()),
        raw_tx_cookie.as_deref(),
    ) else {
        return redirect_with_error("/user/login", "Missing or expired sign-in transaction");
    };

    let Some((tx_id, tx_cookie_secret)) = tx_cookie.split_once('.') else {
        return redirect_with_error("/user/login", "Invalid sign-in transaction cookie");
    };

    // Atomically consume single-use browser-bound OAuth transaction from `AuthChallengeDO`!
    let tx = match challenge_do::consume_oauth_tx(
        &st.env,
        &OAuthTxConsumeReq {
            tx_id: tx_id.to_string(),
            tx_cookie_hash: sha256_hex(tx_cookie_secret),
            state: state.to_string(),
        },
    )
    .await
    {
        Ok(Some(tx)) if tx.provider_id == provider.as_str() => tx,
        Ok(_) => {
            return redirect_with_error("/user/login", "Sign-in transaction expired or mismatched");
        }
        Err(e) => {
            worker::console_error!("oauth consume DO failed: {e:?}");
            return redirect_with_error("/user/login", "Sign-in verification error");
        }
    };

    let fallback_dest = if tx.action == "link" {
        "/user/account"
    } else {
        "/user/login"
    };

    // Re-check current published policy (catches admin disabling provider or tightening
    // to StrictProviderVerified18 mid-flow!).
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(env) => env.policy,
        Err(e) => {
            worker::console_error!("oauth callback: policy load failed: {e:?}");
            return redirect_with_error(fallback_dest, "Site policy unavailable");
        }
    };

    if let Err(msg) = identity::check_login_provider_eligibility(&policy, provider, None) {
        return redirect_with_error(fallback_dest, msg);
    }

    let Some(cfg) = find_provider_config(&policy, provider) else {
        return redirect_with_error(fallback_dest, "Provider is no longer configured");
    };
    let Some(client_id) = cfg
        .public_client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return redirect_with_error(fallback_dest, "Provider client_id missing");
    };

    let client_secret = match secrets::load_provider_secret(
        &st.env,
        &st.deployment_id,
        policy.revision,
        provider.as_str(),
        "client_secret",
        fallback_secret_env_name(provider),
    )
    .await
    {
        Ok(sec) => sec,
        Err(e) => {
            worker::console_error!("secret decrypt failed for {}: {e}", provider.as_str());
            return redirect_with_error(fallback_dest, "Provider credentials unavailable");
        }
    };

    // Exchange authorization code & fetch verified external identity.
    let ident = match complete_provider_exchange(
        &st,
        &policy,
        cfg,
        provider,
        client_id,
        client_secret.as_ref().map(|s| s.expose()),
        code,
        &tx.redirect_uri,
        &tx.pkce_verifier,
        &tx.nonce,
    )
    .await
    {
        Ok(id) => id,
        Err(msg) => return redirect_with_error(fallback_dest, &msg),
    };

    // Re-check eligibility WITH verified assurance level (strict 18+ requires Verified18!).
    if let Err(msg) = identity::check_login_provider_eligibility(
        &policy,
        provider,
        Some(ident.assurance_level),
    ) {
        return redirect_with_error(fallback_dest, msg);
    }

    if tx.action == "link" {
        let active = match identity::require_active_session(&st, &cookies).await {
            Ok(a) => a,
            Err(_) => {
                return redirect_with_error("/user/login", "Sign in required to link account");
            }
        };
        if tx.initiator_user_id.as_deref() != Some(active.user_id.as_str()) {
            return redirect_with_error("/user/account", "Account mismatch while linking identity");
        }
        if identity::require_recent_auth(&st, &active).await.is_err() {
            return redirect_with_error(
                "/user/account",
                "Recent authentication required — sign in again before linking",
            );
        }
        if identity::link_identity_atomic(&st, &active.user_id, &ident, "login")
            .await
            .is_err()
        {
            return redirect_with_error(
                "/user/account",
                "That identity is already linked to an account",
            );
        }

        // Always revoke old `active.sid` and rotate session on `purpose == "login"` link (H8).
        if identity::rotate_session_on_identity_link(&st, &cookies, &active, &ident)
            .await
            .is_err()
        {
            return redirect_with_error("/user/login", "Could not rotate session after linking");
        }
        return (
            StatusCode::FOUND,
            [
                (header::LOCATION, "/user/account?linked=1".to_string()),
                (header::CACHE_CONTROL, "private, no-store".to_string()),
            ],
        )
            .into_response();
    }

    let account = match identity::resolve_or_create_login_account(&st, &policy, &ident).await {
        Ok(a) => a,
        Err(_) => return redirect_with_error("/user/login", "Account is suspended or unavailable"),
    };
    let now = session::now_secs();
    let strict_ok = ident.is_strict_age_verified(now);
    if identity::issue_v2_session(
        &st,
        &cookies,
        &account,
        provider.as_str(),
        &ident.identity_key(),
        ident.assurance_level,
        strict_ok,
    )
    .await
    .is_err()
    {
        return redirect_with_error("/user/login", "Could not issue session");
    }

    let dest = sanitize_next_url(Some(&tx.next_url));
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, dest),
            (header::CACHE_CONTROL, "private, no-store".to_string()),
        ],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Provider-Specific Token Exchange & User Verification
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn complete_provider_exchange(
    st: &AppState,
    policy: &PublicSitePolicy,
    cfg: &AuthProviderPublicConfig,
    provider: AuthProviderId,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: &str,
    expected_nonce: &str,
) -> Result<VerifiedExternalIdentity, String> {
    match provider {
        AuthProviderId::OidcAgeAssurance => {
            exchange_oidc_age_assurance(
                st,
                cfg,
                client_id,
                client_secret,
                code,
                redirect_uri,
                pkce_verifier,
                expected_nonce,
            )
            .await
        }
        AuthProviderId::Google => {
            exchange_google(
                st,
                policy,
                cfg,
                client_id,
                client_secret,
                code,
                redirect_uri,
                pkce_verifier,
                expected_nonce,
            )
            .await
        }
        AuthProviderId::GitHub => {
            exchange_github(client_id, client_secret, code, redirect_uri, pkce_verifier).await
        }
        AuthProviderId::X => {
            exchange_x(client_id, client_secret, code, redirect_uri, pkce_verifier).await
        }
        AuthProviderId::Discord => {
            exchange_discord(client_id, client_secret, code, redirect_uri, pkce_verifier).await
        }
        _ => Err("unsupported OAuth provider".to_string()),
    }
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[allow(clippy::too_many_arguments)]
async fn exchange_oidc_age_assurance(
    st: &AppState,
    cfg: &AuthProviderPublicConfig,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: &str,
    expected_nonce: &str,
) -> Result<VerifiedExternalIdentity, String> {
    let issuer = cfg
        .issuer
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "OIDC issuer not configured".to_string())?;
    let _ = validate_oidc_url(issuer).map_err(|e| format!("invalid OIDC issuer: {e}"))?;

    let mut mat = load_oidc_material(&st.env, issuer, false)
        .await
        .map_err(|e| format!("OIDC discovery failed: {e}"))?;

    let mut form_fields = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", pkce_verifier),
    ];
    if let Some(secret) = client_secret {
        form_fields.push(("client_secret", secret));
    }

    let mut token_resp = fetch_https_no_redirect(
        &mat.endpoints.token_endpoint,
        Method::Post,
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "application/json"),
            ("user-agent", "lets-embed-user-worker"),
        ],
        Some(form_encode(&form_fields)),
    )
    .await
    .map_err(|e| format!("OIDC token exchange failed: {e}"))?;
    let token_json: Value = token_resp
        .json()
        .await
        .map_err(|_| "invalid OIDC token JSON".to_string())?;
    let id_token = token_json
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "OIDC provider did not return an id_token".to_string())?;

    let now = session::now_secs();
    let verified = match verify_id_token(
        id_token,
        &mat.jwks,
        &mat.endpoints.issuer,
        client_id,
        expected_nonce,
        now,
    )
    .await
    {
        Ok(v) => v,
        Err(super::oidc::OidcError::UnknownKeyId) => {
            // Single JWKS cache refresh on key rotation.
            mat = load_oidc_material(&st.env, issuer, true)
                .await
                .map_err(|e| format!("OIDC JWKS refresh failed: {e}"))?;
            verify_id_token(
                id_token,
                &mat.jwks,
                &mat.endpoints.issuer,
                client_id,
                expected_nonce,
                now,
            )
            .await
            .map_err(|e| format!("OIDC ID token verification failed: {e}"))?
        }
        Err(e) => return Err(format!("OIDC ID token verification failed: {e}")),
    };

    let required_acr = st.env.var("OIDC_AGE_REQUIRED_ACR").ok().map(|v| v.to_string());
    let required_amr = st.env.var("OIDC_AGE_REQUIRED_AMR").ok().map(|v| v.to_string());

    let age_res = evaluate_verified_18_claims(
        &verified,
        required_acr.as_deref(),
        required_amr.as_deref(),
        now,
    );

    let (assurance_level, assurance_method, verified_at) = match age_res {
        Ok(res) if res.verified_18 => (AssuranceLevel::Verified18, Some(res.method), Some(now)),
        _ => (AssuranceLevel::None, None, None),
    };

    Ok(VerifiedExternalIdentity {
        provider_id: AuthProviderId::OidcAgeAssurance,
        issuer: verified.iss,
        subject: verified.sub,
        label: verified.name,
        verified_email: verified.email_verified.then_some(verified.email).flatten(),
        assurance_level,
        assurance_method,
        assurance_verified_at: verified_at,
        assurance_expires_at: None,
    })
}

#[allow(clippy::too_many_arguments)]
async fn exchange_google(
    st: &AppState,
    policy: &PublicSitePolicy,
    cfg: &AuthProviderPublicConfig,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: &str,
    expected_nonce: &str,
) -> Result<VerifiedExternalIdentity, String> {
    let secret = client_secret.ok_or_else(|| "Google client_secret not configured".to_string())?;
    let body = form_encode(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", secret),
        ("code_verifier", pkce_verifier),
    ]);
    let mut token_resp = fetch_https_no_redirect(
        "https://oauth2.googleapis.com/token",
        Method::Post,
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "application/json"),
        ],
        Some(body),
    )
    .await
    .map_err(|e| format!("Google token exchange failed: {e}"))?;
    let token_json: Value = token_resp
        .json()
        .await
        .map_err(|_| "invalid Google token JSON".to_string())?;

    let id_token = token_json
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "Google did not return an id_token".to_string())?;
    let access_token = token_json.get("access_token").and_then(Value::as_str);

    let now = session::now_secs();
    let mat = load_oidc_material(&st.env, "https://accounts.google.com", false)
        .await
        .map_err(|e| format!("Google JWKS load failed: {e}"))?;
    let verified = match verify_id_token(
        id_token,
        &mat.jwks,
        "https://accounts.google.com",
        client_id,
        expected_nonce,
        now,
    )
    .await
    {
        Ok(v) => v,
        Err(super::oidc::OidcError::UnknownKeyId) => {
            let fresh = load_oidc_material(&st.env, "https://accounts.google.com", true)
                .await
                .map_err(|e| format!("Google JWKS refresh failed: {e}"))?;
            verify_id_token(
                id_token,
                &fresh.jwks,
                "https://accounts.google.com",
                client_id,
                expected_nonce,
                now,
            )
            .await
            .map_err(|e| format!("Google ID token invalid: {e}"))?
        }
        Err(e) => return Err(format!("Google ID token invalid: {e}")),
    };

    // Optional soft convenience birthday pre-check (ONLY in SelfAttestation mode, NEVER Verified18!).
    let mut assurance_level = AssuranceLevel::None;
    let mut assurance_method = None;
    let mut assurance_verified_at = None;
    if cfg.soft_birthday_check
        && policy.age_policy == AgeVerificationPolicy::SelfAttestation
        && let Some(at) = access_token
    {
        let auth_hdr = format!("Bearer {at}");
        if let Ok(mut resp) = fetch_https_no_redirect(
            "https://people.googleapis.com/v1/people/me?personFields=birthdays",
            Method::Get,
            &[("authorization", &auth_hdr), ("accept", "application/json")],
            None,
        )
        .await
            && let Ok(people_json) = resp.json::<Value>().await
        {
            match evaluate_google_birthday(&people_json, now) {
                Some(true) => {
                    // Strictly ProviderSelfReportedDob — NEVER Verified18!
                    assurance_level = AssuranceLevel::ProviderSelfReportedDob;
                    assurance_method = Some("google_people_birthday".to_string());
                    assurance_verified_at = Some(now);
                }
                Some(false) => {
                    return Err("Google profile birthday indicates age under 18".to_string());
                }
                None => {}
            }
        }
    }

    Ok(VerifiedExternalIdentity {
        provider_id: AuthProviderId::Google,
        issuer: "https://accounts.google.com".to_string(),
        subject: verified.sub,
        label: verified.name,
        verified_email: verified.email_verified.then_some(verified.email).flatten(),
        assurance_level,
        assurance_method,
        assurance_verified_at,
        assurance_expires_at: None,
    })
}

/// Extract full `YYYY-MM-DD` birthday from Google People API response and check >= 18.
/// Partial dates (missing year) return `None`.
pub fn evaluate_google_birthday(people_json: &Value, now_epoch_secs: u64) -> Option<bool> {
    let birthdays = people_json.get("birthdays")?.as_array()?;
    for entry in birthdays {
        let Some(date) = entry.get("date") else {
            continue;
        };
        let (Some(y), Some(m), Some(d)) = (
            date.get("year").and_then(Value::as_i64),
            date.get("month").and_then(Value::as_i64),
            date.get("day").and_then(Value::as_i64),
        ) else {
            continue;
        };
        if y <= 0 || m <= 0 || d <= 0 {
            continue;
        }
        let dob = format!("{y:04}-{m:02}-{d:02}");
        if let Some(is_18) = is_dob_at_least_18(&dob, now_epoch_secs) {
            return Some(is_18);
        }
    }
    None
}

async fn exchange_github(
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: &str,
) -> Result<VerifiedExternalIdentity, String> {
    let secret = client_secret.ok_or_else(|| "GitHub client_secret not configured".to_string())?;
    let body = form_encode(&[
        ("client_id", client_id),
        ("client_secret", secret),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", pkce_verifier),
    ]);
    let mut token_resp = fetch_https_no_redirect(
        "https://github.com/login/oauth/access_token",
        Method::Post,
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "application/json"),
        ],
        Some(body),
    )
    .await
    .map_err(|e| format!("GitHub token exchange failed: {e}"))?;
    let token_json: Value = token_resp
        .json()
        .await
        .map_err(|_| "invalid GitHub token JSON".to_string())?;
    let access_token = token_json
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "GitHub did not return an access_token".to_string())?;

    let auth_hdr = format!("Bearer {access_token}");
    let mut user_resp = fetch_https_no_redirect(
        "https://api.github.com/user",
        Method::Get,
        &[
            ("authorization", &auth_hdr),
            ("accept", "application/vnd.github+json"),
            ("user-agent", "lets-embed-user-worker"),
        ],
        None,
    )
    .await
    .map_err(|e| format!("GitHub user fetch failed: {e}"))?;
    let user: Value = user_resp
        .json()
        .await
        .map_err(|_| "invalid GitHub user JSON".to_string())?;
    let id = user
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| "GitHub user response missing numeric id".to_string())?;
    let login = user
        .get("login")
        .and_then(Value::as_str)
        .map(|s| format!("@{s}"));

    Ok(VerifiedExternalIdentity {
        provider_id: AuthProviderId::GitHub,
        issuer: "https://github.com".to_string(),
        subject: id.to_string(),
        label: login,
        verified_email: None,
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    })
}

async fn exchange_x(
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: &str,
) -> Result<VerifiedExternalIdentity, String> {
    let body = form_encode(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", pkce_verifier),
    ]);
    let mut hdrs: Vec<(&str, String)> = vec![
        ("content-type", "application/x-www-form-urlencoded".into()),
        ("accept", "application/json".into()),
        ("user-agent", "lets-embed-user-worker".into()),
    ];
    if let Some(secret) = client_secret {
        // RFC 6749 §2.3.1 requires application/x-www-form-urlencoded encoding before Base64.
        let enc_id = urlencoding::encode(client_id);
        let enc_secret = urlencoding::encode(secret);
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{enc_id}:{enc_secret}").as_bytes());
        hdrs.push(("authorization", format!("Basic {basic}")));
    }
    let hdr_refs: Vec<(&str, &str)> = hdrs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mut token_resp = fetch_https_no_redirect(
        "https://api.x.com/2/oauth2/token",
        Method::Post,
        &hdr_refs,
        Some(body),
    )
    .await
    .map_err(|e| format!("X token exchange failed: {e}"))?;
    let token_json: Value = token_resp
        .json()
        .await
        .map_err(|_| "invalid X token JSON".to_string())?;
    let access_token = token_json
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "X did not return an access_token".to_string())?;

    let auth_hdr = format!("Bearer {access_token}");
    let mut user_resp = fetch_https_no_redirect(
        "https://api.x.com/2/users/me",
        Method::Get,
        &[
            ("authorization", &auth_hdr),
            ("accept", "application/json"),
            ("user-agent", "lets-embed-user-worker"),
        ],
        None,
    )
    .await
    .map_err(|e| format!("X user fetch failed: {e}"))?;
    let user: Value = user_resp
        .json()
        .await
        .map_err(|_| "invalid X user JSON".to_string())?;
    let data = user
        .get("data")
        .ok_or_else(|| "X response missing data".to_string())?;
    let id = data
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "X response missing immutable user id".to_string())?;
    let username = data
        .get("username")
        .and_then(Value::as_str)
        .map(|u| format!("@{u}"));

    Ok(VerifiedExternalIdentity {
        provider_id: AuthProviderId::X,
        issuer: "https://x.com".to_string(),
        subject: id.to_string(),
        label: username,
        verified_email: None,
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    })
}

async fn exchange_discord(
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: &str,
) -> Result<VerifiedExternalIdentity, String> {
    let secret = client_secret.ok_or_else(|| "Discord client_secret not configured".to_string())?;
    let body = form_encode(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", secret),
        ("code_verifier", pkce_verifier),
    ]);
    let mut token_resp = fetch_https_no_redirect(
        "https://discord.com/api/v10/oauth2/token",
        Method::Post,
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "application/json"),
            ("user-agent", "lets-embed-user-worker"),
        ],
        Some(body),
    )
    .await
    .map_err(|e| format!("Discord token exchange failed: {e}"))?;
    let token_json: Value = token_resp
        .json()
        .await
        .map_err(|_| "invalid Discord token JSON".to_string())?;
    let access_token = token_json
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "Discord did not return an access_token".to_string())?;

    let auth_hdr = format!("Bearer {access_token}");
    let mut user_resp = fetch_https_no_redirect(
        "https://discord.com/api/v10/users/@me",
        Method::Get,
        &[
            ("authorization", &auth_hdr),
            ("accept", "application/json"),
            ("user-agent", "lets-embed-user-worker"),
        ],
        None,
    )
    .await
    .map_err(|e| format!("Discord user fetch failed: {e}"))?;
    let user: Value = user_resp
        .json()
        .await
        .map_err(|_| "invalid Discord user JSON".to_string())?;
    let id = user
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| "Discord response missing snowflake id".to_string())?;
    let username = user
        .get("username")
        .and_then(Value::as_str)
        .map(str::to_string);

    Ok(VerifiedExternalIdentity {
        provider_id: AuthProviderId::Discord,
        issuer: "https://discord.com".to_string(),
        subject: id.to_string(),
        label: username,
        verified_email: None,
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-11-23T00:00:00Z
    const NOW: u64 = 1_795_392_000;

    #[test]
    fn google_birthday_requires_full_yyyy_mm_dd_and_never_grants_verified_18() {
        let adult = serde_json::json!({
            "birthdays": [
                { "date": { "month": 5, "day": 10 } }, // partial date ignored
                { "date": { "year": 2000, "month": 1, "day": 15 } }
            ]
        });
        assert_eq!(evaluate_google_birthday(&adult, NOW), Some(true));

        let minor = serde_json::json!({
            "birthdays": [
                { "date": { "year": 2010, "month": 1, "day": 15 } }
            ]
        });
        assert_eq!(evaluate_google_birthday(&minor, NOW), Some(false));

        let partial_only = serde_json::json!({
            "birthdays": [
                { "date": { "month": 1, "day": 15 } }
            ]
        });
        assert_eq!(evaluate_google_birthday(&partial_only, NOW), None);

        // Even with a full Google DOB, Google provider MUST NEVER satisfy StrictProviderVerified18!
        assert!(!AuthProviderId::Google.supports_strict_age_verification());
        assert!(!AuthProviderId::Google.is_allowed_under(AgeVerificationPolicy::StrictProviderVerified18));
    }
}
