//! Telegram Login Widget authentication (fixes H7, H12).
//!
//! Security checks:
//! - Constant-time HMAC-SHA256 over canonical alphabetically sorted check string
//!   using `secret_key = SHA256(bot_token)`.
//! - Strict `auth_date` window: rejects assertions older than 300s or > 60s in future.
//! - Atomic replay guard: consumes `SHA256(hash)` in `AuthChallengeDO` with TTL `auth_date + 360`.
//! - Automatically rejected under `AgeVerificationPolicy::StrictProviderVerified18`!

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use site_access::{AssuranceLevel, AuthProviderId};
use subtle::ConstantTimeEq;
use tower_cookies::Cookies;

use crate::{
    AppState, auth,
    challenge_do::{self, OAuthTxConsumeReq, OAuthTxStartReq},
    identity, policy_do,
    providers::{ip_rate_key, random_b64url, sanitize_next_url, sha256_hex},
    secrets, session,
    types::ApiError,
};

type HmacSha256 = Hmac<Sha256>;

pub const TELEGRAM_MAX_AGE_SECS: u64 = 300;
pub const TELEGRAM_MAX_FUTURE_SKEW_SECS: u64 = 60;
pub const TELEGRAM_REPLAY_TTL_PADDING_SECS: u64 = 360;
const TELEGRAM_TX_TTL_SECS: u64 = 600;

#[derive(Debug, Clone, Deserialize)]
pub struct TelegramAuthPayload {
    pub id: i64,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub photo_url: Option<String>,
    pub auth_date: u64,
    pub hash: String,
    /// Optional `"login"` (default) or `"link"` for explicit identity linking.
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelegramAuthError {
    InvalidId,
    ExpiredAuthDate,
    FutureAuthDate,
    InvalidHashFormat,
    SignatureMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTelegramAssertion {
    pub telegram_id: i64,
    pub label: String,
    pub assertion_digest: String,
    pub replay_expires_at: u64,
}

/// Build the canonical Telegram Login Widget `data_check_string`:
/// all non-empty fields except `hash`, sorted alphabetically by key, joined with `\n`.
pub fn build_telegram_check_string(p: &TelegramAuthPayload) -> String {
    let mut fields: BTreeMap<&'static str, String> = BTreeMap::new();
    fields.insert("auth_date", p.auth_date.to_string());
    fields.insert("id", p.id.to_string());
    if let Some(v) = p.first_name.as_deref().filter(|s| !s.is_empty()) {
        fields.insert("first_name", v.to_string());
    }
    if let Some(v) = p.last_name.as_deref().filter(|s| !s.is_empty()) {
        fields.insert("last_name", v.to_string());
    }
    if let Some(v) = p.photo_url.as_deref().filter(|s| !s.is_empty()) {
        fields.insert("photo_url", v.to_string());
    }
    if let Some(v) = p.username.as_deref().filter(|s| !s.is_empty()) {
        fields.insert("username", v.to_string());
    }
    fields
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Pure Telegram Login Widget signature + timestamp window verification (host-testable).
pub fn verify_telegram_payload(
    payload: &TelegramAuthPayload,
    bot_token: &str,
    now: u64,
) -> Result<VerifiedTelegramAssertion, TelegramAuthError> {
    if payload.id <= 0 {
        return Err(TelegramAuthError::InvalidId);
    }
    if payload.auth_date > now.saturating_add(TELEGRAM_MAX_FUTURE_SKEW_SECS) {
        return Err(TelegramAuthError::FutureAuthDate);
    }
    if now.saturating_sub(payload.auth_date) > TELEGRAM_MAX_AGE_SECS {
        return Err(TelegramAuthError::ExpiredAuthDate);
    }

    let hash_lower = payload.hash.trim().to_ascii_lowercase();
    if hash_lower.len() != 64 || !hash_lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TelegramAuthError::InvalidHashFormat);
    }
    let provided = hex::decode(&hash_lower).map_err(|_| TelegramAuthError::InvalidHashFormat)?;
    if provided.len() != 32 {
        return Err(TelegramAuthError::InvalidHashFormat);
    }

    let secret_key = Sha256::digest(bot_token.as_bytes());
    let check_string = build_telegram_check_string(payload);
    let mut mac = HmacSha256::new_from_slice(&secret_key).expect("HMAC key");
    mac.update(check_string.as_bytes());
    let expected = mac.finalize().into_bytes();

    if !bool::from(expected.as_slice().ct_eq(provided.as_slice())) {
        return Err(TelegramAuthError::SignatureMismatch);
    }

    let assertion_digest = hex::encode(Sha256::digest(hash_lower.as_bytes()));
    let label = payload
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|u| format!("@{u}"))
        .or_else(|| {
            payload
                .first_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("Telegram #{}", payload.id));

    Ok(VerifiedTelegramAssertion {
        telegram_id: payload.id,
        label,
        assertion_digest,
        replay_expires_at: payload
            .auth_date
            .saturating_add(TELEGRAM_REPLAY_TTL_PADDING_SECS),
    })
}

#[derive(Serialize)]
struct TelegramVerifyResp {
    user_id: String,
    action: &'static str,
}

#[worker::send]
pub async fn verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(payload): Json<TelegramAuthPayload>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }

    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(env) => env.policy,
        Err(e) => {
            worker::console_error!("telegram: policy load failed: {e:?}");
            return auth::internal_error();
        }
    };

    if let Err(msg) =
        identity::check_login_provider_eligibility(&policy, AuthProviderId::Telegram, None)
    {
        return auth::api_error(StatusCode::FORBIDDEN, msg);
    }

    let bot_token = match secrets::load_provider_secret(
        &st.env,
        &st.deployment_id,
        policy.revision,
        AuthProviderId::Telegram.as_str(),
        "bot_token",
        &["TELEGRAM_BOT_TOKEN"],
    )
    .await
    {
        Ok(Some(tok)) => tok,
        Ok(None) => {
            return auth::api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Telegram login is not configured",
            );
        }
        Err(e) => {
            worker::console_error!("telegram secret decrypt failed: {e}");
            return auth::api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Telegram credentials unavailable",
            );
        }
    };

    let now = session::now_secs();
    let verified = match verify_telegram_payload(&payload, bot_token.expose(), now) {
        Ok(v) => v,
        Err(TelegramAuthError::ExpiredAuthDate) => {
            return auth::api_error(StatusCode::UNAUTHORIZED, "Telegram login expired");
        }
        Err(TelegramAuthError::FutureAuthDate) => {
            return auth::api_error(StatusCode::UNAUTHORIZED, "invalid Telegram timestamp");
        }
        Err(_) => {
            return auth::api_error(StatusCode::UNAUTHORIZED, "invalid Telegram signature");
        }
    };

    // Atomic replay protection in `AuthChallengeDO`!
    match challenge_do::consume_telegram_digest(
        &st.env,
        &verified.assertion_digest,
        verified.replay_expires_at,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                Json(ApiError {
                    error: "Telegram login payload was already used".into(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            worker::console_error!("telegram replay guard failed: {e:?}");
            return auth::internal_error();
        }
    }

    let ident = identity::VerifiedExternalIdentity {
        provider_id: AuthProviderId::Telegram,
        issuer: "https://telegram.org".to_string(),
        subject: verified.telegram_id.to_string(),
        label: Some(verified.label),
        verified_email: None,
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    };

    if payload.action.as_deref() == Some("link") {
        let active = match identity::require_active_session(&st, &cookies).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        if let Err(r) = identity::require_recent_auth(&st, &active).await {
            return r;
        }
        if let Err(r) = identity::link_identity_atomic(&st, &active.user_id, &ident, "login").await
        {
            return r;
        }
        if let Err(r) =
            identity::rotate_session_on_identity_link(&st, &cookies, &active, &ident).await
        {
            return r;
        }
        return Json(TelegramVerifyResp {
            user_id: active.user_id,
            action: "link",
        })
        .into_response();
    }

    let account = match identity::resolve_or_create_login_account(&st, &policy, &ident).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = identity::issue_v2_session(
        &st,
        &cookies,
        &account,
        AuthProviderId::Telegram.as_str(),
        &ident.identity_key(),
        AssuranceLevel::None,
        false,
    )
    .await
    {
        return r;
    }

    Json(TelegramVerifyResp {
        user_id: account.user_id,
        action: "login",
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct TelegramStartReq {
    #[serde(default)]
    pub next: Option<String>,
}

#[derive(Debug, Serialize)]
struct TelegramStartResp {
    auth_url: String,
}

/// Begin a browser-bound Telegram Login Widget transaction (`POST /user/auth/telegram/start`).
/// Mints a single-use `state` + `__Host-auth_tx` cookie stored in `AuthChallengeDO` so
/// third-party Telegram callback links cannot silently switch another visitor's session (F13).
#[worker::send]
pub async fn start(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<TelegramStartReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }

    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(env) => env.policy,
        Err(e) => {
            worker::console_error!("telegram start: policy load failed: {e:?}");
            return auth::internal_error();
        }
    };
    if let Err(msg) =
        identity::check_login_provider_eligibility(&policy, AuthProviderId::Telegram, None)
    {
        return auth::api_error(StatusCode::FORBIDDEN, msg);
    }

    let ip_bucket = format!("telegram:{}", ip_rate_key(&headers, &st.session_v2_secret));
    match challenge_do::hit_rate_limit(&st.env, &ip_bucket, 600, 40).await {
        Ok(rl) if !rl.allowed => {
            return auth::api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many sign-in attempts; retry later",
            );
        }
        Ok(_) => {}
        Err(e) => {
            worker::console_error!("telegram start rate limit DO failed: {e:?}");
            return auth::internal_error();
        }
    }

    let tx_id = match random_b64url(16) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let tx_cookie_secret = match random_b64url(24) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let state = match random_b64url(24) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let next_url = sanitize_next_url(req.next.as_deref());
    let redirect_uri = format!("{}/user/auth/telegram/callback", st.public_origin());
    let now = session::now_secs();

    match challenge_do::start_oauth_tx(
        &st.env,
        &OAuthTxStartReq {
            tx_id: tx_id.clone(),
            tx_cookie_hash: sha256_hex(&tx_cookie_secret),
            provider_id: AuthProviderId::Telegram.as_str().to_string(),
            action: "login".to_string(),
            initiator_user_id: None,
            redirect_uri,
            state: state.clone(),
            pkce_verifier: String::new(),
            nonce: String::new(),
            next_url,
            expires_at: now + TELEGRAM_TX_TTL_SECS,
            ip_bucket: None,
        },
    )
    .await
    {
        Ok((200, _)) => {}
        Ok((429, msg)) => return auth::api_error(StatusCode::TOO_MANY_REQUESTS, msg),
        Ok((code, msg)) => {
            worker::console_error!("telegram start DO status {code}: {msg}");
            return auth::internal_error();
        }
        Err(e) => {
            worker::console_error!("telegram start DO failed: {e:?}");
            return auth::internal_error();
        }
    }

    cookies.add(session::make_auth_tx_cookie(
        format!("{tx_id}.{tx_cookie_secret}"),
        TELEGRAM_TX_TTL_SECS as i64,
    ));

    let auth_url = format!(
        "/user/auth/telegram/callback?state={}",
        urlencoding::encode(&state)
    );
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(TelegramStartResp { auth_url }),
    )
        .into_response()
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelegramCallbackQuery {
    pub id: i64,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub photo_url: Option<String>,
    pub auth_date: u64,
    pub hash: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub next: Option<String>,
}

fn redirect_no_store(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, location.to_string()),
            (header::CACHE_CONTROL, "private, no-store".to_string()),
        ],
    )
        .into_response()
}

fn telegram_error_redirect(msg: &str) -> Response {
    let encoded = urlencoding::encode(msg);
    redirect_no_store(&format!("/user/login?error={encoded}"))
}

/// CSP-safe Telegram Login Widget redirect callback (`data-auth-url="/user/auth/telegram/callback?state=..."`).
///
/// Requires a matching browser-bound `__Host-auth_tx` cookie + single-use `state` minted
/// by `POST /user/auth/telegram/start` so unsolicited callback links cannot silently switch
/// a visitor into another user's account (F13).
#[worker::send]
pub async fn callback(
    State(st): State<AppState>,
    cookies: Cookies,
    Query(q): Query<TelegramCallbackQuery>,
) -> Response {
    // Always clear `__Host-auth_tx` immediately regardless of outcome.
    let raw_tx_cookie = cookies
        .get(session::AUTH_TX_COOKIE)
        .map(|c| c.value().to_string());
    cookies.add(session::clear_auth_tx_cookie());

    let (Some(state), Some(tx_cookie)) = (
        q.state.as_deref().map(str::trim).filter(|s| !s.is_empty()),
        raw_tx_cookie.as_deref(),
    ) else {
        return telegram_error_redirect(
            "Missing or expired Telegram sign-in session. Please try again.",
        );
    };
    let Some((tx_id, tx_cookie_secret)) = tx_cookie.split_once('.') else {
        return telegram_error_redirect("Invalid Telegram sign-in session cookie.");
    };

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
        Ok(Some(tx)) if tx.provider_id == AuthProviderId::Telegram.as_str() => tx,
        Ok(_) => {
            return telegram_error_redirect(
                "Telegram sign-in session expired or did not originate from this browser.",
            );
        }
        Err(e) => {
            worker::console_error!("telegram callback tx consume DO failed: {e:?}");
            return telegram_error_redirect("Telegram verification failed.");
        }
    };

    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(env) => env.policy,
        Err(e) => {
            worker::console_error!("telegram callback: policy load failed: {e:?}");
            return telegram_error_redirect("Service temporarily unavailable");
        }
    };

    if let Err(msg) =
        identity::check_login_provider_eligibility(&policy, AuthProviderId::Telegram, None)
    {
        return telegram_error_redirect(msg);
    }

    let bot_token = match secrets::load_provider_secret(
        &st.env,
        &st.deployment_id,
        policy.revision,
        AuthProviderId::Telegram.as_str(),
        "bot_token",
        &["TELEGRAM_BOT_TOKEN"],
    )
    .await
    {
        Ok(Some(tok)) => tok,
        Ok(None) => return telegram_error_redirect("Telegram login is not configured"),
        Err(e) => {
            worker::console_error!("telegram callback secret decrypt failed: {e}");
            return telegram_error_redirect("Telegram credentials unavailable");
        }
    };

    let payload = TelegramAuthPayload {
        id: q.id,
        first_name: q.first_name,
        last_name: q.last_name,
        username: q.username,
        photo_url: q.photo_url,
        auth_date: q.auth_date,
        hash: q.hash,
        action: None,
    };

    let now = session::now_secs();
    let verified = match verify_telegram_payload(&payload, bot_token.expose(), now) {
        Ok(v) => v,
        Err(TelegramAuthError::ExpiredAuthDate) => {
            return telegram_error_redirect("Telegram login expired. Please try again.");
        }
        Err(TelegramAuthError::FutureAuthDate) => {
            return telegram_error_redirect("Invalid Telegram timestamp.");
        }
        Err(_) => return telegram_error_redirect("Invalid Telegram signature."),
    };

    match challenge_do::consume_telegram_digest(
        &st.env,
        &verified.assertion_digest,
        verified.replay_expires_at,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return telegram_error_redirect("Telegram login payload was already used."),
        Err(e) => {
            worker::console_error!("telegram callback replay guard failed: {e:?}");
            return telegram_error_redirect("Telegram verification failed.");
        }
    }

    let ident = identity::VerifiedExternalIdentity {
        provider_id: AuthProviderId::Telegram,
        issuer: "https://telegram.org".to_string(),
        subject: verified.telegram_id.to_string(),
        label: Some(verified.label),
        verified_email: None,
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    };

    let account = match identity::resolve_or_create_login_account(&st, &policy, &ident).await {
        Ok(a) => a,
        Err(_) => return telegram_error_redirect("Could not sign in with Telegram."),
    };
    if identity::issue_v2_session(
        &st,
        &cookies,
        &account,
        AuthProviderId::Telegram.as_str(),
        &ident.identity_key(),
        AssuranceLevel::None,
        false,
    )
    .await
    .is_err()
    {
        return telegram_error_redirect("Could not create session.");
    }

    let dest = sanitize_next_url(
        Some(tx.next_url.as_str())
            .filter(|s| !s.is_empty())
            .or(q.next.as_deref()),
    );
    redirect_no_store(&dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOT_TOKEN: &str = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11";
    const NOW: u64 = 1_795_392_000;

    fn sign_payload(mut p: TelegramAuthPayload, token: &str) -> TelegramAuthPayload {
        let key = Sha256::digest(token.as_bytes());
        let check = build_telegram_check_string(&p);
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(check.as_bytes());
        p.hash = hex::encode(mac.finalize().into_bytes());
        p
    }

    #[test]
    fn telegram_hmac_and_timestamp_window_checks() {
        let base = TelegramAuthPayload {
            id: 424242,
            first_name: Some("Alice".into()),
            last_name: None,
            username: Some("alice_tg".into()),
            photo_url: None,
            auth_date: NOW - 120,
            hash: String::new(),
            action: None,
        };
        let valid = sign_payload(base.clone(), BOT_TOKEN);
        let ok = verify_telegram_payload(&valid, BOT_TOKEN, NOW).expect("valid signature");
        assert_eq!(ok.telegram_id, 424242);
        assert_eq!(ok.label, "@alice_tg");
        assert_eq!(ok.replay_expires_at, base.auth_date + 360);

        // Wrong bot token rejected
        assert_eq!(
            verify_telegram_payload(&valid, "wrong:token", NOW),
            Err(TelegramAuthError::SignatureMismatch)
        );

        // Tampered username rejected
        let mut tampered = valid.clone();
        tampered.username = Some("mallory".into());
        assert_eq!(
            verify_telegram_payload(&tampered, BOT_TOKEN, NOW),
            Err(TelegramAuthError::SignatureMismatch)
        );

        // Older than 300s rejected
        let old = sign_payload(
            TelegramAuthPayload {
                auth_date: NOW - 301,
                ..base.clone()
            },
            BOT_TOKEN,
        );
        assert_eq!(
            verify_telegram_payload(&old, BOT_TOKEN, NOW),
            Err(TelegramAuthError::ExpiredAuthDate)
        );

        // Boundary 300s accepted
        let at_300 = sign_payload(
            TelegramAuthPayload {
                auth_date: NOW - 300,
                ..base.clone()
            },
            BOT_TOKEN,
        );
        assert!(verify_telegram_payload(&at_300, BOT_TOKEN, NOW).is_ok());

        // > 60s in the future rejected
        let future = sign_payload(
            TelegramAuthPayload {
                auth_date: NOW + 61,
                ..base.clone()
            },
            BOT_TOKEN,
        );
        assert_eq!(
            verify_telegram_payload(&future, BOT_TOKEN, NOW),
            Err(TelegramAuthError::FutureAuthDate)
        );

        // Boundary +60s accepted
        let at_60 = sign_payload(
            TelegramAuthPayload {
                auth_date: NOW + 60,
                ..base
            },
            BOT_TOKEN,
        );
        assert!(verify_telegram_payload(&at_60, BOT_TOKEN, NOW).is_ok());
    }
}
