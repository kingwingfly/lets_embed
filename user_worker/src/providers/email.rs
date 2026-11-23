//! Email Magic Link / OTP authentication (fixes H7, H12, L2).
//!
//! - Uses keyed HMAC-SHA256 (`email-otp/v1\0`) stored in `AuthChallengeDO` (never plaintext OTP/token).
//! - Enforces max 5 verify attempts + per-email (5/hr) and per-IP (15/hr) rate limits.
//! - Returns uniform non-enumerating 200 responses on `/user/auth/email/start`.
//! - Uses pinned canonical origin (`PUBLIC_URL` / `SIWE_DOMAIN`) for magic links (L2).
//! - Auto-rejected under `AgeVerificationPolicy::StrictProviderVerified18`.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use site_access::{AssuranceLevel, AuthProviderId};
use tower_cookies::Cookies;
use worker::Method;

use crate::{
    AppState, auth,
    challenge_do::{self, EmailOtpIssueReq, EmailOtpVerifyReq},
    identity, policy_do,
    providers::{ip_rate_key, sanitize_next_url, ssrf::fetch_https_no_redirect},
    secrets, session,
};

type HmacSha256 = Hmac<Sha256>;

const EMAIL_OTP_TTL_SECS: u64 = 600;
const EMAIL_OTP_MAX_ATTEMPTS: u32 = 5;
const EMAIL_PER_ADDRESS_MAX_PER_HOUR: u32 = 5;
const EMAIL_PER_IP_MAX_PER_HOUR: u32 = 15;
const DEFAULT_MAIL_ENDPOINT: &str = "https://api.resend.com/emails";

#[derive(Debug, Deserialize)]
pub struct EmailStartReq {
    pub email: String,
    #[serde(default)]
    pub next: Option<String>,
    /// `"login"` (default) or `"link"`
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Serialize)]
struct EmailStartResp {
    sent: bool,
    message: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct EmailVerifyReq {
    pub email: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Serialize)]
struct EmailVerifyResp {
    user_id: String,
    action: String,
    next: String,
}

pub fn normalize_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_ascii_lowercase();
    if email.len() < 5 || email.len() > 254 || email.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let (local, domain) = email.split_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return None;
    }
    Some(email)
}

pub fn keyed_otp_mac(secret: &[u8], purpose: &[u8], email: &str, value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(b"email-otp/v1\0");
    mac.update(purpose);
    mac.update(email.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn email_hash_key(secret: &[u8], email: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(b"email-hash/v1\0");
    mac.update(email.as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..16])
}

fn generate_6_digit_otp() -> Result<String, Response> {
    let mut out = String::with_capacity(6);
    let mut buf = [0u8; 32];
    while out.len() < 6 {
        getrandom::fill(&mut buf).map_err(|_| auth::internal_error())?;
        for &b in &buf {
            if b < 250 {
                out.push((b'0' + (b % 10)) as char);
                if out.len() == 6 {
                    break;
                }
            }
        }
    }
    Ok(out)
}

fn generate_magic_token() -> Result<String, Response> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|_| auth::internal_error())?;
    Ok(B64.encode(buf))
}

fn uniform_sent_response() -> Response {
    Json(EmailStartResp {
        sent: true,
        message: "If email sign-in is available for this address, a verification code and sign-in link have been sent.",
    })
    .into_response()
}

#[worker::send]
pub async fn start(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<EmailStartReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }

    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(env) => env.policy,
        Err(e) => {
            worker::console_error!("email start: policy load failed: {e:?}");
            return auth::internal_error();
        }
    };

    if let Err(msg) =
        identity::check_login_provider_eligibility(&policy, AuthProviderId::EmailOtp, None)
    {
        return auth::api_error(StatusCode::FORBIDDEN, msg);
    }

    let Some(email) = normalize_email(&req.email) else {
        return auth::api_error(StatusCode::BAD_REQUEST, "enter a valid email address");
    };

    let action = match req.action.as_deref() {
        Some("link") => "link",
        _ => "login",
    };
    let initiator_user_id = if action == "link" {
        let active = match identity::require_active_session(&st, &cookies).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        if let Err(r) = identity::require_recent_auth(&st, &active).await {
            return r;
        }
        Some(active.user_id)
    } else {
        None
    };

    // Per-IP rate limit in `AuthChallengeDO`
    let ip_bucket = format!("email-ip:{}", ip_rate_key(&headers, &st.session_v2_secret));
    match challenge_do::hit_rate_limit(&st.env, &ip_bucket, 3600, EMAIL_PER_IP_MAX_PER_HOUR).await {
        Ok(rl) if !rl.allowed => {
            return auth::api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many email requests — please wait before trying again",
            );
        }
        Ok(_) => {}
        Err(e) => {
            worker::console_error!("email IP rate limit failed: {e:?}");
            return auth::internal_error();
        }
    }

    let api_key = match secrets::load_provider_secret(
        &st.env,
        &st.deployment_id,
        AuthProviderId::EmailOtp.as_str(),
        "api_key",
        &["EMAIL_API_KEY", "RESEND_API_KEY"],
    )
    .await
    {
        Ok(Some(k)) => k,
        Ok(None) => {
            return auth::api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Email sign-in mail provider is not configured",
            );
        }
        Err(e) => {
            worker::console_error!("email api_key decrypt failed: {e}");
            return auth::api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Email provider credentials unavailable",
            );
        }
    };

    let email_cfg = policy
        .enabled_providers
        .iter()
        .find(|p| p.id == AuthProviderId::EmailOtp);

    let mail_from = email_cfg
        .and_then(|c| c.public_client_id.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            st.env
                .var("EMAIL_FROM")
                .ok()
                .map(|v| v.to_string())
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| format!("noreply@{}", st.siwe_domain));

    let mail_endpoint = match email_cfg
        .and_then(|c| c.issuer.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(configured_url) => match crate::providers::ssrf::validate_oidc_url(configured_url) {
            Ok(u) => u.to_string(),
            Err(e) => {
                worker::console_error!("email mail API URL rejected by SSRF policy: {e}");
                return auth::api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Email mail API URL is invalid",
                );
            }
        },
        None => st
            .env
            .var("EMAIL_API_URL")
            .ok()
            .map(|v| v.to_string())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MAIL_ENDPOINT.to_string()),
    };

    let code = match generate_6_digit_otp() {
        Ok(c) => c,
        Err(r) => return r,
    };
    let magic_token = match generate_magic_token() {
        Ok(t) => t,
        Err(r) => return r,
    };

    let email_hash = email_hash_key(&st.session_v2_secret, &email);
    let code_mac = keyed_otp_mac(&st.session_v2_secret, b"code\0", &email, &code);
    let link_mac = keyed_otp_mac(&st.session_v2_secret, b"link\0", &email, &magic_token);
    let next_url = sanitize_next_url(req.next.as_deref());
    let now = session::now_secs();

    let status = match challenge_do::issue_email_otp(
        &st.env,
        &EmailOtpIssueReq {
            email_hash,
            code_mac,
            link_mac,
            action: action.to_string(),
            initiator_user_id,
            next_url,
            expires_at: now + EMAIL_OTP_TTL_SECS,
            max_attempts: EMAIL_OTP_MAX_ATTEMPTS,
            email_rate_max: EMAIL_PER_ADDRESS_MAX_PER_HOUR,
            email_rate_window_secs: 3600,
        },
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("email otp store failed: {e:?}");
            return auth::internal_error();
        }
    };

    if status == 429 {
        // Uniform non-enumerating response on per-address throttle.
        return uniform_sent_response();
    }

    let magic_url = format!(
        "{}/user/login?email={}&email_token={}",
        st.public_origin(),
        urlencoding::encode(&email),
        urlencoding::encode(&magic_token),
    );
    let mail_body = serde_json::json!({
        "from": mail_from,
        "to": [email],
        "subject": format!("Your sign-in code for {}", st.siwe_domain),
        "text": format!(
            "Your 6-digit verification code is: {code}\n\n\
             Or click this one-time sign-in link (expires in 10 minutes):\n{magic_url}\n\n\
             If you did not request this email, you can safely ignore it."
        ),
    });

    let auth_header = format!("Bearer {}", api_key.expose());
    if let Err(e) = fetch_https_no_redirect(
        &mail_endpoint,
        Method::Post,
        &[
            ("authorization", &auth_header),
            ("content-type", "application/json"),
            ("user-agent", "lets-embed-user-worker"),
        ],
        Some(mail_body.to_string()),
    )
    .await
    {
        // Log without revealing email or secret!
        worker::console_error!("email send failed (endpoint={mail_endpoint}): {e}");
    }

    uniform_sent_response()
}

#[worker::send]
pub async fn verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<EmailVerifyReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }

    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(env) => env.policy,
        Err(e) => {
            worker::console_error!("email verify: policy load failed: {e:?}");
            return auth::internal_error();
        }
    };

    if let Err(msg) =
        identity::check_login_provider_eligibility(&policy, AuthProviderId::EmailOtp, None)
    {
        return auth::api_error(StatusCode::FORBIDDEN, msg);
    }

    let Some(email) = normalize_email(&req.email) else {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid email address");
    };
    let code_mac = req
        .code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|c| keyed_otp_mac(&st.session_v2_secret, b"code\0", &email, c));
    let link_mac = req
        .token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|t| keyed_otp_mac(&st.session_v2_secret, b"link\0", &email, t));
    if code_mac.is_none() && link_mac.is_none() {
        return auth::api_error(StatusCode::BAD_REQUEST, "enter your 6-digit code or magic link");
    }

    let email_hash = email_hash_key(&st.session_v2_secret, &email);
    let verified = match challenge_do::verify_email_otp(
        &st.env,
        &EmailOtpVerifyReq {
            email_hash,
            code_mac,
            link_mac,
        },
    )
    .await
    {
        Ok((200, Some(v))) => v,
        Ok((429, _)) => {
            return auth::api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed attempts — request a new verification code",
            );
        }
        Ok(_) => {
            return auth::api_error(StatusCode::UNAUTHORIZED, "invalid or expired code");
        }
        Err(e) => {
            worker::console_error!("email otp verify DO failed: {e:?}");
            return auth::internal_error();
        }
    };

    let ident = identity::VerifiedExternalIdentity {
        provider_id: AuthProviderId::EmailOtp,
        issuer: "email".to_string(),
        subject: email.clone(),
        label: Some(email.clone()),
        verified_email: Some(email),
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    };

    if verified.action == "link" {
        let active = match identity::require_active_session(&st, &cookies).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        if verified.initiator_user_id.as_deref() != Some(active.user_id.as_str()) {
            return auth::api_error(StatusCode::FORBIDDEN, "account mismatch during identity link");
        }
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
        return Json(EmailVerifyResp {
            user_id: active.user_id,
            action: "link".to_string(),
            next: "/user/account".to_string(),
        })
        .into_response();
    }

    // ZERO email auto-linking: resolves ONLY exact `(email_otp, "email", email)`!
    let account = match identity::resolve_or_create_login_account(&st, &policy, &ident).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = identity::issue_v2_session(
        &st,
        &cookies,
        &account,
        AuthProviderId::EmailOtp.as_str(),
        &ident.identity_key(),
        AssuranceLevel::None,
        false,
    )
    .await
    {
        return r;
    }

    Json(EmailVerifyResp {
        user_id: account.user_id,
        action: "login".to_string(),
        next: sanitize_next_url(Some(&verified.next_url)),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalization_and_keyed_mac_domain_separation() {
        assert_eq!(
            normalize_email("  Alice@Example.COM "),
            Some("alice@example.com".to_string())
        );
        assert_eq!(normalize_email("not-an-email"), None);
        assert_eq!(normalize_email("a@localhost"), None);
        assert_eq!(normalize_email("a@b..com"), None);

        let k = b"test-secret";
        let m1 = keyed_otp_mac(k, b"code\0", "a@b.com", "123456");
        let m2 = keyed_otp_mac(k, b"link\0", "a@b.com", "123456");
        let m3 = keyed_otp_mac(k, b"code\0", "other@b.com", "123456");
        assert_ne!(m1, m2);
        assert_ne!(m1, m3);
    }
}
