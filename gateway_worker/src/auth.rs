//! Session verification, HKDF `SITE_SECRET` resolution, staff allowlist filtering,
//! live `UserAccount` DO context handling, and Policy v3 `ActorBinding` resolution.

use serde::{Deserialize, Serialize};
use site_access::{
    ActorBinding, GUEST_SESSION_COOKIE, KeyDomain, SESSION_COOKIE, SessionContext, VerifiedSession,
    resolve_domain_secret, verify_guest_session,
};

/// Lifetime (seconds) of a signed `le_guest_sid` cookie minted for guest
/// click-to-reveal requests (must exceed the 15-minute reveal media capability TTL).
pub(crate) const GUEST_SESSION_TTL: u64 = 24 * 60 * 60;

/// Request payload sent to `USER_ACCOUNT` DO (`POST /session-context`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionContextReq {
    pub(crate) sid: Option<String>,
}

/// Verified, live-checked caller session backed by `USER_ACCOUNT` DO.
#[derive(Debug, Clone)]
pub(crate) struct LiveSession {
    pub(crate) session: VerifiedSession,
    pub(crate) ctx: SessionContext,
}

/// Raw environment inputs for resolving gateway secrets via HKDF `SITE_SECRET`
/// with optional per-purpose overrides.
///
/// NOTE: `ADMIN_ASSERTION_SECRET` is intentionally NOT part of this struct — it is
/// resolved lazily ONLY on the `/admin*` branch via [`resolve_admin_assertion_secret`]
/// so rolling out an override key never breaks gallery traffic.
#[derive(Debug, Clone, Default)]
pub(crate) struct GatewaySecretInputs<'a> {
    pub(crate) site_secret: Option<&'a str>,
    pub(crate) jwt_secret: Option<&'a str>,
    pub(crate) session_v2_secret: Option<&'a str>,
    pub(crate) session_secret: Option<&'a str>,
    pub(crate) media_cap_secret: Option<&'a str>,
    pub(crate) gateway_assertion_secret: Option<&'a str>,
    pub(crate) internal_api_secret: Option<&'a str>,
    pub(crate) guest_session_secret: Option<&'a str>,
}

/// Resolved non-admin domain secrets used across gallery, media, and user routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedGatewaySecrets {
    pub(crate) jwt_secret: Vec<u8>,
    pub(crate) session_v2_secret: Vec<u8>,
    pub(crate) media_cap_secret: Vec<u8>,
    pub(crate) gateway_assertion_secret: Vec<u8>,
    pub(crate) internal_api_secret: Vec<u8>,
    pub(crate) guest_session_secret: Vec<u8>,
}

fn non_empty_trimmed(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|s| !s.is_empty())
}

/// Resolves all non-admin gateway secrets (`Session`, `MediaCap`, `GatewayAssertion`,
/// `InternalApi`, `GuestSession`) from `SITE_SECRET` via RFC 5869 HKDF-SHA256 while
/// honoring any optional explicit per-purpose override env vars.
pub(crate) fn resolve_gateway_secrets(
    inputs: &GatewaySecretInputs<'_>,
) -> std::result::Result<ResolvedGatewaySecrets, &'static str> {
    let site_secret = non_empty_trimmed(inputs.site_secret);
    let explicit_jwt = non_empty_trimmed(inputs.jwt_secret);
    let explicit_session =
        non_empty_trimmed(inputs.session_v2_secret).or_else(|| non_empty_trimmed(inputs.session_secret));

    let jwt_secret =
        resolve_domain_secret(explicit_jwt, site_secret, KeyDomain::Session)?.into_bytes();

    // Explicit SESSION_V2_SECRET / SESSION_SECRET wins; else derive from SITE_SECRET;
    // else fall back to explicit JWT_SECRET for legacy cutover deployments without SITE_SECRET.
    let session_v2_secret = if explicit_session.is_some() || site_secret.is_some() {
        resolve_domain_secret(explicit_session, site_secret, KeyDomain::Session)?.into_bytes()
    } else {
        jwt_secret.clone()
    };

    let media_cap_secret = resolve_domain_secret(
        non_empty_trimmed(inputs.media_cap_secret),
        site_secret,
        KeyDomain::MediaCap,
    )?
    .into_bytes();

    let gateway_assertion_secret = resolve_domain_secret(
        non_empty_trimmed(inputs.gateway_assertion_secret),
        site_secret,
        KeyDomain::GatewayAssertion,
    )?
    .into_bytes();

    let internal_api_secret = resolve_domain_secret(
        non_empty_trimmed(inputs.internal_api_secret),
        site_secret,
        KeyDomain::InternalApi,
    )?
    .into_bytes();

    let guest_session_secret = resolve_domain_secret(
        non_empty_trimmed(inputs.guest_session_secret),
        site_secret,
        KeyDomain::GuestSession,
    )?
    .into_bytes();

    Ok(ResolvedGatewaySecrets {
        jwt_secret,
        session_v2_secret,
        media_cap_secret,
        gateway_assertion_secret,
        internal_api_secret,
        guest_session_secret,
    })
}

/// Lazily resolves `KeyDomain::AdminAssertion` for the `/admin*` branch only.
pub(crate) fn resolve_admin_assertion_secret(
    explicit_admin_assertion_secret: Option<&str>,
    site_secret: Option<&str>,
) -> std::result::Result<Vec<u8>, &'static str> {
    resolve_domain_secret(
        non_empty_trimmed(explicit_admin_assertion_secret),
        non_empty_trimmed(site_secret),
        KeyDomain::AdminAssertion,
    )
    .map(String::into_bytes)
}

/// Parses optional comma-separated `ADMIN_ALLOWED_EMAILS` into an optional
/// normalized lowercase allowlist.
///
/// - `None` (unset or blank) -> allowlist disabled (any email passing `CF_ACCESS_AUD` qualifies).
/// - `Some(list)` (non-blank env var) -> ONLY emails in `list` qualify; a malformed
///   non-blank value like `",,,"` produces `Some(vec![])`, failing closed and denying all.
pub(crate) fn parse_admin_allowed_emails(raw: Option<&str>) -> Option<Vec<String>> {
    let raw = non_empty_trimmed(raw)?;
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let normalized = entry.trim().to_ascii_lowercase();
        if !normalized.is_empty() && !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    Some(out)
}

/// Validates a live Cloudflare Access identity email against the optional
/// `ADMIN_ALLOWED_EMAILS` allowlist (case-insensitive, trimmed).
pub(crate) fn filter_allowed_admin_email<'a>(
    email: Option<&'a str>,
    allowed_emails: Option<&[String]>,
) -> Option<&'a str> {
    let trimmed = email?.trim();
    if trimmed.is_empty() || trimmed.len() > 320 || trimmed.chars().any(char::is_control) {
        return None;
    }
    if let Some(allowed) = allowed_emails
        && !allowed
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(trimmed))
    {
        return None;
    }
    Some(trimmed)
}

/// Resolves the Policy v3 [`ActorBinding`] for a live request:
/// 1. Authenticated gallery session -> `ActorBinding::User { sub, sid }`
/// 2. Live verified staff CF Access identity (when no gallery session and no revoked session)
///    -> `ActorBinding::LiveAdmin { email }`
/// 3. Valid signed `le_guest_sid` cookie (when no revoked session)
///    -> `ActorBinding::GuestSession { gid }`
/// 4. Otherwise -> `ActorBinding::Anon`
///
/// NOTE: `ADMIN_VIEW_COOKIE` (browse pass) NEVER grants `ActorBinding::LiveAdmin`.
pub(crate) fn resolve_actor_binding(
    auth: Option<&LiveSession>,
    session_revoked_or_invalid: bool,
    live_admin_email: Option<&str>,
    guest_session_cookie: Option<&str>,
    guest_session_secret: &[u8],
    now: u64,
) -> ActorBinding {
    if let Some(live) = auth {
        return ActorBinding::User {
            sub: live.session.user_id().to_string(),
            sid: live.session.sid().unwrap_or("legacy").to_string(),
        };
    }
    if session_revoked_or_invalid {
        return ActorBinding::Anon;
    }
    if let Some(email) = live_admin_email.map(str::trim).filter(|e| !e.is_empty()) {
        return ActorBinding::LiveAdmin {
            email: email.to_string(),
        };
    }
    if let Some(raw_guest) = guest_session_cookie
        && let Ok(claims) = verify_guest_session(raw_guest, guest_session_secret, now)
    {
        return ActorBinding::GuestSession { gid: claims.gid };
    }
    ActorBinding::Anon
}

/// `Set-Cookie` header value that immediately expires a revoked or invalid
/// `ue_session` cookie.
pub(crate) fn clear_session_cookie_header() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
}

/// `Set-Cookie` header value for a freshly minted signed `__Host-le_guest_sid` cookie.
/// Per RFC 6265bis, `__Host-` cookies MUST always set `Secure`, `Path=/`, and NO `Domain`.
pub(crate) fn guest_session_set_cookie_header(signed_token: &str) -> String {
    format!(
        "{GUEST_SESSION_COOKIE}={signed_token}; Path=/; Max-Age={GUEST_SESSION_TTL}; HttpOnly; SameSite=Lax; Secure"
    )
}
