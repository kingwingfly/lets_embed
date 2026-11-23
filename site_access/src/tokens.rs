//! Versioned, domain-separated token codecs (`GatewayAssertion v3`,
//! `MediaCapability v3`, `AdminAssertionClaims v2`, `GuestSessionToken`,
//! `SessionV2Claims`) and gateway header contracts.
//!
//! All codecs here are WASM-safe and host-safe, using HMAC-SHA256 with explicit
//! domain-separation prefixes so tokens minted for one purpose can NEVER
//! validate as another even under key reuse.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ChargeKind, ChargeReq,
    legal::hex_lower,
    policy::{
        PolicyAccessResult, PolicyRef, PublicSitePolicy, SITE_POLICY_SCHEMA_VERSION,
    },
};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Shared Cookie & Header Constants
// ---------------------------------------------------------------------------

pub const SESSION_COOKIE: &str = "ue_session";
pub const GUEST_SESSION_COOKIE: &str = "le_guest_sid";
pub const LEGACY_TOKEN_COOKIE: &str = "gw_token";
pub const LEGACY_APP_COOKIE: &str = "gw_app";
pub const AUTH_TX_COOKIE: &str = "__Host-auth_tx";

pub const GATEWAY_ASSERTION_HEADER: &str = "x-gateway-assertion";
pub const GATEWAY_ASSERTION_AUDIENCE: &str = "lets-embed-web";
pub const GATEWAY_ASSERTION_TTL: u64 = 30;
pub const GATEWAY_ASSERTION_DEFAULT_MAX_SKEW: u64 = 10;

pub const ADMIN_ASSERTION_HEADER: &str = "x-gallery-admin-assertion";
pub const ADMIN_ASSERTION_AUDIENCE: &str = "lets-embed-admin-dashboard-worker";
pub const ADMIN_ASSERTION_TTL: u64 = 30;

pub const MEDIA_CAP_AUDIENCE: &str = "lets-embed-media";

pub const ADMIN_CSRF_HEADER: &str = "x-admin-csrf";
pub const USER_CSRF_HEADER: &str = "x-csrf-token";
pub const POLICY_REVISION_HEADER: &str = "x-policy-revision";
pub const POLICY_MIN_REVISION_HEADER: &str = "x-policy-min-revision";
pub const GALLERY_SWITCHERS_HEADER: &str = "x-gallery-switchers";

/// Privileged request headers that `gateway_worker` MUST strip from incoming
/// client requests on every forwarding branch before attaching any freshly
/// authenticated headers of its own.
pub const PRIVILEGED_REQUEST_HEADERS: &[&str] = &[
    GATEWAY_ASSERTION_HEADER,
    ADMIN_ASSERTION_HEADER,
    POLICY_REVISION_HEADER,
    POLICY_MIN_REVISION_HEADER,
    GALLERY_SWITCHERS_HEADER,
    crate::ADMIN_HEADER,
    "x-gallery-admin",
    "x-forwarded-user",
    "cf-access-jwt-assertion",
    "cf-access-authenticated-user-email",
    "cf-access-client-id",
    "cf-access-client-secret",
];

/// Header name prefixes (lowercase) that are always stripped from untrusted
/// client requests before forwarding to origins.
pub const PRIVILEGED_REQUEST_HEADER_PREFIXES: &[&str] = &["cf-access-", "x-gallery-admin"];

/// Returns `true` if `name` is a privileged header that must be stripped from
/// client requests before forwarding upstream.
pub fn is_privileged_request_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PRIVILEGED_REQUEST_HEADERS.contains(&lower.as_str())
        || PRIVILEGED_REQUEST_HEADER_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

/// Session and auth cookie names stripped when forwarding requests to
/// `lets-embed-web` or media origins.
pub const STRIPPED_ORIGIN_COOKIES: &[&str] = &[
    SESSION_COOKIE,
    GUEST_SESSION_COOKIE,
    crate::ADMIN_VIEW_COOKIE,
    LEGACY_TOKEN_COOKIE,
    LEGACY_APP_COOKIE,
    AUTH_TX_COOKIE,
    "CF_Authorization",
];

// ---------------------------------------------------------------------------
// Digest & Token Errors
// ---------------------------------------------------------------------------

/// Computes the canonical 64-char lowercase hex SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_lower(&digest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    MalformedFormat,
    UnsupportedVersion(u8),
    InvalidEncoding,
    InvalidSignature,
    InvalidPayload,
    InvalidClaims(&'static str),
    Expired,
    AudienceMismatch,
    TargetMismatch,
    RequestBindingMismatch(&'static str),
    PolicyRevisionStale { token_rev: u64, min_enforce_rev: u64 },
    PolicyRevisionAhead { token_rev: u64, active_rev: u64 },
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedFormat => write!(f, "malformed token format"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported token version: {v}"),
            Self::InvalidEncoding => write!(f, "invalid base64url encoding"),
            Self::InvalidSignature => write!(f, "invalid token signature"),
            Self::InvalidPayload => write!(f, "invalid token JSON payload"),
            Self::InvalidClaims(msg) => write!(f, "invalid token claims: {msg}"),
            Self::Expired => write!(f, "token expired"),
            Self::AudienceMismatch => write!(f, "token audience mismatch"),
            Self::TargetMismatch => write!(f, "media capability target mismatch"),
            Self::RequestBindingMismatch(msg) => write!(f, "request binding mismatch: {msg}"),
            Self::PolicyRevisionStale {
                token_rev,
                min_enforce_rev,
            } => write!(
                f,
                "token policy revision {token_rev} is older than min_enforce_rev {min_enforce_rev}"
            ),
            Self::PolicyRevisionAhead {
                token_rev,
                active_rev,
            } => write!(
                f,
                "token policy revision {token_rev} exceeds active revision {active_rev}"
            ),
        }
    }
}

impl std::error::Error for TokenError {}

fn domain_mac(secret: &[u8], domain: &[u8], parts: &[&[u8]]) -> Result<HmacSha256, TokenError> {
    if secret.is_empty() {
        return Err(TokenError::InvalidClaims("HMAC secret must not be empty"));
    }
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts variable length keys");
    mac.update(domain);
    for part in parts {
        mac.update(part);
    }
    Ok(mac)
}

fn is_clean_identifier(s: &str, max_len: usize) -> bool {
    !s.is_empty()
        && s.len() <= max_len
        && s == s.trim()
        && !s.chars().any(char::is_control)
}

pub(crate) fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_policy_refs(refs: &[PolicyRef], err_msg: &'static str) -> Result<(), TokenError> {
    for pref in refs {
        pref.validate().map_err(|_| TokenError::InvalidClaims(err_msg))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Principal & Durable Object Key Validation
// ---------------------------------------------------------------------------

/// Lowercase `0x`-prefixed 20-byte Ethereum address.
pub fn is_eth_address(s: &str) -> bool {
    s.len() == 42
        && s.starts_with("0x")
        && s[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Base58-encoded 32-byte Solana Ed25519 public key.
pub fn is_sol_principal(s: &str) -> bool {
    (32..=44).contains(&s.len()) && matches!(bs58::decode(s).into_vec(), Ok(v) if v.len() == 32)
}

/// Valid legacy wallet principal (Ethereum SIWE or Solana SIWS).
pub fn is_valid_legacy_principal(s: &str) -> bool {
    is_eth_address(s) || is_sol_principal(s)
}

/// Valid `UserAccount` Durable Object key.
pub fn is_valid_do_key(s: &str) -> bool {
    if is_valid_legacy_principal(s) {
        return true;
    }
    let Some(rest) = s.strip_prefix("usr:") else {
        return false;
    };
    (8..=64).contains(&rest.len())
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// ---------------------------------------------------------------------------
// ActorBinding (Policy v3)
// ---------------------------------------------------------------------------

/// Live caller identity bound into `GatewayAssertion` v3 and `MediaCapability` v3.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActorBinding {
    User { sub: String, sid: String },
    LiveAdmin { email: String },
    /// Random unforgeable guest session ID backed by signed `le_guest_sid` cookie.
    GuestSession { gid: String },
    /// ONLY valid for unrestricted public assets (`matched_blocks` & `matched_blurs` empty).
    Anon,
}

impl ActorBinding {
    pub const fn is_anon(&self) -> bool {
        matches!(self, Self::Anon)
    }

    pub fn validate(&self) -> Result<(), TokenError> {
        match self {
            Self::User { sub, sid } => {
                if !is_clean_identifier(sub, 128) {
                    return Err(TokenError::InvalidClaims("actor.sub must be clean non-empty"));
                }
                if !is_clean_identifier(sid, 128) {
                    return Err(TokenError::InvalidClaims("actor.sid must be clean non-empty"));
                }
                Ok(())
            }
            Self::LiveAdmin { email } => {
                if !is_clean_identifier(email, 320) {
                    return Err(TokenError::InvalidClaims(
                        "actor.email must be clean non-empty",
                    ));
                }
                Ok(())
            }
            Self::GuestSession { gid } => {
                if gid.len() < 8 || !is_clean_identifier(gid, 128) {
                    return Err(TokenError::InvalidClaims(
                        "actor.gid must be a clean identifier of 8..=128 bytes",
                    ));
                }
                Ok(())
            }
            Self::Anon => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Signed Guest Session Cookie Token (`le_guest_sid`)
// ---------------------------------------------------------------------------

pub const GUEST_SESSION_VERSION: u8 = 1;
const GUEST_SESSION_PREFIX: &str = "gs1.";
const GUEST_SESSION_MAC_DOMAIN: &[u8] = b"guest-session/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestSessionToken {
    pub v: u8,
    pub gid: String,
    pub iat: u64,
    pub exp: u64,
}

impl GuestSessionToken {
    pub fn validate(&self) -> Result<(), TokenError> {
        if self.v != GUEST_SESSION_VERSION {
            return Err(TokenError::UnsupportedVersion(self.v));
        }
        if self.gid.len() < 8 || !is_clean_identifier(&self.gid, 128) {
            return Err(TokenError::InvalidClaims(
                "gid must be a clean identifier of 8..=128 bytes",
            ));
        }
        if self.exp == 0 || self.iat > self.exp {
            return Err(TokenError::InvalidClaims("invalid iat/exp window"));
        }
        Ok(())
    }
}

/// Signs an HMAC-SHA256 `le_guest_sid` cookie token (`gs1.<payload>.<sig>`).
pub fn sign_guest_session(claims: &GuestSessionToken, secret: &[u8]) -> Result<String, TokenError> {
    claims.validate()?;
    let json = serde_json::to_vec(claims).map_err(|_| TokenError::InvalidPayload)?;
    let payload = B64.encode(json);
    let sig = domain_mac(
        secret,
        GUEST_SESSION_MAC_DOMAIN,
        &[GUEST_SESSION_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .finalize()
    .into_bytes();
    Ok(format!("{GUEST_SESSION_PREFIX}{payload}.{}", B64.encode(sig)))
}

/// Verifies an HMAC-SHA256 `le_guest_sid` cookie token.
pub fn verify_guest_session(
    token: &str,
    secret: &[u8],
    now: u64,
) -> Result<GuestSessionToken, TokenError> {
    let rest = token
        .strip_prefix(GUEST_SESSION_PREFIX)
        .ok_or(TokenError::MalformedFormat)?;
    let (payload, sig_b64) = rest.split_once('.').ok_or(TokenError::MalformedFormat)?;
    if payload.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return Err(TokenError::MalformedFormat);
    }
    let sig = B64.decode(sig_b64).map_err(|_| TokenError::InvalidEncoding)?;
    domain_mac(
        secret,
        GUEST_SESSION_MAC_DOMAIN,
        &[GUEST_SESSION_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .verify_slice(&sig)
    .map_err(|_| TokenError::InvalidSignature)?;

    let raw = B64.decode(payload).map_err(|_| TokenError::InvalidEncoding)?;
    let claims: GuestSessionToken =
        serde_json::from_slice(&raw).map_err(|_| TokenError::InvalidPayload)?;
    claims.validate()?;
    if now > claims.exp {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// Revocable v2 Session Token & Legacy Cutover Codec
// ---------------------------------------------------------------------------

pub const SESSION_V2_VERSION: u8 = 2;
pub const SESSION_V2_PREFIX: &str = "v2.";
const SESSION_V2_MAC_DOMAIN: &[u8] = b"session/v2\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionV2Claims {
    pub v: u8,
    pub sub: String,
    pub do_key: String,
    pub sid: String,
    pub iat: u64,
    pub exp: u64,
}

impl SessionV2Claims {
    pub fn validate(&self) -> Result<(), TokenError> {
        if self.v != SESSION_V2_VERSION {
            return Err(TokenError::UnsupportedVersion(self.v));
        }
        if !is_clean_identifier(&self.sub, 128) {
            return Err(TokenError::InvalidClaims(
                "sub must be a clean non-empty identifier",
            ));
        }
        if !is_valid_do_key(&self.do_key) {
            return Err(TokenError::InvalidClaims("invalid do_key"));
        }
        if !is_clean_identifier(&self.sid, 128) {
            return Err(TokenError::InvalidClaims(
                "sid must be a clean non-empty identifier",
            ));
        }
        if self.exp == 0 || self.iat > self.exp {
            return Err(TokenError::InvalidClaims("invalid iat/exp window"));
        }
        Ok(())
    }
}

/// Signs a revocable `v2` session token with explicit `"v2."` prefix and
/// HMAC-SHA256 domain separation (`session/v2\0`).
pub fn sign_session_v2(claims: &SessionV2Claims, secret: &[u8]) -> Result<String, TokenError> {
    claims.validate()?;
    let json = serde_json::to_vec(claims).map_err(|_| TokenError::InvalidPayload)?;
    let payload = B64.encode(json);
    let sig = domain_mac(
        secret,
        SESSION_V2_MAC_DOMAIN,
        &[SESSION_V2_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .finalize()
    .into_bytes();
    Ok(format!("{SESSION_V2_PREFIX}{payload}.{}", B64.encode(sig)))
}

/// Verifies a revocable `v2` session token (signature, prefix, claims, expiry).
pub fn verify_session_v2(
    token: &str,
    secret: &[u8],
    now: u64,
) -> Result<SessionV2Claims, TokenError> {
    let rest = token
        .strip_prefix(SESSION_V2_PREFIX)
        .ok_or(TokenError::MalformedFormat)?;
    let (payload, sig_b64) = rest.split_once('.').ok_or(TokenError::MalformedFormat)?;
    if payload.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return Err(TokenError::MalformedFormat);
    }
    let sig = B64.decode(sig_b64).map_err(|_| TokenError::InvalidEncoding)?;
    domain_mac(
        secret,
        SESSION_V2_MAC_DOMAIN,
        &[SESSION_V2_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .verify_slice(&sig)
    .map_err(|_| TokenError::InvalidSignature)?;

    let raw = B64.decode(payload).map_err(|_| TokenError::InvalidEncoding)?;
    let claims: SessionV2Claims =
        serde_json::from_slice(&raw).map_err(|_| TokenError::InvalidPayload)?;
    claims.validate()?;
    if now > claims.exp {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}

/// Legacy wallet-only session claims (`{payload_b64}.{sig_b64}`, no prefix).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacySessionClaims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
}

/// Signs a legacy wallet session token matching the pre-v2 wire format.
pub fn sign_legacy_session(
    claims: &LegacySessionClaims,
    secret: &[u8],
) -> Result<String, TokenError> {
    if secret.is_empty() {
        return Err(TokenError::InvalidClaims("HMAC secret must not be empty"));
    }
    if !is_valid_legacy_principal(&claims.sub) {
        return Err(TokenError::InvalidClaims(
            "legacy sub must be eth or sol principal",
        ));
    }
    if claims.exp == 0 || claims.iat > claims.exp {
        return Err(TokenError::InvalidClaims("invalid iat/exp window"));
    }
    let payload = B64.encode(serde_json::to_vec(claims).map_err(|_| TokenError::InvalidPayload)?);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts variable length keys");
    mac.update(payload.as_bytes());
    let sig = B64.encode(mac.finalize().into_bytes());
    Ok(format!("{payload}.{sig}"))
}

/// Verifies a legacy wallet session token during cutover.
pub fn verify_legacy_session(
    token: &str,
    secret: &[u8],
    now: u64,
) -> Result<LegacySessionClaims, TokenError> {
    if secret.is_empty() {
        return Err(TokenError::InvalidClaims("HMAC secret must not be empty"));
    }
    if token.starts_with(SESSION_V2_PREFIX) {
        return Err(TokenError::MalformedFormat);
    }
    let (payload, sig_b64) = token.split_once('.').ok_or(TokenError::MalformedFormat)?;
    if payload.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return Err(TokenError::MalformedFormat);
    }
    let sig = B64.decode(sig_b64).map_err(|_| TokenError::InvalidEncoding)?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts variable length keys");
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| TokenError::InvalidSignature)?;

    let raw = B64.decode(payload).map_err(|_| TokenError::InvalidEncoding)?;
    let claims: LegacySessionClaims =
        serde_json::from_slice(&raw).map_err(|_| TokenError::InvalidPayload)?;
    if !is_valid_legacy_principal(&claims.sub) {
        return Err(TokenError::InvalidClaims(
            "legacy sub must be eth or sol principal",
        ));
    }
    if claims.exp == 0 || claims.iat > claims.exp {
        return Err(TokenError::InvalidClaims("invalid iat/exp window"));
    }
    if now > claims.exp {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}

/// Result of dual-format session verification during the `v2` cutover window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedSession {
    V2(SessionV2Claims),
    Legacy(LegacySessionClaims),
}

impl VerifiedSession {
    pub fn user_id(&self) -> &str {
        match self {
            Self::V2(c) => &c.sub,
            Self::Legacy(c) => &c.sub,
        }
    }

    pub fn do_key(&self) -> &str {
        match self {
            Self::V2(c) => &c.do_key,
            Self::Legacy(c) => &c.sub,
        }
    }

    pub fn sid(&self) -> Option<&str> {
        match self {
            Self::V2(c) => Some(&c.sid),
            Self::Legacy(_) => None,
        }
    }

    pub fn exp(&self) -> u64 {
        match self {
            Self::V2(c) => c.exp,
            Self::Legacy(c) => c.exp,
        }
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, Self::V2(_))
    }
}

/// Verifies either a revocable `v2` session token or, when `legacy_secret` is `Some`,
/// a legacy wallet session token.
pub fn verify_session_any(
    token: &str,
    v2_secret: &[u8],
    legacy_secret: Option<&[u8]>,
    now: u64,
) -> Result<VerifiedSession, TokenError> {
    if token.starts_with(SESSION_V2_PREFIX) {
        verify_session_v2(token, v2_secret, now).map(VerifiedSession::V2)
    } else if let Some(legacy_key) = legacy_secret {
        verify_legacy_session(token, legacy_key, now).map(VerifiedSession::Legacy)
    } else {
        Err(TokenError::MalformedFormat)
    }
}

// ---------------------------------------------------------------------------
// Signed X-Gateway-Assertion Header Codec (v = 3)
// ---------------------------------------------------------------------------

pub const GATEWAY_ASSERTION_VERSION: u8 = 3;
const GATEWAY_ASSERTION_PREFIX: &str = "ga3.";
const GATEWAY_ASSERTION_MAC_DOMAIN: &[u8] = b"gateway-assertion/v3\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayAssertion {
    pub v: u8,
    pub aud: String,
    pub actor: ActorBinding,
    pub rev: u64,
    pub min_enforce_rev: u64,
    pub digest: String,
    #[serde(default)]
    pub direct_grants: Vec<PolicyRef>,
    #[serde(default)]
    pub click_eligible: Vec<PolicyRef>,
    #[serde(default)]
    pub is_billing_waived: bool,
    pub exp: u64,
}

impl GatewayAssertion {
    pub fn validate(&self) -> Result<(), TokenError> {
        if self.v != GATEWAY_ASSERTION_VERSION {
            return Err(TokenError::UnsupportedVersion(self.v));
        }
        if !is_clean_identifier(&self.aud, 128) {
            return Err(TokenError::InvalidClaims(
                "aud must be a clean non-empty identifier",
            ));
        }
        self.actor.validate()?;
        if self.min_enforce_rev > self.rev {
            return Err(TokenError::InvalidClaims("min_enforce_rev exceeds rev"));
        }
        if !is_valid_sha256_hex(&self.digest) {
            return Err(TokenError::InvalidClaims(
                "digest must be 64-char lowercase hex SHA-256",
            ));
        }
        validate_policy_refs(&self.direct_grants, "invalid PolicyRef in direct_grants")?;
        validate_policy_refs(&self.click_eligible, "invalid PolicyRef in click_eligible")?;
        if self.actor.is_anon() && !self.direct_grants.is_empty() {
            return Err(TokenError::InvalidClaims(
                "anon actor cannot hold direct_grants",
            ));
        }
        if self.exp == 0 {
            return Err(TokenError::InvalidClaims("exp must be non-zero"));
        }
        Ok(())
    }
}

/// Signs a `GatewayAssertion` (`v = 3`) for transmission in `X-Gateway-Assertion`.
pub fn sign_gateway_assertion(
    assertion: &GatewayAssertion,
    secret: &[u8],
) -> Result<String, TokenError> {
    assertion.validate()?;
    let json = serde_json::to_vec(assertion).map_err(|_| TokenError::InvalidPayload)?;
    let payload = B64.encode(json);
    let sig = domain_mac(
        secret,
        GATEWAY_ASSERTION_MAC_DOMAIN,
        &[GATEWAY_ASSERTION_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .finalize()
    .into_bytes();
    Ok(format!(
        "{GATEWAY_ASSERTION_PREFIX}{payload}.{}",
        B64.encode(sig)
    ))
}

/// Verifies an `X-Gateway-Assertion` (`v = 3`) header value, strictly rejecting
/// any non-v3 tokens (`ga1.`, etc.), audience mismatches, and out-of-window expiry.
pub fn verify_gateway_assertion(
    header_value: &str,
    secret: &[u8],
    expected_aud: &str,
    now: u64,
    max_skew: u64,
) -> Result<GatewayAssertion, TokenError> {
    let rest = header_value
        .strip_prefix(GATEWAY_ASSERTION_PREFIX)
        .ok_or(TokenError::MalformedFormat)?;
    let (payload, sig_b64) = rest.split_once('.').ok_or(TokenError::MalformedFormat)?;
    if payload.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return Err(TokenError::MalformedFormat);
    }
    let sig = B64.decode(sig_b64).map_err(|_| TokenError::InvalidEncoding)?;
    domain_mac(
        secret,
        GATEWAY_ASSERTION_MAC_DOMAIN,
        &[GATEWAY_ASSERTION_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .verify_slice(&sig)
    .map_err(|_| TokenError::InvalidSignature)?;

    let raw = B64.decode(payload).map_err(|_| TokenError::InvalidEncoding)?;
    let assertion: GatewayAssertion =
        serde_json::from_slice(&raw).map_err(|_| TokenError::InvalidPayload)?;
    assertion.validate()?;
    if assertion.aud != expected_aud {
        return Err(TokenError::AudienceMismatch);
    }
    if now > assertion.exp.saturating_add(max_skew) {
        return Err(TokenError::Expired);
    }
    if assertion.exp > now.saturating_add(GATEWAY_ASSERTION_TTL).saturating_add(max_skew) {
        return Err(TokenError::InvalidClaims(
            "assertion exp exceeds maximum TTL",
        ));
    }
    Ok(assertion)
}

// ---------------------------------------------------------------------------
// Signed Admin Dashboard Assertion (`X-Gallery-Admin-Assertion`, v = 2)
// ---------------------------------------------------------------------------

pub const ADMIN_ASSERTION_VERSION: u8 = 2;
const ADMIN_ASSERTION_PREFIX: &str = "aa2.";
const ADMIN_ASSERTION_MAC_DOMAIN: &[u8] = b"admin-assertion/v2\0";

/// Request-bound Admin Assertion (`v = 2`) cryptographically binding the admin
/// identity to the exact HTTP method (`m`), canonical path+query (`p`), body
/// SHA-256 digest (`bh`), and single-use replay nonce (`jti`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminAssertionClaims {
    pub v: u8,
    pub aud: String,
    pub email: String,
    /// Uppercase HTTP method (e.g. `"GET"`, `"POST"`, `"PUT"`, `"DELETE"`).
    pub m: String,
    /// Canonical request target (`path` + optional `?query`, beginning with `'/'`).
    pub p: String,
    /// Lowercase 64-char hex SHA-256 digest of the exact request body bytes.
    pub bh: String,
    /// Unique nonce ID consumed in D1 `admin_assertion_nonces` for mutating requests.
    pub jti: String,
    pub exp: u64,
}

/// Alias preserving ergonomic `AdminAssertion` naming.
pub type AdminAssertion = AdminAssertionClaims;

impl AdminAssertionClaims {
    pub fn validate(&self) -> Result<(), TokenError> {
        if self.v != ADMIN_ASSERTION_VERSION {
            return Err(TokenError::UnsupportedVersion(self.v));
        }
        if !is_clean_identifier(&self.aud, 128) {
            return Err(TokenError::InvalidClaims(
                "aud must be a clean non-empty identifier",
            ));
        }
        if !is_clean_identifier(&self.email, 320) {
            return Err(TokenError::InvalidClaims(
                "email must be a clean non-empty identifier",
            ));
        }
        if self.m.is_empty()
            || self.m.len() > 16
            || !self.m.bytes().all(|b| b.is_ascii_uppercase())
        {
            return Err(TokenError::InvalidClaims(
                "method m must be uppercase ASCII HTTP method",
            ));
        }
        if self.p.is_empty()
            || self.p.len() > 2048
            || !self.p.starts_with('/')
            || self.p != self.p.trim()
            || self.p.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(TokenError::InvalidClaims(
                "target p must be a clean canonical request path starting with '/'",
            ));
        }
        if !is_valid_sha256_hex(&self.bh) {
            return Err(TokenError::InvalidClaims(
                "body digest bh must be 64-char lowercase hex SHA-256",
            ));
        }
        if self.jti.len() < 8 || !is_clean_identifier(&self.jti, 128) {
            return Err(TokenError::InvalidClaims(
                "jti must be a clean identifier of 8..=128 bytes",
            ));
        }
        if self.exp == 0 {
            return Err(TokenError::InvalidClaims("exp must be non-zero"));
        }
        Ok(())
    }
}

/// Signs an [`AdminAssertionClaims`] (`v = 2`) for transmission in `X-Gallery-Admin-Assertion`.
pub fn sign_admin_assertion(
    assertion: &AdminAssertionClaims,
    secret: &[u8],
) -> Result<String, TokenError> {
    assertion.validate()?;
    let json = serde_json::to_vec(assertion).map_err(|_| TokenError::InvalidPayload)?;
    let payload = B64.encode(json);
    let sig = domain_mac(
        secret,
        ADMIN_ASSERTION_MAC_DOMAIN,
        &[ADMIN_ASSERTION_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .finalize()
    .into_bytes();
    Ok(format!(
        "{ADMIN_ASSERTION_PREFIX}{payload}.{}",
        B64.encode(sig)
    ))
}

/// Verifies an `X-Gallery-Admin-Assertion` (`v = 2`) against HMAC signature,
/// audience, bounded expiry, exact HTTP method `m`, canonical target `p`, and
/// exact body SHA-256 digest `bh` computed from `body_bytes`.
#[allow(clippy::too_many_arguments)]
pub fn verify_admin_assertion(
    header_value: &str,
    secret: &[u8],
    expected_aud: &str,
    expected_method: &str,
    expected_target: &str,
    body_bytes: &[u8],
    now: u64,
    max_skew: u64,
) -> Result<AdminAssertionClaims, TokenError> {
    let expected_bh = sha256_hex(body_bytes);
    verify_admin_assertion_with_body_hash(
        header_value,
        secret,
        expected_aud,
        expected_method,
        expected_target,
        &expected_bh,
        now,
        max_skew,
    )
}

/// Same as [`verify_admin_assertion`] when the caller already computed `expected_body_sha256`.
#[allow(clippy::too_many_arguments)]
pub fn verify_admin_assertion_with_body_hash(
    header_value: &str,
    secret: &[u8],
    expected_aud: &str,
    expected_method: &str,
    expected_target: &str,
    expected_body_sha256: &str,
    now: u64,
    max_skew: u64,
) -> Result<AdminAssertionClaims, TokenError> {
    let rest = header_value
        .strip_prefix(ADMIN_ASSERTION_PREFIX)
        .ok_or(TokenError::MalformedFormat)?;
    let (payload, sig_b64) = rest.split_once('.').ok_or(TokenError::MalformedFormat)?;
    if payload.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return Err(TokenError::MalformedFormat);
    }
    let sig = B64.decode(sig_b64).map_err(|_| TokenError::InvalidEncoding)?;
    domain_mac(
        secret,
        ADMIN_ASSERTION_MAC_DOMAIN,
        &[ADMIN_ASSERTION_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .verify_slice(&sig)
    .map_err(|_| TokenError::InvalidSignature)?;

    let raw = B64.decode(payload).map_err(|_| TokenError::InvalidEncoding)?;
    let assertion: AdminAssertionClaims =
        serde_json::from_slice(&raw).map_err(|_| TokenError::InvalidPayload)?;
    assertion.validate()?;
    if assertion.aud != expected_aud {
        return Err(TokenError::AudienceMismatch);
    }
    if now > assertion.exp.saturating_add(max_skew) {
        return Err(TokenError::Expired);
    }
    if assertion.exp > now.saturating_add(ADMIN_ASSERTION_TTL).saturating_add(max_skew) {
        return Err(TokenError::InvalidClaims(
            "admin assertion exp exceeds maximum TTL",
        ));
    }
    if assertion.m != expected_method {
        return Err(TokenError::RequestBindingMismatch("HTTP method mismatch"));
    }
    if assertion.p != expected_target {
        return Err(TokenError::RequestBindingMismatch(
            "canonical request target mismatch",
        ));
    }
    if assertion.bh != expected_body_sha256 {
        return Err(TokenError::RequestBindingMismatch("body digest mismatch"));
    }
    Ok(assertion)
}

// ---------------------------------------------------------------------------
// Signed Media Capability (v = 3) & Canonical Billing Key
// ---------------------------------------------------------------------------

pub const MEDIA_CAP_VERSION: u8 = 3;
const MEDIA_CAP_PREFIX: &str = "mc3.";
const MEDIA_CAP_MAC_DOMAIN: &[u8] = b"media-cap/v3\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaCapKind {
    Image,
    Video,
    Preview,
}

impl MediaCapKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Video => "video",
            Self::Preview => "preview",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "image" => Some(Self::Image),
            "video" => Some(Self::Video),
            "preview" => Some(Self::Preview),
            _ => None,
        }
    }
}

impl fmt::Display for MediaCapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BillableMediaKind {
    Image,
    Video,
}

impl BillableMediaKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Video => "video",
        }
    }

    pub const fn charge_kind(self) -> ChargeKind {
        match self {
            Self::Image => ChargeKind::Image,
            Self::Video => ChargeKind::Video,
        }
    }
}

/// Canonical billing identifier for clear media reads (`("image"|"video", id)`),
/// strictly disjoint from preview transform budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MediaBillingKey {
    pub kind: BillableMediaKind,
    pub id: i64,
}

impl MediaBillingKey {
    pub const fn image(id: i64) -> Self {
        Self {
            kind: BillableMediaKind::Image,
            id,
        }
    }

    pub const fn video(id: i64) -> Self {
        Self {
            kind: BillableMediaKind::Video,
            id,
        }
    }

    pub const fn from_cap_kind(kind: MediaCapKind, id: i64) -> Option<Self> {
        match kind {
            MediaCapKind::Image => Some(Self::image(id)),
            MediaCapKind::Video => Some(Self::video(id)),
            MediaCapKind::Preview => None,
        }
    }

    pub const fn charge_kind(self) -> ChargeKind {
        self.kind.charge_kind()
    }

    pub fn canonical_key(self) -> String {
        format!("media:{}:{}", self.kind.as_str(), self.id)
    }

    pub fn to_charge_req(self) -> ChargeReq {
        ChargeReq {
            path: self.canonical_key(),
            kind: self.charge_kind(),
        }
    }

    pub fn preview_budget_key(id: i64) -> String {
        format!("preview:{id}")
    }
}

/// Policy v3 per-asset media capability (`v = 3`) bound to asset identity,
/// canonical immutable locator, `facts_rev`, `policy_rev`, `actor_binding`,
/// matched restrictions, and object-bound revealed blur refs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaCapability {
    pub v: u8,
    pub aud: String,
    pub kind: MediaCapKind,
    pub asset_id: i64,
    pub immutable_locator: String,
    pub facts_rev: u64,
    pub policy_rev: u64,
    pub actor_binding: ActorBinding,
    #[serde(default)]
    pub matched_blocks: Vec<PolicyRef>,
    #[serde(default)]
    pub matched_blurs: Vec<PolicyRef>,
    #[serde(default)]
    pub revealed_refs: Vec<PolicyRef>,
    pub exp: u64,
}

const MAX_MEDIA_PATH_LEN: usize = 1024;

fn is_safe_media_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MAX_MEDIA_PATH_LEN
        || path != path.trim()
        || path.starts_with('/')
        || path.ends_with('/')
    {
        return false;
    }
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '%' | ':' | '\\' | '?' | '#'))
    {
        return false;
    }
    !path
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
}

impl MediaCapability {
    pub fn validate(&self) -> Result<(), TokenError> {
        if self.v != MEDIA_CAP_VERSION {
            return Err(TokenError::UnsupportedVersion(self.v));
        }
        if !is_clean_identifier(&self.aud, 128) {
            return Err(TokenError::InvalidClaims(
                "aud must be a clean non-empty identifier",
            ));
        }
        if self.asset_id <= 0 {
            return Err(TokenError::InvalidClaims("asset_id must be positive"));
        }
        if !is_safe_media_path(&self.immutable_locator) {
            return Err(TokenError::InvalidClaims("unsafe immutable_locator"));
        }
        if self.facts_rev == 0 {
            return Err(TokenError::InvalidClaims("facts_rev must be >= 1"));
        }
        self.actor_binding.validate()?;
        validate_policy_refs(&self.matched_blocks, "invalid PolicyRef in matched_blocks")?;
        validate_policy_refs(&self.matched_blurs, "invalid PolicyRef in matched_blurs")?;
        validate_policy_refs(&self.revealed_refs, "invalid PolicyRef in revealed_refs")?;

        if self.actor_binding.is_anon()
            && (!self.matched_blocks.is_empty()
                || !self.matched_blurs.is_empty()
                || !self.revealed_refs.is_empty())
        {
            return Err(TokenError::InvalidClaims(
                "anon capability is only valid when matched_blocks, matched_blurs, and revealed_refs are empty",
            ));
        }
        if self.kind == MediaCapKind::Preview && !self.revealed_refs.is_empty() {
            return Err(TokenError::InvalidClaims(
                "preview capability cannot carry revealed_refs",
            ));
        }
        if self
            .revealed_refs
            .iter()
            .any(|r| self.matched_blocks.contains(r) || !self.matched_blurs.contains(r))
        {
            return Err(TokenError::InvalidClaims(
                "revealed_refs must be a subset of matched_blurs and disjoint from matched_blocks",
            ));
        }
        if self.exp == 0 {
            return Err(TokenError::InvalidClaims("exp must be non-zero"));
        }
        Ok(())
    }

    pub fn is_unrestricted_public(&self) -> bool {
        self.matched_blocks.is_empty()
            && self.matched_blurs.is_empty()
            && self.revealed_refs.is_empty()
    }

    /// Canonical clear-view billing key (`None` for blurred previews).
    pub const fn billing_key(&self) -> Option<MediaBillingKey> {
        MediaBillingKey::from_cap_kind(self.kind, self.asset_id)
    }
}

/// Signs a Policy v3 media capability (`mc3.<payload>.<sig>` with HMAC domain `media-cap/v3\0`).
pub fn sign_media_capability(
    cap: &MediaCapability,
    secret: &[u8],
) -> Result<String, TokenError> {
    cap.validate()?;
    let json = serde_json::to_vec(cap).map_err(|_| TokenError::InvalidPayload)?;
    let payload = B64.encode(json);
    let sig = domain_mac(
        secret,
        MEDIA_CAP_MAC_DOMAIN,
        &[MEDIA_CAP_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .finalize()
    .into_bytes();
    Ok(format!("{MEDIA_CAP_PREFIX}{payload}.{}", B64.encode(sig)))
}

/// Verifies a Policy v3 media capability token strictly:
/// - Rejects any `v != 3` token (including all legacy v1/v2 empty-switcher caps!).
/// - Verifies HMAC signature, `aud`, `kind`, `asset_id`, `exp`, canonical `immutable_locator`.
/// - Enforces `min_enforce_rev <= cap.policy_rev <= active_rev`.
#[allow(clippy::too_many_arguments)]
pub fn verify_media_capability(
    token: &str,
    secret: &[u8],
    expected_aud: &str,
    expected_kind: MediaCapKind,
    expected_asset_id: i64,
    now: u64,
    min_enforce_rev: u64,
    active_rev: u64,
) -> Result<MediaCapability, TokenError> {
    let rest = token
        .strip_prefix(MEDIA_CAP_PREFIX)
        .ok_or(TokenError::MalformedFormat)?;
    let (payload, sig_b64) = rest.split_once('.').ok_or(TokenError::MalformedFormat)?;
    if payload.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return Err(TokenError::MalformedFormat);
    }
    let sig = B64.decode(sig_b64).map_err(|_| TokenError::InvalidEncoding)?;
    domain_mac(
        secret,
        MEDIA_CAP_MAC_DOMAIN,
        &[MEDIA_CAP_PREFIX.as_bytes(), payload.as_bytes()],
    )?
    .verify_slice(&sig)
    .map_err(|_| TokenError::InvalidSignature)?;

    let raw = B64.decode(payload).map_err(|_| TokenError::InvalidEncoding)?;
    let cap: MediaCapability =
        serde_json::from_slice(&raw).map_err(|_| TokenError::InvalidPayload)?;
    cap.validate()?;

    if cap.aud != expected_aud {
        return Err(TokenError::AudienceMismatch);
    }
    if cap.kind != expected_kind || cap.asset_id != expected_asset_id {
        return Err(TokenError::TargetMismatch);
    }
    if now > cap.exp {
        return Err(TokenError::Expired);
    }
    if cap.policy_rev < min_enforce_rev {
        return Err(TokenError::PolicyRevisionStale {
            token_rev: cap.policy_rev,
            min_enforce_rev,
        });
    }
    if cap.policy_rev > active_rev {
        return Err(TokenError::PolicyRevisionAhead {
            token_rev: cap.policy_rev,
            active_rev,
        });
    }
    Ok(cap)
}

/// Authorizes a verified Policy v3 [`MediaCapability`] on media redemption
/// (`GET`, `HEAD`, `Range`) BEFORE billing, caching, or upstream fetch.
///
/// Implements the exact Codex Policy v3 decision table:
/// 1. `policy.schema_version == 3` and `cap.validate().is_ok()` (`v == 3`)
/// 2. `policy.min_enforce_rev <= cap.policy_rev <= policy.revision`
/// 3. When `policy.safety_enabled`: `current_facts_rev == Some(cap.facts_rev)`
///    (applies to previously public `Anon` capabilities as well — fail closed on `None` or mismatch!)
/// 4. Actor match:
///    - `Anon` cap is ONLY accepted when `matched_blocks.is_empty() && matched_blurs.is_empty() && revealed_refs.is_empty()`.
///    - Any non-`Anon` cap MUST exactly match `live_actor`.
/// 5. Entitlements: `granted = live_direct_grants ∪ (cap.revealed_refs ∩ live_click_eligible)`:
///    - `Preview`: `matched_blocks ⊆ live_direct_grants` AND `policy.fixed_blur_enabled == true`.
///    - `Image | Video`: `matched_blocks ⊆ live_direct_grants` AND `matched_blurs ⊆ granted`.
pub fn authorize_media_capability_v3(
    cap: &MediaCapability,
    live_actor: &ActorBinding,
    live_access: &PolicyAccessResult,
    policy: &PublicSitePolicy,
    current_facts_rev: Option<u64>,
) -> bool {
    if policy.schema_version != SITE_POLICY_SCHEMA_VERSION || cap.validate().is_err() {
        return false;
    }
    if cap.policy_rev < policy.min_enforce_rev || cap.policy_rev > policy.revision {
        return false;
    }

    // Actor binding check: Anon only valid for completely unrestricted assets;
    // any bound actor must match the caller's live actor exactly.
    if cap.actor_binding.is_anon() {
        if !cap.is_unrestricted_public() {
            return false;
        }
    } else if &cap.actor_binding != live_actor {
        return false;
    }

    if !policy.safety_enabled {
        // Preview route still requires fixed_blur_enabled even when safety is off.
        return cap.kind != MediaCapKind::Preview || policy.fixed_blur_enabled;
    }

    // Authoritative facts_rev check (applies even to Anon public capabilities!).
    if current_facts_rev != Some(cap.facts_rev) {
        return false;
    }

    // Defense-in-depth: Block policies can ONLY be satisfied by direct_grants.
    let blocks_satisfied = cap
        .matched_blocks
        .iter()
        .all(|r| live_access.direct_grants.contains(r));
    if !blocks_satisfied {
        return false;
    }

    match cap.kind {
        MediaCapKind::Preview => policy.fixed_blur_enabled,
        MediaCapKind::Image | MediaCapKind::Video => cap.matched_blurs.iter().all(|r| {
            live_access.direct_grants.contains(r)
                || (cap.revealed_refs.contains(r) && live_access.click_eligible.contains(r))
        }),
    }
}
