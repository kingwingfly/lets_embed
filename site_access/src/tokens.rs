//! Versioned, domain-separated token codecs and gateway header contracts.
//!
//! All codecs here are WASM-safe and host-safe, using HMAC-SHA256 with explicit
//! domain-separation prefixes so tokens minted for one purpose (legacy wallet
//! JWT, `v2` revocable session, `X-Gateway-Assertion`, `MediaCapability`) can
//! never validate as another even under key reuse.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{ChargeKind, ChargeReq};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Shared Cookie & Header Constants
// ---------------------------------------------------------------------------

pub const SESSION_COOKIE: &str = "ue_session";
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
    crate::ADMIN_VIEW_COOKIE,
    LEGACY_TOKEN_COOKIE,
    LEGACY_APP_COOKIE,
    AUTH_TX_COOKIE,
    "CF_Authorization",
];

// ---------------------------------------------------------------------------
// Token Errors
// ---------------------------------------------------------------------------

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
    PolicyRevisionStale { token_rev: u32, min_enforce_rev: u32 },
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
            Self::PolicyRevisionStale {
                token_rev,
                min_enforce_rev,
            } => write!(
                f,
                "token policy revision {token_rev} is older than min_enforce_rev {min_enforce_rev}"
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
///
/// Format-disjoint from [`is_eth_address`] because base58 excludes `'0'`.
pub fn is_sol_principal(s: &str) -> bool {
    (32..=44).contains(&s.len()) && matches!(bs58::decode(s).into_vec(), Ok(v) if v.len() == 32)
}

/// Valid legacy wallet principal (Ethereum SIWE or Solana SIWS).
/// Rejects legacy `gw_token` UUID subjects.
pub fn is_valid_legacy_principal(s: &str) -> bool {
    is_eth_address(s) || is_sol_principal(s)
}

/// Valid `UserAccount` Durable Object key:
/// - a legacy Ethereum or Solana wallet principal (preserving migrated balances/bans), OR
/// - `"usr:<id>"` for newly created multi-auth accounts (`<id>` 8..=64 ASCII `[a-zA-Z0-9_-]`).
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
///
/// Explicitly rejects `v2.` tokens and legacy `gw_token` UUID subjects.
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

/// Verifies either a revocable `v2` session token (using `v2_secret`) or, when
/// `legacy_secret` is `Some`, a legacy wallet session token.
///
/// Tokens beginning with `"v2."` NEVER fall back to legacy verification.
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
// Signed X-Gateway-Assertion Header Codec
// ---------------------------------------------------------------------------

pub const GATEWAY_ASSERTION_VERSION: u8 = 1;
const GATEWAY_ASSERTION_PREFIX: &str = "ga1.";
const GATEWAY_ASSERTION_MAC_DOMAIN: &[u8] = b"gateway-assertion/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayAssertion {
    pub v: u8,
    pub aud: String,
    pub rev: u32,
    pub min_enforce_rev: u32,
    pub policy_digest: String,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub switchers: Vec<String>,
    #[serde(default)]
    pub safe_mode: bool,
    #[serde(default)]
    pub is_admin_view: bool,
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
        if self.min_enforce_rev > self.rev {
            return Err(TokenError::InvalidClaims("min_enforce_rev exceeds rev"));
        }
        if !is_valid_sha256_hex(&self.policy_digest) {
            return Err(TokenError::InvalidClaims(
                "policy_digest must be 64-char lowercase hex SHA-256",
            ));
        }
        if let Some(sub) = &self.sub
            && !is_clean_identifier(sub, 128)
        {
            return Err(TokenError::InvalidClaims(
                "sub must be a clean non-empty identifier when present",
            ));
        }
        if let Some(sid) = &self.sid {
            if !is_clean_identifier(sid, 128) {
                return Err(TokenError::InvalidClaims(
                    "sid must be a clean non-empty identifier when present",
                ));
            }
            if self.sub.is_none() {
                return Err(TokenError::InvalidClaims("sid requires sub"));
            }
        }
        if self.safe_mode && !self.switchers.is_empty() {
            return Err(TokenError::InvalidClaims(
                "safe_mode assertion cannot enable switchers",
            ));
        }
        if self.switchers.iter().any(|sw| !is_clean_identifier(sw, 64)) {
            return Err(TokenError::InvalidClaims(
                "switchers must contain clean non-empty identifiers",
            ));
        }
        if self.exp == 0 {
            return Err(TokenError::InvalidClaims("exp must be non-zero"));
        }
        Ok(())
    }
}

/// Signs a `GatewayAssertion` for transmission in `X-Gateway-Assertion`.
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

/// Verifies an `X-Gateway-Assertion` header value with constant-time HMAC
/// verification, exact audience match, and bounded expiry checks allowing
/// `max_skew` seconds of clock skew (`now <= exp + max_skew` and
/// `exp <= now + GATEWAY_ASSERTION_TTL + max_skew`).
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
// Signed Admin Dashboard Assertion (`X-Gallery-Admin-Assertion`)
//
// Cloudflare Workers with `[assets]` route service bindings through an internal
// assets router hop that drops `ctx.props`. A short-lived HMAC-SHA256 assertion
// signed with a dedicated `ADMIN_ASSERTION_SECRET` shared strictly between
// `gateway_worker` and `admin_dashboard_worker` survives that hop while
// cryptographically proving Cloudflare Access authorization.
// ---------------------------------------------------------------------------

pub const ADMIN_ASSERTION_VERSION: u8 = 1;
const ADMIN_ASSERTION_PREFIX: &str = "aa1.";
const ADMIN_ASSERTION_MAC_DOMAIN: &[u8] = b"admin-assertion/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminAssertion {
    pub v: u8,
    pub aud: String,
    pub email: String,
    pub exp: u64,
}

impl AdminAssertion {
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
        if self.exp == 0 {
            return Err(TokenError::InvalidClaims("exp must be non-zero"));
        }
        Ok(())
    }
}

/// Signs an `AdminAssertion` for transmission in `X-Gallery-Admin-Assertion`.
pub fn sign_admin_assertion(
    assertion: &AdminAssertion,
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

/// Verifies an `X-Gallery-Admin-Assertion` header value with constant-time HMAC
/// verification, exact audience match, and bounded expiry checks.
pub fn verify_admin_assertion(
    header_value: &str,
    secret: &[u8],
    expected_aud: &str,
    now: u64,
    max_skew: u64,
) -> Result<AdminAssertion, TokenError> {
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
    let assertion: AdminAssertion =
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
    Ok(assertion)
}

// ---------------------------------------------------------------------------
// Signed Media Capability (cap) & Canonical Billing Key
// ---------------------------------------------------------------------------

pub const MEDIA_CAP_VERSION: u8 = 1;
pub const MEDIA_CAP_ANON_SUB: &str = "anon";
const MEDIA_CAP_MAC_DOMAIN: &[u8] = b"media-cap/v1\0";

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
/// strictly disjoint from preview transform budgets so reading a blurred preview
/// can never mark a clear media view as paid.
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

    /// Maps a `MediaCapKind` to a clear-view billing key, returning `None` for
    /// [`MediaCapKind::Preview`].
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

    /// Canonical idempotent DO billing key (`media:image:<id>` or `media:video:<id>`).
    pub fn canonical_key(self) -> String {
        format!("media:{}:{}", self.kind.as_str(), self.id)
    }

    /// Converts into a [`ChargeReq`] for `UserAccount` DO settlement.
    pub fn to_charge_req(self) -> ChargeReq {
        ChargeReq {
            path: self.canonical_key(),
            kind: self.charge_kind(),
        }
    }

    /// Separate rate-budget key for server-side blurred previews (`preview:<id>`),
    /// never colliding with [`Self::canonical_key`].
    pub fn preview_budget_key(id: i64) -> String {
        format!("preview:{id}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaCapability {
    pub v: u8,
    pub kind: MediaCapKind,
    pub id: i64,
    pub path: String,
    pub rev: u32,
    pub sub: String,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub req_switchers: Vec<String>,
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
        if self.id <= 0 {
            return Err(TokenError::InvalidClaims("media id must be positive"));
        }
        if !is_safe_media_path(&self.path) {
            return Err(TokenError::InvalidClaims("unsafe media path"));
        }
        if !is_clean_identifier(&self.sub, 128) {
            return Err(TokenError::InvalidClaims(
                "sub must be a clean non-empty identifier",
            ));
        }
        if self.sub == MEDIA_CAP_ANON_SUB {
            if self.sid.is_some() {
                return Err(TokenError::InvalidClaims("anon capability cannot carry sid"));
            }
            if !self.req_switchers.is_empty() {
                return Err(TokenError::InvalidClaims(
                    "anon capability cannot require switchers",
                ));
            }
        } else if let Some(sid) = &self.sid
            && !is_clean_identifier(sid, 128)
        {
            return Err(TokenError::InvalidClaims(
                "sid must be a clean non-empty identifier when present",
            ));
        }
        if self
            .req_switchers
            .iter()
            .any(|sw| !is_clean_identifier(sw, 64))
        {
            return Err(TokenError::InvalidClaims(
                "req_switchers must contain clean non-empty identifiers",
            ));
        }
        if self.exp == 0 {
            return Err(TokenError::InvalidClaims("exp must be non-zero"));
        }
        Ok(())
    }

    pub fn is_anonymous(&self) -> bool {
        self.sub == MEDIA_CAP_ANON_SUB && self.req_switchers.is_empty()
    }

    /// Returns `true` when `gateway_worker` must perform a live `UserAccount` DO
    /// session check before serving bytes.
    pub fn requires_live_session_check(&self) -> bool {
        self.sub != MEDIA_CAP_ANON_SUB || !self.req_switchers.is_empty()
    }

    /// Canonical clear-view billing key (`None` for blurred previews).
    pub const fn billing_key(&self) -> Option<MediaBillingKey> {
        MediaBillingKey::from_cap_kind(self.kind, self.id)
    }
}

/// Signs a per-object media capability token (`{payload_b64}.{sig_b64}` with
/// HMAC domain separation `media-cap/v1\0`).
pub fn sign_media_capability(
    cap: &MediaCapability,
    secret: &[u8],
) -> Result<String, TokenError> {
    cap.validate()?;
    let json = serde_json::to_vec(cap).map_err(|_| TokenError::InvalidPayload)?;
    let payload = B64.encode(json);
    let sig = domain_mac(secret, MEDIA_CAP_MAC_DOMAIN, &[payload.as_bytes()])?
        .finalize()
        .into_bytes();
    Ok(format!("{payload}.{}", B64.encode(sig)))
}

/// Verifies a media capability token against HMAC signature, route `(kind, id)`,
/// expiry (`now <= cap.exp`), and monotonic policy tightening (`cap.rev >= min_enforce_rev`).
pub fn verify_media_capability(
    token: &str,
    secret: &[u8],
    expected_kind: MediaCapKind,
    expected_id: i64,
    now: u64,
    min_enforce_rev: u32,
) -> Result<MediaCapability, TokenError> {
    let (payload, sig_b64) = token.split_once('.').ok_or(TokenError::MalformedFormat)?;
    if payload.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return Err(TokenError::MalformedFormat);
    }
    let sig = B64.decode(sig_b64).map_err(|_| TokenError::InvalidEncoding)?;
    domain_mac(secret, MEDIA_CAP_MAC_DOMAIN, &[payload.as_bytes()])?
        .verify_slice(&sig)
        .map_err(|_| TokenError::InvalidSignature)?;

    let raw = B64.decode(payload).map_err(|_| TokenError::InvalidEncoding)?;
    let cap: MediaCapability =
        serde_json::from_slice(&raw).map_err(|_| TokenError::InvalidPayload)?;
    cap.validate()?;

    if cap.kind != expected_kind || cap.id != expected_id {
        return Err(TokenError::TargetMismatch);
    }
    if now > cap.exp {
        return Err(TokenError::Expired);
    }
    if cap.rev < min_enforce_rev {
        return Err(TokenError::PolicyRevisionStale {
            token_rev: cap.rev,
            min_enforce_rev,
        });
    }
    Ok(cap)
}
