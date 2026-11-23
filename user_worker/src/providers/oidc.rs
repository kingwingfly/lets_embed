//! OIDC Discovery, bounded JWKS caching, ID Token signature & claim verification,
//! and strict provider-verified 18+ age-assurance claim extraction (fixes H7, H11).
//!
//! Signature verification supports:
//! - `RS256`, `RS384`, `RS512`: pure-Rust PKCS#1 v1.5 verification (`num-bigint` + `sha2`)
//!   — runs identically in host unit tests and `wasm32` Cloudflare Workers.
//! - `EdDSA` (Ed25519): pure-Rust verification via `ed25519-dalek` (`verify_strict`).
//! - `ES256`, `ES384`: hardware-accelerated WebCrypto `crypto.subtle` on `wasm32`.
//!
//! Explicitly rejects `"none"`, `"HS256"`, `"HS384"`, `"HS512"` to prevent
//! algorithm-confusion attacks against asymmetric JWKS keys.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdVerifyingKey};
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use worker::{Env, Method};

use crate::challenge_do::{self, JwksCachePutReq};
use crate::providers::ssrf::{
    OidcDiscoveryDoc, SsrfError, ValidatedOidcEndpoints, discovery_url_for_issuer,
    fetch_https_no_redirect, validate_discovery_document,
};

const MAX_CLOCK_SKEW_SECS: u64 = 60;
const JWKS_CACHE_TTL_SECS: u64 = 900;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcError {
    Ssrf(SsrfError),
    MalformedJwt,
    UnsupportedAlgorithm(String),
    UnknownKeyId,
    InvalidKey,
    InvalidSignature,
    InvalidClaims(&'static str),
    Expired,
    NotYetValid,
    IssuerMismatch,
    AudienceMismatch,
    NonceMismatch,
    AgeNotVerified(&'static str),
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssrf(e) => write!(f, "OIDC SSRF/network error: {e}"),
            Self::MalformedJwt => write!(f, "malformed ID token"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported JWT algorithm: {alg}"),
            Self::UnknownKeyId => write!(f, "matching JWKS signing key not found"),
            Self::InvalidKey => write!(f, "invalid JWKS key material"),
            Self::InvalidSignature => write!(f, "invalid ID token signature"),
            Self::InvalidClaims(m) => write!(f, "invalid ID token claims: {m}"),
            Self::Expired => write!(f, "ID token expired"),
            Self::NotYetValid => write!(f, "ID token not yet valid"),
            Self::IssuerMismatch => write!(f, "ID token issuer mismatch"),
            Self::AudienceMismatch => write!(f, "ID token audience mismatch"),
            Self::NonceMismatch => write!(f, "ID token nonce mismatch"),
            Self::AgeNotVerified(m) => write!(f, "age verification claim failed: {m}"),
        }
    }
}

impl std::error::Error for OidcError {}

impl From<SsrfError> for OidcError {
    fn from(e: SsrfError) -> Self {
        Self::Ssrf(e)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(rename = "use", default)]
    pub key_use: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    // RSA fields
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    // EC / OKP fields
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    #[serde(default)]
    pub kid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedIdToken {
    pub sub: String,
    pub iss: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub raw_claims: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAgeResult {
    pub verified_18: bool,
    pub method: String,
}

// ---------------------------------------------------------------------------
// Discovery + Bounded JWKS Cache
// ---------------------------------------------------------------------------

pub struct OidcProviderMaterial {
    pub endpoints: ValidatedOidcEndpoints,
    pub jwks: JwkSet,
}

/// Load OIDC discovery + JWKS from bounded `AuthChallengeDO` cache, or fetch
/// fresh over SSRF-hardened `redirect: Manual` HTTPS and cache.
pub async fn load_oidc_material(
    env: &Env,
    configured_issuer: &str,
    force_refresh: bool,
) -> Result<OidcProviderMaterial, OidcError> {
    if !force_refresh
        && let Ok(Some(cached)) = challenge_do::get_cached_jwks(env, configured_issuer).await
        && let (Ok(doc), Ok(jwks)) = (
            serde_json::from_str::<OidcDiscoveryDoc>(&cached.discovery_json),
            serde_json::from_str::<JwkSet>(&cached.jwks_json),
        )
        && let Ok(endpoints) = validate_discovery_document(configured_issuer, &doc)
    {
        return Ok(OidcProviderMaterial { endpoints, jwks });
    }

    let disc_url = discovery_url_for_issuer(configured_issuer)?;
    let mut disc_resp = fetch_https_no_redirect(
        disc_url.as_str(),
        Method::Get,
        &[("accept", "application/json")],
        None,
    )
    .await?;
    let discovery_json = disc_resp
        .text()
        .await
        .map_err(|e| OidcError::Ssrf(SsrfError::FetchFailed(e.to_string())))?;
    let doc: OidcDiscoveryDoc = serde_json::from_str(&discovery_json)
        .map_err(|_| OidcError::InvalidClaims("malformed OIDC discovery document"))?;
    let endpoints = validate_discovery_document(configured_issuer, &doc)?;

    let mut jwks_resp = fetch_https_no_redirect(
        &endpoints.jwks_uri,
        Method::Get,
        &[("accept", "application/json")],
        None,
    )
    .await?;
    let jwks_json = jwks_resp
        .text()
        .await
        .map_err(|e| OidcError::Ssrf(SsrfError::FetchFailed(e.to_string())))?;
    let jwks: JwkSet = serde_json::from_str(&jwks_json)
        .map_err(|_| OidcError::InvalidClaims("malformed JWKS response"))?;

    let _ = challenge_do::put_cached_jwks(
        env,
        &JwksCachePutReq {
            issuer: configured_issuer.to_string(),
            discovery_json,
            jwks_json,
            ttl_secs: JWKS_CACHE_TTL_SECS,
        },
    )
    .await;

    Ok(OidcProviderMaterial { endpoints, jwks })
}

// ---------------------------------------------------------------------------
// JWT Signature Verification (Pure Rust RSA/Ed25519 + WebCrypto ES256/ES384)
// ---------------------------------------------------------------------------

/// DigestInfo DER prefixes per RFC 8017 Section 9.2 (Notes 1).
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0x05, 0x00, 0x04, 0x30,
];
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    0x05, 0x00, 0x04, 0x40,
];

/// Pure-Rust RSASSA-PKCS1-v1_5 verification (RFC 8017 Section 8.2.2).
pub fn verify_rsa_pkcs1_v15(
    alg: &str,
    n_bytes: &[u8],
    e_bytes: &[u8],
    signing_input: &[u8],
    sig_bytes: &[u8],
) -> Result<(), OidcError> {
    // Reject weak RSA keys (< 2048 bits) and oversized keys (> 8192 bits).
    let n_trimmed = strip_leading_zeros(n_bytes);
    if n_trimmed.len() < 256 || n_trimmed.len() > 1024 {
        return Err(OidcError::InvalidKey);
    }
    let k = n_trimmed.len();
    if sig_bytes.len() != k {
        return Err(OidcError::InvalidSignature);
    }

    let n = BigUint::from_bytes_be(n_trimmed);
    let e = BigUint::from_bytes_be(e_bytes);
    // Exponent must be odd and >= 3 (typically 65537).
    if e < BigUint::from(3u32) || (&e % 2u32) == BigUint::from(0u32) {
        return Err(OidcError::InvalidKey);
    }
    let s = BigUint::from_bytes_be(sig_bytes);
    if s >= n {
        return Err(OidcError::InvalidSignature);
    }

    let m = s.modpow(&e, &n);
    let m_raw = m.to_bytes_be();
    if m_raw.len() > k {
        return Err(OidcError::InvalidSignature);
    }
    let mut em = vec![0u8; k];
    em[k - m_raw.len()..].copy_from_slice(&m_raw);

    let (prefix, hash): (&[u8], Vec<u8>) = match alg {
        "RS256" => (DIGEST_INFO_SHA256, Sha256::digest(signing_input).to_vec()),
        "RS384" => (DIGEST_INFO_SHA384, Sha384::digest(signing_input).to_vec()),
        "RS512" => (DIGEST_INFO_SHA512, Sha512::digest(signing_input).to_vec()),
        other => return Err(OidcError::UnsupportedAlgorithm(other.to_string())),
    };

    let t_len = prefix.len() + hash.len();
    // EMSA-PKCS1-v1_5: 0x00 || 0x01 || PS (>= 8 bytes of 0xff) || 0x00 || T
    if k < t_len + 11 {
        return Err(OidcError::InvalidKey);
    }
    let mut expected = Vec::with_capacity(k);
    expected.push(0x00);
    expected.push(0x01);
    expected.resize(k - t_len - 1, 0xff);
    expected.push(0x00);
    expected.extend_from_slice(prefix);
    expected.extend_from_slice(&hash);

    if bool::from(em.as_slice().ct_eq(expected.as_slice())) {
        Ok(())
    } else {
        Err(OidcError::InvalidSignature)
    }
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nz = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nz..]
}

fn verify_eddsa_jwk(jwk: &Jwk, signing_input: &[u8], sig_bytes: &[u8]) -> Result<(), OidcError> {
    if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
        return Err(OidcError::InvalidKey);
    }
    let x_b64 = jwk.x.as_deref().ok_or(OidcError::InvalidKey)?;
    let x_raw = B64.decode(x_b64).map_err(|_| OidcError::InvalidKey)?;
    let pk_arr: [u8; 32] = x_raw.try_into().map_err(|_| OidcError::InvalidKey)?;
    let vk = EdVerifyingKey::from_bytes(&pk_arr).map_err(|_| OidcError::InvalidKey)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| OidcError::InvalidSignature)?;
    let sig = EdSignature::from_bytes(&sig_arr);
    vk.verify_strict(signing_input, &sig)
        .map_err(|_| OidcError::InvalidSignature)
}

#[cfg(target_arch = "wasm32")]
async fn verify_ecdsa_webcrypto(
    alg: &str,
    jwk: &Jwk,
    signing_input: &[u8],
    sig_bytes: &[u8],
) -> Result<(), OidcError> {
    use js_sys::{Object, Promise, Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let (named_curve, hash_name) = match alg {
        "ES256" => ("P-256", "SHA-256"),
        "ES384" => ("P-384", "SHA-384"),
        other => return Err(OidcError::UnsupportedAlgorithm(other.to_string())),
    };
    if jwk.kty != "EC" || jwk.crv.as_deref() != Some(named_curve) {
        return Err(OidcError::InvalidKey);
    }
    let x = jwk.x.as_deref().ok_or(OidcError::InvalidKey)?;
    let y = jwk.y.as_deref().ok_or(OidcError::InvalidKey)?;

    let global = js_sys::global();
    let crypto = Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|_| OidcError::InvalidSignature)?;
    let subtle = Reflect::get(&crypto, &JsValue::from_str("subtle"))
        .map_err(|_| OidcError::InvalidSignature)?;

    let jwk_obj = Object::new();
    let _ = Reflect::set(&jwk_obj, &"kty".into(), &"EC".into());
    let _ = Reflect::set(&jwk_obj, &"crv".into(), &named_curve.into());
    let _ = Reflect::set(&jwk_obj, &"x".into(), &x.into());
    let _ = Reflect::set(&jwk_obj, &"y".into(), &y.into());

    let import_alg = Object::new();
    let _ = Reflect::set(&import_alg, &"name".into(), &"ECDSA".into());
    let _ = Reflect::set(&import_alg, &"namedCurve".into(), &named_curve.into());

    let usages = js_sys::Array::new();
    usages.push(&JsValue::from_str("verify"));

    let import_fn: js_sys::Function = Reflect::get(&subtle, &"importKey".into())
        .map_err(|_| OidcError::InvalidSignature)?
        .dyn_into()
        .map_err(|_| OidcError::InvalidSignature)?;
    let key_promise: Promise = import_fn
        .apply(
            &subtle,
            &js_sys::Array::of5(
                &"jwk".into(),
                &jwk_obj.into(),
                &import_alg.into(),
                &JsValue::from_bool(false),
                &usages.into(),
            ),
        )
        .map_err(|_| OidcError::InvalidKey)?
        .dyn_into()
        .map_err(|_| OidcError::InvalidKey)?;
    let crypto_key = JsFuture::from(key_promise)
        .await
        .map_err(|_| OidcError::InvalidKey)?;

    let verify_alg = Object::new();
    let _ = Reflect::set(&verify_alg, &"name".into(), &"ECDSA".into());
    let _ = Reflect::set(&verify_alg, &"hash".into(), &hash_name.into());

    let sig_u8 = Uint8Array::from(sig_bytes);
    let data_u8 = Uint8Array::from(signing_input);

    let verify_fn: js_sys::Function = Reflect::get(&subtle, &"verify".into())
        .map_err(|_| OidcError::InvalidSignature)?
        .dyn_into()
        .map_err(|_| OidcError::InvalidSignature)?;
    let verify_promise: Promise = verify_fn
        .apply(
            &subtle,
            &js_sys::Array::of4(
                &verify_alg.into(),
                &crypto_key,
                &sig_u8.into(),
                &data_u8.into(),
            ),
        )
        .map_err(|_| OidcError::InvalidSignature)?
        .dyn_into()
        .map_err(|_| OidcError::InvalidSignature)?;
    let ok = JsFuture::from(verify_promise)
        .await
        .map_err(|_| OidcError::InvalidSignature)?;

    if ok.as_bool() == Some(true) {
        Ok(())
    } else {
        Err(OidcError::InvalidSignature)
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn verify_ecdsa_webcrypto(
    alg: &str,
    _jwk: &Jwk,
    _signing_input: &[u8],
    _sig_bytes: &[u8],
) -> Result<(), OidcError> {
    Err(OidcError::UnsupportedAlgorithm(alg.to_string()))
}

fn select_jwk<'a>(jwks: &'a JwkSet, header: &JwtHeader) -> Result<&'a Jwk, OidcError> {
    let expected_kty = match header.alg.as_str() {
        "RS256" | "RS384" | "RS512" => "RSA",
        "ES256" | "ES384" => "EC",
        "EdDSA" => "OKP",
        other => return Err(OidcError::UnsupportedAlgorithm(other.to_string())),
    };

    let candidates: Vec<&Jwk> = jwks
        .keys
        .iter()
        .filter(|k| k.kty == expected_kty)
        .filter(|k| k.key_use.as_deref().is_none_or(|u| u == "sig"))
        .filter(|k| k.alg.as_deref().is_none_or(|a| a == header.alg))
        .collect();

    if let Some(kid) = header.kid.as_deref() {
        candidates
            .into_iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or(OidcError::UnknownKeyId)
    } else if candidates.len() == 1 {
        Ok(candidates[0])
    } else {
        Err(OidcError::UnknownKeyId)
    }
}

/// Verify an OIDC ID Token's asymmetric signature against `jwks`, plus all
/// mandatory claims (`iss`, `aud`, `azp`, `exp`, `nbf`, `iat`, `nonce`, `sub`).
pub async fn verify_id_token(
    id_token: &str,
    jwks: &JwkSet,
    expected_issuer: &str,
    expected_client_id: &str,
    expected_nonce: &str,
    now: u64,
) -> Result<VerifiedIdToken, OidcError> {
    let mut parts = id_token.split('.');
    let (Some(h_b64), Some(p_b64), Some(s_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(OidcError::MalformedJwt);
    };
    if h_b64.is_empty() || p_b64.is_empty() || s_b64.is_empty() {
        return Err(OidcError::MalformedJwt);
    }

    let header_raw = B64.decode(h_b64).map_err(|_| OidcError::MalformedJwt)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_raw).map_err(|_| OidcError::MalformedJwt)?;

    // Strict asymmetric algorithm allowlist (blocks `"none"` and `"HS256"` key confusion).
    if !matches!(
        header.alg.as_str(),
        "RS256" | "RS384" | "RS512" | "EdDSA" | "ES256" | "ES384"
    ) {
        return Err(OidcError::UnsupportedAlgorithm(header.alg));
    }

    let jwk = select_jwk(jwks, &header)?;
    let signing_input = format!("{h_b64}.{p_b64}");
    let sig_bytes = B64.decode(s_b64).map_err(|_| OidcError::InvalidSignature)?;

    match header.alg.as_str() {
        "RS256" | "RS384" | "RS512" => {
            let n = B64
                .decode(jwk.n.as_deref().ok_or(OidcError::InvalidKey)?)
                .map_err(|_| OidcError::InvalidKey)?;
            let e = B64
                .decode(jwk.e.as_deref().ok_or(OidcError::InvalidKey)?)
                .map_err(|_| OidcError::InvalidKey)?;
            verify_rsa_pkcs1_v15(&header.alg, &n, &e, signing_input.as_bytes(), &sig_bytes)?;
        }
        "EdDSA" => {
            verify_eddsa_jwk(jwk, signing_input.as_bytes(), &sig_bytes)?;
        }
        "ES256" | "ES384" => {
            verify_ecdsa_webcrypto(&header.alg, jwk, signing_input.as_bytes(), &sig_bytes).await?;
        }
        other => return Err(OidcError::UnsupportedAlgorithm(other.to_string())),
    }

    let payload_raw = B64.decode(p_b64).map_err(|_| OidcError::MalformedJwt)?;
    let claims: Value =
        serde_json::from_slice(&payload_raw).map_err(|_| OidcError::MalformedJwt)?;

    validate_oidc_claims(
        &claims,
        expected_issuer,
        expected_client_id,
        expected_nonce,
        now,
    )
}

pub fn validate_oidc_claims(
    claims: &Value,
    expected_issuer: &str,
    expected_client_id: &str,
    expected_nonce: &str,
    now: u64,
) -> Result<VerifiedIdToken, OidcError> {
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(OidcError::InvalidClaims("missing iss"))?;
    if iss != expected_issuer {
        return Err(OidcError::IssuerMismatch);
    }

    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .ok_or(OidcError::InvalidClaims("missing or invalid sub"))?;

    // Audience (`aud`) check + authorized party (`azp`) enforcement per OIDC Core 3.1.3.7.
    let (aud_matches, multi_aud) = match claims.get("aud") {
        Some(Value::String(s)) => (s == expected_client_id, false),
        Some(Value::Array(arr)) => {
            let has = arr
                .iter()
                .any(|v| v.as_str() == Some(expected_client_id));
            (has, arr.len() > 1)
        }
        _ => (false, false),
    };
    if !aud_matches {
        return Err(OidcError::AudienceMismatch);
    }
    let azp = claims.get("azp").and_then(Value::as_str);
    if multi_aud && azp != Some(expected_client_id) {
        return Err(OidcError::AudienceMismatch);
    }
    if let Some(a) = azp
        && a != expected_client_id
    {
        return Err(OidcError::AudienceMismatch);
    }

    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(OidcError::InvalidClaims("missing exp"))?;
    if now > exp.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(OidcError::Expired);
    }

    if let Some(nbf) = claims.get("nbf").and_then(Value::as_u64)
        && now.saturating_add(MAX_CLOCK_SKEW_SECS) < nbf
    {
        return Err(OidcError::NotYetValid);
    }
    if let Some(iat) = claims.get("iat").and_then(Value::as_u64)
        && iat > now.saturating_add(300)
    {
        return Err(OidcError::InvalidClaims("iat in the future"));
    }

    let nonce = claims
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or(OidcError::NonceMismatch)?;
    if !bool::from(nonce.as_bytes().ct_eq(expected_nonce.as_bytes())) {
        return Err(OidcError::NonceMismatch);
    }

    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    let email_verified = claims
        .get("email_verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let name = claims
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| claims.get("preferred_username").and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let acr = claims
        .get("acr")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let amr = claims
        .get("amr")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(VerifiedIdToken {
        sub: sub.to_string(),
        iss: iss.to_string(),
        email,
        email_verified,
        name,
        acr,
        amr,
        raw_claims: claims.clone(),
    })
}

// ---------------------------------------------------------------------------
// Strict Verified-18+ Claim Extraction (OidcAgeAssurance ONLY)
// ---------------------------------------------------------------------------

/// Evaluate verified 18+ claims from a vetted Age-Assurance OIDC provider.
///
/// Requires:
/// 1. If `required_acr` is configured, token `acr` MUST match.
/// 2. If `required_amr` is configured, token `amr` MUST contain it.
/// 3. Explicit 18+ proof:
///    - OIDC4IDA `verified_claims.claims.{age_over_18 == true | age_equal_or_over."18" == true | birthdate >= 18}`
///      (requiring non-empty `verified_claims.verification.trust_framework`), OR
///    - Top-level `age_over_18 == true` / `age_equal_or_over."18" == true` / `birthdate >= 18`
///      accompanied by non-empty `acr` or `amr` assurance provenance!
pub fn evaluate_verified_18_claims(
    token: &VerifiedIdToken,
    required_acr: Option<&str>,
    required_amr: Option<&str>,
    now_epoch_secs: u64,
) -> Result<VerifiedAgeResult, OidcError> {
    if let Some(req_acr) = required_acr.map(str::trim).filter(|s| !s.is_empty())
        && token.acr.as_deref() != Some(req_acr)
    {
        return Err(OidcError::AgeNotVerified("acr assurance level mismatch"));
    }
    if let Some(req_amr) = required_amr.map(str::trim).filter(|s| !s.is_empty())
        && !token.amr.iter().any(|m| m == req_amr)
    {
        return Err(OidcError::AgeNotVerified("required amr method missing"));
    }

    // Path 1: OIDC for Identity Assurance (`verified_claims`)
    if let Some(vc) = token.raw_claims.get("verified_claims") {
        let trust_framework = vc
            .pointer("/verification/trust_framework")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(tf) = trust_framework
            && let Some(vc_claims) = vc.get("claims")
            && let Some(method) = check_age_18_claim_object(vc_claims, now_epoch_secs)
        {
            return Ok(VerifiedAgeResult {
                verified_18: true,
                method: format!("oidc_ida:{tf}:{method}"),
            });
        }
    }

    // Path 2: Top-level verified claims on a vetted age-assurance OIDC issuer with acr/amr provenance
    let has_provenance = token.acr.is_some() || !token.amr.is_empty();
    if has_provenance && let Some(method) = check_age_18_claim_object(&token.raw_claims, now_epoch_secs)
    {
        let prov = token
            .acr
            .as_deref()
            .or_else(|| token.amr.first().map(String::as_str))
            .unwrap_or("oidc");
        return Ok(VerifiedAgeResult {
            verified_18: true,
            method: format!("oidc:{prov}:{method}"),
        });
    }

    Err(OidcError::AgeNotVerified(
        "missing verified age_over_18 or verified birthdate (>= 18) with assurance provenance",
    ))
}

fn check_age_18_claim_object(obj: &Value, now_epoch_secs: u64) -> Option<&'static str> {
    if obj.get("age_over_18").and_then(Value::as_bool) == Some(true) {
        return Some("age_over_18");
    }
    if obj
        .get("age_equal_or_over")
        .and_then(|m| m.get("18"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Some("age_equal_or_over_18");
    }
    if let Some(dob) = obj.get("birthdate").and_then(Value::as_str)
        && is_dob_at_least_18(dob, now_epoch_secs) == Some(true)
    {
        return Some("birthdate");
    }
    None
}

/// Convert Unix epoch seconds to UTC `(year, month, day)` using Howard Hinnant's algorithm.
pub fn epoch_to_utc_date(epoch_secs: u64) -> (i32, u8, u8) {
    let z = (epoch_secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = (y + i64::from(m <= 2)) as i32;
    (year, m as u8, d as u8)
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Calendar-exact full `YYYY-MM-DD` >= 18 check. Rejects partial dates (`0000-05-01`, `1990`).
pub fn is_dob_at_least_18(dob: &str, now_epoch_secs: u64) -> Option<bool> {
    let parts: Vec<&str> = dob.trim().split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return None;
    }
    let y: i32 = parts[0].parse().ok()?;
    let m: u8 = parts[1].parse().ok()?;
    let d: u8 = parts[2].parse().ok()?;
    if !(1900..=2200).contains(&y) || !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    let (cy, cm, cd) = epoch_to_utc_date(now_epoch_secs);
    let age_years = cy - y;
    if age_years > 18 {
        Some(true)
    } else if age_years < 18 {
        Some(false)
    } else {
        Some((cm, cd) >= (m, d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // 2026-11-23T00:00:00Z
    const NOW: u64 = 1_795_392_000;

    #[test]
    fn dob_check_handles_exact_18th_birthday_and_rejects_partial_dates() {
        let (y, m, d) = epoch_to_utc_date(NOW);
        assert_eq!((y, m, d), (2026, 11, 23));

        assert_eq!(is_dob_at_least_18("2008-11-23", NOW), Some(true));
        assert_eq!(is_dob_at_least_18("2008-11-24", NOW), Some(false));
        assert_eq!(is_dob_at_least_18("2000-02-29", NOW), Some(true));
        assert_eq!(is_dob_at_least_18("2001-02-29", NOW), None); // invalid leap day
        assert_eq!(is_dob_at_least_18("0000-05-10", NOW), None); // Google partial birthday
        assert_eq!(is_dob_at_least_18("1995", NOW), None);
    }

    #[test]
    fn eddsa_id_token_signature_and_strict_18_claims_verify() {
        let sk = SigningKey::from_bytes(&[0x33u8; 32]);
        let pk_b64 = B64.encode(sk.verifying_key().to_bytes());
        let jwks = JwkSet {
            keys: vec![Jwk {
                kty: "OKP".into(),
                kid: Some("k-ed1".into()),
                key_use: Some("sig".into()),
                alg: Some("EdDSA".into()),
                n: None,
                e: None,
                crv: Some("Ed25519".into()),
                x: Some(pk_b64),
                y: None,
            }],
        };

        let header = B64.encode(r#"{"alg":"EdDSA","kid":"k-ed1","typ":"JWT"}"#);
        let payload = B64.encode(
            serde_json::json!({
                "iss": "https://id.yoti.com",
                "sub": "yoti-user-99",
                "aud": "client-123",
                "exp": NOW + 300,
                "iat": NOW,
                "nonce": "nonce-abc",
                "acr": "eidas-high",
                "amr": ["idv"],
                "verified_claims": {
                    "verification": { "trust_framework": "uk_tfida" },
                    "claims": { "age_over_18": true }
                }
            })
            .to_string(),
        );
        let signing_input = format!("{header}.{payload}");
        let sig = sk.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", B64.encode(sig.to_bytes()));

        let verified = futures::executor::block_on(verify_id_token(
            &jwt,
            &jwks,
            "https://id.yoti.com",
            "client-123",
            "nonce-abc",
            NOW,
        ))
        .expect("valid EdDSA token");
        assert_eq!(verified.sub, "yoti-user-99");

        let age = evaluate_verified_18_claims(&verified, Some("eidas-high"), Some("idv"), NOW)
            .expect("verified 18+");
        assert!(age.verified_18);

        // Wrong nonce rejected
        assert_eq!(
            futures::executor::block_on(verify_id_token(
                &jwt,
                &jwks,
                "https://id.yoti.com",
                "client-123",
                "wrong-nonce",
                NOW,
            ))
            .unwrap_err(),
            OidcError::NonceMismatch
        );

        // Algorithm confusion ("none" / "HS256") rejected
        let none_header = B64.encode(r#"{"alg":"none"}"#);
        let forged_none = format!("{none_header}.{payload}.sig");
        assert!(matches!(
            futures::executor::block_on(verify_id_token(
                &forged_none,
                &jwks,
                "https://id.yoti.com",
                "client-123",
                "nonce-abc",
                NOW,
            )),
            Err(OidcError::UnsupportedAlgorithm(_))
        ));

        // Missing verified_claims & acr/amr provenance MUST fail verified 18+
        let unverified = VerifiedIdToken {
            acr: None,
            amr: vec![],
            raw_claims: serde_json::json!({ "age_over_18": true }),
            ..verified
        };
        assert!(evaluate_verified_18_claims(&unverified, None, None, NOW).is_err());
    }
}
