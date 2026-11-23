//! Cross-device QR / one-time-code sign-in and mobile wallet-app handoff.
//!
//! Security upgrades (H7, H8):
//! - Enforces `AgeVerificationPolicy` provider eligibility uniformly across
//!   `handoff/approve_eth`, `handoff/approve_sol`, `handoff/poll`, AND `transfer/claim`!
//! - Issues revocable `v2` sessions (`identity::issue_v2_session`) addressed via
//!   `users_v2.account_do_key` across both QR handoff and transfer claim.
//! - Uses pinned `PUBLIC_URL` origin for QR approval & transfer URLs (L2).

use std::net::IpAddr;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use site_access::{AssuranceLevel, AuthProviderId};
use tower_cookies::Cookies;
use worker::{Method, Request, RequestInit, wasm_bindgen::JsValue};

use crate::{
    AppState, auth, config, do_client,
    identity::{self, VerifiedExternalIdentity},
    policy_do,
    qr::{self, QrMatrix},
    session, siwe, solana_link,
};

const HANDOFF_DO_ID: &str = "__auth_handoff__";
const HANDOFF_TTL_SECS: u64 = 300; // 5 minutes
const TRANSFER_TTL_SECS: u64 = 180; // 3 minutes

const SHORT_CODE_ALPH: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

// ---------------------------------------------------------------------------
// Internal DO wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffStartReq {
    pub ip_key: String,
    pub session_id: String,
    pub poll_secret_hash: String,
    pub verify_code: String,
    pub approve_nonce: String,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffInfoReq {
    pub session_id: String,
    #[serde(default)]
    pub ip_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffInfoResp {
    pub status: String,
    pub verify_code: String,
    pub approve_nonce: String,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffApproveReq {
    pub session_id: String,
    pub approve_nonce: String,
    pub principal: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffPollReq {
    pub ip_key: String,
    pub session_id: String,
    pub poll_secret_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffPollResp {
    pub status: String,
    pub principal: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoTransferCreateReq {
    pub principal: String,
    pub code_hash: String,
    pub token_hash: String,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoTransferClaimReq {
    pub ip_key: String,
    pub code_hash: Option<String>,
    pub token_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoTransferClaimResp {
    pub principal: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoTransferRevokeReq {
    pub principal: String,
}

/// Structured envelope stored in `handoff_sessions_v2.principal` / `transfer_codes.principal`
/// carrying full `users_v2` provenance while staying backwards-compatible with legacy DO rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPrincipalEnvelope {
    user_id: String,
    auth_method: String,
    identity_key: String,
    display_address: String,
}

const ENVELOPE_PREFIX: &str = "v2json:";

fn encode_envelope(env: &StoredPrincipalEnvelope) -> String {
    format!(
        "{ENVELOPE_PREFIX}{}",
        serde_json::to_string(env).unwrap_or_default()
    )
}

fn decode_envelope(raw: &str) -> Option<StoredPrincipalEnvelope> {
    if let Some(json_str) = raw.strip_prefix(ENVELOPE_PREFIX) {
        serde_json::from_str(json_str).ok()
    } else if session::is_valid_principal(raw) {
        let provider = if session::is_eth_address(raw) {
            AuthProviderId::Siwe
        } else {
            AuthProviderId::Siws
        };
        let issuer = if provider == AuthProviderId::Siwe {
            "eip155:1"
        } else {
            "solana:mainnet"
        };
        Some(StoredPrincipalEnvelope {
            user_id: raw.to_string(),
            auth_method: provider.as_str().to_string(),
            identity_key: format!("{}|{}|{}", provider.as_str(), issuer, raw),
            display_address: auth::display_address(raw),
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Public HTTP wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct HandoffStartResp {
    pub session_id: String,
    pub poll_secret: String,
    pub verify_code: String,
    pub approve_url: String,
    pub expires_in: u64,
    pub qr: Option<QrMatrix>,
}

#[derive(Debug, Deserialize)]
pub struct HandoffInfoQuery {
    pub s: String,
}

#[derive(Debug, Serialize)]
pub struct HandoffInfoResp {
    pub status: String,
    pub verify_code: String,
    pub approve_nonce: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct HandoffApproveEthReq {
    pub session_id: String,
    pub message: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct HandoffApproveSolReq {
    pub session_id: String,
    pub solana_address: String,
    pub signature: String,
    pub nonce: String,
    #[serde(default)]
    pub signed_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HandoffPollReq {
    pub session_id: String,
    pub poll_secret: String,
}

#[derive(Debug, Serialize)]
pub struct HandoffPollResp {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TransferCreateResp {
    pub code: String,
    pub expires_in: u64,
    pub qr: Option<QrMatrix>,
}

#[derive(Debug, Deserialize)]
pub struct TransferClaimReq {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

// ---------------------------------------------------------------------------
// Pure helpers & challenge templates (host-testable)
// ---------------------------------------------------------------------------

pub fn handoff_siwe_statement(session_id: &str, verify_code: &str) -> String {
    format!(
        "Approve sign-in for another browser on lets_embed (Code: {verify_code}, Session: {session_id})"
    )
}

pub fn valid_handoff_siwe_uri(uri: &str, domain: &str) -> bool {
    uri == format!("https://{domain}/user/login/approve")
        || (domain
            .split(':')
            .next()
            .is_some_and(|h| matches!(h, "localhost" | "127.0.0.1"))
            && uri == format!("http://{domain}/user/login/approve"))
}

pub fn handoff_siws_challenge(
    domain: &str,
    session_id: &str,
    verify_code: &str,
    nonce: &str,
) -> String {
    format!(
        "Approve sign-in for another browser on lets_embed with Solana\nDomain: {domain}\nSession: {session_id}\nCode: {verify_code}\nNonce: {nonce}"
    )
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn random_b64url(num_bytes: usize) -> Result<String, Response> {
    let mut buf = vec![0u8; num_bytes];
    getrandom::fill(&mut buf).map_err(|e| {
        worker::console_error!("getrandom failed: {e:?}");
        auth::internal_error()
    })?;
    Ok(B64.encode(buf))
}

fn generate_short_code() -> Result<String, Response> {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).map_err(|e| {
        worker::console_error!("getrandom failed: {e:?}");
        auth::internal_error()
    })?;
    let raw: String = buf
        .iter()
        .map(|&b| SHORT_CODE_ALPH[(b & 31) as usize] as char)
        .collect();
    Ok(format_short_code(&raw))
}

fn generate_verify_code() -> Result<String, Response> {
    let mut out = String::with_capacity(4);
    let mut buf = [0u8; 16];
    while out.len() < 4 {
        getrandom::fill(&mut buf).map_err(|e| {
            worker::console_error!("getrandom failed: {e:?}");
            auth::internal_error()
        })?;
        for &b in &buf {
            if b < 250 {
                out.push((b'0' + (b % 10)) as char);
                if out.len() == 4 {
                    break;
                }
            }
        }
    }
    Ok(out)
}

pub fn format_short_code(raw8: &str) -> String {
    if raw8.len() == 8 {
        format!("{}-{}", &raw8[..4], &raw8[4..])
    } else {
        raw8.to_string()
    }
}

pub fn normalize_short_code(input: &str) -> Option<String> {
    let mut out = String::with_capacity(8);
    for ch in input.chars() {
        if ch == '-' || ch.is_whitespace() {
            continue;
        }
        let up = ch.to_ascii_uppercase();
        if !up.is_ascii() || !SHORT_CODE_ALPH.contains(&(up as u8)) {
            return None;
        }
        out.push(up);
        if out.len() > 8 {
            return None;
        }
    }
    (out.len() == 8).then_some(out)
}

fn valid_id_token(s: &str) -> bool {
    (16..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn normalize_ip(raw: &str) -> String {
    match raw.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => {
            let segs = v6.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                segs[0], segs[1], segs[2], segs[3]
            )
        }
        Err(_) => "unknown".to_string(),
    }
}

fn ip_rate_key(headers: &HeaderMap, secret: &[u8]) -> String {
    let raw = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let norm = normalize_ip(raw);
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(b":handoff-ip:");
    hasher.update(norm.as_bytes());
    hex::encode(&hasher.finalize()[..16])
}

async fn call_handoff_do<T: Serialize>(
    st: &AppState,
    path: &str,
    payload: &T,
) -> Result<(u16, String), Response> {
    let body = serde_json::to_string(payload).map_err(|_| auth::internal_error())?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(JsValue::from_str(&body)));
    let _ = init.headers.set("content-type", "application/json");
    let req = Request::new_with_init(&format!("https://do{path}"), &init).map_err(|e| {
        worker::console_error!("handoff DO request build failed: {e:?}");
        auth::internal_error()
    })?;
    let stub = st
        .env
        .durable_object("USER_ACCOUNT")
        .and_then(|ns| ns.id_from_name(HANDOFF_DO_ID)?.get_stub())
        .map_err(|e| {
            worker::console_error!("handoff DO stub failed: {e:?}");
            auth::internal_error()
        })?;
    let mut resp = stub.fetch_with_request(req).await.map_err(|e| {
        worker::console_error!("handoff DO fetch failed: {e:?}");
        auth::internal_error()
    })?;
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}

async fn fetch_pending_session(
    st: &AppState,
    session_id: &str,
    ip_key: Option<String>,
) -> Result<DoHandoffInfoResp, Response> {
    let req = DoHandoffInfoReq {
        session_id: session_id.to_string(),
        ip_key,
    };
    match call_handoff_do(st, "/handoff-info", &req).await? {
        (200, text) => {
            serde_json::from_str::<DoHandoffInfoResp>(&text).map_err(|_| auth::internal_error())
        }
        (410, msg) => Err(auth::api_error(StatusCode::GONE, msg)),
        (429, msg) => Err(auth::api_error(StatusCode::TOO_MANY_REQUESTS, msg)),
        (code, msg) => {
            worker::console_error!("handoff-info DO error {code}: {msg}");
            Err(auth::internal_error())
        }
    }
}

// ---------------------------------------------------------------------------
// Wallet app handoff handlers
// ---------------------------------------------------------------------------

#[worker::send]
pub async fn start(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(_) => return auth::internal_error(),
    };
    let eth_ok =
        identity::check_login_provider_eligibility(&policy, AuthProviderId::Siwe, None).is_ok();
    let sol_ok =
        identity::check_login_provider_eligibility(&policy, AuthProviderId::Siws, None).is_ok();
    if !eth_ok && !sol_ok {
        return auth::api_error(
            StatusCode::FORBIDDEN,
            "Wallet sign-in handoff is disabled under the active site age/auth policy.",
        );
    }

    let session_id = match random_b64url(16) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let poll_secret = match random_b64url(32) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let approve_nonce = match random_b64url(16) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let verify_code = match generate_verify_code() {
        Ok(c) => c,
        Err(r) => return r,
    };
    let now = session::now_secs();
    let req = DoHandoffStartReq {
        ip_key: ip_rate_key(&headers, &st.jwt_secret),
        session_id: session_id.clone(),
        poll_secret_hash: sha256_hex(&poll_secret),
        verify_code: verify_code.clone(),
        approve_nonce,
        expires_at: now + HANDOFF_TTL_SECS,
    };
    match call_handoff_do(&st, "/handoff-start", &req).await {
        Ok((200, _)) => {}
        Ok((429, msg)) => return auth::api_error(StatusCode::TOO_MANY_REQUESTS, msg),
        Ok((code, msg)) => {
            worker::console_error!("handoff-start DO error {code}: {msg}");
            return auth::internal_error();
        }
        Err(r) => return r,
    }
    let approve_url = format!("{}/user/login/approve?s={session_id}", st.public_origin());
    let qr = qr::encode(approve_url.as_bytes());
    Json(HandoffStartResp {
        session_id,
        poll_secret,
        verify_code,
        approve_url,
        expires_in: HANDOFF_TTL_SECS,
        qr,
    })
    .into_response()
}

#[worker::send]
pub async fn info(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HandoffInfoQuery>,
) -> Response {
    if !valid_id_token(&q.s) {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid session id");
    }
    let ip_key = Some(ip_rate_key(&headers, &st.jwt_secret));
    match fetch_pending_session(&st, &q.s, ip_key).await {
        Ok(info) => {
            let now = session::now_secs();
            Json(HandoffInfoResp {
                status: info.status,
                verify_code: info.verify_code,
                approve_nonce: info.approve_nonce,
                expires_in: info.expires_at.saturating_sub(now),
            })
            .into_response()
        }
        Err(r) => r,
    }
}

#[worker::send]
pub async fn approve_eth(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HandoffApproveEthReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(_) => return auth::internal_error(),
    };
    if let Err(msg) = identity::check_login_provider_eligibility(&policy, AuthProviderId::Siwe, None)
    {
        return auth::api_error(StatusCode::FORBIDDEN, msg);
    }
    if !valid_id_token(&req.session_id) {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid session id");
    }

    let ip_key = Some(ip_rate_key(&headers, &st.jwt_secret));
    let info = match fetch_pending_session(&st, &req.session_id, ip_key).await {
        Ok(i) => i,
        Err(r) => return r,
    };
    if info.status != "pending" {
        return auth::api_error(StatusCode::CONFLICT, "sign-in session already approved");
    }

    let msg = match siwe::parse_siwe(&req.message) {
        Ok(m) => m,
        Err(e) => return auth::api_error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    if msg.domain != *st.siwe_domain {
        return auth::api_error(StatusCode::UNAUTHORIZED, "domain mismatch");
    }
    if msg.version != "1" {
        return auth::api_error(StatusCode::UNAUTHORIZED, "unsupported version");
    }
    if msg.chain_id != st.chain_id {
        return auth::api_error(StatusCode::UNAUTHORIZED, "chain id mismatch");
    }
    if !valid_handoff_siwe_uri(&msg.uri, &st.siwe_domain) {
        return auth::api_error(StatusCode::UNAUTHORIZED, "invalid approval URI");
    }
    let expected_stmt = handoff_siwe_statement(&req.session_id, &info.verify_code);
    if msg.statement.as_deref() != Some(expected_stmt.as_str()) {
        return auth::api_error(StatusCode::UNAUTHORIZED, "approval statement mismatch");
    }
    if !ct_eq(msg.nonce.as_bytes(), info.approve_nonce.as_bytes()) {
        return auth::api_error(StatusCode::UNAUTHORIZED, "unknown or expired nonce");
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
            return auth::api_error(StatusCode::UNAUTHORIZED, "invalid expiration timestamp");
        };
        if exp <= now {
            return auth::api_error(StatusCode::UNAUTHORIZED, "message expired");
        }
    }

    let addr = match siwe::recover_address(&req.message, &req.signature) {
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
        label: Some("Ethereum wallet".to_string()),
        verified_email: None,
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    };
    let account = match identity::resolve_or_create_login_account(&st, &policy, &ident).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    let envelope = StoredPrincipalEnvelope {
        user_id: account.user_id,
        auth_method: AuthProviderId::Siwe.as_str().to_string(),
        identity_key: ident.identity_key(),
        display_address: auth::display_address(&addr),
    };
    let do_req = DoHandoffApproveReq {
        session_id: req.session_id,
        approve_nonce: info.approve_nonce,
        principal: encode_envelope(&envelope),
    };
    match call_handoff_do(&st, "/handoff-approve", &do_req).await {
        Ok((200, _)) => Json(crate::types::VerifyResp {
            address: auth::display_address(&addr),
        })
        .into_response(),
        Ok((401, msg)) => auth::api_error(StatusCode::UNAUTHORIZED, msg),
        Ok((409, msg)) => auth::api_error(StatusCode::CONFLICT, msg),
        Ok((410, msg)) => auth::api_error(StatusCode::GONE, msg),
        Ok((code, msg)) => {
            worker::console_error!("handoff-approve DO error {code}: {msg}");
            auth::internal_error()
        }
        Err(r) => r,
    }
}

#[worker::send]
pub async fn approve_sol(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HandoffApproveSolReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(_) => return auth::internal_error(),
    };
    if let Err(msg) = identity::check_login_provider_eligibility(&policy, AuthProviderId::Siws, None)
    {
        return auth::api_error(StatusCode::FORBIDDEN, msg);
    }
    if !valid_id_token(&req.session_id) {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid session id");
    }
    if !session::is_sol_principal(&req.solana_address) {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid solana address");
    }

    let ip_key = Some(ip_rate_key(&headers, &st.jwt_secret));
    let info = match fetch_pending_session(&st, &req.session_id, ip_key).await {
        Ok(i) => i,
        Err(r) => return r,
    };
    if info.status != "pending" {
        return auth::api_error(StatusCode::CONFLICT, "sign-in session already approved");
    }
    if !ct_eq(req.nonce.as_bytes(), info.approve_nonce.as_bytes()) {
        return auth::api_error(StatusCode::UNAUTHORIZED, "unknown or expired nonce");
    }

    let msg = handoff_siws_challenge(
        st.siwe_domain.as_str(),
        &req.session_id,
        &info.verify_code,
        &info.approve_nonce,
    );
    if !solana_link::verify_ed25519_challenge(
        &req.solana_address,
        &req.signature,
        &msg,
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
        subject: req.solana_address.clone(),
        label: Some("Solana wallet".to_string()),
        verified_email: None,
        assurance_level: AssuranceLevel::None,
        assurance_method: None,
        assurance_verified_at: None,
        assurance_expires_at: None,
    };
    let account = match identity::resolve_or_create_login_account(&st, &policy, &ident).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    let envelope = StoredPrincipalEnvelope {
        user_id: account.user_id,
        auth_method: AuthProviderId::Siws.as_str().to_string(),
        identity_key: ident.identity_key(),
        display_address: req.solana_address.clone(),
    };
    let do_req = DoHandoffApproveReq {
        session_id: req.session_id,
        approve_nonce: info.approve_nonce,
        principal: encode_envelope(&envelope),
    };
    match call_handoff_do(&st, "/handoff-approve", &do_req).await {
        Ok((200, _)) => Json(crate::types::VerifyResp {
            address: req.solana_address,
        })
        .into_response(),
        Ok((401, msg)) => auth::api_error(StatusCode::UNAUTHORIZED, msg),
        Ok((409, msg)) => auth::api_error(StatusCode::CONFLICT, msg),
        Ok((410, msg)) => auth::api_error(StatusCode::GONE, msg),
        Ok((code, msg)) => {
            worker::console_error!("handoff-approve DO error {code}: {msg}");
            auth::internal_error()
        }
        Err(r) => r,
    }
}

#[worker::send]
pub async fn poll(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<HandoffPollReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    if !valid_id_token(&req.session_id) || !valid_id_token(&req.poll_secret) {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid session parameters");
    }
    let ip_key = ip_rate_key(&headers, &st.jwt_secret);
    let poll_secret_hash = sha256_hex(&req.poll_secret);
    let do_req = DoHandoffPollReq {
        ip_key: ip_key.clone(),
        session_id: req.session_id.clone(),
        poll_secret_hash: poll_secret_hash.clone(),
    };
    let parsed = match call_handoff_do(&st, "/handoff-poll", &do_req).await {
        Ok((200, text)) => match serde_json::from_str::<DoHandoffPollResp>(&text) {
            Ok(p) => p,
            Err(_) => return auth::internal_error(),
        },
        Ok((401, msg)) => return auth::api_error(StatusCode::UNAUTHORIZED, msg),
        Ok((410, msg)) => return auth::api_error(StatusCode::GONE, msg),
        Ok((429, msg)) => return auth::api_error(StatusCode::TOO_MANY_REQUESTS, msg),
        Ok((code, msg)) => {
            worker::console_error!("handoff-poll DO error {code}: {msg}");
            return auth::internal_error();
        }
        Err(r) => return r,
    };

    if parsed.status == "approved"
        && let Some(raw_principal) = parsed.principal
    {
        let Some(env) = decode_envelope(&raw_principal) else {
            return auth::internal_error();
        };
        let policy = match policy_do::load_site_policy(&st.env).await {
            Ok(e) => e.policy,
            Err(_) => return auth::internal_error(),
        };
        let Some(provider_id) = identity::provider_from_str(&env.auth_method) else {
            return auth::api_error(StatusCode::FORBIDDEN, "unsupported provider");
        };
        if let Err(msg) = identity::check_login_provider_eligibility(&policy, provider_id, None) {
            return auth::api_error(StatusCode::FORBIDDEN, msg);
        }

        let Some(account) = (match identity::load_account_by_id(&st, &env.user_id).await {
            Ok(a) => a,
            Err(r) => return r,
        }) else {
            return auth::api_error(StatusCode::UNAUTHORIZED, "account not found");
        };
        if account.banned {
            return auth::api_error(StatusCode::FORBIDDEN, "account banned");
        }

        // Atomically consume approval BEFORE issuing revocable `v2` session!
        let consume_req = DoHandoffPollReq {
            ip_key,
            session_id: req.session_id,
            poll_secret_hash,
        };
        match call_handoff_do(&st, "/handoff-consume", &consume_req).await {
            Ok((200, _)) => {}
            Ok((401, msg)) => return auth::api_error(StatusCode::UNAUTHORIZED, msg),
            Ok((409, msg)) => return auth::api_error(StatusCode::CONFLICT, msg),
            Ok((410, msg)) => return auth::api_error(StatusCode::GONE, msg),
            Ok((code, msg)) => {
                worker::console_error!("handoff-consume DO error {code}: {msg}");
                return auth::internal_error();
            }
            Err(r) => return r,
        }

        if let Err(r) = identity::issue_v2_session(
            &st,
            &cookies,
            &account,
            &env.auth_method,
            &env.identity_key,
            AssuranceLevel::None,
            false,
        )
        .await
        {
            return r;
        }
        return Json(HandoffPollResp {
            status: "approved".to_string(),
            address: Some(env.display_address),
        })
        .into_response();
    }

    Json(HandoffPollResp {
        status: "pending".to_string(),
        address: None,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Signed-in desktop -> mobile QR & one-time code transfer handlers
// ---------------------------------------------------------------------------

#[worker::send]
pub async fn transfer_create(
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

    let session_info = if let Some(sid) = active.sid.as_deref() {
        do_client::do_session_info(&st.env, &active.do_key, sid)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let (auth_method, identity_key) = match session_info {
        Some(info) => (info.auth_method, info.identity_key),
        None => {
            let p = if session::is_eth_address(&active.user_id) {
                "siwe"
            } else {
                "siws"
            };
            (p.to_string(), format!("{p}|legacy|{}", active.user_id))
        }
    };

    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(_) => return auth::internal_error(),
    };
    if let Some(pid) = identity::provider_from_str(&auth_method)
        && let Err(msg) = identity::check_login_provider_eligibility(
            &policy,
            pid,
            Some(active.ctx.assurance_level),
        )
    {
        return auth::api_error(StatusCode::FORBIDDEN, msg);
    }

    let code = match generate_short_code() {
        Ok(c) => c,
        Err(r) => return r,
    };
    let normalized = normalize_short_code(&code).expect("generated code is normalized");
    let qr_token = match random_b64url(24) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let now = session::now_secs();
    let envelope = StoredPrincipalEnvelope {
        user_id: active.user_id.clone(),
        auth_method,
        identity_key,
        display_address: auth::display_address(&active.user_id),
    };
    let do_req = DoTransferCreateReq {
        principal: encode_envelope(&envelope),
        code_hash: sha256_hex(&format!("code:{normalized}")),
        token_hash: sha256_hex(&format!("tok:{qr_token}")),
        expires_at: now + TRANSFER_TTL_SECS,
    };
    match call_handoff_do(&st, "/transfer-create", &do_req).await {
        Ok((200, _)) => {}
        Ok((429, msg)) => return auth::api_error(StatusCode::TOO_MANY_REQUESTS, msg),
        Ok((code, msg)) => {
            worker::console_error!("transfer-create DO error {code}: {msg}");
            return auth::internal_error();
        }
        Err(r) => return r,
    }
    let login_url = format!("{}/user/login#transfer={qr_token}", st.public_origin());
    let qr = qr::encode(login_url.as_bytes());
    Json(TransferCreateResp {
        code,
        expires_in: TRANSFER_TTL_SECS,
        qr,
    })
    .into_response()
}

#[worker::send]
pub async fn transfer_claim(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<TransferClaimReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let ip_key = ip_rate_key(&headers, &st.jwt_secret);
    let token_opt = req
        .token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let code_opt = req.code.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let (code_hash, token_hash) = if let Some(trimmed) = token_opt {
        if !valid_id_token(trimmed) {
            return auth::api_error(StatusCode::BAD_REQUEST, "invalid QR login token");
        }
        (None, Some(sha256_hex(&format!("tok:{trimmed}"))))
    } else if let Some(raw_code) = code_opt {
        let Some(norm) = normalize_short_code(raw_code) else {
            return auth::api_error(
                StatusCode::BAD_REQUEST,
                "enter the 8-character code shown on your account page",
            );
        };
        (Some(sha256_hex(&format!("code:{norm}"))), None)
    } else {
        return auth::api_error(StatusCode::BAD_REQUEST, "missing code or token");
    };

    let do_req = DoTransferClaimReq {
        ip_key,
        code_hash,
        token_hash,
    };
    let claimed = match call_handoff_do(&st, "/transfer-claim", &do_req).await {
        Ok((200, text)) => match serde_json::from_str::<DoTransferClaimResp>(&text) {
            Ok(c) => c,
            Err(_) => return auth::internal_error(),
        },
        Ok((401, msg)) => return auth::api_error(StatusCode::UNAUTHORIZED, msg),
        Ok((429, msg)) => return auth::api_error(StatusCode::TOO_MANY_REQUESTS, msg),
        Ok((code, msg)) => {
            worker::console_error!("transfer-claim DO error {code}: {msg}");
            return auth::internal_error();
        }
        Err(r) => return r,
    };

    let Some(env) = decode_envelope(&claimed.principal) else {
        return auth::internal_error();
    };
    let policy = match policy_do::load_site_policy(&st.env).await {
        Ok(e) => e.policy,
        Err(_) => return auth::internal_error(),
    };
    let Some(provider_id) = identity::provider_from_str(&env.auth_method) else {
        return auth::api_error(StatusCode::FORBIDDEN, "unsupported provider");
    };

    let Some(account) = (match identity::load_account_by_id(&st, &env.user_id).await {
        Ok(a) => a,
        Err(r) => return r,
    }) else {
        return auth::api_error(StatusCode::UNAUTHORIZED, "account not found");
    };
    if account.banned {
        return auth::api_error(StatusCode::FORBIDDEN, "account banned");
    }

    // Re-check linked identity provenance from D1 (unlinked or expired Verified18 loses strict privilege!).
    let now = session::now_secs();
    let identities = identity::list_user_identities(&st, &account.user_id)
        .await
        .unwrap_or_default();
    let Some(mi) = identities.iter().find(|i| {
        i.purpose == "login"
            && format!("{}|{}|{}", i.provider_id, i.issuer, i.subject) == env.identity_key
    }) else {
        return auth::api_error(
            StatusCode::FORBIDDEN,
            "The sign-in identity for this transfer code is no longer linked.",
        );
    };
    let strict_age_ok = provider_id.supports_strict_age_verification()
        && mi.assurance_level == AssuranceLevel::Verified18
        && mi.assurance_expires_at.is_none_or(|e| e > now);
    let assurance_level = if strict_age_ok {
        AssuranceLevel::Verified18
    } else if mi.assurance_level == AssuranceLevel::Verified18 {
        AssuranceLevel::None
    } else {
        mi.assurance_level
    };

    // Enforce `AgeVerificationPolicy` uniformly on transfer claim (H7)!
    if let Err(msg) =
        identity::check_login_provider_eligibility(&policy, provider_id, Some(assurance_level))
    {
        return auth::api_error(StatusCode::FORBIDDEN, msg);
    }

    if let Err(r) = identity::issue_v2_session(
        &st,
        &cookies,
        &account,
        &env.auth_method,
        &env.identity_key,
        assurance_level,
        strict_age_ok,
    )
    .await
    {
        return r;
    }

    Json(crate::types::VerifyResp {
        address: env.display_address,
    })
    .into_response()
}

#[worker::send]
pub async fn transfer_revoke(
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
    let session_info = if let Some(sid) = active.sid.as_deref() {
        do_client::do_session_info(&st.env, &active.do_key, sid)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let (auth_method, identity_key) = match session_info {
        Some(info) => (info.auth_method, info.identity_key),
        None => {
            let p = if session::is_eth_address(&active.user_id) {
                "siwe"
            } else {
                "siws"
            };
            (p.to_string(), format!("{p}|legacy|{}", active.user_id))
        }
    };
    let envelope = StoredPrincipalEnvelope {
        user_id: active.user_id.clone(),
        auth_method,
        identity_key,
        display_address: auth::display_address(&active.user_id),
    };
    let _ = call_handoff_do(
        &st,
        "/transfer-revoke",
        &DoTransferRevokeReq {
            principal: encode_envelope(&envelope),
        },
    )
    .await;
    // Also clean any legacy raw-principal entry.
    let _ = call_handoff_do(
        &st,
        "/transfer-revoke",
        &DoTransferRevokeReq {
            principal: active.user_id,
        },
    )
    .await;
    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_code_alphabet_has_32_unique_unambiguous_chars() {
        let mut seen = std::collections::HashSet::new();
        for &b in SHORT_CODE_ALPH {
            assert!(seen.insert(b), "duplicate char in alphabet: {}", b as char);
            assert!(!matches!(b, b'0' | b'O' | b'1' | b'I'));
        }
        assert_eq!(seen.len(), 32);
    }

    #[test]
    fn normalize_short_code_accepts_flexible_formatting_and_rejects_bad_input() {
        assert_eq!(
            normalize_short_code("k7m9-p4qx").as_deref(),
            Some("K7M9P4QX")
        );
        assert_eq!(
            normalize_short_code("  k7m9 p4qx ").as_deref(),
            Some("K7M9P4QX")
        );
        assert_eq!(normalize_short_code("0000-0000"), None);
        assert_eq!(normalize_short_code("IIII-OOOO"), None);
        assert_eq!(normalize_short_code("K7M9-P4Q"), None);
        assert_eq!(normalize_short_code("K7M9-P4QXZ"), None);
    }

    #[test]
    fn ct_eq_checks_length_and_bytes() {
        assert!(ct_eq(b"abcdef", b"abcdef"));
        assert!(!ct_eq(b"abcdef", b"abcdeg"));
        assert!(!ct_eq(b"abcdef", b"abcde"));
    }

    #[test]
    fn generated_codes_have_valid_format() {
        let code = generate_short_code().expect("rng");
        assert_eq!(code.len(), 9);
        assert_eq!(code.as_bytes()[4], b'-');
        assert!(normalize_short_code(&code).is_some());

        let v = generate_verify_code().expect("rng");
        assert_eq!(v.len(), 4);
        assert!(v.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn ipv6_addresses_normalize_to_64_prefix() {
        assert_eq!(normalize_ip("203.0.113.42"), "203.0.113.42");
        assert_eq!(
            normalize_ip("2001:db8:abcd:12::1"),
            normalize_ip("2001:db8:abcd:12:ffff::99")
        );
        assert_ne!(
            normalize_ip("2001:db8:abcd:12::1"),
            normalize_ip("2001:db8:abcd:13::1")
        );
    }

    #[test]
    fn handoff_challenges_bind_session_and_code() {
        let s = handoff_siwe_statement("sess123", "7429");
        assert!(s.contains("7429") && s.contains("sess123"));
        assert!(valid_handoff_siwe_uri(
            "https://lets-embed.louisfly.icu/user/login/approve",
            "lets-embed.louisfly.icu"
        ));
        assert!(!valid_handoff_siwe_uri(
            "https://lets-embed.louisfly.icu/user/login",
            "lets-embed.louisfly.icu"
        ));
        let sol = handoff_siws_challenge("example.com", "sess123", "7429", "nonce99");
        assert_ne!(sol, auth::siws_challenge("example.com", "nonce99"));
        assert!(sol.contains("Session: sess123"));
        assert!(sol.contains("Code: 7429"));
    }
}
