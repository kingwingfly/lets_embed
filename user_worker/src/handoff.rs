//! Cross-device QR / one-time-code sign-in and mobile wallet-app handoff.
//!
//! Two complementary flows backed by a strongly-consistent singleton SQLite
//! Durable Object (`__auth_handoff__` inside `USER_ACCOUNT`):
//!
//! 1. **Wallet app handoff** (`start` -> `approve_eth`/`approve_sol` -> `poll`):
//!    A mobile browser without an injected wallet starts a 5-minute handoff
//!    session and deep-links to `/user/login/approve?s=<session_id>` inside
//!    MetaMask / Phantom (or shows a QR code). Once the wallet signs SIWE/SIWS,
//!    the original browser's next poll receives `ue_session` so the user never
//!    has to browse inside the wallet's slow in-app browser.
//! 2. **Signed-in device transfer** (`transfer_create` -> `transfer_claim`):
//!    A user already signed in on desktop generates a single-use 3-minute QR
//!    token + 8-char one-time code (`XXXX-XXXX`, 40 bits + per-IP lockout) on
//!    `/user/account` to sign in on their phone's native browser.

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_cookies::Cookies;
use worker::{Method, Request, RequestInit, wasm_bindgen::JsValue};

use crate::{
    AppState, auth, do_client,
    qr::{self, QrMatrix},
    session,
    types::{SiwsReq, VerifyReq},
};

const HANDOFF_DO_ID: &str = "__auth_handoff__";
const HANDOFF_TTL_SECS: u64 = 300; // 5 minutes
const TRANSFER_TTL_SECS: u64 = 180; // 3 minutes

/// 32-character uppercase alphabet omitting ambiguous `0`, `O`, `1`, `I`
/// (24 letters + 8 digits = exact power of two for unbiased 5-bit indexing).
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
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffInfoReq {
    pub session_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffInfoResp {
    pub status: String,
    pub verify_code: String,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffApproveReq {
    pub session_id: String,
    pub principal: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DoHandoffPollReq {
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
// Pure helpers (host-testable)
// ---------------------------------------------------------------------------

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

/// Normalize a user-entered 8-character one-time code: strips spaces/hyphens,
/// uppercases, and verifies every character belongs to `SHORT_CODE_ALPH`.
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

fn ip_rate_key(headers: &HeaderMap, secret: &[u8]) -> String {
    let ip = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown");
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(b":handoff-ip:");
    hasher.update(ip.as_bytes());
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

// ---------------------------------------------------------------------------
// Wallet app handoff handlers
// ---------------------------------------------------------------------------

#[worker::send]
pub async fn start(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let session_id = match random_b64url(16) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let poll_secret = match random_b64url(32) {
        Ok(s) => s,
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
    let approve_url = format!(
        "https://{}/user/login/approve?s={session_id}",
        st.siwe_domain
    );
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
pub async fn info(State(st): State<AppState>, Query(q): Query<HandoffInfoQuery>) -> Response {
    if !valid_id_token(&q.s) {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid session id");
    }
    let req = DoHandoffInfoReq { session_id: q.s };
    match call_handoff_do(&st, "/handoff-info", &req).await {
        Ok((200, text)) => match serde_json::from_str::<DoHandoffInfoResp>(&text) {
            Ok(info) => {
                let now = session::now_secs();
                Json(HandoffInfoResp {
                    status: info.status,
                    verify_code: info.verify_code,
                    expires_in: info.expires_at.saturating_sub(now),
                })
                .into_response()
            }
            Err(_) => auth::internal_error(),
        },
        Ok((410, msg)) => auth::api_error(StatusCode::GONE, msg),
        Ok((code, msg)) => {
            worker::console_error!("handoff-info DO error {code}: {msg}");
            auth::internal_error()
        }
        Err(r) => r,
    }
}

#[worker::send]
pub async fn approve_eth(
    State(st): State<AppState>,
    Json(req): Json<HandoffApproveEthReq>,
) -> Response {
    if !valid_id_token(&req.session_id) {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid session id");
    }
    let addr = match auth::verify_siwe_and_ensure_user(
        &st,
        &VerifyReq {
            message: req.message,
            signature: req.signature,
        },
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let do_req = DoHandoffApproveReq {
        session_id: req.session_id,
        principal: addr.clone(),
    };
    match call_handoff_do(&st, "/handoff-approve", &do_req).await {
        Ok((200, _)) => Json(crate::types::VerifyResp {
            address: auth::display_address(&addr),
        })
        .into_response(),
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
    Json(req): Json<HandoffApproveSolReq>,
) -> Response {
    if !valid_id_token(&req.session_id) {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid session id");
    }
    let addr = match auth::verify_siws_and_ensure_user(
        &st,
        &SiwsReq {
            solana_address: req.solana_address,
            signature: req.signature,
            nonce: req.nonce,
            signed_message: req.signed_message,
        },
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let do_req = DoHandoffApproveReq {
        session_id: req.session_id,
        principal: addr.clone(),
    };
    match call_handoff_do(&st, "/handoff-approve", &do_req).await {
        Ok((200, _)) => Json(crate::types::VerifyResp { address: addr }).into_response(),
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
    cookies: Cookies,
    Json(req): Json<HandoffPollReq>,
) -> Response {
    if !valid_id_token(&req.session_id) || !valid_id_token(&req.poll_secret) {
        return auth::api_error(StatusCode::BAD_REQUEST, "invalid session parameters");
    }
    let do_req = DoHandoffPollReq {
        session_id: req.session_id,
        poll_secret_hash: sha256_hex(&req.poll_secret),
    };
    let parsed = match call_handoff_do(&st, "/handoff-poll", &do_req).await {
        Ok((200, text)) => match serde_json::from_str::<DoHandoffPollResp>(&text) {
            Ok(p) => p,
            Err(_) => return auth::internal_error(),
        },
        Ok((401, msg)) => return auth::api_error(StatusCode::UNAUTHORIZED, msg),
        Ok((410, msg)) => return auth::api_error(StatusCode::GONE, msg),
        Ok((code, msg)) => {
            worker::console_error!("handoff-poll DO error {code}: {msg}");
            return auth::internal_error();
        }
        Err(r) => return r,
    };
    if parsed.status == "approved"
        && let Some(principal) = parsed.principal
    {
        if let Err(r) = auth::ensure_not_banned(&st, &principal).await {
            return r;
        }
        let resp = auth::issue_session(&st, &cookies, &principal);
        return Json(HandoffPollResp {
            status: "approved".to_string(),
            address: Some(resp.address),
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
pub async fn transfer_create(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(principal) = session::session_address(&cookies, &st.jwt_secret) else {
        return auth::api_error(StatusCode::UNAUTHORIZED, "not signed in");
    };
    if let Err(r) = auth::ensure_not_banned(&st, &principal).await {
        return r;
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
    let do_req = DoTransferCreateReq {
        principal,
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
    let login_url = format!("https://{}/user/login?transfer={qr_token}", st.siwe_domain);
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
    let ip_key = ip_rate_key(&headers, &st.jwt_secret);
    let (code_hash, token_hash) = if let Some(raw_token) = req.token.as_deref() {
        let trimmed = raw_token.trim();
        if !valid_id_token(trimmed) {
            return auth::api_error(StatusCode::BAD_REQUEST, "invalid QR login token");
        }
        (None, Some(sha256_hex(&format!("tok:{trimmed}"))))
    } else if let Some(raw_code) = req.code.as_deref() {
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

    if !session::is_valid_principal(&claimed.principal) {
        return auth::internal_error();
    }
    if let Err(r) = auth::ensure_not_banned(&st, &claimed.principal).await {
        return r;
    }
    let now = session::now_secs();
    if let Err(r) = auth::touch_user_login(&st, &claimed.principal, now).await {
        return r;
    }
    if let Err(e) = do_client::do_init(&st.env, &claimed.principal).await {
        worker::console_error!("do init failed on transfer claim: {e:?}");
        return auth::internal_error();
    }
    Json(auth::issue_session(&st, &cookies, &claimed.principal)).into_response()
}

#[worker::send]
pub async fn transfer_revoke(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(principal) = session::session_address(&cookies, &st.jwt_secret) else {
        return auth::api_error(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let do_req = DoTransferRevokeReq { principal };
    match call_handoff_do(&st, "/transfer-revoke", &do_req).await {
        Ok((200, _)) => StatusCode::OK.into_response(),
        Ok((code, msg)) => {
            worker::console_error!("transfer-revoke DO error {code}: {msg}");
            auth::internal_error()
        }
        Err(r) => r,
    }
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
        // Ambiguous or non-alphabet chars rejected.
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
}
