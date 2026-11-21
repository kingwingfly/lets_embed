//! Link/unlink a Solana wallet to an Ethereum (SIWE) session.
//!
//! A Solana top-up tx has no on-chain link to a SIWE (Ethereum) session, so
//! the user proves control of a Solana wallet once by signing a challenge; the
//! linked address is then required to originate their SOL/SPL top-ups.
//!
//! - GET    /user/api/link_solana             -> 200 LinkStatusResp | 401
//! - POST   /user/api/link_solana  LinkSolReq -> 200 LinkSolResp | 400 | 401 | 409
//! - DELETE /user/api/link_solana             -> 200 (idempotent) | 400 | 401

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::types::{ApiError, LinkSolReq, LinkSolResp, LinkStatusResp};
use crate::{AppState, session};

const OFFCHAIN_SIGNING_DOMAIN: &[u8] = b"\xffsolana offchain";

/// The exact message the wallet signs. MUST match the account-page JS byte for
/// byte. `eth_addr` is the lowercase session address; `nonce` is single-use.
pub fn challenge_message(eth_addr: &str, nonce: &str) -> String {
    format!("Link Solana wallet to {eth_addr}\nNonce: {nonce}")
}

fn api_err(code: StatusCode, msg: &str) -> Response {
    (code, Json(ApiError { error: msg.into() })).into_response()
}

fn internal_error() -> Response {
    api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

/// Check whether `bytes` is either the raw `expected` challenge or a recognized
/// Solana Off-Chain Message v0 envelope whose payload equals `expected` exactly.
fn matches_challenge_bytes(bytes: &[u8], expected: &[u8], signer_pk: &[u8; 32]) -> bool {
    if bytes == expected {
        return true;
    }
    let Some(rest) = bytes.strip_prefix(OFFCHAIN_SIGNING_DOMAIN) else {
        return false;
    };
    // Must be version 0.
    let Some((&0u8, after_ver)) = rest.split_first() else {
        return false;
    };
    // Variant A (solana-offchain-message / Ledger v0):
    // [format: u8 (0..=2)][len: u16 le][payload]
    if after_ver.len() >= 3 && after_ver[0] <= 2 {
        let len = u16::from_le_bytes([after_ver[1], after_ver[2]]) as usize;
        if after_ver.len() == 3 + len && &after_ver[3..] == expected {
            return true;
        }
    }
    // Variant B (RFC v0 with 32-byte application domain + explicit signer list):
    // [app_domain: 32][format: u8 (0..=2)][signer_count: u8 >= 1][signers: 32*n][len: u16 le][payload]
    if after_ver.len() >= 34 && after_ver[32] <= 2 {
        let count = usize::from(after_ver[33]);
        let header_end = 34usize.saturating_add(count.saturating_mul(32));
        if count >= 1 && after_ver.len() >= header_end + 2 {
            let signers = &after_ver[34..header_end];
            let has_signer = signers.as_chunks::<32>().0.iter().any(|pk| pk == signer_pk);
            let len =
                u16::from_le_bytes([after_ver[header_end], after_ver[header_end + 1]]) as usize;
            if has_signer
                && after_ver.len() == header_end + 2 + len
                && &after_ver[header_end + 2..] == expected
            {
                return true;
            }
        }
    }
    false
}

/// Pure ed25519 verification of a signed challenge. `solana_address_b58` is the
/// base58 32-byte ed25519 public key; `signature_b58` is the base58 64-byte
/// signature. When `signed_message_b64` is supplied by a Wallet Standard wallet,
/// verifies that it is the exact challenge or a recognized Solana off-chain
/// message envelope wrapping that exact challenge.
pub(crate) fn verify_ed25519_challenge(
    solana_address_b58: &str,
    signature_b58: &str,
    expected_message: &str,
    signed_message_b64: Option<&str>,
) -> bool {
    if !(32..=44).contains(&solana_address_b58.len()) || !(64..=88).contains(&signature_b58.len()) {
        return false;
    }
    let mut pk_arr = [0u8; 32];
    if !matches!(bs58::decode(solana_address_b58).onto(&mut pk_arr), Ok(32)) {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let mut sig_arr = [0u8; 64];
    if !matches!(bs58::decode(signature_b58).onto(&mut sig_arr), Ok(64)) {
        return false;
    }
    let sig = Signature::from_bytes(&sig_arr);
    match signed_message_b64 {
        None => vk.verify_strict(expected_message.as_bytes(), &sig).is_ok(),
        Some(b64) => {
            if b64.len() > 8192 {
                return false;
            }
            let Ok(signed_bytes) = B64.decode(b64) else {
                return false;
            };
            matches_challenge_bytes(&signed_bytes, expected_message.as_bytes(), &pk_arr)
                && vk.verify_strict(&signed_bytes, &sig).is_ok()
        }
    }
}

/// Convenience wrapper for raw-message ed25519 verification (kept for tests).
#[cfg(test)]
pub(crate) fn verify_ed25519_b58(
    solana_address_b58: &str,
    signature_b58: &str,
    message: &str,
) -> bool {
    verify_ed25519_challenge(solana_address_b58, signature_b58, message, None)
}

#[worker::send]
pub async fn link(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(req): Json<LinkSolReq>,
) -> Response {
    // 1) Session must be an Ethereum (SIWE) account; standalone Solana accounts
    // already pay directly from their sign-in wallet.
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };
    if !session::is_eth_address(&addr) {
        return api_err(
            StatusCode::BAD_REQUEST,
            "Solana accounts already pay from their sign-in wallet.",
        );
    }

    // 2) Single-use nonce: must exist in KV, then delete it.
    let kv = match st.env.kv(crate::NONCE_BINDING) {
        Ok(kv) => kv,
        Err(e) => {
            worker::console_error!("kv binding failed: {e:?}");
            return internal_error();
        }
    };
    let nonce_key = format!("nonce:{}", req.nonce);
    match kv.get(&nonce_key).text().await {
        Ok(Some(_)) => {}
        Ok(None) => return api_err(StatusCode::BAD_REQUEST, "unknown or expired nonce"),
        Err(e) => {
            worker::console_error!("nonce get failed: {e:?}");
            return internal_error();
        }
    }
    if let Err(e) = kv.delete(&nonce_key).await {
        worker::console_error!("nonce delete failed: {e:?}");
        return internal_error();
    }

    // 3) Rebuild the challenge the wallet was asked to sign.
    let msg = challenge_message(&addr, &req.nonce);

    // 4) Verify the ed25519 signature (supporting optional Wallet Standard envelope).
    if !verify_ed25519_challenge(
        &req.solana_address,
        &req.signature,
        &msg,
        req.signed_message.as_deref(),
    ) {
        return api_err(StatusCode::BAD_REQUEST, "signature verification failed");
    }

    // 5) Uniqueness: `solana_address` is UNIQUE. Reject if already linked to a
    // different account; otherwise link it to this session's account.
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };

    #[derive(Deserialize)]
    struct OwnerRow {
        address: String,
    }

    // Coexistence rule: a Solana address is EITHER a standalone SIWS account OR a
    // linked wallet, never both. If it's already a standalone account, refuse.
    let standalone = match db
        .prepare("SELECT address FROM users WHERE address = ?")
        .bind(&[req.solana_address.as_str().into()])
    {
        Ok(stmt) => match stmt.first::<OwnerRow>(None).await {
            Ok(row) => row.is_some(),
            Err(e) => {
                worker::console_error!("standalone lookup failed: {e:?}");
                return internal_error();
            }
        },
        Err(e) => {
            worker::console_error!("standalone lookup bind failed: {e:?}");
            return internal_error();
        }
    };
    if standalone {
        return api_err(
            StatusCode::CONFLICT,
            "this wallet already has its own account — log in with it directly instead of linking",
        );
    }
    let existing = match db
        .prepare("SELECT address FROM users WHERE solana_address = ?")
        .bind(&[req.solana_address.as_str().into()])
    {
        Ok(stmt) => match stmt.first::<OwnerRow>(None).await {
            Ok(row) => row,
            Err(e) => {
                worker::console_error!("solana_address lookup failed: {e:?}");
                return internal_error();
            }
        },
        Err(e) => {
            worker::console_error!("solana_address lookup bind failed: {e:?}");
            return internal_error();
        }
    };
    if let Some(owner) = existing
        && owner.address != addr
    {
        return api_err(
            StatusCode::CONFLICT,
            "wallet already linked to another account",
        );
    }

    let update = db
        .prepare("UPDATE users SET solana_address = ? WHERE address = ?")
        .bind(&[req.solana_address.as_str().into(), addr.as_str().into()]);
    match update {
        Ok(stmt) => {
            if let Err(e) = stmt.run().await {
                if format!("{e:?}").to_lowercase().contains("constraint") {
                    return api_err(
                        StatusCode::CONFLICT,
                        "wallet already linked to another account",
                    );
                }
                worker::console_error!("solana_address update failed: {e:?}");
                return internal_error();
            }
        }
        Err(e) => {
            worker::console_error!("solana_address update bind failed: {e:?}");
            return internal_error();
        }
    }

    Json(LinkSolResp {
        solana_address: req.solana_address,
    })
    .into_response()
}

pub(crate) async fn linked_address(
    env: &worker::Env,
    addr: &str,
) -> worker::Result<Option<String>> {
    #[derive(Deserialize)]
    struct Row {
        solana_address: Option<String>,
    }
    let row = env
        .d1(crate::D1_BINDING)?
        .prepare("SELECT solana_address FROM users WHERE address = ?")
        .bind(&[addr.into()])?
        .first::<Row>(None)
        .await?;
    Ok(row.and_then(|r| r.solana_address))
}

/// Report the Solana wallet explicitly linked to the session, if any.
#[worker::send]
pub async fn link_status(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };

    match linked_address(&st.env, &addr).await {
        Ok(solana_address) => Json(LinkStatusResp { solana_address }).into_response(),
        Err(e) => {
            worker::console_error!("solana_address status lookup failed: {e:?}");
            internal_error()
        }
    }
}

#[worker::send]
pub async fn unlink(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };
    if !session::is_eth_address(&addr) {
        return api_err(
            StatusCode::BAD_REQUEST,
            "Solana accounts already pay from their sign-in wallet.",
        );
    }

    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };
    let update = db
        .prepare("UPDATE users SET solana_address = NULL WHERE address = ?")
        .bind(&[addr.as_str().into()]);
    match update {
        Ok(stmt) => {
            if let Err(e) = stmt.run().await {
                worker::console_error!("solana_address clear failed: {e:?}");
                return internal_error();
            }
        }
        Err(e) => {
            worker::console_error!("solana_address clear bind failed: {e:?}");
            return internal_error();
        }
    }

    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn challenge_is_deterministic() {
        let m = challenge_message("0xabc", "n1");
        assert_eq!(m, "Link Solana wallet to 0xabc\nNonce: n1");
    }

    /// Build a deterministic (pubkey_b58, sig_b58, msg) vector from a fixed seed.
    fn fixture() -> (String, String, String) {
        let seed: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let msg = challenge_message("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", "nonce-xyz");
        let sig: Signature = sk.sign(msg.as_bytes());
        (
            bs58::encode(vk.to_bytes()).into_string(),
            bs58::encode(sig.to_bytes()).into_string(),
            msg,
        )
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let (pk, sig, msg) = fixture();
        assert!(verify_ed25519_b58(&pk, &sig, &msg));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let (pk, sig, msg) = fixture();
        let tampered = format!("{msg} ");
        assert!(!verify_ed25519_b58(&pk, &sig, &tampered));
    }

    #[test]
    fn verify_rejects_flipped_signature_byte() {
        let (pk, sig, msg) = fixture();
        let mut sig_bytes = bs58::decode(&sig).into_vec().unwrap();
        sig_bytes[0] ^= 0x01;
        let bad_sig = bs58::encode(&sig_bytes).into_string();
        assert!(!verify_ed25519_b58(&pk, &bad_sig, &msg));
    }

    #[test]
    fn verify_rejects_garbage_base58() {
        let (pk, sig, msg) = fixture();
        // Non-base58 alphabet (contains '0', 'O', 'I', 'l') / wrong lengths.
        assert!(!verify_ed25519_b58("0OIl", &sig, &msg));
        assert!(!verify_ed25519_b58(&pk, "0OIl", &msg));
        // Valid base58 but wrong length (not 32 / 64 bytes).
        let short = bs58::encode([0u8; 4]).into_string();
        assert!(!verify_ed25519_b58(&short, &sig, &msg));
        assert!(!verify_ed25519_b58(&pk, &short, &msg));
    }

    #[test]
    fn verify_accepts_solana_offchain_message_envelopes() {
        let seed: [u8; 32] = [9u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk_bytes = sk.verifying_key().to_bytes();
        let pk = bs58::encode(pk_bytes).into_string();
        let msg = challenge_message("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", "nonce-env");

        // Variant A: solana-offchain-message / Ledger v0 header
        let mut env_a = Vec::new();
        env_a.extend_from_slice(OFFCHAIN_SIGNING_DOMAIN);
        env_a.push(0); // version 0
        env_a.push(0); // restricted ASCII
        env_a.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        env_a.extend_from_slice(msg.as_bytes());
        let sig_a = bs58::encode(sk.sign(&env_a).to_bytes()).into_string();
        assert!(verify_ed25519_challenge(
            &pk,
            &sig_a,
            &msg,
            Some(&B64.encode(&env_a))
        ));
        assert!(!verify_ed25519_challenge(
            &pk,
            &sig_a,
            "different challenge",
            Some(&B64.encode(&env_a))
        ));

        // Variant B: RFC v0 with application domain + signer list
        let mut env_b = Vec::new();
        env_b.extend_from_slice(OFFCHAIN_SIGNING_DOMAIN);
        env_b.push(0); // version 0
        env_b.extend_from_slice(&[0xab; 32]); // app domain
        env_b.push(1); // UTF-8
        env_b.push(1); // 1 signer
        env_b.extend_from_slice(&pk_bytes);
        env_b.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        env_b.extend_from_slice(msg.as_bytes());
        let sig_b = bs58::encode(sk.sign(&env_b).to_bytes()).into_string();
        assert!(verify_ed25519_challenge(
            &pk,
            &sig_b,
            &msg,
            Some(&B64.encode(&env_b))
        ));

        // Arbitrary prefix must be rejected even with a valid signature.
        let bad = format!("prefix:{msg}");
        let sig_bad = bs58::encode(sk.sign(bad.as_bytes()).to_bytes()).into_string();
        assert!(!verify_ed25519_challenge(
            &pk,
            &sig_bad,
            &msg,
            Some(&B64.encode(bad.as_bytes()))
        ));
    }
}
