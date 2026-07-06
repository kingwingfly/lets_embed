//! UNIT 5: link/unlink a Solana wallet to the (ETH) session.
//!
//! A Solana top-up tx has no on-chain link to the SIWE (Ethereum) session, so
//! the user proves control of a Solana wallet once by signing a challenge; the
//! linked address is then required to originate their SOL/SPL top-ups.
//!
//! - POST   /user/api/link_solana  LinkSolReq -> 200 LinkSolResp | 400 | 401 | 409
//! - DELETE /user/api/link_solana             -> 200 (idempotent)
//!
//! SCAFFOLD STATE: the challenge format is implemented (shared with the account
//! page JS); ed25519 verification + D1 writes are stubs — UNIT 5 fills them in.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::types::{ApiError, LinkSolReq, LinkSolResp, LinkStatusResp};
use crate::{AppState, session};

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

/// Pure ed25519 verification of the link challenge. `solana_address_b58` is the
/// base58 32-byte ed25519 public key; `signature_b58` is the base58 64-byte
/// signature. Any decode / length / verify failure yields `false`.
fn verify_link_sig(solana_address_b58: &str, signature_b58: &str, message: &str) -> bool {
    let Ok(pk_bytes) = bs58::decode(solana_address_b58).into_vec() else {
        return false;
    };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_bytes) = bs58::decode(signature_b58).into_vec() else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(message.as_bytes(), &sig).is_ok()
}

#[worker::send]
pub async fn link(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(req): Json<LinkSolReq>,
) -> Response {
    // 1) Session (lowercase 0x eth address).
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };

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

    // 4) Verify the ed25519 signature.
    if !verify_link_sig(&req.solana_address, &req.signature, &msg) {
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

/// Report the Solana wallet currently linked to the session (or `null`), so the
/// account page can show the linked state and gate SOL/SPL top-ups.
#[worker::send]
pub async fn link_status(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };

    #[derive(Deserialize)]
    struct Row {
        solana_address: Option<String>,
    }
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };
    let row = db
        .prepare("SELECT solana_address FROM users WHERE address = ?")
        .bind(&[addr.as_str().into()]);
    let solana_address = match row {
        Ok(stmt) => match stmt.first::<Row>(None).await {
            Ok(r) => r.and_then(|r| r.solana_address),
            Err(e) => {
                worker::console_error!("solana_address status lookup failed: {e:?}");
                return internal_error();
            }
        },
        Err(e) => {
            worker::console_error!("solana_address status bind failed: {e:?}");
            return internal_error();
        }
    };

    Json(LinkStatusResp { solana_address }).into_response()
}

#[worker::send]
pub async fn unlink(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_err(StatusCode::UNAUTHORIZED, "login required");
    };

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
        assert!(verify_link_sig(&pk, &sig, &msg));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let (pk, sig, msg) = fixture();
        let tampered = format!("{msg} ");
        assert!(!verify_link_sig(&pk, &sig, &tampered));
    }

    #[test]
    fn verify_rejects_flipped_signature_byte() {
        let (pk, sig, msg) = fixture();
        let mut sig_bytes = bs58::decode(&sig).into_vec().unwrap();
        sig_bytes[0] ^= 0x01;
        let bad_sig = bs58::encode(&sig_bytes).into_string();
        assert!(!verify_link_sig(&pk, &bad_sig, &msg));
    }

    #[test]
    fn verify_rejects_garbage_base58() {
        let (pk, sig, msg) = fixture();
        // Non-base58 alphabet (contains '0', 'O', 'I', 'l') / wrong lengths.
        assert!(!verify_link_sig("0OIl", &sig, &msg));
        assert!(!verify_link_sig(&pk, "0OIl", &msg));
        // Valid base58 but wrong length (not 32 / 64 bytes).
        let short = bs58::encode([0u8; 4]).into_string();
        assert!(!verify_link_sig(&short, &sig, &msg));
        assert!(!verify_link_sig(&pk, &short, &msg));
    }
}
