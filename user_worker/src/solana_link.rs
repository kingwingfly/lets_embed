//! Link/unlink a Solana payment wallet (`purpose = 'payment'`) to any account,
//! using atomic single-use `AuthChallengeDO` nonces and `user_identities`.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::{
    AppState, auth, challenge_do, identity, session,
    types::{ApiError, LinkSolReq, LinkSolResp, LinkStatusResp},
};

const OFFCHAIN_SIGNING_DOMAIN: &[u8] = b"\xffsolana offchain";

/// Purpose-bound Solana wallet linking challenge binding target account, link purpose
/// (`"payment"` or `"login"`), and single-use nonce (F7).
pub fn challenge_message_for_purpose(account_id: &str, purpose: &str, nonce: &str) -> String {
    format!("Link Solana wallet for {purpose} to {account_id}\nNonce: {nonce}")
}

/// Convenience helper for Solana payment-wallet linking challenge.
pub fn challenge_message(account_id: &str, nonce: &str) -> String {
    challenge_message_for_purpose(account_id, "payment", nonce)
}

fn api_err(code: StatusCode, msg: &str) -> Response {
    (code, Json(ApiError { error: msg.into() })).into_response()
}

fn internal_error() -> Response {
    api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

fn matches_challenge_bytes(bytes: &[u8], expected: &[u8], signer_pk: &[u8; 32]) -> bool {
    if bytes == expected {
        return true;
    }
    let Some(rest) = bytes.strip_prefix(OFFCHAIN_SIGNING_DOMAIN) else {
        return false;
    };
    let Some((&0u8, after_ver)) = rest.split_first() else {
        return false;
    };
    if after_ver.len() >= 3 && after_ver[0] <= 2 {
        let len = u16::from_le_bytes([after_ver[1], after_ver[2]]) as usize;
        if after_ver.len() == 3 + len && &after_ver[3..] == expected {
            return true;
        }
    }
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
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<LinkSolReq>,
) -> Response {
    if let Err(r) = auth::require_same_origin(&st, &headers) {
        return r;
    }
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if !session::is_sol_principal(&req.solana_address) {
        return api_err(StatusCode::BAD_REQUEST, "invalid Solana address");
    }

    // Atomic single-use nonce consumption in `AuthChallengeDO` scoped strictly to payment linking (F7)!
    match challenge_do::consume_nonce(&st.env, &req.nonce, auth::NONCE_PURPOSE_LINK_PAYMENT).await {
        Ok(true) => {}
        Ok(false) => return api_err(StatusCode::BAD_REQUEST, "unknown or expired nonce"),
        Err(e) => {
            worker::console_error!("solana_link nonce consume failed: {e:?}");
            return internal_error();
        }
    }

    let msg = challenge_message_for_purpose(&active.user_id, "payment", &req.nonce);
    if !verify_ed25519_challenge(
        &req.solana_address,
        &req.signature,
        &msg,
        req.signed_message.as_deref(),
    ) {
        return api_err(StatusCode::BAD_REQUEST, "signature verification failed");
    }

    // Atomically replace any previous `purpose = 'payment'` Solana wallet owned by THIS user
    // inside ONE D1 `batch` transaction so a UNIQUE conflict (replacement already linked
    // elsewhere) rolls back cleanly and preserves the working original wallet (F15)!
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(_) => return internal_error(),
    };

    // Idempotent check: if this user ALREADY owns this exact Solana payment wallet, succeed directly.
    #[derive(Deserialize)]
    struct ExistingRow {
        user_id: String,
        purpose: String,
    }
    let existing = match db
        .prepare(
            "SELECT user_id, purpose FROM user_identities \
             WHERE provider_id = 'siws' AND issuer = 'solana:mainnet' AND subject = ?1",
        )
        .bind(&[req.solana_address.as_str().into()])
        .map_err(|_| internal_error())
    {
        Ok(stmt) => match stmt.first::<ExistingRow>(None).await {
            Ok(row) => row,
            Err(e) => {
                worker::console_error!("solana_link lookup failed: {e:?}");
                return internal_error();
            }
        },
        Err(r) => return r,
    };

    if let Some(ex) = existing {
        if ex.user_id == active.user_id && ex.purpose == "payment" {
            // Already linked as this user's payment wallet — no-op success.
        } else {
            return api_err(
                StatusCode::CONFLICT,
                "this identity or wallet is already linked to an account",
            );
        }
    } else {
        let now = session::now_secs();
        let del_stmt = match db
            .prepare(
                "DELETE FROM user_identities \
                 WHERE user_id = ?1 AND provider_id = 'siws' AND purpose = 'payment' AND subject != ?2",
            )
            .bind(&[
                active.user_id.as_str().into(),
                req.solana_address.as_str().into(),
            ]) {
            Ok(s) => s,
            Err(_) => return internal_error(),
        };
        let ins_stmt = match db
            .prepare(
                "INSERT INTO user_identities \
                 (provider_id, issuer, subject, user_id, purpose, label, verified_email, \
                  assurance_level, assurance_method, assurance_verified_at, assurance_expires_at, created_at) \
                 VALUES ('siws', 'solana:mainnet', ?1, ?2, 'payment', 'Linked Solana payment wallet', \
                         NULL, 'none', NULL, NULL, NULL, ?3)",
            )
            .bind(&[
                req.solana_address.as_str().into(),
                active.user_id.as_str().into(),
                (now as f64).into(),
            ]) {
            Ok(s) => s,
            Err(_) => return internal_error(),
        };
        if let Err(e) = db.batch(vec![del_stmt, ins_stmt]).await {
            let msg = format!("{e:?}").to_lowercase();
            if msg.contains("constraint") || msg.contains("unique") {
                return api_err(
                    StatusCode::CONFLICT,
                    "this identity or wallet is already linked to an account",
                );
            }
            worker::console_error!("solana_link atomic replace batch failed: {e:?}");
            return internal_error();
        }
    }

    // Keep legacy `users.solana_address` synced if this is a migrated ETH user.
    if session::is_eth_address(&active.user_id)
        && let Ok(stmt) = db
            .prepare("UPDATE users SET solana_address = ?1 WHERE address = ?2")
            .bind(&[
                req.solana_address.as_str().into(),
                active.user_id.as_str().into(),
            ])
    {
        let _ = stmt.run().await;
    }

    Json(LinkSolResp {
        solana_address: req.solana_address,
    })
    .into_response()
}

pub(crate) async fn linked_address(
    env: &worker::Env,
    user_id: &str,
) -> worker::Result<Option<String>> {
    #[derive(Deserialize)]
    struct Row {
        solana_address: Option<String>,
    }
    let row = env
        .d1(crate::D1_BINDING)?
        .prepare("SELECT solana_address FROM users WHERE address = ?")
        .bind(&[user_id.into()])?
        .first::<Row>(None)
        .await?;
    Ok(row.and_then(|r| r.solana_address))
}

#[worker::send]
pub async fn link_status(State(st): State<AppState>, cookies: Cookies) -> Response {
    let active = match identity::require_active_session(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match identity::linked_solana_wallet(&st, &active.user_id).await {
        Ok(solana_address) => Json(LinkStatusResp { solana_address }).into_response(),
        Err(e) => {
            worker::console_error!("solana_address status lookup failed: {e:?}");
            internal_error()
        }
    }
}

#[worker::send]
pub async fn unlink(
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
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(_) => return internal_error(),
    };
    if let Ok(stmt) = db
        .prepare(
            "DELETE FROM user_identities WHERE user_id = ?1 AND provider_id = 'siws' AND purpose = 'payment'",
        )
        .bind(&[active.user_id.as_str().into()])
    {
        let _ = stmt.run().await;
    }
    if session::is_eth_address(&active.user_id)
        && let Ok(stmt) = db
            .prepare("UPDATE users SET solana_address = NULL WHERE address = ?1")
            .bind(&[active.user_id.as_str().into()])
    {
        let _ = stmt.run().await;
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
        assert_eq!(m, "Link Solana wallet for payment to 0xabc\nNonce: n1");
        assert_ne!(
            challenge_message_for_purpose("0xabc", "payment", "n1"),
            challenge_message_for_purpose("0xabc", "login", "n1")
        );
    }

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
        assert!(!verify_ed25519_b58("0OIl", &sig, &msg));
        assert!(!verify_ed25519_b58(&pk, "0OIl", &msg));
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

        let mut env_a = Vec::new();
        env_a.extend_from_slice(OFFCHAIN_SIGNING_DOMAIN);
        env_a.push(0);
        env_a.push(0);
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

        let mut env_b = Vec::new();
        env_b.extend_from_slice(OFFCHAIN_SIGNING_DOMAIN);
        env_b.push(0);
        env_b.extend_from_slice(&[0xab; 32]);
        env_b.push(1);
        env_b.push(1);
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
