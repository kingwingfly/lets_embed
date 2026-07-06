//! UNIT 4: Solana top-up verification (native SOL + SPL USDT/USDC).
//!
//! Boundary with `payments.rs` (UNIT 3): this module owns everything Solana —
//! the JSON-RPC call and the parse/verify — behind ONE side-effect-free entry
//! point, `topup_solana`. It touches neither D1 nor the DO; `payments.rs` runs
//! the payment-row lifecycle and crediting from the returned `SolOutcome`.
//!
//! `topup_solana` fetches the transaction via `getTransaction`
//! (encoding `jsonParsed`, commitment `finalized`) and delegates to the pure,
//! host-tested `verify_solana`:
//!  - null result -> TooEarly (not found / not finalized); meta.err -> Reject.
//!  - native SOL (spec.contract == None): credited = postBalances[i] -
//!    preBalances[i] for the deposit account in accountKeys; sender = fee payer
//!    accountKeys[0], must equal `linked_address` else WrongSender.
//!  - SPL (spec.contract == Some(mint)): meta.pre/postTokenBalances filtered by
//!    mint + owner == deposit_address, delta of uiTokenAmount.amount; sender =
//!    fee payer accountKeys[0] (the SPL owner signs as fee payer here), must
//!    equal `linked_address` else WrongSender.

use serde_json::Value;
use worker::{Fetch, Method, Request, RequestInit};

use crate::config::TokenSpec;

/// Result of verifying a Solana top-up. No side effects — `payments.rs` maps
/// each variant onto the payment-row lifecycle (mirrors the Ethereum path):
/// `Credited` -> credit + mark row credited; `Reject` -> row 'rejected' (400,
/// permanent for any submitter); `WrongSender`/`TooEarly`/`RpcError` -> delete
/// the pending row so the tx can be resubmitted (403 / 425 / 502).
#[derive(Debug, PartialEq, Eq)]
pub enum SolOutcome {
    /// Verified: raw base units received (lamports for SOL, minor units for SPL).
    Credited { amount: u128 },
    /// Tx-intrinsic, permanent failure (wrong recipient, reverted, dust, ...).
    Reject(&'static str),
    /// Sender is not the linked wallet — submitter-relative.
    WrongSender,
    /// Not visible / not finalized yet — retry later.
    TooEarly,
    /// RPC transport/decoding failure — retry later.
    RpcError(String),
}

/// A base58 Solana tx signature decodes to 64 bytes.
pub fn valid_signature(sig: &str) -> bool {
    matches!(bs58::decode(sig).into_vec(), Ok(v) if v.len() == 64)
}

/// Fetch + verify a Solana top-up transaction. `deposit_address` and
/// `linked_address` are base58. Owns the JSON-RPC round-trip; the actual
/// verification is delegated to the pure `verify_solana`.
pub async fn topup_solana(
    sol_rpc_url: &str,
    spec: &TokenSpec,
    deposit_address: &str,
    linked_address: &str,
    signature: &str,
) -> SolOutcome {
    let result = match get_transaction(sol_rpc_url, signature).await {
        Ok(r) => r,
        Err(e) => return SolOutcome::RpcError(e.to_string()),
    };
    // `result == null` means the tx is unknown to the node or not finalized yet.
    if result.is_null() {
        return SolOutcome::TooEarly;
    }
    verify_solana(&result, spec, deposit_address, linked_address)
}

// ---------------------------------------------------------------------------
// JSON-RPC over worker::Fetch (no solana-sdk on wasm)
// ---------------------------------------------------------------------------

/// `getTransaction(signature, {encoding:"jsonParsed", commitment:"finalized",
/// maxSupportedTransactionVersion:0})`. Returns the `result` field (which may be
/// JSON `null`). A non-2xx HTTP response, a JSON-RPC-level `error`, or a decode
/// failure is turned into `Err`.
async fn get_transaction(url: &str, signature: &str) -> worker::Result<Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            {
                "encoding": "jsonParsed",
                "commitment": "finalized",
                "maxSupportedTransactionVersion": 0,
            },
        ],
    });
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.headers.set("content-type", "application/json")?;
    init.with_body(Some(body.to_string().into()));
    let req = Request::new_with_init(url, &init)?;
    let mut resp = Fetch::Request(req).send().await?;
    let code = resp.status_code();
    if !(200..300).contains(&code) {
        return Err(worker::Error::RustError(format!("getTransaction: http {code}")));
    }
    let v: Value = resp.json().await?;
    if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
        return Err(worker::Error::RustError(format!("getTransaction error: {e}")));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------
// Pure verifier (host-tested)
// ---------------------------------------------------------------------------

/// The pubkey of the `i`-th account key. jsonParsed renders each entry as an
/// object `{pubkey, signer, writable, source}`; legacy/base64 encodings render
/// it as a plain base58 string. Both are handled.
fn pubkey_at(keys: &[Value], i: usize) -> Option<&str> {
    match keys.get(i)? {
        Value::String(s) => Some(s.as_str()),
        other => other.get("pubkey").and_then(Value::as_str),
    }
}

/// Parse `entry.uiTokenAmount.amount` (a decimal string of base units).
fn token_amount(entry: &Value) -> Option<u128> {
    entry
        .get("uiTokenAmount")?
        .get("amount")?
        .as_str()?
        .parse::<u128>()
        .ok()
}

/// Verify a finalized (non-null) `getTransaction` result. Pure and side-effect
/// free. `deposit_address` / `linked_address` are base58.
fn verify_solana(
    result: &Value,
    spec: &TokenSpec,
    deposit_address: &str,
    linked_address: &str,
) -> SolOutcome {
    let meta = &result["meta"];

    // A non-null `meta.err` means the transaction failed on-chain: no transfer
    // took effect, permanent for any submitter.
    if let Some(err) = meta.get("err")
        && !err.is_null()
    {
        return SolOutcome::Reject("tx failed on-chain");
    }

    let Some(keys) = result["transaction"]["message"]["accountKeys"].as_array() else {
        return SolOutcome::RpcError("malformed transaction: missing accountKeys".into());
    };
    // Fee payer / sender is always the first account key.
    let Some(sender) = pubkey_at(keys, 0) else {
        return SolOutcome::RpcError("malformed transaction: missing fee payer".into());
    };
    // Both the native and SPL paths require the linked wallet to be the fee
    // payer: for SPL, the token-account owner signs as fee payer here.
    if sender != linked_address {
        return SolOutcome::WrongSender;
    }

    match spec.contract {
        // -------------------------------------------------------------- native
        None => {
            let Some(i) = (0..keys.len()).find(|&i| pubkey_at(keys, i) == Some(deposit_address))
            else {
                return SolOutcome::Reject("deposit address not in transaction");
            };
            let pre = meta["preBalances"].get(i).and_then(Value::as_u64);
            let post = meta["postBalances"].get(i).and_then(Value::as_u64);
            let (Some(pre), Some(post)) = (pre, post) else {
                return SolOutcome::RpcError("malformed transaction: missing balances".into());
            };
            let credited = post as i128 - pre as i128;
            if credited <= 0 {
                return SolOutcome::Reject("no SOL received");
            }
            SolOutcome::Credited { amount: credited as u128 }
        }
        // ----------------------------------------------------------------- SPL
        Some(mint) => {
            let empty: Vec<Value> = Vec::new();
            let post_balances = meta["postTokenBalances"].as_array().unwrap_or(&empty);
            let pre_balances = meta["preTokenBalances"].as_array().unwrap_or(&empty);

            // The deposit's token account for this mint, after the tx.
            let Some(post_entry) = post_balances.iter().find(|e| {
                e.get("mint").and_then(Value::as_str) == Some(mint)
                    && e.get("owner").and_then(Value::as_str) == Some(deposit_address)
            }) else {
                return SolOutcome::Reject("no token received");
            };
            let Some(post_amount) = token_amount(post_entry) else {
                return SolOutcome::RpcError("malformed transaction: bad token amount".into());
            };
            // The matching pre-balance shares the same accountIndex; a missing
            // pre entry means the token account started at zero.
            let acct_index = post_entry.get("accountIndex").and_then(Value::as_u64);
            let pre_amount = pre_balances
                .iter()
                .find(|e| {
                    acct_index.is_some()
                        && e.get("accountIndex").and_then(Value::as_u64) == acct_index
                })
                .and_then(token_amount)
                .unwrap_or(0);

            if post_amount <= pre_amount {
                return SolOutcome::Reject("no token received");
            }
            SolOutcome::Credited { amount: post_amount - pre_amount }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{self, Chain};

    // Arbitrary base58 addresses; `verify_solana` only string-compares them.
    const LINKED: &str = "7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2";
    const DEPOSIT: &str = "GsbwXfJraMomNxBcpR3DBNxnKwHkYqZ3vP5wFc4T2c2K";
    const OTHER: &str = "3n1mBLhAT4dKC3wJ8wZ9v8bZ8wUeMfq2s3n1mBLhAT4";

    fn sol_spec() -> &'static config::TokenSpec {
        config::token(Chain::Solana, "sol").expect("sol spec")
    }
    fn usdc_spec() -> &'static config::TokenSpec {
        config::token(Chain::Solana, "usdc").expect("usdc spec")
    }

    /// jsonParsed accountKeys entry.
    fn key(pubkey: &str, signer: bool) -> Value {
        serde_json::json!({
            "pubkey": pubkey,
            "signer": signer,
            "writable": true,
            "source": "transaction",
        })
    }

    #[test]
    fn signature_length_check() {
        // 64 zero bytes -> valid length
        let sig = bs58::encode([0u8; 64]).into_string();
        assert!(valid_signature(&sig));
        // 63 bytes -> invalid
        let short = bs58::encode([0u8; 63]).into_string();
        assert!(!valid_signature(&short));
        // non-base58 garbage
        assert!(!valid_signature("not a signature 0OIl"));
    }

    #[test]
    fn native_sol_credited() {
        // sender (index 0) is linked; deposit at index 1 gains 1 SOL.
        let result = serde_json::json!({
            "meta": {
                "err": null,
                "preBalances": [1_000_000_000u64, 5_000_000_000u64],
                "postBalances": [999_995_000u64, 6_000_000_000u64],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false)],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, sol_spec(), DEPOSIT, LINKED),
            SolOutcome::Credited { amount: 1_000_000_000 }
        );
    }

    #[test]
    fn native_sol_wrong_sender() {
        // fee payer (index 0) is not the linked wallet.
        let result = serde_json::json!({
            "meta": {
                "err": null,
                "preBalances": [1_000_000_000u64, 5_000_000_000u64],
                "postBalances": [999_995_000u64, 6_000_000_000u64],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(OTHER, true), key(DEPOSIT, false)],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, sol_spec(), DEPOSIT, LINKED),
            SolOutcome::WrongSender
        );
    }

    #[test]
    fn native_sol_deposit_not_present() {
        let result = serde_json::json!({
            "meta": {
                "err": null,
                "preBalances": [1_000_000_000u64],
                "postBalances": [999_995_000u64],
            },
            "transaction": {
                "message": { "accountKeys": [key(LINKED, true)] }
            }
        });
        assert_eq!(
            verify_solana(&result, sol_spec(), DEPOSIT, LINKED),
            SolOutcome::Reject("deposit address not in transaction")
        );
    }

    #[test]
    fn native_sol_no_receipt_rejected() {
        // deposit balance unchanged.
        let result = serde_json::json!({
            "meta": {
                "err": null,
                "preBalances": [1_000_000_000u64, 5_000_000_000u64],
                "postBalances": [999_995_000u64, 5_000_000_000u64],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false)],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, sol_spec(), DEPOSIT, LINKED),
            SolOutcome::Reject("no SOL received")
        );
    }

    #[test]
    fn spl_usdc_credited() {
        let mint = usdc_spec().contract.expect("usdc mint");
        // deposit's USDC token account (accountIndex 3) goes 0 -> 1.0 USDC.
        let result = serde_json::json!({
            "meta": {
                "err": null,
                "preTokenBalances": [{
                    "accountIndex": 3,
                    "mint": mint,
                    "owner": DEPOSIT,
                    "uiTokenAmount": { "amount": "0" },
                }],
                "postTokenBalances": [{
                    "accountIndex": 3,
                    "mint": mint,
                    "owner": DEPOSIT,
                    "uiTokenAmount": { "amount": "1000000" },
                }],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false)],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, usdc_spec(), DEPOSIT, LINKED),
            SolOutcome::Credited { amount: 1_000_000 }
        );
    }

    #[test]
    fn spl_usdc_missing_pre_treated_as_zero() {
        let mint = usdc_spec().contract.expect("usdc mint");
        // No preTokenBalances entry: pre amount defaults to 0.
        let result = serde_json::json!({
            "meta": {
                "err": null,
                "preTokenBalances": [],
                "postTokenBalances": [{
                    "accountIndex": 3,
                    "mint": mint,
                    "owner": DEPOSIT,
                    "uiTokenAmount": { "amount": "2500000" },
                }],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false)],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, usdc_spec(), DEPOSIT, LINKED),
            SolOutcome::Credited { amount: 2_500_000 }
        );
    }

    #[test]
    fn spl_usdc_no_deposit_entry_rejected() {
        let mint = usdc_spec().contract.expect("usdc mint");
        // post entry is owned by someone else -> no matching deposit entry.
        let result = serde_json::json!({
            "meta": {
                "err": null,
                "preTokenBalances": [],
                "postTokenBalances": [{
                    "accountIndex": 3,
                    "mint": mint,
                    "owner": OTHER,
                    "uiTokenAmount": { "amount": "1000000" },
                }],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false)],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, usdc_spec(), DEPOSIT, LINKED),
            SolOutcome::Reject("no token received")
        );
    }

    #[test]
    fn meta_err_rejected() {
        let result = serde_json::json!({
            "meta": {
                "err": { "InstructionError": [0, "Custom"] },
                "preBalances": [1_000_000_000u64, 5_000_000_000u64],
                "postBalances": [999_995_000u64, 6_000_000_000u64],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false)],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, sol_spec(), DEPOSIT, LINKED),
            SolOutcome::Reject("tx failed on-chain")
        );
    }

    #[test]
    fn accountkeys_as_plain_strings() {
        // Defensive: some encodings render accountKeys as base58 strings.
        let result = serde_json::json!({
            "meta": {
                "err": null,
                "preBalances": [1_000_000_000u64, 5_000_000_000u64],
                "postBalances": [999_995_000u64, 6_000_000_000u64],
            },
            "transaction": {
                "message": { "accountKeys": [LINKED, DEPOSIT] }
            }
        });
        assert_eq!(
            verify_solana(&result, sol_spec(), DEPOSIT, LINKED),
            SolOutcome::Credited { amount: 1_000_000_000 }
        );
    }
}
