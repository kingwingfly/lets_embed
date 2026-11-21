//! UNIT 4: Solana top-up verification (native SOL + SPL USDT/USDC).
//!
//! The payments handler fetches a finalized transaction, selects the recipient and
//! pricing effective at its block time, then verifies the transfer here.

use serde_json::Value;
use worker::{Fetch, Method, Request, RequestInit};

use crate::config::TokenSpec;

/// Verification for the requested wallet, recipient and asset. Only a verified
/// transfer can reserve a credit in the payment ledger.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SolOutcome {
    /// Verified: raw base units received (lamports for SOL, minor units for SPL).
    Credited { amount: u128 },
    /// The transaction does not qualify for the requested deposit.
    Reject(&'static str),
    /// Sender is not the linked wallet — submitter-relative.
    WrongSender,
    /// Incomplete or malformed upstream data. The customer can retry.
    RpcError(String),
}

/// A base58 Solana tx signature decodes to exactly 64 bytes.
pub fn valid_signature(sig: &str) -> bool {
    // 64 bytes in base58 is always 64..=88 characters; bound before decoding.
    if !(64..=88).contains(&sig.len()) {
        return false;
    }
    let mut buf = [0u8; 64];
    matches!(bs58::decode(sig).onto(&mut buf), Ok(64))
}

// ---------------------------------------------------------------------------
// JSON-RPC over worker::Fetch (no solana-sdk on wasm)
// ---------------------------------------------------------------------------

/// `getTransaction(signature, {encoding:"jsonParsed", commitment:"finalized",
/// maxSupportedTransactionVersion:1})`. Returns the `result` field (which may be
/// JSON `null`). A non-2xx HTTP response, a JSON-RPC-level `error`, or a decode
/// failure is turned into `Err`.
pub(crate) async fn get_transaction(url: &str, signature: &str) -> worker::Result<Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            {
                "encoding": "jsonParsed",
                "commitment": "finalized",
                "maxSupportedTransactionVersion": 1,
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
        return Err(worker::Error::RustError(format!(
            "getTransaction: http {code}"
        )));
    }
    let v: Value = resp.json().await?;
    if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
        return Err(worker::Error::RustError(format!(
            "getTransaction error: {e}"
        )));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------
// Pure verifier (host-tested)
// ---------------------------------------------------------------------------

/// The pubkey of an accountKeys / loadedAddresses entry. jsonParsed renders
/// static account keys as `{pubkey, signer, writable, source}`; legacy/base64
/// encodings and `meta.loadedAddresses.{writable,readonly}` render plain base58
/// strings. Both are handled.
fn key_pubkey(entry: &Value) -> Option<&str> {
    match entry {
        Value::String(s) => Some(s.as_str()),
        other => other.get("pubkey").and_then(Value::as_str),
    }
}

/// Build the full account-key table for legacy, v0 (with Address Lookup Tables),
/// and v1 transactions: static `accountKeys` followed by `loadedAddresses.writable`
/// and `loadedAddresses.readonly`.
fn effective_keys(result: &Value) -> Result<Vec<&str>, &'static str> {
    let static_keys = result["transaction"]["message"]["accountKeys"]
        .as_array()
        .ok_or("malformed transaction: missing accountKeys")?;
    let mut keys = Vec::with_capacity(static_keys.len());
    for entry in static_keys {
        keys.push(key_pubkey(entry).ok_or("malformed transaction: bad account key")?);
    }
    let loaded = &result["meta"]["loadedAddresses"];
    if !loaded.is_null() {
        for section in ["writable", "readonly"] {
            if let Some(arr) = loaded.get(section).and_then(Value::as_array) {
                for entry in arr {
                    keys.push(
                        key_pubkey(entry).ok_or("malformed transaction: bad loaded address")?,
                    );
                }
            }
        }
    }
    Ok(keys)
}

/// Extract the fee payer (account key 0) from a `getTransaction` result.
pub(crate) fn tx_sender(result: &Value) -> Option<&str> {
    result["transaction"]["message"]["accountKeys"]
        .as_array()
        .and_then(|keys| keys.first())
        .and_then(key_pubkey)
}

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// jsonParsed includes transfers made directly and by programs invoked by the wallet.
fn transfer_total(
    tx: &Value,
    program: &str,
    mut amount: impl FnMut(&Value) -> Option<u64>,
) -> Option<u128> {
    let outer = tx["transaction"]["message"]["instructions"].as_array()?;
    let mut total = 0;
    let mut add = |instructions: &[Value]| -> Option<()> {
        for ix in instructions {
            if ix["programId"] == program
                && matches!(
                    ix["parsed"]["type"].as_str(),
                    Some("transfer" | "transferChecked" | "transferWithSeed")
                )
            {
                total += u128::from(amount(&ix["parsed"]["info"])?);
            }
        }
        Some(())
    };
    add(outer)?;
    let inner = &tx["meta"]["innerInstructions"];
    if !inner.is_null() {
        for group in inner.as_array()? {
            add(group["instructions"].as_array()?)?;
        }
    }
    Some(total)
}

/// Verify a finalized (non-null) `getTransaction` result. Pure and side-effect
/// free. `deposit_address` / `linked_address` are base58.
pub(crate) fn verify_solana(
    result: &Value,
    spec: &TokenSpec,
    deposit_address: &str,
    linked_address: &str,
) -> SolOutcome {
    let meta = &result["meta"];

    let keys = match effective_keys(result) {
        Ok(k) => k,
        Err(e) => return SolOutcome::RpcError(e.into()),
    };
    // Fee payer / sender is always the first account key. Check ownership before
    // recording permanent rejections so an unrelated caller cannot stuff failed
    // transactions into `payments`.
    let Some(&sender) = keys.first() else {
        return SolOutcome::RpcError("malformed transaction: missing fee payer".into());
    };
    // Both the native and SPL paths require the linked wallet to be the fee
    // payer: for SPL, the token-account owner signs as fee payer here.
    if sender != linked_address {
        return SolOutcome::WrongSender;
    }

    // A non-null `meta.err` means the transaction failed on-chain: no transfer
    // took effect, permanent for any submitter.
    match meta.get("err") {
        Some(Value::Null) => {}
        Some(_) => return SolOutcome::Reject("tx failed on-chain"),
        None => return SolOutcome::RpcError("missing transaction status".into()),
    }

    if sender == deposit_address || deposit_address.is_empty() {
        return SolOutcome::Reject("no deposit received");
    }

    let (received, funded) = match spec.contract {
        None => {
            let Some(i) = keys.iter().position(|&k| k == deposit_address) else {
                return SolOutcome::Reject("deposit address not in transaction");
            };
            let (Some(pre), Some(post)) = (
                meta["preBalances"][i].as_u64(),
                meta["postBalances"][i].as_u64(),
            ) else {
                return SolOutcome::RpcError("malformed transaction: missing balances".into());
            };
            if post <= pre {
                return SolOutcome::Reject("no SOL received");
            }
            let funded = transfer_total(result, SYSTEM_PROGRAM, |info| {
                if info["source"] == sender && info["destination"] == deposit_address {
                    info["lamports"].as_u64()
                } else {
                    Some(0)
                }
            });
            (u128::from(post - pre), funded)
        }
        Some(mint) => {
            let mut destinations = std::collections::HashSet::new();
            let mut sources = std::collections::HashSet::new();
            let mut totals = [0u128; 2];
            for (side, field) in ["preTokenBalances", "postTokenBalances"]
                .into_iter()
                .enumerate()
            {
                let Some(entries) = meta[field].as_array() else {
                    return SolOutcome::RpcError(format!("missing {field}"));
                };
                for entry in entries.iter().filter(|e| e["mint"] == mint) {
                    if entry["owner"] != deposit_address && entry["owner"] != sender {
                        continue;
                    }
                    let Some(key) = entry["accountIndex"]
                        .as_u64()
                        .and_then(|i| usize::try_from(i).ok())
                        .and_then(|i| keys.get(i).copied())
                    else {
                        return SolOutcome::RpcError("missing token account key".into());
                    };
                    if entry["owner"] == sender {
                        sources.insert(key);
                    } else {
                        let Some(amount) = entry["uiTokenAmount"]["amount"]
                            .as_str()
                            .and_then(|v| v.parse::<u64>().ok())
                        else {
                            return SolOutcome::RpcError("malformed deposit token balance".into());
                        };
                        totals[side] += u128::from(amount);
                        if side == 1 {
                            destinations.insert(key);
                        }
                    }
                }
            }
            if totals[1] <= totals[0] {
                return SolOutcome::Reject("no token received");
            }
            let funded = transfer_total(result, TOKEN_PROGRAM, |info| {
                let destination = info["destination"].as_str()?;
                let source = info["source"].as_str()?;
                if !destinations.contains(destination)
                    || source == destination
                    || !sources.contains(source)
                    || info["mint"].as_str().is_some_and(|m| m != mint)
                {
                    return Some(0);
                }
                info["amount"]
                    .as_str()
                    .or_else(|| info["tokenAmount"]["amount"].as_str())?
                    .parse()
                    .ok()
            });
            (totals[1] - totals[0], funded)
        }
    };
    match funded {
        Some(0) => SolOutcome::WrongSender,
        Some(amount) => SolOutcome::Credited {
            amount: received.min(amount),
        },
        None => SolOutcome::RpcError("incomplete transfer instructions".into()),
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

    fn sol_transfer(lamports: u64) -> Value {
        serde_json::json!({"programId": SYSTEM_PROGRAM, "parsed":{"type":"transfer",
            "info":{"source":LINKED,"destination":DEPOSIT,"lamports":lamports}}})
    }

    fn spl_transfer(amount: &str) -> Value {
        serde_json::json!({"programId": TOKEN_PROGRAM, "parsed":{"type":"transfer",
            "info":{"authority":LINKED,"source":"source-token-account","destination":"deposit-token-account","amount":amount}}})
    }

    #[test]
    fn signature_length_check() {
        // 64 zero bytes -> valid length
        let sig = bs58::encode([0u8; 64]).into_string();
        assert!(valid_signature(&sig));
        // 64 max bytes -> 88 chars, valid length
        let max_sig = bs58::encode([0xffu8; 64]).into_string();
        assert_eq!(max_sig.len(), 88);
        assert!(valid_signature(&max_sig));
        // 63 bytes -> invalid
        let short = bs58::encode([0u8; 63]).into_string();
        assert!(!valid_signature(&short));
        // oversized valid-alphabet string rejected immediately without quadratic work
        assert!(!valid_signature(&"1".repeat(10_000)));
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
                "postBalances": [0u64, 6_000_000_000u64],
                "innerInstructions": [{"index": 1, "instructions": [sol_transfer(400_000_000)]}],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false)],
                    "instructions": [sol_transfer(600_000_000), {"programId": "another-program"}],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, sol_spec(), DEPOSIT, LINKED),
            SolOutcome::Credited {
                amount: 1_000_000_000
            }
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
        // The wallet contributes 1 USDC to a batched payment that delivers 3 USDC.
        let mut other_transfer = spl_transfer("2000000");
        other_transfer["parsed"]["info"]["authority"] = OTHER.into();
        other_transfer["parsed"]["info"]["source"] = "other-token-account".into();
        let mut result = serde_json::json!({
            "meta": {
                "err": null,
                "preTokenBalances": [{
                    "accountIndex": 3,
                    "mint": mint,
                    "owner": DEPOSIT,
                    "uiTokenAmount": { "amount": "0" },
                }, {
                    "accountIndex": 2, "mint": mint, "owner": LINKED,
                    "uiTokenAmount": { "amount": "1000000" },
                }],
                "postTokenBalances": [{
                    "accountIndex": 3,
                    "mint": mint,
                    "owner": DEPOSIT,
                    "uiTokenAmount": { "amount": "3000000" },
                }],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false), "source-token-account", "deposit-token-account"],
                    "instructions": [spl_transfer("1000000"), other_transfer],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, usdc_spec(), DEPOSIT, LINKED),
            SolOutcome::Credited { amount: 1_000_000 }
        );
        result["meta"]["preTokenBalances"][0]["uiTokenAmount"]["amount"] = Value::Null;
        assert!(matches!(
            verify_solana(&result, usdc_spec(), DEPOSIT, LINKED),
            SolOutcome::RpcError(_)
        ));
    }

    #[test]
    fn spl_usdc_missing_pre_treated_as_zero() {
        let mint = usdc_spec().contract.expect("usdc mint");
        // The transfer creates the recipient's account, so only the source existed before.
        let result = serde_json::json!({
            "meta": {
                "err": null,
                "preTokenBalances": [{"accountIndex": 2, "mint": mint, "owner": LINKED,
                    "uiTokenAmount": {"amount": "2500000"}}],
                "postTokenBalances": [{
                    "accountIndex": 3,
                    "mint": mint,
                    "owner": DEPOSIT,
                    "uiTokenAmount": { "amount": "2500000" },
                }],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false), "source-token-account", "deposit-token-account"],
                    "instructions": [spl_transfer("2500000")],
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
                "postBalances": [0u64, 6_000_000_000u64],
            },
            "transaction": {
                "message": { "accountKeys": [LINKED, DEPOSIT], "instructions": [sol_transfer(1_000_000_000)] }
            }
        });
        assert_eq!(
            verify_solana(&result, sol_spec(), DEPOSIT, LINKED),
            SolOutcome::Credited {
                amount: 1_000_000_000
            }
        );
    }

    #[test]
    fn v0_loaded_addresses_resolve_token_accounts() {
        let mint = usdc_spec().contract.expect("usdc mint");
        let result = serde_json::json!({
            "version": 0,
            "meta": {
                "err": null,
                "loadedAddresses": {
                    "writable": ["source-token-account", "deposit-token-account"],
                    "readonly": [mint],
                },
                "preTokenBalances": [{
                    "accountIndex": 2,
                    "mint": mint,
                    "owner": LINKED,
                    "uiTokenAmount": { "amount": "1500000" },
                }],
                "postTokenBalances": [{
                    "accountIndex": 3,
                    "mint": mint,
                    "owner": DEPOSIT,
                    "uiTokenAmount": { "amount": "1500000" },
                }],
            },
            "transaction": {
                "message": {
                    "accountKeys": [key(LINKED, true), key(DEPOSIT, false)],
                    "instructions": [spl_transfer("1500000")],
                }
            }
        });
        assert_eq!(
            verify_solana(&result, usdc_spec(), DEPOSIT, LINKED),
            SolOutcome::Credited { amount: 1_500_000 }
        );
    }

    #[test]
    fn wrong_sender_checked_before_meta_err() {
        let result = serde_json::json!({
            "meta": { "err": { "InstructionError": [0, "Custom"] } },
            "transaction": {
                "message": { "accountKeys": [key(OTHER, true), key(DEPOSIT, false)] }
            }
        });
        assert_eq!(
            verify_solana(&result, sol_spec(), DEPOSIT, LINKED),
            SolOutcome::WrongSender
        );
    }
}
