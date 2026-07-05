//! UNIT 4: Solana top-up verification (native SOL + SPL USDT/USDC).
//!
//! Boundary with `payments.rs` (UNIT 3): this module owns everything Solana —
//! the JSON-RPC call and the parse/verify — behind ONE side-effect-free entry
//! point, `topup_solana`. It touches neither D1 nor the DO; `payments.rs` runs
//! the payment-row lifecycle and crediting from the returned `SolOutcome`.
//!
//! SCAFFOLD STATE: `valid_signature` is implemented and the boundary
//! (`SolOutcome` + `topup_solana`) is frozen. `topup_solana`'s body is a stub —
//! UNIT 4 implements it:
//!  - getTransaction(sig, {encoding:"jsonParsed", commitment:"finalized",
//!    maxSupportedTransactionVersion:0}) over `sol_rpc_url`.
//!  - null result -> TooEarly (not found / not finalized); meta.err -> Reject.
//!  - native SOL (spec.contract == None): credited = postBalances[i] -
//!    preBalances[i] for the deposit account in accountKeys; sender = fee payer
//!    accountKeys[0], must equal `linked_address` else WrongSender.
//!  - SPL (spec.contract == Some(mint)): meta.pre/postTokenBalances filtered by
//!    mint + owner == deposit_address, delta of uiTokenAmount.amount; sender =
//!    a balance with owner == linked_address for that mint that decreased.

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
/// `linked_address` are base58. UNIT 4 implements the body per the module docs.
#[allow(unused_variables)]
pub async fn topup_solana(
    sol_rpc_url: &str,
    spec: &TokenSpec,
    deposit_address: &str,
    linked_address: &str,
    signature: &str,
) -> SolOutcome {
    SolOutcome::RpcError("solana top-up not implemented".into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
