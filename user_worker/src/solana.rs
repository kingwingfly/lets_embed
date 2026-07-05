//! UNIT 4: Solana top-up verification (native SOL + SPL USDT/USDC).
//!
//! SCAFFOLD STATE: signature validation is implemented; the on-chain verifier
//! is a stub. UNIT 4 implements `getTransaction` (jsonParsed, finalized) parsing:
//!  - native SOL: credit = postBalances[i] - preBalances[i] for the deposit
//!    account; sender = fee payer accountKeys[0], must equal the linked address.
//!  - SPL: meta.pre/postTokenBalances filtered by mint + owner == deposit;
//!    delta of uiTokenAmount.amount; sender = linked address whose balance fell.
//!  - null result -> not found / not finalized (retry, 425); meta.err -> reject.

use crate::config::TokenSpec;

/// Outcome of verifying a Solana top-up transaction.
#[derive(Debug, PartialEq, Eq)]
pub enum SolVerify {
    /// Verified: raw base units received by the deposit address (lamports for
    /// native SOL, token minor units for SPL).
    Ok(u128),
    /// Permanently invalid for any submitter (wrong recipient, reverted, ...).
    Reject(&'static str),
    /// Sender is not the linked wallet — submitter-relative, release the lock.
    WrongSender,
    /// Not visible / not finalized yet — retry later.
    TooEarly,
}

/// A base58 Solana tx signature decodes to 64 bytes.
pub fn valid_signature(sig: &str) -> bool {
    matches!(bs58::decode(sig).into_vec(), Ok(v) if v.len() == 64)
}

/// Verify a `getTransaction` (jsonParsed) result. `linked_address` is the user's
/// linked Solana wallet (base58). UNIT 4 implements the body.
#[allow(unused_variables)]
pub fn verify_solana_tx(
    tx: &serde_json::Value,
    token: &TokenSpec,
    deposit_address: &str,
    linked_address: &str,
) -> SolVerify {
    SolVerify::Reject("solana verification not implemented")
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
