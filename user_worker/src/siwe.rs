//! UNIT 1: SIWE (EIP-4361) message parsing + EIP-191 signature recovery.
//!
//! Pure, host-testable code — no `worker` types in this module. Time is
//! always passed in as `now: u64` parameters.
//!
//! STUB: every function below must be implemented by the SIWE unit.

/// A parsed EIP-4361 message. `address` is kept exactly as written in the
/// message (mixed case); callers compare `address.to_lowercase()` against the
/// recovered signer.
#[derive(Debug, Clone)]
pub struct SiweMessage {
    pub domain: String,
    pub address: String,
    pub statement: Option<String>,
    pub uri: String,
    pub version: String,
    pub chain_id: u64,
    pub nonce: String,
    /// RFC 3339, as written.
    pub issued_at: String,
    pub expiration_time: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SiweError {
    Parse(&'static str),
    BadSignature,
    BadHex,
}

impl std::fmt::Display for SiweError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiweError::Parse(m) => write!(f, "siwe parse error: {m}"),
            SiweError::BadSignature => write!(f, "invalid signature"),
            SiweError::BadHex => write!(f, "invalid hex"),
        }
    }
}

/// Strict line-oriented EIP-4361 parser.
pub fn parse_siwe(_msg: &str) -> Result<SiweMessage, SiweError> {
    Err(SiweError::Parse("not implemented"))
}

/// keccak256 of `data`.
pub fn keccak256(_data: &[u8]) -> [u8; 32] {
    unimplemented!("siwe unit")
}

/// Recover the lowercase 0x signer address from an EIP-191 personal_sign
/// signature (65-byte r||s||v hex, v in {0,1,27,28}) over `message`.
pub fn recover_address(_message: &str, _signature_hex: &str) -> Result<String, SiweError> {
    Err(SiweError::BadSignature)
}

/// EIP-55 checksummed form of a lowercase 0x address.
pub fn to_checksum(addr_lower: &str) -> String {
    addr_lower.to_string()
}

/// Parse an RFC 3339 timestamp ("2026-07-04T12:34:56Z" or with fractional
/// seconds / numeric offsets) to epoch seconds. No chrono.
pub fn parse_rfc3339_epoch(_s: &str) -> Option<u64> {
    None
}
