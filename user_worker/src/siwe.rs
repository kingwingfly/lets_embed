//! UNIT 1: SIWE (EIP-4361) message parsing + EIP-191 signature recovery.
//!
//! Pure, host-testable code — no `worker` types in this module. Time is
//! always passed in as `now: u64` parameters.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

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

const PREAMBLE_SUFFIX: &str = " wants you to sign in with your Ethereum account:";

struct Lines<'a> {
    lines: Vec<&'a str>,
    i: usize,
}

impl<'a> Lines<'a> {
    fn next(&mut self, what: &'static str) -> Result<&'a str, SiweError> {
        let l = self
            .lines
            .get(self.i)
            .copied()
            .ok_or(SiweError::Parse(what))?;
        self.i += 1;
        Ok(l)
    }

    fn peek(&self) -> Option<&'a str> {
        self.lines.get(self.i).copied()
    }

    fn field(&mut self, name: &'static str, prefix: &str) -> Result<String, SiweError> {
        self.next(name)?
            .strip_prefix(prefix)
            .map(str::to_owned)
            .ok_or(SiweError::Parse(name))
    }
}

/// Strict line-oriented EIP-4361 parser.
pub fn parse_siwe(msg: &str) -> Result<SiweMessage, SiweError> {
    let mut lines = Lines {
        lines: msg
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .collect(),
        i: 0,
    };

    let first = lines.next("missing preamble")?;
    let domain = first
        .strip_suffix(PREAMBLE_SUFFIX)
        .ok_or(SiweError::Parse("bad preamble"))?;
    if domain.is_empty() {
        return Err(SiweError::Parse("empty domain"));
    }
    let address = lines.next("missing address")?;
    if address.is_empty() {
        return Err(SiweError::Parse("empty address"));
    }
    if !lines.next("missing blank line")?.is_empty() {
        return Err(SiweError::Parse("expected blank line after address"));
    }

    // Optional statement block terminated by a blank line; no statement means
    // the fields (or a second blank line) follow directly.
    let mut statement_lines = Vec::new();
    loop {
        let l = lines
            .peek()
            .ok_or(SiweError::Parse("unterminated statement"))?;
        if statement_lines.is_empty() && l.starts_with("URI: ") {
            break; // single-blank-line form: this is already the first field
        }
        lines.i += 1;
        if l.is_empty() {
            break;
        }
        statement_lines.push(l);
    }
    let statement = (!statement_lines.is_empty()).then(|| statement_lines.join("\n"));

    let uri = lines.field("expected URI", "URI: ")?;
    let version = lines.field("expected Version", "Version: ")?;
    let chain_id = lines
        .field("expected Chain ID", "Chain ID: ")?
        .parse::<u64>()
        .map_err(|_| SiweError::Parse("bad chain id"))?;
    let nonce = lines.field("expected Nonce", "Nonce: ")?;
    let issued_at = lines.field("expected Issued At", "Issued At: ")?;

    let mut expiration_time = None;
    if let Some(v) = lines
        .peek()
        .and_then(|l| l.strip_prefix("Expiration Time: "))
    {
        expiration_time = Some(v.to_owned());
        lines.i += 1;
    }

    // Tolerated trailing fields.
    while let Some(l) = lines.peek() {
        lines.i += 1;
        if l.starts_with("Not Before: ") || l.starts_with("Request ID: ") {
            continue;
        }
        if l == "Resources:" {
            while lines.peek().is_some_and(|r| r.starts_with("- ")) {
                lines.i += 1;
            }
            continue;
        }
        if l.is_empty() && lines.lines[lines.i..].iter().all(|r| r.is_empty()) {
            break;
        }
        return Err(SiweError::Parse("unexpected trailing line"));
    }

    Ok(SiweMessage {
        domain: domain.to_owned(),
        address: address.to_owned(),
        statement,
        uri,
        version,
        chain_id,
        nonce,
        issued_at,
        expiration_time,
    })
}

/// keccak256 of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Recover the lowercase 0x signer address from an EIP-191 personal_sign
/// signature (65-byte r||s||v hex, v in {0,1,27,28}) over `message`.
pub fn recover_address(message: &str, signature_hex: &str) -> Result<String, SiweError> {
    let hex_str = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
    let sig_bytes = hex::decode(hex_str).map_err(|_| SiweError::BadHex)?;
    if sig_bytes.len() != 65 {
        return Err(SiweError::BadSignature);
    }
    let mut v = match sig_bytes[64] {
        b @ (0 | 1) => b,
        b @ (27 | 28) => b - 27,
        _ => return Err(SiweError::BadSignature),
    };

    let mut sig = Signature::from_slice(&sig_bytes[..64]).map_err(|_| SiweError::BadSignature)?;
    if let Some(normalized) = sig.normalize_s() {
        sig = normalized;
        v ^= 1;
    }
    let rec_id = RecoveryId::from_byte(v).ok_or(SiweError::BadSignature)?;

    let digest = keccak256(
        &[
            b"\x19Ethereum Signed Message:\n",
            message.len().to_string().as_bytes(),
            message.as_bytes(),
        ]
        .concat(),
    );
    let key = VerifyingKey::recover_from_prehash(&digest, &sig, rec_id)
        .map_err(|_| SiweError::BadSignature)?;
    Ok(pubkey_to_address(&key))
}

fn pubkey_to_address(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..65]);
    format!("0x{}", hex::encode(&hash[12..32]))
}

/// EIP-55 checksummed form of a lowercase 0x address.
pub fn to_checksum(addr_lower: &str) -> String {
    let hex_part = addr_lower.strip_prefix("0x").unwrap_or(addr_lower);
    let hash = keccak256(hex_part.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    // `.take(64)` bounds the hash index for over-long (invalid) inputs.
    for (i, c) in hex_part.chars().enumerate().take(64) {
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0xf
        };
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse an RFC 3339 timestamp ("2026-07-04T12:34:56Z" or with fractional
/// seconds / numeric offsets) to epoch seconds. No chrono.
pub fn parse_rfc3339_epoch(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<u64> {
        let part = b.get(range)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    let sep = |i: usize, c: u8| b.get(i) == Some(&c);

    let year = num(0..4)?;
    let month = num(5..7)?;
    let day = num(8..10)?;
    let hour = num(11..13)?;
    let min = num(14..16)?;
    let sec = num(17..19)?;
    if !(sep(4, b'-') && sep(7, b'-'))
        || !(sep(10, b'T') || sep(10, b't'))
        || !sep(13, b':')
        || !sep(16, b':')
    {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 59 {
        return None;
    }

    // Skip fractional seconds.
    let mut i = 19;
    if sep(i, b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
    }

    // Offset: Z or ±HH:MM, must consume the rest of the string.
    let offset_secs: i64 = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && sep(i + 3, b':') => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let mag = (oh * 3600 + om * 60) as i64;
            if *sign == b'+' { mag } else { -mag }
        }
        _ => return None,
    };

    // Days from civil (Howard Hinnant), valid for year >= 1970 here.
    let (y, m, d) = (year as i64, month as i64, day as i64);
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    let epoch = days * 86400 + (hour * 3600 + min * 60 + sec) as i64 - offset_secs;
    u64::try_from(epoch).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    const MSG: &str = "example.com wants you to sign in with your Ethereum account:\n\
0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed\n\
\n\
Sign in to lets_embed.\n\
\n\
URI: https://example.com/user/login\n\
Version: 1\n\
Chain ID: 1\n\
Nonce: 32891756\n\
Issued At: 2026-07-04T00:00:00Z\n\
Expiration Time: 2026-07-04T00:10:00Z";

    fn eip191_digest(message: &str) -> [u8; 32] {
        keccak256(
            &[
                b"\x19Ethereum Signed Message:\n",
                message.len().to_string().as_bytes(),
                message.as_bytes(),
            ]
            .concat(),
        )
    }

    #[test]
    fn ecrecover_roundtrip() {
        let sk = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let expected = pubkey_to_address(sk.verifying_key());

        let (sig, rec_id) = sk.sign_prehash_recoverable(&eip191_digest(MSG)).unwrap();
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(rec_id.to_byte());
        let sig_hex = format!("0x{}", hex::encode(&bytes));
        assert_eq!(recover_address(MSG, &sig_hex).unwrap(), expected);

        // v encoded as 27/28
        *bytes.last_mut().unwrap() = rec_id.to_byte() + 27;
        let sig_hex27 = hex::encode(&bytes);
        assert_eq!(recover_address(MSG, &sig_hex27).unwrap(), expected);

        // wrong v / bad hex / wrong length
        *bytes.last_mut().unwrap() = 5;
        assert_eq!(
            recover_address(MSG, &hex::encode(&bytes)),
            Err(SiweError::BadSignature)
        );
        assert_eq!(recover_address(MSG, "0xzz"), Err(SiweError::BadHex));
        assert_eq!(recover_address(MSG, "0x0011"), Err(SiweError::BadSignature));

        // tampered message recovers a different address
        let mut ok = sig.to_bytes().to_vec();
        ok.push(rec_id.to_byte());
        let other = recover_address("other message", &hex::encode(&ok)).unwrap();
        assert_ne!(other, expected);
    }

    #[test]
    fn eip55_vectors() {
        for want in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            assert_eq!(to_checksum(&want.to_lowercase()), want);
        }
    }

    #[test]
    fn parse_full_message() {
        let m = parse_siwe(MSG).unwrap();
        assert_eq!(m.domain, "example.com");
        assert_eq!(m.address, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert_eq!(m.statement.as_deref(), Some("Sign in to lets_embed."));
        assert_eq!(m.uri, "https://example.com/user/login");
        assert_eq!(m.version, "1");
        assert_eq!(m.chain_id, 1);
        assert_eq!(m.nonce, "32891756");
        assert_eq!(m.issued_at, "2026-07-04T00:00:00Z");
        assert_eq!(m.expiration_time.as_deref(), Some("2026-07-04T00:10:00Z"));
    }

    #[test]
    fn parse_no_statement() {
        let msg = "example.com wants you to sign in with your Ethereum account:\n\
0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB\n\
\n\
URI: https://example.com\n\
Version: 1\n\
Chain ID: 5\n\
Nonce: abcdef12\n\
Issued At: 2026-01-01T00:00:00Z";
        let m = parse_siwe(msg).unwrap();
        assert_eq!(m.statement, None);
        assert_eq!(m.chain_id, 5);
        assert_eq!(m.expiration_time, None);
    }

    #[test]
    fn parse_tolerates_trailing_fields() {
        let msg = format!(
            "{MSG}\nNot Before: 2026-07-04T00:00:00Z\nRequest ID: xyz\nResources:\n- ipfs://a\n- https://b"
        );
        let m = parse_siwe(&msg).unwrap();
        assert_eq!(m.nonce, "32891756");
    }

    #[test]
    fn parse_rejects() {
        // wrong preamble
        assert!(parse_siwe("hello\n0xabc\n\nURI: x").is_err());
        // missing Nonce
        let msg = "example.com wants you to sign in with your Ethereum account:\n\
0xabc\n\
\n\
URI: https://example.com\n\
Version: 1\n\
Chain ID: 1\n\
Issued At: 2026-01-01T00:00:00Z";
        assert!(parse_siwe(msg).is_err());
        // wrong field order (Nonce before Chain ID)
        let msg = "example.com wants you to sign in with your Ethereum account:\n\
0xabc\n\
\n\
URI: https://example.com\n\
Version: 1\n\
Nonce: abcdef12\n\
Chain ID: 1\n\
Issued At: 2026-01-01T00:00:00Z";
        assert!(parse_siwe(msg).is_err());
        // non-numeric chain id
        let msg = "example.com wants you to sign in with your Ethereum account:\n\
0xabc\n\
\n\
URI: https://example.com\n\
Version: 1\n\
Chain ID: mainnet\n\
Nonce: abcdef12\n\
Issued At: 2026-01-01T00:00:00Z";
        assert!(parse_siwe(msg).is_err());
        // junk after fields
        assert!(parse_siwe(&format!("{MSG}\ngarbage")).is_err());
    }

    #[test]
    fn rfc3339_vectors() {
        assert_eq!(parse_rfc3339_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_epoch("1996-12-19T16:39:57-08:00"),
            Some(851042397)
        );
        assert_eq!(
            parse_rfc3339_epoch("1996-12-20T08:39:57+08:00"),
            Some(851042397)
        );
        assert_eq!(
            parse_rfc3339_epoch("1985-04-12T23:20:50.52Z"),
            Some(482196050)
        );
        assert_eq!(
            parse_rfc3339_epoch("2026-07-04T12:34:56Z"),
            Some(1783168496)
        );
        assert_eq!(parse_rfc3339_epoch("2026-07-04"), None);
        assert_eq!(parse_rfc3339_epoch("2026-07-04T12:34:56"), None);
        assert_eq!(parse_rfc3339_epoch("2026-07-04T12:34:56+8:00"), None);
        assert_eq!(parse_rfc3339_epoch("2026-13-04T12:34:56Z"), None);
        assert_eq!(parse_rfc3339_epoch("2026-07-04T12:34:56.Z"), None);
    }
}
