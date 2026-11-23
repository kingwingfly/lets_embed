//! Canonical WD-Tagger v3 (`wd-eva02-large-tagger-v3`) vocabulary and digest.
//!
//! All 10,861 tag names from `models/wd-eva02-large-tagger-v3/selected_tags.csv`
//! are tracked in sorted ASCII order at `search_types/data/wd_eva02_v3_tags.txt`
//! so worktrees, CI, and `wasm32-unknown-unknown` builds can validate canonical
//! `tag:<name>` predicates with zero runtime allocations and no external model
//! directory dependency.

/// Raw LF-delimited sorted vocabulary file embedded at compile time.
const WD_VOCAB_RAW: &str = include_str!("../data/wd_eva02_v3_tags.txt");

/// Exact number of canonical tags in WD-Tagger v3 (`wd-eva02-large-tagger-v3`).
pub const WD_VOCAB_COUNT: usize = 10_861;

/// Canonical lowercase hex SHA-256 digest of the sorted, `\n`-joined
/// 10,861-name WD-Tagger v3 vocabulary (without trailing newline).
pub const WD_VOCAB_DIGEST: &str =
    "760e0e0b36eff91fe713495c20e3f0ecf49cd958b8033b3c454c97f3abfd339c";

/// The 20 canonical WD-Tagger tags referenced by built-in safety presets and
/// category-9 rating persistence.
pub const BUILTIN_SAFETY_PRESET_TAGS: &[&str] = &[
    // Category 9 ratings
    "general",
    "sensitive",
    "questionable",
    "explicit",
    // R-18 / Explicit preset
    "nude",
    "nipples",
    "pussy",
    "penis",
    "sex",
    "uncensored",
    "censored",
    "topless",
    "bottomless",
    // Suggestive / Ecchi preset
    "lingerie",
    "bikini",
    "underwear",
    "panties",
    "cleavage",
    "bdsm",
    // Blood / Violence preset
    "blood",
];

/// Returns the canonical `\n`-joined UTF-8 bytes over which [`WD_VOCAB_DIGEST`]
/// is computed (excluding any trailing newline).
#[inline]
pub fn canonical_wd_vocab_bytes() -> &'static [u8] {
    WD_VOCAB_RAW.trim_end_matches(['\r', '\n']).as_bytes()
}

/// Returns the exact count of canonical WD-Tagger v3 tags (`10_861`).
#[inline]
pub const fn wd_vocab_count() -> usize {
    WD_VOCAB_COUNT
}

/// Iterates all 10,861 canonical WD-Tagger v3 tag names in sorted ASCII order.
pub fn wd_vocab_tags() -> impl Iterator<Item = &'static str> {
    WD_VOCAB_RAW
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.is_empty())
}

/// Checks whether `name` is an exact canonical WD-Tagger v3 tag name using an
/// `O(log N)` binary search directly over the embedded sorted vocabulary buffer
/// with zero heap allocations.
pub fn is_canonical_wd_tag(name: &str) -> bool {
    if name.is_empty()
        || !name.is_ascii()
        || name.bytes().any(|b| b == b'\n' || b == b'\r')
    {
        return false;
    }

    let raw = canonical_wd_vocab_bytes();
    let target = name.as_bytes();
    let mut lo = 0usize;
    let mut hi = raw.len();

    while lo < hi {
        let mid = lo + (hi - lo) / 2;

        // Locate the start of the line containing byte index `mid`.
        // If `raw[mid] == b'\n'`, that newline terminates the line immediately
        // preceding `mid`, so scanning backwards from `mid` finds its start.
        let mut line_start = mid;
        while line_start > lo && raw[line_start - 1] != b'\n' {
            line_start -= 1;
        }

        // Locate the end of that line.
        let mut line_end = mid;
        while line_end < hi && raw[line_end] != b'\n' {
            line_end += 1;
        }

        let mut line = &raw[line_start..line_end];
        if let Some(stripped) = line.strip_suffix(b"\r") {
            line = stripped;
        }

        match line.cmp(target) {
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Less => {
                lo = line_end.saturating_add(1).min(hi);
            }
            std::cmp::Ordering::Greater => {
                hi = line_start;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure-Rust FIPS 180-4 SHA-256 used in tests so `search_types` stays
    /// dependency-free while still cryptographically verifying `WD_VOCAB_DIGEST`.
    fn sha256_hex(data: &[u8]) -> String {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;
        let mut msg = data.to_vec();
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        let (chunks, rem) = msg.as_chunks::<64>();
        assert!(rem.is_empty());
        for chunk in chunks {
            let mut w = [0u32; 64];
            let (words, word_rem) = chunk.as_chunks::<4>();
            assert!(word_rem.is_empty());
            for (i, &word) in words.iter().enumerate() {
                w[i] = u32::from_be_bytes(word);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        let mut out = String::with_capacity(64);
        for word in h {
            use std::fmt::Write as _;
            let _ = write!(out, "{word:08x}");
        }
        out
    }

    #[test]
    fn vocab_has_exact_10861_sorted_unique_ascii_tags_and_valid_digest() {
        let tags: Vec<&str> = wd_vocab_tags().collect();
        assert_eq!(tags.len(), 10_861);
        assert_eq!(wd_vocab_count(), 10_861);
        assert!(!WD_VOCAB_RAW.contains('\r'), "vocab file must use LF endings");

        for pair in tags.windows(2) {
            assert!(
                pair[0] < pair[1],
                "vocab must be strictly sorted with no duplicates: {:?} >= {:?}",
                pair[0],
                pair[1]
            );
        }

        for tag in &tags {
            assert!(tag.is_ascii() && !tag.is_empty() && *tag == tag.trim());
        }

        let rejoined = tags.join("\n");
        assert_eq!(rejoined.as_bytes(), canonical_wd_vocab_bytes());
        assert_eq!(sha256_hex(rejoined.as_bytes()), WD_VOCAB_DIGEST);
        // Sanity check pure-Rust SHA-256 against NIST empty-string vector
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn all_20_builtin_safety_preset_tags_and_every_vocab_tag_resolve_true() {
        assert_eq!(BUILTIN_SAFETY_PRESET_TAGS.len(), 20);
        for &preset_tag in BUILTIN_SAFETY_PRESET_TAGS {
            assert!(
                is_canonical_wd_tag(preset_tag),
                "missing built-in safety preset tag: {preset_tag}"
            );
        }

        // Exhaustively verify binary search hits every single one of the 10,861 tags.
        let mut count = 0usize;
        for tag in wd_vocab_tags() {
            assert!(
                is_canonical_wd_tag(tag),
                "binary search failed to find canonical tag {tag:?}"
            );
            count += 1;
        }
        assert_eq!(count, WD_VOCAB_COUNT);

        // Edge & negative cases: typos, casing, padding, newlines, boundaries.
        for bogus in [
            "",
            " ",
            "!!not_a_tag",
            "~~~not_a_tag",
            "zzz_nonexistent_tag",
            "BLOOD",
            "Explicit",
            "blod",
            "explict",
            " blood",
            "blood ",
            "blood\n",
            "blood\r",
            "blood\0",
            "女仆",
            ":>=x",
            "general\nsensitive",
        ] {
            assert!(
                !is_canonical_wd_tag(bogus),
                "bogus tag must not match canonical vocab: {bogus:?}"
            );
        }
    }
}
