//! Zero-dependency ISO/IEC 18004 QR Code encoder (Byte mode, ECC Level M,
//! Versions 1–10, up to 213 bytes). Used for local QR rendering of wallet
//! handoff and cross-device login URLs without leaking tokens to third parties.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QrMatrix {
    pub size: usize,
    /// Row-major `'1'` (dark) / `'0'` (light) modules, length `size * size`.
    pub bits: String,
}

struct VersionSpec {
    version: u8,
    ec_per_block: usize,
    g1_blocks: usize,
    g1_data: usize,
    g2_blocks: usize,
    g2_data: usize,
    align: &'static [usize],
}

impl VersionSpec {
    const fn total_data_codewords(&self) -> usize {
        self.g1_blocks * self.g1_data + self.g2_blocks * self.g2_data
    }

    const fn cc_bits(&self) -> usize {
        if self.version <= 9 { 8 } else { 16 }
    }

    const fn byte_capacity(&self) -> usize {
        // 4-bit mode + cc_bits length header; remainder fits whole bytes.
        (self.total_data_codewords() * 8 - 4 - self.cc_bits()) / 8
    }
}

/// ISO/IEC 18004 Table 9 & Annex E parameters for ECC Level M, Versions 1–10.
const SPECS_M: &[VersionSpec] = &[
    VersionSpec {
        version: 1,
        ec_per_block: 10,
        g1_blocks: 1,
        g1_data: 16,
        g2_blocks: 0,
        g2_data: 0,
        align: &[],
    },
    VersionSpec {
        version: 2,
        ec_per_block: 16,
        g1_blocks: 1,
        g1_data: 28,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 18],
    },
    VersionSpec {
        version: 3,
        ec_per_block: 26,
        g1_blocks: 1,
        g1_data: 44,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 22],
    },
    VersionSpec {
        version: 4,
        ec_per_block: 18,
        g1_blocks: 2,
        g1_data: 32,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 26],
    },
    VersionSpec {
        version: 5,
        ec_per_block: 24,
        g1_blocks: 2,
        g1_data: 43,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 30],
    },
    VersionSpec {
        version: 6,
        ec_per_block: 16,
        g1_blocks: 4,
        g1_data: 27,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 34],
    },
    VersionSpec {
        version: 7,
        ec_per_block: 18,
        g1_blocks: 4,
        g1_data: 31,
        g2_blocks: 0,
        g2_data: 0,
        align: &[6, 22, 38],
    },
    VersionSpec {
        version: 8,
        ec_per_block: 22,
        g1_blocks: 2,
        g1_data: 38,
        g2_blocks: 2,
        g2_data: 39,
        align: &[6, 24, 42],
    },
    VersionSpec {
        version: 9,
        ec_per_block: 22,
        g1_blocks: 3,
        g1_data: 36,
        g2_blocks: 2,
        g2_data: 37,
        align: &[6, 26, 46],
    },
    VersionSpec {
        version: 10,
        ec_per_block: 26,
        g1_blocks: 4,
        g1_data: 43,
        g2_blocks: 1,
        g2_data: 44,
        align: &[6, 28, 50],
    },
];

/// Encode arbitrary bytes (e.g. a UTF-8 HTTPS URL) into an ECC-M QR matrix.
/// Returns `None` if `data` exceeds the 213-byte Version 10 capacity.
pub fn encode(data: &[u8]) -> Option<QrMatrix> {
    let spec = SPECS_M.iter().find(|s| data.len() <= s.byte_capacity())?;
    let data_cw = build_data_codewords(data, spec);
    let final_cw = interleave_with_ec(&data_cw, spec);

    let size = usize::from(spec.version) * 4 + 17;
    let mut base = vec![false; size * size];
    let mut func = vec![false; size * size];

    place_function_patterns(spec, size, &mut base, &mut func);
    place_data_bits(&final_cw, size, &mut base, &func);

    let mut best_grid = None;
    let mut best_penalty = u32::MAX;
    for mask in 0..8u8 {
        let mut grid = base.clone();
        apply_mask(mask, size, &mut grid, &func);
        write_format_bits(mask, size, &mut grid);
        let p = penalty(&grid, size);
        if p < best_penalty {
            best_penalty = p;
            best_grid = Some(grid);
        }
    }

    let grid = best_grid?;
    let bits: String = grid
        .into_iter()
        .map(|b| if b { '1' } else { '0' })
        .collect();
    Some(QrMatrix { size, bits })
}

fn push_bits(out: &mut Vec<bool>, val: u32, count: usize) {
    for i in (0..count).rev() {
        out.push(((val >> i) & 1) != 0);
    }
}

fn build_data_codewords(data: &[u8], spec: &VersionSpec) -> Vec<u8> {
    let total_bits = spec.total_data_codewords() * 8;
    let mut bits = Vec::with_capacity(total_bits);

    // Byte mode indicator (0100) + byte length.
    push_bits(&mut bits, 0b0100, 4);
    push_bits(&mut bits, data.len() as u32, spec.cc_bits());
    for &b in data {
        push_bits(&mut bits, u32::from(b), 8);
    }

    // Terminator (up to 4 zero bits) + zero-pad to byte boundary.
    let term = (total_bits - bits.len()).min(4);
    bits.resize(bits.len() + term, false);
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }

    let mut cw = Vec::with_capacity(spec.total_data_codewords());
    for chunk in bits.as_chunks::<8>().0 {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | u8::from(bit);
        }
        cw.push(byte);
    }

    // Alternating pad bytes 0xEC, 0x11.
    let mut pad_idx = 0;
    while cw.len() < spec.total_data_codewords() {
        cw.push(if pad_idx % 2 == 0 { 0xEC } else { 0x11 });
        pad_idx += 1;
    }
    cw
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1D; // primitive polynomial 0x11D
        }
        b >>= 1;
    }
    p
}

fn rs_generator_poly(degree: usize) -> Vec<u8> {
    let mut poly = vec![1u8];
    let mut root = 1u8;
    for _ in 0..degree {
        let mut next = vec![0u8; poly.len() + 1];
        for (i, &c) in poly.iter().enumerate() {
            next[i] ^= c;
            next[i + 1] ^= gf_mul(c, root);
        }
        poly = next;
        root = gf_mul(root, 2);
    }
    poly
}

fn rs_remainder(data: &[u8], ec_len: usize) -> Vec<u8> {
    let g = rs_generator_poly(ec_len);
    let mut rem = vec![0u8; ec_len];
    for &byte in data {
        let factor = byte ^ rem[0];
        rem.rotate_left(1);
        rem[ec_len - 1] = 0;
        for i in 0..ec_len {
            rem[i] ^= gf_mul(g[i + 1], factor);
        }
    }
    rem
}

fn interleave_with_ec(data_cw: &[u8], spec: &VersionSpec) -> Vec<u8> {
    let mut data_blocks: Vec<&[u8]> = Vec::with_capacity(spec.g1_blocks + spec.g2_blocks);
    let mut ec_blocks: Vec<Vec<u8>> = Vec::with_capacity(spec.g1_blocks + spec.g2_blocks);
    let mut off = 0;

    for _ in 0..spec.g1_blocks {
        let blk = &data_cw[off..off + spec.g1_data];
        off += spec.g1_data;
        ec_blocks.push(rs_remainder(blk, spec.ec_per_block));
        data_blocks.push(blk);
    }
    for _ in 0..spec.g2_blocks {
        let blk = &data_cw[off..off + spec.g2_data];
        off += spec.g2_data;
        ec_blocks.push(rs_remainder(blk, spec.ec_per_block));
        data_blocks.push(blk);
    }

    let max_data = spec.g1_data.max(spec.g2_data);
    let mut out = Vec::with_capacity(data_cw.len() + ec_blocks.len() * spec.ec_per_block);
    for i in 0..max_data {
        for blk in &data_blocks {
            if let Some(&b) = blk.get(i) {
                out.push(b);
            }
        }
    }
    for i in 0..spec.ec_per_block {
        for ec in &ec_blocks {
            out.push(ec[i]);
        }
    }
    out
}

fn set_func(grid: &mut [bool], func: &mut [bool], size: usize, r: usize, c: usize, dark: bool) {
    let idx = r * size + c;
    grid[idx] = dark;
    func[idx] = true;
}

fn place_finder(grid: &mut [bool], func: &mut [bool], size: usize, top: usize, left: usize) {
    for dr in -1isize..=7 {
        for dc in -1isize..=7 {
            let r = top as isize + dr;
            let c = left as isize + dc;
            if r < 0 || c < 0 || r >= size as isize || c >= size as isize {
                continue;
            }
            let dark = (0..=6).contains(&dr)
                && (0..=6).contains(&dc)
                && (dr == 0
                    || dr == 6
                    || dc == 0
                    || dc == 6
                    || ((2..=4).contains(&dr) && (2..=4).contains(&dc)));
            set_func(grid, func, size, r as usize, c as usize, dark);
        }
    }
}

fn place_alignment(grid: &mut [bool], func: &mut [bool], size: usize, cr: usize, cc: usize) {
    for dr in -2isize..=2 {
        for dc in -2isize..=2 {
            let r = (cr as isize + dr) as usize;
            let c = (cc as isize + dc) as usize;
            let dist = dr.abs().max(dc.abs());
            set_func(grid, func, size, r, c, dist != 1);
        }
    }
}

fn format_bits_m(mask: u8) -> u16 {
    // ECC Level M = 0b00; 5-bit payload = mask (0..=7).
    let data = u16::from(mask & 7);
    let mut rem = data << 10;
    for i in (10..=14).rev() {
        if ((rem >> i) & 1) != 0 {
            rem ^= 0x537 << (i - 10);
        }
    }
    ((data << 10) | rem) ^ 0x5412
}

fn version_bits(version: u8) -> u32 {
    let data = u32::from(version);
    let mut rem = data << 12;
    for i in (12..=17).rev() {
        if ((rem >> i) & 1) != 0 {
            rem ^= 0x1F25 << (i - 12);
        }
    }
    (data << 12) | rem
}

fn place_function_patterns(spec: &VersionSpec, size: usize, grid: &mut [bool], func: &mut [bool]) {
    // 1) Finder patterns + separators.
    place_finder(grid, func, size, 0, 0);
    place_finder(grid, func, size, 0, size - 7);
    place_finder(grid, func, size, size - 7, 0);

    // 2) Timing patterns (row 6 and col 6).
    for i in 8..size - 8 {
        let dark = i % 2 == 0;
        set_func(grid, func, size, 6, i, dark);
        set_func(grid, func, size, i, 6, dark);
    }

    // 3) Alignment patterns (skipping corners overlapping finder patterns).
    for &r in spec.align {
        for &c in spec.align {
            let overlaps_finder =
                (r <= 8 && c <= 8) || (r <= 8 && c >= size - 8) || (r >= size - 8 && c <= 8);
            if !overlaps_finder {
                place_alignment(grid, func, size, r, c);
            }
        }
    }

    // 4) Reserve format info slots + dark module at (size - 8, 8).
    for i in 0..9 {
        if i != 6 {
            set_func(grid, func, size, 8, i, false);
            set_func(grid, func, size, i, 8, false);
        }
    }
    for i in 0..8 {
        set_func(grid, func, size, 8, size - 8 + i, false);
    }
    for i in 0..7 {
        set_func(grid, func, size, size - 7 + i, 8, false);
    }
    set_func(grid, func, size, size - 8, 8, true);

    // 5) Version info blocks for Version 7+.
    if spec.version >= 7 {
        let vb = version_bits(spec.version);
        for i in 0..18 {
            let dark = ((vb >> i) & 1) != 0;
            let a = size - 11 + (i % 3);
            let b = i / 3;
            set_func(grid, func, size, a, b, dark);
            set_func(grid, func, size, b, a, dark);
        }
    }
}

fn write_format_bits(mask: u8, size: usize, grid: &mut [bool]) {
    let bits = format_bits_m(mask);
    let bit = |pos: u8| ((bits >> pos) & 1) != 0;

    // Copy 1 around top-left finder (MSB = bit 14 down to LSB = bit 0).
    let copy1: [(usize, usize); 15] = [
        (8, 0),
        (8, 1),
        (8, 2),
        (8, 3),
        (8, 4),
        (8, 5),
        (8, 7),
        (8, 8),
        (7, 8),
        (5, 8),
        (4, 8),
        (3, 8),
        (2, 8),
        (1, 8),
        (0, 8),
    ];
    for (idx, &(r, c)) in copy1.iter().enumerate() {
        grid[r * size + c] = bit(14 - idx as u8);
    }

    // Copy 2 along bottom-left (bits 14..=8) and top-right (bits 7..=0).
    for i in 0..7 {
        grid[(size - 1 - i) * size + 8] = bit(14 - i as u8);
    }
    for i in 0..8 {
        grid[8 * size + (size - 8 + i)] = bit(7 - i as u8);
    }
}

fn place_data_bits(codewords: &[u8], size: usize, grid: &mut [bool], func: &[bool]) {
    let mut bit_idx = 0usize;
    let total_bits = codewords.len() * 8;
    let mut upward = true;
    let mut col = size as isize - 1;

    while col > 0 {
        if col == 6 {
            col -= 1; // Skip vertical timing pattern column.
        }
        for step in 0..size {
            let row = if upward { size - 1 - step } else { step };
            for dx in 0..2 {
                let c = (col - dx) as usize;
                let idx = row * size + c;
                if func[idx] {
                    continue;
                }
                let dark = if bit_idx < total_bits {
                    let byte = codewords[bit_idx / 8];
                    ((byte >> (7 - (bit_idx % 8))) & 1) != 0
                } else {
                    false
                };
                grid[idx] = dark;
                bit_idx += 1;
            }
        }
        upward = !upward;
        col -= 2;
    }
}

fn mask_bit(mask: u8, r: usize, c: usize) -> bool {
    match mask {
        0 => (r + c).is_multiple_of(2),
        1 => r.is_multiple_of(2),
        2 => c.is_multiple_of(3),
        3 => (r + c).is_multiple_of(3),
        4 => (r / 2 + c / 3).is_multiple_of(2),
        5 => (r * c) % 2 + (r * c) % 3 == 0,
        6 => ((r * c) % 2 + (r * c) % 3).is_multiple_of(2),
        7 => ((r + c) % 2 + (r * c) % 3).is_multiple_of(2),
        _ => false,
    }
}

fn apply_mask(mask: u8, size: usize, grid: &mut [bool], func: &[bool]) {
    for r in 0..size {
        for c in 0..size {
            let idx = r * size + c;
            if !func[idx] && mask_bit(mask, r, c) {
                grid[idx] = !grid[idx];
            }
        }
    }
}

fn line_penalty(iter: impl Iterator<Item = bool>) -> u32 {
    let mut score = 0u32;
    let mut run_color = false;
    let mut run_len = 0u32;
    let mut history = 0u16;
    let mut seen = 0usize;

    for dark in iter {
        if seen == 0 || dark != run_color {
            run_color = dark;
            run_len = 1;
        } else {
            run_len += 1;
            if run_len == 5 {
                score += 3;
            } else if run_len > 5 {
                score += 1;
            }
        }
        history = ((history << 1) | u16::from(dark)) & 0x7FF;
        seen += 1;
        // Finder-like pattern 10111010000 (0x5D0) or 00001011101 (0x05D).
        if seen >= 11 && (history == 0x5D0 || history == 0x05D) {
            score += 40;
        }
    }
    score
}

fn penalty(grid: &[bool], size: usize) -> u32 {
    let mut score = 0u32;

    // Rule 1 (runs) & Rule 3 (finder-like patterns) along rows and cols.
    for r in 0..size {
        score += line_penalty((0..size).map(|c| grid[r * size + c]));
    }
    for c in 0..size {
        score += line_penalty((0..size).map(|r| grid[r * size + c]));
    }

    // Rule 2: 2x2 same-color blocks.
    for r in 0..size - 1 {
        for c in 0..size - 1 {
            let v = grid[r * size + c];
            if grid[r * size + c + 1] == v
                && grid[(r + 1) * size + c] == v
                && grid[(r + 1) * size + c + 1] == v
            {
                score += 3;
            }
        }
    }

    // Rule 4: dark module balance around 50%.
    let dark = grid.iter().filter(|&&b| b).count();
    let total = size * size;
    let pct_dev = ((dark as isize * 20 - total as isize * 10).unsigned_abs()) / total;
    score += (pct_dev as u32) * 10;

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_and_version_bits_match_iso_18004_tables() {
        // ISO/IEC 18004 Annex C Table C.1 (ECC Level M, masks 0..=7).
        assert_eq!(format_bits_m(0), 0x5412);
        assert_eq!(format_bits_m(1), 0x5125);
        assert_eq!(format_bits_m(2), 0x5E7C);
        assert_eq!(format_bits_m(3), 0x5B4B);
        assert_eq!(format_bits_m(4), 0x45F9);
        assert_eq!(format_bits_m(5), 0x40CE);
        assert_eq!(format_bits_m(6), 0x4F97);
        assert_eq!(format_bits_m(7), 0x4AA0);

        // ISO/IEC 18004 Annex D Table D.1 (Versions 7..=10).
        assert_eq!(version_bits(7), 0x07C94);
        assert_eq!(version_bits(8), 0x085BC);
        assert_eq!(version_bits(9), 0x09A99);
        assert_eq!(version_bits(10), 0x0A4D3);
    }

    #[test]
    fn reed_solomon_remainder_matches_iso_18004_example() {
        // ISO/IEC 18004 Annex I / standard Version 1-M "HELLO WORLD" (16 data cw, 10 ec cw):
        let data = [
            32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17,
        ];
        let expected_ec = [196, 35, 39, 119, 235, 215, 231, 226, 93, 23];
        assert_eq!(rs_remainder(&data, 10), expected_ec);
    }

    #[test]
    fn encodes_login_and_approve_urls_with_valid_geometry() {
        let url =
            "https://lets-embed.louisfly.icu/user/login?transfer=AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        let qr = encode(url.as_bytes()).expect("fits in V5/V6");
        assert_eq!(qr.bits.len(), qr.size * qr.size);
        // Version 5 (37x37) or Version 6 (41x41) depending on exact length (84 bytes -> V5 = 37).
        assert_eq!(qr.size, 37);

        let at = |r: usize, c: usize| qr.bits.as_bytes()[r * qr.size + c] == b'1';
        // Top-left finder center 3x3 dark, ring light, outer border dark.
        assert!(at(0, 0) && at(0, 6) && at(6, 0) && at(6, 6));
        assert!(!at(1, 1) && !at(1, 5) && !at(5, 1) && !at(5, 5));
        assert!(at(3, 3));
        // Dark module at (size - 8, 8).
        assert!(at(qr.size - 8, 8));
        // Timing pattern alternates starting dark at (6, 8).
        assert!(at(6, 8) && !at(6, 9) && at(6, 10));

        // Version 7+ (125+ bytes) exercises version info blocks + two-group interleaving.
        let long_url = format!(
            "https://lets-embed.louisfly.icu/user/login?transfer={}",
            "a".repeat(120)
        );
        let long_qr = encode(long_url.as_bytes()).expect("fits in V9");
        assert!(long_qr.size >= 45);
        assert_eq!(long_qr.bits.len(), long_qr.size * long_qr.size);

        // Over 213 bytes cleanly returns None.
        assert!(encode(&vec![b'x'; 214]).is_none());
    }

    #[test]
    fn full_decode_roundtrip_across_versions_1_to_10() {
        // Verify bit unmasking, de-interleaving, Reed-Solomon zero syndromes,
        // and exact Byte-mode payload recovery across V1, V5, V7, V8 (2-group), and V10.
        let payloads = [
            b"hello".to_vec(),
            b"https://lets-embed.louisfly.icu/user/login#transfer=AbCdEfGhIjKlMnOpQrStUvWxYz012345"
                .to_vec(),
            vec![b'A'; 118], // V7 (version info blocks)
            vec![b'B'; 145], // V8 (2-group block interleaving)
            vec![b'C'; 210], // V10 (16-bit byte count + 2-group interleaving)
        ];

        for payload in payloads {
            let qr = encode(&payload).expect("payload fits in V1-10");
            let spec = SPECS_M
                .iter()
                .find(|s| usize::from(s.version) * 4 + 17 == qr.size)
                .expect("matching version spec");

            let grid: Vec<bool> = qr.bits.bytes().map(|b| b == b'1').collect();
            let mut dummy = vec![false; qr.size * qr.size];
            let mut func = vec![false; qr.size * qr.size];
            place_function_patterns(spec, qr.size, &mut dummy, &mut func);

            // Recover mask from format copy 1 around top-left finder.
            let copy1: [(usize, usize); 15] = [
                (8, 0),
                (8, 1),
                (8, 2),
                (8, 3),
                (8, 4),
                (8, 5),
                (8, 7),
                (8, 8),
                (7, 8),
                (5, 8),
                (4, 8),
                (3, 8),
                (2, 8),
                (1, 8),
                (0, 8),
            ];
            let mut fmt_bits = 0u16;
            for &(r, c) in &copy1 {
                fmt_bits = (fmt_bits << 1) | u16::from(grid[r * qr.size + c]);
            }
            let mask = (0..8u8)
                .find(|&m| format_bits_m(m) == fmt_bits)
                .expect("valid BCH format info");

            // Extract unmasked zigzag codewords.
            let total_cw =
                spec.total_data_codewords() + (spec.g1_blocks + spec.g2_blocks) * spec.ec_per_block;
            let mut bits = Vec::with_capacity(total_cw * 8);
            let mut upward = true;
            let mut col = qr.size as isize - 1;
            while col > 0 {
                if col == 6 {
                    col -= 1;
                }
                for step in 0..qr.size {
                    let row = if upward { qr.size - 1 - step } else { step };
                    for dx in 0..2 {
                        let c = (col - dx) as usize;
                        let idx = row * qr.size + c;
                        if func[idx] {
                            continue;
                        }
                        if bits.len() < total_cw * 8 {
                            bits.push(grid[idx] ^ mask_bit(mask, row, c));
                        }
                    }
                }
                upward = !upward;
                col -= 2;
            }
            let raw_cw: Vec<u8> = bits
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | u8::from(b)))
                .collect();

            // De-interleave data + EC blocks and check exact RS remainder match.
            let num_blocks = spec.g1_blocks + spec.g2_blocks;
            let mut data_blocks: Vec<Vec<u8>> = (0..num_blocks)
                .map(|b| {
                    Vec::with_capacity(if b < spec.g1_blocks {
                        spec.g1_data
                    } else {
                        spec.g2_data
                    })
                })
                .collect();
            let mut ec_blocks: Vec<Vec<u8>> = (0..num_blocks)
                .map(|_| Vec::with_capacity(spec.ec_per_block))
                .collect();
            let mut cursor = 0usize;
            for i in 0..spec.g1_data.max(spec.g2_data) {
                for (b, blk) in data_blocks.iter_mut().enumerate() {
                    let cap = if b < spec.g1_blocks {
                        spec.g1_data
                    } else {
                        spec.g2_data
                    };
                    if i < cap {
                        blk.push(raw_cw[cursor]);
                        cursor += 1;
                    }
                }
            }
            for _ in 0..spec.ec_per_block {
                for ec in &mut ec_blocks {
                    ec.push(raw_cw[cursor]);
                    cursor += 1;
                }
            }
            assert_eq!(cursor, raw_cw.len());
            for (d, ec) in data_blocks.iter().zip(ec_blocks.iter()) {
                assert_eq!(
                    rs_remainder(d, spec.ec_per_block),
                    *ec,
                    "RS mismatch for V{}",
                    spec.version
                );
            }

            // Reconstruct Byte-mode payload and assert exact equality.
            let stream: Vec<bool> = data_blocks
                .into_iter()
                .flatten()
                .flat_map(|byte| (0..8).rev().map(move |bit| ((byte >> bit) & 1) != 0))
                .collect();
            let read_u32 = |off: usize, n: usize| -> u32 {
                (0..n).fold(0u32, |acc, i| (acc << 1) | u32::from(stream[off + i]))
            };
            assert_eq!(read_u32(0, 4), 0b0100);
            let len = read_u32(4, spec.cc_bits()) as usize;
            assert_eq!(len, payload.len());
            let mut decoded = Vec::with_capacity(len);
            let base = 4 + spec.cc_bits();
            for i in 0..len {
                decoded.push(read_u32(base + i * 8, 8) as u8);
            }
            assert_eq!(decoded, payload);
        }
    }
}
