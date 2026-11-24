use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashSet},
    io::{BufReader, Read, Seek},
    path::Path,
};

use anyhow::bail;
use fast_image_resize::{
    FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer,
    images::{CroppedImageMut, Image},
};
use ort::{environment::Environment, ep, inputs, session::Session, value::Tensor};

pub const OUT_DIM: usize = 10861;

pub const IMAGE_WIDTH: usize = 448;
pub const IMAGE_HEIGHT: usize = 448;
pub const IMAGE_CHANNEL: usize = 3;

/// Default minimum tag score persisted for every completed image (Policy v3
/// floor coverage). Storing every tag with `score >= DEFAULT_MIN_PERSISTED_SCORE`
/// (plus all 4 category-9 ratings and all 20 built-in safety tags unconditionally)
/// lets the Policy v3 3-valued evaluator treat absent rows as `False` whenever
/// `wd_min_persisted_score <= threshold`.
pub const DEFAULT_MIN_PERSISTED_SCORE: f32 = 0.05;

/// Canonical lowercase hex SHA-256 digest of the sorted, `\n`-joined
/// 10,861-name WD-Tagger v3 vocabulary (matching `search_types::wd_vocab::WD_VOCAB_DIGEST`).
pub const WD_VOCAB_DIGEST: &str =
    "760e0e0b36eff91fe713495c20e3f0ecf49cd958b8033b3c454c97f3abfd339c";

/// The four WD-Tagger category-9 rating tags, always persisted regardless of
/// `top_k`, `min_persisted_score`, or `general_threshold`.
pub const RATING_TAG_NAMES: &[&str] = &["general", "sensitive", "questionable", "explicit"];

/// Built-in safety-vocabulary tags (category-9 ratings + preset rule tags)
/// persisted unconditionally during ingestion so safety rules never miss tags
/// truncated by `top_k`.
pub const DEFAULT_SAFETY_TAGS: &[&str] = &[
    "general",
    "sensitive",
    "questionable",
    "explicit",
    "nude",
    "nipples",
    "pussy",
    "penis",
    "sex",
    "uncensored",
    "censored",
    "topless",
    "bottomless",
    "lingerie",
    "bikini",
    "underwear",
    "panties",
    "cleavage",
    "bdsm",
    "blood",
];

pub fn default_safety_tag_set() -> HashSet<String> {
    DEFAULT_SAFETY_TAGS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Canonical lowercase hex SHA-256 digest of the ordered WD-Tagger v3
/// `selected_tags.csv` manifest (`"{index}:{G|C|R}:{name}"` joined by `'\n'`).
/// Guards against silently pairing inference logits with a reordered or altered CSV.
pub const WD_ORDERED_MANIFEST_DIGEST: &str =
    "833a2120d0b02f720cf317ce4d831fb175292c9255bc04390829356face6aa46";

/// Computes the canonical lowercase hex SHA-256 digest of a WD-Tagger vocabulary:
/// unique tag names sorted in ASCII byte order and joined with `'\n'` (no trailing newline).
pub fn compute_vocab_digest(tags: &[Tag]) -> String {
    let mut names: Vec<&str> = tags
        .iter()
        .map(|t| t.name.trim())
        .filter(|n| !n.is_empty())
        .collect();
    names.sort_unstable();
    names.dedup();
    let joined = names.join("\n");
    sha256_hex(joined.as_bytes())
}

/// Computes the order- and category-sensitive SHA-256 digest over `(index, type, name)`
/// so a reordered or miscategorized `selected_tags.csv` cannot pass validation.
pub fn compute_ordered_manifest_digest(tags: &[Tag]) -> String {
    use std::fmt::Write as _;
    let mut buf = String::with_capacity(tags.len() * 24);
    for (idx, tag) in tags.iter().enumerate() {
        if idx > 0 {
            buf.push('\n');
        }
        let cat = match tag.r#type {
            TagType::Character => 'C',
            TagType::Rating => 'R',
            TagType::General => 'G',
        };
        let _ = write!(buf, "{idx}:{cat}:{}", tag.name);
    }
    sha256_hex(buf.as_bytes())
}

/// Verifies that `tags` has exact length [`OUT_DIM`] and exact positional `(index, category, name)`
/// alignment matching [`WD_ORDERED_MANIFEST_DIGEST`].
pub fn verify_ordered_manifest(tags: &[Tag]) -> anyhow::Result<()> {
    if tags.len() != OUT_DIM {
        bail!(
            "WD-Tagger CSV has {} tags, expected exact OUT_DIM={OUT_DIM}",
            tags.len()
        );
    }
    let actual = compute_ordered_manifest_digest(tags);
    if actual != WD_ORDERED_MANIFEST_DIGEST {
        bail!(
            "WD-Tagger CSV positional/category manifest digest mismatch: got {actual}, expected {WD_ORDERED_MANIFEST_DIGEST} (CSV may be reordered or from a different model)"
        );
    }
    Ok(())
}

/// Pure-Rust FIPS 180-4 SHA-256 returning lowercase hex (keeps `wd_tagger` free of extra crates).
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

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
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

pub fn model(model_path: impl AsRef<Path>) -> ort::Result<Session> {
    let env = ort::init().build()?;
    model_with_env(&env, model_path)
}

pub fn model_with_env(env: &Environment, model_path: impl AsRef<Path>) -> ort::Result<Session> {
    let session = Session::builder(env)?
        .with_execution_providers([
            #[cfg(not(target_os = "macos"))]
            ep::CUDA::default().build(),
            #[cfg(target_os = "macos")]
            ep::WebGPU::default().build(),
        ])
        .unwrap()
        .commit_from_file(model_path)?;

    Ok(session)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TagType {
    General,
    Character,
    Rating,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tag {
    pub r#type: TagType,
    pub name: String,
}

/// Parses WD-Tagger `selected_tags.csv` rows without asserting [`OUT_DIM`].
///
/// Category `"4"` maps to [`TagType::Character`], `"9"` maps to [`TagType::Rating`],
/// and all other categories map to [`TagType::General`].
pub fn parse_tags_csv<R: Read>(reader: R) -> anyhow::Result<Vec<Tag>> {
    let mut csv_reader = csv::Reader::from_reader(reader);
    let mut tags = Vec::new();
    for r in csv_reader.records() {
        let r = r?;
        tags.push(Tag {
            r#type: match r.get(2) {
                Some("4") => TagType::Character,
                Some("9") => TagType::Rating,
                _ => TagType::General,
            },
            name: r.get(1).unwrap_or_default().to_string(),
        });
    }
    Ok(tags)
}

pub fn tags(csv_path: impl AsRef<Path>) -> anyhow::Result<Vec<Tag>> {
    let file = std::fs::File::open(csv_path)?;
    let tags = parse_tags_csv(BufReader::new(file))?;

    verify_ordered_manifest(&tags)?;

    Ok(tags)
}

/// `tags` should be [`OUT_DIM`] long.
///
/// Returns top_k `(tag, p)` pairs plus all [`TagType::Rating`] tags (always
/// retained regardless of `top_k` and thresholds).
pub fn infer_tag<'a>(
    session: &mut Session,
    batch_input: Vec<Vec<f32>>,
    tags: &'a [Tag],
    top_k: usize,
    general_threshold: f32,
    character_threshold: f32,
) -> anyhow::Result<Vec<Vec<(&'a Tag, f32)>>> {
    infer_tag_with_safety(
        session,
        batch_input,
        tags,
        top_k,
        general_threshold,
        character_threshold,
        None,
    )
}

/// Runs WD-Tagger inference and selects top-`top_k` tags above threshold while
/// unconditionally retaining every [`TagType::Rating`] tag and every tag whose
/// canonical name appears in `always_keep_tags`.
pub fn infer_tag_with_safety<'a>(
    session: &mut Session,
    batch_input: Vec<Vec<f32>>,
    tags: &'a [Tag],
    top_k: usize,
    general_threshold: f32,
    character_threshold: f32,
    always_keep_tags: Option<&HashSet<String>>,
) -> anyhow::Result<Vec<Vec<(&'a Tag, f32)>>> {
    verify_ordered_manifest(tags)?;
    let batch_size = batch_input.len();
    let pixel_values = batch_input.into_iter().flatten().collect::<Vec<_>>();

    if pixel_values.len() != batch_size * IMAGE_HEIGHT * IMAGE_WIDTH * IMAGE_CHANNEL {
        bail!("invalid input image size")
    }

    let output = session.run(inputs![
        "input" => Tensor::from_array(([batch_size, IMAGE_HEIGHT, IMAGE_WIDTH, IMAGE_CHANNEL], pixel_values))?,
    ])?;

    let (shape, predictions) = output["output"].try_extract_tensor::<f32>()?;

    debug_assert_eq!(shape[0], batch_size as i64);
    debug_assert_eq!(shape[1], OUT_DIM as i64);

    let tags = predictions
        .chunks(OUT_DIM)
        .map(|prediction| {
            select_tags(
                prediction,
                top_k,
                general_threshold,
                character_threshold,
                tags,
                always_keep_tags,
            )
        })
        .collect();

    Ok(tags)
}

/// Runs WD-Tagger inference with Policy v3 floor coverage: persists EVERY tag
/// whose predicted score is `>= min_persisted_score` (with NO `top_k` truncation
/// that could hide safety tags), PLUS unconditionally all 4 category-9
/// [`TagType::Rating`] tags and every tag in `always_keep_tags`.
pub fn infer_tag_with_coverage<'a>(
    session: &mut Session,
    batch_input: Vec<Vec<f32>>,
    tags: &'a [Tag],
    min_persisted_score: f32,
    always_keep_tags: Option<&HashSet<String>>,
) -> anyhow::Result<Vec<Vec<(&'a Tag, f32)>>> {
    verify_ordered_manifest(tags)?;
    if !min_persisted_score.is_finite() || min_persisted_score <= 0.0 || min_persisted_score > 1.0 {
        bail!("min_persisted_score must be finite and in (0.0, 1.0]")
    }
    let batch_size = batch_input.len();
    let pixel_values = batch_input.into_iter().flatten().collect::<Vec<_>>();

    if pixel_values.len() != batch_size * IMAGE_HEIGHT * IMAGE_WIDTH * IMAGE_CHANNEL {
        bail!("invalid input image size")
    }

    let output = session.run(inputs![
        "input" => Tensor::from_array(([batch_size, IMAGE_HEIGHT, IMAGE_WIDTH, IMAGE_CHANNEL], pixel_values))?,
    ])?;

    let (shape, predictions) = output["output"].try_extract_tensor::<f32>()?;

    debug_assert_eq!(shape[0], batch_size as i64);
    debug_assert_eq!(shape[1], OUT_DIM as i64);

    let tags = predictions
        .chunks(OUT_DIM)
        .map(|prediction| {
            select_tags_with_floor(prediction, min_persisted_score, tags, always_keep_tags)
        })
        .collect();

    Ok(tags)
}

/// Pure floor-coverage tag-selection step for a single prediction vector.
///
/// Retains EVERY tag with `score >= min_persisted_score` without any `top_k`
/// truncation, plus unconditionally all [`TagType::Rating`] tags and every tag
/// in `always_keep_tags` regardless of score. Returns results sorted descending
/// by score with zero duplicates.
pub fn select_tags_with_floor<'a>(
    prediction: &[f32],
    min_persisted_score: f32,
    tags: &'a [Tag],
    always_keep_tags: Option<&HashSet<String>>,
) -> Vec<(&'a Tag, f32)> {
    debug_assert_eq!(prediction.len(), tags.len());
    let mut result: Vec<(&'a Tag, f32)> = Vec::new();
    for (&val, tag) in prediction.iter().zip(tags) {
        let must_keep = tag.r#type == TagType::Rating
            || always_keep_tags.is_some_and(|set| set.contains(&tag.name));
        if must_keep || (val.is_finite() && val >= min_persisted_score) {
            result.push((tag, val));
        }
    }
    result.sort_unstable_by(|a, b| b.1.total_cmp(&a.1));
    result
}

/// Pure tag-selection step for a single prediction vector.
///
/// Always includes every [`TagType::Rating`] tag and every tag in
/// `always_keep_tags` regardless of `top_k`, `general_threshold`, or
/// `character_threshold`, without deduplication bugs or consuming `top_k`
/// capacity from general/character tags.
pub fn select_tags<'a>(
    prediction: &[f32],
    top_k: usize,
    general_threshold: f32,
    character_threshold: f32,
    tags: &'a [Tag],
    always_keep_tags: Option<&HashSet<String>>,
) -> Vec<(&'a Tag, f32)> {
    top_k_heap(
        prediction,
        top_k,
        general_threshold,
        character_threshold,
        tags,
        always_keep_tags,
    )
}

/// Returns HWC BGR (black padded if ratio not match).
///
/// Normalization is not needed in preprocess of wd-tagger.
pub fn convert_image<R: Read + Seek>(r: R) -> anyhow::Result<Vec<f32>> {
    let src_image = image::ImageReader::new(BufReader::new(r))
        .with_guessed_format()?
        .decode()?
        .to_rgb8();

    let (w, h) = src_image.dimensions();
    let r = (IMAGE_WIDTH as f32 / w as f32).min(IMAGE_HEIGHT as f32 / h as f32);
    let nw = ((w as f32 * r).round() as u32).max(1);
    let nh = ((h as f32 * r).round() as u32).max(1);
    let dx = (IMAGE_WIDTH as i32 - nw as i32).unsigned_abs() / 2;
    let dy = (IMAGE_HEIGHT as i32 - nh as i32).unsigned_abs() / 2;

    let mut dst_image = Image::new(IMAGE_WIDTH as u32, IMAGE_HEIGHT as u32, PixelType::U8x3);
    let mut view = CroppedImageMut::new(&mut dst_image, dx, dy, nw, nh)?;

    let mut resizer = Resizer::new();
    resizer.resize(
        &src_image,
        &mut view,
        &ResizeOptions::new().resize_alg(ResizeAlg::Interpolation(FilterType::CatmullRom)),
    )?;

    let mut hwc = dst_image
        .buffer()
        .iter()
        .map(|i| *i as f32)
        .collect::<Vec<_>>();

    for pix in hwc.chunks_mut(3) {
        pix.reverse(); // rgb -> bgr
    }

    Ok(hwc)
}

#[derive(PartialEq)]
struct FloatOrd(f32);

impl Eq for FloatOrd {}

impl PartialOrd for FloatOrd {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FloatOrd {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

fn top_k_heap<'a>(
    vec: &[f32],
    k: usize,
    general_threshold: f32,
    character_threshold: f32,
    tags: &'a [Tag],
    always_keep_tags: Option<&HashSet<String>>,
) -> Vec<(&'a Tag, f32)> {
    debug_assert_eq!(vec.len(), tags.len());

    let mut heap: BinaryHeap<Reverse<(FloatOrd, usize)>> = BinaryHeap::with_capacity(k + 1);
    let mut always_kept: Vec<(&'a Tag, f32)> = Vec::new();

    for (i, (&val, tag)) in vec.iter().zip(tags).enumerate() {
        let must_keep = tag.r#type == TagType::Rating
            || always_keep_tags.is_some_and(|set| set.contains(&tag.name));
        if must_keep {
            always_kept.push((tag, val));
            continue;
        }

        let threshold = match tag.r#type {
            TagType::General => general_threshold,
            TagType::Character => character_threshold,
            TagType::Rating => unreachable!(),
        };
        if val < threshold || k == 0 {
            continue;
        }

        if heap.len() < k {
            heap.push(Reverse((FloatOrd(val), i)));
        } else if let Some(&Reverse((FloatOrd(min_val), _))) = heap.peek()
            && val > min_val
        {
            heap.pop();
            heap.push(Reverse((FloatOrd(val), i)));
        }
    }

    let mut result: Vec<(&'a Tag, f32)> = Vec::with_capacity(heap.len() + always_kept.len());
    result.extend(
        heap.into_iter()
            .map(|Reverse((FloatOrd(val), idx))| (&tags[idx], val)),
    );
    result.extend(always_kept);
    result.sort_unstable_by(|a, b| b.1.total_cmp(&a.1));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_csv_category_9_as_rating_type() {
        let csv_data = "\
tag_id,name,category,count
9999999,general,9,1000
9999998,sensitive,9,500
9999997,questionable,9,200
9999996,explicit,9,100
1,1girl,0,50000
2,hakurei_reimu,4,10000
";
        let parsed = parse_tags_csv(csv_data.as_bytes()).expect("valid csv");
        assert_eq!(parsed.len(), 6);
        assert_eq!(parsed[0].r#type, TagType::Rating);
        assert_eq!(parsed[0].name, "general");
        assert_eq!(parsed[1].r#type, TagType::Rating);
        assert_eq!(parsed[2].r#type, TagType::Rating);
        assert_eq!(parsed[3].r#type, TagType::Rating);
        assert_eq!(parsed[4].r#type, TagType::General);
        assert_eq!(parsed[5].r#type, TagType::Character);
    }

    #[test]
    fn preserves_all_rating_and_safety_tags_even_when_40_general_tags_score_higher() {
        let mut tags = vec![
            Tag {
                r#type: TagType::Rating,
                name: "general".into(),
            },
            Tag {
                r#type: TagType::Rating,
                name: "sensitive".into(),
            },
            Tag {
                r#type: TagType::Rating,
                name: "questionable".into(),
            },
            Tag {
                r#type: TagType::Rating,
                name: "explicit".into(),
            },
            Tag {
                r#type: TagType::General,
                name: "blood".into(),
            },
            Tag {
                r#type: TagType::General,
                name: "nude".into(),
            },
        ];
        // Rating & safety scores deliberately low (below general_threshold = 0.30)
        // and lower than all 40 general tags below.
        let mut scores = vec![0.05, 0.10, 0.12, 0.18, 0.22, 0.99];

        for i in 0..40 {
            tags.push(Tag {
                r#type: TagType::General,
                name: format!("high_general_{i}"),
            });
            scores.push(0.50 + (i as f32) * 0.01);
        }

        // Without always_keep_tags: all 4 Rating tags MUST still be preserved alongside top_k=36.
        let res_ratings_only = select_tags(&scores, 36, 0.30, 0.75, &tags, None);
        let names_only: HashSet<&str> = res_ratings_only
            .iter()
            .map(|(t, _)| t.name.as_str())
            .collect();
        for rating in RATING_TAG_NAMES {
            assert!(
                names_only.contains(rating),
                "rating tag '{rating}' must never be dropped"
            );
        }
        assert_eq!(res_ratings_only.len(), 36 + 4);

        // With safety vocabulary set: rating tags AND `blood` (below threshold) AND `nude` (no dup!)
        let safety_set = default_safety_tag_set();
        let res_with_safety = select_tags(&scores, 36, 0.30, 0.75, &tags, Some(&safety_set));
        let names_with_safety: Vec<&str> = res_with_safety
            .iter()
            .map(|(t, _)| t.name.as_str())
            .collect();
        // Zero duplicates
        let unique_count = names_with_safety.iter().copied().collect::<HashSet<_>>().len();
        assert_eq!(unique_count, names_with_safety.len());

        for required in ["general", "sensitive", "questionable", "explicit", "blood", "nude"] {
            assert!(
                names_with_safety.contains(&required),
                "expected '{required}' to be preserved"
            );
        }
        // Full 36 top non-safety general tags + 4 rating + 2 safety tags = 42
        assert_eq!(res_with_safety.len(), 36 + 6);
        // Sorted descending by score (`nude` at 0.99 is first)
        assert_eq!(res_with_safety[0].0.name, "nude");
        assert!(res_with_safety.windows(2).all(|w| w[0].1 >= w[1].1));
    }

    #[test]
    fn floor_coverage_persists_all_above_floor_plus_all_rating_and_safety_tags_without_top_k_truncation()
    {
        let mut tags = Vec::new();
        let mut scores = Vec::new();

        // All 4 category-9 rating tags + 16 remaining built-in safety tags with tiny score 0.001 < 0.05
        for &name in DEFAULT_SAFETY_TAGS {
            let ty = if RATING_TAG_NAMES.contains(&name) {
                TagType::Rating
            } else {
                TagType::General
            };
            tags.push(Tag {
                r#type: ty,
                name: name.to_string(),
            });
            scores.push(0.001);
        }

        // 80 general tags above floor 0.05 (far more than legacy top_k = 36!)
        for i in 0..80 {
            tags.push(Tag {
                r#type: TagType::General,
                name: format!("above_floor_{i}"),
            });
            scores.push(0.05 + (i as f32) * 0.01);
        }

        // 10 general tags below floor 0.05 (should be dropped)
        for i in 0..10 {
            tags.push(Tag {
                r#type: TagType::General,
                name: format!("below_floor_{i}"),
            });
            scores.push(0.049 - (i as f32) * 0.001);
        }

        let safety = default_safety_tag_set();
        let selected = select_tags_with_floor(
            &scores,
            DEFAULT_MIN_PERSISTED_SCORE,
            &tags,
            Some(&safety),
        );

        let selected_names: Vec<&str> = selected.iter().map(|(t, _)| t.name.as_str()).collect();
        let unique: HashSet<&str> = selected_names.iter().copied().collect();
        assert_eq!(unique.len(), selected_names.len(), "no duplicates");
        // All 20 safety/rating tags + all 80 above-floor tags = 100 (NO top_k truncation!)
        assert_eq!(selected.len(), 20 + 80);

        for &required in DEFAULT_SAFETY_TAGS {
            assert!(unique.contains(required), "missing required tag '{required}'");
        }
        for i in 0..80 {
            assert!(
                unique.contains(format!("above_floor_{i}").as_str()),
                "missing above_floor_{i}"
            );
        }
        for i in 0..10 {
            assert!(
                !unique.contains(format!("below_floor_{i}").as_str()),
                "below_floor_{i} should not be persisted"
            );
        }
        assert!(selected.windows(2).all(|w| w[0].1 >= w[1].1));
    }

    #[test]
    fn compute_vocab_digest_matches_canonical_wd_eva02_v3_vocab() {
        let raw = include_str!("../../search_types/data/wd_eva02_v3_tags.txt");
        let tags: Vec<Tag> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| Tag {
                r#type: TagType::General,
                name: l.trim().to_string(),
            })
            .collect();
        assert_eq!(tags.len(), OUT_DIM);
        assert_eq!(compute_vocab_digest(&tags), WD_VOCAB_DIGEST);

        // Order-independent digest (reverse input still hashes identically)
        let mut reversed = tags;
        reversed.reverse();
        assert_eq!(compute_vocab_digest(&reversed), WD_VOCAB_DIGEST);
    }

    #[test]
    fn ordered_manifest_digest_rejects_reordered_or_miscategorized_tags() {
        let mut sample = vec![
            Tag {
                r#type: TagType::Rating,
                name: "general".into(),
            },
            Tag {
                r#type: TagType::Rating,
                name: "explicit".into(),
            },
            Tag {
                r#type: TagType::General,
                name: "1girl".into(),
            },
        ];
        let base_vocab = compute_vocab_digest(&sample);
        let base_ordered = compute_ordered_manifest_digest(&sample);

        // Swapping two entries preserves the set digest, but MUST change the ordered digest!
        sample.swap(0, 1);
        assert_eq!(compute_vocab_digest(&sample), base_vocab);
        assert_ne!(compute_ordered_manifest_digest(&sample), base_ordered);
        sample.swap(0, 1);

        // Changing a tag's category preserves the name set, but MUST change the ordered digest!
        sample[1].r#type = TagType::General;
        assert_eq!(compute_vocab_digest(&sample), base_vocab);
        assert_ne!(compute_ordered_manifest_digest(&sample), base_ordered);

        // If the local model CSV exists in the workspace, verify it passes `verify_ordered_manifest`
        // and that swapping two rows fails immediately.
        let model_csv = Path::new("../models/wd-eva02-large-tagger-v3/selected_tags.csv");
        if model_csv.exists() {
            let mut loaded = tags(model_csv).expect("model CSV must match ordered manifest");
            assert_eq!(loaded.len(), OUT_DIM);
            loaded.swap(0, 3);
            assert!(
                verify_ordered_manifest(&loaded).is_err(),
                "reordered CSV must fail ordered manifest verification"
            );
        }
    }
}
