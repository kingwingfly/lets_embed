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

/// The four WD-Tagger category-9 rating tags, always persisted regardless of
/// `top_k` or `general_threshold`.
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

    assert_eq!(
        OUT_DIM,
        tags.len(),
        "there should be as many tags as wd-tagger OUT_DIM"
    );

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
    if tags.len() != OUT_DIM {
        bail!("invalid tags number")
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
}
