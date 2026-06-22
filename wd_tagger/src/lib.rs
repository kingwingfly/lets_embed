use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    io::{BufReader, Read, Seek},
    path::Path,
};

use anyhow::bail;
use fast_image_resize::{
    FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer,
    images::{CroppedImageMut, Image},
};
use ort::{ep, inputs, session::Session, value::Tensor};

pub const OUT_DIM: usize = 10861;

pub const IMAGE_WIDTH: usize = 448;
pub const IMAGE_HEIGHT: usize = 448;
pub const IMAGE_CHANNEL: usize = 3;

pub fn model(model_path: impl AsRef<Path>) -> ort::Result<Session> {
    let session = Session::builder()?
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tag {
    pub r#type: TagType,
    pub name: String,
}

pub fn tags(csv_path: impl AsRef<Path>) -> anyhow::Result<Vec<Tag>> {
    let mut reader = csv::Reader::from_path(csv_path)?;

    let mut tags = Vec::with_capacity(OUT_DIM);
    for r in reader.records() {
        let r = r?;
        tags.push(Tag {
            r#type: match r.get(2) {
                Some("4") => TagType::Character,
                _ => TagType::General,
            },
            name: r.get(1).unwrap_or_default().to_string(),
        });
    }

    assert_eq!(
        OUT_DIM,
        tags.len(),
        "there should be as many tags as wd-tagger OUT_DIM"
    );

    Ok(tags)
}

/// tags should be [`OUT_DIM`] long.
///
/// Returns top_k `(tag: &str, p: f32)`s
pub fn infer_tag<'a>(
    session: &mut Session,
    batch_input: Vec<Vec<f32>>,
    tags: &'a [Tag],
    top_k: usize,
    general_threshold: f32,
    character_threshold: f32,
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
            top_k_heap(
                prediction,
                top_k,
                general_threshold,
                character_threshold,
                tags,
            )
        })
        .collect();

    Ok(tags)
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
) -> Vec<(&'a Tag, f32)> {
    debug_assert_eq!(vec.len(), tags.len());

    let mut heap: BinaryHeap<Reverse<(FloatOrd, usize)>> = BinaryHeap::with_capacity(k + 1);

    for (i, (&val, _)) in vec.iter().zip(tags).enumerate().filter(|(_, (p, t))| {
        **p >= match t.r#type {
            TagType::General => general_threshold,
            TagType::Character => character_threshold,
        }
    }) {
        if heap.len() < k {
            heap.push(Reverse((FloatOrd(val), i)));
        } else if let Some(&Reverse((FloatOrd(min_val), _))) = heap.peek()
            && val > min_val
        {
            heap.pop();
            heap.push(Reverse((FloatOrd(val), i)));
        }
    }

    let mut result: Vec<(&Tag, f32)> = heap
        .into_iter()
        .map(|Reverse((FloatOrd(val), idx))| (&tags[idx], val))
        .collect();
    result.sort_unstable_by(|a, b| b.1.total_cmp(&a.1));
    result
}
