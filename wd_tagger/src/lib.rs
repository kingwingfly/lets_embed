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

pub fn model(model_path: impl AsRef<Path>) -> anyhow::Result<Session> {
    let session = Session::builder()?
        .with_execution_providers([ep::CUDA::default().build()])
        .unwrap()
        .commit_from_file(model_path)?;

    Ok(session)
}

pub fn tags(csv_path: impl AsRef<Path>) -> anyhow::Result<Vec<String>> {
    let mut reader = csv::Reader::from_path(csv_path)?;

    let mut tags = vec!["".to_string(); OUT_DIM];
    for (i, r) in reader.records().enumerate() {
        let r = r?;
        tags[i] = r.get(1).unwrap_or_default().to_string();
    }

    Ok(tags)
}

/// tags should be [`OUT_DIM`] long.
///
/// Returns top_k `(tag: &str, p: f32)`s
pub fn infer_tag<T: Clone>(
    session: &mut Session,
    batch_input: Vec<Vec<f32>>,
    tags: &[T],
    top_k: usize,
    threshold: f32,
) -> anyhow::Result<Vec<Vec<(T, f32)>>> {
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
            top_k_heap(prediction, top_k, threshold)
                .into_iter()
                .map(|(i, p)| (tags[i].clone(), p))
                .collect()
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

fn top_k_heap(vec: &[f32], k: usize, threshold: f32) -> Vec<(usize, f32)> {
    let mut heap: BinaryHeap<Reverse<(FloatOrd, usize)>> = BinaryHeap::with_capacity(k + 1);

    for (i, &val) in vec.iter().enumerate().filter(|(_, p)| **p >= threshold) {
        if heap.len() < k {
            heap.push(Reverse((FloatOrd(val), i)));
        } else if let Some(&Reverse((FloatOrd(min_val), _))) = heap.peek()
            && val > min_val
        {
            heap.pop();
            heap.push(Reverse((FloatOrd(val), i)));
        }
    }

    let mut result: Vec<(usize, f32)> = heap
        .into_iter()
        .map(|Reverse((FloatOrd(val), idx))| (idx, val))
        .collect();
    result.sort_unstable_by(|a, b| b.1.total_cmp(&a.1));
    result
}
