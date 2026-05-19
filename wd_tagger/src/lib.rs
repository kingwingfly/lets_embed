use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    io::{BufReader, Read, Seek},
    path::Path,
};

use anyhow::bail;
use fast_image_resize::{
    PixelType, Resizer,
    images::{CroppedImageMut, Image},
};
use ort::{inputs, session::Session, value::Tensor};

pub const OUT_DIM: usize = 10861;

pub const IMAGE_WIDTH: usize = 448;
pub const IMAGE_HEIGHT: usize = 448;
pub const IMAGE_CHANNEL: usize = 3;

pub const MEAN: [f64; 3] = [0.5; 3];
pub const STD: [f64; 3] = [0.5; 3];

pub fn model(model_path: impl AsRef<Path>) -> anyhow::Result<Session> {
    #[cfg(target_os = "macos")]
    let session = Session::builder()?
        .with_execution_providers([ort::ep::WebGPU::default().build().error_on_failure()])
        .unwrap()
        .commit_from_file(model_path)?;
    #[cfg(not(target_os = "macos"))]
    let session = Session::builder()?
        .with_execution_providers([ort::ep::CUDA::default().build().error_on_failure()])
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
pub fn infer_tag<'a>(
    session: &mut Session,
    batch_input: Vec<Vec<f32>>,
    tags: &'a [impl AsRef<str>],
    top_k: usize,
) -> anyhow::Result<Vec<Vec<(&'a str, f32)>>>
where
{
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
            top_k_heap(prediction, top_k)
                .into_iter()
                .map(|(i, p)| (tags[i].as_ref(), p))
                .collect()
        })
        .collect();

    Ok(tags)
}

/// width, height: target size
///
/// Returns normalized HWC (black padded if ratio not match).
pub fn load_image<R: Read + Seek>(r: R, width: u32, height: u32) -> anyhow::Result<Vec<f32>> {
    let src_image = image::ImageReader::new(BufReader::new(r))
        .with_guessed_format()?
        .decode()?
        .to_rgb8();

    let (w, h) = src_image.dimensions();
    let r = (width as f32 / w as f32).min(height as f32 / h as f32);
    let nw = ((w as f32 * r).round() as u32).max(1);
    let nh = ((h as f32 * r).round() as u32).max(1);
    let dx = (width as i32 - nw as i32).unsigned_abs() / 2;
    let dy = (height as i32 - nh as i32).unsigned_abs() / 2;

    let mut dst_image = Image::new(width, height, PixelType::U8x3);
    let mut view = CroppedImageMut::new(&mut dst_image, dx, dy, nw, nh)?;

    let mut resizer = Resizer::new();
    resizer.resize(&src_image, &mut view, None)?;

    let mut hwc = dst_image
        .buffer()
        .iter()
        .map(|i| *i as f32)
        .collect::<Vec<_>>();

    for pix in hwc.chunks_mut(3) {
        pix[0] = ((pix[0] as f64 / 255.0 - MEAN[0]) / STD[0]) as f32;
        pix[1] = ((pix[1] as f64 / 255.0 - MEAN[1]) / STD[1]) as f32;
        pix[2] = ((pix[2] as f64 / 255.0 - MEAN[2]) / STD[2]) as f32;
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

fn top_k_heap(vec: &[f32], k: usize) -> Vec<(usize, f32)> {
    let mut heap: BinaryHeap<Reverse<(FloatOrd, usize)>> = BinaryHeap::with_capacity(k + 1);

    for (i, &val) in vec.iter().enumerate() {
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
    result.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    result
}
