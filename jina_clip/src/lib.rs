use std::{
    io::{BufReader, Read, Seek},
    path::Path,
};

use anyhow::{anyhow, bail};
use fast_image_resize::{
    FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer,
    images::{CroppedImageMut, Image},
};
use ort::ep;
use ort::{inputs, session::Session, value::Tensor};
use tokenizers::{EncodeInput, Tokenizer};

pub const EMBED_DIM: usize = 1024;

pub const MAX_TOEKN_DIM: usize = 77;

pub const IMAGE_CHANNEL: usize = 3;
pub const IMAGE_WIDTH: usize = 512;
pub const IMAGE_HEIGHT: usize = 512;

pub const MEAN: [f64; 3] = [0.48145466, 0.4578275, 0.40821073];
pub const STD: [f64; 3] = [0.26862954, 0.26130258, 0.27577711];

pub fn tokenizer(config: impl AsRef<Path>) -> anyhow::Result<Tokenizer> {
    Tokenizer::from_file(config).map_err(|e| anyhow!("{e}"))
}

pub fn model(model_path: impl AsRef<Path>) -> anyhow::Result<Session> {
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

pub fn infer_text<'s>(
    tokenizer: &Tokenizer,
    session: &mut Session,
    batch_input: impl IntoIterator<Item = impl Into<EncodeInput<'s>> + Send + 's>,
) -> anyhow::Result<Vec<Vec<f32>>>
where
{
    let encodings = tokenizer
        .encode_batch(batch_input.into_iter().collect(), true)
        .map_err(|e| anyhow!("{e}"))?;

    let batch_size = encodings.len();
    if batch_size == 0 {
        bail!("empty batch")
    }
    let token_dim = encodings
        .iter()
        .map(|enc| enc.get_ids().len())
        .max()
        .unwrap();
    if token_dim == 0 {
        bail!("empty input")
    }
    if token_dim > MAX_TOEKN_DIM {
        bail!("token dim too long (should <= {MAX_TOEKN_DIM})")
    }

    let token_pad_id = tokenizer.token_to_id("<pad>").unwrap_or(1) as i64;
    let mut input_ids = vec![token_pad_id; batch_size * token_dim];
    for (i, enc) in encodings.iter().enumerate() {
        for (j, &id) in enc.get_ids().iter().enumerate() {
            input_ids[i * token_dim + j] = id as i64;
        }
    }

    let output = session.run(inputs![
        "input_ids" => Tensor::from_array(([batch_size, token_dim], input_ids))?,
    ])?;

    let (shape, predictions) = output["l2norm_text_embeddings"].try_extract_tensor::<f32>()?;

    debug_assert_eq!(shape[0], batch_size as i64);
    debug_assert_eq!(shape[1], EMBED_DIM as i64);

    Ok(predictions
        .chunks(EMBED_DIM)
        .map(|chunk| chunk.to_vec())
        .collect())
}

pub fn infer_vision(
    session: &mut Session,
    batch_input: Vec<Vec<f32>>,
) -> anyhow::Result<Vec<Vec<f32>>>
where
{
    if batch_input
        .iter()
        .any(|i| i.len() != IMAGE_CHANNEL * IMAGE_HEIGHT * IMAGE_WIDTH)
    {
        bail!("invalid input image size")
    }

    let batch_size = batch_input.len();
    let pixel_values = batch_input.into_iter().flatten().collect::<Vec<_>>();

    let output = session.run(inputs![
        "pixel_values" => Tensor::from_array(([batch_size, IMAGE_CHANNEL, IMAGE_HEIGHT, IMAGE_WIDTH], pixel_values))?,
    ])?;

    let (shape, predictions) = output["l2norm_image_embeddings"].try_extract_tensor::<f32>()?;

    debug_assert_eq!(shape[0], batch_size as i64);
    debug_assert_eq!(shape[1], EMBED_DIM as i64);

    Ok(predictions
        .chunks(EMBED_DIM)
        .map(|chunk| chunk.to_vec())
        .collect())
}

/// Returns normalized CHW (black padded if ratio not match).
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

    let hwc = dst_image.buffer();

    let mut chw = vec![0.0f32; hwc.len()];
    const HW: usize = IMAGE_HEIGHT * IMAGE_WIDTH;
    for h in 0..IMAGE_HEIGHT {
        for w in 0..IMAGE_WIDTH {
            let src = (h * IMAGE_WIDTH + w) * 3;
            for c in 0..3usize {
                chw[c * HW + h * IMAGE_WIDTH + w] =
                    ((hwc[src + c] as f64 / 255.0 - MEAN[c]) / STD[c]) as f32;
            }
        }
    }

    Ok(chw)
}
