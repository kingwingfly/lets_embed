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

pub const EMBED_DIM: usize = 512;

pub const TOKEN_DIM: usize = 52;
pub const TOKEN_PAD_ID: i64 = 0;

pub const IMAGE_CHANNEL: usize = 3;
pub const IMAGE_WIDTH: usize = 224;
pub const IMAGE_HEIGHT: usize = 224;

pub const MEAN: [f64; 3] = [0.48145466, 0.4578275, 0.40821073];
pub const STD: [f64; 3] = [0.26862954, 0.26130258, 0.27577711];

pub fn tokenizer(config: impl AsRef<Path>) -> anyhow::Result<Tokenizer> {
    Tokenizer::from_file(config).map_err(|e| anyhow!("{e}"))
}

pub fn model(model_path: impl AsRef<Path>) -> anyhow::Result<Session> {
    let session = Session::builder()?
        .with_execution_providers([
            ep::TensorRT::default().build(),
            ep::CUDA::default().build(),
            ep::DirectML::default().build(),
            ep::WebGPU::default().build(),
            ep::CoreML::default().build(),
        ])
        .unwrap()
        .commit_from_file(model_path)?;

    Ok(session)
}

pub fn infer_text<'s, E>(
    tokenizer: &Tokenizer,
    session: &mut Session,
    batch_input: Vec<E>,
) -> anyhow::Result<Vec<Vec<f32>>>
where
    E: Into<EncodeInput<'s>> + Send + 's,
{
    let tokens = tokenizer
        .encode_batch(batch_input, true)
        .map_err(|e| anyhow!("{e}"))?;
    let batch_size = tokens.len();

    let input_ids: Vec<i64> = tokens
        .iter()
        .flat_map(|enc| {
            let ids = enc.get_ids();
            (0..TOKEN_DIM).map(|i| ids.get(i).map(|&x| x as i64).unwrap_or(TOKEN_PAD_ID))
        })
        .collect();

    let attention_mask: Vec<i64> = tokens
        .iter()
        .flat_map(|enc| {
            let mask = enc.get_attention_mask();
            (0..TOKEN_DIM).map(|i| mask.get(i).map(|&x| x as i64).unwrap_or(0))
        })
        .collect();

    let output = session.run(inputs![
        "input_ids" => Tensor::from_array(([batch_size, 52], input_ids))?,
        "attention_mask" => Tensor::from_array(([batch_size, 52], attention_mask))?
    ])?;

    let (shape, predictions) = output["text_features"].try_extract_tensor::<f32>()?;

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
    let batch_size = batch_input.len();
    let pixel_values = batch_input.into_iter().flatten().collect::<Vec<_>>();

    if pixel_values.len() != batch_size * IMAGE_CHANNEL * IMAGE_HEIGHT * IMAGE_WIDTH {
        bail!("invalid input image size")
    }

    let output = session.run(inputs![
        "pixel_values" => Tensor::from_array(([batch_size, IMAGE_CHANNEL, IMAGE_HEIGHT, IMAGE_WIDTH], pixel_values))?,
    ])?;

    let (shape, predictions) = output["image_features"].try_extract_tensor::<f32>()?;

    debug_assert_eq!(shape[0], batch_size as i64);
    debug_assert_eq!(shape[1], EMBED_DIM as i64);

    Ok(predictions
        .chunks(EMBED_DIM)
        .map(|chunk| chunk.to_vec())
        .collect())
}

/// width, height: target size
///
/// Returns normalized CHW (black padded if ratio not match).
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
    resizer.resize(
        &src_image,
        &mut view,
        &ResizeOptions::new().resize_alg(ResizeAlg::Interpolation(FilterType::CatmullRom)),
    )?;

    let hwc = dst_image.buffer();

    let mut chw = vec![0.0f32; hwc.len()];
    let hw = (height * width) as usize;
    for h in 0..height as usize {
        for w in 0..width as usize {
            let src = (h * width as usize + w) * 3;
            for c in 0..3usize {
                chw[c * hw + h * width as usize + w] =
                    ((hwc[src + c] as f64 / 255.0 - MEAN[c]) / STD[c]) as f32;
            }
        }
    }

    Ok(chw)
}
