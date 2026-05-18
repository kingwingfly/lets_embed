use std::{
    io::{BufReader, Read, Seek},
    path::Path,
};

use anyhow::bail;
use fast_image_resize::{
    PixelType, Resizer,
    images::{CroppedImageMut, Image},
};
use ort::{inputs, session::Session, value::Tensor};
use tokenizers::{EncodeInput, Tokenizer};

pub const TOKEN_DIM: usize = 52;
pub const EMBED_DIM: usize = 512;
pub const IMAGE_INPUT_DIM: usize = 3;
pub const IMAGE_SIZE: usize = 224;
pub const PAD_ID: i64 = 0;

pub const MEAN: [f64; 3] = [0.48145466, 0.4578275, 0.40821073];
pub const STD: [f64; 3] = [0.26862954, 0.26130258, 0.27577711];

pub fn tokenizer(config: impl AsRef<Path>) -> anyhow::Result<Tokenizer> {
    Ok(Tokenizer::from_file(config).unwrap())
}

pub fn model(text_model_path: impl AsRef<Path>) -> anyhow::Result<Session> {
    #[cfg(target_os = "macos")]
    let session = Session::builder()?
        .with_execution_providers([ort::ep::WebGPU::default().build().error_on_failure()])
        .unwrap()
        .commit_from_file(text_model_path)?;
    #[cfg(not(target_os = "macos"))]
    let session = Session::builder()?
        .with_execution_providers([ort::ep::CUDA::default().build().error_on_failure()])
        .unwrap()
        .commit_from_file(text_model_path)?;

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
    let tokens = tokenizer.encode_batch(batch_input, true).unwrap();
    let batch_size = tokens.len();

    let input_ids: Vec<i64> = tokens
        .iter()
        .flat_map(|enc| {
            let ids = enc.get_ids();
            (0..TOKEN_DIM).map(|i| ids.get(i).map(|&x| x as i64).unwrap_or(PAD_ID))
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

    if pixel_values.len() != batch_size * IMAGE_INPUT_DIM * IMAGE_SIZE * IMAGE_SIZE {
        bail!("invalid input image size")
    }

    let output = session.run(inputs![
        "pixel_values" => Tensor::from_array(([batch_size, 3, 224, 224], pixel_values))?,
    ])?;

    let (shape, predictions) = output["image_features"].try_extract_tensor::<f32>()?;

    debug_assert_eq!(shape[0], batch_size as i64);
    debug_assert_eq!(shape[1], EMBED_DIM as i64);

    Ok(predictions
        .chunks(EMBED_DIM)
        .map(|chunk| chunk.to_vec())
        .collect())
}

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

    let mut buf = dst_image
        .buffer()
        .iter()
        .map(|i| *i as f32)
        .collect::<Vec<_>>();

    for pix in buf.chunks_mut(3) {
        pix[0] = ((pix[0] as f64 - MEAN[0]) / STD[0]) as f32;
        pix[1] = ((pix[1] as f64 - MEAN[1]) / STD[1]) as f32;
        pix[2] = ((pix[2] as f64 - MEAN[2]) / STD[2]) as f32;
    }

    Ok(buf)
}
