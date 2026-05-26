#![feature(portable_simd)]

use std::{
    io::{BufReader, Read, Seek},
    path::Path,
    simd::{StdFloat, f32x16, num::SimdFloat},
};

use anyhow::bail;
use fast_image_resize::{FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer, images::Image};
use ort::ep;
use ort::{inputs, session::Session, value::Tensor};

pub const EMBED_DIM: usize = 768;

pub const IMAGE_CHANNEL: usize = 3;
pub const IMAGE_WIDTH: usize = 256;
pub const IMAGE_HEIGHT: usize = 256;

pub const MEAN: [f64; 3] = [0.485, 0.456, 0.406];
pub const STD: [f64; 3] = [0.229, 0.224, 0.225];

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

    let (shape, predictions) = output["pooler_output"].try_extract_tensor::<f32>()?;

    debug_assert_eq!(shape[0], batch_size as i64);
    debug_assert_eq!(shape[1], EMBED_DIM as i64);

    Ok(predictions
        .chunks(EMBED_DIM)
        .map(|chunk| {
            let mut chunk = chunk.to_vec();
            l2_normalize_inplace_simd(&mut chunk);
            chunk
        })
        .collect())
}

/// Returns normalized CHW (black padded if ratio not match).
pub fn convert_image<R: Read + Seek>(r: R) -> anyhow::Result<Vec<f32>> {
    let src_image = image::ImageReader::new(BufReader::new(r))
        .with_guessed_format()?
        .decode()?
        .to_rgb8();

    let mut dst_image = Image::new(IMAGE_WIDTH as u32, IMAGE_HEIGHT as u32, PixelType::U8x3);

    let mut resizer = Resizer::new();
    resizer.resize(
        &src_image,
        &mut dst_image,
        &ResizeOptions::new().resize_alg(ResizeAlg::Convolution(FilterType::Bilinear)),
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

#[cfg(test)]
fn l2_normalize_inplace(data: &mut [f32]) {
    let sum_sq: f32 = data.iter().map(|x| x * x).sum();
    let norm = sum_sq.sqrt().max(1e-12);
    let inv = 1.0 / norm;
    for x in data.iter_mut() {
        *x *= inv;
    }
}

fn l2_normalize_inplace_simd(data: &mut [f32]) {
    debug_assert!(data.len().is_multiple_of(16));

    let mut acc0 = f32x16::splat(0.0);
    let mut acc1 = f32x16::splat(0.0);
    let mut acc2 = f32x16::splat(0.0);
    let mut acc3 = f32x16::splat(0.0);
    let chunks = data.chunks_exact(64); // 4 * 16
    let remainder = chunks.remainder();
    for c in chunks {
        let v0 = f32x16::from_slice(&c[0..16]);
        let v1 = f32x16::from_slice(&c[16..32]);
        let v2 = f32x16::from_slice(&c[32..48]);
        let v3 = f32x16::from_slice(&c[48..64]);
        acc0 = v0.mul_add(v0, acc0);
        acc1 = v1.mul_add(v1, acc1);
        acc2 = v2.mul_add(v2, acc2);
        acc3 = v3.mul_add(v3, acc3);
    }
    for c in remainder.chunks_exact(16) {
        let v = f32x16::from_slice(c);
        acc0 = v.mul_add(v, acc0);
    }
    let sum_sq = (acc0 + acc1 + acc2 + acc3).reduce_sum();
    let inv = 1.0 / sum_sq.sqrt().max(1e-12);
    let inv_v = f32x16::splat(inv);

    for c in data.chunks_exact_mut(16) {
        let v = f32x16::from_slice(c) * inv_v;
        c.copy_from_slice(v.as_array());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2_normalize_inplace_simd_test() {
        let mut data1 = (0..128).map(|i| i as f32).collect::<Vec<_>>();
        let mut data2 = data1.clone();
        l2_normalize_inplace(&mut data1);
        l2_normalize_inplace_simd(&mut data2);
        assert_eq!(data1, data2);
        assert!((data1.into_iter().map(|i| i * i).sum::<f32>() - 1.0).abs() <= 1e-5);
        assert!((data2.into_iter().map(|i| i * i).sum::<f32>() - 1.0).abs() <= 1e-5);
    }
}
