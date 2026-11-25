#![feature(portable_simd)]

use std::{
    io::{BufReader, Read, Seek},
    path::Path,
    simd::{StdFloat, f32x16, num::SimdFloat},
};

use anyhow::bail;
use fast_image_resize::{FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer, images::Image};
use ort::{environment::Environment, ep, inputs, session::Session, value::Tensor};

pub const EMBED_DIM: usize = 768;

pub const IMAGE_CHANNEL: usize = 3;
pub const IMAGE_WIDTH: usize = 256;
pub const IMAGE_HEIGHT: usize = 256;

pub const MAX_IMAGE_DIMENSION: u32 = 32_768;
pub const MAX_IMAGE_PIXELS: u64 = 100_000_000;
pub const MAX_DECODE_ALLOC_BYTES: u64 = 512 * 1024 * 1024;

pub const MEAN: [f64; 3] = [0.485, 0.456, 0.406];
pub const STD: [f64; 3] = [0.229, 0.224, 0.225];

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

fn decode_limits() -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC_BYTES);
    limits
}

/// Returns normalized CHW (black padded if ratio not match).
pub fn convert_image<R: Read + Seek>(r: R) -> anyhow::Result<Vec<f32>> {
    let mut buf = BufReader::new(r);
    let mut dim_reader = image::ImageReader::new(&mut buf).with_guessed_format()?;
    dim_reader.limits(decode_limits());
    let (w, h) = dim_reader.into_dimensions()?;
    let pixels = u64::from(w).saturating_mul(u64::from(h));
    if w == 0
        || h == 0
        || w > MAX_IMAGE_DIMENSION
        || h > MAX_IMAGE_DIMENSION
        || pixels > MAX_IMAGE_PIXELS
    {
        bail!(
            "image dimensions {w}x{h} exceed limits (max {MAX_IMAGE_DIMENSION}px per side, {MAX_IMAGE_PIXELS} total pixels)"
        );
    }

    buf.rewind()?;
    let mut reader = image::ImageReader::new(buf).with_guessed_format()?;
    reader.limits(decode_limits());
    let src_image = reader.decode()?.to_rgb8();

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
    let (chunks, remainder) = data.as_chunks::<64>(); // 4 * 16
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
    for c in remainder.as_chunks::<16>().0 {
        let v = f32x16::from_slice(c);
        acc0 = v.mul_add(v, acc0);
    }
    let sum_sq = (acc0 + acc1 + acc2 + acc3).reduce_sum();
    let inv = 1.0 / sum_sq.sqrt().max(1e-12);
    let inv_v = f32x16::splat(inv);

    for c in data.as_chunks_mut::<16>().0 {
        let v = f32x16::from_slice(c) * inv_v;
        c.copy_from_slice(v.as_array());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &b in bytes {
            crc ^= u32::from(b);
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xedb8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    fn png_header_only(width: u32, height: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let mut ihdr = Vec::with_capacity(17);
        ihdr.extend_from_slice(b"IHDR");
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        out.extend_from_slice(&13u32.to_be_bytes());
        out.extend_from_slice(&ihdr);
        out.extend_from_slice(&crc32(&ihdr).to_be_bytes());
        // Include a 1-byte IDAT chunk header so `into_dimensions()` finishes reading
        // metadata without needing any compressed pixel payload.
        let idat = b"IDAT\x00";
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(idat);
        out.extend_from_slice(&crc32(idat).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(b"IEND");
        out.extend_from_slice(&crc32(b"IEND").to_be_bytes());
        out
    }

    #[test]
    fn convert_image_rejects_huge_png_dimensions_without_allocating() {
        let huge_dim = png_header_only(40_000, 40_000);
        let err = convert_image(Cursor::new(huge_dim)).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("Format error")
                && (msg.contains("exceed") || msg.contains("limit") || msg.contains("dimension")),
            "unexpected error for 40000x40000 PNG: {msg}"
        );

        let huge_pixels = png_header_only(12_000, 12_000);
        let err_px = convert_image(Cursor::new(huge_pixels)).unwrap_err();
        assert!(
            err_px.to_string().contains("12000x12000"),
            "expected pixel limit rejection for 12000x12000 PNG, got: {err_px}"
        );
    }

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
