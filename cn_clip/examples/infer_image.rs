use std::fs;

use cn_clip::{IMAGE_SIZE, infer_vision, load_image, model};

fn main() -> anyhow::Result<()> {
    let mut vision_session = model("models/cn_clip_vision.onnx")?;
    let pika = load_image(
        fs::File::open("assets/pika.png")?,
        IMAGE_SIZE as u32,
        IMAGE_SIZE as u32,
    )?;
    let _res = infer_vision(&mut vision_session, vec![pika])?;
    Ok(())
}
