use std::fs;

use cn_clip::{IMAGE_HEIGHT, IMAGE_WIDTH, infer_vision, load_image, model};

fn main() -> anyhow::Result<()> {
    let mut vision_session = model("models/cn_clip_vision.onnx")?;
    let pika = load_image(
        fs::File::open("assets/pika.png")?,
        IMAGE_WIDTH as u32,
        IMAGE_HEIGHT as u32,
    )?;
    let _res = infer_vision(&mut vision_session, vec![pika])?;
    Ok(())
}
