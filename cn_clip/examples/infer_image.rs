use std::fs;

use cn_clip::{convert_image, infer_vision, model};

fn main() -> anyhow::Result<()> {
    let mut vision_session = model("models/cn_clip_vision.onnx")?;
    let pika = convert_image(fs::File::open("assets/pika.png")?)?;
    let _res = infer_vision(&mut vision_session, vec![pika])?;
    Ok(())
}
