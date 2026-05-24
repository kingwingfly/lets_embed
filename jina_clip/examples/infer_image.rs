use std::fs;

use jina_clip::{convert_image, infer_vision, model};

fn main() -> anyhow::Result<()> {
    let mut vision_session = model("models/jina-clip-v2/onnx/jina-clip-v2-vision.onnx")?;
    let pika = convert_image(fs::File::open("assets/pika.png")?)?;
    let _res = infer_vision(&mut vision_session, vec![pika])?;
    Ok(())
}
