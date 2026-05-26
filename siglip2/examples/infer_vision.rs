use std::fs;

use siglip2::{convert_image, infer_vision, model};

fn main() -> anyhow::Result<()> {
    let mut vision_session = model("models/siglip2-so400m-patch14-384/onnx/vision_model.onnx")?;
    let pika = convert_image(fs::File::open("assets/pika.png")?)?;
    let _res = infer_vision(&mut vision_session, vec![pika])?;
    Ok(())
}
