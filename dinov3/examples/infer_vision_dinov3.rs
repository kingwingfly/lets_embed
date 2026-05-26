use std::fs;

use dinov3::{convert_image, infer_vision, model};

fn main() -> anyhow::Result<()> {
    let mut session = model("models/dinov3-vitb16-pretrain-lvd1689m/onnx/model.onnx")?;
    let pika = convert_image(fs::File::open("assets/pika.png")?)?;
    let _res = infer_vision(&mut session, vec![pika])?;
    Ok(())
}
