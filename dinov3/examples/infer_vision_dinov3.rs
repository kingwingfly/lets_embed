use std::fs;

use dinov3::{convert_image, infer_vision, model_with_env};

fn main() -> anyhow::Result<()> {
    let env = ort::init().build()?;
    let mut session = model_with_env(&env, "models/dinov3-vitb16-pretrain-lvd1689m/onnx/model.onnx")?;
    let pika = convert_image(fs::File::open("assets/pika.png")?)?;
    let _res = infer_vision(&mut session, vec![pika])?;
    Ok(())
}
