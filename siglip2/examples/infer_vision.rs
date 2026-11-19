use std::fs;

use siglip2::{convert_image, infer_vision, model_with_env};

fn main() -> anyhow::Result<()> {
    let env = ort::init().build()?;
    let mut vision_session = model_with_env(
        &env,
        "models/siglip2-so400m-patch14-384/onnx/vision_model.onnx",
    )?;
    let pika = convert_image(fs::File::open("assets/pika.png")?)?;
    let _res = infer_vision(&mut vision_session, vec![pika])?;
    Ok(())
}
