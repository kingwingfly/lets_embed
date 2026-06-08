use std::fs;

use wd_tagger::{convert_image, infer_tag, model, tags};

fn main() -> anyhow::Result<()> {
    let tags = tags("models/wd-eva02-large-tagger-v3/selected_tags.csv")?;
    let mut session = model("models/wd-eva02-large-tagger-v3/onnx/wd-eva02-large-tagger-v3.onnx")?;
    let pika = convert_image(fs::File::open("assets/pika.png")?)?;
    let _res = infer_tag(&mut session, vec![pika], &tags, 10, 0.3, 0.8)?;
    Ok(())
}
