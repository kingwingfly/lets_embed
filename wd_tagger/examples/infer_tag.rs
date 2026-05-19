use std::fs;

use wd_tagger::{IMAGE_HEIGHT, IMAGE_WIDTH, infer_tag, load_image, model, tags};

fn main() -> anyhow::Result<()> {
    let tags = tags("models/selected_tags.csv")?;
    let mut session = model("models/wd-eva02-large-tagger-v3.onnx")?;
    let pika = load_image(
        fs::File::open("assets/pika.png")?,
        IMAGE_WIDTH as u32,
        IMAGE_HEIGHT as u32,
    )?;
    let res = infer_tag(&mut session, vec![pika], &tags, 10, 0.8)?;
    dbg!(res);
    Ok(())
}
