use cn_clip::{infer_text, model, tokenizer};

fn main() -> anyhow::Result<()> {
    let tokenizer = tokenizer("models/tokenizer.json")?;
    let mut text_session = model("models/cn_clip_text.onnx")?;
    let _res = infer_text(
        &tokenizer,
        &mut text_session,
        vec!["皇帝", "女王", "男人", "女人"],
    )?;
    Ok(())
}
