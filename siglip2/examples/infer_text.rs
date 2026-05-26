use siglip2::{infer_text, model, tokenizer};

fn main() -> anyhow::Result<()> {
    let tokenizer = tokenizer("models/siglip2-so400m-patch14-384/tokenizer.json")?;
    let mut text_session = model("models/siglip2-so400m-patch14-384/onnx/text_model.onnx")?;
    let _res = infer_text(
        &tokenizer,
        &mut text_session,
        vec!["皇帝", "女王", "男人", "女人"],
    )?;
    Ok(())
}
