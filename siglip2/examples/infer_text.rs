use siglip2::{infer_text, model_with_env, tokenizer};

fn main() -> anyhow::Result<()> {
    let env = ort::init().build()?;
    let tokenizer = tokenizer("models/siglip2-so400m-patch14-384/tokenizer.json")?;
    let mut text_session =
        model_with_env(&env, "models/siglip2-so400m-patch14-384/onnx/text_model.onnx")?;
    let _res = infer_text(
        &tokenizer,
        &mut text_session,
        vec!["皇帝", "女王", "男人", "女人"],
    )?;
    Ok(())
}
