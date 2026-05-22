use search::Engine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let engine = Engine::new("models/cn_clip_text.onnx", "models/tokenizer.json").await?;
    let (_posts, _images) = engine.search_tag(["genshin impact"], []).await?;
    let _images = engine.search_clip(["长满青苔的小路"], 5).await?;
    Ok(())
}
