use search_engine::Engine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let engine = Engine::new(
        "models/jina-clip-v2/onnx/jina-clip-v2-text.onnx_data",
        "models/jina-clip-v2/tokenizer.json",
    )
    .await?;
    let (_posts, _images) = engine.search_tag(["genshin impact"], [], 5, 0).await?;
    let _images = engine.search_clip(["长满青苔的小路"], 5, 0).await?;
    Ok(())
}
