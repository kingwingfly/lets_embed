use search::Engine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let engine = Engine::new("models/cn_clip_text.onnx", "models/tokenizer.json").await?;
    let (posts, images) = engine.search_tag(["genshin impact"], []).await?;
    for p in posts {
        println!("{:?}", p);
    }
    for i in images {
        println!("{:?}", i);
    }
    Ok(())
}
