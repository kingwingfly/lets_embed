use std::fs::File;

use search_engine::Engine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let engine = Engine::new(
        Some("models/siglip2-so400m-patch14-384/onnx/text_model.onnx"),
        Some("models/siglip2-so400m-patch14-384/tokenizer.json"),
        Some("models/dinov3-vitb16-pretrain-lvd1689m/onnx/model.onnx"),
        None,
    )
    .await?;
    let _posts = engine.search_posts_by_tag("genshin impact", 5, 0).await?;
    let _images = engine.search_images_by_tag("genshin impact", 5, 0).await?;
    let _images = engine.search_clip(["长满青苔的小路"], 5, 0).await?;
    let _images = engine
        .search_dinov3([File::open("assets/pika.png")?], 5, 0)
        .await?;
    Ok(())
}
