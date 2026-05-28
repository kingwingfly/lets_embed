use std::fs::File;

use search_engine::Engine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let engine = Engine::new(
        "models/siglip2-so400m-patch14-384/onnx/text_model.onnx",
        "models/siglip2-so400m-patch14-384/tokenizer.json",
        "models/dinov3-vitb16-pretrain-lvd1689m/onnx/model.onnx",
    )
    .await?;
    let _images = engine
        .search_image_tag(["genshin impact"], [], 5, 0)
        .await?;
    let _images = engine.search_clip(["长满青苔的小路"], 5, 0).await?;
    let _images = engine
        .search_dinov3([File::open("assets/pika.png")?], 5, 0)
        .await?;
    Ok(())
}
