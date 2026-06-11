use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "lets-embed", version, about = "Image search server")]
pub struct Cli {
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    #[arg(long, default_value_t = 3000)]
    pub port: u16,

    #[arg(
        long,
        default_value = "models/siglip2-so400m-patch14-384/onnx/text_model.onnx"
    )]
    pub clip_text_model: PathBuf,

    #[arg(
        long,
        default_value = "models/siglip2-so400m-patch14-384/tokenizer.json"
    )]
    pub tokenizer: PathBuf,

    #[arg(
        long,
        default_value = "models/dinov3-vitb16-pretrain-lvd1689m/onnx/model.onnx"
    )]
    pub dinov3_model: PathBuf,

    /// images path prefix
    pub prefix: Option<PathBuf>,
}
