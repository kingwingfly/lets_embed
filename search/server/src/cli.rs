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
        default_value = "models/jina-clip-v2/onnx/jina-clip-v2-text.onnx"
    )]
    pub clip_text_model: PathBuf,

    #[arg(long, default_value = "models/jina-clip-v2/tokenizer.json")]
    pub tokenizer: PathBuf,

    pub prefix: PathBuf,
}
