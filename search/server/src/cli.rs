use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "lets-embed", version, about = "Image search server")]
pub struct Cli {
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    #[arg(long, default_value_t = 3000)]
    pub port: u16,

    #[arg(long, default_value = "models/cn_clip_text.onnx")]
    pub clip_model: PathBuf,

    #[arg(long, default_value = "models/tokenizer.json")]
    pub tokenizer: PathBuf,

    pub prefix: PathBuf,
}
