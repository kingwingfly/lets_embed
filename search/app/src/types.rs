use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Mode {
    Tag,
    Author,
    Clip,
    Similar,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Tag => "tag",
            Mode::Author => "author",
            Mode::Clip => "clip",
            Mode::Similar => "similar",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "author" => Mode::Author,
            "clip" => Mode::Clip,
            "similar" => Mode::Similar,
            _ => Mode::Tag,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageItem {
    pub id: i64,
    pub name: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostItem {
    pub id: i64,
    pub title: String,
    pub images: Vec<ImageItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoneEvent {
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorEvent {
    pub message: String,
}
