use search_types::{Image, Video};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Mode {
    Tag,
    Author,
    Title,
    Clip,
    Similar,
    SearchImage,
    Random,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Tag => "tag",
            Mode::Author => "author",
            Mode::Title => "title",
            Mode::Clip => "clip",
            Mode::Similar => "similar",
            Mode::SearchImage => "search_image",
            Mode::Random => "random",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "author" => Mode::Author,
            "title" => Mode::Title,
            "clip" => Mode::Clip,
            "similar" => Mode::Similar,
            "search_image" => Mode::SearchImage,
            "random" => Mode::Random,
            _ => Mode::Tag,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MediaItem {
    Image(Image),
    Video(Video),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostItem {
    pub id: i64,
    pub title: String,
    pub images: Vec<Image>,
    pub videos: Vec<Video>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoneEvent {
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorEvent {
    pub message: String,
}
