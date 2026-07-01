use leptos::prelude::RwSignal;
use search_types::{Image, Video};
use serde::{Deserialize, Serialize};

/// Client-side holder for a pending image-search payload (URL-safe base64, no pad).
///
/// The bytes are kept out of the URL to avoid the request-line length limit that
/// caused 400s; only a short nonce travels in the query string. Provided as a
/// context at the app root and read by the search entry points + `Results`.
#[derive(Clone, Copy)]
pub struct ImageQuery(pub RwSignal<Option<String>>);

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

/// A single page of search results returned by the REST search endpoints.
///
/// Exactly one of `posts` / `images` is populated depending on the search mode;
/// the other is empty. `has_more` drives infinite-scroll pagination.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SearchResponse {
    pub posts: Vec<PostItem>,
    pub images: Vec<Image>,
    pub has_more: bool,
}
