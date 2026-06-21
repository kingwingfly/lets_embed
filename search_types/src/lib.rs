#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Image {
    pub id: i64,
    pub name: String,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Post {
    pub id: i64,
    pub title: String,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tag {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Author {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ImageDetails {
    pub image: Image,
    pub post: Option<Post>,
    pub authors: Vec<Author>,
    pub tags: Vec<Tag>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Video {
    pub id: i64,
    pub name: String,
    pub width: i32,
    pub height: i32,
    pub duration: i32,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VideoDetails {
    pub video: Video,
    pub post: Option<Post>,
    pub authors: Vec<Author>,
    pub tags: Vec<Tag>,
}
