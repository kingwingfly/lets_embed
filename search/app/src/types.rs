use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Tag,
    Clip,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Tag => "tag",
            Mode::Clip => "clip",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "clip" => Mode::Clip,
            _ => Mode::Tag,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageItem {
    pub id: i64,
    pub name: String,
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

/// 解析 `foo bar -baz` 形式
pub fn parse_tag_query(q: &str) -> (Vec<String>, Vec<String>) {
    let mut tags = Vec::new();
    let mut not_tags = Vec::new();
    for tok in q.split_whitespace() {
        if let Some(rest) = tok.strip_prefix('-') {
            if !rest.is_empty() {
                not_tags.push(rest.to_string());
            }
        } else {
            tags.push(tok.to_string());
        }
    }
    (tags, not_tags)
}
