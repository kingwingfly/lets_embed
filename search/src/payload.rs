use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize)]
pub struct PostPayload {
    pub id: i64,
    pub title: String,
    pub images: Vec<ImagePayload>,
}

#[derive(Serialize)]
pub struct ImagePayload {
    pub id: i64,
    pub name: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct Done {
    pub next_offset: i64,
}

#[derive(Deserialize)]
pub struct TagBody {
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub not_tags: Vec<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Deserialize)]
pub struct ClipBody {
    #[serde(default)]
    pub queries: Vec<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// Round-robin merge of multi-query CLIP results, preserving rank diversity, dedup by id.
pub fn merge_clip(groups: Vec<Vec<search_engine::Image>>) -> Vec<search_engine::Image> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let max_len = groups.iter().map(|v| v.len()).max().unwrap_or(0);
    for i in 0..max_len {
        for g in &groups {
            if let Some(img) = g.get(i)
                && seen.insert(img.id)
            {
                out.push(search_engine::Image {
                    id: img.id,
                    name: img.name.clone(),
                });
            }
        }
    }
    out
}

/// Percent-encode a single path segment. Slashes are preserved across segments by encode_path.
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

pub fn encode_path(s: &str) -> String {
    s.split('/')
        .map(encode_segment)
        .collect::<Vec<_>>()
        .join("/")
}
