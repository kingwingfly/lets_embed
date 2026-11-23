//! Aspect-ratio masonry placement helpers (pure Rust, zero browser coupling).

pub const DESKTOP_COLUMN_GAP: u32 = 12;
pub const MOBILE_COLUMN_GAP: u32 = 8;

/// An item placed into a specific masonry column with its original slice index.
#[derive(Clone, Debug, PartialEq)]
pub struct MasonryPlaced<T> {
    pub item: T,
    pub index: usize,
    pub aspect_ratio: f64,
}

/// Distribute `items` across `col_count` columns by greedily placing each item
/// into the currently shortest column based on `height / width` ratio.
pub fn layout_masonry<T: Clone>(
    items: &[T],
    col_count: usize,
    ratio_fn: impl Fn(&T) -> f64,
) -> Vec<Vec<MasonryPlaced<T>>> {
    let n = col_count.max(1);
    let mut cols: Vec<Vec<MasonryPlaced<T>>> = (0..n).map(|_| Vec::new()).collect();
    let mut heights = vec![0.0_f64; n];

    for (index, item) in items.iter().enumerate() {
        let shortest = heights
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.total_cmp(b))
            .map(|(i, _)| i)
            .unwrap_or(0);
        let ratio = ratio_fn(item).clamp(0.25, 4.5);
        heights[shortest] += ratio;
        cols[shortest].push(MasonryPlaced {
            item: item.clone(),
            index,
            aspect_ratio: ratio,
        });
    }

    cols
}

pub fn column_gap_for(viewport_width: f64) -> u32 {
    if viewport_width > 0.0 && viewport_width <= 640.0 {
        MOBILE_COLUMN_GAP
    } else {
        DESKTOP_COLUMN_GAP
    }
}

pub fn column_pixel_width(container_width: f64, col_count: usize, gap: u32) -> u32 {
    let count = col_count.max(1);
    ((container_width - f64::from(gap) * (count.saturating_sub(1) as f64)) / count as f64)
        .round()
        .max(80.0) as u32
}

/// Format a video duration in seconds as `M:SS` or `H:MM:SS`.
pub fn format_duration(seconds: i32) -> String {
    let s = seconds.max(0) as u64;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let rem = s % 60;
    if h > 0 {
        format!("{h}:{m:02}:{rem:02}")
    } else {
        format!("{m}:{rem:02}")
    }
}
