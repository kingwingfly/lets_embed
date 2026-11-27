use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

use leptos::{ev, html, prelude::*};
use serde::{Deserialize, Serialize};

use crate::browser::{
    use_window_keydown, use_window_pointerdown, use_window_resize, use_window_scroll_capture,
};
use crate::components::{OptionalScoreInput, SkySelect};
use crate::models::{PresetTemplate, QuerySuggestion, SelectOption, SelectVariant};
use crate::rule_syntax::{MAX_RULE_LEN, MAX_TERMS_PER_RULE};

static NEXT_QB_NODE_ID: AtomicU64 = AtomicU64::new(1000);

fn alloc_qb_id() -> u64 {
    NEXT_QB_NODE_ID.fetch_add(1, Ordering::Relaxed)
}

/// Strictly parse a score/similarity threshold at hundredths precision in `0.01..=1.00`.
///
/// Accepts `0.01`, `0.45`, `0.5`, `0.50`, `.45`, `1`, `1.0`, `1.00`.
/// Rejects `0`, `0.005`, `0.456` (>2 decimal places), `> 1.00`, negative numbers,
/// scientific notation, `NaN`, `Inf`, and trailing garbage.
pub fn parse_threshold_hundredths(raw: &str) -> Result<f32, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Missing threshold after `>=`".to_string());
    }
    if trimmed.contains(">=") {
        return Err("Multiple `>=` thresholds in one condition".to_string());
    }
    if trimmed.starts_with('-') {
        return Err(format!(
            "Threshold `{trimmed}` out of range (must be between 0.01 and 1.00)"
        ));
    }

    let hundredths: u32 = match trimmed.split_once('.') {
        None => {
            if !trimmed.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!(
                    "Invalid threshold `{trimmed}` (expected hundredths in 0.01..=1.00)"
                ));
            }
            let int_val = trimmed.parse::<u32>().map_err(|_| {
                format!("Threshold `{trimmed}` out of range (must be between 0.01 and 1.00)")
            })?;
            int_val.saturating_mul(100)
        }
        Some((int_part, frac_part)) => {
            if frac_part.contains('.') {
                return Err(format!(
                    "Invalid threshold `{trimmed}` (expected hundredths in 0.01..=1.00)"
                ));
            }
            if frac_part.is_empty() || frac_part.len() > 2 {
                return Err(format!(
                    "Threshold `{trimmed}` must have 1 or 2 decimal places (0.01..=1.00)"
                ));
            }
            if !int_part.chars().all(|c| c.is_ascii_digit())
                || !frac_part.chars().all(|c| c.is_ascii_digit())
            {
                return Err(format!(
                    "Invalid threshold `{trimmed}` (expected hundredths in 0.01..=1.00)"
                ));
            }
            let int_val: u32 = if int_part.is_empty() {
                0
            } else {
                int_part.parse::<u32>().map_err(|_| {
                    format!("Threshold `{trimmed}` out of range (must be between 0.01 and 1.00)")
                })?
            };
            let frac_raw = frac_part.parse::<u32>().map_err(|_| {
                format!("Invalid threshold `{trimmed}` (expected hundredths in 0.01..=1.00)")
            })?;
            let frac_val = if frac_part.len() == 1 {
                frac_raw * 10
            } else {
                frac_raw
            };
            int_val.saturating_mul(100).saturating_add(frac_val)
        }
    };

    if !(1..=100).contains(&hundredths) {
        return Err(format!(
            "Threshold `{trimmed}` out of range (must be between 0.01 and 1.00)"
        ));
    }

    Ok((hundredths as f32) / 100.0)
}

/// Clamp and quantize a floating-point threshold to hundredths precision in `0.01..=1.00`.
pub fn quantize_threshold(v: f32) -> Option<f32> {
    if !v.is_finite() || v <= 0.0 {
        return None;
    }
    let hundredths = (v.clamp(0.01, 1.0) * 100.0).round().clamp(1.0, 100.0);
    Some(hundredths / 100.0)
}

/// Format a score/similarity threshold at exact hundredths precision in `0.01..=1.00`
/// (e.g. `0.45` -> `"0.45"`, `0.5` -> `"0.50"`, `1.0` -> `"1.00"`).
pub fn format_threshold(v: f32) -> String {
    let hundredths = (v.clamp(0.01, 1.0) * 100.0).round().clamp(1.0, 100.0) as u32;
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

/// Split `raw` on commas/newlines, trim each candidate, and append unique non-empty
/// values into `existing` while preserving order. Returns `true` if any chip was added.
pub(crate) fn merge_chip_values(existing: &mut Vec<String>, raw: &str) -> bool {
    let mut added = false;
    for part in raw.split([',', '\n', '\r']) {
        let trimmed = part.trim();
        if !trimmed.is_empty() && !existing.iter().any(|v| v == trimmed) {
            existing.push(trimmed.to_string());
            added = true;
        }
    }
    added
}

/// Operating mode for the unified visual [`QueryBuilder`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryBuilderMode {
    /// Gallery Advanced Search (`all:`, `title:`, `author:`, `tag:`, `clip:`, `dino:`, `upload:`).
    #[default]
    AdvancedSearch,
    /// Admin Content Policy Selector — strictly metadata-only (`tag:`, `post_tag:`, `author:`, `unclassified`).
    SafetyPolicy,
}

/// Comparison operator for a condition card in [`QueryBuilder`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryConditionOp {
    #[default]
    Is,
    IsNot,
    In,
    NotIn,
}

impl QueryConditionOp {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Is => "is",
            Self::IsNot => "is_not",
            Self::In => "in",
            Self::NotIn => "not_in",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Is => "is",
            Self::IsNot => "is not",
            Self::In => "in",
            Self::NotIn => "not in",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "is_not" | "is not" | "not" => Self::IsNot,
            "in" => Self::In,
            "not_in" | "not in" => Self::NotIn,
            _ => Self::Is,
        }
    }

    pub const fn is_negated(self) -> bool {
        matches!(self, Self::IsNot | Self::NotIn)
    }

    pub const fn is_list(self) -> bool {
        matches!(self, Self::In | Self::NotIn)
    }

    pub fn select_options(supports_list: bool) -> Vec<SelectOption> {
        if supports_list {
            vec![
                SelectOption::new("is", "is"),
                SelectOption::new("is_not", "is not"),
                SelectOption::new("in", "in"),
                SelectOption::new("not_in", "not in"),
            ]
        } else {
            vec![
                SelectOption::new("is", "is"),
                SelectOption::new("is_not", "is not"),
            ]
        }
    }
}

/// Predicate field kinds supported across [`QueryBuilderMode::AdvancedSearch`] and
/// [`QueryBuilderMode::SafetyPolicy`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryFieldKind {
    TitleAndAuthor,
    Title,
    Author,
    #[default]
    Tag,
    PostTag,
    ClipText,
    SimilarId,
    UploadImage,
    Unclassified,
}

impl QueryFieldKind {
    pub const ADVANCED_TOP_FIELDS: [Self; 7] = [
        Self::TitleAndAuthor,
        Self::Title,
        Self::Author,
        Self::Tag,
        Self::ClipText,
        Self::SimilarId,
        Self::UploadImage,
    ];

    pub const ADVANCED_GROUP_FIELDS: [Self; 4] =
        [Self::TitleAndAuthor, Self::Title, Self::Author, Self::Tag];

    pub const SAFETY_FIELDS: [Self; 4] = [Self::Tag, Self::PostTag, Self::Author, Self::Unclassified];

    pub const fn fields_for_mode(mode: QueryBuilderMode) -> &'static [Self] {
        match mode {
            QueryBuilderMode::AdvancedSearch => &Self::ADVANCED_TOP_FIELDS,
            QueryBuilderMode::SafetyPolicy => &Self::SAFETY_FIELDS,
        }
    }

    pub const fn group_fields_for_mode(mode: QueryBuilderMode) -> &'static [Self] {
        match mode {
            QueryBuilderMode::AdvancedSearch => &Self::ADVANCED_GROUP_FIELDS,
            QueryBuilderMode::SafetyPolicy => &Self::SAFETY_FIELDS,
        }
    }

    pub const fn is_allowed_in_mode(self, mode: QueryBuilderMode) -> bool {
        match mode {
            QueryBuilderMode::AdvancedSearch => matches!(
                self,
                Self::TitleAndAuthor
                    | Self::Title
                    | Self::Author
                    | Self::Tag
                    | Self::ClipText
                    | Self::SimilarId
                    | Self::UploadImage
            ),
            QueryBuilderMode::SafetyPolicy => matches!(
                self,
                Self::Tag | Self::PostTag | Self::Author | Self::Unclassified
            ),
        }
    }

    pub const fn is_vector(self) -> bool {
        matches!(self, Self::ClipText | Self::SimilarId | Self::UploadImage)
    }

    /// Discrete metadata fields supporting multi-value `IN (...)` / `NOT IN (...)` lists.
    /// Matches `search_types::query` (`tag`, `author`) and `search_types::safety`
    /// (`tag`, `post_tag`, `author`). Vector fields (`clip`, `dino`, `upload`) stay single-value.
    pub const fn supports_in(self) -> bool {
        matches!(self, Self::Tag | Self::PostTag | Self::Author)
    }

    /// Fields that carry an inline per-condition `>=` score/similarity threshold.
    pub const fn supports_threshold(self) -> bool {
        matches!(
            self,
            Self::Tag | Self::ClipText | Self::SimilarId | Self::UploadImage
        )
    }

    pub const fn threshold_label(self) -> &'static str {
        match self {
            Self::Tag => "Min score",
            Self::ClipText | Self::SimilarId | Self::UploadImage => "Min sim",
            _ => "",
        }
    }

    pub const fn as_prefix(self) -> &'static str {
        match self {
            Self::TitleAndAuthor => "all",
            Self::Title => "title",
            Self::Author => "author",
            Self::Tag => "tag",
            Self::PostTag => "post_tag",
            Self::ClipText => "clip",
            Self::SimilarId => "dino",
            Self::UploadImage => "upload",
            Self::Unclassified => "unclassified",
        }
    }

    pub const fn label(self, mode: QueryBuilderMode) -> &'static str {
        match self {
            Self::TitleAndAuthor => "Title & Author",
            Self::Title => "Title",
            Self::Author => "Author",
            Self::Tag => match mode {
                QueryBuilderMode::SafetyPolicy => "WD Tag",
                QueryBuilderMode::AdvancedSearch => "Tag",
            },
            Self::PostTag => "Post Tag",
            Self::ClipText => "CLIP Text",
            Self::SimilarId => "Similar ID",
            Self::UploadImage => "Upload Image",
            Self::Unclassified => "Unclassified",
        }
    }

    pub const fn placeholder(self, mode: QueryBuilderMode) -> &'static str {
        match self {
            Self::TitleAndAuthor => "Post title or author\u{2026}",
            Self::Title => "Post title keyword\u{2026}",
            Self::Author => match mode {
                QueryBuilderMode::SafetyPolicy => "Exact author name\u{2026}",
                QueryBuilderMode::AdvancedSearch => "Author name\u{2026}",
            },
            Self::Tag => match mode {
                QueryBuilderMode::SafetyPolicy => "canonical_wd_tag (e.g. explicit)",
                QueryBuilderMode::AdvancedSearch => "Tag or alias (EN / 中文 / 日本語)\u{2026}",
            },
            Self::PostTag => "Canonical post tag\u{2026}",
            Self::ClipText => "Describe scene, lighting, mood\u{2026}",
            Self::SimilarId => "Image ID (e.g. 2286979)",
            Self::UploadImage => "Upload slot index (e.g. 0)",
            Self::Unclassified => "Matches pending / unclassified media",
        }
    }

    pub const fn chip_placeholder(self) -> &'static str {
        match self {
            Self::Tag => "Type tag & press Enter or , \u{2026}",
            Self::PostTag => "Type post tag & press Enter or , \u{2026}",
            Self::Author => "Type author & press Enter or , \u{2026}",
            _ => "Type value & press Enter or , \u{2026}",
        }
    }

    pub fn parse_for_mode(raw: &str, mode: QueryBuilderMode) -> Option<Self> {
        let lower = raw.trim().to_ascii_lowercase();
        match mode {
            QueryBuilderMode::SafetyPolicy => match lower.as_str() {
                "tag" => Some(Self::Tag),
                "post_tag" => Some(Self::PostTag),
                "author" => Some(Self::Author),
                "unclassified" => Some(Self::Unclassified),
                _ => None,
            },
            QueryBuilderMode::AdvancedSearch => match lower.as_str() {
                "all" | "any" | "post" => Some(Self::TitleAndAuthor),
                "title" | "ti" => Some(Self::Title),
                "author" | "au" => Some(Self::Author),
                "tag" | "tg" => Some(Self::Tag),
                "clip" | "desc" => Some(Self::ClipText),
                "dino" | "similar" | "id" => Some(Self::SimilarId),
                "upload" | "img" => Some(Self::UploadImage),
                _ => None,
            },
        }
    }

    pub fn select_options(mode: QueryBuilderMode, in_group: bool) -> Vec<SelectOption> {
        let fields = if in_group {
            Self::group_fields_for_mode(mode)
        } else {
            Self::fields_for_mode(mode)
        };
        fields
            .iter()
            .map(|f| SelectOption::new(f.as_prefix(), f.label(mode)))
            .collect()
    }
}

/// Top-level boolean connector joining nodes (`AND` / `OR`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryConnector {
    #[default]
    And,
    Or,
}

impl QueryConnector {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::And => "and",
            Self::Or => "or",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "or" => Self::Or,
            _ => Self::And,
        }
    }
}

/// Inner boolean combinator inside a parenthesized [`QueryGroup`] (`OR` / `AND`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryCombinator {
    #[default]
    Or,
    And,
}

impl QueryCombinator {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Or => "or",
            Self::And => "and",
        }
    }

    pub const fn upper(self) -> &'static str {
        match self {
            Self::Or => "OR",
            Self::And => "AND",
        }
    }
}

/// Single query condition with optional negation (`NOT`) and optional per-condition
/// score/similarity threshold (`>=0.01..=1.00`, hundredths precision).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryCondition {
    pub id: u64,
    #[serde(default)]
    pub field: QueryFieldKind,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub negated: bool,
    #[serde(default)]
    pub threshold: Option<f32>,
}

impl QueryCondition {
    /// Effective single-value operator (`Is` or `IsNot`).
    pub const fn operator(&self) -> QueryConditionOp {
        if self.negated {
            QueryConditionOp::IsNot
        } else {
            QueryConditionOp::Is
        }
    }
}

/// Multi-value `IN (...)` / `NOT IN (...)` condition for discrete list-capable fields
/// (`Tag`, `PostTag`, `Author`) with optional shared `>=` score threshold on `Tag`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryListCondition {
    pub id: u64,
    #[serde(default)]
    pub field: QueryFieldKind,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub negated: bool,
    #[serde(default)]
    pub threshold: Option<f32>,
}

impl QueryListCondition {
    /// Effective list operator (`In` or `NotIn`).
    pub const fn operator(&self) -> QueryConditionOp {
        if self.negated {
            QueryConditionOp::NotIn
        } else {
            QueryConditionOp::In
        }
    }

    pub fn set_operator(&mut self, op: QueryConditionOp) {
        self.negated = op.is_negated();
    }
}

/// Parenthesized `( ... )` boolean group containing 1..N [`QueryCondition`] rows.
///
/// Inner conditions using `IN` / `NOT IN` store their multi-chip value list in
/// `list_values` keyed by `QueryCondition::id`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryGroup {
    pub id: u64,
    #[serde(default)]
    pub combinator: QueryCombinator,
    #[serde(default)]
    pub connector: QueryConnector,
    #[serde(default)]
    pub negated: bool,
    #[serde(default)]
    pub conditions: Vec<QueryCondition>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub list_values: BTreeMap<u64, Vec<String>>,
}

impl QueryGroup {
    pub fn condition_operator(&self, cond: &QueryCondition) -> QueryConditionOp {
        if self.list_values.contains_key(&cond.id) {
            if cond.negated {
                QueryConditionOp::NotIn
            } else {
                QueryConditionOp::In
            }
        } else {
            cond.operator()
        }
    }
}

/// Ordered top-level item inside a [`QueryBuilderDraft`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum QueryBuilderNode {
    Condition {
        #[serde(default)]
        connector: QueryConnector,
        condition: QueryCondition,
    },
    ListCondition {
        #[serde(default)]
        connector: QueryConnector,
        condition: QueryListCondition,
    },
    Group(QueryGroup),
}

impl QueryBuilderNode {
    pub const fn id(&self) -> u64 {
        match self {
            Self::Condition { condition, .. } => condition.id,
            Self::ListCondition { condition, .. } => condition.id,
            Self::Group(group) => group.id,
        }
    }

    pub const fn connector(&self) -> QueryConnector {
        match self {
            Self::Condition { connector, .. } => *connector,
            Self::ListCondition { connector, .. } => *connector,
            Self::Group(group) => group.connector,
        }
    }

    pub fn set_connector(&mut self, next: QueryConnector) {
        match self {
            Self::Condition { connector, .. } => *connector = next,
            Self::ListCondition { connector, .. } => *connector = next,
            Self::Group(group) => group.connector = next,
        }
    }

    pub fn is_vector(&self) -> bool {
        match self {
            Self::Condition { condition, .. } => condition.field.is_vector(),
            Self::ListCondition { condition, .. } => condition.field.is_vector(),
            Self::Group(group) => group.conditions.iter().any(|c| c.field.is_vector()),
        }
    }
}

/// Effective default thresholds displayed as subtle placeholders when a condition's
/// per-condition `threshold` is `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct QueryThresholdDefaults {
    pub tag_min_score: Option<f32>,
    pub clip_min_sim: Option<f32>,
    pub dino_min_sim: Option<f32>,
}

impl QueryThresholdDefaults {
    pub fn placeholder_for(self, field: QueryFieldKind, mode: QueryBuilderMode) -> String {
        match field {
            QueryFieldKind::Tag => match self.tag_min_score.and_then(quantize_threshold) {
                Some(v) => format_threshold(v),
                None if mode == QueryBuilderMode::SafetyPolicy => "0.45".to_string(),
                None => "default".to_string(),
            },
            QueryFieldKind::ClipText => match self.clip_min_sim.and_then(quantize_threshold) {
                Some(v) => format_threshold(v),
                None => "default".to_string(),
            },
            QueryFieldKind::SimilarId | QueryFieldKind::UploadImage => {
                match self.dino_min_sim.and_then(quantize_threshold) {
                    Some(v) => format_threshold(v),
                    None => "default".to_string(),
                }
            }
            _ => String::new(),
        }
    }
}

/// Complete visual + text query state bound to [`QueryBuilder`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryBuilderDraft {
    #[serde(default)]
    pub mode: QueryBuilderMode,
    #[serde(default)]
    pub nodes: Vec<QueryBuilderNode>,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub active_preset: Option<String>,
}

impl Default for QueryBuilderDraft {
    fn default() -> Self {
        Self::for_mode(QueryBuilderMode::AdvancedSearch)
    }
}

impl QueryBuilderDraft {
    pub fn for_mode(mode: QueryBuilderMode) -> Self {
        Self {
            mode,
            nodes: vec![QueryBuilderNode::Condition {
                connector: QueryConnector::And,
                condition: QueryCondition {
                    id: alloc_qb_id(),
                    field: QueryFieldKind::Tag,
                    value: String::new(),
                    negated: false,
                    threshold: None,
                },
            }],
            query: String::new(),
            active_preset: None,
        }
    }

    pub fn from_query(mode: QueryBuilderMode, query: &str) -> Result<Self, String> {
        let mut alloc = alloc_qb_id;
        let nodes = parse_query_to_nodes(mode, query, &mut alloc)?;
        let normalized_nodes = if nodes.is_empty() {
            Self::for_mode(mode).nodes
        } else {
            nodes
        };
        let mut draft = Self {
            mode,
            nodes: normalized_nodes,
            query: query.trim().to_string(),
            active_preset: None,
        };
        draft.normalize_for_mode();
        Ok(draft)
    }

    pub fn has_vector_node(&self) -> bool {
        self.nodes.iter().any(QueryBuilderNode::is_vector)
    }

    pub fn normalize_for_mode(&mut self) {
        if let Some(first) = self.nodes.first_mut()
            && first.connector() == QueryConnector::Or
        {
            first.set_connector(QueryConnector::And);
        }
        if self.mode == QueryBuilderMode::AdvancedSearch && self.has_vector_node() {
            for node in &mut self.nodes {
                if node.connector() == QueryConnector::Or {
                    node.set_connector(QueryConnector::And);
                }
            }
        }
    }

    pub fn format_query(&self) -> String {
        format_query_nodes(&self.nodes)
    }

    pub fn sync_query(&mut self) {
        self.normalize_for_mode();
        self.query = format_query_nodes(&self.nodes);
    }
}

fn quote_query_value_if_needed(raw: &str) -> String {
    let needs_quote = raw.is_empty()
        || raw.starts_with('/')
        || raw.starts_with('-')
        || raw.eq_ignore_ascii_case("AND")
        || raw.eq_ignore_ascii_case("OR")
        || raw.eq_ignore_ascii_case("NOT")
        || raw.chars().any(|c| {
            c.is_whitespace() || matches!(c, '(' | ')' | '"' | '\\' | '>' | '<' | '~' | '=' | ':')
        });
    if !needs_quote {
        return raw.to_string();
    }
    let escaped = raw.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn quote_query_list_item_if_needed(raw: &str) -> String {
    let needs_quote = raw.is_empty()
        || raw.starts_with('/')
        || raw.starts_with('-')
        || raw.eq_ignore_ascii_case("AND")
        || raw.eq_ignore_ascii_case("OR")
        || raw.eq_ignore_ascii_case("NOT")
        || raw.eq_ignore_ascii_case("IN")
        || raw.chars().any(|c| {
            c.is_whitespace()
                || matches!(c, '(' | ')' | '"' | '\\' | '>' | '<' | '~' | '=' | ':' | ',')
        });
    if !needs_quote {
        return raw.to_string();
    }
    let escaped = raw.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Format a single [`QueryCondition`] into canonical query syntax (including `>=0.45`
/// hundredths-precision threshold when set on `Tag`, `ClipText`, `SimilarId`, or `UploadImage`).
pub fn format_query_condition(cond: &QueryCondition) -> Option<String> {
    let base = match cond.field {
        QueryFieldKind::Unclassified => "unclassified".to_string(),
        _ => {
            let trimmed = cond.value.trim();
            if trimmed.is_empty() {
                return None;
            }
            let encoded = quote_query_value_if_needed(trimmed);
            let prefix = cond.field.as_prefix();
            if cond.field.supports_threshold()
                && let Some(score) = cond.threshold.and_then(quantize_threshold)
            {
                format!("{prefix}:{encoded}>={}", format_threshold(score))
            } else {
                format!("{prefix}:{encoded}")
            }
        }
    };
    Some(if cond.negated {
        format!("NOT {base}")
    } else {
        base
    })
}

/// Format a [`QueryListCondition`] into canonical `IN` / `NOT IN` query syntax, e.g.:
/// - `tag IN (explicit, nude, nipples) >= 0.45`
/// - `tag NOT IN (safe, general) >= 0.45`
/// - `author IN ("alice smith", bob)`
pub fn format_query_list_condition(cond: &QueryListCondition) -> Option<String> {
    if !cond.field.supports_in() {
        return None;
    }
    let items: Vec<String> = cond
        .values
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(quote_query_list_item_if_needed)
        .collect();
    if items.is_empty() {
        return None;
    }
    let prefix = cond.field.as_prefix();
    let op = if cond.negated { "NOT IN" } else { "IN" };
    let joined = items.join(", ");
    if cond.field.supports_threshold()
        && let Some(score) = cond.threshold.and_then(quantize_threshold)
    {
        Some(format!(
            "{prefix} {op} ({joined}) >= {}",
            format_threshold(score)
        ))
    } else {
        Some(format!("{prefix} {op} ({joined})"))
    }
}

/// Format visual [`QueryBuilderNode`] entries into canonical query syntax.
pub fn format_query_nodes(nodes: &[QueryBuilderNode]) -> String {
    let mut or_branches: Vec<Vec<String>> = Vec::new();
    let mut current_and: Vec<String> = Vec::new();

    for node in nodes {
        let (connector, formatted) = match node {
            QueryBuilderNode::Condition {
                connector,
                condition,
            } => (*connector, format_query_condition(condition)),
            QueryBuilderNode::ListCondition {
                connector,
                condition,
            } => (*connector, format_query_list_condition(condition)),
            QueryBuilderNode::Group(group) => {
                let parts: Vec<String> = group
                    .conditions
                    .iter()
                    .filter_map(|c| {
                        if let Some(vals) = group.list_values.get(&c.id) {
                            format_query_list_condition(&QueryListCondition {
                                id: c.id,
                                field: c.field,
                                values: vals.clone(),
                                negated: c.negated,
                                threshold: c.threshold,
                            })
                        } else {
                            format_query_condition(c)
                        }
                    })
                    .collect();
                let expr = match parts.len() {
                    0 => None,
                    1 => {
                        let only = parts.into_iter().next().unwrap();
                        if group.negated {
                            if only.starts_with("NOT ") || only.contains(" NOT IN ") {
                                Some(format!("NOT ({only})"))
                            } else {
                                Some(format!("NOT {only}"))
                            }
                        } else {
                            Some(only)
                        }
                    }
                    _ => {
                        let sep = match group.combinator {
                            QueryCombinator::Or => " OR ",
                            QueryCombinator::And => " AND ",
                        };
                        let joined = format!("({})", parts.join(sep));
                        if group.negated {
                            Some(format!("NOT {joined}"))
                        } else {
                            Some(joined)
                        }
                    }
                };
                (group.connector, expr)
            }
        };

        let Some(expr) = formatted else {
            continue;
        };

        match connector {
            QueryConnector::And => current_and.push(expr),
            QueryConnector::Or => {
                if !current_and.is_empty() {
                    or_branches.push(std::mem::take(&mut current_and));
                }
                current_and.push(expr);
            }
        }
    }

    if !current_and.is_empty() {
        or_branches.push(current_and);
    }

    or_branches
        .into_iter()
        .filter(|b| !b.is_empty())
        .map(|b| b.join(" AND "))
        .collect::<Vec<_>>()
        .join(" OR ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QbAtomValue {
    text: String,
    quoted: bool,
    trailing: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QbAtom {
    prefix: String,
    rest: Option<QbAtomValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QbListItem {
    text: String,
    quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QbInList {
    prefix: String,
    negated_in: bool,
    items: Vec<QbListItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QbToken {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Minus,
    Gte,
    Atom(QbAtom),
    InList(QbInList),
}

fn is_gte_at(chars: &[char], i: usize) -> bool {
    chars.get(i) == Some(&'>') && chars.get(i + 1) == Some(&'=')
}

fn skip_ws_qb(chars: &[char], i: &mut usize) {
    while *i < chars.len() && chars[*i].is_whitespace() {
        *i += 1;
    }
}

fn peek_word_qb(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut i = start;
    let mut word = String::new();
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace()
            || matches!(c, '(' | ')' | ':' | '"' | ',')
            || is_gte_at(chars, i)
        {
            break;
        }
        word.push(c);
        i += 1;
    }
    (!word.is_empty()).then_some((word, i))
}

fn is_known_in_candidate_in_advanced(prefix: &str) -> bool {
    QueryFieldKind::parse_for_mode(prefix, QueryBuilderMode::AdvancedSearch).is_some()
        || prefix.eq_ignore_ascii_case("post_tag")
        || prefix.eq_ignore_ascii_case("unclassified")
}

/// If the characters after a bare field word `prefix` match `[NOT] IN ( ... )`
/// (case-insensitive), consume the entire list expression up to and including `)`
/// and return `Ok(Some(QbInList))`. Otherwise leave `i` unchanged and return `Ok(None)`.
///
/// In `AdvancedSearch` mode, non-field words (e.g. `alice in (wonderland)`) are left as
/// bare words so free-text queries containing the word `in` continue to work naturally.
fn try_consume_in_list_qb(
    chars: &[char],
    i: &mut usize,
    prefix: &str,
    mode: QueryBuilderMode,
) -> Result<Option<QbInList>, String> {
    if mode == QueryBuilderMode::AdvancedSearch && !is_known_in_candidate_in_advanced(prefix) {
        return Ok(None);
    }
    let mut look = *i;
    skip_ws_qb(chars, &mut look);
    let Some((first_word, after_first)) = peek_word_qb(chars, look) else {
        return Ok(None);
    };
    let (negated_in, after_in) = if first_word.eq_ignore_ascii_case("IN") {
        (false, after_first)
    } else if first_word.eq_ignore_ascii_case("NOT") {
        let mut next_pos = after_first;
        skip_ws_qb(chars, &mut next_pos);
        let Some((second_word, after_second)) = peek_word_qb(chars, next_pos) else {
            return Ok(None);
        };
        if !second_word.eq_ignore_ascii_case("IN") {
            return Ok(None);
        }
        (true, after_second)
    } else {
        return Ok(None);
    };

    let mut paren_pos = after_in;
    skip_ws_qb(chars, &mut paren_pos);
    if chars.get(paren_pos) != Some(&'(') {
        return Ok(None);
    }

    *i = paren_pos + 1; // consume '('
    let mut items = Vec::new();
    let mut closed = false;
    let mut saw_comma = false;

    while *i < chars.len() {
        skip_ws_qb(chars, i);
        if *i >= chars.len() {
            break;
        }
        let c = chars[*i];
        if c == ')' {
            *i += 1;
            closed = true;
            break;
        }
        if c == '(' {
            return Err("Nested `(` is not allowed inside `IN (...)` list".to_string());
        }
        if c == ',' {
            if items.is_empty() || saw_comma {
                return Err("Unexpected `,` inside `IN (...)` list".to_string());
            }
            saw_comma = true;
            *i += 1;
            continue;
        }
        if c == '"' {
            let text = read_quoted_qb(chars, i)?;
            if *i < chars.len() && !chars[*i].is_whitespace() && !matches!(chars[*i], ',' | ')') {
                return Err(
                    "Unexpected trailing characters after quoted item in `IN (...)`".to_string(),
                );
            }
            items.push(QbListItem { text, quoted: true });
            saw_comma = false;
        } else {
            let mut text = String::new();
            while *i < chars.len() {
                let uc = chars[*i];
                if uc.is_whitespace() || matches!(uc, ',' | '(' | ')') {
                    break;
                }
                if uc == '"' {
                    return Err(
                        "Unexpected quote inside unquoted item in `IN (...)` list".to_string(),
                    );
                }
                text.push(uc);
                *i += 1;
            }
            items.push(QbListItem {
                text,
                quoted: false,
            });
            saw_comma = false;
        }
    }

    if !closed {
        return Err("Unclosed `(` in `IN (...)` list".to_string());
    }
    if saw_comma {
        return Err("Trailing `,` before `)` in `IN (...)` list".to_string());
    }
    if items.is_empty() {
        return Err("Empty value list in `IN ()` is not allowed".to_string());
    }

    Ok(Some(QbInList {
        prefix: prefix.to_string(),
        negated_in,
        items,
    }))
}

fn tokenize_qb(input: &str, mode: QueryBuilderMode) -> Result<Vec<QbToken>, String> {
    if input.len() > MAX_RULE_LEN {
        return Err(format!(
            "Query exceeds maximum length of {MAX_RULE_LEN} bytes"
        ));
    }
    if input
        .chars()
        .any(|c| c == '\0' || (c.is_control() && !matches!(c, ' ' | '\t' | '\n' | '\r')))
    {
        return Err("Control characters are not allowed in query".to_string());
    }

    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut tokens = Vec::new();

    while i < chars.len() {
        let ch = chars[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        if ch == '(' {
            tokens.push(QbToken::LParen);
            i += 1;
            continue;
        }
        if ch == ')' {
            tokens.push(QbToken::RParen);
            i += 1;
            continue;
        }
        if is_gte_at(&chars, i) {
            tokens.push(QbToken::Gte);
            i += 2;
            continue;
        }
        if ch == '-' {
            if i + 1 < chars.len() && !chars[i + 1].is_whitespace() {
                tokens.push(QbToken::Minus);
                i += 1;
                continue;
            }
            return Err("Expected a predicate or '(' after '-'".to_string());
        }
        if ch == '/' && mode == QueryBuilderMode::SafetyPolicy {
            return Err("Regular expressions are not allowed in safety policies".to_string());
        }
        if ch == '"' {
            if mode == QueryBuilderMode::SafetyPolicy {
                return Err(
                    "Bare quoted text is not allowed — prefix with tag:, post_tag:, or author:"
                        .to_string(),
                );
            }
            let quoted = read_quoted_qb(&chars, &mut i)?;
            let mut trailing = String::new();
            while i < chars.len() {
                let c = chars[i];
                if c.is_whitespace() || c == '(' || c == ')' || is_gte_at(&chars, i) {
                    break;
                }
                if c == '"' {
                    return Err("Unexpected extra quote after value".to_string());
                }
                trailing.push(c);
                i += 1;
            }
            tokens.push(QbToken::Atom(QbAtom {
                prefix: "all".to_string(),
                rest: Some(QbAtomValue {
                    text: quoted,
                    quoted: true,
                    trailing,
                }),
            }));
            continue;
        }

        let mut prefix = String::new();
        while i < chars.len() {
            let c = chars[i];
            if c == ':' || c.is_whitespace() || c == '(' || c == ')' || is_gte_at(&chars, i) {
                break;
            }
            if c == '"' {
                return Err("Unexpected quote in field name".to_string());
            }
            prefix.push(c);
            i += 1;
        }

        if i < chars.len() && chars[i] == ':' {
            if prefix.is_empty() {
                return Err("Missing field name before `:`".to_string());
            }
            i += 1;
            let rest = if i < chars.len() && chars[i] == '"' {
                let text = read_quoted_qb(&chars, &mut i)?;
                let mut trailing = String::new();
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_whitespace() || c == '(' || c == ')' || is_gte_at(&chars, i) {
                        break;
                    }
                    if c == '"' {
                        return Err("Unexpected extra quote after value".to_string());
                    }
                    trailing.push(c);
                    i += 1;
                }
                QbAtomValue {
                    text,
                    quoted: true,
                    trailing,
                }
            } else {
                let mut text = String::new();
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_whitespace() || c == '(' || c == ')' || is_gte_at(&chars, i) {
                        break;
                    }
                    if c == '"' {
                        return Err(
                            "Quote must immediately follow `:` (e.g. clip:\"sunlit sky\")"
                                .to_string(),
                        );
                    }
                    text.push(c);
                    i += 1;
                }
                QbAtomValue {
                    text,
                    quoted: false,
                    trailing: String::new(),
                }
            };
            tokens.push(QbToken::Atom(QbAtom {
                prefix,
                rest: Some(rest),
            }));
        } else {
            match prefix.to_ascii_uppercase().as_str() {
                "AND" => tokens.push(QbToken::And),
                "OR" => tokens.push(QbToken::Or),
                "NOT" => tokens.push(QbToken::Not),
                _ => {
                    if let Some(in_list) = try_consume_in_list_qb(&chars, &mut i, &prefix, mode)? {
                        tokens.push(QbToken::InList(in_list));
                    } else {
                        tokens.push(QbToken::Atom(QbAtom { prefix, rest: None }));
                    }
                }
            }
        }
    }

    Ok(tokens)
}

fn read_quoted_qb(chars: &[char], i: &mut usize) -> Result<String, String> {
    *i += 1; // opening '"'
    let mut text = String::new();
    let mut closed = false;
    while *i < chars.len() {
        let c = chars[*i];
        if c.is_control() {
            return Err("Control characters are not allowed inside quoted values".to_string());
        }
        if c == '\\' {
            if *i + 1 >= chars.len() {
                return Err("Trailing backslash in quoted value".to_string());
            }
            let next = chars[*i + 1];
            if next.is_control() {
                return Err("Control characters are not allowed inside quoted values".to_string());
            }
            text.push(next);
            *i += 2;
            continue;
        }
        if c == '"' {
            closed = true;
            *i += 1;
            break;
        }
        text.push(c);
        *i += 1;
    }
    if !closed {
        return Err("Unclosed quote in query".to_string());
    }
    Ok(text)
}

fn reject_safety_disallowed_syntax(raw: &str, field_name: &str) -> Result<(), String> {
    if raw.starts_with('/') {
        return Err(format!(
            "Regex patterns are not allowed in safety policies (`{field_name}:{raw}`)"
        ));
    }
    if raw.contains("~=")
        || raw.contains("=~")
        || raw.contains("<=")
        || raw.contains("!=")
        || raw.contains('>')
        || raw.contains('<')
    {
        return Err(format!(
            "Unsupported comparator in `{field_name}:{raw}` (only `>=` on `tag:` is allowed)"
        ));
    }
    if let Some((lhs, rhs)) = raw.rsplit_once('=')
        && !lhs.is_empty()
        && !lhs.ends_with(['>', '<', '~', '!'])
        && !rhs.is_empty()
        && rhs.parse::<f32>().is_ok_and(f32::is_finite)
    {
        return Err(format!(
            "Invalid `=` threshold in `{field_name}:{raw}` (use `>=`, e.g. tag:blood>=0.50)"
        ));
    }
    Ok(())
}

fn consume_optional_threshold(
    tokens: &[QbToken],
    pos: &mut usize,
    field: QueryFieldKind,
) -> Result<Option<f32>, String> {
    if !matches!(tokens.get(*pos), Some(QbToken::Gte)) {
        return Ok(None);
    }
    if !field.supports_threshold() {
        return Err(format!(
            "Thresholds (`>=`) are not supported on `{}`",
            field.as_prefix()
        ));
    }
    *pos += 1; // consume `>=`

    let threshold = match tokens.get(*pos) {
        Some(QbToken::Atom(atom)) if atom.rest.is_none() => {
            *pos += 1;
            parse_threshold_hundredths(&atom.prefix)?
        }
        Some(QbToken::Minus) => {
            return Err("Threshold out of range (must be between 0.01 and 1.00)".to_string());
        }
        Some(QbToken::Gte) => {
            return Err("Multiple `>=` thresholds in one condition".to_string());
        }
        _ => {
            return Err("Missing threshold after `>=`".to_string());
        }
    };

    if matches!(tokens.get(*pos), Some(QbToken::Gte)) {
        return Err("Multiple `>=` thresholds in one condition".to_string());
    }

    Ok(Some(threshold))
}

fn parse_qb_in_list(
    in_list: &QbInList,
    mode: QueryBuilderMode,
    in_group: bool,
    outer_negated: bool,
    next_id: &mut impl FnMut() -> u64,
) -> Result<QueryListCondition, String> {
    if outer_negated && in_list.negated_in {
        return Err("Double negation (`NOT ... NOT IN`) is not allowed".to_string());
    }
    let field = QueryFieldKind::parse_for_mode(&in_list.prefix, mode).ok_or_else(|| match mode {
        QueryBuilderMode::SafetyPolicy => format!(
            "Disallowed predicate `{}` in `IN (...)` safety policy (allowed: tag, post_tag, author)",
            in_list.prefix
        ),
        QueryBuilderMode::AdvancedSearch => format!(
            "Unsupported field `{}` for `IN (...)` (allowed: tag, author)",
            in_list.prefix
        ),
    })?;

    if !field.supports_in() {
        return Err(format!(
            "`{}` does not support `IN (...)` / `NOT IN (...)` (only discrete metadata fields do)",
            field.as_prefix()
        ));
    }
    if in_group && field.is_vector() {
        return Err("Vector clauses cannot be placed inside parenthesized groups".to_string());
    }

    let field_name = field.as_prefix();
    let mut values = Vec::with_capacity(in_list.items.len());
    for item in &in_list.items {
        let trimmed = item.text.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "Empty value inside `{field_name} IN (...)` is not allowed"
            ));
        }
        if !item.quoted {
            if trimmed.contains(">=") {
                return Err(format!(
                    "Place `>=` threshold outside `)` (e.g. `{field_name} IN (a, b) >= 0.45`)"
                ));
            }
            if mode == QueryBuilderMode::SafetyPolicy {
                reject_safety_disallowed_syntax(trimmed, field_name)?;
            }
        }
        values.push(trimmed.to_string());
    }

    if values.is_empty() {
        return Err(format!("Empty value list in `{field_name} IN ()` is not allowed"));
    }

    Ok(QueryListCondition {
        id: next_id(),
        field,
        values,
        negated: outer_negated || in_list.negated_in,
        threshold: None,
    })
}

fn parse_qb_atom(
    atom: &QbAtom,
    mode: QueryBuilderMode,
    in_group: bool,
    negated: bool,
    next_id: &mut impl FnMut() -> u64,
) -> Result<QueryCondition, String> {
    let Some(rest) = &atom.rest else {
        if mode == QueryBuilderMode::SafetyPolicy {
            if atom.prefix.eq_ignore_ascii_case("unclassified") {
                return Ok(QueryCondition {
                    id: next_id(),
                    field: QueryFieldKind::Unclassified,
                    value: String::new(),
                    negated,
                    threshold: None,
                });
            }
            return Err(format!(
                "Unsupported term `{}` — use tag:, post_tag:, author:, unclassified, or tag IN (...)",
                atom.prefix
            ));
        }
        return Ok(QueryCondition {
            id: next_id(),
            field: QueryFieldKind::TitleAndAuthor,
            value: atom.prefix.clone(),
            negated,
            threshold: None,
        });
    };

    let field = QueryFieldKind::parse_for_mode(&atom.prefix, mode).ok_or_else(|| match mode {
        QueryBuilderMode::SafetyPolicy => format!(
            "Disallowed predicate `{}:` in safety policy (only tag:, post_tag:, author:, unclassified are allowed)",
            atom.prefix
        ),
        QueryBuilderMode::AdvancedSearch => format!("Unsupported field `{}:`", atom.prefix),
    })?;

    if in_group && field.is_vector() {
        return Err(
            "Vector clauses (clip:, dino:, upload:) cannot be placed inside parenthesized groups"
                .to_string(),
        );
    }

    if field == QueryFieldKind::Unclassified {
        return Err("`unclassified` takes no value (write bare `unclassified`)".to_string());
    }

    let field_name = field.as_prefix();
    if rest.quoted {
        if !rest.trailing.is_empty() {
            return Err(format!(
                "Unexpected suffix `{}` after quoted value for `{field_name}:`",
                rest.trailing
            ));
        }
        let trimmed = rest.text.trim();
        if trimmed.is_empty() {
            return Err(format!("Missing value after `{field_name}:`"));
        }
        return Ok(QueryCondition {
            id: next_id(),
            field,
            value: trimmed.to_string(),
            negated,
            threshold: None,
        });
    }

    let raw = rest.text.trim();
    if raw.is_empty() {
        return Err(format!("Missing value after `{field_name}:`"));
    }
    if mode == QueryBuilderMode::SafetyPolicy {
        reject_safety_disallowed_syntax(raw, field_name)?;
    }

    Ok(QueryCondition {
        id: next_id(),
        field,
        value: raw.to_string(),
        negated,
        threshold: None,
    })
}

/// Parse a flat or single-level-parenthesized query string into visual [`QueryBuilderNode`] items
/// for the given [`QueryBuilderMode`].
///
/// Supports:
/// - Multi-value `IN (...)` / `NOT IN (...)` / `NOT field IN (...)` lists on discrete metadata
///   fields (`tag`, `author` in `AdvancedSearch`; `tag`, `post_tag`, `author` in `SafetyPolicy`)
/// - Optional whitespace around `>=` outside quotes or `)` (`tag:maid>=0.45`, `tag IN (a, b) >= 0.45`)
/// - Hundredths-precision thresholds `0.01..=1.00` on `tag:`, `clip:`, `dino:`, `upload:`
/// - Unary `-` (`-tag:monochrome`, `-(tag:a OR tag:b)`) as equivalent to `NOT`
pub fn parse_query_to_nodes(
    mode: QueryBuilderMode,
    query: &str,
    next_id: &mut impl FnMut() -> u64,
) -> Result<Vec<QueryBuilderNode>, String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let tokens = tokenize_qb(trimmed, mode)?;
    let mut nodes = Vec::new();
    let mut term_count = 0usize;
    let mut pos = 0usize;
    let mut expect_operand = true;
    let mut pending_conn = QueryConnector::And;
    let mut pending_neg = false;

    while pos < tokens.len() {
        if !expect_operand {
            match &tokens[pos] {
                QbToken::And => {
                    pending_conn = QueryConnector::And;
                    pending_neg = false;
                    expect_operand = true;
                    pos += 1;
                }
                QbToken::Or => {
                    pending_conn = QueryConnector::Or;
                    pending_neg = false;
                    expect_operand = true;
                    pos += 1;
                }
                QbToken::RParen => return Err("Unexpected `)` in query".to_string()),
                QbToken::Gte => {
                    return Err("Unexpected `>=` threshold operator".to_string());
                }
                QbToken::Not
                | QbToken::Minus
                | QbToken::Atom(_)
                | QbToken::InList(_)
                | QbToken::LParen => {
                    if mode == QueryBuilderMode::SafetyPolicy {
                        return Err(
                            "Missing explicit `AND` or `OR` operator between predicates"
                                .to_string(),
                        );
                    }
                    // AdvancedSearch allows implicit adjacency (`tag:maid NOT tag:monochrome`).
                    pending_conn = QueryConnector::And;
                    pending_neg = false;
                    expect_operand = true;
                }
            }
            continue;
        }

        match &tokens[pos] {
            QbToken::And | QbToken::Or => {
                return Err(
                    "Unexpected binary operator (`AND`/`OR`) without left operand".to_string(),
                );
            }
            QbToken::RParen => return Err("Unexpected `)` in query".to_string()),
            QbToken::Gte => return Err("Unexpected `>=` threshold without predicate".to_string()),
            QbToken::Not | QbToken::Minus => {
                if pending_neg {
                    return Err("Duplicate `NOT`/`-` operator is not allowed".to_string());
                }
                pending_neg = true;
                pos += 1;
            }
            QbToken::LParen => {
                pos += 1;
                let mut conditions = Vec::new();
                let mut list_values: BTreeMap<u64, Vec<String>> = BTreeMap::new();
                let mut combinator: Option<QueryCombinator> = None;
                let mut inner_expect_operand = true;
                let mut inner_neg = false;
                let mut closed = false;

                while pos < tokens.len() {
                    if !inner_expect_operand {
                        match &tokens[pos] {
                            QbToken::RParen => {
                                pos += 1;
                                closed = true;
                                break;
                            }
                            QbToken::Or => {
                                if combinator == Some(QueryCombinator::And) {
                                    return Err(
                                        "Cannot mix `AND` and `OR` inside one visual group"
                                            .to_string(),
                                    );
                                }
                                combinator = Some(QueryCombinator::Or);
                                inner_expect_operand = true;
                                inner_neg = false;
                                pos += 1;
                            }
                            QbToken::And => {
                                if combinator == Some(QueryCombinator::Or) {
                                    return Err(
                                        "Cannot mix `OR` and `AND` inside one visual group"
                                            .to_string(),
                                    );
                                }
                                combinator = Some(QueryCombinator::And);
                                inner_expect_operand = true;
                                inner_neg = false;
                                pos += 1;
                            }
                            QbToken::Gte => {
                                return Err("Unexpected `>=` threshold operator inside group"
                                    .to_string());
                            }
                            QbToken::Not
                            | QbToken::Minus
                            | QbToken::Atom(_)
                            | QbToken::InList(_)
                            | QbToken::LParen => {
                                if mode == QueryBuilderMode::SafetyPolicy {
                                    return Err(
                                        "Missing explicit `AND` or `OR` inside `(...)` group"
                                            .to_string(),
                                    );
                                }
                                if combinator == Some(QueryCombinator::Or) {
                                    return Err(
                                        "Cannot mix `OR` and implicit `AND` inside one group"
                                            .to_string(),
                                    );
                                }
                                combinator = Some(QueryCombinator::And);
                                inner_expect_operand = true;
                                inner_neg = false;
                            }
                        }
                        continue;
                    }

                    match &tokens[pos] {
                        QbToken::RParen => {
                            if conditions.is_empty() && !inner_neg {
                                return Err("Empty `()` group in query".to_string());
                            }
                            return Err("Trailing operator before `)` in group".to_string());
                        }
                        QbToken::LParen => {
                            return Err(
                                "Nested parentheses inside group are not editable in visual mode"
                                    .to_string(),
                            );
                        }
                        QbToken::And | QbToken::Or => {
                            return Err("Unexpected `AND`/`OR` operator inside group".to_string());
                        }
                        QbToken::Gte => {
                            return Err(
                                "Unexpected `>=` threshold without predicate inside group"
                                    .to_string(),
                            );
                        }
                        QbToken::Not | QbToken::Minus => {
                            if inner_neg {
                                return Err(
                                    "Duplicate `NOT`/`-` operator inside group".to_string()
                                );
                            }
                            inner_neg = true;
                            pos += 1;
                        }
                        QbToken::Atom(atom) => {
                            term_count += 1;
                            if term_count > MAX_TERMS_PER_RULE {
                                return Err(format!(
                                    "Query exceeds maximum of {MAX_TERMS_PER_RULE} terms"
                                ));
                            }
                            let mut cond = parse_qb_atom(atom, mode, true, inner_neg, next_id)?;
                            pos += 1;
                            cond.threshold =
                                consume_optional_threshold(&tokens, &mut pos, cond.field)?;
                            conditions.push(cond);
                            inner_neg = false;
                            inner_expect_operand = false;
                        }
                        QbToken::InList(in_list) => {
                            term_count += in_list.items.len();
                            if term_count > MAX_TERMS_PER_RULE {
                                return Err(format!(
                                    "Query exceeds maximum of {MAX_TERMS_PER_RULE} terms"
                                ));
                            }
                            let mut list_cond =
                                parse_qb_in_list(in_list, mode, true, inner_neg, next_id)?;
                            pos += 1;
                            list_cond.threshold =
                                consume_optional_threshold(&tokens, &mut pos, list_cond.field)?;
                            let cid = list_cond.id;
                            let first_val = list_cond.values.first().cloned().unwrap_or_default();
                            list_values.insert(cid, list_cond.values);
                            conditions.push(QueryCondition {
                                id: cid,
                                field: list_cond.field,
                                value: first_val,
                                negated: list_cond.negated,
                                threshold: list_cond.threshold,
                            });
                            inner_neg = false;
                            inner_expect_operand = false;
                        }
                    }
                }

                if !closed {
                    return Err("Unclosed `(` in query".to_string());
                }
                if conditions.is_empty() {
                    return Err("Empty `()` group in query".to_string());
                }
                if matches!(tokens.get(pos), Some(QbToken::Gte)) {
                    return Err(
                        "Threshold (`>=`) cannot be applied to a parenthesized group".to_string(),
                    );
                }
                nodes.push(QueryBuilderNode::Group(QueryGroup {
                    id: next_id(),
                    combinator: combinator.unwrap_or(QueryCombinator::Or),
                    connector: pending_conn,
                    negated: pending_neg,
                    conditions,
                    list_values,
                }));
                pending_conn = QueryConnector::And;
                pending_neg = false;
                expect_operand = false;
            }
            QbToken::Atom(atom) => {
                term_count += 1;
                if term_count > MAX_TERMS_PER_RULE {
                    return Err(format!(
                        "Query exceeds maximum of {MAX_TERMS_PER_RULE} terms"
                    ));
                }
                let mut cond = parse_qb_atom(atom, mode, false, pending_neg, next_id)?;
                pos += 1;
                cond.threshold = consume_optional_threshold(&tokens, &mut pos, cond.field)?;
                nodes.push(QueryBuilderNode::Condition {
                    connector: pending_conn,
                    condition: cond,
                });
                pending_conn = QueryConnector::And;
                pending_neg = false;
                expect_operand = false;
            }
            QbToken::InList(in_list) => {
                term_count += in_list.items.len();
                if term_count > MAX_TERMS_PER_RULE {
                    return Err(format!(
                        "Query exceeds maximum of {MAX_TERMS_PER_RULE} terms"
                    ));
                }
                let mut list_cond = parse_qb_in_list(in_list, mode, false, pending_neg, next_id)?;
                pos += 1;
                list_cond.threshold =
                    consume_optional_threshold(&tokens, &mut pos, list_cond.field)?;
                nodes.push(QueryBuilderNode::ListCondition {
                    connector: pending_conn,
                    condition: list_cond,
                });
                pending_conn = QueryConnector::And;
                pending_neg = false;
                expect_operand = false;
            }
        }
    }

    if expect_operand {
        return Err("Incomplete expression — trailing operator without predicate".to_string());
    }

    if mode == QueryBuilderMode::AdvancedSearch
        && nodes.iter().any(QueryBuilderNode::is_vector)
        && nodes.iter().any(|n| n.connector() == QueryConnector::Or)
    {
        return Err(
            "Vector clauses (CLIP / Similar ID / Upload Image) must be combined with AND / NOT, not OR"
                .to_string(),
        );
    }

    Ok(nodes)
}

#[component]
fn ThresholdPillInput(
    field: QueryFieldKind,
    mode: QueryBuilderMode,
    threshold: Signal<Option<f32>>,
    defaults: Signal<QueryThresholdDefaults>,
    on_change: Callback<Option<f32>>,
) -> impl IntoView {
    let label_text = field.threshold_label();
    let aria_label = format!("{label_text} threshold");
    let title_text = match field {
        QueryFieldKind::Tag => "Minimum WD-Tagger confidence score (0.01–1.00)",
        _ => "Minimum similarity score (0.01–1.00)",
    };
    let placeholder_sig = Signal::derive(move || defaults.get().placeholder_for(field, mode));

    view! {
        <label class="le-qb-threshold" title=title_text>
            <span class="le-qb-threshold-label">{label_text}</span>
            <span class="le-qb-threshold-op" aria-hidden="true">">="</span>
            <OptionalScoreInput
                value=threshold
                on_change=on_change
                min=0.01
                max=1.00
                step=0.01
                placeholder=placeholder_sig
                aria_label=aria_label
                class="le-qb-threshold-input"
            />
        </label>
    }
}

/// Compact condition operator selector:
/// - List-capable fields (`Tag`, `PostTag`, `Author`): `<SkySelect>` with `is | is not | in | not in`.
/// - Non-list fields (`TitleAndAuthor`, `Title`, `ClipText`, `SimilarId`, `UploadImage`, `Unclassified`):
///   compact `is | is not` segmented toggle.
#[component]
fn OperatorControl(
    field: Signal<QueryFieldKind>,
    operator: Signal<QueryConditionOp>,
    variant: SelectVariant,
    on_change: Callback<QueryConditionOp>,
) -> impl IntoView {
    let list_op_options = Signal::derive(|| QueryConditionOp::select_options(true));

    view! {
        {move || {
            let f = field.get();
            if f.supports_in() {
                let op_val = Signal::derive(move || operator.get().as_str().to_string());
                view! {
                    <span class=move || if operator.get().is_negated() {
                        "le-qb-op-wrap is-negated"
                    } else {
                        "le-qb-op-wrap"
                    }>
                        <SkySelect
                            aria_label="Condition operator"
                            variant=variant
                            trigger_class="le-qb-op-select"
                            value=op_val
                            options=list_op_options
                            on_change=Callback::new(move |raw: String| {
                                on_change.run(QueryConditionOp::parse(&raw));
                            })
                        />
                    </span>
                }
                .into_any()
            } else {
                view! {
                    <div class="le-qb-op-toggle" role="group" aria-label="Condition operator">
                        <button
                            type="button"
                            class=move || if !operator.get().is_negated() {
                                "le-qb-op-toggle-btn is-active"
                            } else {
                                "le-qb-op-toggle-btn"
                            }
                            aria-pressed=move || (!operator.get().is_negated()).to_string()
                            on:click=move |_| on_change.run(QueryConditionOp::Is)
                        >
                            "is"
                        </button>
                        <button
                            type="button"
                            class=move || if operator.get().is_negated() {
                                "le-qb-op-toggle-btn is-active is-negated"
                            } else {
                                "le-qb-op-toggle-btn"
                            }
                            aria-pressed=move || operator.get().is_negated().to_string()
                            on:click=move |_| on_change.run(QueryConditionOp::IsNot)
                        >
                            "is not"
                        </button>
                    </div>
                }
                .into_any()
            }
        }}
    }
}

const MAX_SUGGEST_LEN: usize = 200;
#[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
const SUGGEST_DEBOUNCE_MS: u64 = 160;
const SUGGEST_VIEWPORT_MARGIN_PX: f64 = 12.0;
const SUGGEST_MENU_GAP_PX: f64 = 6.0;
const SUGGEST_MENU_MAX_HEIGHT_CAP_PX: f64 = 260.0;
#[cfg_attr(
    not(any(test, all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))),
    allow(dead_code)
)]
const SUGGEST_MENU_MIN_HEIGHT_PX: f64 = 84.0;
#[cfg_attr(
    not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))),
    allow(dead_code)
)]
const LOCAL_WD_SUGGEST_LIMIT: usize = 10;

/// Returns `true` when `field` supports candidate autocomplete and `raw` meets the
/// minimum character threshold (`>= 2` ASCII characters, or `>= 1` non-ASCII character).
pub(crate) fn should_suggest_query(field: QueryFieldKind, raw: &str) -> bool {
    if raw.len() > MAX_SUGGEST_LEN {
        return false;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    let meets_len = !trimmed.is_ascii() || trimmed.chars().count() >= 2;
    meets_len
        && matches!(
            field,
            QueryFieldKind::TitleAndAuthor
                | QueryFieldKind::Title
                | QueryFieldKind::Author
                | QueryFieldKind::Tag
                | QueryFieldKind::PostTag
        )
}

/// Pure local candidate search over the bundled 10,861-tag canonical WD-Tagger v3
/// vocabulary (`search_types::wd_vocab_tags`), normalizing spaces to `_` and matching
/// case-insensitively ranked `exact > prefix > substring`.
#[cfg_attr(
    not(any(test, all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))),
    allow(dead_code)
)]
pub(crate) fn suggest_wd_vocab_tags(query: &str, limit: usize) -> Vec<QuerySuggestion> {
    let trimmed = query.trim();
    if trimmed.is_empty() || limit == 0 || !trimmed.is_ascii() {
        return Vec::new();
    }
    let q_raw = trimmed.to_ascii_lowercase();
    let q_under = q_raw.replace(' ', "_");
    let diff_under = q_under != q_raw;

    let mut matches: Vec<(u8, usize, &'static str)> = Vec::new();
    for tag in search_types::wd_vocab_tags() {
        let rank = if tag == q_raw || (diff_under && tag == q_under) {
            0u8
        } else if tag.starts_with(&q_raw) || (diff_under && tag.starts_with(&q_under)) {
            1u8
        } else if tag.contains(&q_raw) || (diff_under && tag.contains(&q_under)) {
            2u8
        } else {
            continue;
        };
        matches.push((rank, tag.len(), tag));
    }

    matches.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)).then_with(|| a.2.cmp(b.2)));
    matches
        .into_iter()
        .take(limit)
        .map(|(_, _, tag)| QuerySuggestion {
            value: tag.to_string(),
            kind: "tag".to_string(),
            aliases: Vec::new(),
        })
        .collect()
}

/// Convert a DOM UTF-16 caret index (from `HtmlInputElement::selection_start`) into a
/// safe UTF-8 byte boundary inside `s`.
pub(crate) fn utf16_offset_to_byte(s: &str, utf16_pos: usize) -> usize {
    let mut u16_acc = 0usize;
    for (byte_idx, ch) in s.char_indices() {
        if u16_acc >= utf16_pos {
            return byte_idx;
        }
        u16_acc += ch.len_utf16();
    }
    s.len()
}

/// Convert a UTF-8 byte boundary inside `s` into a DOM UTF-16 caret index.
pub(crate) fn byte_offset_to_utf16(s: &str, byte_pos: usize) -> usize {
    let clamped = byte_pos.min(s.len());
    let mut boundary = clamped;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    s[..boundary].encode_utf16().count()
}

fn unescape_quoted_raw(raw_inner: &str) -> String {
    let mut out = String::with_capacity(raw_inner.len());
    let mut chars = raw_inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Cursor-aware autocomplete context extracted from the raw query expression editor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawSuggestSpan {
    pub field: QueryFieldKind,
    pub query: String,
    pub replace_range: Range<usize>,
    pub in_list: bool,
    pub inside_quotes: bool,
    pub existing_in_items: Vec<String>,
}

fn skip_ws_bytes(raw: &str, i: &mut usize) {
    while *i < raw.len() {
        let ch = raw[*i..].chars().next().unwrap();
        if !ch.is_whitespace() {
            break;
        }
        *i += ch.len_utf8();
    }
}

fn peek_word_bytes(raw: &str, start: usize) -> Option<(&str, usize)> {
    let mut i = start;
    while i < raw.len() {
        if raw[i..].starts_with(">=") {
            break;
        }
        let ch = raw[i..].chars().next().unwrap();
        if ch.is_whitespace() || matches!(ch, '(' | ')' | ':' | '"' | ',') {
            break;
        }
        i += ch.len_utf8();
    }
    (i > start).then_some((&raw[start..i], i))
}

fn scan_quoted_bytes(raw: &str, open_quote_idx: usize) -> (usize, usize, bool) {
    // `open_quote_idx` points to the opening `"`.
    let mut i = open_quote_idx + 1;
    while i < raw.len() {
        let ch = raw[i..].chars().next().unwrap();
        if ch == '\\' {
            i += 1;
            if i < raw.len() {
                let next = raw[i..].chars().next().unwrap();
                i += next.len_utf8();
            }
            continue;
        }
        if ch == '"' {
            let inner_end = i;
            return (inner_end, i + 1, true);
        }
        i += ch.len_utf8();
    }
    (raw.len(), raw.len(), false)
}

fn try_match_in_paren(raw: &str, start: usize) -> Option<usize> {
    let mut look = start;
    skip_ws_bytes(raw, &mut look);
    let (w1, after1) = peek_word_bytes(raw, look)?;
    let after_in = if w1.eq_ignore_ascii_case("IN") {
        after1
    } else if w1.eq_ignore_ascii_case("NOT") {
        let mut p2 = after1;
        skip_ws_bytes(raw, &mut p2);
        let (w2, after2) = peek_word_bytes(raw, p2)?;
        if !w2.eq_ignore_ascii_case("IN") {
            return None;
        }
        after2
    } else {
        return None;
    };
    let mut paren_idx = after_in;
    skip_ws_bytes(raw, &mut paren_idx);
    raw[paren_idx..].starts_with('(').then_some(paren_idx)
}

fn raw_field_supports_suggest(field: QueryFieldKind) -> bool {
    matches!(
        field,
        QueryFieldKind::TitleAndAuthor
            | QueryFieldKind::Title
            | QueryFieldKind::Author
            | QueryFieldKind::Tag
            | QueryFieldKind::PostTag
    )
}

/// Inspect `raw` around `caret_utf16` and return the active suggestible field value span
/// without clobbering surrounding tokens, parentheses, commas, or `>=threshold` suffixes.
///
/// Supports:
/// - `field:value` / `-field:value` / `field:"quoted value"` (including unclosed quotes
///   and `>=0.45` suffixes)
/// - `field IN (a, b, ...)` / `field NOT IN (a, "b ...")` (replaces only the active list item)
pub(crate) fn extract_raw_suggest_context(
    raw: &str,
    caret_utf16: usize,
    mode: QueryBuilderMode,
) -> Option<RawSuggestSpan> {
    let caret_byte = utf16_offset_to_byte(raw, caret_utf16);
    let mut i = 0usize;

    while i < raw.len() {
        skip_ws_bytes(raw, &mut i);
        if i >= raw.len() {
            break;
        }
        if raw[i..].starts_with(">=") {
            i += 2;
            skip_ws_bytes(raw, &mut i);
            while i < raw.len() {
                let ch = raw[i..].chars().next().unwrap();
                if ch.is_whitespace() || matches!(ch, '(' | ')' | '"') {
                    break;
                }
                i += ch.len_utf8();
            }
            continue;
        }
        let ch = raw[i..].chars().next().unwrap();
        if matches!(ch, '(' | ')' | '-') {
            i += ch.len_utf8();
            continue;
        }
        if ch == '"' {
            let (_, after_quote, closed) = scan_quoted_bytes(raw, i);
            i = after_quote;
            if !closed {
                break;
            }
            continue;
        }

        // Read candidate field prefix or keyword.
        let prefix_start = i;
        while i < raw.len() {
            if raw[i..].starts_with(">=") {
                break;
            }
            let c = raw[i..].chars().next().unwrap();
            if c == ':' || c.is_whitespace() || matches!(c, '(' | ')' | '"' | ',') {
                break;
            }
            i += c.len_utf8();
        }
        let prefix = &raw[prefix_start..i];
        if prefix.is_empty() {
            let c = raw[i..].chars().next().unwrap();
            i += c.len_utf8();
            continue;
        }

        // Case 1: `field:value`
        if i < raw.len() && raw.as_bytes()[i] == b':' {
            i += 1; // consume ':'
            let val_start = i;
            let parsed_field = QueryFieldKind::parse_for_mode(prefix, mode)
                .filter(|&f| raw_field_supports_suggest(f));

            if i < raw.len() && raw.as_bytes()[i] == b'"' {
                let inner_start = i + 1;
                let (inner_end, after_quote, closed) = scan_quoted_bytes(raw, i);
                if closed {
                    let val_end = after_quote;
                    i = val_end;
                    if let Some(field) = parsed_field
                        && caret_byte > val_start
                        && caret_byte <= val_end
                    {
                        let q = unescape_quoted_raw(&raw[inner_start..inner_end]);
                        let trimmed = q.trim().to_string();
                        if !trimmed.is_empty() {
                            return Some(RawSuggestSpan {
                                field,
                                query: trimmed,
                                replace_range: val_start..val_end,
                                in_list: false,
                                inside_quotes: true,
                                existing_in_items: Vec::new(),
                            });
                        }
                    }
                } else {
                    // Unclosed quote: replace strictly up to `caret_byte` so any trailing
                    // tokens after the cursor (e.g. `tag:"blue | AND tag:maid`) stay intact.
                    if let Some(field) = parsed_field
                        && caret_byte >= inner_start
                        && caret_byte <= raw.len()
                    {
                        let q = unescape_quoted_raw(&raw[inner_start..caret_byte]);
                        let trimmed = q.trim().to_string();
                        if !trimmed.is_empty() {
                            return Some(RawSuggestSpan {
                                field,
                                query: trimmed,
                                replace_range: val_start..caret_byte,
                                in_list: false,
                                inside_quotes: true,
                                existing_in_items: Vec::new(),
                            });
                        }
                    }
                    break;
                }
            } else {
                while i < raw.len() {
                    if raw[i..].starts_with(">=") {
                        break;
                    }
                    let c = raw[i..].chars().next().unwrap();
                    if c.is_whitespace() || matches!(c, '(' | ')' | '"') {
                        break;
                    }
                    i += c.len_utf8();
                }
                let val_end = i;
                if let Some(field) = parsed_field
                    && caret_byte >= val_start
                    && caret_byte <= val_end
                {
                    let trimmed = raw[val_start..val_end].trim();
                    if !trimmed.is_empty() {
                        return Some(RawSuggestSpan {
                            field,
                            query: trimmed.to_string(),
                            replace_range: val_start..val_end,
                            in_list: false,
                            inside_quotes: false,
                            existing_in_items: Vec::new(),
                        });
                    }
                }
            }
            continue;
        }

        // Case 2: `field [NOT] IN (a, b, ...)`
        if !prefix.eq_ignore_ascii_case("AND")
            && !prefix.eq_ignore_ascii_case("OR")
            && !prefix.eq_ignore_ascii_case("NOT")
            && let Some(paren_idx) = try_match_in_paren(raw, i)
            && let Some(field) = QueryFieldKind::parse_for_mode(prefix, mode)
            && field.supports_in()
            && raw_field_supports_suggest(field)
        {
            i = paren_idx + 1; // consume '('
            let mut active: Option<(String, Range<usize>, bool)> = None;
            let mut parsed_items: Vec<(String, Range<usize>)> = Vec::new();

            while i < raw.len() {
                skip_ws_bytes(raw, &mut i);
                if i >= raw.len() {
                    break;
                }
                let b = raw.as_bytes()[i];
                if b == b')' {
                    i += 1;
                    break;
                }
                if b == b',' {
                    i += 1;
                    continue;
                }
                let item_start = i;
                if b == b'"' {
                    let inner_start = i + 1;
                    let (inner_end, after_quote, closed) = scan_quoted_bytes(raw, i);
                    if closed {
                        let item_end = after_quote;
                        i = item_end;
                        let q = unescape_quoted_raw(&raw[inner_start..inner_end]);
                        let trimmed = q.trim().to_string();
                        if caret_byte > item_start && caret_byte <= item_end {
                            if !trimmed.is_empty() {
                                active = Some((trimmed.clone(), item_start..item_end, true));
                            }
                        } else if !trimmed.is_empty() {
                            parsed_items.push((trimmed, item_start..item_end));
                        }
                    } else {
                        // Unclosed quoted item inside `IN (...)`: cap replacement at `caret_byte`
                        // so closing `)` and trailing `>= 0.45` are preserved.
                        if caret_byte >= inner_start && caret_byte <= raw.len() {
                            let q = unescape_quoted_raw(&raw[inner_start..caret_byte]);
                            let trimmed = q.trim().to_string();
                            if !trimmed.is_empty() {
                                active = Some((trimmed, item_start..caret_byte, true));
                            }
                        }
                        i = raw.len();
                        break;
                    }
                } else {
                    while i < raw.len() {
                        let c = raw[i..].chars().next().unwrap();
                        if matches!(c, ',' | ')' | '(' | '"') {
                            break;
                        }
                        i += c.len_utf8();
                    }
                    let scan_end = i;
                    let mut item_end = scan_end;
                    while item_end > item_start && item_end > caret_byte {
                        let prev = raw[..item_end].chars().next_back().unwrap();
                        if !prev.is_whitespace() {
                            break;
                        }
                        item_end -= prev.len_utf8();
                    }
                    let trimmed = raw[item_start..item_end].trim().to_string();
                    if caret_byte >= item_start && caret_byte <= scan_end {
                        if !trimmed.is_empty() {
                            active = Some((trimmed, item_start..item_end, false));
                        }
                    } else if !trimmed.is_empty() {
                        parsed_items.push((trimmed, item_start..item_end));
                    }
                }
            }

            if let Some((query, replace_range, inside_quotes)) = active {
                let existing_in_items = parsed_items.into_iter().map(|(v, _)| v).collect();
                return Some(RawSuggestSpan {
                    field,
                    query,
                    replace_range,
                    in_list: true,
                    inside_quotes,
                    existing_in_items,
                });
            }
        }
    }

    None
}

/// Splice `candidate` into `raw` at `span.replace_range` using canonical quoting, returning
/// `(new_raw_query, new_caret_utf16)` positioned immediately after the inserted candidate.
pub(crate) fn splice_raw_suggestion(
    raw: &str,
    span: &RawSuggestSpan,
    candidate: &str,
) -> (String, usize) {
    let formatted = if span.in_list {
        quote_query_list_item_if_needed(candidate)
    } else {
        quote_query_value_if_needed(candidate)
    };
    let start = span.replace_range.start.min(raw.len());
    let end = span.replace_range.end.min(raw.len()).max(start);
    let mut out = String::with_capacity(raw.len() - (end - start) + formatted.len());
    out.push_str(&raw[..start]);
    out.push_str(&formatted);
    let new_caret_byte = out.len();
    out.push_str(&raw[end..]);
    let new_caret_utf16 = byte_offset_to_utf16(&out, new_caret_byte);
    (out, new_caret_utf16)
}

#[derive(Clone, Copy)]
struct SuggestProvider {
    mode: QueryBuilderMode,
    on_suggest: Option<Callback<(QueryFieldKind, String, Callback<Vec<QuerySuggestion>>)>>,
}

impl SuggestProvider {
    fn supports_field(self, field: QueryFieldKind) -> bool {
        if self.on_suggest.is_some() {
            raw_field_supports_suggest(field)
        } else {
            self.mode == QueryBuilderMode::SafetyPolicy && field == QueryFieldKind::Tag
        }
    }

    #[cfg_attr(
        not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))),
        allow(dead_code)
    )]
    fn fetch(self, field: QueryFieldKind, query: String, reply: Callback<Vec<QuerySuggestion>>) {
        if !should_suggest_query(field, &query) {
            reply.run(Vec::new());
            return;
        }
        if let Some(cb) = self.on_suggest {
            cb.run((field, query, reply));
        } else if self.mode == QueryBuilderMode::SafetyPolicy && field == QueryFieldKind::Tag {
            reply.run(suggest_wd_vocab_tags(&query, LOCAL_WD_SUGGEST_LIMIT));
        } else {
            reply.run(Vec::new());
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct SuggestMenuPlacement {
    open_above: bool,
    top_px: Option<f64>,
    bottom_px: Option<f64>,
    left_px: f64,
    width_px: f64,
    max_height_px: u32,
}

impl Default for SuggestMenuPlacement {
    fn default() -> Self {
        Self {
            open_above: false,
            top_px: Some(SUGGEST_VIEWPORT_MARGIN_PX),
            bottom_px: None,
            left_px: SUGGEST_VIEWPORT_MARGIN_PX,
            width_px: 260.0,
            max_height_px: SUGGEST_MENU_MAX_HEIGHT_CAP_PX as u32,
        }
    }
}

impl SuggestMenuPlacement {
    fn inline_style(&self) -> String {
        let mut s = format!(
            "position:fixed;z-index:10050;left:{:.1}px;width:{:.1}px;max-height:{}px;",
            self.left_px, self.width_px, self.max_height_px
        );
        if let Some(bottom) = self.bottom_px {
            s.push_str(&format!("bottom:{bottom:.1}px;top:auto;"));
        } else if let Some(top) = self.top_px {
            s.push_str(&format!("top:{top:.1}px;bottom:auto;"));
        }
        s
    }
}

#[cfg_attr(
    not(any(test, all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))),
    allow(dead_code)
)]
fn compute_suggest_placement_from_metrics(
    rect_top: f64,
    rect_bottom: f64,
    rect_left: f64,
    rect_right: f64,
    vw: f64,
    vh: f64,
    item_count: usize,
) -> SuggestMenuPlacement {
    let est_height = (item_count as f64 * 46.0 + 14.0).min(SUGGEST_MENU_MAX_HEIGHT_CAP_PX);
    let space_below = (vh - rect_bottom - SUGGEST_VIEWPORT_MARGIN_PX - SUGGEST_MENU_GAP_PX).max(0.0);
    let space_above = (rect_top - SUGGEST_VIEWPORT_MARGIN_PX - SUGGEST_MENU_GAP_PX).max(0.0);
    let open_above = space_below < est_height && space_above > space_below;
    let avail_h = if open_above { space_above } else { space_below };
    let max_height_px = avail_h
        .min(SUGGEST_MENU_MAX_HEIGHT_CAP_PX)
        .max(avail_h.min(SUGGEST_MENU_MIN_HEIGHT_PX))
        .max(64.0)
        .round() as u32;

    let (top_px, bottom_px) = if open_above {
        let bottom = (vh - rect_top + SUGGEST_MENU_GAP_PX).max(SUGGEST_VIEWPORT_MARGIN_PX);
        (None, Some(bottom))
    } else {
        let top = (rect_bottom + SUGGEST_MENU_GAP_PX).max(SUGGEST_VIEWPORT_MARGIN_PX);
        (Some(top), None)
    };

    let viewport_cap_w = (vw - 2.0 * SUGGEST_VIEWPORT_MARGIN_PX).max(160.0);
    let anchor_w = (rect_right - rect_left).max(0.0);
    let width_px = anchor_w.max(240.0).min(viewport_cap_w);
    let max_left = (vw - width_px - SUGGEST_VIEWPORT_MARGIN_PX).max(SUGGEST_VIEWPORT_MARGIN_PX);
    let left_px = rect_left.clamp(SUGGEST_VIEWPORT_MARGIN_PX, max_left);

    SuggestMenuPlacement {
        open_above,
        top_px,
        bottom_px,
        left_px,
        width_px,
        max_height_px,
    }
}

#[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
fn compute_suggest_placement(anchor: &web_sys::Element, item_count: usize) -> SuggestMenuPlacement {
    let rect = anchor.get_bounding_client_rect();
    let win = web_sys::window();
    let vw = win
        .as_ref()
        .and_then(|w| w.inner_width().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(1024.0);
    let vh = win
        .as_ref()
        .and_then(|w| w.inner_height().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(768.0);
    compute_suggest_placement_from_metrics(
        rect.top(),
        rect.bottom(),
        rect.left(),
        rect.right(),
        vw,
        vh,
        item_count,
    )
}

fn scroll_suggest_option_into_view(uid: u64, idx: usize) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::{JsCast, JsValue};

        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(&format!("le-qb-suggest-opt-{uid}-{idx}")))
        {
            let _ = js_sys::Reflect::get(&el, &JsValue::from_str("scrollIntoView"))
                .ok()
                .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
                .and_then(|f| {
                    let opts = js_sys::Object::new();
                    let _ = js_sys::Reflect::set(
                        &opts,
                        &JsValue::from_str("block"),
                        &JsValue::from_str("nearest"),
                    );
                    f.call1(&el, &opts).ok()
                });
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = (uid, idx);
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(
    not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))),
    allow(dead_code)
)]
enum SuggestAnchor {
    Input(NodeRef<html::Input>),
    Div(NodeRef<html::Div>),
}

impl SuggestAnchor {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    fn element(&self) -> Option<web_sys::Element> {
        match *self {
            Self::Input(r) => r.get_untracked().map(|el| {
                let e: &web_sys::Element = el.as_ref();
                e.clone()
            }),
            Self::Div(r) => r.get_untracked().map(|el| {
                let e: &web_sys::Element = el.as_ref();
                e.clone()
            }),
        }
    }

    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    fn contains_node(&self, node: &web_sys::Node) -> bool {
        match *self {
            Self::Input(r) => r.get_untracked().is_some_and(|el| el.contains(Some(node))),
            Self::Div(r) => r.get_untracked().is_some_and(|el| el.contains(Some(node))),
        }
    }
}

#[derive(Clone, Copy)]
struct SuggestController {
    uid: u64,
    provider: SuggestProvider,
    #[cfg_attr(
        not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))),
        allow(dead_code)
    )]
    anchor: SuggestAnchor,
    focused: RwSignal<bool>,
    items: RwSignal<Vec<QuerySuggestion>>,
    shown_field: RwSignal<QueryFieldKind>,
    active_idx: RwSignal<Option<usize>>,
    placement: RwSignal<SuggestMenuPlacement>,
    menu_ref: NodeRef<html::Div>,
    req_id: StoredValue<u64>,
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    debounce_handle: StoredValue<Option<TimeoutHandle>, LocalStorage>,
}

impl SuggestController {
    fn new(provider: SuggestProvider, anchor: SuggestAnchor) -> Self {
        let ctrl = Self {
            uid: alloc_qb_id(),
            provider,
            anchor,
            focused: RwSignal::new(false),
            items: RwSignal::new(Vec::new()),
            shown_field: RwSignal::new(QueryFieldKind::Tag),
            active_idx: RwSignal::new(None),
            placement: RwSignal::new(SuggestMenuPlacement::default()),
            menu_ref: NodeRef::new(),
            req_id: StoredValue::new(0),
            #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
            debounce_handle: StoredValue::new_local(None),
        };

        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            let dh = ctrl.debounce_handle;
            on_cleanup(move || {
                if let Some(h) = dh.try_update_value(|slot| slot.take()).flatten() {
                    h.clear();
                }
            });
        }

        // Close popup cleanly on outside pointerdown, window resize, external scroll, or capture-phase Escape.
        use_window_pointerdown(move |e: ev::PointerEvent| {
            if !ctrl.is_open_untracked() {
                return;
            }
            #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
            {
                use wasm_bindgen::JsCast;
                let target_node = e.target().and_then(|t| t.dyn_into::<web_sys::Node>().ok());
                let inside_anchor = target_node
                    .as_ref()
                    .is_some_and(|n| ctrl.anchor.contains_node(n));
                let inside_menu = ctrl
                    .menu_ref
                    .get_untracked()
                    .is_some_and(|el| target_node.as_ref().is_some_and(|n| el.contains(Some(n))));
                if !inside_anchor && !inside_menu {
                    ctrl.cancel();
                }
            }
            #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
            {
                let _ = e;
            }
        });

        use_window_resize(move |_| {
            if ctrl.is_open_untracked() {
                ctrl.cancel();
            }
        });

        use_window_scroll_capture(move |e: ev::Event| {
            if !ctrl.is_open_untracked() {
                return;
            }
            #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
            {
                use wasm_bindgen::JsCast;
                let target_node = e.target().and_then(|t| t.dyn_into::<web_sys::Node>().ok());
                let inside_menu = ctrl
                    .menu_ref
                    .get_untracked()
                    .is_some_and(|el| target_node.as_ref().is_some_and(|n| el.contains(Some(n))));
                if !inside_menu {
                    ctrl.cancel();
                }
            }
            #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
            {
                let _ = e;
            }
        });

        use_window_keydown(true, move |e: ev::KeyboardEvent| {
            if !ctrl.is_open_untracked() {
                return;
            }
            if e.key() == "Escape"
                && !e.is_composing()
                && e.key_code() != 229
                && !e.alt_key()
                && !e.ctrl_key()
                && !e.meta_key()
            {
                e.prevent_default();
                e.stop_propagation();
                ctrl.cancel();
            }
        });

        ctrl
    }

    fn list_id(self) -> String {
        format!("le-qb-suggest-list-{}", self.uid)
    }

    fn active_descendant(self) -> Option<String> {
        self.is_open()
            .then(|| {
                self.active_idx
                    .get()
                    .map(|i| format!("le-qb-suggest-opt-{}-{i}", self.uid))
            })
            .flatten()
    }

    fn is_open(self) -> bool {
        self.focused.get() && !self.items.with(Vec::is_empty)
    }

    fn is_open_untracked(self) -> bool {
        self.focused.get_untracked() && !self.items.with_untracked(Vec::is_empty)
    }

    fn clear_debounce(self) {
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            if let Some(h) = self
                .debounce_handle
                .try_update_value(|slot| slot.take())
                .flatten()
            {
                h.clear();
            }
        }
    }

    fn cancel(self) {
        self.clear_debounce();
        let next = self.req_id.get_value().wrapping_add(1);
        self.req_id.set_value(next);
        let _ = self.items.try_set(Vec::new());
        let _ = self.active_idx.try_set(None);
    }

    fn schedule(self, field: QueryFieldKind, query: String, exclude: Vec<String>) {
        self.clear_debounce();
        let next_id = self.req_id.get_value().wrapping_add(1);
        self.req_id.set_value(next_id);
        let _ = self.active_idx.try_set(None);

        if !self.provider.supports_field(field) || !should_suggest_query(field, &query) {
            let _ = self.items.try_set(Vec::new());
            return;
        }

        // Clear stale candidates immediately while debouncing the new text.
        let _ = self.items.try_set(Vec::new());

        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            use std::time::Duration;

            let req_id_store = self.req_id;
            let focused_sig = self.focused;
            let items_sig = self.items;
            let shown_field_sig = self.shown_field;
            let active_idx_sig = self.active_idx;
            let placement_sig = self.placement;
            let anchor = self.anchor;
            let provider = self.provider;

            if let Ok(handle) = set_timeout_with_handle(
                move || {
                    if req_id_store.try_get_value() != Some(next_id)
                        || focused_sig.try_get_untracked() != Some(true)
                    {
                        return;
                    }
                    let exclude_list = exclude;
                    let reply = Callback::new(move |raw_items: Vec<QuerySuggestion>| {
                        if req_id_store.try_get_value() != Some(next_id)
                            || focused_sig.try_get_untracked() != Some(true)
                        {
                            return;
                        }
                        let filtered: Vec<QuerySuggestion> = if exclude_list.is_empty() {
                            raw_items
                        } else {
                            raw_items
                                .into_iter()
                                .filter(|s| {
                                    !exclude_list
                                        .iter()
                                        .any(|ex| ex.eq_ignore_ascii_case(&s.value))
                                })
                                .collect()
                        };
                        if !filtered.is_empty()
                            && let Some(el) = anchor.element()
                        {
                            let _ = placement_sig
                                .try_set(compute_suggest_placement(&el, filtered.len()));
                        }
                        let _ = shown_field_sig.try_set(field);
                        let _ = items_sig.try_set(filtered);
                        let _ = active_idx_sig.try_set(None);
                    });
                    provider.fetch(field, query, reply);
                },
                Duration::from_millis(SUGGEST_DEBOUNCE_MS),
            ) {
                let _ = self.debounce_handle.try_set_value(Some(handle));
            }
        }
        #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
        {
            let _ = exclude;
        }
    }

    /// Handle `ArrowDown`, `ArrowUp`, `Escape`, and `Enter` when the candidate menu is open.
    /// Returns `Some(picked)` if `Enter` selected an active candidate, or `None` otherwise
    /// (with `ev.default_prevented()` set when the key was consumed by the menu).
    fn handle_keydown(self, ev: &ev::KeyboardEvent) -> Option<QuerySuggestion> {
        if ev.is_composing() || ev.key_code() == 229 {
            return None;
        }
        let len = self.items.with_untracked(Vec::len);
        if len == 0 || !self.focused.get_untracked() {
            return None;
        }
        match ev.key().as_str() {
            "ArrowDown" => {
                ev.prevent_default();
                let next = match self.active_idx.get_untracked() {
                    Some(i) if i + 1 < len => i + 1,
                    _ => 0,
                };
                self.active_idx.set(Some(next));
                scroll_suggest_option_into_view(self.uid, next);
                None
            }
            "ArrowUp" => {
                ev.prevent_default();
                let next = match self.active_idx.get_untracked() {
                    Some(0) | None => len - 1,
                    Some(i) => i - 1,
                };
                self.active_idx.set(Some(next));
                scroll_suggest_option_into_view(self.uid, next);
                None
            }
            "Escape" => {
                ev.prevent_default();
                ev.stop_propagation();
                self.cancel();
                None
            }
            "Enter" => {
                if let Some(i) = self.active_idx.get_untracked()
                    && let Some(picked) = self.items.with_untracked(|list| list.get(i).cloned())
                {
                    ev.prevent_default();
                    ev.stop_propagation();
                    return Some(picked);
                }
                None
            }
            "Tab" => {
                self.cancel();
                None
            }
            _ => None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_suggest_menu_view(
    menu_ref: NodeRef<html::Div>,
    uid: u64,
    list_id: String,
    indigo: bool,
    show_kind_badge: bool,
    items: Vec<QuerySuggestion>,
    pl: SuggestMenuPlacement,
    active_idx: RwSignal<Option<usize>>,
    on_pick: Callback<QuerySuggestion>,
) -> impl IntoView {
    let menu_cls = if indigo {
        "le-qb-suggest-menu le-qb-suggest-menu--indigo"
    } else {
        "le-qb-suggest-menu"
    };
    let menu_style = pl.inline_style();

    view! {
        <div
            node_ref=menu_ref
            id=list_id
            role="listbox"
            aria-label="Tag and query suggestions"
            style=menu_style
            class=menu_cls
            on:mousedown=|ev| ev.prevent_default()
            on:click=|ev: ev::MouseEvent| ev.stop_propagation()
        >
            {items.into_iter().enumerate().map(|(i, s)| {
                let picked = s.clone();
                let opt_id = format!("le-qb-suggest-opt-{uid}-{i}");
                let alias_line = (!s.aliases.is_empty()).then(|| s.aliases.join(" \u{00B7} "));
                let badge = if show_kind_badge {
                    match s.kind.as_str() {
                        "author" => Some(("@ Author", "le-qb-suggest-badge le-qb-suggest-badge--author")),
                        "title" => Some(("Title", "le-qb-suggest-badge le-qb-suggest-badge--title")),
                        _ => None,
                    }
                } else {
                    None
                };
                view! {
                    <button
                        id=opt_id
                        type="button"
                        role="option"
                        tabindex="-1"
                        aria-selected=move || (active_idx.get() == Some(i)).to_string()
                        class=move || if active_idx.get() == Some(i) {
                            "le-qb-suggest-item is-active"
                        } else {
                            "le-qb-suggest-item"
                        }
                        on:mousedown=|ev| ev.prevent_default()
                        on:mouseenter=move |_| active_idx.set(Some(i))
                        on:click=move |ev: ev::MouseEvent| {
                            ev.stop_propagation();
                            on_pick.run(picked.clone());
                        }
                    >
                        <div class="le-qb-suggest-item-row">
                            <span class="le-qb-suggest-value">{s.value}</span>
                            {badge.map(|(lbl, cls)| view! {
                                <span class=cls>{lbl}</span>
                            })}
                        </div>
                        {alias_line.map(|line| view! {
                            <span class="le-qb-suggest-aliases">{line}</span>
                        })}
                    </button>
                }
            }).collect_view()}
        </div>
    }
}

#[component]
fn SuggestPortalMenu(
    ctrl: SuggestController,
    indigo: bool,
    on_pick: Callback<QuerySuggestion>,
) -> impl IntoView {
    let list_id_sv = StoredValue::new(ctrl.list_id());
    view! {
        {move || {
            ctrl.is_open().then(move || {
                #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
                {
                    view! {
                        <leptos::portal::Portal>
                            {move || {
                                let list = ctrl.items.get();
                                let pl = ctrl.placement.get();
                                let show_badge =
                                    ctrl.shown_field.get() == QueryFieldKind::TitleAndAuthor;
                                render_suggest_menu_view(
                                    ctrl.menu_ref,
                                    ctrl.uid,
                                    list_id_sv.get_value(),
                                    indigo,
                                    show_badge,
                                    list,
                                    pl,
                                    ctrl.active_idx,
                                    on_pick,
                                )
                            }}
                        </leptos::portal::Portal>
                    }
                    .into_any()
                }
                #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
                {
                    let list = ctrl.items.get();
                    let pl = ctrl.placement.get();
                    let show_badge = ctrl.shown_field.get() == QueryFieldKind::TitleAndAuthor;
                    render_suggest_menu_view(
                        ctrl.menu_ref,
                        ctrl.uid,
                        list_id_sv.get_value(),
                        indigo,
                        show_badge,
                        list,
                        pl,
                        ctrl.active_idx,
                        on_pick,
                    )
                    .into_any()
                }
            })
        }}
    }
}

/// Single-value condition text input with fixed-portal autocomplete candidates.
#[component]
fn SuggestTextInput(
    field: Signal<QueryFieldKind>,
    mode: QueryBuilderMode,
    aria_label: &'static str,
    value: Signal<String>,
    provider: SuggestProvider,
    indigo: bool,
    on_value_change: Callback<String>,
) -> impl IntoView {
    let input_ref = NodeRef::<html::Input>::new();
    let ctrl = SuggestController::new(provider, SuggestAnchor::Input(input_ref));
    let list_id_aria = ctrl.list_id();

    Effect::new(move |_| {
        let _ = field.get();
        ctrl.cancel();
    });

    let on_pick = Callback::new(move |picked: QuerySuggestion| {
        ctrl.cancel();
        on_value_change.run(picked.value);
    });

    view! {
        <input
            node_ref=input_ref
            type="text"
            role="combobox"
            autocomplete="off"
            aria-label=aria_label
            aria-autocomplete="list"
            aria-expanded=move || ctrl.is_open().to_string()
            aria-controls=move || ctrl.is_open().then(|| list_id_aria.clone())
            aria-activedescendant=move || ctrl.active_descendant()
            class="le-qb-value-input"
            placeholder=move || field.get().placeholder(mode)
            value=move || value.get()
            prop:value=move || value.get()
            on:focus=move |_| {
                ctrl.focused.set(true);
                let cur = value.get_untracked();
                let f = field.get_untracked();
                if should_suggest_query(f, &cur) {
                    ctrl.schedule(f, cur, Vec::new());
                }
            }
            on:input=move |ev| {
                let next = event_target_value(&ev);
                on_value_change.run(next.clone());
                ctrl.focused.set(true);
                ctrl.schedule(field.get_untracked(), next, Vec::new());
            }
            on:keydown=move |ev: ev::KeyboardEvent| {
                if let Some(picked) = ctrl.handle_keydown(&ev) {
                    on_pick.run(picked);
                }
            }
            on:blur=move |_| {
                ctrl.focused.set(false);
                ctrl.cancel();
            }
        />
        <SuggestPortalMenu ctrl=ctrl indigo=indigo on_pick=on_pick />
    }
}

/// Raw query expression editor with cursor-aware token candidate autocomplete.
#[component]
fn RawQueryInput(
    input_id: String,
    placeholder: &'static str,
    mode: QueryBuilderMode,
    draft: RwSignal<QueryBuilderDraft>,
    provider: SuggestProvider,
    on_apply_raw: Callback<String>,
) -> impl IntoView {
    let input_ref = NodeRef::<html::Input>::new();
    let ctrl = SuggestController::new(provider, SuggestAnchor::Input(input_ref));
    let active_span: StoredValue<Option<RawSuggestSpan>> = StoredValue::new(None);
    let list_id_aria = ctrl.list_id();

    let read_caret_utf16 = move |fallback_raw: &str| -> usize {
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            if let Some(el) = input_ref.get_untracked()
                && let Ok(Some(pos)) = el.selection_start()
            {
                return pos as usize;
            }
        }
        fallback_raw.encode_utf16().count()
    };

    let refresh_from_cursor = move |raw_val: String| {
        let caret = read_caret_utf16(&raw_val);
        if let Some(span) = extract_raw_suggest_context(&raw_val, caret, mode)
            && provider.supports_field(span.field)
            && should_suggest_query(span.field, &span.query)
        {
            let field = span.field;
            let query = span.query.clone();
            let exclude = span.existing_in_items.clone();
            active_span.set_value(Some(span));
            ctrl.schedule(field, query, exclude);
        } else {
            active_span.set_value(None);
            ctrl.cancel();
        }
    };

    let on_pick = Callback::new(move |picked: QuerySuggestion| {
        let cur_raw = draft.with_untracked(|d| d.query.clone());
        let caret = read_caret_utf16(&cur_raw);
        let span_opt = extract_raw_suggest_context(&cur_raw, caret, mode)
            .or_else(|| active_span.get_value());
        let Some(span) = span_opt else {
            ctrl.cancel();
            return;
        };
        let (next_raw, next_caret_utf16) = splice_raw_suggestion(&cur_raw, &span, &picked.value);
        ctrl.cancel();
        active_span.set_value(None);

        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        if let Some(el) = input_ref.get_untracked() {
            el.set_value(&next_raw);
            let pos = next_caret_utf16 as u32;
            let _ = el.set_selection_range(pos, pos);
            let _ = el.focus();
        }

        on_apply_raw.run(next_raw.clone());

        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            use std::time::Duration;
            let expected = next_raw;
            let pos = next_caret_utf16 as u32;
            set_timeout(
                move || {
                    if let Some(el) = input_ref.try_get_untracked().flatten()
                        && el.value() == expected
                    {
                        let _ = el.set_selection_range(pos, pos);
                    }
                },
                Duration::ZERO,
            );
        }
        #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
        {
            let _ = next_caret_utf16;
        }
    });

    view! {
        <input
            node_ref=input_ref
            id=input_id
            type="text"
            role="combobox"
            autocomplete="off"
            aria-autocomplete="list"
            aria-expanded=move || ctrl.is_open().to_string()
            aria-controls=move || ctrl.is_open().then(|| list_id_aria.clone())
            aria-activedescendant=move || ctrl.active_descendant()
            class="le-qb-raw-input"
            placeholder=placeholder
            value=move || draft.with(|d| d.query.clone())
            prop:value=move || draft.with(|d| d.query.clone())
            on:focus=move |_| {
                ctrl.focused.set(true);
            }
            on:click=move |_| {
                ctrl.focused.set(true);
                refresh_from_cursor(draft.with_untracked(|d| d.query.clone()));
            }
            on:input=move |ev| {
                let next_raw = event_target_value(&ev);
                on_apply_raw.run(next_raw.clone());
                ctrl.focused.set(true);
                refresh_from_cursor(next_raw);
            }
            on:keydown=move |ev: ev::KeyboardEvent| {
                if let Some(picked) = ctrl.handle_keydown(&ev) {
                    on_pick.run(picked);
                }
            }
            on:keyup=move |ev: ev::KeyboardEvent| {
                if ev.is_composing() || ev.key_code() == 229 {
                    return;
                }
                if matches!(ev.key().as_str(), "ArrowLeft" | "ArrowRight" | "Home" | "End")
                    && ctrl.focused.get_untracked()
                {
                    refresh_from_cursor(draft.with_untracked(|d| d.query.clone()));
                }
            }
            on:blur=move |_| {
                ctrl.focused.set(false);
                active_span.set_value(None);
                ctrl.cancel();
            }
        />
        <SuggestPortalMenu ctrl=ctrl indigo=false on_pick=on_pick />
    }
}

/// Multi-chip pill editor rendered when a condition uses `in` or `not in`.
///
/// Supports:
/// - `Enter` or `,` to commit trimmed deduplicated chip(s) (preventing form submission)
/// - Live candidate autocomplete filtering out already-selected chips
/// - Pasting comma/newline-separated tags splits and adds all items immediately
/// - `Backspace` on an empty input removes the last chip
/// - Clicking `×` removes a specific chip
/// - Commits any pending text on `blur` so users never lose the last typed tag
#[component]
fn ChipListInput(
    field: QueryFieldKind,
    negated: Signal<bool>,
    values: Signal<Vec<String>>,
    provider: SuggestProvider,
    indigo: bool,
    on_commit_raw: Callback<String>,
    on_remove_chip: Callback<String>,
    on_remove_last: Callback<()>,
) -> impl IntoView {
    let pending = RwSignal::new(String::new());
    let box_ref = NodeRef::<html::Div>::new();
    let input_ref = NodeRef::<html::Input>::new();
    let ctrl = SuggestController::new(provider, SuggestAnchor::Div(box_ref));
    let list_id_aria = ctrl.list_id();

    let focus_input = move |_| {
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        if let Some(el) = input_ref.get_untracked() {
            let _ = el.focus();
        }
    };

    let commit_pending = move || {
        let cur = pending.get_untracked();
        if !cur.trim().is_empty() {
            on_commit_raw.run(cur);
        }
        pending.set(String::new());
        ctrl.cancel();
    };

    let on_pick = Callback::new(move |picked: QuerySuggestion| {
        on_commit_raw.run(picked.value);
        pending.set(String::new());
        ctrl.cancel();
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        if let Some(el) = input_ref.get_untracked() {
            let _ = el.focus();
        }
    });

    let placeholder_text = field.chip_placeholder();

    view! {
        <div
            node_ref=box_ref
            class=move || if negated.get() {
                "le-qb-chips-box is-negated"
            } else {
                "le-qb-chips-box"
            }
            on:click=focus_input
        >
            <For
                each=move || values.get()
                key=|chip| chip.clone()
                let(chip)
            >
                {
                    let chip_for_remove = chip.clone();
                    let remove_aria = format!("Remove {chip}");
                    view! {
                        <span class="le-qb-chip">
                            <span class="le-qb-chip-text">{chip}</span>
                            <button
                                type="button"
                                class="le-qb-chip-remove"
                                aria-label=remove_aria
                                on:click=move |ev: ev::MouseEvent| {
                                    ev.stop_propagation();
                                    on_remove_chip.run(chip_for_remove.clone());
                                }
                            >
                                "\u{00D7}"
                            </button>
                        </span>
                    }
                }
            </For>

            <input
                node_ref=input_ref
                type="text"
                role="combobox"
                autocomplete="off"
                aria-label="Add list value"
                aria-autocomplete="list"
                aria-expanded=move || ctrl.is_open().to_string()
                aria-controls=move || ctrl.is_open().then(|| list_id_aria.clone())
                aria-activedescendant=move || ctrl.active_descendant()
                class="le-qb-chips-input"
                placeholder=move || if values.with(Vec::is_empty) {
                    placeholder_text
                } else {
                    "Add more\u{2026}"
                }
                value=move || pending.get()
                prop:value=move || pending.get()
                on:focus=move |_| {
                    ctrl.focused.set(true);
                    let cur = pending.get_untracked();
                    if should_suggest_query(field, &cur) {
                        ctrl.schedule(field, cur, values.get_untracked());
                    }
                }
                on:input=move |ev| {
                    let next = event_target_value(&ev);
                    if next.contains(',') || next.contains('\n') || next.contains('\r') {
                        on_commit_raw.run(next);
                        pending.set(String::new());
                        ctrl.cancel();
                    } else {
                        pending.set(next.clone());
                        ctrl.focused.set(true);
                        ctrl.schedule(field, next, values.get_untracked());
                    }
                }
                on:keydown=move |ev: ev::KeyboardEvent| {
                    if ev.is_composing() || ev.key_code() == 229 {
                        return;
                    }
                    if let Some(picked) = ctrl.handle_keydown(&ev) {
                        on_pick.run(picked);
                        return;
                    }
                    if ev.default_prevented() {
                        return;
                    }
                    match ev.key().as_str() {
                        "Enter" | "," => {
                            ev.prevent_default();
                            commit_pending();
                        }
                        "Backspace" if pending.get_untracked().is_empty() => {
                            ctrl.cancel();
                            on_remove_last.run(());
                        }
                        _ => {}
                    }
                }
                on:blur=move |_| {
                    ctrl.focused.set(false);
                    ctrl.cancel();
                    commit_pending();
                }
            />
        </div>
        <SuggestPortalMenu ctrl=ctrl indigo=indigo on_pick=on_pick />
    }
}

/// Apply an operator change (`Is` / `IsNot` / `In` / `NotIn`) to a top-level condition
/// node (converting seamlessly between `Condition` and `ListCondition` while preserving
/// `id`, `connector`, `field`, `threshold`, and migrating values).
fn apply_top_operator_change(node: &mut QueryBuilderNode, next_op: QueryConditionOp) {
    let target_is_list = next_op.is_list();
    let target_neg = next_op.is_negated();
    match node {
        QueryBuilderNode::Condition {
            connector,
            condition,
        } => {
            if target_is_list && condition.field.supports_in() {
                let mut vals = Vec::new();
                merge_chip_values(&mut vals, &condition.value);
                let list_cond = QueryListCondition {
                    id: condition.id,
                    field: condition.field,
                    values: vals,
                    negated: target_neg,
                    threshold: condition.threshold,
                };
                *node = QueryBuilderNode::ListCondition {
                    connector: *connector,
                    condition: list_cond,
                };
            } else {
                condition.negated = target_neg;
            }
        }
        QueryBuilderNode::ListCondition {
            connector,
            condition,
        } => {
            if target_is_list && condition.field.supports_in() {
                condition.negated = target_neg;
            } else {
                let single = QueryCondition {
                    id: condition.id,
                    field: condition.field,
                    value: condition.values.first().cloned().unwrap_or_default(),
                    negated: target_neg,
                    threshold: condition.threshold,
                };
                *node = QueryBuilderNode::Condition {
                    connector: *connector,
                    condition: single,
                };
            }
        }
        QueryBuilderNode::Group(_) => {}
    }
}

/// Apply a field change to a top-level condition node, automatically collapsing `ListCondition`
/// to `Condition` if the new field does not support `IN` / `NOT IN`.
fn apply_top_field_change(node: &mut QueryBuilderNode, next_field: QueryFieldKind) {
    match node {
        QueryBuilderNode::Condition { condition, .. } => {
            condition.field = next_field;
            if !next_field.supports_threshold() {
                condition.threshold = None;
            }
            if next_field == QueryFieldKind::Unclassified {
                condition.value.clear();
            }
        }
        QueryBuilderNode::ListCondition {
            connector,
            condition,
        } => {
            if next_field.supports_in() {
                condition.field = next_field;
                if !next_field.supports_threshold() {
                    condition.threshold = None;
                }
            } else {
                let value = if next_field == QueryFieldKind::Unclassified {
                    String::new()
                } else {
                    condition.values.first().cloned().unwrap_or_default()
                };
                let threshold = if next_field.supports_threshold() {
                    condition.threshold
                } else {
                    None
                };
                *node = QueryBuilderNode::Condition {
                    connector: *connector,
                    condition: QueryCondition {
                        id: condition.id,
                        field: next_field,
                        value,
                        negated: condition.negated,
                        threshold,
                    },
                };
            }
        }
        QueryBuilderNode::Group(_) => {}
    }
}

/// Unified visual boolean query builder shared by BOTH Gallery Advanced Search
/// (`QueryBuilderMode::AdvancedSearch`) and Admin Content Policy Selector
/// (`QueryBuilderMode::SafetyPolicy`).
///
/// Key guarantees:
/// - Self-contained bordered condition cards (`le-qb-card`) with top-right `×` close
///   buttons unambiguously bound to each card.
/// - Compact `is | is not | in | not in` operator selector for discrete list-capable
///   fields (`Tag`, `PostTag`, `Author`) with an inline multi-chip pill editor, and
///   `is | is not` segmented toggle for single-value/vector fields.
/// - Distinct nested group cards (`le-qb-group`) with a crisp single-row header
///   (`[AND/OR] [NOT] ( ... ) [ANY | ALL]` + `[+ Row]` + `[×]`) and distinct
///   inner mini-cards (`le-qb-subcard`) with their own top-right `×` buttons.
/// - Keyboard-friendly per-condition score/similarity thresholds (`0.01..=1.00`,
///   hundredths precision via [`OptionalScoreInput`]) on every `Tag`, `CLIP Text`,
///   `Similar ID`, and `Upload Image` condition.
/// - Zero vector fields in `SafetyPolicy` mode; zero CLIP/DINO weight sliders in `AdvancedSearch` mode.
#[component]
pub fn QueryBuilder(
    draft: RwSignal<QueryBuilderDraft>,
    #[prop(optional)] mode: Option<QueryBuilderMode>,
    #[prop(optional)] presets: Option<Vec<PresetTemplate>>,
    #[prop(optional)] show_presets: Option<bool>,
    #[prop(optional)] threshold_defaults: Option<Signal<QueryThresholdDefaults>>,
    #[prop(optional)] validation_error: Option<Signal<Option<String>>>,
    #[prop(optional)] on_change: Option<Callback<QueryBuilderDraft>>,
    #[prop(optional)] on_preset_select: Option<Callback<PresetTemplate>>,
    #[prop(optional)] render_upload_slot: Option<Callback<u64, AnyView>>,
    #[prop(optional)] on_suggest: Option<
        Callback<(QueryFieldKind, String, Callback<Vec<QuerySuggestion>>)>,
    >,
    #[prop(default = true)] show_raw_editor: bool,
) -> impl IntoView {
    let effective_mode = mode.unwrap_or_else(|| draft.with_untracked(|d| d.mode));
    let suggest_provider = SuggestProvider {
        mode: effective_mode,
        on_suggest,
    };
    let show_preset_bar = show_presets.unwrap_or(effective_mode == QueryBuilderMode::SafetyPolicy);
    let preset_list = if show_preset_bar {
        presets.unwrap_or_else(PresetTemplate::builtins)
    } else {
        Vec::new()
    };
    let defaults_sig =
        threshold_defaults.unwrap_or_else(|| Signal::derive(QueryThresholdDefaults::default));

    let raw_parse_error: RwSignal<Option<String>> = RwSignal::new(None);
    let raw_input_id = format!("le-qb-raw-input-{}", alloc_qb_id());

    let top_field_options =
        Signal::derive(move || QueryFieldKind::select_options(effective_mode, false));
    let group_field_options =
        Signal::derive(move || QueryFieldKind::select_options(effective_mode, true));

    let emit_change = move || {
        if let Some(cb) = on_change {
            cb.run(draft.get_untracked());
        }
    };

    let sync_from_nodes = move || {
        raw_parse_error.set(None);
        draft.update(|d| {
            d.mode = effective_mode;
            d.active_preset = None;
            d.sync_query();
        });
        emit_change();
    };

    let apply_preset = move |tpl: PresetTemplate| {
        let mut alloc = alloc_qb_id;
        let nodes = if tpl.query.trim().is_empty() {
            vec![QueryBuilderNode::Condition {
                connector: QueryConnector::And,
                condition: QueryCondition {
                    id: alloc(),
                    field: QueryFieldKind::Tag,
                    value: String::new(),
                    negated: false,
                    threshold: None,
                },
            }]
        } else {
            parse_query_to_nodes(effective_mode, &tpl.query, &mut alloc).unwrap_or_default()
        };
        raw_parse_error.set(None);
        draft.update(|d| {
            d.mode = effective_mode;
            d.nodes = nodes;
            d.active_preset = Some(tpl.id.clone());
            d.sync_query();
        });
        if let Some(cb) = on_preset_select {
            cb.run(tpl);
        }
        emit_change();
    };

    let add_condition = move |_| {
        let cond_id = alloc_qb_id();
        draft.update(|d| {
            d.nodes.push(QueryBuilderNode::Condition {
                connector: QueryConnector::And,
                condition: QueryCondition {
                    id: cond_id,
                    field: QueryFieldKind::Tag,
                    value: String::new(),
                    negated: false,
                    threshold: None,
                },
            });
        });
        sync_from_nodes();
    };

    let add_group = move |_| {
        let gid = alloc_qb_id();
        let c1 = alloc_qb_id();
        let c2 = alloc_qb_id();
        draft.update(|d| {
            d.nodes.push(QueryBuilderNode::Group(QueryGroup {
                id: gid,
                combinator: QueryCombinator::Or,
                connector: QueryConnector::And,
                negated: false,
                conditions: vec![
                    QueryCondition {
                        id: c1,
                        field: QueryFieldKind::Tag,
                        value: String::new(),
                        negated: false,
                        threshold: None,
                    },
                    QueryCondition {
                        id: c2,
                        field: QueryFieldKind::Tag,
                        value: String::new(),
                        negated: false,
                        threshold: None,
                    },
                ],
                list_values: BTreeMap::new(),
            }));
        });
        sync_from_nodes();
    };

    let node_ids = Memo::new(move |_| {
        draft.with(|d| d.nodes.iter().map(QueryBuilderNode::id).collect::<Vec<_>>())
    });

    let has_vectors = Memo::new(move |_| draft.with(QueryBuilderDraft::has_vector_node));

    let combined_error = move || {
        raw_parse_error
            .get()
            .or_else(|| validation_error.and_then(|e| e.get()))
    };

    let mode_slug = match effective_mode {
        QueryBuilderMode::AdvancedSearch => "advanced",
        QueryBuilderMode::SafetyPolicy => "safety",
    };

    let raw_label = match effective_mode {
        QueryBuilderMode::SafetyPolicy => {
            "Policy Selector Expression (metadata-only: tag:, post_tag:, author:, IN (...), unclassified)"
        }
        QueryBuilderMode::AdvancedSearch => {
            "Query Expression (tag:, title:, author:, IN (...), clip:, dino:, upload:, with optional >=threshold)"
        }
    };

    let raw_placeholder = match effective_mode {
        QueryBuilderMode::SafetyPolicy => {
            "e.g. tag IN (explicit, nude, nipples) >= 0.45 AND NOT post_tag:safe"
        }
        QueryBuilderMode::AdvancedSearch => {
            "e.g. tag IN (maid, apron) >= 0.45 AND clip:\"sunlit garden\">=0.25"
        }
    };

    view! {
        <div class=format!("le-qb le-qb--{mode_slug}") data-mode=mode_slug>
            // Optional 1-click WD-Tagger preset bar (shown by default in SafetyPolicy mode)
            {(!preset_list.is_empty()).then(|| view! {
                <div class="le-qb-presets" role="group" aria-label="WD-Tagger presets">
                    <span class="le-qb-presets-label">"Presets:"</span>
                    <div class="le-qb-presets-list">
                        {preset_list.into_iter().map(|tpl| {
                            let tpl_click = tpl.clone();
                            let pid = tpl.id.clone();
                            let pid_cmp = tpl.id.clone();
                            let desc = tpl.description.clone();
                            view! {
                                <button
                                    type="button"
                                    class=move || {
                                        let active = if draft.with(|d| d.active_preset.as_deref() == Some(pid_cmp.as_str())) {
                                            " is-active"
                                        } else {
                                            ""
                                        };
                                        format!("le-preset-btn le-preset-btn--{pid}{active}")
                                    }
                                    title=desc
                                    on:click=move |_| apply_preset(tpl_click.clone())
                                >
                                    {tpl.label}
                                </button>
                            }
                        }).collect_view()}
                    </div>
                </div>
            })}

            // Visual condition cards & parenthesized group cards
            <div class="le-qb-nodes">
                <For
                    each=move || node_ids.get()
                    key=|id| *id
                    let(node_id)
                >
                    {
                        let idx_sig = Memo::new(move |_| {
                            node_ids
                                .with(|ids| ids.iter().position(|x| *x == node_id))
                                .unwrap_or(0)
                        });
                        let conn_sig = Memo::new(move |_| {
                            draft.with(|d| {
                                d.nodes
                                    .iter()
                                    .find(|n| n.id() == node_id)
                                    .map(QueryBuilderNode::connector)
                                    .unwrap_or(QueryConnector::And)
                            })
                        });
                        let is_group = draft.with_untracked(|d| {
                            d.nodes
                                .iter()
                                .find(|n| n.id() == node_id)
                                .is_some_and(|n| matches!(n, QueryBuilderNode::Group(_)))
                        });

                        let remove_node = move |_| {
                            draft.update(|d| {
                                d.nodes.retain(|n| n.id() != node_id);
                                if let Some(first) = d.nodes.first_mut()
                                    && first.connector() == QueryConnector::Or
                                {
                                    first.set_connector(QueryConnector::And);
                                }
                            });
                            sync_from_nodes();
                        };

                        let connector_options = Signal::derive(move || {
                            let or_disabled =
                                effective_mode == QueryBuilderMode::AdvancedSearch && has_vectors.get();
                            vec![
                                SelectOption::new("and", "AND"),
                                SelectOption::new("or", "OR").disabled(or_disabled),
                            ]
                        });

                        let on_connector_change = Callback::new(move |val: String| {
                            let mut next = QueryConnector::parse(&val);
                            if idx_sig.get_untracked() == 0 {
                                next = QueryConnector::And;
                            }
                            if effective_mode == QueryBuilderMode::AdvancedSearch
                                && has_vectors.get_untracked()
                            {
                                next = QueryConnector::And;
                            }
                            draft.update(|d| {
                                if let Some(n) = d.nodes.iter_mut().find(|n| n.id() == node_id) {
                                    n.set_connector(next);
                                }
                            });
                            sync_from_nodes();
                        });

                        if !is_group {
                            let field_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::Condition { condition, .. } => {
                                                Some(condition.field)
                                            }
                                            QueryBuilderNode::ListCondition { condition, .. } => {
                                                Some(condition.field)
                                            }
                                            QueryBuilderNode::Group(_) => None,
                                        })
                                        .unwrap_or(QueryFieldKind::Tag)
                                })
                            });
                            let op_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::Condition { condition, .. } => {
                                                Some(condition.operator())
                                            }
                                            QueryBuilderNode::ListCondition { condition, .. } => {
                                                Some(condition.operator())
                                            }
                                            QueryBuilderNode::Group(_) => None,
                                        })
                                        .unwrap_or(QueryConditionOp::Is)
                                })
                            });
                            let val_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::Condition { condition, .. } => {
                                                Some(condition.value.clone())
                                            }
                                            _ => None,
                                        })
                                        .unwrap_or_default()
                                })
                            });
                            let values_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::ListCondition { condition, .. } => {
                                                Some(condition.values.clone())
                                            }
                                            _ => None,
                                        })
                                        .unwrap_or_default()
                                })
                            });
                            let threshold_sig = Signal::derive(move || {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::Condition { condition, .. } => {
                                                condition.threshold
                                            }
                                            QueryBuilderNode::ListCondition { condition, .. } => {
                                                condition.threshold
                                            }
                                            QueryBuilderNode::Group(_) => None,
                                        })
                                })
                            });

                            let on_threshold_change = Callback::new(move |next: Option<f32>| {
                                draft.update(|d| {
                                    match d.nodes.iter_mut().find(|n| n.id() == node_id) {
                                        Some(QueryBuilderNode::Condition { condition, .. }) => {
                                            condition.threshold = next.and_then(quantize_threshold);
                                        }
                                        Some(QueryBuilderNode::ListCondition { condition, .. }) => {
                                            condition.threshold = next.and_then(quantize_threshold);
                                        }
                                        _ => {}
                                    }
                                });
                                sync_from_nodes();
                            });

                            let on_op_change = Callback::new(move |next_op: QueryConditionOp| {
                                draft.update(|d| {
                                    if let Some(node) = d.nodes.iter_mut().find(|n| n.id() == node_id) {
                                        apply_top_operator_change(node, next_op);
                                    }
                                });
                                sync_from_nodes();
                            });

                            let on_commit_raw = Callback::new(move |raw: String| {
                                let mut changed = false;
                                draft.update(|d| {
                                    if let Some(QueryBuilderNode::ListCondition { condition, .. }) =
                                        d.nodes.iter_mut().find(|n| n.id() == node_id)
                                    {
                                        changed = merge_chip_values(&mut condition.values, &raw);
                                    }
                                });
                                if changed {
                                    sync_from_nodes();
                                }
                            });

                            let on_remove_chip = Callback::new(move |chip: String| {
                                draft.update(|d| {
                                    if let Some(QueryBuilderNode::ListCondition { condition, .. }) =
                                        d.nodes.iter_mut().find(|n| n.id() == node_id)
                                    {
                                        condition.values.retain(|v| v != &chip);
                                    }
                                });
                                sync_from_nodes();
                            });

                            let on_remove_last = Callback::new(move |()| {
                                let mut removed = false;
                                draft.update(|d| {
                                    if let Some(QueryBuilderNode::ListCondition { condition, .. }) =
                                        d.nodes.iter_mut().find(|n| n.id() == node_id)
                                    {
                                        removed = condition.values.pop().is_some();
                                    }
                                });
                                if removed {
                                    sync_from_nodes();
                                }
                            });

                            view! {
                                <div class="le-qb-card">
                                    <div class="le-qb-card-header">
                                        <div class="le-qb-card-controls">
                                            {move || {
                                                if idx_sig.get() == 0 {
                                                    view! {
                                                        <span class="le-qb-match-pill">"Match"</span>
                                                    }
                                                    .into_any()
                                                } else {
                                                    view! {
                                                        <SkySelect
                                                            aria_label="Boolean connector"
                                                            variant=SelectVariant::SkyBox
                                                            trigger_class="le-qb-conn-select"
                                                            value=Signal::derive(move || conn_sig.get().as_str().to_string())
                                                            options=connector_options
                                                            on_change=on_connector_change
                                                        />
                                                    }
                                                    .into_any()
                                                }
                                            }}

                                            <SkySelect
                                                aria_label="Condition field"
                                                variant=SelectVariant::SkyBox
                                                trigger_class="le-qb-field-select"
                                                value=Signal::derive(move || field_sig.get().as_prefix().to_string())
                                                options=top_field_options
                                                on_change=Callback::new(move |val: String| {
                                                    if let Some(next_field) =
                                                        QueryFieldKind::parse_for_mode(&val, effective_mode)
                                                    {
                                                        draft.update(|d| {
                                                            if let Some(node) =
                                                                d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                            {
                                                                apply_top_field_change(node, next_field);
                                                            }
                                                            // Vector clauses cannot be combined with OR (Cycle 4 I9).
                                                            if effective_mode == QueryBuilderMode::AdvancedSearch
                                                                && next_field.is_vector()
                                                            {
                                                                for n in &mut d.nodes {
                                                                    if n.connector() == QueryConnector::Or {
                                                                        n.set_connector(QueryConnector::And);
                                                                    }
                                                                }
                                                            }
                                                        });
                                                        sync_from_nodes();
                                                    }
                                                })
                                            />

                                            <OperatorControl
                                                field=Signal::derive(move || field_sig.get())
                                                operator=Signal::derive(move || op_sig.get())
                                                variant=SelectVariant::SkyBox
                                                on_change=on_op_change
                                            />
                                        </div>

                                        <button
                                            type="button"
                                            class="le-qb-remove-btn"
                                            title="Remove condition"
                                            aria-label="Remove condition"
                                            on:click=remove_node
                                        >
                                            "\u{00D7}"
                                        </button>
                                    </div>

                                    <div class="le-qb-card-body">
                                        {move || {
                                            let f = field_sig.get();
                                            let op = op_sig.get();
                                            if f.supports_in() && op.is_list() {
                                                return view! {
                                                    <ChipListInput
                                                        field=f
                                                        negated=Signal::derive(move || op_sig.get().is_negated())
                                                        values=Signal::derive(move || values_sig.get())
                                                        provider=suggest_provider
                                                        indigo=false
                                                        on_commit_raw=on_commit_raw
                                                        on_remove_chip=on_remove_chip
                                                        on_remove_last=on_remove_last
                                                    />
                                                }
                                                .into_any();
                                            }
                                            match f {
                                                QueryFieldKind::Unclassified => view! {
                                                    <span class="le-qb-unclassified-badge">
                                                        "Matches pending / unclassified media"
                                                    </span>
                                                }
                                                .into_any(),
                                                QueryFieldKind::UploadImage => {
                                                    if let Some(render_slot) = render_upload_slot {
                                                        view! {
                                                            <div class="le-qb-upload-slot">
                                                                {render_slot.run(node_id)}
                                                            </div>
                                                        }
                                                        .into_any()
                                                    } else {
                                                        view! {
                                                            <input
                                                                type="text"
                                                                class="le-qb-value-input"
                                                                aria-label="Upload image slot"
                                                                placeholder=f.placeholder(effective_mode)
                                                                value=move || val_sig.get()
                                                                prop:value=move || val_sig.get()
                                                                on:input=move |ev| {
                                                                    let next = event_target_value(&ev);
                                                                    draft.update(|d| {
                                                                        if let Some(QueryBuilderNode::Condition { condition, .. }) =
                                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                                        {
                                                                            condition.value = next;
                                                                        }
                                                                    });
                                                                    sync_from_nodes();
                                                                }
                                                            />
                                                        }
                                                        .into_any()
                                                    }
                                                }
                                                _ => {
                                                    let on_val_change = Callback::new(move |next: String| {
                                                        draft.update(|d| {
                                                            if let Some(QueryBuilderNode::Condition { condition, .. }) =
                                                                d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                            {
                                                                condition.value = next;
                                                            }
                                                        });
                                                        sync_from_nodes();
                                                    });
                                                    view! {
                                                        <SuggestTextInput
                                                            field=Signal::derive(move || field_sig.get())
                                                            mode=effective_mode
                                                            aria_label="Condition value"
                                                            value=Signal::derive(move || val_sig.get())
                                                            provider=suggest_provider
                                                            indigo=false
                                                            on_value_change=on_val_change
                                                        />
                                                    }
                                                    .into_any()
                                                }
                                            }
                                        }}

                                        {move || {
                                            let f = field_sig.get();
                                            f.supports_threshold().then(|| view! {
                                                <ThresholdPillInput
                                                    field=f
                                                    mode=effective_mode
                                                    threshold=threshold_sig
                                                    defaults=defaults_sig
                                                    on_change=on_threshold_change
                                                />
                                            })
                                        }}
                                    </div>
                                </div>
                            }
                            .into_any()
                        } else {
                            let group_neg_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::Group(g) => Some(g.negated),
                                            _ => None,
                                        })
                                        .unwrap_or(false)
                                })
                            });
                            let comb_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::Group(g) => Some(g.combinator),
                                            _ => None,
                                        })
                                        .unwrap_or(QueryCombinator::Or)
                                })
                            });
                            let inner_ids = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .map(|n| match n {
                                            QueryBuilderNode::Group(g) => {
                                                g.conditions.iter().map(|c| c.id).collect::<Vec<_>>()
                                            }
                                            _ => Vec::new(),
                                        })
                                        .unwrap_or_default()
                                })
                            });

                            let set_combinator = move |next: QueryCombinator| {
                                draft.update(|d| {
                                    if let Some(QueryBuilderNode::Group(g)) =
                                        d.nodes.iter_mut().find(|n| n.id() == node_id)
                                    {
                                        g.combinator = next;
                                    }
                                });
                                sync_from_nodes();
                            };

                            let add_inner_condition = move |_| {
                                let cid = alloc_qb_id();
                                draft.update(|d| {
                                    if let Some(QueryBuilderNode::Group(g)) =
                                        d.nodes.iter_mut().find(|n| n.id() == node_id)
                                    {
                                        g.conditions.push(QueryCondition {
                                            id: cid,
                                            field: QueryFieldKind::Tag,
                                            value: String::new(),
                                            negated: false,
                                            threshold: None,
                                        });
                                    }
                                });
                                sync_from_nodes();
                            };

                            view! {
                                <div class="le-qb-group">
                                    <div class="le-qb-group-header">
                                        <div class="le-qb-group-header-left">
                                            {move || {
                                                if idx_sig.get() == 0 {
                                                    view! {
                                                        <span class="le-qb-match-pill le-qb-match-pill--indigo">"Match"</span>
                                                    }
                                                    .into_any()
                                                } else {
                                                    view! {
                                                        <SkySelect
                                                            aria_label="Group boolean connector"
                                                            variant=SelectVariant::IndigoBox
                                                            trigger_class="le-qb-conn-select"
                                                            value=Signal::derive(move || conn_sig.get().as_str().to_string())
                                                            options=connector_options
                                                            on_change=on_connector_change
                                                        />
                                                    }
                                                    .into_any()
                                                }
                                            }}

                                            <button
                                                type="button"
                                                class=move || if group_neg_sig.get() {
                                                    "le-qb-not-btn is-active"
                                                } else {
                                                    "le-qb-not-btn"
                                                }
                                                aria-pressed=move || group_neg_sig.get().to_string()
                                                title="Negate entire group (NOT (...))"
                                                on:click=move |_| {
                                                    draft.update(|d| {
                                                        if let Some(QueryBuilderNode::Group(g)) =
                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                        {
                                                            g.negated = !g.negated;
                                                        }
                                                    });
                                                    sync_from_nodes();
                                                }
                                            >
                                                "NOT"
                                            </button>

                                            <span class="le-qb-group-paren" aria-hidden="true">"( ... )"</span>

                                            <div class="le-qb-comb-toggle" role="group" aria-label="Group match mode">
                                                <button
                                                    type="button"
                                                    class=move || if comb_sig.get() == QueryCombinator::Or {
                                                        "le-qb-comb-btn is-active"
                                                    } else {
                                                        "le-qb-comb-btn"
                                                    }
                                                    aria-pressed=move || (comb_sig.get() == QueryCombinator::Or).to_string()
                                                    aria-label="Match ANY (OR)"
                                                    title="Match ANY condition in this group (OR)"
                                                    on:click=move |_| set_combinator(QueryCombinator::Or)
                                                >
                                                    "ANY"
                                                    <span class="le-qb-hide-narrow">" (OR)"</span>
                                                </button>
                                                <button
                                                    type="button"
                                                    class=move || if comb_sig.get() == QueryCombinator::And {
                                                        "le-qb-comb-btn is-active"
                                                    } else {
                                                        "le-qb-comb-btn"
                                                    }
                                                    aria-pressed=move || (comb_sig.get() == QueryCombinator::And).to_string()
                                                    aria-label="Match ALL (AND)"
                                                    title="Match ALL conditions in this group (AND)"
                                                    on:click=move |_| set_combinator(QueryCombinator::And)
                                                >
                                                    "ALL"
                                                    <span class="le-qb-hide-narrow">" (AND)"</span>
                                                </button>
                                            </div>
                                        </div>

                                        <div class="le-qb-group-header-actions">
                                            <button
                                                type="button"
                                                class="le-qb-mini-btn"
                                                on:click=add_inner_condition
                                            >
                                                "+ Row"
                                            </button>
                                            <button
                                                type="button"
                                                class="le-qb-remove-btn"
                                                title="Remove group"
                                                aria-label="Remove group"
                                                on:click=remove_node
                                            >
                                                "\u{00D7}"
                                            </button>
                                        </div>
                                    </div>

                                    <div class="le-qb-group-body">
                                        <For
                                            each=move || inner_ids.get()
                                            key=|cid| *cid
                                            let(cid)
                                        >
                                            {
                                                let c_idx = Memo::new(move |_| {
                                                    inner_ids
                                                        .with(|ids| ids.iter().position(|x| *x == cid))
                                                        .unwrap_or(0)
                                                });
                                                let c_field = Memo::new(move |_| {
                                                    draft.with(|d| {
                                                        d.nodes
                                                            .iter()
                                                            .find(|n| n.id() == node_id)
                                                            .and_then(|n| match n {
                                                                QueryBuilderNode::Group(g) => g
                                                                    .conditions
                                                                    .iter()
                                                                    .find(|c| c.id == cid)
                                                                    .map(|c| c.field),
                                                                _ => None,
                                                            })
                                                            .unwrap_or(QueryFieldKind::Tag)
                                                    })
                                                });
                                                let c_op = Memo::new(move |_| {
                                                    draft.with(|d| {
                                                        d.nodes
                                                            .iter()
                                                            .find(|n| n.id() == node_id)
                                                            .and_then(|n| match n {
                                                                QueryBuilderNode::Group(g) => g
                                                                    .conditions
                                                                    .iter()
                                                                    .find(|c| c.id == cid)
                                                                    .map(|c| g.condition_operator(c)),
                                                                _ => None,
                                                            })
                                                            .unwrap_or(QueryConditionOp::Is)
                                                    })
                                                });
                                                let c_val = Memo::new(move |_| {
                                                    draft.with(|d| {
                                                        d.nodes
                                                            .iter()
                                                            .find(|n| n.id() == node_id)
                                                            .and_then(|n| match n {
                                                                QueryBuilderNode::Group(g) => g
                                                                    .conditions
                                                                    .iter()
                                                                    .find(|c| c.id == cid)
                                                                    .map(|c| c.value.clone()),
                                                                _ => None,
                                                            })
                                                            .unwrap_or_default()
                                                    })
                                                });
                                                let c_values = Memo::new(move |_| {
                                                    draft.with(|d| {
                                                        d.nodes
                                                            .iter()
                                                            .find(|n| n.id() == node_id)
                                                            .and_then(|n| match n {
                                                                QueryBuilderNode::Group(g) => {
                                                                    g.list_values.get(&cid).cloned()
                                                                }
                                                                _ => None,
                                                            })
                                                            .unwrap_or_default()
                                                    })
                                                });
                                                let c_threshold = Signal::derive(move || {
                                                    draft.with(|d| {
                                                        d.nodes
                                                            .iter()
                                                            .find(|n| n.id() == node_id)
                                                            .and_then(|n| match n {
                                                                QueryBuilderNode::Group(g) => g
                                                                    .conditions
                                                                    .iter()
                                                                    .find(|c| c.id == cid)
                                                                    .and_then(|c| c.threshold),
                                                                _ => None,
                                                            })
                                                    })
                                                });

                                                let on_inner_threshold = Callback::new(move |next: Option<f32>| {
                                                    draft.update(|d| {
                                                        if let Some(QueryBuilderNode::Group(g)) =
                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                            && let Some(c) =
                                                                g.conditions.iter_mut().find(|c| c.id == cid)
                                                        {
                                                            c.threshold = next.and_then(quantize_threshold);
                                                        }
                                                    });
                                                    sync_from_nodes();
                                                });

                                                let on_inner_op_change = Callback::new(move |next_op: QueryConditionOp| {
                                                    draft.update(|d| {
                                                        if let Some(QueryBuilderNode::Group(g)) =
                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                            && let Some(c) =
                                                                g.conditions.iter_mut().find(|c| c.id == cid)
                                                        {
                                                            c.negated = next_op.is_negated();
                                                            if next_op.is_list() && c.field.supports_in() {
                                                                let entry = g.list_values.entry(cid).or_default();
                                                                if entry.is_empty() && !c.value.trim().is_empty() {
                                                                    merge_chip_values(entry, &c.value);
                                                                }
                                                            } else if let Some(vals) = g.list_values.remove(&cid) {
                                                                c.value = vals.into_iter().next().unwrap_or_default();
                                                            }
                                                        }
                                                    });
                                                    sync_from_nodes();
                                                });

                                                let on_inner_commit_raw = Callback::new(move |raw: String| {
                                                    let mut changed = false;
                                                    draft.update(|d| {
                                                        if let Some(QueryBuilderNode::Group(g)) =
                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                        {
                                                            let entry = g.list_values.entry(cid).or_default();
                                                            changed = merge_chip_values(entry, &raw);
                                                        }
                                                    });
                                                    if changed {
                                                        sync_from_nodes();
                                                    }
                                                });

                                                let on_inner_remove_chip = Callback::new(move |chip: String| {
                                                    draft.update(|d| {
                                                        if let Some(QueryBuilderNode::Group(g)) =
                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                            && let Some(vals) = g.list_values.get_mut(&cid)
                                                        {
                                                            vals.retain(|v| v != &chip);
                                                        }
                                                    });
                                                    sync_from_nodes();
                                                });

                                                let on_inner_remove_last = Callback::new(move |()| {
                                                    let mut removed = false;
                                                    draft.update(|d| {
                                                        if let Some(QueryBuilderNode::Group(g)) =
                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                            && let Some(vals) = g.list_values.get_mut(&cid)
                                                        {
                                                            removed = vals.pop().is_some();
                                                        }
                                                    });
                                                    if removed {
                                                        sync_from_nodes();
                                                    }
                                                });

                                                let remove_inner = move |_| {
                                                    draft.update(|d| {
                                                        let mut drop_group = false;
                                                        if let Some(QueryBuilderNode::Group(g)) =
                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                        {
                                                            g.conditions.retain(|c| c.id != cid);
                                                            g.list_values.remove(&cid);
                                                            drop_group = g.conditions.is_empty();
                                                        }
                                                        if drop_group {
                                                            d.nodes.retain(|n| n.id() != node_id);
                                                            if let Some(first) = d.nodes.first_mut()
                                                                && first.connector() == QueryConnector::Or
                                                            {
                                                                first.set_connector(QueryConnector::And);
                                                            }
                                                        }
                                                    });
                                                    sync_from_nodes();
                                                };

                                                view! {
                                                    <div class="le-qb-subcard">
                                                        <div class="le-qb-card-header">
                                                            <div class="le-qb-card-controls">
                                                                {move || (c_idx.get() > 0).then(|| view! {
                                                                    <span class="le-qb-inner-comb">
                                                                        {move || comb_sig.get().upper()}
                                                                    </span>
                                                                })}

                                                                <SkySelect
                                                                    aria_label="Inner condition field"
                                                                    variant=SelectVariant::IndigoBox
                                                                    trigger_class="le-qb-field-select"
                                                                    value=Signal::derive(move || c_field.get().as_prefix().to_string())
                                                                    options=group_field_options
                                                                    on_change=Callback::new(move |val: String| {
                                                                        if let Some(f) =
                                                                            QueryFieldKind::parse_for_mode(&val, effective_mode)
                                                                            && !f.is_vector()
                                                                        {
                                                                            draft.update(|d| {
                                                                                if let Some(QueryBuilderNode::Group(g)) =
                                                                                    d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                                                    && let Some(c) =
                                                                                        g.conditions.iter_mut().find(|c| c.id == cid)
                                                                                {
                                                                                    c.field = f;
                                                                                    if !f.supports_threshold() {
                                                                                        c.threshold = None;
                                                                                    }
                                                                                    if !f.supports_in()
                                                                                        && let Some(vals) = g.list_values.remove(&cid)
                                                                                    {
                                                                                        c.value = vals.into_iter().next().unwrap_or_default();
                                                                                    }
                                                                                    if f == QueryFieldKind::Unclassified {
                                                                                        c.value.clear();
                                                                                    }
                                                                                }
                                                                            });
                                                                            sync_from_nodes();
                                                                        }
                                                                    })
                                                                />

                                                                <OperatorControl
                                                                    field=Signal::derive(move || c_field.get())
                                                                    operator=Signal::derive(move || c_op.get())
                                                                    variant=SelectVariant::IndigoBox
                                                                    on_change=on_inner_op_change
                                                                />
                                                            </div>

                                                            <button
                                                                type="button"
                                                                class="le-qb-remove-btn"
                                                                title="Remove row"
                                                                aria-label="Remove row"
                                                                on:click=remove_inner
                                                            >
                                                                "\u{00D7}"
                                                            </button>
                                                        </div>

                                                        <div class="le-qb-card-body">
                                                            {move || {
                                                                let f = c_field.get();
                                                                let op = c_op.get();
                                                                if f.supports_in() && op.is_list() {
                                                                    view! {
                                                                        <ChipListInput
                                                                            field=f
                                                                            negated=Signal::derive(move || c_op.get().is_negated())
                                                                            values=Signal::derive(move || c_values.get())
                                                                            provider=suggest_provider
                                                                            indigo=true
                                                                            on_commit_raw=on_inner_commit_raw
                                                                            on_remove_chip=on_inner_remove_chip
                                                                            on_remove_last=on_inner_remove_last
                                                                        />
                                                                    }
                                                                    .into_any()
                                                                } else if f == QueryFieldKind::Unclassified {
                                                                    view! {
                                                                        <span class="le-qb-unclassified-badge">
                                                                            "unclassified"
                                                                        </span>
                                                                    }
                                                                    .into_any()
                                                                } else {
                                                                    let on_inner_val_change = Callback::new(move |next: String| {
                                                                        draft.update(|d| {
                                                                            if let Some(QueryBuilderNode::Group(g)) =
                                                                                d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                                                && let Some(c) =
                                                                                    g.conditions.iter_mut().find(|c| c.id == cid)
                                                                            {
                                                                                c.value = next;
                                                                            }
                                                                        });
                                                                        sync_from_nodes();
                                                                    });
                                                                    view! {
                                                                        <SuggestTextInput
                                                                            field=Signal::derive(move || c_field.get())
                                                                            mode=effective_mode
                                                                            aria_label="Inner condition value"
                                                                            value=Signal::derive(move || c_val.get())
                                                                            provider=suggest_provider
                                                                            indigo=true
                                                                            on_value_change=on_inner_val_change
                                                                        />
                                                                    }
                                                                    .into_any()
                                                                }
                                                            }}

                                                            {move || {
                                                                let f = c_field.get();
                                                                f.supports_threshold().then(|| view! {
                                                                    <ThresholdPillInput
                                                                        field=f
                                                                        mode=effective_mode
                                                                        threshold=c_threshold
                                                                        defaults=defaults_sig
                                                                        on_change=on_inner_threshold
                                                                    />
                                                                })
                                                            }}
                                                        </div>
                                                    </div>
                                                }
                                            }
                                        </For>
                                    </div>
                                </div>
                            }
                            .into_any()
                        }
                    }
                </For>
            </div>

            // Action toolbar
            <div class="le-qb-toolbar">
                <button type="button" class="le-btn le-btn--secondary le-btn--sm" on:click=add_condition>
                    "+ Condition"
                </button>
                <button type="button" class="le-btn le-btn--indigo le-btn--sm" on:click=add_group>
                    "+ ( OR / AND ) Group"
                </button>
            </div>

            // Live raw query expression editor
            {show_raw_editor.then(|| {
                let raw_for_id = raw_input_id.clone();
                let raw_el_id = raw_input_id.clone();
                let on_apply_raw = Callback::new(move |next_raw: String| {
                    let mut alloc = alloc_qb_id;
                    match parse_query_to_nodes(effective_mode, &next_raw, &mut alloc) {
                        Ok(parsed) => {
                            raw_parse_error.set(None);
                            draft.update(|d| {
                                d.mode = effective_mode;
                                d.active_preset = None;
                                d.query = next_raw;
                                d.nodes = parsed;
                            });
                            emit_change();
                        }
                        Err(err) => {
                            raw_parse_error.set(Some(err));
                            draft.update(|d| {
                                d.active_preset = None;
                                d.query = next_raw;
                            });
                            emit_change();
                        }
                    }
                });
                view! {
                    <div class="le-qb-raw">
                        <label class="le-field-label" for=raw_for_id>{raw_label}</label>
                        <RawQueryInput
                            input_id=raw_el_id
                            placeholder=raw_placeholder
                            mode=effective_mode
                            draft=draft
                            provider=suggest_provider
                            on_apply_raw=on_apply_raw
                        />
                    </div>
                }
            })}

            {move || combined_error().map(|err| view! {
                <div class="le-qb-error" role="alert">{err}</div>
            })}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggest_wd_vocab_ranks_exact_prefix_substring_and_normalizes_spaces_and_case() {
        let res = suggest_wd_vocab_tags("maid", 10);
        assert_eq!(res.len(), 10);
        assert_eq!(res[0].value, "maid");
        assert_eq!(res[0].kind, "tag");
        assert!(res[0].aliases.is_empty());
        // Prefix matches precede pure substring matches.
        let first_non_prefix = res.iter().position(|s| !s.value.starts_with("maid"));
        if let Some(idx) = first_non_prefix {
            assert!(res[idx..].iter().all(|s| !s.value.starts_with("maid")));
        }

        // Case-insensitive and space-to-underscore normalization.
        let sky = suggest_wd_vocab_tags("Blue Sky", 10);
        assert!(!sky.is_empty());
        assert_eq!(sky[0].value, "blue_sky");

        // Substring-only query finds tags containing it, sorted by length then lexicographically.
        let sub = suggest_wd_vocab_tags("censoring", 5);
        assert!(sub.iter().any(|s| s.value == "mosaic_censoring"));

        // Non-ASCII and empty inputs return empty safely without panicking.
        assert!(suggest_wd_vocab_tags("", 10).is_empty());
        assert!(suggest_wd_vocab_tags("   ", 10).is_empty());
        assert!(suggest_wd_vocab_tags("女仆", 10).is_empty());
        assert!(suggest_wd_vocab_tags("maid", 0).is_empty());
    }

    #[test]
    fn should_suggest_query_enforces_field_and_length_thresholds() {
        assert!(!should_suggest_query(QueryFieldKind::Tag, ""));
        assert!(!should_suggest_query(QueryFieldKind::Tag, "a"));
        assert!(should_suggest_query(QueryFieldKind::Tag, "ab"));
        assert!(should_suggest_query(QueryFieldKind::Tag, "猫"));
        assert!(should_suggest_query(QueryFieldKind::Author, "渡"));
        assert!(should_suggest_query(QueryFieldKind::Title, "ab"));
        assert!(should_suggest_query(QueryFieldKind::TitleAndAuthor, "ab"));
        assert!(!should_suggest_query(QueryFieldKind::ClipText, "sunset"));
        assert!(!should_suggest_query(QueryFieldKind::SimilarId, "12345"));
        assert!(!should_suggest_query(QueryFieldKind::UploadImage, "0"));
        assert!(!should_suggest_query(QueryFieldKind::Unclassified, "un"));
    }

    #[test]
    fn raw_suggest_handles_simple_negated_thresholds_and_surrounding_tokens() {
        let mode = QueryBuilderMode::AdvancedSearch;

        // Simple prefix at end
        let raw = "tag:blu";
        let span = extract_raw_suggest_context(raw, raw.len(), mode).expect("simple tag");
        assert_eq!(span.field, QueryFieldKind::Tag);
        assert_eq!(span.query, "blu");
        assert_eq!(span.replace_range, 4..7);
        assert!(!span.in_list);
        assert_eq!(
            splice_raw_suggestion(raw, &span, "blue_sky"),
            ("tag:blue_sky".to_string(), 12)
        );

        // Negated with `-tag:` + surrounding tokens preserved
        let raw = "-tag:mon AND clip:\"sunset\"";
        let span = extract_raw_suggest_context(raw, 8, mode).expect("negated tag");
        assert_eq!(span.field, QueryFieldKind::Tag);
        assert_eq!(span.query, "mon");
        assert_eq!(span.replace_range, 5..8);
        assert_eq!(
            splice_raw_suggestion(raw, &span, "monochrome"),
            ("-tag:monochrome AND clip:\"sunset\"".to_string(), 15)
        );

        // Preserves `>=0.50` threshold suffix right after value
        let raw = "tag:blu>=0.50 AND NOT tag:monochrome";
        let span = extract_raw_suggest_context(raw, 7, mode).expect("tag before threshold");
        assert_eq!(span.query, "blu");
        assert_eq!(span.replace_range, 4..7);
        assert_eq!(
            splice_raw_suggestion(raw, &span, "blue_sky"),
            ("tag:blue_sky>=0.50 AND NOT tag:monochrome".to_string(), 12)
        );

        // Caret inside numeric threshold does NOT trigger tag suggestions
        assert!(extract_raw_suggest_context("tag:maid>=0.45", 13, mode).is_none());

        // Inside parenthesized group preserves `)` and trailing tokens
        let raw = "(tag:maid OR tag:ap) NOT tag:monochrome";
        let span = extract_raw_suggest_context(raw, 19, mode).expect("tag in group");
        assert_eq!(span.query, "ap");
        assert_eq!(
            splice_raw_suggestion(raw, &span, "apron"),
            ("(tag:maid OR tag:apron) NOT tag:monochrome".to_string(), 22)
        );
    }

    #[test]
    fn raw_suggest_handles_quoted_values_and_unclosed_quotes_without_clobbering() {
        let mode = QueryBuilderMode::AdvancedSearch;

        // Unclosed quote at end of string
        let raw = "tag:\"blue ";
        let span = extract_raw_suggest_context(raw, raw.len(), mode).expect("unclosed quote");
        assert_eq!(span.field, QueryFieldKind::Tag);
        assert_eq!(span.query, "blue");
        assert!(span.inside_quotes);
        assert_eq!(
            splice_raw_suggestion(raw, &span, "blue_sky"),
            ("tag:blue_sky".to_string(), 12)
        );
        assert_eq!(
            splice_raw_suggestion(raw, &span, "blue sky"),
            ("tag:\"blue sky\"".to_string(), 14)
        );

        // Unclosed quote BEFORE trailing tokens does not clobber following clause
        let raw = "tag:\"blue  AND tag:maid";
        let span = extract_raw_suggest_context(raw, 9, mode).expect("unclosed mid-query");
        assert_eq!(span.query, "blue");
        assert_eq!(span.replace_range, 4..9);
        assert_eq!(
            splice_raw_suggestion(raw, &span, "blue_sky"),
            ("tag:blue_sky  AND tag:maid".to_string(), 12)
        );

        // Closed quote before `>=0.45` replaces quoted span while preserving `>=0.45`
        let raw = "tag:\"blue sk\">=0.45";
        let span = extract_raw_suggest_context(raw, 12, mode).expect("closed quote before gte");
        assert_eq!(span.query, "blue sk");
        assert_eq!(span.replace_range, 4..13);
        assert_eq!(
            splice_raw_suggestion(raw, &span, "blue_sky"),
            ("tag:blue_sky>=0.45".to_string(), 12)
        );
    }

    #[test]
    fn raw_suggest_handles_in_and_not_in_lists_and_excludes_existing_items() {
        let mode = QueryBuilderMode::AdvancedSearch;

        // Active item inside `tag IN (maid, apr) >= 0.45`
        let raw = "tag IN (maid, apr) >= 0.45";
        let span = extract_raw_suggest_context(raw, 17, mode).expect("tag IN item");
        assert_eq!(span.field, QueryFieldKind::Tag);
        assert!(span.in_list);
        assert_eq!(span.query, "apr");
        assert_eq!(span.replace_range, 14..17);
        assert_eq!(span.existing_in_items, vec!["maid".to_string()]);
        assert_eq!(
            splice_raw_suggestion(raw, &span, "apron"),
            ("tag IN (maid, apron) >= 0.45".to_string(), 19)
        );

        // Unclosed quote inside `tag NOT IN (maid, "blue ) >= 0.45` preserves `) >= 0.45`
        let raw = "tag NOT IN (maid, \"blue ) >= 0.45";
        let span = extract_raw_suggest_context(raw, 24, mode).expect("unclosed quote in NOT IN");
        assert_eq!(span.field, QueryFieldKind::Tag);
        assert!(span.in_list);
        assert!(span.inside_quotes);
        assert_eq!(span.query, "blue");
        assert_eq!(span.existing_in_items, vec!["maid".to_string()]);
        assert_eq!(
            splice_raw_suggestion(raw, &span, "blue_sky"),
            ("tag NOT IN (maid, blue_sky) >= 0.45".to_string(), 26)
        );
        assert_eq!(
            splice_raw_suggestion(raw, &span, "blue sky"),
            ("tag NOT IN (maid, \"blue sky\") >= 0.45".to_string(), 28)
        );

        // `author IN (...)` with value requiring quotes (comma/space)
        let raw = "author IN (alice, bob s)";
        let span = extract_raw_suggest_context(raw, 23, mode).expect("author IN item");
        assert_eq!(span.field, QueryFieldKind::Author);
        assert!(span.in_list);
        assert_eq!(span.query, "bob s");
        assert_eq!(span.existing_in_items, vec!["alice".to_string()]);
        assert_eq!(
            splice_raw_suggestion(raw, &span, "bob smith"),
            ("author IN (alice, \"bob smith\")".to_string(), 29)
        );
    }

    #[test]
    fn raw_suggest_handles_utf16_cjk_emoji_carets_and_mode_restrictions() {
        let adv = QueryBuilderMode::AdvancedSearch;
        let safety = QueryBuilderMode::SafetyPolicy;

        // CJK + supplementary emoji UTF-16 offset conversion
        let raw = "title:✨星光 AND author:渡久 NOT tag:蓝";
        // `title:`(6) + `✨`(1 u16) + `星`(1) + `光`(1) + ` AND author:`(12) + `渡`(1) + `久`(1) = 23 u16
        let author_caret_u16 = byte_offset_to_utf16(raw, raw.find(" NOT").unwrap());
        let span = extract_raw_suggest_context(raw, author_caret_u16, adv).expect("CJK author");
        assert_eq!(span.field, QueryFieldKind::Author);
        assert_eq!(span.query, "渡久");
        let (spliced, next_u16) = splice_raw_suggestion(raw, &span, "渡久山");
        assert_eq!(spliced, "title:✨星光 AND author:渡久山 NOT tag:蓝");
        assert_eq!(
            next_u16,
            byte_offset_to_utf16(&spliced, spliced.find(" NOT").unwrap())
        );

        // Emoji (surrogate pair = 2 UTF-16 code units, 4 UTF-8 bytes) before `tag:ma`
        let emoji_raw = "title:🎨 AND tag:ma";
        let end_u16 = emoji_raw.encode_utf16().count();
        assert_eq!(utf16_offset_to_byte(emoji_raw, end_u16), emoji_raw.len());
        let emoji_span = extract_raw_suggest_context(emoji_raw, end_u16, adv).expect("after emoji");
        assert_eq!(emoji_span.field, QueryFieldKind::Tag);
        assert_eq!(emoji_span.query, "ma");
        assert_eq!(
            splice_raw_suggestion(emoji_raw, &emoji_span, "maid"),
            ("title:🎨 AND tag:maid".to_string(), end_u16 + 2)
        );

        // Mode restrictions: `title:` and `all:` work in AdvancedSearch, rejected in SafetyPolicy;
        // vector fields (`clip:`, `dino:`, `upload:`) never trigger suggestions.
        assert_eq!(
            extract_raw_suggest_context("title:sun", 9, adv).map(|s| s.field),
            Some(QueryFieldKind::Title)
        );
        assert_eq!(
            extract_raw_suggest_context("all:sun", 7, adv).map(|s| s.field),
            Some(QueryFieldKind::TitleAndAuthor)
        );
        assert!(extract_raw_suggest_context("title:sun", 9, safety).is_none());
        assert_eq!(
            extract_raw_suggest_context("author:foo", 10, safety).map(|s| s.field),
            Some(QueryFieldKind::Author)
        );
        assert!(extract_raw_suggest_context("clip:sunset", 11, adv).is_none());
        assert!(extract_raw_suggest_context("dino:1234", 9, adv).is_none());
        assert!(extract_raw_suggest_context("upload:0", 8, adv).is_none());
    }

    #[test]
    fn suggest_placement_flips_above_when_near_bottom_and_clamps_to_viewport() {
        let below = compute_suggest_placement_from_metrics(100.0, 136.0, 40.0, 320.0, 1024.0, 768.0, 5);
        assert!(!below.open_above);
        assert!(below.top_px.is_some());
        assert!(below.bottom_px.is_none());
        assert_eq!(below.width_px, 280.0);

        let above = compute_suggest_placement_from_metrics(690.0, 726.0, 40.0, 320.0, 1024.0, 768.0, 6);
        assert!(above.open_above);
        assert!(above.bottom_px.is_some());
        assert!(above.top_px.is_none());

        // Narrow mobile viewport clamps width & left margin
        let mobile = compute_suggest_placement_from_metrics(200.0, 236.0, 10.0, 350.0, 360.0, 640.0, 4);
        assert!(mobile.width_px <= 336.0);
        assert!(mobile.left_px >= SUGGEST_VIEWPORT_MARGIN_PX);
    }
}
