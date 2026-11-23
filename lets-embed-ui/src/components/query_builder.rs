use std::sync::atomic::{AtomicU64, Ordering};

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::{OptionalScoreInput, SkySelect};
use crate::models::{PresetTemplate, SelectOption, SelectVariant};
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

/// Parenthesized `( ... )` boolean group containing 1..N [`QueryCondition`] rows.
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
}

/// Ordered top-level item inside a [`QueryBuilderDraft`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum QueryBuilderNode {
    Condition {
        #[serde(default)]
        connector: QueryConnector,
        condition: QueryCondition,
    },
    Group(QueryGroup),
}

impl QueryBuilderNode {
    pub const fn id(&self) -> u64 {
        match self {
            Self::Condition { condition, .. } => condition.id,
            Self::Group(group) => group.id,
        }
    }

    pub const fn connector(&self) -> QueryConnector {
        match self {
            Self::Condition { connector, .. } => *connector,
            Self::Group(group) => group.connector,
        }
    }

    pub fn set_connector(&mut self, next: QueryConnector) {
        match self {
            Self::Condition { connector, .. } => *connector = next,
            Self::Group(group) => group.connector = next,
        }
    }

    pub fn is_vector(&self) -> bool {
        match self {
            Self::Condition { condition, .. } => condition.field.is_vector(),
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
            QueryBuilderNode::Group(group) => {
                let parts: Vec<String> = group
                    .conditions
                    .iter()
                    .filter_map(format_query_condition)
                    .collect();
                let expr = match parts.len() {
                    0 => None,
                    1 => {
                        let only = parts.into_iter().next().unwrap();
                        if group.negated {
                            if only.starts_with("NOT ") {
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
enum QbToken {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Minus,
    Gte,
    Atom(QbAtom),
}

fn is_gte_at(chars: &[char], i: usize) -> bool {
    chars.get(i) == Some(&'>') && chars.get(i + 1) == Some(&'=')
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
                _ => tokens.push(QbToken::Atom(QbAtom { prefix, rest: None })),
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
                "Unsupported term `{}` — use tag:, post_tag:, author:, or unclassified",
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
/// - Optional whitespace around `>=` outside quotes (`tag:maid>=0.45`, `tag:maid>= 0.45`,
///   `tag:maid >=0.45`, `tag:maid >= 0.45`, `clip:"sunlit sky" >= 0.25`)
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
                QbToken::Not | QbToken::Minus | QbToken::Atom(_) | QbToken::LParen => {
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
                            QbToken::Not | QbToken::Minus | QbToken::Atom(_) | QbToken::LParen => {
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
                            let mut cond =
                                parse_qb_atom(atom, mode, true, inner_neg, next_id)?;
                            pos += 1;
                            cond.threshold =
                                consume_optional_threshold(&tokens, &mut pos, cond.field)?;
                            conditions.push(cond);
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

/// Unified visual boolean query builder shared by BOTH Gallery Advanced Search
/// (`QueryBuilderMode::AdvancedSearch`) and Admin Content Policy Selector
/// (`QueryBuilderMode::SafetyPolicy`).
///
/// Key guarantees:
/// - Self-contained bordered condition cards (`le-qb-card`) with top-right `×` close
///   buttons unambiguously bound to each card.
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
    #[prop(default = true)] show_raw_editor: bool,
) -> impl IntoView {
    let effective_mode = mode.unwrap_or_else(|| draft.with_untracked(|d| d.mode));
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
            "Policy Selector Expression (metadata-only: tag:, post_tag:, author:, unclassified)"
        }
        QueryBuilderMode::AdvancedSearch => {
            "Query Expression (tag:, title:, author:, clip:, dino:, upload:, with optional >=threshold)"
        }
    };

    let raw_placeholder = match effective_mode {
        QueryBuilderMode::SafetyPolicy => {
            "e.g. (tag:explicit>=0.45 OR tag:nude) AND NOT post_tag:safe"
        }
        QueryBuilderMode::AdvancedSearch => {
            "e.g. (tag:maid>=0.45 OR tag:apron) AND clip:\"sunlit garden\">=0.25"
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
                            let neg_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::Condition { condition, .. } => {
                                                Some(condition.negated)
                                            }
                                            _ => None,
                                        })
                                        .unwrap_or(false)
                                })
                            });
                            let field_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::Condition { condition, .. } => {
                                                Some(condition.field)
                                            }
                                            _ => None,
                                        })
                                        .unwrap_or(QueryFieldKind::Tag)
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
                            let threshold_sig = Signal::derive(move || {
                                draft.with(|d| {
                                    d.nodes
                                        .iter()
                                        .find(|n| n.id() == node_id)
                                        .and_then(|n| match n {
                                            QueryBuilderNode::Condition { condition, .. } => {
                                                condition.threshold
                                            }
                                            _ => None,
                                        })
                                })
                            });

                            let on_threshold_change = Callback::new(move |next: Option<f32>| {
                                draft.update(|d| {
                                    if let Some(QueryBuilderNode::Condition { condition, .. }) =
                                        d.nodes.iter_mut().find(|n| n.id() == node_id)
                                    {
                                        condition.threshold = next.and_then(quantize_threshold);
                                    }
                                });
                                sync_from_nodes();
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

                                            <button
                                                type="button"
                                                class=move || if neg_sig.get() {
                                                    "le-qb-not-btn is-active"
                                                } else {
                                                    "le-qb-not-btn"
                                                }
                                                aria-pressed=move || neg_sig.get().to_string()
                                                title="Negate condition (NOT)"
                                                on:click=move |_| {
                                                    draft.update(|d| {
                                                        if let Some(QueryBuilderNode::Condition { condition, .. }) =
                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                        {
                                                            condition.negated = !condition.negated;
                                                        }
                                                    });
                                                    sync_from_nodes();
                                                }
                                            >
                                                "NOT"
                                            </button>

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
                                                            if let Some(QueryBuilderNode::Condition { condition, .. }) =
                                                                d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                            {
                                                                condition.field = next_field;
                                                                if !next_field.supports_threshold() {
                                                                    condition.threshold = None;
                                                                }
                                                                if next_field == QueryFieldKind::Unclassified {
                                                                    condition.value.clear();
                                                                }
                                                            }
                                                        });
                                                        sync_from_nodes();
                                                    }
                                                })
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
                                                _ => view! {
                                                    <input
                                                        type="text"
                                                        class="le-qb-value-input"
                                                        aria-label="Condition value"
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
                                                .into_any(),
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
                                                let c_neg = Memo::new(move |_| {
                                                    draft.with(|d| {
                                                        d.nodes
                                                            .iter()
                                                            .find(|n| n.id() == node_id)
                                                            .and_then(|n| match n {
                                                                QueryBuilderNode::Group(g) => g
                                                                    .conditions
                                                                    .iter()
                                                                    .find(|c| c.id == cid)
                                                                    .map(|c| c.negated),
                                                                _ => None,
                                                            })
                                                            .unwrap_or(false)
                                                    })
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

                                                let remove_inner = move |_| {
                                                    draft.update(|d| {
                                                        let mut drop_group = false;
                                                        if let Some(QueryBuilderNode::Group(g)) =
                                                            d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                        {
                                                            g.conditions.retain(|c| c.id != cid);
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

                                                                <button
                                                                    type="button"
                                                                    class=move || if c_neg.get() {
                                                                        "le-qb-not-btn is-active"
                                                                    } else {
                                                                        "le-qb-not-btn"
                                                                    }
                                                                    aria-pressed=move || c_neg.get().to_string()
                                                                    title="Negate this condition (NOT)"
                                                                    on:click=move |_| {
                                                                        draft.update(|d| {
                                                                            if let Some(QueryBuilderNode::Group(g)) =
                                                                                d.nodes.iter_mut().find(|n| n.id() == node_id)
                                                                                && let Some(c) =
                                                                                    g.conditions.iter_mut().find(|c| c.id == cid)
                                                                            {
                                                                                c.negated = !c.negated;
                                                                            }
                                                                        });
                                                                        sync_from_nodes();
                                                                    }
                                                                >
                                                                    "NOT"
                                                                </button>

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
                                                                                    if f == QueryFieldKind::Unclassified {
                                                                                        c.value.clear();
                                                                                    }
                                                                                }
                                                                            });
                                                                            sync_from_nodes();
                                                                        }
                                                                    })
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
                                                                if f == QueryFieldKind::Unclassified {
                                                                    view! {
                                                                        <span class="le-qb-unclassified-badge">
                                                                            "unclassified"
                                                                        </span>
                                                                    }
                                                                    .into_any()
                                                                } else {
                                                                    view! {
                                                                        <input
                                                                            type="text"
                                                                            class="le-qb-value-input"
                                                                            aria-label="Inner condition value"
                                                                            placeholder=f.placeholder(effective_mode)
                                                                            value=move || c_val.get()
                                                                            prop:value=move || c_val.get()
                                                                            on:input=move |ev| {
                                                                                let next = event_target_value(&ev);
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
                                                                            }
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
                view! {
                    <div class="le-qb-raw">
                        <label class="le-field-label" for=raw_for_id>{raw_label}</label>
                        <input
                            id=raw_el_id
                            type="text"
                            class="le-qb-raw-input"
                            placeholder=raw_placeholder
                            value=move || draft.with(|d| d.query.clone())
                            prop:value=move || draft.with(|d| d.query.clone())
                            on:input=move |ev| {
                                let next_raw = event_target_value(&ev);
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
                            }
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
