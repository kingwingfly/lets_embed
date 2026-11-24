//! Query v3 boolean AST, per-condition threshold parsing (`>= 0.01..=1.00`),
//! and independent vector-clause planning (zero cross-model weighted summation).

use std::fmt;

pub const MAX_QUERY_LEN: usize = 2000;
pub const MAX_DEPTH: usize = 8;
pub const MAX_TERMS: usize = 24;
pub const MAX_CLIP_TERMS: usize = 8;
pub const MAX_DINO_TERMS: usize = 8;
pub const MAX_UPLOAD_TERMS: usize = 4;

// ---------------------------------------------------------------------------
// Strict Hundredths Threshold Validation Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdError {
    pub message: String,
}

impl ThresholdError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ThresholdError {}

/// Strictly parses a newly supplied threshold string at hundredths precision
/// (`0.01..=1.00`, i.e. integer hundredths `1..=100`, at most 2 decimal places).
///
/// Rejects `0`, `0.00`, `> 1.00`, negative values, leading `+`, `NaN`/`Inf`,
/// scientific notation, `> 2` decimal places, whitespace, and trailing garbage.
pub fn parse_threshold_hundredths(raw: &str) -> Result<f32, ThresholdError> {
    if raw.is_empty() {
        return Err(ThresholdError::new("Expected numeric score after '>='"));
    }
    if !raw.is_ascii() || raw != raw.trim() {
        return Err(ThresholdError::new(format!(
            "Invalid threshold '{raw}' (expected decimal in 0.01..=1.00 with at most 2 decimal places)"
        )));
    }
    if raw.starts_with('+') || raw.starts_with('-') {
        return Err(ThresholdError::new(format!(
            "Threshold '{raw}' must be in 0.01..=1.00"
        )));
    }

    let hundredths: u32 = if let Some((int_part, frac_part)) = raw.split_once('.') {
        if frac_part.is_empty()
            || frac_part.len() > 2
            || frac_part.contains('.')
            || !int_part.bytes().all(|b| b.is_ascii_digit())
            || !frac_part.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(ThresholdError::new(format!(
                "Invalid threshold '{raw}' (expected decimal in 0.01..=1.00 with at most 2 decimal places)"
            )));
        }

        let whole: u32 = match int_part {
            "" | "0" => 0,
            "1" => 1,
            _ => {
                return Err(ThresholdError::new(format!(
                    "Threshold '{raw}' must be in 0.01..=1.00"
                )));
            }
        };

        let frac_val: u32 = if frac_part.len() == 1 {
            (frac_part.as_bytes()[0] - b'0') as u32 * 10
        } else {
            (frac_part.as_bytes()[0] - b'0') as u32 * 10 + (frac_part.as_bytes()[1] - b'0') as u32
        };

        whole * 100 + frac_val
    } else {
        if raw == "1" {
            100
        } else {
            return Err(ThresholdError::new(format!(
                "Threshold '{raw}' must be in 0.01..=1.00"
            )));
        }
    };

    if !(1..=100).contains(&hundredths) {
        return Err(ThresholdError::new(format!(
            "Threshold '{raw}' must be in 0.01..=1.00"
        )));
    }

    Ok((hundredths as f32) / 100.0)
}

/// Validates a finite threshold in `(0.0, 1.0]` without restricting to hundredths,
/// suitable for preserving legacy persisted thresholds during migration.
pub fn validate_threshold_range(value: f32) -> Result<f32, ThresholdError> {
    if !value.is_finite() || value <= 0.0 || value > 1.0 {
        return Err(ThresholdError::new(format!(
            "Threshold '{value}' must be finite and in (0.0, 1.0]"
        )));
    }
    Ok(value)
}

/// Validates an `f32` threshold as exact hundredths in `0.01..=1.00` (for new
/// policy publishes / API payloads carrying JSON floats).
pub fn validate_threshold_hundredths_f32(value: f32) -> Result<f32, ThresholdError> {
    if !value.is_finite() {
        return Err(ThresholdError::new(format!(
            "Threshold '{value}' must be finite and in 0.01..=1.00"
        )));
    }
    let scaled = value * 100.0;
    let rounded = scaled.round();
    if (scaled - rounded).abs() > 1e-4 {
        return Err(ThresholdError::new(format!(
            "Threshold '{value}' must use at most 2 decimal places (0.01..=1.00)"
        )));
    }
    let hundredths = rounded as i64;
    if !(1..=100).contains(&hundredths) {
        return Err(ThresholdError::new(format!(
            "Threshold '{value}' must be in 0.01..=1.00"
        )));
    }
    Ok((hundredths as f32) / 100.0)
}

/// Formats a threshold cleanly at hundredths precision (`0.01`..`1.00`) when it
/// represents hundredths, or falls back to `value.to_string()` for legacy values.
pub fn format_threshold_hundredths(value: f32) -> String {
    if let Ok(q) = validate_threshold_hundredths_f32(value) {
        format!("{q:.2}")
    } else {
        value.to_string()
    }
}

// ---------------------------------------------------------------------------
// Search Fields, AST & Query Plan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SearchField {
    /// Post title OR author name (post-level).
    All,
    /// Post title substring (post-level).
    Title,
    /// Post author name substring (post-level).
    Author,
    /// WD image tag or multilingual translation alias (image-level).
    Tag,
    /// SigLIP2 natural-language text description (image-level vector).
    Clip,
    /// DINOv3 visually similar image ID (image-level vector).
    Dino,
    /// DINOv3 uploaded image slot index `0..N` (image-level vector).
    Upload,
}

impl SearchField {
    pub const fn as_prefix(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Title => "title",
            Self::Author => "author",
            Self::Tag => "tag",
            Self::Clip => "clip",
            Self::Dino => "dino",
            Self::Upload => "upload",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "Title & Author",
            Self::Title => "Title",
            Self::Author => "Author",
            Self::Tag => "Tag",
            Self::Clip => "CLIP Text",
            Self::Dino => "Similar ID",
            Self::Upload => "Upload Image",
        }
    }

    pub fn parse_prefix(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "all" | "any" | "post" => Some(Self::All),
            "title" | "ti" => Some(Self::Title),
            "author" | "au" => Some(Self::Author),
            "tag" | "tg" => Some(Self::Tag),
            "clip" | "desc" => Some(Self::Clip),
            "dino" | "similar" | "id" => Some(Self::Dino),
            "upload" | "img" => Some(Self::Upload),
            _ => None,
        }
    }

    pub const fn is_vector(self) -> bool {
        matches!(self, Self::Clip | Self::Dino | Self::Upload)
    }

    pub const fn is_image_level(self) -> bool {
        matches!(self, Self::Tag | Self::Clip | Self::Dino | Self::Upload)
    }

    /// Returns `true` for fields that accept an optional per-condition `>= <score>` cutoff.
    pub const fn supports_threshold(self) -> bool {
        matches!(self, Self::Tag | Self::Clip | Self::Dino | Self::Upload)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AdvancedSort {
    #[default]
    Relevance,
    Newest,
}

impl AdvancedSort {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Relevance => "relevance",
            Self::Newest => "newest",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "newest" | "latest" | "id" => Self::Newest,
            _ => Self::Relevance,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ResultKind {
    Posts,
    Images,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VectorTier {
    /// Metadata-only query (All / Title / Author / Tag).
    None,
    /// Uses stored DINOv3 image IDs (`dino:`), no CLIP or uploads.
    EmbedId,
    /// Uses CLIP text inference (`clip:`), no uploads.
    Clip,
    /// Uses uploaded image inference (`upload:`), with or without CLIP/DINO.
    ImageUpload,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum QueryExpr {
    Term {
        field: SearchField,
        value: String,
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        threshold: Option<f32>,
    },
    Not(Box<QueryExpr>),
    And(Vec<QueryExpr>),
    Or(Vec<QueryExpr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub message: String,
    pub position: Option<usize>,
}

impl QueryError {
    fn new(message: impl Into<String>, position: Option<usize>) -> Self {
        Self {
            message: message.into(),
            position,
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(pos) => write!(f, "{} (at char {})", self.message, pos + 1),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for QueryError {}

/// Single CLIP text condition with optional per-leaf similarity threshold.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClipClause {
    pub text: String,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub threshold: Option<f32>,
}

/// Single stored DINOv3 image ID condition with optional per-leaf similarity threshold.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DinoClause {
    pub image_id: i64,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub threshold: Option<f32>,
}

/// Single uploaded-image slot condition with optional per-leaf similarity threshold.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UploadClause {
    pub slot: usize,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub threshold: Option<f32>,
}

/// Discriminated target for an independent vector leaf clause.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VectorTarget {
    Clip(String),
    Dino(i64),
    Upload(usize),
}

/// Independent vector leaf condition preserved in declared AST order so the
/// search engine evaluates EVERY positive and negated vector leaf against its
/// own embedding and cutoff (zero cross-model weighting or centroid averaging).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VectorClause {
    pub positive: bool,
    pub target: VectorTarget,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub threshold: Option<f32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueryPlan {
    pub result_kind: ResultKind,
    pub tier: VectorTier,
    /// Pure metadata boolean expression (`All`, `Title`, `Author`, `Tag` with optional per-leaf thresholds).
    pub meta_filter: Option<QueryExpr>,
    /// Positive tag queries collected from `meta_filter` (for relevance scoring).
    pub positive_tags: Vec<String>,
    /// All vector leaf conditions in exact declared left-to-right AST order.
    pub vector_clauses: Vec<VectorClause>,
    pub clip_pos: Vec<ClipClause>,
    pub clip_neg: Vec<ClipClause>,
    pub dino_pos: Vec<DinoClause>,
    pub dino_neg: Vec<DinoClause>,
    pub upload_pos: Vec<UploadClause>,
    pub upload_neg: Vec<UploadClause>,
}

impl QueryPlan {
    pub fn has_clip(&self) -> bool {
        !self.clip_pos.is_empty() || !self.clip_neg.is_empty()
    }

    pub fn has_dino(&self) -> bool {
        !self.dino_pos.is_empty()
            || !self.dino_neg.is_empty()
            || !self.upload_pos.is_empty()
            || !self.upload_neg.is_empty()
    }

    pub fn has_vectors(&self) -> bool {
        !self.vector_clauses.is_empty()
    }

    /// Returns the first declared positive vector leaf, used as the deterministic
    /// primary ranking vector when multiple vector conditions are present.
    pub fn primary_positive_vector(&self) -> Option<&VectorClause> {
        self.vector_clauses.iter().find(|c| c.positive)
    }
}

impl QueryExpr {
    pub fn has_image_level_clause(&self) -> bool {
        match self {
            Self::Term { field, .. } => field.is_image_level(),
            Self::Not(inner) => inner.has_image_level_clause(),
            Self::And(items) | Self::Or(items) => items.iter().any(Self::has_image_level_clause),
        }
    }

    pub fn has_vector_clause(&self) -> bool {
        match self {
            Self::Term { field, .. } => field.is_vector(),
            Self::Not(inner) => inner.has_vector_clause(),
            Self::And(items) | Self::Or(items) => items.iter().any(Self::has_vector_clause),
        }
    }

    pub fn result_kind(&self) -> ResultKind {
        if self.has_image_level_clause() {
            ResultKind::Images
        } else {
            ResultKind::Posts
        }
    }

    pub fn format_query(&self) -> String {
        let mut out = String::new();
        self.fmt_into(&mut out, 0);
        out
    }

    fn fmt_into(&self, out: &mut String, parent_prec: u8) {
        match self {
            Self::Term {
                field,
                value,
                threshold,
            } => {
                out.push_str(field.as_prefix());
                out.push(':');
                format_value(value, out);
                if let Some(score) = threshold {
                    out.push_str(">=");
                    out.push_str(&format_threshold_hundredths(*score));
                }
            }
            Self::Not(inner) => {
                let wrap = parent_prec > 3;
                if wrap {
                    out.push('(');
                }
                out.push_str("NOT ");
                let need_inner = matches!(inner.as_ref(), Self::And(_) | Self::Or(_));
                if need_inner {
                    out.push('(');
                    inner.fmt_into(out, 0);
                    out.push(')');
                } else {
                    inner.fmt_into(out, 3);
                }
                if wrap {
                    out.push(')');
                }
            }
            Self::And(items) => {
                let wrap = parent_prec > 2;
                if wrap {
                    out.push('(');
                }
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(" AND ");
                    }
                    item.fmt_into(out, 2);
                }
                if wrap {
                    out.push(')');
                }
            }
            Self::Or(items) => {
                let wrap = parent_prec > 1;
                if wrap {
                    out.push('(');
                }
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(" OR ");
                    }
                    item.fmt_into(out, 1);
                }
                if wrap {
                    out.push(')');
                }
            }
        }
    }

    /// Analyze, validate, and split the AST into a metadata filter + independent vector clauses.
    pub fn compile_plan(&self) -> Result<QueryPlan, QueryError> {
        let mut term_count = 0usize;
        check_limits(self, 1, &mut term_count)?;

        let mut vector_clauses = Vec::new();
        let mut clip_pos = Vec::new();
        let mut clip_neg = Vec::new();
        let mut dino_pos = Vec::new();
        let mut dino_neg = Vec::new();
        let mut upload_pos = Vec::new();
        let mut upload_neg = Vec::new();

        let meta_filter = extract_vectors(
            self,
            true,
            false,
            &mut vector_clauses,
            &mut clip_pos,
            &mut clip_neg,
            &mut dino_pos,
            &mut dino_neg,
            &mut upload_pos,
            &mut upload_neg,
        )?;

        if clip_pos.len() + clip_neg.len() > MAX_CLIP_TERMS {
            return Err(QueryError::new(
                format!("At most {MAX_CLIP_TERMS} CLIP clauses are allowed"),
                None,
            ));
        }
        if dino_pos.len() + dino_neg.len() > MAX_DINO_TERMS {
            return Err(QueryError::new(
                format!("At most {MAX_DINO_TERMS} Similar ID clauses are allowed"),
                None,
            ));
        }
        if upload_pos.len() + upload_neg.len() > MAX_UPLOAD_TERMS {
            return Err(QueryError::new(
                format!("At most {MAX_UPLOAD_TERMS} uploaded image clauses are allowed"),
                None,
            ));
        }

        let mut positive_tags = Vec::new();
        if let Some(meta) = &meta_filter {
            collect_positive_tags(meta, true, &mut positive_tags);
        }

        let has_upload = !upload_pos.is_empty() || !upload_neg.is_empty();
        let has_clip = !clip_pos.is_empty() || !clip_neg.is_empty();
        let has_dino = !dino_pos.is_empty() || !dino_neg.is_empty();

        let tier = if has_upload {
            VectorTier::ImageUpload
        } else if has_clip {
            VectorTier::Clip
        } else if has_dino {
            VectorTier::EmbedId
        } else {
            VectorTier::None
        };

        let result_kind = self.result_kind();

        if meta_filter.is_none() && tier == VectorTier::None {
            return Err(QueryError::new("Query is empty", None));
        }

        Ok(QueryPlan {
            result_kind,
            tier,
            meta_filter,
            positive_tags,
            vector_clauses,
            clip_pos,
            clip_neg,
            dino_pos,
            dino_neg,
            upload_pos,
            upload_neg,
        })
    }
}

fn format_value(value: &str, out: &mut String) {
    let needs_quote = value.is_empty()
        || value.starts_with('-')
        || value.eq_ignore_ascii_case("AND")
        || value.eq_ignore_ascii_case("OR")
        || value.eq_ignore_ascii_case("NOT")
        || value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '(' | ')' | '"' | '\\' | ':' | '>' | '<' | '='));
    if !needs_quote {
        out.push_str(value);
        return;
    }
    out.push('"');
    for ch in value.chars() {
        if matches!(ch, '"' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
}

fn check_limits(expr: &QueryExpr, depth: usize, terms: &mut usize) -> Result<(), QueryError> {
    if depth > MAX_DEPTH {
        return Err(QueryError::new(
            format!("Query nesting exceeds maximum depth of {MAX_DEPTH}"),
            None,
        ));
    }
    match expr {
        QueryExpr::Term {
            field,
            value,
            threshold,
        } => {
            if value.trim().is_empty() {
                return Err(QueryError::new("Search term cannot be empty", None));
            }
            if let Some(score) = threshold {
                if !field.supports_threshold() {
                    return Err(QueryError::new(
                        format!(
                            "Threshold '>=' is not supported on '{}:' terms",
                            field.as_prefix()
                        ),
                        None,
                    ));
                }
                validate_threshold_range(*score)
                    .map_err(|e| QueryError::new(e.message, None))?;
            }
            *terms += 1;
            if *terms > MAX_TERMS {
                return Err(QueryError::new(
                    format!("Query exceeds maximum of {MAX_TERMS} conditions"),
                    None,
                ));
            }
            Ok(())
        }
        QueryExpr::Not(inner) => check_limits(inner, depth + 1, terms),
        QueryExpr::And(items) | QueryExpr::Or(items) => {
            if items.is_empty() {
                return Err(QueryError::new("Empty boolean group", None));
            }
            for item in items {
                check_limits(item, depth + 1, terms)?;
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_vectors(
    expr: &QueryExpr,
    positive: bool,
    inside_or: bool,
    vector_clauses: &mut Vec<VectorClause>,
    clip_pos: &mut Vec<ClipClause>,
    clip_neg: &mut Vec<ClipClause>,
    dino_pos: &mut Vec<DinoClause>,
    dino_neg: &mut Vec<DinoClause>,
    upload_pos: &mut Vec<UploadClause>,
    upload_neg: &mut Vec<UploadClause>,
) -> Result<Option<QueryExpr>, QueryError> {
    match expr {
        QueryExpr::Term {
            field,
            value,
            threshold,
        } if field.is_vector() => {
            if inside_or {
                return Err(QueryError::new(
                    "CLIP and Similar Image clauses rank results and must be combined with AND or NOT (not OR)",
                    None,
                ));
            }
            let trimmed = value.trim();
            match field {
                SearchField::Clip => {
                    if trimmed.is_empty() {
                        return Err(QueryError::new("CLIP description cannot be empty", None));
                    }
                    let clause = ClipClause {
                        text: trimmed.to_string(),
                        threshold: *threshold,
                    };
                    vector_clauses.push(VectorClause {
                        positive,
                        target: VectorTarget::Clip(trimmed.to_string()),
                        threshold: *threshold,
                    });
                    if positive {
                        clip_pos.push(clause);
                    } else {
                        clip_neg.push(clause);
                    }
                }
                SearchField::Dino => {
                    let clean = trimmed.strip_prefix('#').unwrap_or(trimmed);
                    let id = clean.parse::<i64>().map_err(|_| {
                        QueryError::new(
                            format!("Invalid image ID '{trimmed}' for dino: (expected integer)"),
                            None,
                        )
                    })?;
                    if id <= 0 {
                        return Err(QueryError::new(
                            format!("Image ID '{trimmed}' must be a positive integer"),
                            None,
                        ));
                    }
                    let clause = DinoClause {
                        image_id: id,
                        threshold: *threshold,
                    };
                    vector_clauses.push(VectorClause {
                        positive,
                        target: VectorTarget::Dino(id),
                        threshold: *threshold,
                    });
                    if positive {
                        dino_pos.push(clause);
                    } else {
                        dino_neg.push(clause);
                    }
                }
                SearchField::Upload => {
                    let idx = trimmed.parse::<usize>().map_err(|_| {
                        QueryError::new(
                            format!("Invalid upload slot '{trimmed}' (expected integer index)"),
                            None,
                        )
                    })?;
                    if idx >= MAX_UPLOAD_TERMS {
                        return Err(QueryError::new(
                            format!("Upload slot '{idx}' exceeds limit ({MAX_UPLOAD_TERMS})"),
                            None,
                        ));
                    }
                    let clause = UploadClause {
                        slot: idx,
                        threshold: *threshold,
                    };
                    vector_clauses.push(VectorClause {
                        positive,
                        target: VectorTarget::Upload(idx),
                        threshold: *threshold,
                    });
                    if positive {
                        upload_pos.push(clause);
                    } else {
                        upload_neg.push(clause);
                    }
                }
                _ => unreachable!(),
            }
            Ok(None)
        }
        QueryExpr::Term { .. } => Ok(Some(expr.clone())),
        QueryExpr::Not(inner) => {
            // `NOT (a AND b)` where a vector sits inside a negated compound is ambiguous
            // unless the whole negated child is purely a vector term or purely metadata.
            if inner.has_vector_clause() && !matches!(inner.as_ref(), QueryExpr::Term { .. }) {
                return Err(QueryError::new(
                    "Negate CLIP or Similar Image clauses directly (e.g. NOT clip:\"...\"), not inside a negated group",
                    None,
                ));
            }
            let meta = extract_vectors(
                inner,
                !positive,
                inside_or,
                vector_clauses,
                clip_pos,
                clip_neg,
                dino_pos,
                dino_neg,
                upload_pos,
                upload_neg,
            )?;
            Ok(meta.map(|m| QueryExpr::Not(Box::new(m))))
        }
        QueryExpr::And(items) => {
            let mut kept = Vec::new();
            for item in items {
                if let Some(m) = extract_vectors(
                    item,
                    positive,
                    inside_or,
                    vector_clauses,
                    clip_pos,
                    clip_neg,
                    dino_pos,
                    dino_neg,
                    upload_pos,
                    upload_neg,
                )? {
                    kept.push(m);
                }
            }
            Ok(match kept.len() {
                0 => None,
                1 => Some(kept.pop().unwrap()),
                _ => Some(QueryExpr::And(kept)),
            })
        }
        QueryExpr::Or(items) => {
            let mut kept = Vec::new();
            for item in items {
                if let Some(m) = extract_vectors(
                    item,
                    positive,
                    true,
                    vector_clauses,
                    clip_pos,
                    clip_neg,
                    dino_pos,
                    dino_neg,
                    upload_pos,
                    upload_neg,
                )? {
                    kept.push(m);
                }
            }
            Ok(match kept.len() {
                0 => None,
                1 => Some(kept.pop().unwrap()),
                _ => Some(QueryExpr::Or(kept)),
            })
        }
    }
}

fn collect_positive_tags(expr: &QueryExpr, positive: bool, out: &mut Vec<String>) {
    match expr {
        QueryExpr::Term {
            field: SearchField::Tag,
            value,
            ..
        } if positive => {
            if !out.iter().any(|t| t.eq_ignore_ascii_case(value)) {
                out.push(value.clone());
            }
        }
        QueryExpr::Not(inner) => collect_positive_tags(inner, !positive, out),
        QueryExpr::And(items) | QueryExpr::Or(items) => {
            for item in items {
                collect_positive_tags(item, positive, out);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Lexer & Recursive-Descent Parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Minus,
    Gte,
    Word(String),
    Quoted(String),
    Field(SearchField),
    InList {
        field: SearchField,
        negated: bool,
        values: Vec<String>,
    },
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    pos: usize,
}

fn is_gte_at(chars: &[(usize, char)], i: usize) -> bool {
    i + 1 < chars.len() && chars[i].1 == '>' && chars[i + 1].1 == '='
}

fn skip_ws(chars: &[(usize, char)], i: &mut usize) {
    while *i < chars.len() && chars[*i].1.is_whitespace() {
        *i += 1;
    }
}

fn parse_quoted_string(chars: &[(usize, char)], i: &mut usize) -> Result<String, QueryError> {
    let start = chars[*i].0;
    *i += 1;
    let mut val = String::new();
    let mut closed = false;
    while *i < chars.len() {
        let (_, c) = chars[*i];
        if c == '\\' {
            if *i + 1 >= chars.len() {
                return Err(QueryError::new(
                    "Unterminated escape sequence in quoted string",
                    Some(chars[*i].0),
                ));
            }
            val.push(chars[*i + 1].1);
            *i += 2;
        } else if c == '"' {
            closed = true;
            *i += 1;
            break;
        } else {
            val.push(c);
            *i += 1;
        }
    }
    if !closed {
        return Err(QueryError::new("Unterminated quoted string", Some(start)));
    }
    Ok(val)
}

fn read_alpha_keyword(chars: &[(usize, char)], i: &mut usize) -> String {
    let mut out = String::new();
    while *i < chars.len() {
        let (_, c) = chars[*i];
        if c.is_whitespace() || matches!(c, '(' | ')' | '"' | ',' | ':') {
            break;
        }
        out.push(c);
        *i += 1;
    }
    out
}

/// Look ahead after a bare field word for `[NOT] IN (` (case-insensitive).
/// Returns `Some((negated, lparen_index))` if matched, without mutating caller state.
fn peek_in_operator(chars: &[(usize, char)], i: usize) -> Option<(bool, usize)> {
    let mut j = i;
    skip_ws(chars, &mut j);
    if j >= chars.len() {
        return None;
    }
    let w1 = read_alpha_keyword(chars, &mut j);
    if w1.eq_ignore_ascii_case("IN") {
        skip_ws(chars, &mut j);
        if j < chars.len() && chars[j].1 == '(' {
            return Some((false, j));
        }
        return None;
    }
    if w1.eq_ignore_ascii_case("NOT") {
        skip_ws(chars, &mut j);
        if j >= chars.len() {
            return None;
        }
        let w2 = read_alpha_keyword(chars, &mut j);
        if w2.eq_ignore_ascii_case("IN") {
            skip_ws(chars, &mut j);
            if j < chars.len() && chars[j].1 == '(' {
                return Some((true, j));
            }
        }
    }
    None
}

fn parse_in_list_items(
    chars: &[(usize, char)],
    i: &mut usize,
    field: SearchField,
    negated: bool,
) -> Result<Vec<String>, QueryError> {
    let lparen_pos = chars[*i].0;
    *i += 1; // consume '('

    let mut values = Vec::new();
    let mut expect_item_after_comma = false;
    let mut closed = false;

    while *i < chars.len() {
        skip_ws(chars, i);
        if *i >= chars.len() {
            break;
        }
        let (item_pos, ch) = chars[*i];
        if ch == ')' {
            if expect_item_after_comma {
                return Err(QueryError::new(
                    "Expected a value after ',' in IN (...) list",
                    Some(item_pos),
                ));
            }
            *i += 1;
            closed = true;
            break;
        }
        if ch == ',' {
            if values.is_empty() || expect_item_after_comma {
                return Err(QueryError::new(
                    "Unexpected ',' in IN (...) list",
                    Some(item_pos),
                ));
            }
            expect_item_after_comma = true;
            *i += 1;
            continue;
        }
        if ch == '(' {
            return Err(QueryError::new(
                "Unexpected '(' inside IN (...) list; quote values containing parentheses",
                Some(item_pos),
            ));
        }
        if is_gte_at(chars, *i) {
            return Err(QueryError::new(
                "Threshold '>=' must appear after ')', not inside IN (...) list",
                Some(item_pos),
            ));
        }

        let raw = if ch == '"' {
            let quoted = parse_quoted_string(chars, i)?;
            if *i < chars.len()
                && !chars[*i].1.is_whitespace()
                && !matches!(chars[*i].1, ',' | ')')
            {
                return Err(QueryError::new(
                    format!(
                        "Unexpected trailing characters after quoted value in '{} IN (...)'",
                        field.as_prefix()
                    ),
                    Some(chars[*i].0),
                ));
            }
            quoted
        } else {
            let mut word = String::new();
            while *i < chars.len() {
                if is_gte_at(chars, *i) {
                    return Err(QueryError::new(
                        "Threshold '>=' must appear after ')', not inside IN (...) list",
                        Some(chars[*i].0),
                    ));
                }
                let (_, c) = chars[*i];
                if c.is_whitespace() || matches!(c, ',' | '(' | ')' | '"') {
                    break;
                }
                word.push(c);
                *i += 1;
            }
            if *i < chars.len() && chars[*i].1 == '"' {
                return Err(QueryError::new(
                    format!(
                        "Unexpected '\"' inside unquoted value in '{} IN (...)'",
                        field.as_prefix()
                    ),
                    Some(chars[*i].0),
                ));
            }
            if *i < chars.len() && chars[*i].1 == '(' {
                return Err(QueryError::new(
                    "Unexpected '(' inside IN (...) list; quote values containing parentheses",
                    Some(chars[*i].0),
                ));
            }
            word
        };

        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            return Err(QueryError::new(
                format!("Value in '{} IN (...)' cannot be empty", field.as_prefix()),
                Some(item_pos),
            ));
        }
        values.push(trimmed);
        expect_item_after_comma = false;
    }

    if !closed {
        return Err(QueryError::new(
            "Unclosed '(' in IN (...) list",
            Some(lparen_pos),
        ));
    }
    if values.is_empty() {
        return Err(QueryError::new(
            format!(
                "Empty list in '{} {}IN ()' is not allowed",
                field.as_prefix(),
                if negated { "NOT " } else { "" }
            ),
            Some(lparen_pos),
        ));
    }

    Ok(values)
}

fn tokenize(input: &str) -> Result<Vec<Token>, QueryError> {
    if input.len() > MAX_QUERY_LEN {
        return Err(QueryError::new(
            format!("Query exceeds maximum length of {MAX_QUERY_LEN} bytes"),
            None,
        ));
    }

    let chars: Vec<(usize, char)> = input.chars().enumerate().collect();
    let mut i = 0usize;
    let mut tokens = Vec::new();

    while i < chars.len() {
        let (char_pos, ch) = chars[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        if is_gte_at(&chars, i) {
            tokens.push(Token {
                kind: TokenKind::Gte,
                pos: char_pos,
            });
            i += 2;
            continue;
        }
        match ch {
            '(' => {
                tokens.push(Token {
                    kind: TokenKind::LParen,
                    pos: char_pos,
                });
                i += 1;
            }
            ')' => {
                tokens.push(Token {
                    kind: TokenKind::RParen,
                    pos: char_pos,
                });
                i += 1;
            }
            '-' => {
                // After a field prefix (`dino:-5`, `tag:-foo`) or `>=` (`tag:maid >= -0.5`),
                // lex `-...` as a word value so field/threshold validators run directly.
                let after_value_expecting = matches!(
                    tokens.last().map(|t| &t.kind),
                    Some(TokenKind::Field(_) | TokenKind::Gte)
                );
                if i + 1 < chars.len() && !chars[i + 1].1.is_whitespace() {
                    if after_value_expecting {
                        let start = char_pos;
                        let mut word = String::new();
                        while i < chars.len() {
                            if is_gte_at(&chars, i) {
                                break;
                            }
                            let (_, c) = chars[i];
                            if c.is_whitespace() || matches!(c, '(' | ')' | '"') {
                                break;
                            }
                            word.push(c);
                            i += 1;
                        }
                        tokens.push(Token {
                            kind: TokenKind::Word(word),
                            pos: start,
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::Minus,
                            pos: char_pos,
                        });
                        i += 1;
                    }
                } else {
                    return Err(QueryError::new("Expected a term after '-'", Some(char_pos)));
                }
            }
            '"' => {
                let start = char_pos;
                let val = parse_quoted_string(&chars, &mut i)?;
                tokens.push(Token {
                    kind: TokenKind::Quoted(val),
                    pos: start,
                });
            }
            _ => {
                let start = char_pos;
                let mut word = String::new();
                let mut field_hit = None;
                let after_value_expecting = matches!(
                    tokens.last().map(|t| &t.kind),
                    Some(TokenKind::Field(_) | TokenKind::Gte)
                );
                while i < chars.len() {
                    if is_gte_at(&chars, i) {
                        break;
                    }
                    let (_, c) = chars[i];
                    if c.is_whitespace() || matches!(c, '(' | ')' | '"') {
                        break;
                    }
                    if c == ':'
                        && !after_value_expecting
                        && field_hit.is_none()
                        && let Some(field) = SearchField::parse_prefix(&word)
                    {
                        field_hit = Some(field);
                        i += 1;
                        break;
                    }
                    word.push(c);
                    i += 1;
                }
                if let Some(field) = field_hit {
                    tokens.push(Token {
                        kind: TokenKind::Field(field),
                        pos: start,
                    });
                } else if after_value_expecting {
                    tokens.push(Token {
                        kind: TokenKind::Word(word),
                        pos: start,
                    });
                } else {
                    let lower = word.to_ascii_lowercase();
                    if let Some((negated, lparen_idx)) = peek_in_operator(&chars, i) {
                        match lower.as_str() {
                            "tag" => {
                                i = lparen_idx;
                                let values =
                                    parse_in_list_items(&chars, &mut i, SearchField::Tag, negated)?;
                                tokens.push(Token {
                                    kind: TokenKind::InList {
                                        field: SearchField::Tag,
                                        negated,
                                        values,
                                    },
                                    pos: start,
                                });
                                continue;
                            }
                            "author" => {
                                i = lparen_idx;
                                let values = parse_in_list_items(
                                    &chars,
                                    &mut i,
                                    SearchField::Author,
                                    negated,
                                )?;
                                tokens.push(Token {
                                    kind: TokenKind::InList {
                                        field: SearchField::Author,
                                        negated,
                                        values,
                                    },
                                    pos: start,
                                });
                                continue;
                            }
                            "post_tag" | "title" | "all" | "clip" | "dino" | "upload" => {
                                return Err(QueryError::new(
                                    format!(
                                        "Operator 'IN (...)' is not supported on '{lower}' (supported fields: tag, author)"
                                    ),
                                    Some(start),
                                ));
                            }
                            _ => {}
                        }
                    }

                    let kind = match word.to_ascii_uppercase().as_str() {
                        "AND" => TokenKind::And,
                        "OR" => TokenKind::Or,
                        "NOT" => TokenKind::Not,
                        _ => TokenKind::Word(word),
                    };
                    tokens.push(Token { kind, pos: start });
                }
            }
        }
    }

    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn parse_or(&mut self, depth: usize) -> Result<QueryExpr, QueryError> {
        if depth > MAX_DEPTH {
            return Err(QueryError::new(
                format!("Query nesting exceeds maximum depth of {MAX_DEPTH}"),
                self.peek().map(|t| t.pos),
            ));
        }
        let mut items = vec![self.parse_and(depth)?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Or)) {
            self.next();
            items.push(self.parse_and(depth)?);
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap()
        } else {
            QueryExpr::Or(items)
        })
    }

    fn parse_and(&mut self, depth: usize) -> Result<QueryExpr, QueryError> {
        let mut items = vec![self.parse_not(depth)?];
        loop {
            match self.peek().map(|t| &t.kind) {
                Some(TokenKind::And) => {
                    self.next();
                    items.push(self.parse_not(depth)?);
                }
                // WoS infix NOT (`tag:maid NOT tag:monochrome` == `tag:maid AND NOT tag:monochrome`)
                // and implicit adjacency (`tag:maid author:foo` == `tag:maid AND author:foo`).
                Some(
                    TokenKind::Not
                    | TokenKind::Minus
                    | TokenKind::LParen
                    | TokenKind::Field(_)
                    | TokenKind::InList { .. }
                    | TokenKind::Word(_)
                    | TokenKind::Quoted(_),
                ) => {
                    items.push(self.parse_not(depth)?);
                }
                _ => break,
            }
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap()
        } else {
            QueryExpr::And(items)
        })
    }

    fn parse_not(&mut self, depth: usize) -> Result<QueryExpr, QueryError> {
        if depth > MAX_DEPTH {
            return Err(QueryError::new(
                format!("Query nesting exceeds maximum depth of {MAX_DEPTH}"),
                self.peek().map(|t| t.pos),
            ));
        }
        let mut neg_count = 0usize;
        while matches!(
            self.peek().map(|t| &t.kind),
            Some(TokenKind::Not | TokenKind::Minus)
        ) {
            if depth + neg_count >= MAX_DEPTH {
                return Err(QueryError::new(
                    format!("Query nesting exceeds maximum depth of {MAX_DEPTH}"),
                    self.peek().map(|t| t.pos),
                ));
            }
            self.next();
            neg_count += 1;
        }
        let mut expr = self.parse_primary(depth + neg_count)?;
        for _ in 0..neg_count {
            expr = QueryExpr::Not(Box::new(expr));
        }
        Ok(expr)
    }

    fn parse_optional_threshold(&mut self, field: SearchField) -> Result<Option<f32>, QueryError> {
        let Some(Token {
            kind: TokenKind::Gte,
            pos: gte_pos,
        }) = self.peek().cloned()
        else {
            return Ok(None);
        };
        if !field.supports_threshold() {
            return Err(QueryError::new(
                format!(
                    "Threshold '>=' is only supported on clip:, dino:, upload:, and tag: terms (not '{}:')",
                    field.as_prefix()
                ),
                Some(gte_pos),
            ));
        }
        self.next(); // consume `>=`

        let Some(score_tok) = self.next() else {
            return Err(QueryError::new(
                "Expected numeric threshold in 0.01..=1.00 after '>='",
                Some(gte_pos),
            ));
        };
        let raw_score = match score_tok.kind {
            TokenKind::Word(w) => w,
            _ => {
                return Err(QueryError::new(
                    "Expected numeric threshold in 0.01..=1.00 after '>='",
                    Some(score_tok.pos),
                ));
            }
        };
        let parsed = parse_threshold_hundredths(&raw_score)
            .map_err(|e| QueryError::new(e.message, Some(score_tok.pos)))?;

        if let Some(Token {
            kind: TokenKind::Gte,
            pos: dup_pos,
        }) = self.peek()
        {
            return Err(QueryError::new(
                "Duplicate '>=' threshold on a single condition",
                Some(*dup_pos),
            ));
        }
        Ok(Some(parsed))
    }

    fn parse_primary(&mut self, depth: usize) -> Result<QueryExpr, QueryError> {
        let Some(tok) = self.next() else {
            return Err(QueryError::new("Unexpected end of query", None));
        };
        match tok.kind {
            TokenKind::LParen => {
                let inner = self.parse_or(depth + 1)?;
                match self.next() {
                    Some(Token {
                        kind: TokenKind::RParen,
                        ..
                    }) => Ok(inner),
                    Some(other) => Err(QueryError::new("Expected closing ')'", Some(other.pos))),
                    None => Err(QueryError::new("Unclosed '(' in query", Some(tok.pos))),
                }
            }
            TokenKind::Field(field) => {
                let Some(val_tok) = self.next() else {
                    return Err(QueryError::new(
                        format!("Expected a value after '{}:'", field.as_prefix()),
                        Some(tok.pos),
                    ));
                };
                let value = match val_tok.kind {
                    TokenKind::Word(w) | TokenKind::Quoted(w) => w,
                    _ => {
                        return Err(QueryError::new(
                            format!("Expected a value after '{}:'", field.as_prefix()),
                            Some(val_tok.pos),
                        ));
                    }
                };
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    return Err(QueryError::new(
                        format!("Value after '{}:' cannot be empty", field.as_prefix()),
                        Some(val_tok.pos),
                    ));
                }
                let threshold = self.parse_optional_threshold(field)?;
                Ok(QueryExpr::Term {
                    field,
                    value: trimmed,
                    threshold,
                })
            }
            TokenKind::InList {
                field,
                negated,
                values,
            } => {
                let threshold = self.parse_optional_threshold(field)?;
                let mut terms: Vec<QueryExpr> = values
                    .into_iter()
                    .map(|value| QueryExpr::Term {
                        field,
                        value,
                        threshold,
                    })
                    .collect();
                let mut expr = if terms.len() == 1 {
                    terms.pop().unwrap()
                } else {
                    QueryExpr::Or(terms)
                };
                if negated {
                    expr = QueryExpr::Not(Box::new(expr));
                }
                Ok(expr)
            }
            TokenKind::Word(w) | TokenKind::Quoted(w) => {
                let trimmed = w.trim().to_string();
                if trimmed.is_empty() {
                    return Err(QueryError::new(
                        "Search term cannot be empty",
                        Some(tok.pos),
                    ));
                }
                // Bare terms map to `SearchField::All`, which rejects `>=` thresholds.
                let threshold = self.parse_optional_threshold(SearchField::All)?;
                Ok(QueryExpr::Term {
                    field: SearchField::All,
                    value: trimmed,
                    threshold,
                })
            }
            TokenKind::Gte => Err(QueryError::new(
                "Unexpected '>=' (thresholds apply to clip:, dino:, upload:, and tag: terms)",
                Some(tok.pos),
            )),
            TokenKind::RParen => Err(QueryError::new("Unexpected ')'", Some(tok.pos))),
            TokenKind::And => Err(QueryError::new("Unexpected 'AND'", Some(tok.pos))),
            TokenKind::Or => Err(QueryError::new("Unexpected 'OR'", Some(tok.pos))),
            TokenKind::Not | TokenKind::Minus => unreachable!(),
        }
    }
}

/// Parse a Web-of-Science-style boolean query string into a `QueryExpr` AST.
pub fn parse_query(input: &str) -> Result<QueryExpr, QueryError> {
    if input.len() > MAX_QUERY_LEN {
        return Err(QueryError::new(
            format!("Query exceeds maximum length of {MAX_QUERY_LEN} bytes"),
            None,
        ));
    }
    if input.trim().is_empty() {
        return Err(QueryError::new("Query is empty", None));
    }
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(QueryError::new("Query is empty", None));
    }
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.parse_or(1)?;
    if let Some(extra) = parser.peek() {
        return Err(QueryError::new(
            "Unexpected token in query",
            Some(extra.pos),
        ));
    }
    Ok(expr)
}

/// Parse and immediately compile & validate a query string into a `QueryPlan`.
pub fn parse_and_compile(input: &str) -> Result<(QueryExpr, QueryPlan), QueryError> {
    let expr = parse_query(input)?;
    let plan = expr.compile_plan()?;
    Ok((expr, plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wos_boolean_precedence_and_roundtrips() {
        let q = r#"(tag:"black hair" OR tag:maid>=0.45) AND author:渡久山 NOT tag:monochrome"#;
        let expr = parse_query(q).expect("valid query");
        let plan = expr.compile_plan().expect("valid plan");
        assert_eq!(plan.result_kind, ResultKind::Images);
        assert_eq!(plan.tier, VectorTier::None);
        assert_eq!(plan.positive_tags, vec!["black hair", "maid"]);

        let formatted = expr.format_query();
        let reparsed = parse_query(&formatted).expect("roundtrip parse");
        assert_eq!(expr, reparsed);
    }

    #[test]
    fn parses_per_condition_thresholds_across_all_four_whitespace_forms() {
        let cases = [
            (r#"clip:"sunset">=0.25"#, SearchField::Clip, "sunset", 0.25),
            (r#"clip:"sunset">= 0.25"#, SearchField::Clip, "sunset", 0.25),
            (r#"clip:"sunset" >=0.25"#, SearchField::Clip, "sunset", 0.25),
            (r#"clip:"sunset" >= 0.25"#, SearchField::Clip, "sunset", 0.25),
            ("tag:maid>=0.45", SearchField::Tag, "maid", 0.45),
            ("tag:maid>= 0.45", SearchField::Tag, "maid", 0.45),
            ("tag:maid >=0.45", SearchField::Tag, "maid", 0.45),
            ("tag:maid >= 0.45", SearchField::Tag, "maid", 0.45),
            ("dino:42>=0.70", SearchField::Dino, "42", 0.70),
            ("dino:42 >= 0.70", SearchField::Dino, "42", 0.70),
            ("upload:0>=0.65", SearchField::Upload, "0", 0.65),
            ("upload:0 >= 0.65", SearchField::Upload, "0", 0.65),
            (r#"tag:":>=" >= 0.50"#, SearchField::Tag, ":>=", 0.50),
            (
                r#"clip:"score >= 0.9" >= 0.30"#,
                SearchField::Clip,
                "score >= 0.9",
                0.30,
            ),
        ];

        for (raw, field, val, expected_thr) in cases {
            let expr = parse_query(raw).unwrap_or_else(|e| panic!("failed to parse {raw}: {e}"));
            assert_eq!(
                expr,
                QueryExpr::Term {
                    field,
                    value: val.to_string(),
                    threshold: Some(expected_thr),
                },
                "mismatch for {raw}"
            );
            let reparsed = parse_query(&expr.format_query()).expect("roundtrip");
            assert_eq!(expr, reparsed);
        }

        // Quoted `>=` without trailing threshold keeps `threshold = None`.
        assert_eq!(
            parse_query(r#"clip:"a >= b""#).unwrap(),
            QueryExpr::Term {
                field: SearchField::Clip,
                value: "a >= b".into(),
                threshold: None,
            }
        );
    }

    #[test]
    fn strictly_validates_hundredths_thresholds_and_rejects_invalid_fields() {
        // Valid hundredths boundaries
        assert_eq!(parse_threshold_hundredths("0.01").unwrap(), 0.01);
        assert_eq!(parse_threshold_hundredths(".01").unwrap(), 0.01);
        assert_eq!(parse_threshold_hundredths("0.5").unwrap(), 0.50);
        assert_eq!(parse_threshold_hundredths("0.45").unwrap(), 0.45);
        assert_eq!(parse_threshold_hundredths("1").unwrap(), 1.00);
        assert_eq!(parse_threshold_hundredths("1.0").unwrap(), 1.00);
        assert_eq!(parse_threshold_hundredths("1.00").unwrap(), 1.00);

        // Legacy range helper accepts >2 decimals in (0, 1] while rejecting 0, >1, non-finite
        assert_eq!(validate_threshold_range(0.005).unwrap(), 0.005);
        assert!(validate_threshold_range(0.0).is_err());
        assert!(validate_threshold_range(1.01).is_err());
        assert!(validate_threshold_range(f32::NAN).is_err());
        assert!(validate_threshold_range(f32::INFINITY).is_err());

        // Strict hundredths rejections
        for bad in [
            "", "0", "0.0", "0.00", "0.001", "0.005", "0.456", "0.500", "1.01", "1.000", "2",
            "-0.5", "+0.5", "NaN", "inf", "-inf", "1e-1", "0.", "1.", ".", "00.5", "0.5abc",
            " 0.5", "0.5 ",
        ] {
            assert!(
                parse_threshold_hundredths(bad).is_err(),
                "must reject invalid hundredths threshold: {bad:?}"
            );
        }

        // Reject invalid thresholds inside queries
        for bad_q in [
            "tag:maid>=0",
            "tag:maid>=0.00",
            "tag:maid>=0.005",
            "tag:maid>=0.456",
            "tag:maid>=1.01",
            "tag:maid>=NaN",
            "tag:maid>=inf",
            "tag:maid>=-0.5",
            "tag:maid >= -0.5",
            "tag:maid>=0.5abc",
            "tag:maid>=",
            "tag:maid >= ",
            r#"tag:maid >= "0.5""#,
            "tag:maid>=0.45>=0.50",
            "tag:maid >= 0.45 >= 0.50",
            "tag:>=0.5",
            ">= 0.5",
            // Non-threshold fields must reject `>=` with OR without whitespace!
            "title:cafe>=0.5",
            "title:cafe >= 0.5",
            "author:bob>=0.5",
            "author:bob >= 0.5",
            "all:sunset>=0.5",
            "all:sunset >= 0.5",
            "sunset >= 0.5",
            "(tag:maid) >= 0.5",
        ] {
            assert!(
                parse_and_compile(bad_q).is_err(),
                "must reject query: {bad_q:?}"
            );
        }
    }

    #[test]
    fn post_only_queries_auto_switch_to_posts() {
        let (_, plan) =
            parse_and_compile(r#"author:"渡久山" AND (title:咖啡 OR title:女仆) NOT title:预告"#)
                .unwrap();
        assert_eq!(plan.result_kind, ResultKind::Posts);
        assert_eq!(plan.tier, VectorTier::None);
    }

    #[test]
    fn combines_metadata_and_independent_positive_negative_vectors_with_thresholds() {
        let (_, plan) = parse_and_compile(
            r#"tag:maid>=0.50 AND clip:"sunny cafe" >= 0.25 AND NOT clip:"dark room">=0.40 AND dino:2286979 >= 0.70 AND NOT dino:100>=0.60 AND upload:0 >= 0.65 AND NOT upload:1>=0.80"#,
        )
        .unwrap();
        assert_eq!(plan.result_kind, ResultKind::Images);
        assert_eq!(plan.tier, VectorTier::ImageUpload);
        assert_eq!(
            plan.clip_pos,
            vec![ClipClause {
                text: "sunny cafe".into(),
                threshold: Some(0.25),
            }]
        );
        assert_eq!(
            plan.clip_neg,
            vec![ClipClause {
                text: "dark room".into(),
                threshold: Some(0.40),
            }]
        );
        assert_eq!(
            plan.dino_pos,
            vec![DinoClause {
                image_id: 2286979,
                threshold: Some(0.70),
            }]
        );
        assert_eq!(
            plan.dino_neg,
            vec![DinoClause {
                image_id: 100,
                threshold: Some(0.60),
            }]
        );
        assert_eq!(
            plan.upload_pos,
            vec![UploadClause {
                slot: 0,
                threshold: Some(0.65),
            }]
        );
        assert_eq!(
            plan.upload_neg,
            vec![UploadClause {
                slot: 1,
                threshold: Some(0.80),
            }]
        );
        assert_eq!(plan.vector_clauses.len(), 6);
        assert_eq!(
            plan.primary_positive_vector(),
            Some(&VectorClause {
                positive: true,
                target: VectorTarget::Clip("sunny cafe".into()),
                threshold: Some(0.25),
            })
        );
        assert_eq!(
            plan.meta_filter,
            Some(QueryExpr::Term {
                field: SearchField::Tag,
                value: "maid".into(),
                threshold: Some(0.50),
            })
        );
    }

    #[test]
    fn upload_tier_takes_precedence_over_clip_and_dino() {
        let (_, plan) = parse_and_compile(r#"upload:0 AND clip:"beach" AND dino:42"#).unwrap();
        assert_eq!(plan.tier, VectorTier::ImageUpload);
        assert_eq!(
            plan.upload_pos,
            vec![UploadClause {
                slot: 0,
                threshold: None,
            }]
        );
    }

    #[test]
    fn rejects_vector_inside_or_and_invalid_dino_ids() {
        assert!(parse_and_compile(r#"clip:"sunset" OR tag:night"#).is_err());
        assert!(parse_and_compile(r#"dino:abc"#).is_err());
        assert!(parse_and_compile(r#"dino:0"#).is_err());
        assert!(parse_and_compile(r#"NOT (clip:"a" AND tag:b)"#).is_err());
    }

    #[test]
    fn supports_bare_terms_and_unary_minus() {
        let expr = parse_query(r#"星光 -预告"#).unwrap();
        assert_eq!(
            expr,
            QueryExpr::And(vec![
                QueryExpr::Term {
                    field: SearchField::All,
                    value: "星光".into(),
                    threshold: None,
                },
                QueryExpr::Not(Box::new(QueryExpr::Term {
                    field: SearchField::All,
                    value: "预告".into(),
                    threshold: None,
                })),
            ])
        );
    }

    #[test]
    fn rejects_deep_not_chains_and_reports_char_positions_for_cjk() {
        let deep = format!("{}a", "-".repeat(1999));
        let err = parse_query(&deep).unwrap_err();
        assert!(err.message.contains("maximum depth"));

        let cjk_err = parse_query("tag:女仆 )").unwrap_err();
        assert_eq!(cjk_err.position, Some(7));
    }

    #[test]
    fn enforces_max_query_len_before_trim_and_preserves_leading_whitespace_positions() {
        let padded_oversize = format!("{}a", " ".repeat(MAX_QUERY_LEN));
        let err = parse_query(&padded_oversize).unwrap_err();
        assert!(err.message.contains("maximum length"));

        let ws_only_oversize = " ".repeat(MAX_QUERY_LEN + 1);
        let ws_err = parse_query(&ws_only_oversize).unwrap_err();
        assert!(ws_err.message.contains("maximum length"));

        let pos_err = parse_query("   tag:女仆 )").unwrap_err();
        assert_eq!(pos_err.position, Some(10));
    }

    #[test]
    fn lexes_leading_minus_after_field_as_word_value() {
        let err = parse_and_compile("dino:-5").unwrap_err();
        assert!(
            err.message.contains("-5") && err.message.contains("positive integer"),
            "unexpected error for dino:-5: {}",
            err.message
        );

        let expr = parse_query("tag:-foo").unwrap();
        assert_eq!(
            expr,
            QueryExpr::Term {
                field: SearchField::Tag,
                value: "-foo".into(),
                threshold: None,
            }
        );
        let reparsed = parse_query(&expr.format_query()).unwrap();
        assert_eq!(expr, reparsed);
    }

    #[test]
    fn parses_in_and_not_in_multi_value_lists_with_thresholds_and_quotes() {
        // Comma-separated with threshold (all 4 whitespace combos) and case-insensitive operators
        let expected_tag_in = QueryExpr::Or(vec![
            QueryExpr::Term {
                field: SearchField::Tag,
                value: "maid".into(),
                threshold: Some(0.45),
            },
            QueryExpr::Term {
                field: SearchField::Tag,
                value: "apron".into(),
                threshold: Some(0.45),
            },
            QueryExpr::Term {
                field: SearchField::Tag,
                value: "long hair".into(),
                threshold: Some(0.45),
            },
        ]);
        for raw in [
            r#"tag IN (maid, apron, "long hair") >= 0.45"#,
            r#"tag IN (maid, apron, "long hair")>=0.45"#,
            r#"tag IN (maid, apron, "long hair")>= 0.45"#,
            r#"tag IN (maid, apron, "long hair") >=0.45"#,
            r#"TAG in(maid apron "long hair") >= 0.45"#,
            r#"Tag In (maid,apron "long hair") >= 0.45"#,
        ] {
            let parsed = parse_query(raw).unwrap_or_else(|e| panic!("failed {raw}: {e}"));
            assert_eq!(parsed, expected_tag_in, "mismatch for {raw}");
            let (_, plan) = parse_and_compile(raw).expect("valid plan");
            assert_eq!(plan.result_kind, ResultKind::Images);
            assert_eq!(plan.tier, VectorTier::None);
            assert_eq!(plan.positive_tags, vec!["maid", "apron", "long hair"]);
            // Roundtrip formatting
            assert_eq!(parse_query(&parsed.format_query()).unwrap(), parsed);
        }

        // `tag NOT IN (...) >= T`, `NOT tag IN (...) >= T`, and `-tag IN (...) >= T` desugar identically
        let expected_tag_not_in = QueryExpr::Not(Box::new(QueryExpr::Or(vec![
            QueryExpr::Term {
                field: SearchField::Tag,
                value: "safe".into(),
                threshold: Some(0.45),
            },
            QueryExpr::Term {
                field: SearchField::Tag,
                value: "general".into(),
                threshold: Some(0.45),
            },
        ])));
        for raw in [
            "tag NOT IN (safe, general) >= 0.45",
            "tag not in(safe general)>=0.45",
            "NOT tag IN (safe, general) >= 0.45",
            "-tag IN (safe, general) >= 0.45",
        ] {
            let parsed = parse_query(raw).unwrap_or_else(|e| panic!("failed {raw}: {e}"));
            assert_eq!(parsed, expected_tag_not_in, "mismatch for {raw}");
            let (_, plan) = parse_and_compile(raw).expect("valid plan");
            assert_eq!(plan.result_kind, ResultKind::Images);
            assert!(plan.positive_tags.is_empty());
        }

        // Single-element IN / NOT IN collapses cleanly without redundant single-item Or
        assert_eq!(
            parse_query("tag IN (maid) >= 0.50").unwrap(),
            QueryExpr::Term {
                field: SearchField::Tag,
                value: "maid".into(),
                threshold: Some(0.50),
            }
        );
        assert_eq!(
            parse_query("tag NOT IN (maid)").unwrap(),
            QueryExpr::Not(Box::new(QueryExpr::Term {
                field: SearchField::Tag,
                value: "maid".into(),
                threshold: None,
            }))
        );

        // Escaped quotes, commas inside quotes, parentheses inside quotes, Unicode authors
        let escaped = parse_query(r#"author NOT IN ("alice \"A\"", "渡久山", bob)"#).unwrap();
        assert_eq!(
            escaped,
            QueryExpr::Not(Box::new(QueryExpr::Or(vec![
                QueryExpr::Term {
                    field: SearchField::Author,
                    value: r#"alice "A""#.into(),
                    threshold: None,
                },
                QueryExpr::Term {
                    field: SearchField::Author,
                    value: "渡久山".into(),
                    threshold: None,
                },
                QueryExpr::Term {
                    field: SearchField::Author,
                    value: "bob".into(),
                    threshold: None,
                },
            ])))
        );
        let (_, author_plan) = parse_and_compile(r#"author IN ("渡久山", bob)"#).unwrap();
        assert_eq!(author_plan.result_kind, ResultKind::Posts);

        // Implicit AND adjacency and combination with vector clauses
        let (_, combined_plan) = parse_and_compile(
            r#"tag IN (maid, apron) >= 0.45 author NOT IN (alice, bob) AND clip:"sunny cafe" >= 0.25"#,
        )
        .expect("combined IN + vector plan");
        assert_eq!(combined_plan.result_kind, ResultKind::Images);
        assert_eq!(combined_plan.tier, VectorTier::Clip);
        assert_eq!(combined_plan.positive_tags, vec!["maid", "apron"]);

        // Bare word queries containing "tag" / "author" / "in" remain backwards compatible
        assert_eq!(
            parse_query("tag NOT alice").unwrap(),
            QueryExpr::And(vec![
                QueryExpr::Term {
                    field: SearchField::All,
                    value: "tag".into(),
                    threshold: None,
                },
                QueryExpr::Not(Box::new(QueryExpr::Term {
                    field: SearchField::All,
                    value: "alice".into(),
                    threshold: None,
                })),
            ])
        );
        assert!(parse_query("alice in (wonderland)").is_ok());
    }

    #[test]
    fn rejects_invalid_in_not_in_lists_thresholds_and_unsupported_fields() {
        for bad in [
            "tag IN ()",
            "tag IN (   )",
            "tag NOT IN ()",
            "author IN ()",
            "tag IN (,)",
            "tag IN (, maid)",
            "tag IN (maid,)",
            "tag IN (maid,,apron)",
            r#"tag IN ("")"#,
            r#"tag IN ("   ", maid)"#,
            "tag IN (maid, apron",
            "tag IN (maid >= 0.45)",
            "tag IN (maid>=0.45)",
            r#"tag IN ("maid"apron)"#,
            r#"tag IN (maid"apron")"#,
            "tag IN (eimi_(blue_archive))",
            "tag IN (maid, apron) >= 0.456",
            "tag IN (maid, apron) >= 0",
            "tag IN (maid, apron) >= 1.01",
            "tag IN (maid, apron) >= -0.5",
            "tag IN (maid, apron) >=",
            "tag IN (maid, apron) >= 0.45 >= 0.50",
            "(tag IN (maid, apron)) >= 0.45",
            // Thresholds rejected on author IN / NOT IN
            "author IN (alice, bob) >= 0.45",
            "author NOT IN (alice, bob) >= 0.45",
            // Unsupported fields for IN / NOT IN in search_types::query
            "dino IN (12, 34, 56)",
            "dino IN (12, 34) >= 0.70",
            "dino NOT IN (12, 34)",
            "post_tag IN (cosplay, maid)",
            r#"clip IN ("sunset", "beach")"#,
            "upload IN (0, 1)",
            "title IN (cafe, tea)",
            "all IN (cafe, tea)",
        ] {
            assert!(
                parse_and_compile(bad).is_err(),
                "must reject invalid IN/NOT IN query: {bad:?}"
            );
        }

        // MAX_TERMS (24) budget counts every element inside IN (...)
        let too_many = format!(
            "tag IN ({})",
            (0..=MAX_TERMS)
                .map(|i| format!("t{i}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(parse_and_compile(&too_many).is_err());

        let exact_max = format!(
            "tag IN ({})",
            (0..MAX_TERMS)
                .map(|i| format!("t{i}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(parse_and_compile(&exact_max).is_ok());
    }
}
