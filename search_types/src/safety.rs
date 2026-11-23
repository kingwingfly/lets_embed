//! Dedicated metadata-only Safety Rule parser, 3-valued logic (`TriBool`),
//! canonical WD-Tagger vocabulary validation, and catalog reference extraction.
//!
//! Grammar (strictly metadata-only, zero vector/fuzzy/regex operators):
//! - `tag:<exact_name>[>= <score>]` (score in `0.01..=1.00` hundredths on new writes)
//! - `post_tag:<exact_name>`
//! - `author:<exact_name>`
//! - `unclassified`
//! - Boolean operators `AND`, `OR`, `NOT`, unary `-`, and parentheses `(...)`

use std::{
    collections::BTreeSet,
    fmt,
    ops::{BitAnd, BitOr, Not},
};

use crate::{
    query::{format_threshold_hundredths, parse_threshold_hundredths, validate_threshold_range},
    wd_vocab::is_canonical_wd_tag,
};

pub const MAX_POLICIES_PER_SET: usize = 16;
pub const MAX_RULES_PER_POLICY: usize = MAX_POLICIES_PER_SET;
pub const MAX_TERMS_PER_POLICY: usize = 32;
pub const MAX_TERMS_PER_RULE: usize = MAX_TERMS_PER_POLICY;
pub const MAX_DEPTH: usize = 6;
pub const MAX_TOTAL_TERMS_PER_SET: usize = 128;
pub const MAX_TOTAL_TERMS_PER_POLICY: usize = MAX_TOTAL_TERMS_PER_SET;
pub const MAX_RULE_LEN: usize = 2048;

// ---------------------------------------------------------------------------
// 3-Valued Logic (Kleene Strong K3)
// ---------------------------------------------------------------------------

/// 3-valued truth value for Policy v3 evaluation over potentially incomplete
/// or unclassified image facts.
///
/// Algebra preserves:
/// - `!Unknown = Unknown`
/// - `True | Unknown = True`
/// - `False & Unknown = False`
/// - All other combinations involving `Unknown` yield `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TriBool {
    True,
    False,
    Unknown,
}

impl TriBool {
    #[inline]
    pub const fn from_bool(v: bool) -> Self {
        if v { Self::True } else { Self::False }
    }

    #[inline]
    pub const fn is_true(self) -> bool {
        matches!(self, Self::True)
    }

    #[inline]
    pub const fn is_false(self) -> bool {
        matches!(self, Self::False)
    }

    #[inline]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    #[inline]
    pub const fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    #[inline]
    pub const fn and(self, rhs: Self) -> Self {
        match (self, rhs) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }

    #[inline]
    pub const fn or(self, rhs: Self) -> Self {
        match (self, rhs) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }
}

impl From<bool> for TriBool {
    #[inline]
    fn from(v: bool) -> Self {
        Self::from_bool(v)
    }
}

impl Not for TriBool {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        TriBool::not(self)
    }
}

impl BitAnd for TriBool {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        TriBool::and(self, rhs)
    }
}

impl BitOr for TriBool {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        TriBool::or(self, rhs)
    }
}

// ---------------------------------------------------------------------------
// Safety AST & Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SafetyPredicate {
    /// Exact canonical WD-Tagger tag name with optional per-term score threshold.
    WdTag {
        name: String,
        #[cfg_attr(feature = "serde", serde(default))]
        min_score: Option<f32>,
    },
    /// Exact canonical post tag name (`tags.name`).
    PostTag(String),
    /// Exact canonical author name (`authors.name`).
    Author(String),
    /// Matches items whose classification is not completed (`images.status != 'completed'`).
    Unclassified,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SafetyExpr {
    Predicate(SafetyPredicate),
    Not(Box<SafetyExpr>),
    And(Vec<SafetyExpr>),
    Or(Vec<SafetyExpr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyRuleError {
    pub message: String,
    pub position: Option<usize>,
}

impl SafetyRuleError {
    pub fn new(message: impl Into<String>, position: Option<usize>) -> Self {
        Self {
            message: message.into(),
            position,
        }
    }
}

impl fmt::Display for SafetyRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(pos) => write!(f, "{} (at char {})", self.message, pos + 1),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for SafetyRuleError {}

impl SafetyExpr {
    /// Total number of leaf predicates in this rule.
    pub fn term_count(&self) -> usize {
        match self {
            Self::Predicate(_) => 1,
            Self::Not(inner) => inner.term_count(),
            Self::And(items) | Self::Or(items) => items.iter().map(Self::term_count).sum(),
        }
    }

    /// Maximum AST nesting depth (`Predicate` = 1).
    pub fn max_depth(&self) -> usize {
        match self {
            Self::Predicate(_) => 1,
            Self::Not(inner) => 1 + inner.max_depth(),
            Self::And(items) | Self::Or(items) => {
                1 + items.iter().map(Self::max_depth).max().unwrap_or(0)
            }
        }
    }

    /// Evaluates this expression using 3-valued Kleene logic (`TriBool`).
    pub fn eval_tribool(&self, eval_leaf: &impl Fn(&SafetyPredicate) -> TriBool) -> TriBool {
        match self {
            Self::Predicate(pred) => eval_leaf(pred),
            Self::Not(inner) => inner.eval_tribool(eval_leaf).not(),
            Self::And(items) => items
                .iter()
                .fold(TriBool::True, |acc, item| acc.and(item.eval_tribool(eval_leaf))),
            Self::Or(items) => items
                .iter()
                .fold(TriBool::False, |acc, item| acc.or(item.eval_tribool(eval_leaf))),
        }
    }

    /// Evaluates Policy v3's `match_expr AND NOT except_expr` in 3-valued logic.
    ///
    /// When `except_expr` is `None`, evaluates `match_expr` directly.
    /// When `except_expr` is `Some(ex)`, evaluates `match_val & !except_val`.
    pub fn eval_policy_match(
        match_expr: &Self,
        except_expr: Option<&Self>,
        eval_leaf: &impl Fn(&SafetyPredicate) -> TriBool,
    ) -> TriBool {
        let matched = match_expr.eval_tribool(eval_leaf);
        match except_expr {
            None => matched,
            Some(ex) => matched.and(ex.eval_tribool(eval_leaf).not()),
        }
    }

    /// Deduplicated, deterministically sorted canonical WD-Tagger tag names referenced by this rule.
    pub fn referenced_wd_tags(&self) -> Vec<String> {
        let mut out = BTreeSet::new();
        self.collect_wd_tags(&mut out);
        out.into_iter().collect()
    }

    /// Deduplicated, deterministically sorted canonical post tag names referenced by this rule.
    pub fn referenced_post_tags(&self) -> Vec<String> {
        let mut out = BTreeSet::new();
        self.collect_post_tags(&mut out);
        out.into_iter().collect()
    }

    /// Deduplicated, deterministically sorted canonical author names referenced by this rule.
    pub fn referenced_authors(&self) -> Vec<String> {
        let mut out = BTreeSet::new();
        self.collect_authors(&mut out);
        out.into_iter().collect()
    }

    /// Returns `true` if this rule explicitly references `unclassified`.
    pub fn references_unclassified(&self) -> bool {
        match self {
            Self::Predicate(SafetyPredicate::Unclassified) => true,
            Self::Predicate(_) => false,
            Self::Not(inner) => inner.references_unclassified(),
            Self::And(items) | Self::Or(items) => items.iter().any(Self::references_unclassified),
        }
    }

    fn collect_wd_tags(&self, out: &mut BTreeSet<String>) {
        match self {
            Self::Predicate(SafetyPredicate::WdTag { name, .. }) => {
                out.insert(name.clone());
            }
            Self::Predicate(_) => {}
            Self::Not(inner) => inner.collect_wd_tags(out),
            Self::And(items) | Self::Or(items) => {
                for item in items {
                    item.collect_wd_tags(out);
                }
            }
        }
    }

    fn collect_post_tags(&self, out: &mut BTreeSet<String>) {
        match self {
            Self::Predicate(SafetyPredicate::PostTag(name)) => {
                out.insert(name.clone());
            }
            Self::Predicate(_) => {}
            Self::Not(inner) => inner.collect_post_tags(out),
            Self::And(items) | Self::Or(items) => {
                for item in items {
                    item.collect_post_tags(out);
                }
            }
        }
    }

    fn collect_authors(&self, out: &mut BTreeSet<String>) {
        match self {
            Self::Predicate(SafetyPredicate::Author(name)) => {
                out.insert(name.clone());
            }
            Self::Predicate(_) => {}
            Self::Not(inner) => inner.collect_authors(out),
            Self::And(items) | Self::Or(items) => {
                for item in items {
                    item.collect_authors(out);
                }
            }
        }
    }

    /// Formats the AST back into canonical safety-rule syntax.
    pub fn format_rule(&self) -> String {
        let mut out = String::new();
        self.fmt_into(&mut out, 0);
        out
    }

    fn fmt_into(&self, out: &mut String, parent_prec: u8) {
        match self {
            Self::Predicate(pred) => match pred {
                SafetyPredicate::WdTag { name, min_score } => {
                    out.push_str("tag:");
                    format_exact_name(name, out);
                    if let Some(score) = min_score {
                        out.push_str(">=");
                        out.push_str(&format_threshold_hundredths(*score));
                    }
                }
                SafetyPredicate::PostTag(name) => {
                    out.push_str("post_tag:");
                    format_exact_name(name, out);
                }
                SafetyPredicate::Author(name) => {
                    out.push_str("author:");
                    format_exact_name(name, out);
                }
                SafetyPredicate::Unclassified => out.push_str("unclassified"),
            },
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
}

/// Validates EVERY `tag:<name>` leaf in `expr` (including inside `NOT` branches)
/// against the bundled canonical 10,861-tag WD-Tagger v3 vocabulary.
pub fn validate_wd_tags_in_expr(expr: &SafetyExpr) -> Result<(), SafetyRuleError> {
    let unknown: Vec<String> = expr
        .referenced_wd_tags()
        .into_iter()
        .filter(|name| !is_canonical_wd_tag(name))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(SafetyRuleError::new(
            format!(
                "Unknown WD-Tagger v3 tag(s): {}",
                unknown.join(", ")
            ),
            None,
        ))
    }
}

/// Extracts deduplicated, deterministically sorted `(post_tags, authors)` catalog
/// references from `expr` so `/admin` can validate them against the origin catalog.
pub fn collect_catalog_refs(expr: &SafetyExpr) -> (Vec<String>, Vec<String>) {
    (expr.referenced_post_tags(), expr.referenced_authors())
}

fn format_exact_name(name: &str, out: &mut String) {
    let needs_quote = name.is_empty()
        || name.starts_with('-')
        || name.starts_with('/')
        || name.eq_ignore_ascii_case("AND")
        || name.eq_ignore_ascii_case("OR")
        || name.eq_ignore_ascii_case("NOT")
        || name.eq_ignore_ascii_case("unclassified")
        || name
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '(' | ')' | '"' | '\\' | '>' | '<' | '=' | '~'));
    if !needs_quote {
        out.push_str(name);
        return;
    }
    out.push('"');
    for ch in name.chars() {
        if matches!(ch, '"' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
}

// ---------------------------------------------------------------------------
// Lexer & Recursive-Descent Parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SafetyField {
    Tag,
    PostTag,
    Author,
}

impl SafetyField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tag => "tag",
            Self::PostTag => "post_tag",
            Self::Author => "author",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum TokenKind {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Minus,
    Unclassified,
    Predicate(SafetyPredicate),
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    pos: usize,
}

fn parse_threshold_value(
    raw: &str,
    pos: usize,
    strict_hundredths: bool,
) -> Result<f32, SafetyRuleError> {
    if raw.is_empty() {
        return Err(SafetyRuleError::new(
            "Expected numeric score after '>='",
            Some(pos),
        ));
    }
    if raw.contains(">=") {
        return Err(SafetyRuleError::new(
            "Duplicate '>=' threshold in tag predicate",
            Some(pos),
        ));
    }
    if strict_hundredths {
        parse_threshold_hundredths(raw).map_err(|e| SafetyRuleError::new(e.message, Some(pos)))
    } else {
        let val = raw.parse::<f32>().map_err(|_| {
            SafetyRuleError::new(
                format!("Invalid score threshold '{raw}' (expected float in (0.0, 1.0])"),
                Some(pos),
            )
        })?;
        validate_threshold_range(val).map_err(|e| SafetyRuleError::new(e.message, Some(pos)))
    }
}

fn is_regex_literal(s: &str) -> bool {
    s.starts_with('/')
}

fn is_gte_at(chars: &[(usize, char)], i: usize) -> bool {
    i + 1 < chars.len() && chars[i].1 == '>' && chars[i + 1].1 == '='
}

fn skip_ws(chars: &[(usize, char)], i: &mut usize) {
    while *i < chars.len() && chars[*i].1.is_whitespace() {
        *i += 1;
    }
}

fn parse_quoted(chars: &[(usize, char)], i: &mut usize) -> Result<String, SafetyRuleError> {
    let start = chars[*i].0;
    *i += 1;
    let mut val = String::new();
    let mut closed = false;
    while *i < chars.len() {
        let (_, c) = chars[*i];
        if c == '\\' {
            if *i + 1 >= chars.len() {
                return Err(SafetyRuleError::new(
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
        return Err(SafetyRuleError::new(
            "Unterminated quoted string",
            Some(start),
        ));
    }
    Ok(val)
}

fn read_unquoted_segment(chars: &[(usize, char)], i: &mut usize) -> String {
    let mut out = String::new();
    while *i < chars.len() {
        let (_, c) = chars[*i];
        if c.is_whitespace() || matches!(c, '(' | ')' | '"') {
            break;
        }
        out.push(c);
        *i += 1;
    }
    out
}

/// Checks for an optional `>= <score>` following a predicate value, allowing
/// optional whitespace before and after `>=`.
fn try_read_trailing_gte(
    chars: &[(usize, char)],
    i: &mut usize,
) -> Result<Option<(String, usize)>, SafetyRuleError> {
    let saved = *i;
    skip_ws(chars, i);
    if !is_gte_at(chars, *i) {
        *i = saved;
        return Ok(None);
    }
    let op_pos = chars[*i].0;
    *i += 2; // consume `>=`
    skip_ws(chars, i);
    if *i >= chars.len() || matches!(chars[*i].1, '(' | ')' | '"') {
        return Err(SafetyRuleError::new(
            "Expected numeric score after '>='",
            Some(op_pos),
        ));
    }
    let score_pos = chars[*i].0;
    let raw_score = read_unquoted_segment(chars, i);
    // Reject duplicate `>=` even when separated by whitespace (`tag:blood >= 0.5 >= 0.6`).
    let after_score = *i;
    skip_ws(chars, i);
    if is_gte_at(chars, *i) {
        return Err(SafetyRuleError::new(
            "Duplicate '>=' threshold in tag predicate",
            Some(chars[*i].0),
        ));
    }
    *i = after_score;
    Ok(Some((raw_score, score_pos)))
}

fn tokenize(input: &str, strict_hundredths: bool) -> Result<Vec<Token>, SafetyRuleError> {
    if input.len() > MAX_RULE_LEN {
        return Err(SafetyRuleError::new(
            format!("Safety rule exceeds maximum length of {MAX_RULE_LEN} bytes"),
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
            return Err(SafetyRuleError::new(
                "Unexpected '>=' (score thresholds are only allowed on tag: predicates)",
                Some(char_pos),
            ));
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
                if i + 1 < chars.len() && !chars[i + 1].1.is_whitespace() {
                    tokens.push(Token {
                        kind: TokenKind::Minus,
                        pos: char_pos,
                    });
                    i += 1;
                } else {
                    return Err(SafetyRuleError::new(
                        "Expected a predicate or '(' after '-'",
                        Some(char_pos),
                    ));
                }
            }
            '"' => {
                return Err(SafetyRuleError::new(
                    "Bare quoted text is not allowed in safety rules; use tag:, post_tag:, author:, or unclassified",
                    Some(char_pos),
                ));
            }
            '/' => {
                return Err(SafetyRuleError::new(
                    "Regular expressions are not allowed in safety rules",
                    Some(char_pos),
                ));
            }
            _ => {
                let start = char_pos;
                let mut prefix = String::new();
                let mut hit_colon = false;
                while i < chars.len() {
                    let (_, c) = chars[i];
                    if c.is_whitespace() || matches!(c, '(' | ')' | '"') {
                        break;
                    }
                    if c == ':' {
                        hit_colon = true;
                        i += 1;
                        break;
                    }
                    prefix.push(c);
                    i += 1;
                }

                if hit_colon {
                    let lower = prefix.to_ascii_lowercase();
                    let field = match lower.as_str() {
                        "tag" => SafetyField::Tag,
                        "post_tag" => SafetyField::PostTag,
                        "author" => SafetyField::Author,
                        "clip" | "desc" | "dino" | "similar" | "id" | "upload" | "img" => {
                            return Err(SafetyRuleError::new(
                                format!(
                                    "Vector operator '{prefix}:' is not allowed in metadata-only safety rules"
                                ),
                                Some(start),
                            ));
                        }
                        "re" | "regex" => {
                            return Err(SafetyRuleError::new(
                                "Regular expressions are not allowed in safety rules",
                                Some(start),
                            ));
                        }
                        _ => {
                            return Err(SafetyRuleError::new(
                                format!(
                                    "Unsupported field '{prefix}:' in safety rules (allowed: tag:, post_tag:, author:, unclassified)"
                                ),
                                Some(start),
                            ));
                        }
                    };

                    if i >= chars.len()
                        || chars[i].1.is_whitespace()
                        || matches!(chars[i].1, '(' | ')')
                    {
                        return Err(SafetyRuleError::new(
                            format!("Expected an exact name after '{}:'", field.as_str()),
                            Some(start),
                        ));
                    }

                    let (name, trailing_score) = if chars[i].1 == '"' {
                        let quoted = parse_quoted(&chars, &mut i)?;
                        if i < chars.len()
                            && !chars[i].1.is_whitespace()
                            && !matches!(chars[i].1, '(' | ')')
                            && !is_gte_at(&chars, i)
                        {
                            return Err(SafetyRuleError::new(
                                format!(
                                    "Unexpected trailing characters after quoted value for '{}:'",
                                    field.as_str()
                                ),
                                Some(chars[i].0),
                            ));
                        }
                        let score_opt = try_read_trailing_gte(&chars, &mut i)?;
                        (quoted, score_opt)
                    } else {
                        let val_pos = chars[i].0;
                        let raw = read_unquoted_segment(&chars, &mut i);
                        if is_regex_literal(&raw) {
                            return Err(SafetyRuleError::new(
                                "Regular expressions are not allowed in safety rules",
                                Some(val_pos),
                            ));
                        }
                        if raw.contains("~=") || raw.contains("=~") {
                            return Err(SafetyRuleError::new(
                                "Regex/fuzzy comparison operators are not allowed in safety rules",
                                Some(val_pos),
                            ));
                        }
                        if let Some((lhs, rhs)) = raw.split_once(">=") {
                            if rhs.is_empty() {
                                // `tag:blood>= 0.45`: whitespace after `>=`
                                skip_ws(&chars, &mut i);
                                if i >= chars.len() || matches!(chars[i].1, '(' | ')' | '"') {
                                    return Err(SafetyRuleError::new(
                                        "Expected numeric score after '>='",
                                        Some(val_pos),
                                    ));
                                }
                                let score_pos = chars[i].0;
                                let score_word = read_unquoted_segment(&chars, &mut i);
                                let after_score = i;
                                skip_ws(&chars, &mut i);
                                if is_gte_at(&chars, i) {
                                    return Err(SafetyRuleError::new(
                                        "Duplicate '>=' threshold in tag predicate",
                                        Some(chars[i].0),
                                    ));
                                }
                                i = after_score;
                                (lhs.to_string(), Some((score_word, score_pos)))
                            } else {
                                // Reject duplicate `>=` separated by whitespace after inline score
                                let after_score = i;
                                skip_ws(&chars, &mut i);
                                if is_gte_at(&chars, i) {
                                    return Err(SafetyRuleError::new(
                                        "Duplicate '>=' threshold in tag predicate",
                                        Some(chars[i].0),
                                    ));
                                }
                                i = after_score;
                                (lhs.to_string(), Some((rhs.to_string(), val_pos)))
                            }
                        } else {
                            // Reject unsupported comparison operators like `>0.5`, `<=0.5`, `==0.5`
                            // attached directly after a tag name (e.g. `tag:blood>0.5`).
                            if field == SafetyField::Tag
                                && let Some(op_idx) = raw.find(['>', '<', '='])
                            {
                                let after = &raw[op_idx..];
                                if after.starts_with("<=")
                                    || after.starts_with("==")
                                    || after.starts_with('>')
                                    || after.starts_with('<')
                                    || after.starts_with('=')
                                {
                                    let num_part = after.trim_start_matches(['>', '<', '=']);
                                    if !num_part.is_empty() && num_part.parse::<f32>().is_ok() {
                                        return Err(SafetyRuleError::new(
                                            "Only '>=' score thresholds are allowed on tag: predicates",
                                            Some(val_pos),
                                        ));
                                    }
                                }
                            }
                            let score_opt = try_read_trailing_gte(&chars, &mut i)?;
                            (raw, score_opt)
                        }
                    };

                    let trimmed_name = name.trim();
                    if trimmed_name.is_empty() || trimmed_name != name {
                        return Err(SafetyRuleError::new(
                            format!(
                                "Exact name after '{}:' cannot be empty or padded with whitespace",
                                field.as_str()
                            ),
                            Some(start),
                        ));
                    }
                    if name.chars().any(char::is_control) {
                        return Err(SafetyRuleError::new(
                            format!(
                                "Exact name after '{}:' cannot contain control characters",
                                field.as_str()
                            ),
                            Some(start),
                        ));
                    }

                    let predicate = match field {
                        SafetyField::Tag => {
                            let min_score = match trailing_score {
                                Some((raw_score, score_pos)) => Some(parse_threshold_value(
                                    &raw_score,
                                    score_pos,
                                    strict_hundredths,
                                )?),
                                None => None,
                            };
                            SafetyPredicate::WdTag { name, min_score }
                        }
                        SafetyField::PostTag => {
                            if trailing_score.is_some() {
                                return Err(SafetyRuleError::new(
                                    "Score thresholds ('>=') are only allowed on tag: predicates",
                                    Some(start),
                                ));
                            }
                            SafetyPredicate::PostTag(name)
                        }
                        SafetyField::Author => {
                            if trailing_score.is_some() {
                                return Err(SafetyRuleError::new(
                                    "Score thresholds ('>=') are only allowed on tag: predicates",
                                    Some(start),
                                ));
                            }
                            SafetyPredicate::Author(name)
                        }
                    };

                    tokens.push(Token {
                        kind: TokenKind::Predicate(predicate),
                        pos: start,
                    });
                } else {
                    if prefix.contains("~=") || prefix.contains("=~") || is_regex_literal(&prefix) {
                        return Err(SafetyRuleError::new(
                            "Regular expressions are not allowed in safety rules",
                            Some(start),
                        ));
                    }
                    let kind = match prefix.to_ascii_uppercase().as_str() {
                        "AND" => TokenKind::And,
                        "OR" => TokenKind::Or,
                        "NOT" => TokenKind::Not,
                        "UNCLASSIFIED" => TokenKind::Unclassified,
                        _ => {
                            return Err(SafetyRuleError::new(
                                format!(
                                    "Bare term '{prefix}' is not allowed in safety rules; use tag:, post_tag:, author:, or unclassified"
                                ),
                                Some(start),
                            ));
                        }
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

    fn parse_or(&mut self, paren_depth: usize) -> Result<SafetyExpr, SafetyRuleError> {
        if paren_depth > MAX_DEPTH {
            return Err(SafetyRuleError::new(
                format!("Safety rule nesting exceeds maximum depth of {MAX_DEPTH}"),
                self.peek().map(|t| t.pos),
            ));
        }
        let mut items = vec![self.parse_and(paren_depth)?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Or)) {
            self.next();
            items.push(self.parse_and(paren_depth)?);
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap()
        } else {
            SafetyExpr::Or(items)
        })
    }

    fn parse_and(&mut self, paren_depth: usize) -> Result<SafetyExpr, SafetyRuleError> {
        let mut items = vec![self.parse_not(paren_depth)?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::And)) {
            self.next();
            items.push(self.parse_not(paren_depth)?);
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap()
        } else {
            SafetyExpr::And(items)
        })
    }

    fn parse_not(&mut self, paren_depth: usize) -> Result<SafetyExpr, SafetyRuleError> {
        let mut neg_count = 0usize;
        while matches!(
            self.peek().map(|t| &t.kind),
            Some(TokenKind::Not | TokenKind::Minus)
        ) {
            if paren_depth + neg_count >= MAX_DEPTH {
                return Err(SafetyRuleError::new(
                    format!("Safety rule nesting exceeds maximum depth of {MAX_DEPTH}"),
                    self.peek().map(|t| t.pos),
                ));
            }
            self.next();
            neg_count += 1;
        }
        let mut expr = self.parse_primary(paren_depth + neg_count)?;
        for _ in 0..neg_count {
            expr = SafetyExpr::Not(Box::new(expr));
        }
        Ok(expr)
    }

    fn parse_primary(&mut self, paren_depth: usize) -> Result<SafetyExpr, SafetyRuleError> {
        let Some(tok) = self.next() else {
            return Err(SafetyRuleError::new("Unexpected end of safety rule", None));
        };
        match tok.kind {
            TokenKind::LParen => {
                let inner = self.parse_or(paren_depth + 1)?;
                match self.next() {
                    Some(Token {
                        kind: TokenKind::RParen,
                        ..
                    }) => Ok(inner),
                    Some(other) => {
                        Err(SafetyRuleError::new("Expected closing ')'", Some(other.pos)))
                    }
                    None => Err(SafetyRuleError::new(
                        "Unclosed '(' in safety rule",
                        Some(tok.pos),
                    )),
                }
            }
            TokenKind::Predicate(pred) => Ok(SafetyExpr::Predicate(pred)),
            TokenKind::Unclassified => Ok(SafetyExpr::Predicate(SafetyPredicate::Unclassified)),
            TokenKind::RParen => Err(SafetyRuleError::new("Unexpected ')'", Some(tok.pos))),
            TokenKind::And => Err(SafetyRuleError::new("Unexpected 'AND'", Some(tok.pos))),
            TokenKind::Or => Err(SafetyRuleError::new("Unexpected 'OR'", Some(tok.pos))),
            TokenKind::Not | TokenKind::Minus => unreachable!(),
        }
    }
}

fn parse_safety_rule_inner(
    input: &str,
    strict_hundredths: bool,
) -> Result<SafetyExpr, SafetyRuleError> {
    if input.len() > MAX_RULE_LEN {
        return Err(SafetyRuleError::new(
            format!("Safety rule exceeds maximum length of {MAX_RULE_LEN} bytes"),
            None,
        ));
    }
    if input.trim().is_empty() {
        return Err(SafetyRuleError::new("Safety rule is empty", None));
    }
    let tokens = tokenize(input, strict_hundredths)?;
    if tokens.is_empty() {
        return Err(SafetyRuleError::new("Safety rule is empty", None));
    }
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.parse_or(1)?;
    if let Some(extra) = parser.peek() {
        return Err(SafetyRuleError::new(
            "Unexpected token in safety rule (missing AND/OR?)",
            Some(extra.pos),
        ));
    }
    let depth = expr.max_depth();
    if depth > MAX_DEPTH {
        return Err(SafetyRuleError::new(
            format!("Safety rule nesting depth {depth} exceeds maximum of {MAX_DEPTH}"),
            None,
        ));
    }
    let terms = expr.term_count();
    if terms > MAX_TERMS_PER_POLICY {
        return Err(SafetyRuleError::new(
            format!("Safety rule has {terms} terms, exceeding maximum of {MAX_TERMS_PER_POLICY}"),
            None,
        ));
    }
    Ok(expr)
}

/// Parses and validates a single metadata-only Safety Rule expression,
/// enforcing `MAX_RULE_LEN`, `MAX_DEPTH`, `MAX_TERMS_PER_POLICY`, and strict
/// hundredths score thresholds (`0.01..=1.00`).
pub fn parse_safety_rule(input: &str) -> Result<SafetyExpr, SafetyRuleError> {
    parse_safety_rule_inner(input, true)
}

/// Parses a metadata-only Safety Rule while permitting legacy `(0.0, 1.0]`
/// float precision (for migrating persisted pre-v3 policies).
pub fn parse_safety_rule_legacy_precision(input: &str) -> Result<SafetyExpr, SafetyRuleError> {
    parse_safety_rule_inner(input, false)
}

/// Parses and validates a Policy v3 `(match_expr, except_expr)` pair:
/// - Enforces strict metadata-only grammar and AST depth `<= 6` on both.
/// - Enforces combined term count `match_terms + except_terms <= 32`.
/// - Validates EVERY `tag:<name>` leaf in both `match_expr` and `except_expr`
///   (including inside `NOT`) against the canonical 10,861-tag WD-Tagger v3 vocab.
pub fn validate_policy_expr_pair(
    match_expr: &str,
    except_expr: Option<&str>,
) -> Result<(SafetyExpr, Option<SafetyExpr>), SafetyRuleError> {
    let parsed_match = parse_safety_rule(match_expr)?;
    validate_wd_tags_in_expr(&parsed_match)?;

    let parsed_except = match except_expr.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw_except) => {
            let ex = parse_safety_rule(raw_except).map_err(|e| {
                SafetyRuleError::new(format!("except_expr: {}", e.message), e.position)
            })?;
            validate_wd_tags_in_expr(&ex).map_err(|e| {
                SafetyRuleError::new(format!("except_expr: {}", e.message), e.position)
            })?;
            Some(ex)
        }
        None => None,
    };

    let combined_terms = parsed_match.term_count()
        + parsed_except.as_ref().map_or(0, SafetyExpr::term_count);
    if combined_terms > MAX_TERMS_PER_POLICY {
        return Err(SafetyRuleError::new(
            format!(
                "Policy has {combined_terms} combined terms (match_expr + except_expr), exceeding maximum of {MAX_TERMS_PER_POLICY}"
            ),
            None,
        ));
    }

    Ok((parsed_match, parsed_except))
}

/// Validates an entire policy's safety rule list, enforcing `MAX_POLICIES_PER_SET`
/// and `MAX_TOTAL_TERMS_PER_SET` in addition to per-rule limits.
pub fn validate_policy_rules<'a>(
    rules: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<SafetyExpr>, SafetyRuleError> {
    let mut parsed = Vec::new();
    let mut total_terms = 0usize;
    for (idx, raw) in rules.into_iter().enumerate() {
        if parsed.len() >= MAX_POLICIES_PER_SET {
            return Err(SafetyRuleError::new(
                format!("Policy exceeds maximum of {MAX_POLICIES_PER_SET} safety rules"),
                None,
            ));
        }
        let expr = parse_safety_rule(raw).map_err(|e| {
            SafetyRuleError::new(format!("Rule #{}: {}", idx + 1, e.message), e.position)
        })?;
        total_terms += expr.term_count();
        if total_terms > MAX_TOTAL_TERMS_PER_SET {
            return Err(SafetyRuleError::new(
                format!(
                    "Policy exceeds maximum of {MAX_TOTAL_TERMS_PER_SET} total safety terms"
                ),
                None,
            ));
        }
        parsed.push(expr);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tribool_kleene_algebra_preserves_exact_truth_tables() {
        use TriBool::{False as F, True as T, Unknown as U};

        // NOT
        assert_eq!(!T, F);
        assert_eq!(!F, T);
        assert_eq!(!U, U);

        // AND
        assert_eq!(T & T, T);
        assert_eq!(T & F, F);
        assert_eq!(F & T, F);
        assert_eq!(F & F, F);
        assert_eq!(F & U, F);
        assert_eq!(U & F, F);
        assert_eq!(T & U, U);
        assert_eq!(U & T, U);
        assert_eq!(U & U, U);

        // OR
        assert_eq!(T | T, T);
        assert_eq!(T | F, T);
        assert_eq!(F | T, T);
        assert_eq!(F | F, F);
        assert_eq!(T | U, T);
        assert_eq!(U | T, T);
        assert_eq!(F | U, U);
        assert_eq!(U | F, U);
        assert_eq!(U | U, U);

        // Policy evaluation: `match_expr AND NOT except_expr`
        let match_expr = parse_safety_rule("tag:blood").unwrap();
        let except_expr = parse_safety_rule("post_tag:safe_override").unwrap();

        // Match True, Except Unknown -> True & !Unknown = Unknown (fail-closed Placeholder!)
        let res = SafetyExpr::eval_policy_match(&match_expr, Some(&except_expr), &|p| match p {
            SafetyPredicate::WdTag { .. } => T,
            SafetyPredicate::PostTag(_) => U,
            _ => F,
        });
        assert_eq!(res, U);

        // Match False, Except Unknown -> False & Unknown = False
        let res = SafetyExpr::eval_policy_match(&match_expr, Some(&except_expr), &|p| match p {
            SafetyPredicate::WdTag { .. } => F,
            SafetyPredicate::PostTag(_) => U,
            _ => F,
        });
        assert_eq!(res, F);

        // Match Unknown, Except True -> Unknown & False = False (exempt!)
        let res = SafetyExpr::eval_policy_match(&match_expr, Some(&except_expr), &|p| match p {
            SafetyPredicate::WdTag { .. } => U,
            SafetyPredicate::PostTag(_) => T,
            _ => F,
        });
        assert_eq!(res, F);
    }

    #[test]
    fn parses_all_allowed_predicates_whitespace_around_gte_and_extracts_catalog_refs() {
        let rule = r#"(tag:explicit >= 0.75 OR tag:"eimi_(blue_archive)" >=0.50 OR post_tag:r18_set) AND author:"artist_name" AND NOT tag:general>= 0.20 AND -unclassified"#;
        let expr = parse_safety_rule(rule).expect("valid safety rule");

        assert_eq!(
            expr.referenced_wd_tags(),
            vec![
                "eimi_(blue_archive)".to_string(),
                "explicit".to_string(),
                "general".to_string(),
            ]
        );
        let (post_tags, authors) = collect_catalog_refs(&expr);
        assert_eq!(post_tags, vec!["r18_set".to_string()]);
        assert_eq!(authors, vec!["artist_name".to_string()]);
        assert!(expr.references_unclassified());
        assert_eq!(expr.term_count(), 6);

        // Roundtrip formatting
        let formatted = expr.format_rule();
        let reparsed = parse_safety_rule(&formatted).expect("roundtrip parse");
        assert_eq!(expr, reparsed);
    }

    #[test]
    fn validates_wd_tags_including_inside_not_and_except_expr() {
        // Valid canonical WD tags pass
        let (m, ex) = validate_policy_expr_pair(
            "tag:blood >= 0.45 AND NOT tag:general",
            Some("tag:sensitive OR post_tag:medical_diagram"),
        )
        .expect("canonical tags valid");
        assert_eq!(m.term_count(), 2);
        assert_eq!(ex.unwrap().term_count(), 2);

        // Typo inside NOT in match_expr MUST be rejected
        let err = validate_policy_expr_pair("tag:blood AND NOT tag:genral_typo", None)
            .unwrap_err();
        assert!(err.message.contains("genral_typo"));

        // Typo inside except_expr MUST be rejected
        let err =
            validate_policy_expr_pair("tag:blood", Some("NOT tag:explict_typo")).unwrap_err();
        assert!(err.message.contains("except_expr") && err.message.contains("explict_typo"));

        // Combined term count (match_expr + except_expr > 32) MUST be rejected
        let twenty = (0..20)
            .map(|_| "tag:blood")
            .collect::<Vec<_>>()
            .join(" OR ");
        let thirteen = (0..13)
            .map(|_| "tag:explicit")
            .collect::<Vec<_>>()
            .join(" OR ");
        assert!(validate_policy_expr_pair(&twenty, Some(&thirteen)).is_err());
    }

    #[test]
    fn parses_builtin_preset_queries_and_validates_all_against_wd_vocab() {
        let r18 = "tag:explicit OR tag:nude OR tag:nipples OR tag:pussy OR tag:penis OR tag:sex OR tag:uncensored OR tag:censored OR tag:topless OR tag:bottomless";
        let sensitive = "tag:questionable OR tag:sensitive OR tag:lingerie OR tag:bikini OR tag:underwear OR tag:panties OR tag:cleavage OR tag:bdsm";
        let blood = "tag:blood";
        let rules = validate_policy_rules([r18, sensitive, blood]).expect("presets valid");
        assert_eq!(rules.len(), 3);
        for expr in &rules {
            validate_wd_tags_in_expr(expr).expect("all preset tags exist in WD vocab");
        }
    }

    #[test]
    fn rejects_vector_fuzzy_bare_regex_and_empty_names() {
        assert!(parse_safety_rule(r#"clip:"blood""#).is_err());
        assert!(parse_safety_rule("dino:12345").is_err());
        assert!(parse_safety_rule("upload:0").is_err());
        assert!(parse_safety_rule("tag:blood OR clip:gore").is_err());
        assert!(parse_safety_rule("title:nsfw").is_err());
        assert!(parse_safety_rule("all:nsfw").is_err());
        assert!(parse_safety_rule("blood").is_err());
        assert!(parse_safety_rule(r#""explicit""#).is_err());
        assert!(parse_safety_rule("tag:blood gore").is_err());
        assert!(parse_safety_rule("/blood.*/").is_err());
        assert!(parse_safety_rule("tag:/blood.*/").is_err());
        assert!(parse_safety_rule("tag:/blood.*/i").is_err());
        assert!(parse_safety_rule("regex:blood.*").is_err());
        assert!(parse_safety_rule("tag:blood~=0.5").is_err());
        assert!(parse_safety_rule("tag:\"blood\0\"").is_err());
        assert!(parse_safety_rule("tag:\"blood\nline\"").is_err());
        assert!(parse_safety_rule("tag:blood\x00").is_err());
        assert!(parse_safety_rule("post_tag:\"foo\x07bar\"").is_err());
        assert!(parse_safety_rule("author:\"bob\r\"").is_err());
        assert!(parse_safety_rule("tag:").is_err());
        assert!(parse_safety_rule(r#"tag:"""#).is_err());
        assert!(parse_safety_rule(r#"tag:"   ""#).is_err());
        assert!(parse_safety_rule("tag:>=0.5").is_err());
        assert!(parse_safety_rule("post_tag:").is_err());
        assert!(parse_safety_rule("author:").is_err());
    }

    #[test]
    fn validates_score_thresholds_strictly() {
        // Valid hundredths (all 4 whitespace combos)
        for q in [
            "tag:blood>=0.01",
            "tag:blood>= 0.01",
            "tag:blood >=0.01",
            "tag:blood >= 0.01",
            "tag:blood>=1.0",
            "tag:blood>=1.00",
            "tag:blood>=1",
            r#"tag:":>=" >= 0.50"#,
        ] {
            assert!(parse_safety_rule(q).is_ok(), "expected ok for {q}");
        }

        // Legacy precision preserved via dedicated migration helper
        assert!(parse_safety_rule("tag:blood>=0.001").is_err());
        assert!(parse_safety_rule("tag:blood>=0.456").is_err());
        assert!(parse_safety_rule_legacy_precision("tag:blood>=0.001").is_ok());

        // Kaomoji tags containing '=' without numeric suffix remain valid
        assert_eq!(
            parse_safety_rule("tag:=_=").unwrap(),
            SafetyExpr::Predicate(SafetyPredicate::WdTag {
                name: "=_=".to_string(),
                min_score: None,
            })
        );

        // Out of range, non-finite, duplicate, or invalid operators
        for bad in [
            "tag:blood>=0",
            "tag:blood>=0.0",
            "tag:blood>=-0.5",
            "tag:blood >= -0.5",
            "tag:blood>=1.01",
            "tag:blood>=NaN",
            "tag:blood>=inf",
            "tag:blood>=-inf",
            "tag:blood>=",
            "tag:blood >= ",
            "tag:blood>0.5",
            "tag:blood<=0.5",
            "tag:blood=0.5",
            "tag:blood==0.5",
            "tag:blood>=0.5>=0.6",
            "tag:blood >= 0.5 >= 0.6",
            "post_tag:nsfw>=0.5",
            "post_tag:nsfw >= 0.5",
            "author:bob>=0.5",
            "author:bob >= 0.5",
            "unclassified >= 0.5",
        ] {
            assert!(parse_safety_rule(bad).is_err(), "expected err for {bad}");
        }
    }

    #[test]
    fn enforces_hard_policy_and_rule_limits() {
        let oversized = format!("tag:{}", "a".repeat(MAX_RULE_LEN));
        assert!(parse_safety_rule(&oversized).is_err());

        let too_many_terms = (0..=MAX_TERMS_PER_POLICY)
            .map(|i| format!("tag:t{i}"))
            .collect::<Vec<_>>()
            .join(" OR ");
        assert!(parse_safety_rule(&too_many_terms).is_err());

        let exact_terms = (0..MAX_TERMS_PER_POLICY)
            .map(|i| format!("tag:t{i}"))
            .collect::<Vec<_>>()
            .join(" OR ");
        assert!(parse_safety_rule(&exact_terms).is_ok());

        let deep_not = format!("{}tag:blood", "NOT ".repeat(MAX_DEPTH));
        assert!(parse_safety_rule(&deep_not).is_err());
        let deep_parens = format!(
            "{}tag:blood{}",
            "(".repeat(MAX_DEPTH + 1),
            ")".repeat(MAX_DEPTH + 1)
        );
        assert!(parse_safety_rule(&deep_parens).is_err());

        let too_many_rules = vec!["tag:blood"; MAX_POLICIES_PER_SET + 1];
        assert!(validate_policy_rules(too_many_rules).is_err());

        let twenty_terms = (0..20)
            .map(|i| format!("tag:t{i}"))
            .collect::<Vec<_>>()
            .join(" OR ");
        let seven_rules: Vec<&str> = (0..7).map(|_| twenty_terms.as_str()).collect();
        assert!(validate_policy_rules(seven_rules).is_err());
    }
}
