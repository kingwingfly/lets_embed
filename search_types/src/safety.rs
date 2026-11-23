//! Dedicated metadata-only Safety Rule parser and AST.
//!
//! Grammar (strictly metadata-only, zero vector/fuzzy/regex operators):
//! - `tag:<exact_name>[>=<f32>]` (score in `(0.0, 1.0]`, finite)
//! - `post_tag:<exact_name>`
//! - `author:<exact_name>`
//! - `unclassified`
//! - Boolean operators `AND`, `OR`, `NOT`, unary `-`, and parentheses `(...)`

use std::{collections::BTreeSet, fmt};

pub const MAX_RULES_PER_POLICY: usize = 16;
pub const MAX_TERMS_PER_RULE: usize = 32;
pub const MAX_DEPTH: usize = 6;
pub const MAX_TOTAL_TERMS_PER_POLICY: usize = 128;
pub const MAX_RULE_LEN: usize = 2048;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SafetyPredicate {
    /// Exact canonical WD-Tagger tag name with optional per-term score threshold in `(0.0, 1.0]`.
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
    fn new(message: impl Into<String>, position: Option<usize>) -> Self {
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
                        out.push_str(&score.to_string());
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

fn parse_threshold_value(raw: &str, pos: usize) -> Result<f32, SafetyRuleError> {
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
    let val = raw.parse::<f32>().map_err(|_| {
        SafetyRuleError::new(
            format!("Invalid score threshold '{raw}' (expected float in (0.0, 1.0])"),
            Some(pos),
        )
    })?;
    if !val.is_finite() || val <= 0.0 || val > 1.0 {
        return Err(SafetyRuleError::new(
            format!("Score threshold '{raw}' must be finite and in (0.0, 1.0]"),
            Some(pos),
        ));
    }
    Ok(val)
}

fn is_regex_literal(s: &str) -> bool {
    s.starts_with('/')
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

fn tokenize(input: &str) -> Result<Vec<Token>, SafetyRuleError> {
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
                        let score_opt = if i + 1 < chars.len()
                            && chars[i].1 == '>'
                            && chars[i + 1].1 == '='
                        {
                            let score_pos = chars[i].0;
                            i += 2;
                            let raw_score = read_unquoted_segment(&chars, &mut i);
                            Some((raw_score, score_pos))
                        } else if i < chars.len()
                            && !chars[i].1.is_whitespace()
                            && !matches!(chars[i].1, '(' | ')')
                        {
                            return Err(SafetyRuleError::new(
                                format!(
                                    "Unexpected trailing characters after quoted value for '{}:'",
                                    field.as_str()
                                ),
                                Some(chars[i].0),
                            ));
                        } else {
                            None
                        };
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
                            (lhs.to_string(), Some((rhs.to_string(), val_pos)))
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
                            (raw, None)
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
                                Some((raw_score, score_pos)) => {
                                    Some(parse_threshold_value(&raw_score, score_pos)?)
                                }
                                None => None,
                            };
                            SafetyPredicate::WdTag {
                                name,
                                min_score,
                            }
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

/// Parses and validates a single metadata-only Safety Rule expression,
/// enforcing `MAX_RULE_LEN`, `MAX_DEPTH`, and `MAX_TERMS_PER_RULE`.
pub fn parse_safety_rule(input: &str) -> Result<SafetyExpr, SafetyRuleError> {
    if input.len() > MAX_RULE_LEN {
        return Err(SafetyRuleError::new(
            format!("Safety rule exceeds maximum length of {MAX_RULE_LEN} bytes"),
            None,
        ));
    }
    if input.trim().is_empty() {
        return Err(SafetyRuleError::new("Safety rule is empty", None));
    }
    let tokens = tokenize(input)?;
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
    if terms > MAX_TERMS_PER_RULE {
        return Err(SafetyRuleError::new(
            format!("Safety rule has {terms} terms, exceeding maximum of {MAX_TERMS_PER_RULE}"),
            None,
        ));
    }
    Ok(expr)
}

/// Validates an entire policy's safety rule list, enforcing `MAX_RULES_PER_POLICY`
/// and `MAX_TOTAL_TERMS_PER_POLICY` in addition to per-rule limits.
pub fn validate_policy_rules<'a>(
    rules: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<SafetyExpr>, SafetyRuleError> {
    let mut parsed = Vec::new();
    let mut total_terms = 0usize;
    for (idx, raw) in rules.into_iter().enumerate() {
        if parsed.len() >= MAX_RULES_PER_POLICY {
            return Err(SafetyRuleError::new(
                format!("Policy exceeds maximum of {MAX_RULES_PER_POLICY} safety rules"),
                None,
            ));
        }
        let expr = parse_safety_rule(raw).map_err(|e| {
            SafetyRuleError::new(format!("Rule #{}: {}", idx + 1, e.message), e.position)
        })?;
        total_terms += expr.term_count();
        if total_terms > MAX_TOTAL_TERMS_PER_POLICY {
            return Err(SafetyRuleError::new(
                format!(
                    "Policy exceeds maximum of {MAX_TOTAL_TERMS_PER_POLICY} total safety terms"
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
    fn parses_all_allowed_predicates_and_extracts_references() {
        let rule = r#"(tag:explicit>=0.75 OR tag:"eimi_(blue_archive)">=0.5 OR post_tag:r18_set) AND author:"artist_name" AND NOT tag:general AND -unclassified"#;
        let expr = parse_safety_rule(rule).expect("valid safety rule");

        assert_eq!(
            expr.referenced_wd_tags(),
            vec![
                "eimi_(blue_archive)".to_string(),
                "explicit".to_string(),
                "general".to_string(),
            ]
        );
        assert_eq!(expr.referenced_post_tags(), vec!["r18_set".to_string()]);
        assert_eq!(expr.referenced_authors(), vec!["artist_name".to_string()]);
        assert!(expr.references_unclassified());
        assert_eq!(expr.term_count(), 6);

        // Roundtrip formatting
        let formatted = expr.format_rule();
        let reparsed = parse_safety_rule(&formatted).expect("roundtrip parse");
        assert_eq!(expr, reparsed);
    }

    #[test]
    fn parses_builtin_preset_queries() {
        let r18 = "tag:explicit OR tag:nude OR tag:nipples OR tag:pussy OR tag:penis OR tag:sex OR tag:uncensored OR tag:censored OR tag:topless OR tag:bottomless";
        let sensitive = "tag:questionable OR tag:sensitive OR tag:lingerie OR tag:bikini OR tag:underwear OR tag:panties OR tag:cleavage OR tag:bdsm";
        let blood = "tag:blood";
        let rules = validate_policy_rules([r18, sensitive, blood]).expect("presets valid");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].referenced_wd_tags().len(), 10);
        assert_eq!(rules[1].referenced_wd_tags().len(), 8);
        assert_eq!(rules[2].referenced_wd_tags(), vec!["blood".to_string()]);
    }

    #[test]
    fn rejects_vector_fuzzy_bare_regex_and_empty_names() {
        // Vector operators
        assert!(parse_safety_rule(r#"clip:"blood""#).is_err());
        assert!(parse_safety_rule("dino:12345").is_err());
        assert!(parse_safety_rule("upload:0").is_err());
        assert!(parse_safety_rule("tag:blood OR clip:gore").is_err());

        // Unsupported search fields
        assert!(parse_safety_rule("title:nsfw").is_err());
        assert!(parse_safety_rule("all:nsfw").is_err());

        // Bare/unscoped free text
        assert!(parse_safety_rule("blood").is_err());
        assert!(parse_safety_rule(r#""explicit""#).is_err());
        assert!(parse_safety_rule("tag:blood gore").is_err());

        // Regexes (including regexes with trailing flags)
        assert!(parse_safety_rule("/blood.*/").is_err());
        assert!(parse_safety_rule("tag:/blood.*/").is_err());
        assert!(parse_safety_rule("tag:/blood.*/i").is_err());
        assert!(parse_safety_rule("tag:/blood/gimsu").is_err());
        assert!(parse_safety_rule("regex:blood.*").is_err());
        assert!(parse_safety_rule("tag:blood~=0.5").is_err());

        // Control chars and NUL bytes in quoted or unquoted names
        assert!(parse_safety_rule("tag:\"blood\0\"").is_err());
        assert!(parse_safety_rule("tag:\"blood\nline\"").is_err());
        assert!(parse_safety_rule("tag:blood\x00").is_err());
        assert!(parse_safety_rule("post_tag:\"foo\x07bar\"").is_err());
        assert!(parse_safety_rule("author:\"bob\r\"").is_err());

        // Empty names
        assert!(parse_safety_rule("tag:").is_err());
        assert!(parse_safety_rule(r#"tag:"""#).is_err());
        assert!(parse_safety_rule(r#"tag:"   ""#).is_err());
        assert!(parse_safety_rule("tag:>=0.5").is_err());
        assert!(parse_safety_rule("post_tag:").is_err());
        assert!(parse_safety_rule("author:").is_err());
    }

    #[test]
    fn validates_score_thresholds_strictly() {
        assert!(parse_safety_rule("tag:blood>=0.001").is_ok());
        assert!(parse_safety_rule("tag:blood>=1.0").is_ok());
        assert!(parse_safety_rule("tag:blood>=1").is_ok());
        // Kaomoji tags containing '=' without numeric suffix remain valid
        assert_eq!(
            parse_safety_rule("tag:=_=").unwrap(),
            SafetyExpr::Predicate(SafetyPredicate::WdTag {
                name: "=_=".to_string(),
                min_score: None,
            })
        );

        // Out of range or non-finite
        assert!(parse_safety_rule("tag:blood>=0").is_err());
        assert!(parse_safety_rule("tag:blood>=0.0").is_err());
        assert!(parse_safety_rule("tag:blood>=-0.5").is_err());
        assert!(parse_safety_rule("tag:blood>=1.01").is_err());
        assert!(parse_safety_rule("tag:blood>=NaN").is_err());
        assert!(parse_safety_rule("tag:blood>=inf").is_err());
        assert!(parse_safety_rule("tag:blood>=-inf").is_err());
        assert!(parse_safety_rule("tag:blood>=").is_err());
        assert!(parse_safety_rule("tag:blood>0.5").is_err());
        assert!(parse_safety_rule("tag:blood<=0.5").is_err());
        assert!(parse_safety_rule("tag:blood=0.5").is_err());
        assert!(parse_safety_rule("tag:blood==0.5").is_err());
        assert!(parse_safety_rule("tag:blood>=0.5>=0.6").is_err());

        // Score threshold disallowed on post_tag / author
        assert!(parse_safety_rule("post_tag:nsfw>=0.5").is_err());
        assert!(parse_safety_rule("author:bob>=0.5").is_err());
    }

    #[test]
    fn enforces_hard_policy_and_rule_limits() {
        // MAX_RULE_LEN
        let oversized = format!("tag:{}", "a".repeat(MAX_RULE_LEN));
        assert!(parse_safety_rule(&oversized).is_err());

        // MAX_TERMS_PER_RULE (33 terms)
        let too_many_terms = (0..=MAX_TERMS_PER_RULE)
            .map(|i| format!("tag:t{i}"))
            .collect::<Vec<_>>()
            .join(" OR ");
        assert!(parse_safety_rule(&too_many_terms).is_err());

        let exact_terms = (0..MAX_TERMS_PER_RULE)
            .map(|i| format!("tag:t{i}"))
            .collect::<Vec<_>>()
            .join(" OR ");
        assert!(parse_safety_rule(&exact_terms).is_ok());

        // MAX_DEPTH (> 6)
        let deep_not = format!("{}tag:blood", "NOT ".repeat(MAX_DEPTH));
        assert!(parse_safety_rule(&deep_not).is_err());
        let deep_parens = format!("{}tag:blood{}", "(".repeat(MAX_DEPTH + 1), ")".repeat(MAX_DEPTH + 1));
        assert!(parse_safety_rule(&deep_parens).is_err());

        // MAX_RULES_PER_POLICY (> 16)
        let too_many_rules = vec!["tag:blood"; MAX_RULES_PER_POLICY + 1];
        assert!(validate_policy_rules(too_many_rules).is_err());

        // MAX_TOTAL_TERMS_PER_POLICY (> 128 across rules)
        let twenty_terms = (0..20)
            .map(|i| format!("tag:t{i}"))
            .collect::<Vec<_>>()
            .join(" OR ");
        let seven_rules: Vec<&str> = (0..7).map(|_| twenty_terms.as_str()).collect(); // 140 terms > 128
        assert!(validate_policy_rules(seven_rules).is_err());
    }
}
