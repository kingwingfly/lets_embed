use std::fmt;

pub const MAX_QUERY_LEN: usize = 2000;
pub const MAX_DEPTH: usize = 8;
pub const MAX_TERMS: usize = 24;
pub const MAX_CLIP_TERMS: usize = 8;
pub const MAX_DINO_TERMS: usize = 8;
pub const MAX_UPLOAD_TERMS: usize = 4;

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

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum QueryExpr {
    Term { field: SearchField, value: String },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPlan {
    pub result_kind: ResultKind,
    pub tier: VectorTier,
    /// Pure metadata boolean expression (`All`, `Title`, `Author`, `Tag`).
    pub meta_filter: Option<QueryExpr>,
    /// Positive tag queries collected from `meta_filter` (for relevance scoring).
    pub positive_tags: Vec<String>,
    pub clip_pos: Vec<String>,
    pub clip_neg: Vec<String>,
    pub dino_pos: Vec<i64>,
    pub dino_neg: Vec<i64>,
    pub upload_pos: Vec<usize>,
    pub upload_neg: Vec<usize>,
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
        self.has_clip() || self.has_dino()
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
            Self::Term { field, value } => {
                out.push_str(field.as_prefix());
                out.push(':');
                format_value(value, out);
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

    /// Analyze, validate, and split the AST into a metadata filter + vector rankers.
    pub fn compile_plan(&self) -> Result<QueryPlan, QueryError> {
        let mut term_count = 0usize;
        check_limits(self, 1, &mut term_count)?;

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
            .any(|c| c.is_whitespace() || matches!(c, '(' | ')' | '"' | '\\' | ':'));
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
        QueryExpr::Term { value, .. } => {
            if value.trim().is_empty() {
                return Err(QueryError::new("Search term cannot be empty", None));
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
    clip_pos: &mut Vec<String>,
    clip_neg: &mut Vec<String>,
    dino_pos: &mut Vec<i64>,
    dino_neg: &mut Vec<i64>,
    upload_pos: &mut Vec<usize>,
    upload_neg: &mut Vec<usize>,
) -> Result<Option<QueryExpr>, QueryError> {
    match expr {
        QueryExpr::Term { field, value } if field.is_vector() => {
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
                    if positive {
                        clip_pos.push(trimmed.to_string());
                    } else {
                        clip_neg.push(trimmed.to_string());
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
                    if positive {
                        dino_pos.push(id);
                    } else {
                        dino_neg.push(id);
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
                    if positive {
                        upload_pos.push(idx);
                    } else {
                        upload_neg.push(idx);
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
                inner, !positive, inside_or, clip_pos, clip_neg, dino_pos, dino_neg, upload_pos,
                upload_neg,
            )?;
            Ok(meta.map(|m| QueryExpr::Not(Box::new(m))))
        }
        QueryExpr::And(items) => {
            let mut kept = Vec::new();
            for item in items {
                if let Some(m) = extract_vectors(
                    item, positive, inside_or, clip_pos, clip_neg, dino_pos, dino_neg, upload_pos,
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
                    item, positive, true, clip_pos, clip_neg, dino_pos, dino_neg, upload_pos,
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
    Word(String),
    Quoted(String),
    Field(SearchField),
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    pos: usize,
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
                // After a field prefix (e.g. `dino:-5` or `tag:-foo`), lex `-...` as a
                // word value so field-specific validators run instead of failing with
                // "Expected a value after '<field>:'".
                let after_field =
                    matches!(tokens.last().map(|t| &t.kind), Some(TokenKind::Field(_)));
                if i + 1 < chars.len() && !chars[i + 1].1.is_whitespace() {
                    if after_field {
                        let start = char_pos;
                        let mut word = String::new();
                        while i < chars.len() {
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
                i += 1;
                let mut val = String::new();
                let mut closed = false;
                while i < chars.len() {
                    let (_, c) = chars[i];
                    if c == '\\' {
                        if i + 1 >= chars.len() {
                            return Err(QueryError::new(
                                "Unterminated escape sequence in quoted string",
                                Some(chars[i].0),
                            ));
                        }
                        val.push(chars[i + 1].1);
                        i += 2;
                    } else if c == '"' {
                        closed = true;
                        i += 1;
                        break;
                    } else {
                        val.push(c);
                        i += 1;
                    }
                }
                if !closed {
                    return Err(QueryError::new("Unterminated quoted string", Some(start)));
                }
                tokens.push(Token {
                    kind: TokenKind::Quoted(val),
                    pos: start,
                });
            }
            _ => {
                let start = char_pos;
                let mut word = String::new();
                let mut field_hit = None;
                while i < chars.len() {
                    let (_, c) = chars[i];
                    if c.is_whitespace() || matches!(c, '(' | ')' | '"') {
                        break;
                    }
                    if c == ':'
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
                } else {
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
                Ok(QueryExpr::Term {
                    field,
                    value: trimmed,
                })
            }
            TokenKind::Word(w) | TokenKind::Quoted(w) => {
                let trimmed = w.trim().to_string();
                if trimmed.is_empty() {
                    return Err(QueryError::new(
                        "Search term cannot be empty",
                        Some(tok.pos),
                    ));
                }
                Ok(QueryExpr::Term {
                    field: SearchField::All,
                    value: trimmed,
                })
            }
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
        let q = r#"(tag:"black hair" OR tag:maid) AND author:渡久山 NOT tag:monochrome"#;
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
    fn post_only_queries_auto_switch_to_posts() {
        let (_, plan) =
            parse_and_compile(r#"author:"渡久山" AND (title:咖啡 OR title:女仆) NOT title:预告"#)
                .unwrap();
        assert_eq!(plan.result_kind, ResultKind::Posts);
        assert_eq!(plan.tier, VectorTier::None);
    }

    #[test]
    fn combines_metadata_and_positive_negative_vectors() {
        let (_, plan) = parse_and_compile(
            r#"tag:maid AND clip:"sunny cafe" AND NOT clip:"dark room" AND dino:2286979 AND NOT dino:100"#,
        )
        .unwrap();
        assert_eq!(plan.result_kind, ResultKind::Images);
        assert_eq!(plan.tier, VectorTier::Clip);
        assert_eq!(plan.clip_pos, vec!["sunny cafe"]);
        assert_eq!(plan.clip_neg, vec!["dark room"]);
        assert_eq!(plan.dino_pos, vec![2286979]);
        assert_eq!(plan.dino_neg, vec![100]);
        assert!(plan.meta_filter.is_some());
    }

    #[test]
    fn upload_tier_takes_precedence_over_clip_and_dino() {
        let (_, plan) = parse_and_compile(r#"upload:0 AND clip:"beach" AND dino:42"#).unwrap();
        assert_eq!(plan.tier, VectorTier::ImageUpload);
        assert_eq!(plan.upload_pos, vec![0]);
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
                },
                QueryExpr::Not(Box::new(QueryExpr::Term {
                    field: SearchField::All,
                    value: "预告".into(),
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
        // 'tag:女仆 ' is 7 Unicode chars -> ')' is at 0-based char index 7 (displayed as char 8).
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
        // 3 leading spaces + 'tag:女仆 ' (7 chars) -> ')' at 0-based char index 10.
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
            }
        );
        let reparsed = parse_query(&expr.format_query()).unwrap();
        assert_eq!(expr, reparsed);
    }
}
