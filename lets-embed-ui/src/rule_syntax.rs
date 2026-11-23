use crate::models::{
    RuleBlock, RuleBlockKind, RuleClause, RuleConnector, RuleField, RuleGroupCombinator,
};

/// Maximum safety rule query length in bytes (aligned with `search_types::safety`).
pub const MAX_RULE_LEN: usize = 2048;

/// Maximum number of predicate terms in a single safety rule (aligned with `search_types::safety`).
pub const MAX_TERMS_PER_RULE: usize = 32;

/// Minimum allowed non-zero WD-Tagger confidence threshold.
pub const MIN_POSITIVE_SCORE: f32 = 0.0001;

/// Format a positive confidence score in `(0.0, 1.0]` without trailing zeroes and
/// without rounding small valid positive thresholds (e.g. `0.001`) down to `"0"`.
pub fn format_score(score: f32) -> String {
    let clamped = score.clamp(MIN_POSITIVE_SCORE, 1.0);
    let s = format!("{clamped:.4}");
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "0" {
        "0.0001".to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_valid_score(score: f32) -> bool {
    score.is_finite() && score > 0.0 && score <= 1.0
}

fn quote_value_if_needed(raw: &str) -> String {
    let needs_quote = raw.starts_with('/')
        || raw.chars().any(|c| {
            c.is_whitespace() || matches!(c, '(' | ')' | '"' | '>' | '<' | '~' | '=' | ':' | ',')
        });
    if !needs_quote {
        return raw.to_string();
    }
    let escaped = raw.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Format a single [`RuleClause`] into canonical safety-rule syntax.
pub fn format_rule_clause(clause: &RuleClause) -> Option<String> {
    let base = match clause.field {
        RuleField::Unclassified => "unclassified".to_string(),
        RuleField::Tag => {
            let val = clause.value.trim();
            if val.is_empty() {
                return None;
            }
            let encoded = quote_value_if_needed(val);
            match clause.min_score {
                Some(score) if is_valid_score(score) => {
                    format!("tag:{encoded}>={}", format_score(score))
                }
                _ => format!("tag:{encoded}"),
            }
        }
        RuleField::PostTag => {
            let val = clause.value.trim();
            if val.is_empty() {
                return None;
            }
            format!("post_tag:{}", quote_value_if_needed(val))
        }
        RuleField::Author => {
            let val = clause.value.trim();
            if val.is_empty() {
                return None;
            }
            format!("author:{}", quote_value_if_needed(val))
        }
    };
    Some(if clause.negated {
        format!("NOT {base}")
    } else {
        base
    })
}

/// Format visual [`RuleBlock`] items into a canonical metadata-only safety query string.
pub fn format_rule_blocks(blocks: &[RuleBlock]) -> String {
    let mut or_branches: Vec<Vec<String>> = Vec::new();
    let mut current_and: Vec<String> = Vec::new();

    for block in blocks {
        let formatted = match &block.kind {
            RuleBlockKind::Clause(clause) => format_rule_clause(clause),
            RuleBlockKind::Group {
                combinator,
                clauses,
            } => {
                let parts: Vec<String> = clauses.iter().filter_map(format_rule_clause).collect();
                match parts.len() {
                    0 => None,
                    1 => parts.into_iter().next(),
                    _ => {
                        let sep = match combinator {
                            RuleGroupCombinator::Or => " OR ",
                            RuleGroupCombinator::And => " AND ",
                        };
                        Some(format!("({})", parts.join(sep)))
                    }
                }
            }
        };

        let Some(expr) = formatted else {
            continue;
        };

        match block.connector {
            RuleConnector::And => current_and.push(expr),
            RuleConnector::Not => {
                if expr.starts_with("NOT ") {
                    current_and.push(format!("NOT ({expr})"));
                } else {
                    current_and.push(format!("NOT {expr}"));
                }
            }
            RuleConnector::Or => {
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
struct AtomToken {
    /// Raw text before any `:` (or full word for bare tokens like `unclassified`).
    prefix: String,
    /// Present when the token contained a `:`.
    rest: Option<AtomValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AtomValue {
    /// Unescaped value text (inside quotes when `quoted == true`).
    text: String,
    /// True when the value immediately following `:` was quoted (`"..."`).
    quoted: bool,
    /// Any trailing unquoted characters immediately after a closing quote (e.g. `>=0.45`).
    trailing: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InListToken {
    prefix: String,
    negated_in: bool,
    items: Vec<(String, bool)>,
    trailing_score: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Atom(AtomToken),
    InList(InListToken),
}

fn skip_ws_chars(chars: &[char], i: &mut usize) {
    while *i < chars.len() && chars[*i].is_whitespace() {
        *i += 1;
    }
}

fn read_word_ci(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut i = start;
    let mut word = String::new();
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || matches!(c, '(' | ')' | ':' | '"' | ',') {
            break;
        }
        word.push(c);
        i += 1;
    }
    (!word.is_empty()).then_some((word, i))
}

fn try_consume_in_list_rule(
    chars: &[char],
    i: &mut usize,
    prefix: &str,
) -> Result<Option<InListToken>, String> {
    let saved = *i;
    let mut look = saved;
    skip_ws_chars(chars, &mut look);
    let Some((first_word, after_first)) = read_word_ci(chars, look) else {
        return Ok(None);
    };
    let (negated_in, after_in) = if first_word.eq_ignore_ascii_case("IN") {
        (false, after_first)
    } else if first_word.eq_ignore_ascii_case("NOT") {
        let mut next_pos = after_first;
        skip_ws_chars(chars, &mut next_pos);
        let Some((second_word, after_second)) = read_word_ci(chars, next_pos) else {
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
    skip_ws_chars(chars, &mut paren_pos);
    if chars.get(paren_pos) != Some(&'(') {
        return Ok(None);
    }

    *i = paren_pos + 1; // consume '('
    let mut items: Vec<(String, bool)> = Vec::new();
    let mut closed = false;
    let mut saw_comma = false;

    while *i < chars.len() {
        skip_ws_chars(chars, i);
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
            *i += 1;
            let mut text = String::new();
            let mut q_closed = false;
            while *i < chars.len() {
                let qc = chars[*i];
                if qc.is_control() {
                    return Err(
                        "Control characters are not allowed inside quoted values".to_string()
                    );
                }
                if qc == '\\' {
                    if *i + 1 >= chars.len() {
                        return Err("Trailing backslash in quoted safety rule value".to_string());
                    }
                    let next = chars[*i + 1];
                    if next.is_control() {
                        return Err(
                            "Control characters are not allowed inside quoted values".to_string()
                        );
                    }
                    text.push(next);
                    *i += 2;
                    continue;
                }
                if qc == '"' {
                    q_closed = true;
                    *i += 1;
                    break;
                }
                text.push(qc);
                *i += 1;
            }
            if !q_closed {
                return Err("Unclosed quote in safety rule `IN (...)` list".to_string());
            }
            if *i < chars.len() && !chars[*i].is_whitespace() && !matches!(chars[*i], ',' | ')') {
                return Err("Unexpected trailing characters after quoted item in `IN (...)`".to_string());
            }
            items.push((text, true));
            saw_comma = false;
        } else {
            let mut text = String::new();
            while *i < chars.len() {
                let uc = chars[*i];
                if uc.is_whitespace() || matches!(uc, ',' | '(' | ')') {
                    break;
                }
                if uc == '"' {
                    return Err("Unexpected quote inside unquoted item in `IN (...)`".to_string());
                }
                text.push(uc);
                *i += 1;
            }
            items.push((text, false));
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

    // Optional trailing `>= <score>` outside `)`
    let after_rparen = *i;
    skip_ws_chars(chars, i);
    let trailing_score = if *i + 1 < chars.len() && chars[*i] == '>' && chars[*i + 1] == '=' {
        *i += 2;
        skip_ws_chars(chars, i);
        let mut score_str = String::new();
        while *i < chars.len() {
            let sc = chars[*i];
            if sc.is_whitespace() || matches!(sc, '(' | ')' | '"') {
                break;
            }
            score_str.push(sc);
            *i += 1;
        }
        Some(score_str)
    } else {
        *i = after_rparen;
        None
    };

    Ok(Some(InListToken {
        prefix: prefix.to_string(),
        negated_in,
        items,
        trailing_score,
    }))
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    if input.len() > MAX_RULE_LEN {
        return Err(format!(
            "Safety rule exceeds maximum length of {MAX_RULE_LEN} bytes"
        ));
    }
    if input
        .chars()
        .any(|c| c == '\0' || (c.is_control() && !matches!(c, ' ' | '\t' | '\n' | '\r')))
    {
        return Err("Control characters are not allowed in safety rules".to_string());
    }

    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        if ch == '(' {
            tokens.push(Token::LParen);
            i += 1;
            continue;
        }
        if ch == ')' {
            tokens.push(Token::RParen);
            i += 1;
            continue;
        }
        if ch == '"' {
            return Err("Bare quoted text is not allowed — prefix with tag:, post_tag:, or author:".to_string());
        }

        // Read prefix up to `:`, whitespace, `(`, `)`, or `"`.
        let mut prefix = String::new();
        while i < chars.len() {
            let c = chars[i];
            if c == ':' || c.is_whitespace() || c == '(' || c == ')' {
                break;
            }
            if c == '"' {
                return Err("Unexpected quote in safety rule predicate name".to_string());
            }
            prefix.push(c);
            i += 1;
        }

        if i < chars.len() && chars[i] == ':' {
            i += 1; // consume ':'
            let rest = if i < chars.len() && chars[i] == '"' {
                i += 1; // consume opening quote
                let mut text = String::new();
                let mut closed = false;
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_control() {
                        return Err("Control characters are not allowed inside quoted values".to_string());
                    }
                    if c == '\\' {
                        if i + 1 >= chars.len() {
                            return Err("Trailing backslash in quoted safety rule value".to_string());
                        }
                        let next = chars[i + 1];
                        if next.is_control() {
                            return Err("Control characters are not allowed inside quoted values".to_string());
                        }
                        text.push(next);
                        i += 2;
                        continue;
                    }
                    if c == '"' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    text.push(c);
                    i += 1;
                }
                if !closed {
                    return Err("Unclosed quote in safety rule query".to_string());
                }
                let mut trailing = String::new();
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_whitespace() || c == '(' || c == ')' {
                        break;
                    }
                    if c == '"' {
                        return Err("Unexpected extra quote after value".to_string());
                    }
                    trailing.push(c);
                    i += 1;
                }
                AtomValue {
                    text,
                    quoted: true,
                    trailing,
                }
            } else {
                let mut text = String::new();
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_whitespace() || c == '(' || c == ')' {
                        break;
                    }
                    if c == '"' {
                        return Err("Quote must immediately follow `:` (e.g. tag:\"my tag\")".to_string());
                    }
                    text.push(c);
                    i += 1;
                }
                AtomValue {
                    text,
                    quoted: false,
                    trailing: String::new(),
                }
            };

            tokens.push(Token::Atom(AtomToken {
                prefix,
                rest: Some(rest),
            }));
        } else {
            match prefix.as_str() {
                "AND" | "and" => tokens.push(Token::And),
                "OR" | "or" => tokens.push(Token::Or),
                "NOT" | "not" => tokens.push(Token::Not),
                _ => {
                    if let Some(in_list) = try_consume_in_list_rule(&chars, &mut i, &prefix)? {
                        tokens.push(Token::InList(in_list));
                    } else {
                        tokens.push(Token::Atom(AtomToken { prefix, rest: None }));
                    }
                }
            }
        }
    }

    Ok(tokens)
}

fn looks_like_regex_literal(raw: &str) -> bool {
    if !raw.starts_with('/') || raw.len() < 2 {
        return false;
    }
    let Some(last_slash) = raw[1..].rfind('/') else {
        return false;
    };
    let flags = &raw[1 + last_slash + 1..];
    flags.chars().all(|c| c.is_ascii_alphabetic())
}

fn has_single_eq_numeric_threshold(raw: &str) -> bool {
    if let Some((lhs, rhs)) = raw.rsplit_once('=')
        && !lhs.is_empty()
        && !lhs.ends_with(['>', '<', '~', '!'])
        && !rhs.is_empty()
        && rhs.parse::<f32>().is_ok_and(f32::is_finite)
    {
        return true;
    }
    false
}

fn parse_threshold_score(score_raw: &str) -> Result<f32, String> {
    let trimmed = score_raw.trim();
    if trimmed.is_empty() {
        return Err("Missing confidence score after `>=`".to_string());
    }
    let score: f32 = trimmed
        .parse()
        .map_err(|_| format!("Invalid min score `{trimmed}` (expected a number in (0.0, 1.0])"))?;
    if !is_valid_score(score) {
        return Err(format!(
            "Min score `{trimmed}` out of range (must be > 0.0 and <= 1.0)"
        ));
    }
    Ok(score)
}

fn reject_disallowed_unquoted_syntax(raw: &str, field_name: &str) -> Result<(), String> {
    if looks_like_regex_literal(raw) {
        return Err(format!(
            "Regex patterns are not allowed in safety rules (`{field_name}:{raw}`)"
        ));
    }
    if raw.contains("~=")
        || raw.contains("<=")
        || raw.contains("!=")
        || raw.contains('>')
        || raw.contains('<')
    {
        return Err(format!(
            "Unsupported comparator in `{field_name}:{raw}` (only `>=` on `tag:` is allowed)"
        ));
    }
    if has_single_eq_numeric_threshold(raw) {
        return Err(format!(
            "Invalid `=` threshold in `{field_name}:{raw}` (use `>=` on `tag:`, e.g. tag:blood>=0.5)"
        ));
    }
    Ok(())
}

fn parse_atom_to_clause(
    atom: &AtomToken,
    negated: bool,
    next_id: &mut impl FnMut() -> u64,
) -> Result<RuleClause, String> {
    let Some(rest) = &atom.rest else {
        if atom.prefix.eq_ignore_ascii_case("unclassified") {
            return Ok(RuleClause {
                id: next_id(),
                negated,
                field: RuleField::Unclassified,
                value: String::new(),
                min_score: None,
            });
        }
        return Err(format!(
            "Unsupported term `{}` — use tag:, post_tag:, author:, or unclassified",
            atom.prefix
        ));
    };

    let field = RuleField::parse(&atom.prefix).ok_or_else(|| {
        format!(
            "Disallowed predicate `{}:` in safety rules (only tag:, post_tag:, author:, unclassified are allowed)",
            atom.prefix
        )
    })?;

    if field == RuleField::Unclassified {
        return Err("`unclassified` takes no value (write bare `unclassified`)".to_string());
    }

    if field == RuleField::Tag {
        if rest.quoted {
            let trimmed = rest.text.trim();
            if trimmed.is_empty() {
                return Err("Tag name cannot be empty".to_string());
            }
            let min_score = if rest.trailing.is_empty() {
                None
            } else if let Some(score_raw) = rest.trailing.strip_prefix(">=") {
                if score_raw.contains(">=") {
                    return Err("Multiple `>=` thresholds in one tag predicate".to_string());
                }
                Some(parse_threshold_score(score_raw)?)
            } else {
                return Err(format!(
                    "Unexpected suffix `{}` after quoted tag (only `>=score` is supported)",
                    rest.trailing
                ));
            };
            return Ok(RuleClause {
                id: next_id(),
                negated,
                field,
                value: trimmed.to_string(),
                min_score,
            });
        }

        let raw = rest.text.as_str();
        if raw.is_empty() {
            return Err("Missing tag name after `tag:`".to_string());
        }
        if let Some((tag_part, score_part)) = raw.split_once(">=") {
            if score_part.contains(">=") {
                return Err(format!("Multiple `>=` thresholds in `tag:{raw}`"));
            }
            let tag_trimmed = tag_part.trim();
            if tag_trimmed.is_empty() {
                return Err("Tag name cannot be empty before `>=`".to_string());
            }
            reject_disallowed_unquoted_syntax(tag_trimmed, "tag")?;
            let score = parse_threshold_score(score_part)?;
            return Ok(RuleClause {
                id: next_id(),
                negated,
                field,
                value: tag_trimmed.to_string(),
                min_score: Some(score),
            });
        }

        reject_disallowed_unquoted_syntax(raw, "tag")?;
        return Ok(RuleClause {
            id: next_id(),
            negated,
            field,
            value: raw.to_string(),
            min_score: None,
        });
    }

    // `post_tag:` and `author:` never accept thresholds or regexes.
    let field_name = field.as_str();
    if rest.quoted {
        if !rest.trailing.is_empty() {
            return Err(format!(
                "Thresholds or suffixes (`{}`) are not supported on `{field_name}:`",
                rest.trailing
            ));
        }
        let trimmed = rest.text.trim();
        if trimmed.is_empty() {
            return Err(format!("Missing value after `{field_name}:`"));
        }
        return Ok(RuleClause {
            id: next_id(),
            negated,
            field,
            value: trimmed.to_string(),
            min_score: None,
        });
    }

    let raw = rest.text.trim();
    if raw.is_empty() {
        return Err(format!("Missing value after `{field_name}:`"));
    }
    if raw.contains(">=") {
        return Err(format!(
            "Score thresholds are only supported on `tag:`, not `{field_name}:`"
        ));
    }
    reject_disallowed_unquoted_syntax(raw, field_name)?;

    Ok(RuleClause {
        id: next_id(),
        negated,
        field,
        value: raw.to_string(),
        min_score: None,
    })
}

fn parse_in_list_to_clauses(
    in_list: &InListToken,
    outer_negated: bool,
    next_id: &mut impl FnMut() -> u64,
) -> Result<(bool, Vec<RuleClause>), String> {
    if outer_negated && in_list.negated_in {
        return Err("Double negation (`NOT ... NOT IN`) is not allowed".to_string());
    }
    let field = RuleField::parse(&in_list.prefix).ok_or_else(|| {
        format!(
            "Disallowed predicate `{}` in `IN (...)` safety rule (allowed: tag, post_tag, author)",
            in_list.prefix
        )
    })?;
    if field == RuleField::Unclassified {
        return Err("`unclassified` does not support `IN (...)`".to_string());
    }
    let min_score = match &in_list.trailing_score {
        None => None,
        Some(raw) => {
            if field != RuleField::Tag {
                return Err(format!(
                    "Score thresholds are only supported on `tag`, not `{}`",
                    field.as_str()
                ));
            }
            Some(parse_threshold_score(raw)?)
        }
    };
    let mut clauses = Vec::with_capacity(in_list.items.len());
    for (raw_val, quoted) in &in_list.items {
        let trimmed = raw_val.trim();
        if trimmed.is_empty() {
            return Err("Empty value inside `IN (...)` list is not allowed".to_string());
        }
        if !*quoted {
            if trimmed.contains(">=") {
                return Err(
                    "Place `>=` threshold outside `)` (e.g. `tag IN (a, b) >= 0.45`)".to_string(),
                );
            }
            reject_disallowed_unquoted_syntax(trimmed, field.as_str())?;
        }
        clauses.push(RuleClause {
            id: next_id(),
            negated: false,
            field,
            value: trimmed.to_string(),
            min_score,
        });
    }
    Ok((outer_negated || in_list.negated_in, clauses))
}

/// Parse a flat or single-level-parenthesized metadata-only safety rule query
/// into visual [`RuleBlock`] items, enforcing the same strict grammar rules and
/// limits as `search_types::safety`.
pub fn parse_safety_rule_to_blocks(
    query: &str,
    next_id: &mut impl FnMut() -> u64,
) -> Result<Vec<RuleBlock>, String> {
    if query.len() > MAX_RULE_LEN {
        return Err(format!(
            "Safety rule exceeds maximum length of {MAX_RULE_LEN} bytes"
        ));
    }
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let tokens = tokenize(trimmed)?;
    let mut blocks = Vec::new();
    let mut term_count = 0usize;
    let mut pos = 0usize;
    let mut expect_operand = true;
    let mut pending_conn = RuleConnector::And;
    let mut pending_neg = false;

    while pos < tokens.len() {
        if !expect_operand {
            match &tokens[pos] {
                Token::And => {
                    pending_conn = RuleConnector::And;
                    pending_neg = false;
                    expect_operand = true;
                    pos += 1;
                }
                Token::Or => {
                    pending_conn = RuleConnector::Or;
                    pending_neg = false;
                    expect_operand = true;
                    pos += 1;
                }
                Token::RParen => {
                    return Err("Unexpected `)` in safety rule query".to_string());
                }
                Token::Not | Token::Atom(_) | Token::InList(_) | Token::LParen => {
                    return Err(
                        "Missing explicit `AND` or `OR` operator between predicates".to_string()
                    );
                }
            }
            continue;
        }

        match &tokens[pos] {
            Token::And | Token::Or => {
                return Err("Unexpected binary operator (`AND`/`OR`) without left operand".to_string());
            }
            Token::RParen => {
                return Err("Unexpected `)` in safety rule query".to_string());
            }
            Token::Not => {
                if pending_neg {
                    return Err("Duplicate `NOT` operator is not allowed".to_string());
                }
                pending_neg = true;
                pos += 1;
            }
            Token::LParen => {
                if pending_conn == RuleConnector::Or && pending_neg {
                    return Err(
                        "Negated OR-group (`OR NOT (...)`) is not supported directly — negate inner clauses instead".to_string(),
                    );
                }
                pos += 1;
                let mut clauses = Vec::new();
                let mut group_comb: Option<RuleGroupCombinator> = None;
                let mut inner_expect_operand = true;
                let mut inner_neg = false;
                let mut closed = false;

                while pos < tokens.len() {
                    if !inner_expect_operand {
                        match &tokens[pos] {
                            Token::RParen => {
                                pos += 1;
                                closed = true;
                                break;
                            }
                            Token::Or => {
                                if group_comb == Some(RuleGroupCombinator::And) {
                                    return Err(
                                        "Cannot mix `AND` and `OR` inside one visual group"
                                            .to_string(),
                                    );
                                }
                                group_comb = Some(RuleGroupCombinator::Or);
                                inner_expect_operand = true;
                                inner_neg = false;
                                pos += 1;
                            }
                            Token::And => {
                                if group_comb == Some(RuleGroupCombinator::Or) {
                                    return Err(
                                        "Cannot mix `OR` and `AND` inside one visual group"
                                            .to_string(),
                                    );
                                }
                                group_comb = Some(RuleGroupCombinator::And);
                                inner_expect_operand = true;
                                inner_neg = false;
                                pos += 1;
                            }
                            Token::Not | Token::Atom(_) | Token::InList(_) | Token::LParen => {
                                return Err(
                                    "Missing explicit `AND` or `OR` inside `(...)` group"
                                        .to_string(),
                                );
                            }
                        }
                        continue;
                    }

                    match &tokens[pos] {
                        Token::RParen => {
                            if clauses.is_empty() && !inner_neg {
                                return Err("Empty `()` group in safety rule query".to_string());
                            }
                            return Err("Trailing operator before `)` in group".to_string());
                        }
                        Token::LParen => {
                            return Err(
                                "Nested parentheses inside group are not editable in visual mode"
                                    .to_string(),
                            );
                        }
                        Token::And | Token::Or => {
                            return Err("Unexpected `AND`/`OR` operator inside group".to_string());
                        }
                        Token::Not => {
                            if inner_neg {
                                return Err("Duplicate `NOT` operator inside group".to_string());
                            }
                            inner_neg = true;
                            pos += 1;
                        }
                        Token::Atom(atom) => {
                            term_count += 1;
                            if term_count > MAX_TERMS_PER_RULE {
                                return Err(format!(
                                    "Safety rule exceeds maximum of {MAX_TERMS_PER_RULE} terms"
                                ));
                            }
                            clauses.push(parse_atom_to_clause(atom, inner_neg, next_id)?);
                            inner_neg = false;
                            inner_expect_operand = false;
                            pos += 1;
                        }
                        Token::InList(in_list) => {
                            term_count += in_list.items.len();
                            if term_count > MAX_TERMS_PER_RULE {
                                return Err(format!(
                                    "Safety rule exceeds maximum of {MAX_TERMS_PER_RULE} terms"
                                ));
                            }
                            let (neg, mut list_clauses) =
                                parse_in_list_to_clauses(in_list, inner_neg, next_id)?;
                            if list_clauses.len() == 1 {
                                let mut only = list_clauses.remove(0);
                                only.negated = neg;
                                clauses.push(only);
                            } else if !neg && group_comb != Some(RuleGroupCombinator::And) {
                                group_comb = Some(RuleGroupCombinator::Or);
                                clauses.extend(list_clauses);
                            } else {
                                return Err(
                                    "Nested `IN (...)` inside incompatible group requires top-level list".to_string(),
                                );
                            }
                            inner_neg = false;
                            inner_expect_operand = false;
                            pos += 1;
                        }
                    }
                }
                if !closed {
                    return Err("Unclosed `(` in safety rule query".to_string());
                }
                if clauses.is_empty() {
                    return Err("Empty `()` group in safety rule query".to_string());
                }
                let block_conn = if pending_neg {
                    RuleConnector::Not
                } else {
                    pending_conn
                };
                blocks.push(RuleBlock {
                    id: next_id(),
                    connector: block_conn,
                    kind: RuleBlockKind::Group {
                        combinator: group_comb.unwrap_or(RuleGroupCombinator::Or),
                        clauses,
                    },
                });
                pending_conn = RuleConnector::And;
                pending_neg = false;
                expect_operand = false;
            }
            Token::Atom(atom) => {
                term_count += 1;
                if term_count > MAX_TERMS_PER_RULE {
                    return Err(format!(
                        "Safety rule exceeds maximum of {MAX_TERMS_PER_RULE} terms"
                    ));
                }
                // Preserve `OR NOT <clause>` accurately instead of silently collapsing to `AND NOT`.
                let (block_conn, clause_neg) = match (pending_conn, pending_neg) {
                    (RuleConnector::Or, true) => (RuleConnector::Or, true),
                    (RuleConnector::Or, false) => (RuleConnector::Or, false),
                    (_, true) => (RuleConnector::Not, false),
                    (c, false) => (c, false),
                };
                let clause = parse_atom_to_clause(atom, clause_neg, next_id)?;
                blocks.push(RuleBlock {
                    id: next_id(),
                    connector: block_conn,
                    kind: RuleBlockKind::Clause(clause),
                });
                pending_conn = RuleConnector::And;
                pending_neg = false;
                expect_operand = false;
                pos += 1;
            }
            Token::InList(in_list) => {
                term_count += in_list.items.len();
                if term_count > MAX_TERMS_PER_RULE {
                    return Err(format!(
                        "Safety rule exceeds maximum of {MAX_TERMS_PER_RULE} terms"
                    ));
                }
                let (is_negated, mut list_clauses) =
                    parse_in_list_to_clauses(in_list, pending_neg, next_id)?;
                if pending_conn == RuleConnector::Or && is_negated && list_clauses.len() > 1 {
                    return Err(
                        "Negated OR-list (`OR ... NOT IN (...)`) is not supported directly in legacy rule blocks"
                            .to_string(),
                    );
                }
                let block_conn = match (pending_conn, is_negated) {
                    (RuleConnector::Or, true) => RuleConnector::Or,
                    (RuleConnector::Or, false) => RuleConnector::Or,
                    (_, true) => RuleConnector::Not,
                    (c, false) => c,
                };
                let kind = if list_clauses.len() == 1 {
                    let mut only = list_clauses.remove(0);
                    if pending_conn == RuleConnector::Or && is_negated {
                        only.negated = true;
                    }
                    RuleBlockKind::Clause(only)
                } else {
                    RuleBlockKind::Group {
                        combinator: RuleGroupCombinator::Or,
                        clauses: list_clauses,
                    }
                };
                blocks.push(RuleBlock {
                    id: next_id(),
                    connector: block_conn,
                    kind,
                });
                pending_conn = RuleConnector::And;
                pending_neg = false;
                expect_operand = false;
                pos += 1;
            }
        }
    }

    if expect_operand {
        return Err("Incomplete expression — trailing operator without predicate".to_string());
    }

    Ok(blocks)
}
