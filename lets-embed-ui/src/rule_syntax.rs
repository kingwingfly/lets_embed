use crate::models::{RuleBlock, RuleBlockKind, RuleClause, RuleConnector, RuleField, RuleGroupCombinator};

/// Format a confidence score cleanly without trailing zeroes (e.g. `0.45`, `0.5`, `1`).
pub fn format_score(score: f32) -> String {
    let clamped = score.clamp(0.0, 1.0);
    let rounded = (clamped * 100.0).round() / 100.0;
    let s = format!("{rounded:.2}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn quote_value_if_needed(raw: &str) -> String {
    let needs_quote = raw.chars().any(|c| {
        c.is_whitespace() || matches!(c, '(' | ')' | '"' | '>' | '=' | ':' | ',')
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
                Some(score) if score.is_finite() => {
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
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Atom(String),
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
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

        // Read one atom, honoring quoted segments like `author:"foo bar"` or `tag:"a b">=0.5`.
        let mut buf = String::new();
        let mut in_quotes = false;
        while i < chars.len() {
            let c = chars[i];
            if in_quotes {
                if c == '\\' && i + 1 < chars.len() {
                    buf.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if c == '"' {
                    in_quotes = false;
                    i += 1;
                    continue;
                }
                buf.push(c);
                i += 1;
            } else {
                if c.is_whitespace() || c == '(' || c == ')' {
                    break;
                }
                if c == '"' {
                    in_quotes = true;
                    i += 1;
                    continue;
                }
                buf.push(c);
                i += 1;
            }
        }
        if in_quotes {
            return Err("Unclosed quote in safety rule query".to_string());
        }
        match buf.as_str() {
            "AND" | "and" => tokens.push(Token::And),
            "OR" | "or" => tokens.push(Token::Or),
            "NOT" | "not" => tokens.push(Token::Not),
            _ => tokens.push(Token::Atom(buf)),
        }
    }

    Ok(tokens)
}

fn parse_atom_to_clause(atom: &str, negated: bool, next_id: &mut impl FnMut() -> u64) -> Result<RuleClause, String> {
    if atom.eq_ignore_ascii_case("unclassified") {
        return Ok(RuleClause {
            id: next_id(),
            negated,
            field: RuleField::Unclassified,
            value: String::new(),
            min_score: None,
        });
    }

    let Some((prefix, rest)) = atom.split_once(':') else {
        return Err(format!(
            "Unsupported term `{atom}` — use tag:, post_tag:, author:, or unclassified"
        ));
    };

    let field = RuleField::parse(prefix).ok_or_else(|| {
        format!(
            "Disallowed predicate `{prefix}:` in safety rules (only tag:, post_tag:, author:, unclassified are allowed)"
        )
    })?;

    if field == RuleField::Unclassified {
        return Ok(RuleClause {
            id: next_id(),
            negated,
            field,
            value: String::new(),
            min_score: None,
        });
    }

    if field == RuleField::Tag
        && let Some((tag_name, score_raw)) = rest.rsplit_once(">=")
    {
        let tag_trimmed = tag_name.trim();
        if tag_trimmed.is_empty() {
            return Err("Tag name cannot be empty before `>=`".to_string());
        }
        let score: f32 = score_raw
            .trim()
            .parse()
            .map_err(|_| format!("Invalid min score `{score_raw}` (expected 0.00–1.00)"))?;
        if !(0.0..=1.0).contains(&score) || !score.is_finite() {
            return Err(format!(
                "Min score `{score}` out of range (expected 0.00–1.00)"
            ));
        }
        return Ok(RuleClause {
            id: next_id(),
            negated,
            field,
            value: tag_trimmed.to_string(),
            min_score: Some(score),
        });
    }

    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return Err(format!("Missing value after `{prefix}:`"));
    }

    Ok(RuleClause {
        id: next_id(),
        negated,
        field,
        value: trimmed.to_string(),
        min_score: None,
    })
}

/// Parse a flat or single-level-parenthesized metadata-only safety rule query
/// into visual [`RuleBlock`] items.
pub fn parse_safety_rule_to_blocks(
    query: &str,
    next_id: &mut impl FnMut() -> u64,
) -> Result<Vec<RuleBlock>, String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let tokens = tokenize(trimmed)?;
    let mut blocks = Vec::new();
    let mut pos = 0;
    let mut pending_conn = RuleConnector::And;

    while pos < tokens.len() {
        match &tokens[pos] {
            Token::And => {
                pending_conn = RuleConnector::And;
                pos += 1;
            }
            Token::Or => {
                pending_conn = RuleConnector::Or;
                pos += 1;
            }
            Token::Not => {
                pending_conn = RuleConnector::Not;
                pos += 1;
            }
            Token::LParen => {
                pos += 1;
                let mut clauses = Vec::new();
                let mut group_comb: Option<RuleGroupCombinator> = None;
                let mut inner_neg = false;
                let mut closed = false;

                while pos < tokens.len() {
                    match &tokens[pos] {
                        Token::RParen => {
                            pos += 1;
                            closed = true;
                            break;
                        }
                        Token::LParen => {
                            return Err("Nested parentheses inside group are not editable in visual mode".to_string());
                        }
                        Token::Or => {
                            if group_comb == Some(RuleGroupCombinator::And) {
                                return Err("Cannot mix AND and OR inside one visual group".to_string());
                            }
                            group_comb = Some(RuleGroupCombinator::Or);
                            pos += 1;
                        }
                        Token::And => {
                            if group_comb == Some(RuleGroupCombinator::Or) {
                                return Err("Cannot mix OR and AND inside one visual group".to_string());
                            }
                            group_comb = Some(RuleGroupCombinator::And);
                            pos += 1;
                        }
                        Token::Not => {
                            inner_neg = !inner_neg;
                            pos += 1;
                        }
                        Token::Atom(atom) => {
                            clauses.push(parse_atom_to_clause(atom, inner_neg, next_id)?);
                            inner_neg = false;
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
                blocks.push(RuleBlock {
                    id: next_id(),
                    connector: pending_conn,
                    kind: RuleBlockKind::Group {
                        combinator: group_comb.unwrap_or(RuleGroupCombinator::Or),
                        clauses,
                    },
                });
                pending_conn = RuleConnector::And;
            }
            Token::RParen => {
                return Err("Unexpected `)` in safety rule query".to_string());
            }
            Token::Atom(atom) => {
                let clause = parse_atom_to_clause(atom, false, next_id)?;
                blocks.push(RuleBlock {
                    id: next_id(),
                    connector: pending_conn,
                    kind: RuleBlockKind::Clause(clause),
                });
                pending_conn = RuleConnector::And;
                pos += 1;
            }
        }
    }

    Ok(blocks)
}
