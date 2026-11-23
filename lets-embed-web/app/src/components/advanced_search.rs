use crate::components::{
    SelectOption, SelectVariant, SkySelect,
    search_bar::{
        DEFAULT_LIMIT, SearchSuggestion, UrlSearchState, encode_image_file, fetch_suggestions,
        should_suggest_field,
    },
};
use crate::types::{
    AdvancedUploads, AdvancedUploadsPayload, ImageQuery, Mode, SafetyUiState, UploadedImageSlot,
};
#[cfg(feature = "hydrate")]
use crate::util::trap_dialog_tab;
use crate::util::{lock_body_scroll, navigate_from_modal, push_modal_history};
#[cfg(feature = "hydrate")]
use leptos::ev;
use leptos::{html, prelude::*, task::spawn_local};
use leptos_router::{NavigateOptions, hooks::use_navigate};
#[cfg(feature = "hydrate")]
use leptos_use_event_listener::use_event_listener;
use leptos_use_signal_debounce_throttle::signal_debounced;
use lets_embed_ui::MinSimilaritySlider;
use search_types::query::{
    AdvancedSort, QueryExpr, QueryPlan, ResultKind, SearchField, VectorTier, parse_and_compile,
    parse_query,
};
#[cfg(feature = "hydrate")]
use wasm_bindgen::{JsCast as _, JsValue};

const QUICK_EXAMPLES: &[(&str, &str)] = &[
    (
        "Maid or apron (no monochrome)",
        "(tag:maid OR tag:apron) NOT tag:monochrome",
    ),
    (
        "Tag + CLIP scene",
        "tag:blue_sky AND clip:\"sunlit coastal breeze\"",
    ),
    (
        "Author posts without preview",
        "author:渡久山 NOT title:预告",
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Connector {
    /// Positive match ("Match" on row 0, "AND" on rows 1+).
    And,
    /// Disjunction ("OR" on rows 1+; disabled on vector rows).
    Or,
    /// Negation ("NOT" on row 0 and rows 1+, conjoined with AND).
    Not,
}

impl Connector {
    const fn as_str(self) -> &'static str {
        match self {
            Self::And => "and",
            Self::Or => "or",
            Self::Not => "not",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "or" => Self::Or,
            "not" => Self::Not,
            _ => Self::And,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupCombinator {
    Or,
    And,
}

impl GroupCombinator {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Or => "or",
            Self::And => "and",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuilderRow {
    pub id: u64,
    pub field: SearchField,
    pub value: String,
    pub upload: Option<UploadedImageSlot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InnerRow {
    pub id: u64,
    pub negated: bool,
    pub field: SearchField,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BuilderItemKind {
    Row(BuilderRow),
    Group {
        combinator: GroupCombinator,
        rows: Vec<InnerRow>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuilderItem {
    pub id: u64,
    pub connector: Connector,
    pub kind: BuilderItemKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ValidationState {
    Empty,
    Valid(QueryPlan),
    Error(String),
}

fn field_placeholder(field: SearchField) -> &'static str {
    match field {
        SearchField::Tag => "Tag or alias (EN / 中文 / 日本語)…",
        SearchField::Author => "Author name…",
        SearchField::Title => "Post title keyword…",
        SearchField::All => "Post title or author…",
        SearchField::Clip => "Describe scene, lighting, mood…",
        SearchField::Dino => "Image ID (e.g. 2286979)",
        SearchField::Upload => "Choose an image…",
    }
}

fn preview_url_from_urlsafe_b64(url_safe: &str) -> String {
    let mut std_b64 = url_safe.replace('-', "+").replace('_', "/");
    while !std_b64.len().is_multiple_of(4) {
        std_b64.push('=');
    }
    format!("data:image/webp;base64,{std_b64}")
}

/// Convert visual builder items into a `QueryExpr` AST plus the ordered list of uploaded slots.
pub(crate) fn builder_to_expr(
    items: &[BuilderItem],
) -> (Option<QueryExpr>, Vec<UploadedImageSlot>) {
    let mut slots: Vec<UploadedImageSlot> = Vec::new();
    let mut or_branches: Vec<Vec<QueryExpr>> = Vec::new();
    let mut current_and: Vec<QueryExpr> = Vec::new();

    for item in items {
        let base_expr = match &item.kind {
            BuilderItemKind::Row(row) => {
                if row.field == SearchField::Upload {
                    if let Some(slot) = &row.upload {
                        let idx = slots.len();
                        slots.push(slot.clone());
                        Some(QueryExpr::Term {
                            field: SearchField::Upload,
                            value: idx.to_string(),
                        })
                    } else {
                        // Never emit a raw slot index for an unattached Upload row, or it
                        // could collide with an attached slot index (e.g. `upload:0`).
                        None
                    }
                } else {
                    let trimmed = row.value.trim();
                    (!trimmed.is_empty()).then(|| QueryExpr::Term {
                        field: row.field,
                        value: trimmed.to_string(),
                    })
                }
            }
            BuilderItemKind::Group { combinator, rows } => {
                let mut inner_exprs = Vec::new();
                for r in rows {
                    let trimmed = r.value.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let term = QueryExpr::Term {
                        field: r.field,
                        value: trimmed.to_string(),
                    };
                    inner_exprs.push(if r.negated {
                        QueryExpr::Not(Box::new(term))
                    } else {
                        term
                    });
                }
                match inner_exprs.len() {
                    0 => None,
                    1 => inner_exprs.pop(),
                    _ => Some(match combinator {
                        GroupCombinator::Or => QueryExpr::Or(inner_exprs),
                        GroupCombinator::And => QueryExpr::And(inner_exprs),
                    }),
                }
            }
        };

        let Some(expr) = base_expr else {
            continue;
        };

        match item.connector {
            Connector::And => current_and.push(expr),
            Connector::Not => current_and.push(QueryExpr::Not(Box::new(expr))),
            Connector::Or => {
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

    let mut collapsed: Vec<QueryExpr> = or_branches
        .into_iter()
        .filter_map(|mut terms| match terms.len() {
            0 => None,
            1 => terms.pop(),
            _ => Some(QueryExpr::And(terms)),
        })
        .collect();

    let expr = match collapsed.len() {
        0 => None,
        1 => collapsed.pop(),
        _ => Some(QueryExpr::Or(collapsed)),
    };

    (expr, slots)
}

pub(crate) fn format_builder_to_query(items: &[BuilderItem]) -> (String, Vec<UploadedImageSlot>) {
    let (expr, slots) = builder_to_expr(items);
    let query = expr.map(|e| e.format_query()).unwrap_or_default();
    (query, slots)
}

fn term_to_builder_row(
    field: SearchField,
    value: &str,
    slots: &[Option<UploadedImageSlot>],
    next_id: &mut impl FnMut() -> u64,
) -> BuilderRow {
    let upload = if field == SearchField::Upload {
        value
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|idx| slots.get(idx).cloned().flatten())
    } else {
        None
    };
    BuilderRow {
        id: next_id(),
        field,
        value: value.to_string(),
        upload,
    }
}

fn exprs_to_inner_rows(
    exprs: &[QueryExpr],
    next_id: &mut impl FnMut() -> u64,
) -> Option<Vec<InnerRow>> {
    let mut out = Vec::with_capacity(exprs.len());
    for e in exprs {
        match e {
            QueryExpr::Term { field, value } if !field.is_vector() => {
                out.push(InnerRow {
                    id: next_id(),
                    negated: false,
                    field: *field,
                    value: value.clone(),
                });
            }
            QueryExpr::Not(inner) => match inner.as_ref() {
                QueryExpr::Term { field, value } if !field.is_vector() => {
                    out.push(InnerRow {
                        id: next_id(),
                        negated: true,
                        field: *field,
                        value: value.clone(),
                    });
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    Some(out)
}

fn and_child_to_item(
    expr: &QueryExpr,
    slots: &[Option<UploadedImageSlot>],
    next_id: &mut impl FnMut() -> u64,
) -> Option<BuilderItem> {
    match expr {
        QueryExpr::Term { field, value } => Some(BuilderItem {
            id: next_id(),
            connector: Connector::And,
            kind: BuilderItemKind::Row(term_to_builder_row(*field, value, slots, next_id)),
        }),
        QueryExpr::Not(inner) => match inner.as_ref() {
            QueryExpr::Term { field, value } => Some(BuilderItem {
                id: next_id(),
                connector: Connector::Not,
                kind: BuilderItemKind::Row(term_to_builder_row(*field, value, slots, next_id)),
            }),
            QueryExpr::Or(children) => Some(BuilderItem {
                id: next_id(),
                connector: Connector::Not,
                kind: BuilderItemKind::Group {
                    combinator: GroupCombinator::Or,
                    rows: exprs_to_inner_rows(children, next_id)?,
                },
            }),
            QueryExpr::And(children) => Some(BuilderItem {
                id: next_id(),
                connector: Connector::Not,
                kind: BuilderItemKind::Group {
                    combinator: GroupCombinator::And,
                    rows: exprs_to_inner_rows(children, next_id)?,
                },
            }),
            QueryExpr::Not(_) => None,
        },
        QueryExpr::Or(children) => Some(BuilderItem {
            id: next_id(),
            connector: Connector::And,
            kind: BuilderItemKind::Group {
                combinator: GroupCombinator::Or,
                rows: exprs_to_inner_rows(children, next_id)?,
            },
        }),
        QueryExpr::And(children) => Some(BuilderItem {
            id: next_id(),
            connector: Connector::And,
            kind: BuilderItemKind::Group {
                combinator: GroupCombinator::And,
                rows: exprs_to_inner_rows(children, next_id)?,
            },
        }),
    }
}

fn or_branch_lead_to_item(
    expr: &QueryExpr,
    is_first_branch: bool,
    slots: &[Option<UploadedImageSlot>],
    next_id: &mut impl FnMut() -> u64,
) -> Option<BuilderItem> {
    if is_first_branch {
        return and_child_to_item(expr, slots, next_id);
    }
    match expr {
        QueryExpr::Term { field, value } => Some(BuilderItem {
            id: next_id(),
            connector: Connector::Or,
            kind: BuilderItemKind::Row(term_to_builder_row(*field, value, slots, next_id)),
        }),
        QueryExpr::Not(inner) => match inner.as_ref() {
            QueryExpr::Term { field, value } if !field.is_vector() => Some(BuilderItem {
                id: next_id(),
                connector: Connector::Or,
                kind: BuilderItemKind::Group {
                    combinator: GroupCombinator::And,
                    rows: vec![InnerRow {
                        id: next_id(),
                        negated: true,
                        field: *field,
                        value: value.clone(),
                    }],
                },
            }),
            _ => None,
        },
        QueryExpr::Or(children) => Some(BuilderItem {
            id: next_id(),
            connector: Connector::Or,
            kind: BuilderItemKind::Group {
                combinator: GroupCombinator::Or,
                rows: exprs_to_inner_rows(children, next_id)?,
            },
        }),
        QueryExpr::And(children) => Some(BuilderItem {
            id: next_id(),
            connector: Connector::Or,
            kind: BuilderItemKind::Group {
                combinator: GroupCombinator::And,
                rows: exprs_to_inner_rows(children, next_id)?,
            },
        }),
    }
}

fn is_compound_expr(expr: &QueryExpr) -> bool {
    match expr {
        QueryExpr::And(_) | QueryExpr::Or(_) => true,
        QueryExpr::Not(inner) => !matches!(inner.as_ref(), QueryExpr::Term { .. }),
        QueryExpr::Term { .. } => false,
    }
}

/// Convert a parsed 1–2 level `QueryExpr` back into Visual Builder items.
/// Returns `None` for deeply nested or non-standard expressions so the UI can show
/// a `"Custom nested query — edit in raw box"` badge without losing the raw text.
pub(crate) fn expr_to_builder(
    expr: &QueryExpr,
    slots: &[Option<UploadedImageSlot>],
    next_id: &mut impl FnMut() -> u64,
) -> Option<Vec<BuilderItem>> {
    match expr {
        QueryExpr::Term { .. } | QueryExpr::Not(_) => {
            Some(vec![and_child_to_item(expr, slots, next_id)?])
        }
        QueryExpr::And(children) => children
            .iter()
            .map(|c| and_child_to_item(c, slots, next_id))
            .collect(),
        QueryExpr::Or(branches) => {
            let mut items = Vec::with_capacity(branches.len());
            for (i, branch) in branches.iter().enumerate() {
                let is_first = i == 0;
                let conn = if is_first {
                    Connector::And
                } else {
                    Connector::Or
                };
                match branch {
                    QueryExpr::Term { .. } | QueryExpr::Not(_) | QueryExpr::Or(_) => {
                        items.push(or_branch_lead_to_item(branch, is_first, slots, next_id)?);
                    }
                    QueryExpr::And(children) => {
                        if let Some(rows) = exprs_to_inner_rows(children, next_id) {
                            items.push(BuilderItem {
                                id: next_id(),
                                connector: conn,
                                kind: BuilderItemKind::Group {
                                    combinator: GroupCombinator::And,
                                    rows,
                                },
                            });
                        } else {
                            // Support a single group/conjunction combined with flat terms inside an OR branch,
                            // while still sending multi-group deeply nested expressions to custom raw mode.
                            let compound_count =
                                children.iter().filter(|c| is_compound_expr(c)).count();
                            if compound_count > 1 || children.is_empty() {
                                return None;
                            }
                            items.push(or_branch_lead_to_item(
                                &children[0],
                                is_first,
                                slots,
                                next_id,
                            )?);
                            for child in &children[1..] {
                                items.push(and_child_to_item(child, slots, next_id)?);
                            }
                        }
                    }
                }
            }
            Some(items)
        }
    }
}

fn items_have_vector(items: &[BuilderItem]) -> bool {
    items.iter().any(|it| match &it.kind {
        BuilderItemKind::Row(r) => r.field.is_vector(),
        BuilderItemKind::Group { .. } => false,
    })
}

fn normalize_or_connectors_for_vectors(list: &mut [BuilderItem]) {
    if items_have_vector(list) {
        for it in list.iter_mut() {
            if it.connector == Connector::Or {
                it.connector = Connector::And;
            }
        }
    }
}

fn collect_upload_indices(expr: &QueryExpr, out: &mut std::collections::BTreeSet<usize>) {
    match expr {
        QueryExpr::Term {
            field: SearchField::Upload,
            value,
        } => {
            if let Ok(idx) = value.trim().parse::<usize>() {
                out.insert(idx);
            }
        }
        QueryExpr::Term { .. } => {}
        QueryExpr::Not(inner) => collect_upload_indices(inner, out),
        QueryExpr::And(items) | QueryExpr::Or(items) => {
            for item in items {
                collect_upload_indices(item, out);
            }
        }
    }
}

fn remap_upload_expr(
    expr: &QueryExpr,
    map: &std::collections::HashMap<usize, usize>,
) -> Option<QueryExpr> {
    match expr {
        QueryExpr::Term {
            field: SearchField::Upload,
            value,
        } => {
            let orig = value.trim().parse::<usize>().ok()?;
            let new_idx = *map.get(&orig)?;
            Some(QueryExpr::Term {
                field: SearchField::Upload,
                value: new_idx.to_string(),
            })
        }
        QueryExpr::Term { .. } => Some(expr.clone()),
        QueryExpr::Not(inner) => Some(QueryExpr::Not(Box::new(remap_upload_expr(inner, map)?))),
        QueryExpr::And(items) => {
            let mapped = items
                .iter()
                .map(|it| remap_upload_expr(it, map))
                .collect::<Option<Vec<_>>>()?;
            Some(QueryExpr::And(mapped))
        }
        QueryExpr::Or(items) => {
            let mapped = items
                .iter()
                .map(|it| remap_upload_expr(it, map))
                .collect::<Option<Vec<_>>>()?;
            Some(QueryExpr::Or(mapped))
        }
    }
}

/// Prune unreferenced upload slots and remap `upload:<idx>` terms to contiguous `0..pruned.len()`.
fn prune_and_remap_uploads(
    raw: &str,
    slots: &[Option<UploadedImageSlot>],
) -> Option<(String, Vec<UploadedImageSlot>)> {
    let expr = parse_query(raw.trim()).ok()?;
    let mut referenced = std::collections::BTreeSet::new();
    collect_upload_indices(&expr, &mut referenced);
    if referenced.is_empty() {
        return Some((raw.trim().to_string(), Vec::new()));
    }
    let mut index_map = std::collections::HashMap::with_capacity(referenced.len());
    let mut pruned = Vec::with_capacity(referenced.len());
    for orig_idx in referenced {
        let slot = slots.get(orig_idx)?.as_ref()?;
        if slot.b64.is_empty() {
            return None;
        }
        let new_idx = pruned.len();
        index_map.insert(orig_idx, new_idx);
        pruned.push(slot.clone());
    }
    let remapped = remap_upload_expr(&expr, &index_map)?;
    Some((remapped.format_query(), pruned))
}

fn has_unattached_upload_row(items: &[BuilderItem]) -> bool {
    items.iter().any(|item| {
        matches!(
            &item.kind,
            BuilderItemKind::Row(r) if r.field == SearchField::Upload && r.upload.is_none()
        )
    })
}

/// Reuse existing item/row IDs for structurally matching positions when syncing
/// raw-editor text back into the visual builder so `<For>` never tears down rows per keystroke.
fn reconcile_builder_ids(prev: &[BuilderItem], next: &mut [BuilderItem]) {
    for (old, new_it) in prev.iter().zip(next.iter_mut()) {
        match (&old.kind, &mut new_it.kind) {
            (BuilderItemKind::Row(old_r), BuilderItemKind::Row(new_r)) => {
                new_it.id = old.id;
                new_r.id = old_r.id;
            }
            (
                BuilderItemKind::Group { rows: old_rows, .. },
                BuilderItemKind::Group { rows: new_rows, .. },
            ) => {
                new_it.id = old.id;
                for (old_r, new_r) in old_rows.iter().zip(new_rows.iter_mut()) {
                    new_r.id = old_r.id;
                }
            }
            _ => {}
        }
    }
}

/// Remove an inner row from a group, dropping the group if empty and normalizing
/// any `OR` item shifted to index 0 back to `Connector::And`.
fn remove_group_inner_row(
    list: &mut Vec<BuilderItem>,
    group_id: u64,
    inner_row_id: u64,
    next_id: &mut impl FnMut() -> u64,
) {
    let mut drop_group = false;
    if let Some(it) = list.iter_mut().find(|it| it.id == group_id)
        && let BuilderItemKind::Group { rows, .. } = &mut it.kind
    {
        rows.retain(|r| r.id != inner_row_id);
        if rows.is_empty() {
            drop_group = true;
        }
    }
    if drop_group {
        list.retain(|it| it.id != group_id);
        if list.is_empty() {
            *list = default_blank_items(next_id);
        } else if list[0].connector == Connector::Or {
            list[0].connector = Connector::And;
        }
    }
}

fn validate_raw_query(raw: &str, slots: &[Option<UploadedImageSlot>]) -> ValidationState {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ValidationState::Empty;
    }
    match parse_and_compile(trimmed) {
        Ok((_, plan)) => {
            for idx in plan.upload_pos.iter().chain(plan.upload_neg.iter()) {
                if slots
                    .get(*idx)
                    .and_then(|o| o.as_ref())
                    .is_none_or(|s| s.b64.is_empty())
                {
                    return ValidationState::Error(format!(
                        "Upload slot upload:{idx} has no image attached — upload an image above"
                    ));
                }
            }
            ValidationState::Valid(plan)
        }
        Err(err) => ValidationState::Error(err.to_string()),
    }
}

fn validate_panel_state(
    raw: &str,
    slots: &[Option<UploadedImageSlot>],
    items: &[BuilderItem],
    custom_nested: bool,
    encoding_count: usize,
    upload_err_count: usize,
) -> ValidationState {
    if encoding_count > 0 {
        return ValidationState::Error("Encoding uploaded image\u{2026}".to_string());
    }
    if upload_err_count > 0 {
        return ValidationState::Error(
            "Image upload failed \u{2014} choose another image".to_string(),
        );
    }
    if !custom_nested && has_unattached_upload_row(items) {
        return ValidationState::Error(
            "Choose an image for every Upload Image condition".to_string(),
        );
    }
    validate_raw_query(raw, slots)
}

fn default_blank_items(next_id: &mut impl FnMut() -> u64) -> Vec<BuilderItem> {
    vec![BuilderItem {
        id: next_id(),
        connector: Connector::And,
        kind: BuilderItemKind::Row(BuilderRow {
            id: next_id(),
            field: SearchField::Tag,
            value: String::new(),
            upload: None,
        }),
    }]
}

fn build_initial_state(
    initial_state: Option<UrlSearchState>,
    adv_uploads: Option<AdvancedUploadsPayload>,
    single_image: Option<crate::types::ImageQueryPayload>,
    next_id: &mut impl FnMut() -> u64,
) -> (
    Vec<BuilderItem>,
    String,
    bool,
    Vec<Option<UploadedImageSlot>>,
    AdvancedSort,
    i32,
) {
    let Some(st) = initial_state else {
        return (
            default_blank_items(next_id),
            String::new(),
            false,
            Vec::new(),
            AdvancedSort::Relevance,
            50,
        );
    };

    match st.mode {
        Mode::Advanced if !st.adv.trim().is_empty() => {
            let slots: Vec<Option<UploadedImageSlot>> = adv_uploads
                .filter(|p| !st.img_nonce.is_empty() && p.nonce == st.img_nonce)
                .map(|p| p.slots.into_iter().map(Some).collect())
                .unwrap_or_default();
            let raw = st.adv.trim().to_string();
            match parse_query(&raw) {
                Ok(expr) => match expr_to_builder(&expr, &slots, next_id) {
                    Some(items) => (items, raw, false, slots, st.sort, st.clip_weight),
                    None => (
                        default_blank_items(next_id),
                        raw,
                        true,
                        slots,
                        st.sort,
                        st.clip_weight,
                    ),
                },
                Err(_) => (
                    default_blank_items(next_id),
                    raw,
                    false,
                    slots,
                    st.sort,
                    st.clip_weight,
                ),
            }
        }
        Mode::All | Mode::Title | Mode::Author | Mode::Tag | Mode::Clip | Mode::Similar
            if !st.q.trim().is_empty() =>
        {
            let field = match st.mode {
                Mode::Title => SearchField::Title,
                Mode::Author => SearchField::Author,
                Mode::Tag => SearchField::Tag,
                Mode::Clip => SearchField::Clip,
                Mode::Similar => SearchField::Dino,
                _ => SearchField::All,
            };
            let items = vec![BuilderItem {
                id: next_id(),
                connector: Connector::And,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: next_id(),
                    field,
                    value: st.q.trim().to_string(),
                    upload: None,
                }),
            }];
            let (raw, slots) = format_builder_to_query(&items);
            (
                items,
                raw,
                false,
                slots.into_iter().map(Some).collect(),
                AdvancedSort::Relevance,
                50,
            )
        }
        Mode::SearchImage if !st.q.trim().is_empty() => {
            if let Some(payload) = single_image.filter(|p| p.nonce == st.q) {
                let slot = UploadedImageSlot {
                    filename: "Uploaded image".to_string(),
                    preview_url: preview_url_from_urlsafe_b64(&payload.b64),
                    b64: payload.b64,
                };
                let items = vec![BuilderItem {
                    id: next_id(),
                    connector: Connector::And,
                    kind: BuilderItemKind::Row(BuilderRow {
                        id: next_id(),
                        field: SearchField::Upload,
                        value: "0".to_string(),
                        upload: Some(slot),
                    }),
                }];
                let (raw, slots) = format_builder_to_query(&items);
                (
                    items,
                    raw,
                    false,
                    slots.into_iter().map(Some).collect(),
                    AdvancedSort::Relevance,
                    50,
                )
            } else {
                (
                    default_blank_items(next_id),
                    String::new(),
                    false,
                    Vec::new(),
                    AdvancedSort::Relevance,
                    50,
                )
            }
        }
        _ => (
            default_blank_items(next_id),
            String::new(),
            false,
            Vec::new(),
            AdvancedSort::Relevance,
            50,
        ),
    }
}

fn build_advanced_nav_url(
    raw: &str,
    plan: &QueryPlan,
    sort: AdvancedSort,
    clip_weight: i32,
    min_similarity: Option<f32>,
    img_nonce: Option<&str>,
    limit: usize,
) -> String {
    let mut url = format!("/?mode=advanced&adv={}", urlencoding::encode(raw.trim()));
    if !plan.has_vectors() && !plan.positive_tags.is_empty() && sort == AdvancedSort::Newest {
        url.push_str("&sort=newest");
    }
    if plan.has_clip() && plan.has_dino() && clip_weight != 50 {
        url.push_str(&format!("&cw={}", clip_weight.clamp(5, 95)));
    }
    if plan.has_vectors()
        && let Some(ms) = min_similarity
        && ms.is_finite()
        && ms > 0.0005
    {
        url.push_str(&format!("&min_sim={:.2}", ms.clamp(0.0, 1.0)));
    }
    if let Some(nonce) = img_nonce {
        url.push_str(&format!("&img={}", urlencoding::encode(nonce)));
    }
    if limit != DEFAULT_LIMIT {
        url.push_str(&format!("&limit={}", limit.max(1)));
    }
    url
}

fn ranker_summary(plan: &QueryPlan) -> Option<&'static str> {
    match (plan.has_clip(), plan.has_dino()) {
        (true, true) => Some("CLIP + Visual"),
        (true, false) => Some("CLIP"),
        (false, true) => {
            if !plan.upload_pos.is_empty() || !plan.upload_neg.is_empty() {
                Some("Visual Upload")
            } else {
                Some("Visual")
            }
        }
        (false, false) => None,
    }
}

/// Reusable debounced live autocomplete input used for per-row metadata values
/// (`Tag` with multilingual aliases, `Author`, `Title`, `Title & Author`) and plain text for `CLIP`/`Similar ID`.
#[component]
fn ValueAutocompleteInput(
    field: Signal<SearchField>,
    value: Signal<String>,
    on_change: Callback<String>,
    input_id: String,
) -> impl IntoView {
    let focused = RwSignal::new(false);
    let suggestions: RwSignal<Vec<SearchSuggestion>> = RwSignal::new(Vec::new());
    let suggestions_for: RwSignal<(String, String)> = RwSignal::new((String::new(), String::new()));
    let active_idx: RwSignal<Option<usize>> = RwSignal::new(None);
    let req_id: StoredValue<u64> = StoredValue::new(0);

    let key = Signal::derive(move || (field.get(), value.get()));
    let debounced: Signal<(SearchField, String)> = signal_debounced(key, 180.0);

    let cancel = move || {
        req_id.set_value(req_id.get_value().wrapping_add(1));
        suggestions.set(Vec::new());
        suggestions_for.set((String::new(), String::new()));
        active_idx.set(None);
    };

    Effect::new(move |_| {
        let (f, v) = key.get();
        let cur_key = (f.as_prefix().to_string(), v.trim().to_string());
        if !should_suggest_field(f, &v)
            || suggestions_for.with_untracked(|k| !k.1.is_empty() && *k != cur_key)
        {
            cancel();
        }
    });

    Effect::new(move |_| {
        let (f, v) = debounced.get();
        if !focused.get() || !should_suggest_field(f, &v) {
            cancel();
            return;
        }
        if field.get_untracked() != f || value.get_untracked() != v {
            return;
        }
        let next = req_id.get_value().wrapping_add(1);
        req_id.set_value(next);
        let expected = v.clone();
        spawn_local(async move {
            let items = fetch_suggestions(f, v).await;
            if req_id.try_get_value() != Some(next) {
                return;
            }
            if field.try_get_untracked() != Some(f)
                || value.try_get_untracked().as_deref() != Some(expected.as_str())
                || focused.try_get_untracked() != Some(true)
            {
                return;
            }
            let arrived_key = (f.as_prefix().to_string(), expected.trim().to_string());
            let _ = suggestions_for.try_set(arrived_key);
            let _ = suggestions.try_set(items);
            let _ = active_idx.try_set(None);
        });
    });

    let list_id = format!("{input_id}-list");
    let list_id_attr = list_id.clone();
    let opt_prefix = format!("{input_id}-opt-");
    let opt_prefix_aria = opt_prefix.clone();
    let opt_prefix_scroll = opt_prefix.clone();
    let dropdown_open = move || focused.get() && !suggestions.with(Vec::is_empty);

    let scroll_option_into_view = move |idx: usize| {
        #[cfg(feature = "hydrate")]
        {
            if let Some(el) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.get_element_by_id(&format!("{opt_prefix_scroll}{idx}")))
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
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = (&opt_prefix_scroll, idx);
        }
    };

    view! {
        <div class="relative w-full sm:w-auto basis-full sm:basis-0 flex-1 min-w-0">
            <input
                id=input_id
                type="text"
                role="combobox"
                autocomplete="off"
                aria-autocomplete="list"
                aria-controls=list_id_attr
                aria-expanded=move || dropdown_open().to_string()
                aria-activedescendant=move || {
                    dropdown_open()
                        .then(|| active_idx.get().map(|i| format!("{opt_prefix_aria}{i}")))
                        .flatten()
                }
                placeholder=move || field_placeholder(field.get())
                class="w-full min-w-0 rounded-xl bg-white border border-sky-200 px-3 py-1.5 pr-7 text-sm
                       text-slate-700 placeholder:text-slate-400 outline-none
                       focus:border-sky-400 focus:ring-2 focus:ring-sky-200/70 transition"
                value=move || value.get()
                prop:value=move || value.get()
                on:focus=move |_| focused.set(true)
                on:click=move |_| focused.set(true)
                on:blur=move |_| focused.set(false)
                on:input=move |ev| {
                    let val = event_target_value(&ev);
                    let next_key = (
                        field.get_untracked().as_prefix().to_string(),
                        val.trim().to_string(),
                    );
                    active_idx.set(None);
                    if suggestions_for.with_untracked(|k| *k != next_key) {
                        suggestions.set(Vec::new());
                        suggestions_for.set((String::new(), String::new()));
                    }
                    on_change.run(val);
                    focused.set(true);
                }
                on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                    if ev.is_composing() || ev.key_code() == 229 {
                        return;
                    }
                    let len = suggestions.with_untracked(Vec::len);
                    if len == 0 || !focused.get_untracked() {
                        return;
                    }
                    match ev.key().as_str() {
                        "ArrowDown" => {
                            ev.prevent_default();
                            let next = match active_idx.get_untracked() {
                                Some(i) if i + 1 < len => i + 1,
                                _ => 0,
                            };
                            active_idx.set(Some(next));
                            scroll_option_into_view(next);
                        }
                        "ArrowUp" => {
                            ev.prevent_default();
                            let next = match active_idx.get_untracked() {
                                Some(0) | None => len - 1,
                                Some(i) => i - 1,
                            };
                            active_idx.set(Some(next));
                            scroll_option_into_view(next);
                        }
                        "Escape" => {
                            ev.prevent_default();
                            ev.stop_propagation();
                            focused.set(false);
                        }
                        "Enter" => {
                            let cur_field = field.get_untracked();
                            let cur_val = value.get_untracked();
                            let matches_current = suggestions_for.with_untracked(|k| {
                                k.0 == cur_field.as_prefix() && k.1 == cur_val.trim()
                            });
                            if matches_current
                                && let Some(i) = active_idx.get_untracked()
                                && let Some(picked) =
                                    suggestions.with_untracked(|s| s.get(i).map(|x| x.value.clone()))
                            {
                                ev.prevent_default();
                                on_change.run(picked);
                                focused.set(false);
                                cancel();
                            }
                        }
                        _ => {}
                    }
                }
            />
            {move || (!value.get().is_empty()).then(|| view! {
                <button
                    type="button"
                    aria-label="Clear field"
                    class="absolute right-1.5 top-1/2 -translate-y-1/2 w-5 h-5 rounded-full
                           flex items-center justify-center text-slate-400 hover:text-slate-700
                           hover:bg-slate-100 text-xs transition-colors cursor-pointer"
                    on:mousedown=|ev| ev.prevent_default()
                    on:click=move |_| {
                        on_change.run(String::new());
                        cancel();
                    }
                >
                    "\u{00D7}"
                </button>
            })}
            {move || {
                let items = suggestions.get();
                let is_open = focused.get() && !items.is_empty();
                let cur_field = field.get();
                let list_id = list_id.clone();
                let opt_prefix = opt_prefix.clone();
                is_open.then(move || {
                    view! {
                        <div
                            id=list_id
                            role="listbox"
                            on:mousedown=|ev| ev.prevent_default()
                            class="absolute left-0 right-0 top-full mt-1.5 z-[60] max-h-60 overflow-y-auto overscroll-contain
                                   rounded-2xl bg-white/95 backdrop-blur-md ring-1 ring-sky-200/90
                                   shadow-xl shadow-sky-200/60 p-1.5 flex flex-col gap-0.5"
                        >
                            {items.into_iter().enumerate().map(|(i, s)| {
                                let val = s.value.clone();
                                let alias_line = (!s.aliases.is_empty())
                                    .then(|| s.aliases.join(" \u{00B7} "));
                                let kind_badge = if cur_field == SearchField::All {
                                    match s.kind.as_str() {
                                        "author" => Some(("@ Author", "bg-sky-100 text-sky-700")),
                                        "title" => Some(("Title", "bg-indigo-50 text-indigo-700")),
                                        _ => None,
                                    }
                                } else {
                                    None
                                };
                                let opt_id = format!("{opt_prefix}{i}");
                                view! {
                                    <button
                                        id=opt_id
                                        type="button"
                                        role="option"
                                        aria-selected=move || (active_idx.get() == Some(i)).to_string()
                                        class=move || if active_idx.get() == Some(i) {
                                            "w-full text-left px-3 py-1.5 rounded-xl flex flex-col gap-0.5 bg-sky-100/90 text-sky-900 cursor-pointer transition-colors"
                                        } else {
                                            "w-full text-left px-3 py-1.5 rounded-xl flex flex-col gap-0.5 hover:bg-sky-50 text-slate-700 cursor-pointer transition-colors"
                                        }
                                        on:mousedown=|ev| ev.prevent_default()
                                        on:mouseenter=move |_| active_idx.set(Some(i))
                                        on:click=move |_| {
                                            on_change.run(val.clone());
                                            focused.set(false);
                                            cancel();
                                        }
                                    >
                                        <div class="flex items-center justify-between gap-2 min-w-0">
                                            <span class="text-sm font-medium truncate">{s.value}</span>
                                            {kind_badge.map(|(label, cls)| view! {
                                                <span class=format!(
                                                    "shrink-0 px-1.5 py-0.5 rounded-full text-[10px] font-semibold whitespace-nowrap {cls}"
                                                )>
                                                    {label}
                                                </span>
                                            })}
                                        </div>
                                        {alias_line.map(|line| view! {
                                            <span class="text-[11px] text-slate-400 truncate">{line}</span>
                                        })}
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                    }
                })
            }}
        </div>
    }
}

/// Inline WebP file uploader & thumbnail preview for `SearchField::Upload` rows.
#[component]
fn UploadSlotControl(
    uploaded: Signal<Option<UploadedImageSlot>>,
    on_upload: Callback<Option<UploadedImageSlot>>,
    encoding_count: RwSignal<usize>,
    upload_err_count: RwSignal<usize>,
) -> impl IntoView {
    let encoding = RwSignal::new(false);
    let encode_err: RwSignal<Option<String>> = RwSignal::new(None);
    let encode_req: StoredValue<u64> = StoredValue::new(0);

    let set_encoding_state = move |next: bool| {
        let was = encoding.try_get_untracked().unwrap_or(false);
        if was != next {
            let _ = encoding.try_set(next);
            let _ = encoding_count.try_update(|c| {
                if next {
                    *c += 1;
                } else {
                    *c = c.saturating_sub(1);
                }
            });
        }
    };

    let set_err_state = move |next: Option<String>| {
        let was = encode_err
            .try_with_untracked(Option::is_some)
            .unwrap_or(false);
        let now = next.is_some();
        let _ = encode_err.try_set(next);
        if was != now {
            let _ = upload_err_count.try_update(|c| {
                if now {
                    *c += 1;
                } else {
                    *c = c.saturating_sub(1);
                }
            });
        }
    };

    on_cleanup(move || {
        if encoding.try_get_untracked().unwrap_or(false) {
            let _ = encoding_count.try_update(|c| *c = c.saturating_sub(1));
        }
        if encode_err
            .try_with_untracked(Option::is_some)
            .unwrap_or(false)
        {
            let _ = upload_err_count.try_update(|c| *c = c.saturating_sub(1));
        }
    });

    let on_file_change = move |ev: leptos::ev::Event| {
        let input: web_sys::HtmlInputElement = event_target(&ev);
        let Some(file) = input.files().and_then(|fs| fs.get(0)) else {
            return;
        };
        // Clear so selecting the exact same file again still fires `change`.
        input.set_value("");
        let filename = file.name();
        let req = encode_req.get_value().wrapping_add(1);
        encode_req.set_value(req);
        set_encoding_state(true);
        set_err_state(None);
        spawn_local(async move {
            let encoded = encode_image_file(file).await;
            if encode_req.try_get_value() != Some(req) {
                return;
            }
            set_encoding_state(false);
            if let Some((b64, preview_url)) = encoded {
                on_upload.run(Some(UploadedImageSlot {
                    filename,
                    b64,
                    preview_url,
                }));
            } else {
                set_err_state(Some(
                    "Could not decode image \u{2014} choose another image".to_string(),
                ));
            }
        });
    };

    view! {
        <div class="w-full sm:w-auto basis-full sm:basis-0 flex-1 min-w-0 flex flex-col gap-1">
            {move || match uploaded.get() {
                Some(s) => {
                    let alt_name = s.filename.clone();
                    let title_name = s.filename.clone();
                    let display_name = s.filename;
                    view! {
                        <div class="flex-1 min-w-0 flex items-center gap-2 rounded-xl bg-sky-50/80 border border-sky-200 px-2 py-1">
                            <img
                                src=s.preview_url
                                alt=alt_name
                                class="w-8 h-8 rounded-lg object-cover ring-1 ring-sky-200 shrink-0 bg-white"
                            />
                            <span class="flex-1 min-w-0 truncate text-xs font-medium text-slate-700" title=title_name>
                                {display_name}
                            </span>
                            {move || encoding.get().then(|| view! {
                                <span class="shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-sky-100 text-sky-700 text-[10px] font-semibold">
                                    <span class="inline-block w-2.5 h-2.5 rounded-full border-2 border-sky-500 border-t-transparent animate-spin" aria-hidden="true" />
                                    <span>"Encoding\u{2026}"</span>
                                </span>
                            })}
                            <label class="relative shrink-0 px-2 py-1 rounded-lg text-[11px] font-medium text-sky-700
                                          bg-white hover:bg-sky-100 ring-1 ring-sky-200 cursor-pointer transition-colors
                                          focus-within:ring-2 focus-within:ring-sky-400 focus-within:ring-offset-1">
                                "Replace"
                                <input
                                    type="file"
                                    accept="image/*"
                                    class="sr-only peer"
                                    on:change=on_file_change
                                />
                            </label>
                            <button
                                type="button"
                                title="Remove uploaded image"
                                aria-label="Remove uploaded image"
                                class="shrink-0 w-6 h-6 rounded-lg flex items-center justify-center text-slate-400
                                       hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                                on:click=move |_| {
                                    encode_req.set_value(encode_req.get_value().wrapping_add(1));
                                    set_encoding_state(false);
                                    set_err_state(None);
                                    on_upload.run(None);
                                }
                            >
                                "\u{00D7}"
                            </button>
                        </div>
                        {move || encode_err.get().map(|msg| view! {
                            <div
                                role="alert"
                                class="flex items-center justify-between gap-2 px-2.5 py-1 rounded-lg bg-rose-50 ring-1 ring-rose-200 text-[11px] font-medium text-rose-700"
                            >
                                <span class="min-w-0 break-words">{msg}</span>
                                <button
                                    type="button"
                                    class="shrink-0 text-rose-600 hover:text-rose-800 underline cursor-pointer whitespace-nowrap"
                                    on:click=move |_| set_err_state(None)
                                >
                                    "Dismiss"
                                </button>
                            </div>
                        })}
                    }.into_any()
                }
                None => view! {
                    <label class=move || {
                        let tone = if encode_err.with(Option::is_some) {
                            "border-rose-300 bg-rose-50/70 hover:bg-rose-50 text-rose-700"
                        } else {
                            "border-sky-300 bg-sky-50/50 hover:bg-sky-50 text-sky-700"
                        };
                        format!(
                            "relative flex-1 min-w-0 flex items-center justify-center gap-2 rounded-xl border border-dashed \
                             px-3 py-1.5 text-xs sm:text-sm font-medium cursor-pointer transition-colors \
                             focus-within:ring-2 focus-within:ring-sky-400 focus-within:ring-offset-1 {tone}"
                        )
                    }>
                        {move || encoding.get().then(|| view! {
                            <span class="inline-block w-3.5 h-3.5 rounded-full border-2 border-sky-500 border-t-transparent animate-spin shrink-0" aria-hidden="true" />
                        })}
                        <span>
                            {move || if encoding.get() {
                                "Encoding image\u{2026}".to_string()
                            } else if let Some(err) = encode_err.get() {
                                err
                            } else {
                                "\u{1F5BC}\u{FE0F} Choose an image\u{2026}".to_string()
                            }}
                        </span>
                        <input
                            type="file"
                            accept="image/*"
                            class="sr-only peer"
                            on:change=on_file_change
                        />
                    </label>
                }.into_any(),
            }}
        </div>
    }
}

/// Web-of-Science-style Dual Visual Row Builder + Synced Editable Raw Query Box.
#[component]
pub fn AdvancedSearchPanel(
    open: RwSignal<bool>,
    initial_state: Option<UrlSearchState>,
) -> impl IntoView {
    let dialog_ref: NodeRef<html::Div> = NodeRef::new();
    let raw_ref: NodeRef<html::Textarea> = NodeRef::new();
    lock_body_scroll();
    push_modal_history(move || open.set(false));

    // Move keyboard focus into the dialog on mount (matching Lightbox).
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        if let Some(el) = dialog_ref.get() {
            let _ = el.focus();
        }
    });

    let navigate = use_navigate();
    let adv_uploads = expect_context::<AdvancedUploads>();
    let single_img = expect_context::<ImageQuery>();
    let safety = use_context::<SafetyUiState>();

    let init_limit = initial_state
        .as_ref()
        .map(|s| s.limit)
        .unwrap_or(DEFAULT_LIMIT);
    let init_min_sim = initial_state
        .as_ref()
        .and_then(|s| s.min_similarity)
        .unwrap_or_else(|| {
            safety
                .map(|s| {
                    s.default_dinov3_min
                        .get_untracked()
                        .max(s.default_siglip2_min.get_untracked())
                })
                .unwrap_or(0.0)
        });

    let next_id: StoredValue<u64> = StoredValue::new(1);
    let alloc_id = move || {
        let id = next_id.get_value();
        next_id.set_value(id.wrapping_add(1));
        id
    };

    let (init_items, init_raw, init_custom, init_slots, init_sort, init_cw) = {
        let mut id_gen = alloc_id;
        build_initial_state(
            initial_state,
            adv_uploads.0.get_untracked(),
            single_img.0.get_untracked(),
            &mut id_gen,
        )
    };
    let init_raw_invalid =
        !init_raw.trim().is_empty() && parse_and_compile(init_raw.trim()).is_err();
    let init_raw_text = init_raw.clone();

    let items: RwSignal<Vec<BuilderItem>> = RwSignal::new(init_items);
    let raw_query: RwSignal<String> = RwSignal::new(init_raw);
    let custom_nested: RwSignal<bool> = RwSignal::new(init_custom);
    let raw_out_of_sync: RwSignal<bool> = RwSignal::new(init_raw_invalid);
    let slots_pool: RwSignal<Vec<Option<UploadedImageSlot>>> = RwSignal::new(init_slots);
    let encoding_count: RwSignal<usize> = RwSignal::new(0);
    let upload_err_count: RwSignal<usize> = RwSignal::new(0);
    let sort: RwSignal<AdvancedSort> = RwSignal::new(init_sort);
    let clip_weight: RwSignal<i32> = RwSignal::new(init_cw);
    let min_similarity: RwSignal<f32> = RwSignal::new(init_min_sim);
    let show_cheat_sheet: RwSignal<bool> = RwSignal::new(false);
    let submit_seq: StoredValue<u64> = StoredValue::new(1);
    let backdrop_pointerdown: StoredValue<bool> = StoredValue::new(false);

    let set_raw_dom = move |val: &str| {
        if let Some(el) = raw_ref.get_untracked() {
            el.set_value(val);
        }
    };

    // Dismiss on Escape (IME-safe and respecting inner autocomplete default_prevented)
    // and trap Tab focus inside the modal dialog (matching Lightbox).
    #[cfg(feature = "hydrate")]
    {
        let _ = use_event_listener(window(), ev::keydown, move |e: ev::KeyboardEvent| {
            if !open.get_untracked() {
                return;
            }
            if e.key() == "Tab" {
                trap_dialog_tab(&e, dialog_ref.get_untracked());
                return;
            }
            if e.key() == "Escape"
                && !e.is_composing()
                && e.key_code() != 229
                && !e.default_prevented()
                && !e.alt_key()
                && !e.ctrl_key()
                && !e.meta_key()
            {
                e.prevent_default();
                open.set(false);
            }
        });
    }

    let sync_raw_from_builder = move || {
        let (formatted, active_slots) = items.with_untracked(|list| format_builder_to_query(list));
        set_raw_dom(&formatted);
        raw_query.set(formatted);
        slots_pool.set(active_slots.into_iter().map(Some).collect());
        custom_nested.set(false);
        raw_out_of_sync.set(false);
    };

    let apply_raw_text = move |text: String, write_dom: bool| {
        if write_dom {
            set_raw_dom(&text);
        }
        raw_query.set(text.clone());
        let trimmed = text.trim();
        if trimmed.is_empty() {
            let mut id_gen = alloc_id;
            let mut blank = default_blank_items(&mut id_gen);
            items.update(|prev| {
                reconcile_builder_ids(prev, &mut blank);
                *prev = blank;
            });
            slots_pool.set(Vec::new());
            custom_nested.set(false);
            raw_out_of_sync.set(false);
            return;
        }
        match parse_and_compile(trimmed) {
            Ok((expr, _)) => {
                let current_slots = slots_pool.get_untracked();
                let mut id_gen = alloc_id;
                match expr_to_builder(&expr, &current_slots, &mut id_gen) {
                    Some(mut parsed) => {
                        items.update(|prev| {
                            reconcile_builder_ids(prev, &mut parsed);
                            *prev = parsed;
                        });
                        custom_nested.set(false);
                    }
                    None => {
                        custom_nested.set(true);
                    }
                }
                raw_out_of_sync.set(false);
            }
            Err(_) => {
                raw_out_of_sync.set(true);
            }
        }
    };

    let raw_syntax_error = Memo::new(move |_| {
        raw_out_of_sync.get()
            && raw_query.with(|raw| {
                let trimmed = raw.trim();
                !trimmed.is_empty() && parse_and_compile(trimmed).is_err()
            })
    });

    let has_any_vector = Memo::new(move |_| items.with(|list| items_have_vector(list)));

    let validation = Memo::new(move |_| {
        let raw = raw_query.get();
        let is_custom = custom_nested.get();
        let enc = encoding_count.get();
        let errs = upload_err_count.get();
        items.with(|list| {
            slots_pool.with(|slots| validate_panel_state(&raw, slots, list, is_custom, enc, errs))
        })
    });

    let add_condition = move |_| {
        if raw_syntax_error.get_untracked() {
            return;
        }
        let id = alloc_id();
        let row_id = alloc_id();
        items.update(|list| {
            list.push(BuilderItem {
                id,
                connector: Connector::And,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: row_id,
                    field: SearchField::Tag,
                    value: String::new(),
                    upload: None,
                }),
            });
        });
        custom_nested.set(false);
    };

    let add_or_group = move |_| {
        if raw_syntax_error.get_untracked() {
            return;
        }
        let id = alloc_id();
        let r1 = alloc_id();
        let r2 = alloc_id();
        items.update(|list| {
            list.push(BuilderItem {
                id,
                connector: Connector::And,
                kind: BuilderItemKind::Group {
                    combinator: GroupCombinator::Or,
                    rows: vec![
                        InnerRow {
                            id: r1,
                            negated: false,
                            field: SearchField::Tag,
                            value: String::new(),
                        },
                        InnerRow {
                            id: r2,
                            negated: false,
                            field: SearchField::Tag,
                            value: String::new(),
                        },
                    ],
                },
            });
        });
        custom_nested.set(false);
    };

    let clear_all = move |_| {
        let mut id_gen = alloc_id;
        items.set(default_blank_items(&mut id_gen));
        set_raw_dom("");
        raw_query.set(String::new());
        slots_pool.set(Vec::new());
        custom_nested.set(false);
        raw_out_of_sync.set(false);
        sort.set(AdvancedSort::Relevance);
        clip_weight.set(50);
        min_similarity.set(0.0);
    };

    let do_submit = {
        let nav = navigate.clone();
        move || {
            let raw = raw_query.get_untracked();
            let slots = slots_pool.get_untracked();
            let is_custom = custom_nested.get_untracked();
            let enc = encoding_count.get_untracked();
            let errs = upload_err_count.get_untracked();
            let state = items.with_untracked(|list| {
                validate_panel_state(&raw, &slots, list, is_custom, enc, errs)
            });
            let ValidationState::Valid(plan) = state else {
                return;
            };
            let (submitted_raw, nonce) = if plan.tier == VectorTier::ImageUpload {
                let Some((remapped_raw, pruned_slots)) = prune_and_remap_uploads(&raw, &slots)
                else {
                    return;
                };
                let seq = submit_seq.get_value();
                submit_seq.set_value(seq.wrapping_add(1));
                let n = format!("{}-{seq}", js_sys::Date::now() as u64);
                adv_uploads.0.set(Some(AdvancedUploadsPayload {
                    nonce: n.clone(),
                    slots: pruned_slots,
                }));
                (remapped_raw, Some(n))
            } else {
                (raw, None)
            };
            let min_sim_val = min_similarity.get_untracked();
            let url = build_advanced_nav_url(
                &submitted_raw,
                &plan,
                sort.get_untracked(),
                clip_weight.get_untracked(),
                (min_sim_val > 0.0005).then_some(min_sim_val),
                nonce.as_deref(),
                init_limit,
            );
            let nav = nav.clone();
            navigate_from_modal(
                url,
                move || open.set(false),
                move |dest, replace| {
                    nav(
                        dest,
                        NavigateOptions {
                            replace,
                            ..Default::default()
                        },
                    );
                },
            );
        }
    };

    let submit_form = {
        let do_submit = do_submit.clone();
        move |ev: leptos::ev::SubmitEvent| {
            ev.prevent_default();
            do_submit();
        }
    };

    let submit_btn = do_submit;

    let render_item = move |item_id: u64| {
        // Use `Memo` (deduplicated by `PartialEq`) for structural/enum fields so typing into
        // a row's value input never re-triggers `SkySelect` or remounts `ValueAutocompleteInput`.
        let idx_sig: Signal<usize> = Memo::new(move |_| {
            items
                .with(|list| list.iter().position(|it| it.id == item_id))
                .unwrap_or(0)
        })
        .into();
        let conn_sig: Signal<Connector> = Memo::new(move |_| {
            items
                .with(|list| {
                    list.iter()
                        .find(|it| it.id == item_id)
                        .map(|it| it.connector)
                })
                .unwrap_or(Connector::And)
        })
        .into();
        let is_group = items.with_untracked(|list| {
            list.iter()
                .find(|it| it.id == item_id)
                .is_some_and(|it| matches!(it.kind, BuilderItemKind::Group { .. }))
        });

        let remove_item = move |_| {
            if raw_syntax_error.get_untracked() {
                return;
            }
            items.update(|list| {
                list.retain(|it| it.id != item_id);
                if list.is_empty() {
                    let mut id_gen = alloc_id;
                    *list = default_blank_items(&mut id_gen);
                } else if list[0].connector == Connector::Or {
                    list[0].connector = Connector::And;
                }
            });
            sync_raw_from_builder();
        };

        if !is_group {
            let field_sig: Signal<SearchField> = Memo::new(move |_| {
                items
                    .with(|list| {
                        list.iter()
                            .find(|it| it.id == item_id)
                            .and_then(|it| match &it.kind {
                                BuilderItemKind::Row(r) => Some(r.field),
                                _ => None,
                            })
                    })
                    .unwrap_or(SearchField::Tag)
            })
            .into();
            let is_upload = Memo::new(move |_| field_sig.get() == SearchField::Upload);
            let val_sig: Signal<String> = Memo::new(move |_| {
                items
                    .with(|list| {
                        list.iter()
                            .find(|it| it.id == item_id)
                            .and_then(|it| match &it.kind {
                                BuilderItemKind::Row(r) => Some(r.value.clone()),
                                _ => None,
                            })
                    })
                    .unwrap_or_default()
            })
            .into();
            let slot_sig: Signal<Option<UploadedImageSlot>> = Memo::new(move |_| {
                items.with(|list| {
                    list.iter()
                        .find(|it| it.id == item_id)
                        .and_then(|it| match &it.kind {
                            BuilderItemKind::Row(r) => r.upload.clone(),
                            _ => None,
                        })
                })
            })
            .into();
            let is_vector: Signal<bool> = Memo::new(move |_| field_sig.get().is_vector()).into();

            let on_value_change = Callback::new(move |next_val: String| {
                if raw_syntax_error.get_untracked() {
                    return;
                }
                items.update(|list| {
                    if let Some(it) = list.iter_mut().find(|it| it.id == item_id)
                        && let BuilderItemKind::Row(r) = &mut it.kind
                    {
                        r.value = next_val;
                    }
                });
                sync_raw_from_builder();
            });

            let on_upload_change = Callback::new(move |next_slot: Option<UploadedImageSlot>| {
                if raw_syntax_error.get_untracked() {
                    return;
                }
                items.update(|list| {
                    if let Some(it) = list.iter_mut().find(|it| it.id == item_id)
                        && let BuilderItemKind::Row(r) = &mut it.kind
                    {
                        r.upload = next_slot;
                        if r.upload.is_none() {
                            r.value.clear();
                        }
                    }
                });
                sync_raw_from_builder();
            });

            view! {
                <div class="flex flex-col gap-1 p-2.5 rounded-2xl bg-sky-50/55 ring-1 ring-sky-200/75">
                    <div class="flex items-center gap-1.5 sm:gap-2">
                        <div class="flex-1 min-w-0 flex flex-wrap sm:flex-nowrap items-center gap-2">
                        // Connector select (row 0: Match / NOT; rows 1+: AND / OR / NOT)
                        <SkySelect
                            aria_label="Boolean connector"
                            variant=SelectVariant::SkyBox
                            trigger_class="w-24 font-semibold text-sky-800"
                            value=Signal::derive(move || conn_sig.get().as_str().to_string())
                            options=Signal::derive(move || {
                                let mut opts = vec![SelectOption::new(
                                    "and",
                                    if idx_sig.get() == 0 { "Match" } else { "AND" },
                                )];
                                if idx_sig.get() > 0 {
                                    opts.push(
                                        SelectOption::new("or", "OR")
                                            .disabled(has_any_vector.get()),
                                    );
                                }
                                opts.push(SelectOption::new("not", "NOT"));
                                opts
                            })
                            on_change=Callback::new(move |val: String| {
                                if raw_syntax_error.get_untracked() {
                                    return;
                                }
                                let mut next = Connector::parse(&val);
                                if next == Connector::Or
                                    && (idx_sig.get_untracked() == 0
                                        || has_any_vector.get_untracked())
                                {
                                    next = Connector::And;
                                }
                                items.update(|list| {
                                    if let Some(it) = list.iter_mut().find(|it| it.id == item_id) {
                                        it.connector = next;
                                    }
                                });
                                sync_raw_from_builder();
                            })
                        />

                        // Field select
                        <SkySelect
                            aria_label="Condition field"
                            variant=SelectVariant::SkyBox
                            trigger_class="w-36 font-medium text-slate-700"
                            value=Signal::derive(move || field_sig.get().as_prefix().to_string())
                            options=Signal::derive(move || {
                                vec![
                                    SelectOption::new("tag", "Tag"),
                                    SelectOption::new("author", "Author"),
                                    SelectOption::new("title", "Title"),
                                    SelectOption::new("all", "Title & Author"),
                                    SelectOption::new("clip", "CLIP Text"),
                                    SelectOption::new("dino", "Similar ID"),
                                    SelectOption::new("upload", "Upload Image"),
                                ]
                            })
                            on_change=Callback::new(move |val: String| {
                                if raw_syntax_error.get_untracked() {
                                    return;
                                }
                                let next_field = SearchField::parse_prefix(&val)
                                    .unwrap_or(SearchField::Tag);
                                items.update(|list| {
                                    if let Some(it) = list.iter_mut().find(|it| it.id == item_id)
                                        && let BuilderItemKind::Row(r) = &mut it.kind
                                    {
                                        let prev_upload = r.field == SearchField::Upload;
                                        r.field = next_field;
                                        if next_field != SearchField::Upload {
                                            r.upload = None;
                                            if prev_upload {
                                                r.value.clear();
                                            }
                                        } else if !prev_upload {
                                            r.value.clear();
                                        }
                                    }
                                    if next_field.is_vector() {
                                        normalize_or_connectors_for_vectors(list);
                                    }
                                });
                                sync_raw_from_builder();
                            })
                        />

                        // Value input or inline Upload Image picker (memoized on `is_upload` so typing never remounts input)
                        {move || if is_upload.get() {
                            view! {
                                <UploadSlotControl
                                    uploaded=slot_sig
                                    on_upload=on_upload_change
                                    encoding_count=encoding_count
                                    upload_err_count=upload_err_count
                                />
                            }.into_any()
                        } else {
                            view! {
                                <ValueAutocompleteInput
                                    field=field_sig
                                    value=val_sig
                                    on_change=on_value_change
                                    input_id=format!("adv-row-{item_id}")
                                />
                            }.into_any()
                        }}
                        </div>

                        // Remove row button (always vertically centered on the right, even when controls wrap)
                        <button
                            type="button"
                            title="Remove condition"
                            aria-label="Remove condition"
                            class="shrink-0 w-7 h-7 rounded-xl flex items-center justify-center text-slate-400
                                   hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                            on:click=remove_item
                        >
                            "\u{00D7}"
                        </button>
                    </div>

                    // Subtle vector ranking hint
                    {move || is_vector.get().then(|| view! {
                        <div class="pl-1 text-[11px] text-indigo-600/85">
                            "Vector clauses rank results (use AND / NOT)"
                        </div>
                    })}
                </div>
            }.into_any()
        } else {
            let comb_sig: Signal<GroupCombinator> = Memo::new(move |_| {
                items
                    .with(|list| {
                        list.iter()
                            .find(|it| it.id == item_id)
                            .and_then(|it| match &it.kind {
                                BuilderItemKind::Group { combinator, .. } => Some(*combinator),
                                _ => None,
                            })
                    })
                    .unwrap_or(GroupCombinator::Or)
            })
            .into();

            let inner_ids = Memo::new(move |_| {
                items.with(|list| {
                    list.iter()
                        .find(|it| it.id == item_id)
                        .map(|it| match &it.kind {
                            BuilderItemKind::Group { rows, .. } => {
                                rows.iter().map(|r| r.id).collect::<Vec<_>>()
                            }
                            _ => Vec::new(),
                        })
                        .unwrap_or_default()
                })
            });

            let add_inner_row = move |_| {
                if raw_syntax_error.get_untracked() {
                    return;
                }
                let r_id = alloc_id();
                items.update(|list| {
                    if let Some(it) = list.iter_mut().find(|it| it.id == item_id)
                        && let BuilderItemKind::Group { rows, .. } = &mut it.kind
                    {
                        rows.push(InnerRow {
                            id: r_id,
                            negated: false,
                            field: SearchField::Tag,
                            value: String::new(),
                        });
                    }
                });
            };

            let set_combinator = move |next: GroupCombinator| {
                if raw_syntax_error.get_untracked() {
                    return;
                }
                items.update(|list| {
                    if let Some(it) = list.iter_mut().find(|it| it.id == item_id)
                        && let BuilderItemKind::Group { combinator, .. } = &mut it.kind
                    {
                        *combinator = next;
                    }
                });
                sync_raw_from_builder();
            };

            view! {
                <div class="flex flex-col gap-2 p-3 rounded-2xl bg-indigo-50/45 ring-1 ring-indigo-200/80">
                    // Group header bar
                    <div class="flex flex-wrap items-center justify-between gap-2">
                        <div class="flex flex-wrap items-center gap-2 min-w-0">
                            <SkySelect
                                aria_label="Group boolean connector"
                                variant=SelectVariant::IndigoBox
                                trigger_class="w-24 font-semibold text-indigo-800 !py-1"
                                value=Signal::derive(move || conn_sig.get().as_str().to_string())
                                options=Signal::derive(move || {
                                    let mut opts = vec![SelectOption::new(
                                        "and",
                                        if idx_sig.get() == 0 { "Match" } else { "AND" },
                                    )];
                                    if idx_sig.get() > 0 {
                                        opts.push(
                                            SelectOption::new("or", "OR")
                                                .disabled(has_any_vector.get()),
                                        );
                                    }
                                    opts.push(SelectOption::new("not", "NOT"));
                                    opts
                                })
                                on_change=Callback::new(move |val: String| {
                                    if raw_syntax_error.get_untracked() {
                                        return;
                                    }
                                    let mut next = Connector::parse(&val);
                                    if next == Connector::Or
                                        && (idx_sig.get_untracked() == 0
                                            || has_any_vector.get_untracked())
                                    {
                                        next = Connector::And;
                                    }
                                    items.update(|list| {
                                        if let Some(it) = list.iter_mut().find(|it| it.id == item_id) {
                                            it.connector = next;
                                        }
                                    });
                                    sync_raw_from_builder();
                                })
                            />

                            <span class="text-xs font-mono font-semibold text-indigo-500 whitespace-nowrap shrink-0">"( ... )"</span>

                            <div class="inline-flex items-center p-0.5 rounded-full bg-white ring-1 ring-indigo-200/80 text-[11px] shrink-0">
                                <button
                                    type="button"
                                    class=move || if comb_sig.get() == GroupCombinator::Or {
                                        "px-2.5 py-0.5 rounded-full font-semibold bg-indigo-500 text-white cursor-pointer transition-colors whitespace-nowrap"
                                    } else {
                                        "px-2.5 py-0.5 rounded-full font-medium text-indigo-700 hover:bg-indigo-50 cursor-pointer transition-colors whitespace-nowrap"
                                    }
                                    on:click=move |_| set_combinator(GroupCombinator::Or)
                                >
                                    "Match ANY (OR)"
                                </button>
                                <button
                                    type="button"
                                    class=move || if comb_sig.get() == GroupCombinator::And {
                                        "px-2.5 py-0.5 rounded-full font-semibold bg-indigo-500 text-white cursor-pointer transition-colors whitespace-nowrap"
                                    } else {
                                        "px-2.5 py-0.5 rounded-full font-medium text-indigo-700 hover:bg-indigo-50 cursor-pointer transition-colors whitespace-nowrap"
                                    }
                                    on:click=move |_| set_combinator(GroupCombinator::And)
                                >
                                    "Match ALL (AND)"
                                </button>
                            </div>
                        </div>

                        <div class="flex items-center gap-1.5 shrink-0 ml-auto">
                            <button
                                type="button"
                                class="px-2.5 py-1 rounded-full text-xs font-medium text-indigo-700 bg-white
                                       hover:bg-indigo-100 ring-1 ring-indigo-200 transition-colors cursor-pointer whitespace-nowrap"
                                on:click=add_inner_row
                            >
                                "+ Row"
                            </button>
                            <button
                                type="button"
                                title="Remove group"
                                aria-label="Remove group"
                                class="w-7 h-7 rounded-xl flex items-center justify-center text-slate-400
                                       hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                                on:click=remove_item
                            >
                                "\u{00D7}"
                            </button>
                        </div>
                    </div>

                    // Inner metadata rows
                    <div class="flex flex-col gap-1.5 pl-3 border-l-2 border-indigo-200">
                        <For
                            each=move || inner_ids.get()
                            key=|r_id| *r_id
                            let(r_id)
                        >
                            {
                                let r_idx: Signal<usize> = Memo::new(move |_| {
                                    inner_ids
                                        .with(|ids| ids.iter().position(|x| *x == r_id))
                                        .unwrap_or(0)
                                })
                                .into();
                                let r_field: Signal<SearchField> = Memo::new(move |_| {
                                    items
                                        .with(|list| {
                                            list.iter().find(|it| it.id == item_id).and_then(|it| match &it.kind {
                                                BuilderItemKind::Group { rows, .. } => {
                                                    rows.iter().find(|r| r.id == r_id).map(|r| r.field)
                                                }
                                                _ => None,
                                            })
                                        })
                                        .unwrap_or(SearchField::Tag)
                                })
                                .into();
                                let r_val: Signal<String> = Memo::new(move |_| {
                                    items
                                        .with(|list| {
                                            list.iter().find(|it| it.id == item_id).and_then(|it| match &it.kind {
                                                BuilderItemKind::Group { rows, .. } => {
                                                    rows.iter().find(|r| r.id == r_id).map(|r| r.value.clone())
                                                }
                                                _ => None,
                                            })
                                        })
                                        .unwrap_or_default()
                                })
                                .into();
                                let r_neg: Signal<bool> = Memo::new(move |_| {
                                    items
                                        .with(|list| {
                                            list.iter().find(|it| it.id == item_id).and_then(|it| match &it.kind {
                                                BuilderItemKind::Group { rows, .. } => {
                                                    rows.iter().find(|r| r.id == r_id).map(|r| r.negated)
                                                }
                                                _ => None,
                                            })
                                        })
                                        .unwrap_or(false)
                                })
                                .into();

                                let on_inner_change = Callback::new(move |next_val: String| {
                                    if raw_syntax_error.get_untracked() {
                                        return;
                                    }
                                    items.update(|list| {
                                        if let Some(it) = list.iter_mut().find(|it| it.id == item_id)
                                            && let BuilderItemKind::Group { rows, .. } = &mut it.kind
                                            && let Some(r) = rows.iter_mut().find(|r| r.id == r_id)
                                        {
                                            r.value = next_val;
                                        }
                                    });
                                    sync_raw_from_builder();
                                });

                                view! {
                                    <div class="flex items-center gap-1.5">
                                        <div class="flex-1 min-w-0 flex flex-wrap sm:flex-nowrap items-center gap-1.5">
                                        <span class="w-10 shrink-0 text-center text-[11px] font-semibold uppercase text-indigo-500">
                                            {move || if r_idx.get() == 0 {
                                                ""
                                            } else {
                                                comb_sig.get().as_str()
                                            }}
                                        </span>

                                        <button
                                            type="button"
                                            title="Toggle NOT on this inner clause"
                                            aria-pressed=move || r_neg.get().to_string()
                                            class=move || if r_neg.get() {
                                                "shrink-0 px-2 py-1 rounded-lg text-[11px] font-semibold bg-rose-100 text-rose-700 ring-1 ring-rose-200 cursor-pointer"
                                            } else {
                                                "shrink-0 px-2 py-1 rounded-lg text-[11px] font-medium bg-white text-slate-400 hover:text-slate-700 ring-1 ring-slate-200 cursor-pointer"
                                            }
                                            on:click=move |_| {
                                                if raw_syntax_error.get_untracked() {
                                                    return;
                                                }
                                                items.update(|list| {
                                                    if let Some(it) = list.iter_mut().find(|it| it.id == item_id)
                                                        && let BuilderItemKind::Group { rows, .. } = &mut it.kind
                                                        && let Some(r) = rows.iter_mut().find(|r| r.id == r_id)
                                                    {
                                                        r.negated = !r.negated;
                                                    }
                                                });
                                                sync_raw_from_builder();
                                            }
                                        >
                                            "NOT"
                                        </button>

                                        <SkySelect
                                            aria_label="Group row field"
                                            variant=SelectVariant::IndigoBox
                                            trigger_class="w-32 font-medium text-slate-700"
                                            value=Signal::derive(move || r_field.get().as_prefix().to_string())
                                            options=Signal::derive(move || {
                                                vec![
                                                    SelectOption::new("tag", "Tag"),
                                                    SelectOption::new("author", "Author"),
                                                    SelectOption::new("title", "Title"),
                                                    SelectOption::new("all", "Title & Author"),
                                                ]
                                            })
                                            on_change=Callback::new(move |val: String| {
                                                if raw_syntax_error.get_untracked() {
                                                    return;
                                                }
                                                let next = match SearchField::parse_prefix(&val) {
                                                    Some(f) if !f.is_vector() => f,
                                                    _ => SearchField::Tag,
                                                };
                                                items.update(|list| {
                                                    if let Some(it) = list.iter_mut().find(|it| it.id == item_id)
                                                        && let BuilderItemKind::Group { rows, .. } = &mut it.kind
                                                        && let Some(r) = rows.iter_mut().find(|r| r.id == r_id)
                                                    {
                                                        r.field = next;
                                                    }
                                                });
                                                sync_raw_from_builder();
                                            })
                                        />

                                        <ValueAutocompleteInput
                                            field=r_field
                                            value=r_val
                                            on_change=on_inner_change
                                            input_id=format!("adv-grp-{item_id}-{r_id}")
                                        />
                                        </div>

                                        <button
                                            type="button"
                                            title="Remove row from group"
                                            aria-label="Remove row from group"
                                            class="shrink-0 w-6 h-6 rounded-lg flex items-center justify-center text-slate-400
                                                   hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                                            on:click=move |_| {
                                                if raw_syntax_error.get_untracked() {
                                                    return;
                                                }
                                                items.update(|list| {
                                                    let mut id_gen = alloc_id;
                                                    remove_group_inner_row(list, item_id, r_id, &mut id_gen);
                                                });
                                                sync_raw_from_builder();
                                            }
                                        >
                                            "\u{00D7}"
                                        </button>
                                    </div>
                                }
                            }
                        </For>
                    </div>
                </div>
            }.into_any()
        }
    };

    let item_ids =
        Memo::new(move |_| items.with(|list| list.iter().map(|it| it.id).collect::<Vec<_>>()));
    let custom_nested_memo = Memo::new(move |_| custom_nested.get());
    let custom_upload_indices = Memo::new(move |_| {
        if !custom_nested_memo.get() {
            return Vec::<usize>::new();
        }
        raw_query.with(|raw| match parse_and_compile(raw.trim()) {
            Ok((_, plan)) => {
                let mut set = std::collections::BTreeSet::new();
                for &idx in plan.upload_pos.iter().chain(plan.upload_neg.iter()) {
                    set.insert(idx);
                }
                set.into_iter().collect()
            }
            Err(_) => Vec::new(),
        })
    });

    view! {
        <div
            node_ref=dialog_ref
            id="advanced-search-panel"
            role="dialog"
            aria-modal="true"
            aria-label="Advanced Search Query Builder"
            tabindex="-1"
            class="fixed inset-0 z-50 overflow-y-auto bg-slate-900/35 backdrop-blur-[2px] flex items-start justify-center p-2 sm:p-4 sm:pt-14 outline-none"
            on:pointerdown=move |ev: leptos::ev::PointerEvent| {
                let is_backdrop = ev.target().is_some() && ev.target() == ev.current_target();
                backdrop_pointerdown.set_value(is_backdrop);
            }
            on:pointercancel=move |_| backdrop_pointerdown.set_value(false)
            on:click=move |ev: leptos::ev::MouseEvent| {
                let started_on_backdrop = backdrop_pointerdown.get_value();
                backdrop_pointerdown.set_value(false);
                if started_on_backdrop && ev.target() == ev.current_target() {
                    open.set(false);
                }
            }
        >
            <form
                class="w-full max-w-4xl rounded-3xl bg-white/95 backdrop-blur-md ring-1 ring-sky-200
                       shadow-2xl shadow-sky-900/15 my-auto sm:my-0 flex flex-col"
                on:click=|ev| ev.stop_propagation()
                on:submit=submit_form
            >
                // Header
                <div class="flex items-center justify-between gap-3 px-5 py-3.5 border-b border-sky-100">
                    <div class="flex items-center gap-2.5 min-w-0">
                        <span class="w-8 h-8 rounded-2xl bg-gradient-to-br from-sky-400 to-indigo-500 text-white
                                     flex items-center justify-center shadow-sm shrink-0">
                            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2">
                                <path stroke-linecap="round" stroke-linejoin="round"
                                      d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
                            </svg>
                        </span>
                        <div class="min-w-0">
                            <h2 class="text-base sm:text-lg font-bold text-slate-800 leading-tight truncate">
                                "Advanced Search"
                            </h2>
                            <p class="text-xs text-slate-500 truncate">
                                "Combine metadata filters, tags, CLIP text & visual similarity — returns Posts or Images automatically"
                            </p>
                        </div>
                    </div>
                    <button
                        type="button"
                        aria-label="Close Advanced Search"
                        class="shrink-0 w-8 h-8 rounded-full flex items-center justify-center text-slate-400
                               hover:text-slate-700 hover:bg-sky-100/80 transition-colors cursor-pointer text-lg"
                        on:click=move |_| open.set(false)
                    >
                        "\u{00D7}"
                    </button>
                </div>

                // Body
                <div class="p-4 sm:p-5 flex flex-col gap-4">
                    // Section 1: Visual Row Builder
                    <div class="flex flex-col gap-2.5">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <span class="text-xs font-semibold uppercase tracking-wide text-sky-700">
                                "Visual Query Builder"
                            </span>
                            {move || (!custom_nested_memo.get()).then(|| view! {
                                <div class="flex flex-wrap items-center gap-1.5">
                                    <button
                                        type="button"
                                        prop:disabled=move || raw_syntax_error.get()
                                        class="px-3 py-1 rounded-full text-xs font-semibold text-sky-700 bg-sky-50
                                               hover:bg-sky-100 ring-1 ring-sky-200 transition-colors cursor-pointer
                                               whitespace-nowrap disabled:opacity-45 disabled:cursor-not-allowed"
                                        on:click=add_condition
                                    >
                                        "+ Add condition"
                                    </button>
                                    <button
                                        type="button"
                                        prop:disabled=move || raw_syntax_error.get()
                                        class="px-3 py-1 rounded-full text-xs font-semibold text-indigo-700 bg-indigo-50
                                               hover:bg-indigo-100 ring-1 ring-indigo-200 transition-colors cursor-pointer
                                               whitespace-nowrap disabled:opacity-45 disabled:cursor-not-allowed"
                                        on:click=add_or_group
                                    >
                                        "+ Add OR group ( ... )"
                                    </button>
                                </div>
                            })}
                        </div>

                        {move || if custom_nested_memo.get() {
                            view! {
                                <div class="flex flex-col gap-2.5">
                                    <div class="flex items-center justify-between gap-2 px-3.5 py-2.5 rounded-2xl
                                                bg-amber-50/90 ring-1 ring-amber-200 text-amber-800 text-xs sm:text-sm">
                                        <span>
                                            "Custom nested query — edit in raw box below"
                                        </span>
                                        <button
                                            type="button"
                                            class="shrink-0 px-2.5 py-1 rounded-full text-xs font-semibold bg-white
                                                   text-amber-800 ring-1 ring-amber-300 hover:bg-amber-100 cursor-pointer"
                                            on:click=clear_all
                                        >
                                            "Reset builder"
                                        </button>
                                    </div>
                                    {move || {
                                        let indices = custom_upload_indices.get();
                                        (!indices.is_empty()).then(move || {
                                            view! {
                                                <div class="flex flex-col gap-2 p-3 rounded-2xl bg-sky-50/70 ring-1 ring-sky-200/80">
                                                    <span class="text-xs font-semibold text-sky-800">
                                                        "Attach images for raw query"
                                                    </span>
                                                    <div class="flex flex-col gap-2">
                                                        <For
                                                            each=move || custom_upload_indices.get()
                                                            key=|idx| *idx
                                                            let(slot_idx)
                                                        >
                                                            {
                                                                let slot_sig: Signal<Option<UploadedImageSlot>> =
                                                                    Memo::new(move |_| {
                                                                        slots_pool.with(|pool| {
                                                                            pool.get(slot_idx).cloned().flatten()
                                                                        })
                                                                    })
                                                                    .into();
                                                                let on_slot_upload = Callback::new(
                                                                    move |next_slot: Option<UploadedImageSlot>| {
                                                                        slots_pool.update(|pool| {
                                                                            if pool.len() <= slot_idx {
                                                                                pool.resize(slot_idx + 1, None);
                                                                            }
                                                                            pool[slot_idx] = next_slot;
                                                                        });
                                                                    },
                                                                );
                                                                view! {
                                                                    <div class="flex flex-wrap sm:flex-nowrap items-center gap-2">
                                                                        <span class="shrink-0 px-2.5 py-1 rounded-xl bg-white ring-1 ring-sky-200 font-mono text-xs font-semibold text-sky-800">
                                                                            {format!("upload:{slot_idx}")}
                                                                        </span>
                                                                        <UploadSlotControl
                                                                            uploaded=slot_sig
                                                                            on_upload=on_slot_upload
                                                                            encoding_count=encoding_count
                                                                            upload_err_count=upload_err_count
                                                                        />
                                                                    </div>
                                                                }
                                                            }
                                                        </For>
                                                    </div>
                                                </div>
                                            }
                                        })
                                    }}
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="flex flex-col gap-2">
                                    {move || raw_syntax_error.get().then(|| view! {
                                        <div class="flex flex-wrap items-center justify-between gap-2 px-3.5 py-2 rounded-2xl
                                                    bg-rose-50/90 ring-1 ring-rose-200 text-rose-700 text-xs">
                                            <span>
                                                "Fix raw syntax error below or click Revert to edit rows"
                                            </span>
                                            <button
                                                type="button"
                                                class="shrink-0 px-2.5 py-1 rounded-full text-xs font-semibold bg-white
                                                       text-rose-700 ring-1 ring-rose-300 hover:bg-rose-100 cursor-pointer"
                                                on:click=move |_| sync_raw_from_builder()
                                            >
                                                "Revert to builder"
                                            </button>
                                        </div>
                                    })}
                                    <div
                                        inert=move || raw_syntax_error.get()
                                        class=move || if raw_syntax_error.get() {
                                            "flex flex-col gap-2 opacity-50 pointer-events-none select-none transition-opacity"
                                        } else {
                                            "flex flex-col gap-2 transition-opacity"
                                        }
                                    >
                                        <For
                                            each=move || item_ids.get()
                                            key=|id| *id
                                            let(id)
                                        >
                                            {render_item(id)}
                                        </For>
                                    </div>
                                </div>
                            }.into_any()
                        }}
                    </div>

                    // Section 2: Synced Editable Raw Query Box + Validation + Examples
                    <div class="flex flex-col gap-2 pt-3 border-t border-sky-100">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <label
                                for="adv-raw-query"
                                class="text-xs font-semibold uppercase tracking-wide text-slate-600"
                            >
                                "Query Preview & Raw Editor"
                            </label>
                            <div class="flex flex-wrap items-center gap-2">
                                // Live validation status pill
                                {move || match validation.get() {
                                    ValidationState::Empty => view! {
                                        <span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-500">
                                            "Add a condition or type a query"
                                        </span>
                                    }.into_any(),
                                    ValidationState::Valid(plan) => {
                                        let kind = match plan.result_kind {
                                            ResultKind::Posts => "Returns Posts",
                                            ResultKind::Images => "Returns Images",
                                        };
                                        let label = match ranker_summary(&plan) {
                                            Some(r) => format!("\u{2713} Valid \u{00B7} {kind} \u{00B7} {r}"),
                                            None => format!("\u{2713} Valid \u{00B7} {kind}"),
                                        };
                                        view! {
                                            <span class="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200">
                                                {label}
                                            </span>
                                        }.into_any()
                                    }
                                    ValidationState::Error(msg) => view! {
                                        <span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-50 text-rose-700 ring-1 ring-rose-200 max-w-full truncate">
                                            {msg}
                                        </span>
                                    }.into_any(),
                                }}

                                <button
                                    type="button"
                                    class="text-xs font-medium text-sky-600 hover:text-sky-800 hover:underline cursor-pointer"
                                    on:click=move |_| show_cheat_sheet.update(|v| *v = !*v)
                                >
                                    {move || if show_cheat_sheet.get() { "Hide syntax" } else { "Syntax help" }}
                                </button>
                            </div>
                        </div>

                        <textarea
                            node_ref=raw_ref
                            id="adv-raw-query"
                            rows="2"
                            spellcheck="false"
                            placeholder="e.g. (tag:\"maid\" OR tag:\"apron\") AND author:渡久山 NOT tag:monochrome"
                            class=move || {
                                let ring = match validation.get() {
                                    ValidationState::Error(_) => "border-rose-300 focus:border-rose-400 focus:ring-rose-200/70",
                                    ValidationState::Valid(_) => "border-emerald-300/80 focus:border-sky-400 focus:ring-sky-200/70",
                                    ValidationState::Empty => "border-sky-200 focus:border-sky-400 focus:ring-sky-200/70",
                                };
                                format!(
                                    "w-full rounded-2xl bg-slate-50/80 border px-3.5 py-2.5 font-mono text-xs sm:text-sm \
                                     text-slate-800 placeholder:text-slate-400 outline-none focus:bg-white focus:ring-2 transition resize-y {ring}"
                                )
                            }
                            on:input=move |ev| apply_raw_text(event_target_value(&ev), false)
                            on:keydown={
                                let submit_key = submit_btn.clone();
                                move |ev: leptos::ev::KeyboardEvent| {
                                    if !ev.is_composing()
                                        && ev.key_code() != 229
                                        && (ev.ctrl_key() || ev.meta_key())
                                        && ev.key() == "Enter"
                                    {
                                        ev.prevent_default();
                                        submit_key();
                                    }
                                }
                            }
                        >{init_raw_text}</textarea>

                        // Quick-fill example chips
                        <div class="flex flex-wrap items-center gap-1.5 text-[11px]">
                            <span class="text-slate-400 font-medium">"Examples:"</span>
                            {QUICK_EXAMPLES.iter().map(|&(label, query)| {
                                view! {
                                    <button
                                        type="button"
                                        title=query
                                        class="px-2.5 py-0.5 rounded-full bg-sky-50 hover:bg-sky-100 text-sky-700
                                               ring-1 ring-sky-200/80 transition-colors cursor-pointer"
                                        on:click=move |_| apply_raw_text(query.to_string(), true)
                                    >
                                        {label}
                                    </button>
                                }
                            }).collect_view()}
                        </div>

                        // Collapsible syntax cheat sheet
                        {move || show_cheat_sheet.get().then(|| view! {
                            <div class="rounded-2xl bg-slate-50 ring-1 ring-slate-200/80 p-3 text-xs text-slate-600 grid grid-cols-1 sm:grid-cols-2 gap-2">
                                <div>
                                    <div class="font-semibold text-slate-700 mb-1">"Fields"</div>
                                    <div class="font-mono text-[11px] leading-relaxed">
                                        "tag:  author:  title:  all:  clip:  dino:  upload:"
                                    </div>
                                </div>
                                <div>
                                    <div class="font-semibold text-slate-700 mb-1">"Operators"</div>
                                    <div class="font-mono text-[11px] leading-relaxed">
                                        "AND  OR  NOT  -term  ( ... )  \"phrase with spaces\""
                                    </div>
                                </div>
                                <div class="sm:col-span-2 text-[11px] text-slate-500">
                                    "Post-only queries (all / title / author) return Posts; adding any Tag, CLIP, Similar ID, or Upload clause automatically switches results to Images. Vector clauses combine with AND / NOT."
                                </div>
                            </div>
                        })}
                    </div>

                    // Section 3: Dynamic Options (CLIP/Visual balance + Min similarity OR Tag sort toggle)
                    {move || match validation.get() {
                        ValidationState::Valid(plan) if plan.has_vectors() => {
                            let dual = plan.has_clip() && plan.has_dino();
                            let badge = match (plan.has_clip(), plan.has_dino()) {
                                (true, true) => "SigLIP2 + DINOv3",
                                (true, false) => "SigLIP2",
                                (false, true) => "DINOv3",
                                _ => "Vector",
                            };
                            Some(view! {
                                <div class="flex flex-col gap-2">
                                    {dual.then(|| view! {
                                        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-3.5 py-2.5
                                                    rounded-2xl bg-indigo-50/60 ring-1 ring-indigo-200/80">
                                            <div class="flex items-center gap-2 text-xs font-semibold text-indigo-800">
                                                <span>"CLIP / Visual balance"</span>
                                            </div>
                                            <div class="flex items-center gap-3 flex-1 sm:max-w-md">
                                                <span class="text-xs font-medium text-sky-700 tabular-nums whitespace-nowrap">
                                                    {move || format!("CLIP {}%", clip_weight.get())}
                                                </span>
                                                <input
                                                    type="range"
                                                    min="5"
                                                    max="95"
                                                    step="5"
                                                    aria-label="CLIP versus Visual similarity balance"
                                                    class="flex-1 accent-indigo-500 cursor-pointer"
                                                    prop:value=move || clip_weight.get().to_string()
                                                    on:input=move |ev| {
                                                        if let Ok(v) = event_target_value(&ev).parse::<i32>() {
                                                            clip_weight.set(v.clamp(5, 95));
                                                        }
                                                    }
                                                />
                                                <span class="text-xs font-medium text-indigo-700 tabular-nums whitespace-nowrap">
                                                    {move || format!("Visual {}%", 100 - clip_weight.get())}
                                                </span>
                                            </div>
                                        </div>
                                    })}
                                    <div class="px-3.5 py-2.5 rounded-2xl bg-sky-50/65 ring-1 ring-sky-200/80">
                                        <MinSimilaritySlider
                                            value=min_similarity
                                            label="Min similarity"
                                            model_badge=badge
                                        />
                                    </div>
                                </div>
                            }.into_any())
                        }
                        ValidationState::Valid(plan)
                            if !plan.has_vectors() && !plan.positive_tags.is_empty() =>
                        {
                            Some(view! {
                                <div class="flex items-center justify-between gap-2 px-3.5 py-2
                                            rounded-2xl bg-sky-50/70 ring-1 ring-sky-200/80">
                                    <span class="text-xs font-semibold text-sky-800">"Sort images by"</span>
                                    <div class="inline-flex items-center p-0.5 rounded-full bg-white ring-1 ring-sky-200">
                                        <button
                                            type="button"
                                            aria-pressed=move || (sort.get() == AdvancedSort::Relevance).to_string()
                                            class=move || if sort.get() == AdvancedSort::Relevance {
                                                "px-3 py-1 rounded-full text-xs font-semibold bg-sky-500 text-white cursor-pointer transition-colors"
                                            } else {
                                                "px-3 py-1 rounded-full text-xs font-medium text-sky-700 hover:bg-sky-50 cursor-pointer transition-colors"
                                            }
                                            on:click=move |_| sort.set(AdvancedSort::Relevance)
                                        >
                                            "Relevance"
                                        </button>
                                        <button
                                            type="button"
                                            aria-pressed=move || (sort.get() == AdvancedSort::Newest).to_string()
                                            class=move || if sort.get() == AdvancedSort::Newest {
                                                "px-3 py-1 rounded-full text-xs font-semibold bg-sky-500 text-white cursor-pointer transition-colors"
                                            } else {
                                                "px-3 py-1 rounded-full text-xs font-medium text-sky-700 hover:bg-sky-50 cursor-pointer transition-colors"
                                            }
                                            on:click=move |_| sort.set(AdvancedSort::Newest)
                                        >
                                            "Newest"
                                        </button>
                                    </div>
                                </div>
                            }.into_any())
                        }
                        _ => None,
                    }}
                </div>

                // Footer
                <div class="flex flex-wrap items-center justify-between gap-2 px-5 py-3.5
                            border-t border-sky-100 bg-sky-50/40 rounded-b-3xl">
                    <button
                        type="button"
                        class="px-3.5 py-1.5 rounded-full text-xs sm:text-sm font-medium text-slate-600
                               hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                        on:click=clear_all
                    >
                        "Clear all"
                    </button>

                    <div class="flex items-center gap-2">
                        <button
                            type="button"
                            class="px-4 py-2 rounded-full text-xs sm:text-sm font-medium text-slate-600
                                   bg-white hover:bg-slate-100 ring-1 ring-slate-200 transition-colors cursor-pointer"
                            on:click=move |_| open.set(false)
                        >
                            "Cancel"
                        </button>
                        <button
                            type="submit"
                            prop:disabled=move || !matches!(validation.get(), ValidationState::Valid(_))
                            class="px-5 py-2 rounded-full text-xs sm:text-sm font-semibold text-white
                                   bg-gradient-to-r from-sky-400 via-blue-500 to-indigo-500
                                   shadow-sm shadow-sky-300/60 hover:brightness-105 active:scale-95
                                   disabled:opacity-45 disabled:cursor-not-allowed disabled:active:scale-100
                                   transition-all cursor-pointer"
                        >
                            "Search"
                        </button>
                    </div>
                </div>
            </form>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gen() -> impl FnMut() -> u64 {
        let mut n = 1u64;
        move || {
            let id = n;
            n += 1;
            id
        }
    }

    #[test]
    fn roundtrips_flat_and_grouped_wos_queries() {
        let cases = [
            r#"tag:maid"#,
            r#"NOT tag:monochrome"#,
            r#"(tag:"black hair" OR tag:maid) AND author:渡久山 NOT tag:monochrome"#,
            r#"tag:maid OR tag:apron"#,
            r#"NOT tag:monochrome OR tag:maid"#,
            r#"tag:maid OR NOT tag:monochrome"#,
            r#"author:渡久山 AND NOT (title:预告 OR title:花絮)"#,
            r#"tag:maid AND clip:"sunny cafe" AND NOT clip:"dark room" AND dino:2286979"#,
            r#"(tag:maid AND author:foo) OR (tag:apron AND author:bar)"#,
            r#"(tag:a AND (tag:b OR tag:c)) OR tag:d"#,
            r#"tag:d OR ((tag:b OR tag:c) AND tag:a)"#,
        ];

        for raw in cases {
            let expr = parse_query(raw).expect("input parses");
            let mut id_gen = make_gen();
            let items = expr_to_builder(&expr, &[], &mut id_gen)
                .unwrap_or_else(|| panic!("expected builder items for: {raw}"));
            let (rebuilt, _) = builder_to_expr(&items);
            assert_eq!(
                rebuilt.as_ref(),
                Some(&expr),
                "roundtrip mismatch for {raw}"
            );

            let formatted = rebuilt.unwrap().format_query();
            let reparsed = parse_query(&formatted).expect("reformatted parses");
            assert_eq!(reparsed, expr, "formatted roundtrip mismatch for {raw}");
        }

        // OR branch containing an explicit OR group roundtrips structurally in builder AST.
        let grouped_or = parse_query("tag:a OR (tag:b OR tag:c)").unwrap();
        let mut id_gen = make_gen();
        let items = expr_to_builder(&grouped_or, &[], &mut id_gen)
            .expect("OR branch with OR group should build");
        let (rebuilt, _) = builder_to_expr(&items);
        assert_eq!(rebuilt.as_ref(), Some(&grouped_or));
    }

    #[test]
    fn deeply_nested_query_falls_back_to_custom_raw_mode() {
        let raw = "((tag:a OR tag:b) AND (tag:c OR tag:d)) OR tag:e";
        let expr = parse_query(raw).expect("valid deep query");
        let mut id_gen = make_gen();
        assert!(expr_to_builder(&expr, &[], &mut id_gen).is_none());
    }

    #[test]
    fn upload_slots_assign_contiguous_indices_and_validate() {
        let slot0 = UploadedImageSlot {
            filename: "a.png".into(),
            b64: "AAAA".into(),
            preview_url: "data:image/webp;base64,AAAA".into(),
        };
        let slot1 = UploadedImageSlot {
            filename: "b.png".into(),
            b64: "BBBB".into(),
            preview_url: "data:image/webp;base64,BBBB".into(),
        };
        let items = vec![
            BuilderItem {
                id: 1,
                connector: Connector::And,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: 2,
                    field: SearchField::Upload,
                    value: String::new(),
                    upload: Some(slot0.clone()),
                }),
            },
            BuilderItem {
                id: 3,
                connector: Connector::Not,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: 4,
                    field: SearchField::Upload,
                    value: String::new(),
                    upload: Some(slot1.clone()),
                }),
            },
        ];

        let (formatted, slots) = format_builder_to_query(&items);
        let slot_opts: Vec<Option<UploadedImageSlot>> = slots.iter().cloned().map(Some).collect();
        assert_eq!(formatted, "upload:0 AND NOT upload:1");
        assert_eq!(slots, vec![slot0.clone(), slot1.clone()]);
        assert!(matches!(
            validate_raw_query(&formatted, &slot_opts),
            ValidationState::Valid(_)
        ));
        assert!(matches!(
            validate_raw_query(&formatted, &[Some(slot0.clone())]),
            ValidationState::Error(_)
        ));

        let expr = parse_query(&formatted).unwrap();
        let mut id_gen = make_gen();
        let rebuilt = expr_to_builder(&expr, &slot_opts, &mut id_gen).unwrap();
        assert_eq!(rebuilt.len(), 2);
        match &rebuilt[0].kind {
            BuilderItemKind::Row(r) => assert_eq!(r.upload.as_ref(), Some(&slot0)),
            _ => panic!("expected upload row 0"),
        }
        match &rebuilt[1].kind {
            BuilderItemKind::Row(r) => assert_eq!(r.upload.as_ref(), Some(&slot1)),
            _ => panic!("expected upload row 1"),
        }
    }

    #[test]
    fn prune_and_remap_uploads_compacts_after_deleting_upload_zero() {
        let slot0 = UploadedImageSlot {
            filename: "first.webp".into(),
            b64: "AAAA".into(),
            preview_url: "data:image/webp;base64,AAAA".into(),
        };
        let slot1 = UploadedImageSlot {
            filename: "second.webp".into(),
            b64: "BBBB".into(),
            preview_url: "data:image/webp;base64,BBBB".into(),
        };
        let pool = vec![Some(slot0), Some(slot1.clone())];

        // Starting from `upload:0 AND upload:1`, user deletes `upload:0` in raw editor -> `upload:1`.
        let (submitted_raw, pruned_slots) =
            prune_and_remap_uploads("upload:1", &pool).expect("remaps cleanly");
        assert_eq!(submitted_raw, "upload:0");
        assert_eq!(pruned_slots, vec![slot1.clone()]);

        // Also handles negated or sparse references.
        let sparse_pool = vec![None, Some(slot1.clone())];
        let (neg_raw, neg_slots) =
            prune_and_remap_uploads("tag:maid AND NOT upload:1", &sparse_pool)
                .expect("sparse remaps cleanly");
        assert_eq!(neg_raw, "tag:maid AND NOT upload:0");
        assert_eq!(neg_slots, vec![slot1]);
    }

    #[test]
    fn unattached_upload_row_never_collides_with_attached_slot() {
        let slot = UploadedImageSlot {
            filename: "b.png".into(),
            b64: "BBBB".into(),
            preview_url: "data:image/webp;base64,BBBB".into(),
        };
        let items = vec![
            // Row 1: unattached Upload row carrying stale `value: "0"` (e.g. from reloaded URL)
            BuilderItem {
                id: 1,
                connector: Connector::And,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: 2,
                    field: SearchField::Upload,
                    value: "0".into(),
                    upload: None,
                }),
            },
            // Row 2: attached Upload row
            BuilderItem {
                id: 3,
                connector: Connector::And,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: 4,
                    field: SearchField::Upload,
                    value: String::new(),
                    upload: Some(slot.clone()),
                }),
            },
        ];

        let (formatted, slots) = format_builder_to_query(&items);
        let slot_opts: Vec<Option<UploadedImageSlot>> = slots.iter().cloned().map(Some).collect();
        assert_eq!(formatted, "upload:0");
        assert_eq!(slots, vec![slot]);
        assert_eq!(
            validate_panel_state(&formatted, &slot_opts, &items, false, 0, 0),
            ValidationState::Error("Choose an image for every Upload Image condition".into())
        );
        // Pending encoding and decode failure both block submission.
        assert_eq!(
            validate_panel_state("upload:0", &slot_opts, &items, true, 1, 0),
            ValidationState::Error("Encoding uploaded image\u{2026}".into())
        );
        assert_eq!(
            validate_panel_state("upload:0", &slot_opts, &items, true, 0, 1),
            ValidationState::Error("Image upload failed \u{2014} choose another image".into())
        );
    }

    #[test]
    fn adding_vector_normalizes_all_top_level_or_connectors_to_and() {
        let mut items = vec![
            BuilderItem {
                id: 1,
                connector: Connector::And,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: 2,
                    field: SearchField::Clip,
                    value: "sunset".into(),
                    upload: None,
                }),
            },
            BuilderItem {
                id: 3,
                connector: Connector::Or,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: 4,
                    field: SearchField::Tag,
                    value: "maid".into(),
                    upload: None,
                }),
            },
            BuilderItem {
                id: 5,
                connector: Connector::Or,
                kind: BuilderItemKind::Group {
                    combinator: GroupCombinator::Or,
                    rows: vec![InnerRow {
                        id: 6,
                        negated: false,
                        field: SearchField::Tag,
                        value: "apron".into(),
                    }],
                },
            },
        ];
        assert!(items_have_vector(&items));
        normalize_or_connectors_for_vectors(&mut items);
        assert!(items.iter().all(|it| it.connector != Connector::Or));
    }

    #[test]
    fn deleting_last_row_of_first_group_normalizes_shifted_or_connector() {
        let mut items = vec![
            BuilderItem {
                id: 1,
                connector: Connector::And,
                kind: BuilderItemKind::Group {
                    combinator: GroupCombinator::Or,
                    rows: vec![InnerRow {
                        id: 2,
                        negated: false,
                        field: SearchField::Tag,
                        value: "maid".into(),
                    }],
                },
            },
            BuilderItem {
                id: 3,
                connector: Connector::Or,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: 4,
                    field: SearchField::Tag,
                    value: "apron".into(),
                    upload: None,
                }),
            },
        ];

        let mut id_gen = make_gen();
        remove_group_inner_row(&mut items, 1, 2, &mut id_gen);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, 3);
        assert_eq!(items[0].connector, Connector::And);
    }

    #[test]
    fn reconcile_builder_ids_preserves_existing_row_and_group_ids() {
        let prev = vec![
            BuilderItem {
                id: 10,
                connector: Connector::And,
                kind: BuilderItemKind::Group {
                    combinator: GroupCombinator::Or,
                    rows: vec![
                        InnerRow {
                            id: 11,
                            negated: false,
                            field: SearchField::Tag,
                            value: "mai".into(),
                        },
                        InnerRow {
                            id: 12,
                            negated: false,
                            field: SearchField::Tag,
                            value: "apron".into(),
                        },
                    ],
                },
            },
            BuilderItem {
                id: 20,
                connector: Connector::And,
                kind: BuilderItemKind::Row(BuilderRow {
                    id: 21,
                    field: SearchField::Author,
                    value: "foo".into(),
                    upload: None,
                }),
            },
        ];

        let expr = parse_query("(tag:maid OR tag:apron) AND author:foobar").unwrap();
        let mut id_gen = || 999;
        let mut next = expr_to_builder(&expr, &[], &mut id_gen).unwrap();
        reconcile_builder_ids(&prev, &mut next);

        assert_eq!(next[0].id, 10);
        match &next[0].kind {
            BuilderItemKind::Group { rows, .. } => {
                assert_eq!(rows[0].id, 11);
                assert_eq!(rows[1].id, 12);
            }
            _ => panic!("expected group"),
        }
        assert_eq!(next[1].id, 20);
        match &next[1].kind {
            BuilderItemKind::Row(r) => assert_eq!(r.id, 21),
            _ => panic!("expected row"),
        }
    }

    #[test]
    fn builds_advanced_nav_url_with_optional_params() {
        let (_, tag_plan) = parse_and_compile("tag:maid").unwrap();
        assert_eq!(
            build_advanced_nav_url(
                "tag:maid",
                &tag_plan,
                AdvancedSort::Relevance,
                50,
                None,
                None,
                50
            ),
            "/?mode=advanced&adv=tag%3Amaid"
        );
        assert_eq!(
            build_advanced_nav_url(
                "tag:maid",
                &tag_plan,
                AdvancedSort::Newest,
                50,
                Some(0.5),
                None,
                25
            ),
            "/?mode=advanced&adv=tag%3Amaid&sort=newest&limit=25"
        );

        let (_, dual_plan) = parse_and_compile(r#"clip:"cafe" AND dino:42"#).unwrap();
        assert_eq!(
            build_advanced_nav_url(
                r#"clip:"cafe" AND dino:42"#,
                &dual_plan,
                AdvancedSort::Newest,
                70,
                Some(0.35),
                None,
                50
            ),
            "/?mode=advanced&adv=clip%3A%22cafe%22%20AND%20dino%3A42&cw=70&min_sim=0.35"
        );

        let (_, upload_plan) = parse_and_compile("upload:0").unwrap();
        assert_eq!(
            build_advanced_nav_url(
                "upload:0",
                &upload_plan,
                AdvancedSort::Relevance,
                50,
                None,
                Some("123-1"),
                50
            ),
            "/?mode=advanced&adv=upload%3A0&img=123-1"
        );
    }

    #[test]
    fn prepopulates_from_default_and_legacy_urls() {
        let mut id_gen = make_gen();
        let (items, raw, custom, _, _, _) = build_initial_state(
            Some(UrlSearchState {
                mode: Mode::Author,
                q: "渡久山".into(),
                ..Default::default()
            }),
            None,
            None,
            &mut id_gen,
        );
        assert!(!custom);
        assert_eq!(items.len(), 1);
        assert_eq!(raw, "author:渡久山");

        let (items2, raw2, _, _, _, _) = build_initial_state(
            Some(UrlSearchState {
                mode: Mode::Tag,
                q: "black hair".into(),
                ..Default::default()
            }),
            None,
            None,
            &mut id_gen,
        );
        assert_eq!(items2.len(), 1);
        assert_eq!(raw2, r#"tag:"black hair""#);
    }
}
