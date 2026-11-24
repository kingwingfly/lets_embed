//! Advanced Search modal powered by the unified `lets_embed_ui::QueryBuilder`
//! (`QueryBuilderMode::AdvancedSearch`).
//!
//! Features:
//! - Self-contained mobile-clean condition cards & nested boolean groups with top-right `×`.
//! - Inline per-condition `>=0.01..=1.00` thresholds via `<OptionalScoreInput>` on `Tag`,
//!   `CLIP Text`, `Similar ID`, and `Upload Image` (zero CLIP/DINO weight sliders!).
//! - Multi-image upload slot picker wired via `QueryBuilder`'s `render_upload_slot` callback.
//! - Live `search_types::query::parse_and_compile` validation & result-kind badge (`Posts` | `Images`).

use std::collections::{BTreeSet, HashMap, HashSet};

#[cfg(feature = "hydrate")]
use crate::components::search_bar::encode_image_file;
use crate::components::search_bar::{DEFAULT_LIMIT, UrlSearchState};
use crate::types::{
    AdvancedUploads, AdvancedUploadsPayload, ImageQuery, Mode, SafetyUiState, UploadedImageSlot,
};
#[cfg(feature = "hydrate")]
use crate::util::trap_dialog_tab;
use crate::util::{lock_body_scroll, navigate_from_modal, push_modal_history};
#[cfg(feature = "hydrate")]
use leptos::{ev, task::spawn_local};
use leptos::{html, prelude::*};
use leptos_router::{NavigateOptions, hooks::use_navigate};
#[cfg(feature = "hydrate")]
use leptos_use_event_listener::use_event_listener;
use lets_embed_ui::{
    QueryBuilder, QueryBuilderDraft, QueryBuilderMode, QueryBuilderNode, QueryCondition,
    QueryConnector, QueryFieldKind, QueryThresholdDefaults,
};
use search_types::query::{
    AdvancedSort, QueryExpr, QueryPlan, ResultKind, SearchField, VectorTier, parse_and_compile,
    parse_query,
};
#[cfg(feature = "hydrate")]
use wasm_bindgen::JsCast as _;

const QUICK_EXAMPLES: &[(&str, &str)] = &[
    (
        "Maid or apron (no monochrome)",
        "(tag:maid OR tag:apron) NOT tag:monochrome",
    ),
    (
        "Tag + CLIP with cutoffs",
        "tag:blue_sky>=0.50 AND clip:\"sunlit coastal breeze\">=0.25",
    ),
    (
        "Author posts without preview",
        "author:渡久山 NOT title:预告",
    ),
];

#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
enum ValidationState {
    Empty,
    Valid(QueryPlan),
    Error(String),
}

fn preview_url_from_urlsafe_b64(url_safe: &str) -> String {
    let mut std_b64 = url_safe.replace('-', "+").replace('_', "/");
    while !std_b64.len().is_multiple_of(4) {
        std_b64.push('=');
    }
    format!("data:image/webp;base64,{std_b64}")
}

fn collect_upload_indices(expr: &QueryExpr, out: &mut BTreeSet<usize>) {
    match expr {
        QueryExpr::Term {
            field: SearchField::Upload,
            value,
            ..
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

fn remap_upload_expr(expr: &QueryExpr, map: &HashMap<usize, usize>) -> Option<QueryExpr> {
    match expr {
        QueryExpr::Term {
            field: SearchField::Upload,
            value,
            threshold,
        } => {
            let orig = value.trim().parse::<usize>().ok()?;
            let new_idx = *map.get(&orig)?;
            Some(QueryExpr::Term {
                field: SearchField::Upload,
                value: new_idx.to_string(),
                threshold: *threshold,
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

/// Prune unreferenced upload slots and remap `upload:<idx>` terms to contiguous `0..pruned.len()`,
/// preserving any per-condition `>=threshold` attached to each upload leaf.
pub(crate) fn prune_and_remap_uploads(
    raw: &str,
    slots: &[Option<UploadedImageSlot>],
) -> Option<(String, Vec<UploadedImageSlot>)> {
    let expr = parse_query(raw.trim()).ok()?;
    let mut referenced = BTreeSet::new();
    collect_upload_indices(&expr, &mut referenced);
    if referenced.is_empty() {
        return Some((raw.trim().to_string(), Vec::new()));
    }
    let mut index_map = HashMap::with_capacity(referenced.len());
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

fn has_unattached_upload_node(draft: &QueryBuilderDraft, slots: &[Option<UploadedImageSlot>]) -> bool {
    draft.nodes.iter().any(|node| match node {
        QueryBuilderNode::Condition { condition, .. }
            if condition.field == QueryFieldKind::UploadImage =>
        {
            let Ok(idx) = condition.value.trim().parse::<usize>() else {
                return true;
            };
            slots
                .get(idx)
                .and_then(|s| s.as_ref())
                .is_none_or(|s| s.b64.is_empty())
        }
        _ => false,
    })
}

fn validate_raw_query(raw: &str, slots: &[Option<UploadedImageSlot>]) -> ValidationState {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ValidationState::Empty;
    }
    match parse_and_compile(trimmed) {
        Ok((_, plan)) => {
            for clause in plan.upload_pos.iter().chain(plan.upload_neg.iter()) {
                let idx = clause.slot;
                if slots
                    .get(idx)
                    .and_then(|o| o.as_ref())
                    .is_none_or(|s| s.b64.is_empty())
                {
                    return ValidationState::Error(format!(
                        "Upload slot upload:{idx} has no image attached \u{2014} upload an image above"
                    ));
                }
            }
            ValidationState::Valid(plan)
        }
        Err(err) => ValidationState::Error(err.to_string()),
    }
}

fn validate_panel_state(
    draft: &QueryBuilderDraft,
    slots: &[Option<UploadedImageSlot>],
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
    if has_unattached_upload_node(draft, slots) {
        return ValidationState::Error(
            "Choose an image for every Upload Image condition".to_string(),
        );
    }
    validate_raw_query(&draft.query, slots)
}

pub(crate) fn build_advanced_nav_url(
    raw_query: &str,
    plan: &QueryPlan,
    sort: AdvancedSort,
    img_nonce: Option<&str>,
    limit: usize,
) -> String {
    let mut url = format!(
        "/?mode=advanced&adv={}",
        urlencoding::encode(raw_query.trim())
    );
    if !plan.has_vectors() && !plan.positive_tags.is_empty() && sort == AdvancedSort::Newest {
        url.push_str("&sort=newest");
    }
    if plan.tier == VectorTier::ImageUpload
        && let Some(nonce) = img_nonce
        && !nonce.is_empty()
    {
        url.push_str(&format!("&img={}", urlencoding::encode(nonce)));
    }
    if limit != DEFAULT_LIMIT {
        url.push_str(&format!("&limit={}", limit.max(1)));
    }
    url
}

fn build_initial_draft(
    initial_state: Option<UrlSearchState>,
    adv_uploads: Option<AdvancedUploadsPayload>,
    single_image: Option<crate::types::ImageQueryPayload>,
) -> (QueryBuilderDraft, Vec<Option<UploadedImageSlot>>, AdvancedSort) {
    let Some(st) = initial_state else {
        return (
            QueryBuilderDraft::for_mode(QueryBuilderMode::AdvancedSearch),
            Vec::new(),
            AdvancedSort::Relevance,
        );
    };

    match st.mode {
        Mode::Advanced if !st.adv.trim().is_empty() => {
            let slots: Vec<Option<UploadedImageSlot>> = adv_uploads
                .filter(|p| !st.img_nonce.is_empty() && p.nonce == st.img_nonce)
                .map(|p| p.slots.into_iter().map(Some).collect())
                .unwrap_or_default();
            let raw = st.adv.trim();
            let draft = QueryBuilderDraft::from_query(QueryBuilderMode::AdvancedSearch, raw)
                .unwrap_or_else(|_| {
                    let mut d = QueryBuilderDraft::for_mode(QueryBuilderMode::AdvancedSearch);
                    d.query = raw.to_string();
                    d
                });
            (draft, slots, st.sort)
        }
        Mode::All | Mode::Title | Mode::Author | Mode::Tag | Mode::Clip | Mode::Similar
            if !st.q.trim().is_empty() =>
        {
            let field = match st.mode {
                Mode::Title => QueryFieldKind::Title,
                Mode::Author => QueryFieldKind::Author,
                Mode::Tag => QueryFieldKind::Tag,
                Mode::Clip => QueryFieldKind::ClipText,
                Mode::Similar => QueryFieldKind::SimilarId,
                _ => QueryFieldKind::TitleAndAuthor,
            };
            let threshold = field
                .supports_threshold()
                .then_some(st.min_similarity)
                .flatten()
                .and_then(lets_embed_ui::quantize_threshold);
            let mut draft = QueryBuilderDraft {
                mode: QueryBuilderMode::AdvancedSearch,
                nodes: vec![QueryBuilderNode::Condition {
                    connector: QueryConnector::And,
                    condition: QueryCondition {
                        id: 1,
                        field,
                        value: st.q.trim().to_string(),
                        negated: false,
                        threshold,
                    },
                }],
                query: String::new(),
                active_preset: None,
            };
            draft.sync_query();
            (draft, Vec::new(), AdvancedSort::Relevance)
        }
        Mode::SearchImage if !st.q.trim().is_empty() => {
            if let Some(payload) = single_image.filter(|p| p.nonce == st.q) {
                let slot = UploadedImageSlot {
                    filename: "Uploaded image".to_string(),
                    preview_url: preview_url_from_urlsafe_b64(&payload.b64),
                    b64: payload.b64,
                };
                let threshold = st
                    .min_similarity
                    .and_then(lets_embed_ui::quantize_threshold);
                let mut draft = QueryBuilderDraft {
                    mode: QueryBuilderMode::AdvancedSearch,
                    nodes: vec![QueryBuilderNode::Condition {
                        connector: QueryConnector::And,
                        condition: QueryCondition {
                            id: 1,
                            field: QueryFieldKind::UploadImage,
                            value: "0".to_string(),
                            negated: false,
                            threshold,
                        },
                    }],
                    query: String::new(),
                    active_preset: None,
                };
                draft.sync_query();
                return (draft, vec![Some(slot)], AdvancedSort::Relevance);
            }
            (
                QueryBuilderDraft::for_mode(QueryBuilderMode::AdvancedSearch),
                Vec::new(),
                AdvancedSort::Relevance,
            )
        }
        _ => (
            QueryBuilderDraft::for_mode(QueryBuilderMode::AdvancedSearch),
            Vec::new(),
            AdvancedSort::Relevance,
        ),
    }
}

#[component]
fn UploadSlotControl(
    node_id: u64,
    draft: RwSignal<QueryBuilderDraft>,
    upload_pool: RwSignal<Vec<Option<UploadedImageSlot>>>,
    encoding_nodes: RwSignal<HashSet<u64>>,
    error_nodes: RwSignal<HashMap<u64, String>>,
) -> impl IntoView {
    let input_ref = NodeRef::<html::Input>::new();
    let upload_gen: StoredValue<u64> = StoredValue::new(0);

    let current_slot_idx = Memo::new(move |_| {
        draft.with(|d| {
            d.nodes.iter().find_map(|n| match n {
                QueryBuilderNode::Condition { condition, .. } if condition.id == node_id => {
                    condition.value.trim().parse::<usize>().ok()
                }
                _ => None,
            })
        })
    });

    let current_slot = Memo::new(move |_| {
        let idx = current_slot_idx.get()?;
        upload_pool.with(|pool| pool.get(idx).cloned().flatten())
    });

    let is_encoding = move || encoding_nodes.with(|set| set.contains(&node_id));
    let err_msg = move || error_nodes.with(|map| map.get(&node_id).cloned());

    let clear_upload = move |_| {
        upload_gen.set_value(upload_gen.get_value().wrapping_add(1));
        encoding_nodes.update(|s| {
            s.remove(&node_id);
        });
        error_nodes.update(|m| {
            m.remove(&node_id);
        });
        draft.update(|d| {
            if let Some(QueryBuilderNode::Condition { condition, .. }) =
                d.nodes.iter_mut().find(|n| n.id() == node_id)
            {
                condition.value.clear();
            }
            d.sync_query();
        });
    };

    let on_file_change = move |ev: leptos::ev::Event| {
        #[cfg(feature = "hydrate")]
        {
            let Some(input) = ev
                .target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
            else {
                return;
            };
            let Some(files) = input.files() else {
                return;
            };
            let Some(file) = files.get(0) else {
                return;
            };
            let filename = file.name();
            input.set_value("");

            let next_gen = upload_gen.get_value().wrapping_add(1);
            upload_gen.set_value(next_gen);
            encoding_nodes.update(|s| {
                s.insert(node_id);
            });
            error_nodes.update(|m| {
                m.remove(&node_id);
            });

            spawn_local(async move {
                let encoded = encode_image_file(file).await;
                if upload_gen.try_get_value() != Some(next_gen) {
                    return;
                }
                let _ = encoding_nodes.try_update(|s| {
                    s.remove(&node_id);
                });
                let Some((b64, preview_url)) = encoded else {
                    let _ = error_nodes.try_update(|m| {
                        m.insert(node_id, "Could not decode image file.".to_string());
                    });
                    return;
                };

                // Allocate or reuse slot index exclusively for this UploadImage node.
                let reuse_idx = draft.with_untracked(|d| {
                    let my_idx = d.nodes.iter().find_map(|n| match n {
                        QueryBuilderNode::Condition { condition, .. } if condition.id == node_id => {
                            condition.value.trim().parse::<usize>().ok()
                        }
                        _ => None,
                    })?;
                    let shared = d.nodes.iter().any(|n| match n {
                        QueryBuilderNode::Condition { condition, .. }
                            if condition.id != node_id
                                && condition.field == QueryFieldKind::UploadImage =>
                        {
                            condition.value.trim().parse::<usize>().ok() == Some(my_idx)
                        }
                        _ => false,
                    });
                    (!shared).then_some(my_idx)
                });

                let slot = UploadedImageSlot {
                    filename,
                    b64,
                    preview_url,
                };
                let assigned_idx = match reuse_idx {
                    Some(idx) => {
                        let _ = upload_pool.try_update(|pool| {
                            if idx >= pool.len() {
                                pool.resize(idx + 1, None);
                            }
                            pool[idx] = Some(slot);
                        });
                        idx
                    }
                    None => {
                        let mut new_idx = 0usize;
                        let _ = upload_pool.try_update(|pool| {
                            new_idx = pool.len();
                            pool.push(Some(slot));
                        });
                        new_idx
                    }
                };

                let _ = draft.try_update(|d| {
                    if let Some(QueryBuilderNode::Condition { condition, .. }) =
                        d.nodes.iter_mut().find(|n| n.id() == node_id)
                    {
                        condition.value = assigned_idx.to_string();
                    }
                    d.sync_query();
                });
            });
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = ev;
        }
    };

    view! {
        <div class="flex flex-wrap items-center gap-2 min-w-0 w-full">
            <input
                node_ref=input_ref
                type="file"
                accept="image/*"
                class="hidden"
                on:change=on_file_change
            />
            {move || if is_encoding() {
                view! {
                    <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-sky-50 text-sky-700 text-xs font-medium ring-1 ring-sky-200 animate-pulse">
                        "Encoding image\u{2026}"
                    </span>
                }
                .into_any()
            } else if let Some(slot) = current_slot.get() {
                view! {
                    <div class="flex items-center gap-2 min-w-0 flex-1 bg-sky-50/80 ring-1 ring-sky-200 rounded-xl px-2 py-1">
                        <img
                            src=slot.preview_url
                            alt=slot.filename.clone()
                            class="w-8 h-8 rounded-lg object-cover shrink-0 ring-1 ring-sky-200 bg-white"
                        />
                        <span class="text-xs font-medium text-slate-700 truncate flex-1 min-w-0">
                            {slot.filename}
                        </span>
                        <button
                            type="button"
                            class="shrink-0 px-2 py-0.5 rounded-lg text-[11px] font-semibold text-sky-700 bg-white hover:bg-sky-100 ring-1 ring-sky-200 cursor-pointer"
                            on:click=move |_| {
                                #[cfg(feature = "hydrate")]
                                if let Some(el) = input_ref.get() {
                                    el.click();
                                }
                            }
                        >
                            "Replace"
                        </button>
                        <button
                            type="button"
                            class="shrink-0 px-2 py-0.5 rounded-lg text-[11px] font-medium text-rose-600 bg-white hover:bg-rose-50 ring-1 ring-rose-200 cursor-pointer"
                            on:click=clear_upload
                        >
                            "Clear"
                        </button>
                    </div>
                }
                .into_any()
            } else {
                view! {
                    <button
                        type="button"
                        class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold
                               text-sky-700 bg-sky-50 hover:bg-sky-100 ring-1 ring-sky-200/90 transition-colors cursor-pointer"
                        on:click=move |_| {
                            #[cfg(feature = "hydrate")]
                            if let Some(el) = input_ref.get() {
                                el.click();
                            }
                        }
                    >
                        <span>"\u{1F5BC}\u{FE0F}"</span>
                        <span>"Choose reference image\u{2026}"</span>
                    </button>
                }
                .into_any()
            }}
            {move || err_msg().map(|msg| view! {
                <span class="text-[11px] text-rose-600 font-medium">{msg}</span>
            })}
        </div>
    }
}

#[component]
pub fn AdvancedSearchPanel(
    open: RwSignal<bool>,
    initial_state: Option<UrlSearchState>,
) -> impl IntoView {
    let navigate = use_navigate();
    let adv_uploads = expect_context::<AdvancedUploads>();
    let img_query = expect_context::<ImageQuery>();
    let safety = use_context::<SafetyUiState>();

    let limit = initial_state
        .as_ref()
        .map(|s| s.limit)
        .unwrap_or(DEFAULT_LIMIT);

    let (init_draft, init_slots, init_sort) = build_initial_draft(
        initial_state,
        adv_uploads.0.get_untracked(),
        img_query.0.get_untracked(),
    );

    let draft = RwSignal::new(init_draft);
    let upload_pool = RwSignal::new(init_slots);
    let sort = RwSignal::new(init_sort);
    let encoding_nodes: RwSignal<HashSet<u64>> = RwSignal::new(HashSet::new());
    let error_nodes: RwSignal<HashMap<u64, String>> = RwSignal::new(HashMap::new());
    let dialog_ref = NodeRef::<html::Div>::new();

    lock_body_scroll();
    push_modal_history(move || open.set(false));

    #[cfg(feature = "hydrate")]
    {
        let modal_layer = lets_embed_ui::browser::push_modal_layer();
        Effect::new(move |_| {
            if let Some(el) = dialog_ref.get() {
                let _ = el.focus();
            }
        });

        let _ = use_event_listener(window(), ev::keydown, move |e: ev::KeyboardEvent| {
            if !lets_embed_ui::browser::is_top_modal(modal_layer) {
                return;
            }
            if e.key() == "Tab" {
                trap_dialog_tab(&e, dialog_ref.get_untracked());
                return;
            }
            if e.key() == "Escape"
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

    let threshold_defaults = Signal::derive(move || {
        let (clip_min, dino_min) = safety
            .map(|s| {
                let c = s.default_siglip2_min.get();
                let d = s.default_dinov3_min.get();
                (
                    (c.is_finite() && c > 0.0).then_some(c),
                    (d.is_finite() && d > 0.0).then_some(d),
                )
            })
            .unwrap_or((None, None));
        QueryThresholdDefaults {
            tag_min_score: None,
            clip_min_sim: clip_min,
            dino_min_sim: dino_min,
        }
    });

    let validation = Memo::new(move |_| {
        let d = draft.get();
        let slots = upload_pool.get();
        let enc_count = encoding_nodes.with(HashSet::len);
        let err_count = error_nodes.with(HashMap::len);
        validate_panel_state(&d, &slots, enc_count, err_count)
    });

    let validation_error = Signal::derive(move || match validation.get() {
        ValidationState::Error(msg) => Some(msg),
        _ => None,
    });

    let show_sort_toggle = Memo::new(move |_| match validation.get() {
        ValidationState::Valid(plan) => !plan.has_vectors() && !plan.positive_tags.is_empty(),
        _ => false,
    });

    let apply_example = move |expr: &'static str| {
        if let Ok(next_draft) =
            QueryBuilderDraft::from_query(QueryBuilderMode::AdvancedSearch, expr)
        {
            draft.set(next_draft);
        }
    };

    let clear_all = move |_| {
        draft.set(QueryBuilderDraft::for_mode(QueryBuilderMode::AdvancedSearch));
        upload_pool.set(Vec::new());
        encoding_nodes.set(HashSet::new());
        error_nodes.set(HashMap::new());
        sort.set(AdvancedSort::Relevance);
    };

    let render_upload_slot = Callback::new(move |node_id: u64| {
        view! {
            <UploadSlotControl
                node_id=node_id
                draft=draft
                upload_pool=upload_pool
                encoding_nodes=encoding_nodes
                error_nodes=error_nodes
            />
        }
        .into_any()
    });

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let d = draft.get_untracked();
        let slots = upload_pool.get_untracked();
        let enc_count = encoding_nodes.with_untracked(HashSet::len);
        let err_count = error_nodes.with_untracked(HashMap::len);
        let ValidationState::Valid(plan) = validate_panel_state(&d, &slots, enc_count, err_count)
        else {
            return;
        };

        let (submitted_raw, pruned_slots) = match prune_and_remap_uploads(&d.query, &slots) {
            Some(pair) => pair,
            None => return,
        };

        let nonce = if !pruned_slots.is_empty() {
            let n = format!("{}-{}", js_sys::Date::now() as u64, pruned_slots.len());
            adv_uploads.0.set(Some(AdvancedUploadsPayload {
                nonce: n.clone(),
                slots: pruned_slots,
            }));
            Some(n)
        } else {
            None
        };

        let url = build_advanced_nav_url(
            &submitted_raw,
            &plan,
            sort.get_untracked(),
            nonce.as_deref(),
            limit,
        );
        let nav = navigate.clone();
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
    };

    view! {
        <div
            node_ref=dialog_ref
            id="advanced-search-panel"
            role="dialog"
            aria-modal="true"
            aria-label="Advanced Search Query Builder"
            tabindex="-1"
            class="fixed inset-0 z-[55] flex items-start sm:items-center justify-center p-2 sm:p-4
                   bg-slate-900/50 backdrop-blur-xs overflow-y-auto overscroll-contain outline-none"
            on:click=move |_| open.set(false)
        >
            <form
                on:submit=on_submit
                on:click=|ev| ev.stop_propagation()
                class="w-full max-w-3xl my-auto rounded-2xl sm:rounded-3xl bg-white/98 backdrop-blur-md
                       ring-1 ring-sky-200/90 shadow-2xl shadow-sky-900/20 flex flex-col max-h-[92dvh] overflow-hidden"
            >
                // Modal Header
                <div class="shrink-0 flex items-center justify-between gap-2 px-4 sm:px-5 py-3
                            border-b border-sky-100 bg-gradient-to-r from-sky-50/90 via-white to-indigo-50/70">
                    <div class="flex items-center gap-2 min-w-0 flex-wrap">
                        <h2 class="text-sm sm:text-base font-bold text-slate-800 m-0 truncate">
                            "Advanced Query Builder"
                        </h2>
                        {move || match validation.get() {
                            ValidationState::Valid(plan) => {
                                let (kind_lbl, kind_cls) = match plan.result_kind {
                                    ResultKind::Posts => ("Posts", "bg-sky-100 text-sky-700 ring-sky-200"),
                                    ResultKind::Images => ("Images", "bg-indigo-100 text-indigo-700 ring-indigo-200"),
                                };
                                let tier_badge = match plan.tier {
                                    VectorTier::None => None,
                                    VectorTier::EmbedId => Some("Visual ID"),
                                    VectorTier::Clip => Some("CLIP"),
                                    VectorTier::ImageUpload => Some("Image Upload"),
                                };
                                Some(view! {
                                    <span class=format!(
                                        "px-2 py-0.5 rounded-full text-[11px] font-semibold ring-1 whitespace-nowrap {kind_cls}"
                                    )>
                                        {kind_lbl}
                                    </span>
                                    {tier_badge.map(|tb| view! {
                                        <span class="px-2 py-0.5 rounded-full text-[11px] font-medium bg-slate-100 text-slate-600 ring-1 ring-slate-200 whitespace-nowrap">
                                            {tb}
                                        </span>
                                    })}
                                }.into_any())
                            }
                            _ => None,
                        }}
                    </div>
                    <button
                        type="button"
                        aria-label="Close Advanced Search"
                        title="Close (Esc)"
                        class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700
                               hover:bg-sky-100/80 transition-colors cursor-pointer shrink-0 text-lg"
                        on:click=move |_| open.set(false)
                    >
                        "\u{00D7}"
                    </button>
                </div>

                // Scrollable Body with unified QueryBuilder
                <div class="flex-1 min-h-0 overflow-y-auto overscroll-contain p-3.5 sm:p-5 flex flex-col gap-3.5">
                    // Quick Examples bar
                    <div class="flex flex-wrap items-center gap-1.5">
                        <span class="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mr-1">
                            "Examples:"
                        </span>
                        {QUICK_EXAMPLES.iter().map(|(label, expr)| {
                            let q = *expr;
                            view! {
                                <button
                                    type="button"
                                    class="px-2.5 py-1 rounded-full text-[11px] font-medium bg-sky-50 hover:bg-sky-100
                                           text-sky-700 ring-1 ring-sky-200/80 transition-colors cursor-pointer"
                                    on:click=move |_| apply_example(q)
                                >
                                    {*label}
                                </button>
                            }
                        }).collect_view()}
                    </div>

                    <QueryBuilder
                        draft=draft
                        mode=QueryBuilderMode::AdvancedSearch
                        show_presets=false
                        threshold_defaults=threshold_defaults
                        validation_error=validation_error
                        render_upload_slot=render_upload_slot
                        show_raw_editor=true
                    />

                    // Optional Tag Sort toggle when query is metadata-only with positive tags
                    {move || show_sort_toggle.get().then(|| view! {
                        <div class="flex flex-wrap items-center justify-between gap-2 px-3 py-2 rounded-xl bg-sky-50/70 ring-1 ring-sky-200/70">
                            <span class="text-xs font-semibold text-slate-700">"Tag result order"</span>
                            <div class="inline-flex items-center p-0.5 rounded-full bg-white ring-1 ring-sky-200">
                                <button
                                    type="button"
                                    aria-pressed=move || (sort.get() == AdvancedSort::Relevance).to_string()
                                    class=move || if sort.get() == AdvancedSort::Relevance {
                                        "px-3 py-1 rounded-full text-xs font-semibold bg-sky-500 text-white shadow-xs cursor-pointer"
                                    } else {
                                        "px-3 py-1 rounded-full text-xs font-medium text-slate-600 hover:text-sky-700 cursor-pointer"
                                    }
                                    on:click=move |_| sort.set(AdvancedSort::Relevance)
                                >
                                    "Confidence"
                                </button>
                                <button
                                    type="button"
                                    aria-pressed=move || (sort.get() == AdvancedSort::Newest).to_string()
                                    class=move || if sort.get() == AdvancedSort::Newest {
                                        "px-3 py-1 rounded-full text-xs font-semibold bg-sky-500 text-white shadow-xs cursor-pointer"
                                    } else {
                                        "px-3 py-1 rounded-full text-xs font-medium text-slate-600 hover:text-sky-700 cursor-pointer"
                                    }
                                    on:click=move |_| sort.set(AdvancedSort::Newest)
                                >
                                    "Newest"
                                </button>
                            </div>
                        </div>
                    })}
                </div>

                // Modal Footer
                <div class="shrink-0 flex items-center justify-between gap-2 px-4 sm:px-5 py-3
                            border-t border-sky-100 bg-sky-50/40">
                    <button
                        type="button"
                        class="px-3.5 py-1.5 rounded-full text-xs sm:text-sm font-medium text-slate-600
                               hover:text-rose-600 hover:bg-rose-50 ring-1 ring-slate-200/90 transition-colors cursor-pointer"
                        on:click=clear_all
                    >
                        "Reset"
                    </button>
                    <div class="flex items-center gap-2">
                        <button
                            type="button"
                            class="px-4 py-1.5 rounded-full text-xs sm:text-sm font-medium text-slate-600
                                   bg-white hover:bg-slate-50 ring-1 ring-slate-200 transition-colors cursor-pointer"
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

    #[test]
    fn prune_and_remap_uploads_compacts_sparse_slots_and_preserves_thresholds() {
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

        let (submitted_raw, pruned_slots) =
            prune_and_remap_uploads("upload:1>=0.35", &pool).expect("remaps cleanly");
        assert_eq!(submitted_raw, "upload:0>=0.35");
        assert_eq!(pruned_slots, vec![slot1.clone()]);

        let sparse_pool = vec![None, Some(slot1.clone())];
        let (neg_raw, neg_slots) =
            prune_and_remap_uploads("tag:maid>=0.50 AND NOT upload:1>=0.25", &sparse_pool)
                .expect("sparse remaps cleanly");
        assert_eq!(neg_raw, "tag:maid>=0.50 AND NOT upload:0>=0.25");
        assert_eq!(neg_slots, vec![slot1]);
    }

    #[test]
    fn validate_panel_state_blocks_unattached_or_encoding_uploads() {
        let slot = UploadedImageSlot {
            filename: "a.webp".into(),
            b64: "AAAA".into(),
            preview_url: "data:image/webp;base64,AAAA".into(),
        };
        let unattached = QueryBuilderDraft {
            mode: QueryBuilderMode::AdvancedSearch,
            nodes: vec![QueryBuilderNode::Condition {
                connector: QueryConnector::And,
                condition: QueryCondition {
                    id: 1,
                    field: QueryFieldKind::UploadImage,
                    value: "0".into(),
                    negated: false,
                    threshold: Some(0.35),
                },
            }],
            query: "upload:0>=0.35".into(),
            active_preset: None,
        };
        assert_eq!(
            validate_panel_state(&unattached, &[], 0, 0),
            ValidationState::Error("Choose an image for every Upload Image condition".into())
        );
        assert!(matches!(
            validate_panel_state(&unattached, &[Some(slot.clone())], 0, 0),
            ValidationState::Valid(_)
        ));
        assert_eq!(
            validate_panel_state(&unattached, &[Some(slot.clone())], 1, 0),
            ValidationState::Error("Encoding uploaded image\u{2026}".into())
        );
        assert_eq!(
            validate_panel_state(&unattached, &[Some(slot)], 0, 1),
            ValidationState::Error("Image upload failed \u{2014} choose another image".into())
        );
    }

    #[test]
    fn builds_advanced_nav_url_without_clip_weight() {
        let (_, tag_plan) = parse_and_compile("tag:maid>=0.45").unwrap();
        assert_eq!(
            build_advanced_nav_url("tag:maid>=0.45", &tag_plan, AdvancedSort::Relevance, None, 50),
            "/?mode=advanced&adv=tag%3Amaid%3E%3D0.45"
        );
        assert_eq!(
            build_advanced_nav_url("tag:maid>=0.45", &tag_plan, AdvancedSort::Newest, None, 25),
            "/?mode=advanced&adv=tag%3Amaid%3E%3D0.45&sort=newest&limit=25"
        );

        let (_, dual_plan) =
            parse_and_compile(r#"clip:"cafe">=0.25 AND dino:42>=0.60"#).unwrap();
        let dual_url = build_advanced_nav_url(
            r#"clip:"cafe">=0.25 AND dino:42>=0.60"#,
            &dual_plan,
            AdvancedSort::Newest,
            None,
            50,
        );
        assert!(!dual_url.contains("cw="));
        assert!(!dual_url.contains("min_sim="));

        let (_, upload_plan) = parse_and_compile("upload:0>=0.40").unwrap();
        assert_eq!(
            build_advanced_nav_url(
                "upload:0>=0.40",
                &upload_plan,
                AdvancedSort::Relevance,
                Some("123-1"),
                50
            ),
            "/?mode=advanced&adv=upload%3A0%3E%3D0.40&img=123-1"
        );
    }

    #[test]
    fn prepopulates_unified_draft_from_default_and_legacy_urls() {
        let (draft1, _, _) = build_initial_draft(
            Some(UrlSearchState {
                mode: Mode::Author,
                q: "渡久山".into(),
                ..Default::default()
            }),
            None,
            None,
        );
        assert_eq!(draft1.query, "author:渡久山");

        let (draft2, _, _) = build_initial_draft(
            Some(UrlSearchState {
                mode: Mode::Clip,
                q: "sunny garden".into(),
                min_similarity: Some(0.28),
                ..Default::default()
            }),
            None,
            None,
        );
        assert_eq!(draft2.query, r#"clip:"sunny garden">=0.28"#);
    }
}
