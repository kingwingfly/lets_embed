use std::sync::atomic::{AtomicU64, Ordering};

use leptos::prelude::*;

use crate::components::SkySelect;
use crate::models::{
    PresetTemplate, RuleBlock, RuleBlockKind, RuleClause, RuleConnector, RuleDraft, RuleField,
    RuleGroupCombinator, SelectOption, SelectVariant,
};
use crate::rule_syntax::{format_rule_blocks, format_score, parse_safety_rule_to_blocks};

static NEXT_RULE_NODE_ID: AtomicU64 = AtomicU64::new(100);

fn alloc_node_id() -> u64 {
    NEXT_RULE_NODE_ID.fetch_add(1, Ordering::Relaxed)
}

fn parse_optional_score(raw: &str) -> Option<f32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .parse::<f32>()
        .ok()
        .filter(|v| v.is_finite() && *v > 0.0)
        .map(|v| v.min(1.0))
}

/// Visual boolean rule builder for metadata-only content safety rules.
///
/// Features:
/// - WD-Tagger preset template buttons (`R-18 / Explicit`, `Suggestive / Ecchi`,
///   `Blood / Violence`, `Custom`)
/// - Standalone clauses and parenthesized `( ... )` OR/AND groups designed for
///   narrow viewports (non-wrapping `( ... )` group badge + inline `×` remove button)
/// - Per-tag minimum confidence score input (`>=0.45`) for `tag:` predicates
/// - Live formatted query string preview + raw query parser with syntax validation
#[component]
pub fn QueryRuleBuilder(
    draft: RwSignal<RuleDraft>,
    #[prop(optional)] presets: Option<Vec<PresetTemplate>>,
    #[prop(optional)] validation_error: Option<Signal<Option<String>>>,
    #[prop(optional)] on_change: Option<Callback<RuleDraft>>,
    #[prop(default = true)] show_raw_editor: bool,
) -> impl IntoView {
    let preset_list = presets.unwrap_or_else(PresetTemplate::builtins);
    let raw_parse_error: RwSignal<Option<String>> = RwSignal::new(None);
    let field_options = Signal::derive(RuleField::select_options);
    let raw_input_id = format!("le-rule-raw-input-{}", alloc_node_id());

    let emit_change = move || {
        if let Some(cb) = on_change {
            cb.run(draft.get_untracked());
        }
    };

    let sync_query_from_blocks = move || {
        raw_parse_error.set(None);
        draft.update(|d| {
            d.query = format_rule_blocks(&d.blocks);
        });
        emit_change();
    };

    let apply_preset = move |tpl: PresetTemplate| {
        let mut alloc = alloc_node_id;
        let blocks = if tpl.query.trim().is_empty() {
            vec![RuleBlock {
                id: alloc(),
                connector: RuleConnector::And,
                kind: RuleBlockKind::Clause(RuleClause {
                    id: alloc(),
                    negated: false,
                    field: RuleField::Tag,
                    value: String::new(),
                    min_score: Some(0.45),
                }),
            }]
        } else {
            parse_safety_rule_to_blocks(&tpl.query, &mut alloc).unwrap_or_default()
        };
        raw_parse_error.set(None);
        draft.update(|d| {
            if d.name.trim().is_empty() || tpl.id != "custom" {
                d.name = tpl.label.clone();
            }
            d.mode = tpl.default_mode;
            d.preset = tpl.preset;
            d.requires_age = tpl.requires_age;
            d.blocks = blocks;
            d.query = format_rule_blocks(&d.blocks);
        });
        emit_change();
    };

    let add_clause = move |_| {
        let block_id = alloc_node_id();
        let clause_id = alloc_node_id();
        draft.update(|d| {
            d.blocks.push(RuleBlock {
                id: block_id,
                connector: RuleConnector::And,
                kind: RuleBlockKind::Clause(RuleClause {
                    id: clause_id,
                    negated: false,
                    field: RuleField::Tag,
                    value: String::new(),
                    min_score: Some(0.45),
                }),
            });
        });
        sync_query_from_blocks();
    };

    let add_or_group = move |_| {
        let block_id = alloc_node_id();
        let c1 = alloc_node_id();
        let c2 = alloc_node_id();
        draft.update(|d| {
            d.blocks.push(RuleBlock {
                id: block_id,
                connector: RuleConnector::And,
                kind: RuleBlockKind::Group {
                    combinator: RuleGroupCombinator::Or,
                    clauses: vec![
                        RuleClause {
                            id: c1,
                            negated: false,
                            field: RuleField::Tag,
                            value: String::new(),
                            min_score: Some(0.45),
                        },
                        RuleClause {
                            id: c2,
                            negated: false,
                            field: RuleField::Tag,
                            value: String::new(),
                            min_score: Some(0.45),
                        },
                    ],
                },
            });
        });
        sync_query_from_blocks();
    };

    let block_ids = Memo::new(move |_| {
        draft.with(|d| d.blocks.iter().map(|b| b.id).collect::<Vec<_>>())
    });

    let combined_error = move || {
        raw_parse_error
            .get()
            .or_else(|| validation_error.and_then(|e| e.get()))
    };

    view! {
        <div class="le-rule-builder">
            // Preset template quick-fill buttons
            <div class="le-rule-presets" role="group" aria-label="WD-Tagger safety rule presets">
                <span class="le-rule-presets-label">"Presets:"</span>
                <div class="le-rule-presets-list">
                    {preset_list.into_iter().map(|tpl| {
                        let tpl_click = tpl.clone();
                        let preset_id = tpl.id.clone();
                        let preset_kind = tpl.preset;
                        let title_attr = tpl.description.clone();
                        view! {
                            <button
                                type="button"
                                class=move || {
                                    let active = if draft.with(|d| d.preset == preset_kind) {
                                        " is-active"
                                    } else {
                                        ""
                                    };
                                    format!("le-preset-btn le-preset-btn--{preset_id}{active}")
                                }
                                title=title_attr
                                on:click=move |_| apply_preset(tpl_click.clone())
                            >
                                {tpl.label}
                            </button>
                        }
                    }).collect_view()}
                </div>
            </div>

            // Visual blocks list
            <div class="le-rule-blocks">
                <For
                    each=move || block_ids.get()
                    key=|id| *id
                    let(block_id)
                >
                    {
                        let idx_sig = Memo::new(move |_| {
                            block_ids
                                .with(|ids| ids.iter().position(|x| *x == block_id))
                                .unwrap_or(0)
                        });
                        let conn_sig = Memo::new(move |_| {
                            draft.with(|d| {
                                d.blocks
                                    .iter()
                                    .find(|b| b.id == block_id)
                                    .map(|b| b.connector)
                                    .unwrap_or(RuleConnector::And)
                            })
                        });
                        let is_group = draft.with_untracked(|d| {
                            d.blocks
                                .iter()
                                .find(|b| b.id == block_id)
                                .is_some_and(|b| matches!(b.kind, RuleBlockKind::Group { .. }))
                        });

                        let remove_block = move |_| {
                            draft.update(|d| {
                                d.blocks.retain(|b| b.id != block_id);
                                if let Some(first) = d.blocks.first_mut()
                                    && first.connector == RuleConnector::Or
                                {
                                    first.connector = RuleConnector::And;
                                }
                            });
                            sync_query_from_blocks();
                        };

                        let connector_options = Signal::derive(move || {
                            let mut opts = vec![SelectOption::new(
                                "and",
                                if idx_sig.get() == 0 { "Match" } else { "AND" },
                            )];
                            if idx_sig.get() > 0 {
                                opts.push(SelectOption::new("or", "OR"));
                            }
                            opts.push(SelectOption::new("not", "NOT"));
                            opts
                        });

                        let on_connector_change = Callback::new(move |val: String| {
                            let mut next = RuleConnector::parse(&val);
                            if next == RuleConnector::Or && idx_sig.get_untracked() == 0 {
                                next = RuleConnector::And;
                            }
                            draft.update(|d| {
                                if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id) {
                                    b.connector = next;
                                }
                            });
                            sync_query_from_blocks();
                        });

                        if !is_group {
                            let field_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.blocks
                                        .iter()
                                        .find(|b| b.id == block_id)
                                        .and_then(|b| match &b.kind {
                                            RuleBlockKind::Clause(c) => Some(c.field),
                                            _ => None,
                                        })
                                        .unwrap_or(RuleField::Tag)
                                })
                            });
                            let val_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.blocks
                                        .iter()
                                        .find(|b| b.id == block_id)
                                        .and_then(|b| match &b.kind {
                                            RuleBlockKind::Clause(c) => Some(c.value.clone()),
                                            _ => None,
                                        })
                                        .unwrap_or_default()
                                })
                            });
                            let score_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.blocks
                                        .iter()
                                        .find(|b| b.id == block_id)
                                        .and_then(|b| match &b.kind {
                                            RuleBlockKind::Clause(c) => c.min_score,
                                            _ => None,
                                        })
                                })
                            });

                            view! {
                                <div class="le-rule-row">
                                    <div class="le-rule-row-main">
                                        <SkySelect
                                            aria_label="Boolean connector"
                                            variant=SelectVariant::SkyBox
                                            trigger_class="le-rule-conn-select"
                                            value=Signal::derive(move || conn_sig.get().as_str().to_string())
                                            options=connector_options
                                            on_change=on_connector_change
                                        />

                                        <SkySelect
                                            aria_label="Predicate field"
                                            variant=SelectVariant::SkyBox
                                            trigger_class="le-rule-field-select"
                                            value=Signal::derive(move || field_sig.get().as_str().to_string())
                                            options=field_options
                                            on_change=Callback::new(move |val: String| {
                                                if let Some(f) = RuleField::parse(&val) {
                                                    draft.update(|d| {
                                                        if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                                            && let RuleBlockKind::Clause(c) = &mut b.kind
                                                        {
                                                            c.field = f;
                                                            if f != RuleField::Tag {
                                                                c.min_score = None;
                                                            }
                                                            if f == RuleField::Unclassified {
                                                                c.value.clear();
                                                            }
                                                        }
                                                    });
                                                    sync_query_from_blocks();
                                                }
                                            })
                                        />

                                        {move || {
                                            let f = field_sig.get();
                                            if f == RuleField::Unclassified {
                                                view! {
                                                    <span class="le-rule-unclassified-badge">
                                                        "Matches pending / unclassified media"
                                                    </span>
                                                }
                                                .into_any()
                                            } else {
                                                view! {
                                                    <input
                                                        type="text"
                                                        class="le-rule-input"
                                                        aria-label="Predicate value"
                                                        placeholder=f.placeholder()
                                                        value=move || val_sig.get()
                                                        prop:value=move || val_sig.get()
                                                        on:input=move |ev| {
                                                            let next = event_target_value(&ev);
                                                            draft.update(|d| {
                                                                if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                                                    && let RuleBlockKind::Clause(c) = &mut b.kind
                                                                {
                                                                    c.value = next;
                                                                }
                                                            });
                                                            sync_query_from_blocks();
                                                        }
                                                    />
                                                }
                                                .into_any()
                                            }
                                        }}

                                        {move || (field_sig.get() == RuleField::Tag).then(|| view! {
                                            <label class="le-score-box" title="Minimum WD-Tagger confidence score (0.01–1.00)">
                                                <span class="le-score-prefix">">="</span>
                                                <input
                                                    type="number"
                                                    class="le-score-input"
                                                    aria-label="Minimum tag confidence score"
                                                    min="0.01"
                                                    max="1.00"
                                                    step="0.01"
                                                    placeholder="0.45"
                                                    value=move || score_sig.get().map(format_score).unwrap_or_default()
                                                    prop:value=move || score_sig.get().map(format_score).unwrap_or_default()
                                                    on:input=move |ev| {
                                                        let parsed = parse_optional_score(&event_target_value(&ev));
                                                        draft.update(|d| {
                                                            if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                                                && let RuleBlockKind::Clause(c) = &mut b.kind
                                                            {
                                                                c.min_score = parsed;
                                                            }
                                                        });
                                                        sync_query_from_blocks();
                                                    }
                                                />
                                            </label>
                                        })}
                                    </div>

                                    <button
                                        type="button"
                                        class="le-rule-remove-btn"
                                        title="Remove clause"
                                        aria-label="Remove clause"
                                        on:click=remove_block
                                    >
                                        "\u{00D7}"
                                    </button>
                                </div>
                            }
                            .into_any()
                        } else {
                            let comb_sig = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.blocks
                                        .iter()
                                        .find(|b| b.id == block_id)
                                        .and_then(|b| match &b.kind {
                                            RuleBlockKind::Group { combinator, .. } => {
                                                Some(*combinator)
                                            }
                                            _ => None,
                                        })
                                        .unwrap_or(RuleGroupCombinator::Or)
                                })
                            });
                            let inner_ids = Memo::new(move |_| {
                                draft.with(|d| {
                                    d.blocks
                                        .iter()
                                        .find(|b| b.id == block_id)
                                        .map(|b| match &b.kind {
                                            RuleBlockKind::Group { clauses, .. } => {
                                                clauses.iter().map(|c| c.id).collect::<Vec<_>>()
                                            }
                                            _ => Vec::new(),
                                        })
                                        .unwrap_or_default()
                                })
                            });

                            let set_combinator = move |next: RuleGroupCombinator| {
                                draft.update(|d| {
                                    if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                        && let RuleBlockKind::Group { combinator, .. } = &mut b.kind
                                    {
                                        *combinator = next;
                                    }
                                });
                                sync_query_from_blocks();
                            };

                            let add_inner_clause = move |_| {
                                let cid = alloc_node_id();
                                draft.update(|d| {
                                    if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                        && let RuleBlockKind::Group { clauses, .. } = &mut b.kind
                                    {
                                        clauses.push(RuleClause {
                                            id: cid,
                                            negated: false,
                                            field: RuleField::Tag,
                                            value: String::new(),
                                            min_score: Some(0.45),
                                        });
                                    }
                                });
                                sync_query_from_blocks();
                            };

                            view! {
                                <div class="le-rule-group">
                                    // Narrow-viewport clean header: non-wrapping `( ... )` label + inline `×` remove button
                                    <div class="le-rule-group-header">
                                        <div class="le-rule-group-header-left">
                                            <SkySelect
                                                aria_label="Group boolean connector"
                                                variant=SelectVariant::IndigoBox
                                                trigger_class="le-rule-conn-select"
                                                value=Signal::derive(move || conn_sig.get().as_str().to_string())
                                                options=connector_options
                                                on_change=on_connector_change
                                            />
                                            <span class="le-rule-group-paren" aria-hidden="true">"( ... )"</span>
                                            <div class="le-rule-comb-toggle" role="group" aria-label="Group combinator">
                                                <button
                                                    type="button"
                                                    class=move || if comb_sig.get() == RuleGroupCombinator::Or {
                                                        "le-rule-comb-btn is-active"
                                                    } else {
                                                        "le-rule-comb-btn"
                                                    }
                                                    aria-pressed=move || (comb_sig.get() == RuleGroupCombinator::Or).to_string()
                                                    on:click=move |_| set_combinator(RuleGroupCombinator::Or)
                                                >
                                                    "ANY (OR)"
                                                </button>
                                                <button
                                                    type="button"
                                                    class=move || if comb_sig.get() == RuleGroupCombinator::And {
                                                        "le-rule-comb-btn is-active"
                                                    } else {
                                                        "le-rule-comb-btn"
                                                    }
                                                    aria-pressed=move || (comb_sig.get() == RuleGroupCombinator::And).to_string()
                                                    on:click=move |_| set_combinator(RuleGroupCombinator::And)
                                                >
                                                    "ALL (AND)"
                                                </button>
                                            </div>
                                        </div>

                                        <div class="le-rule-group-header-actions">
                                            <button
                                                type="button"
                                                class="le-rule-mini-btn"
                                                on:click=add_inner_clause
                                            >
                                                "+ Row"
                                            </button>
                                            <button
                                                type="button"
                                                class="le-rule-remove-btn"
                                                title="Remove group"
                                                aria-label="Remove group"
                                                on:click=remove_block
                                            >
                                                "\u{00D7}"
                                            </button>
                                        </div>
                                    </div>

                                    <div class="le-rule-group-body">
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
                                                        d.blocks
                                                            .iter()
                                                            .find(|b| b.id == block_id)
                                                            .and_then(|b| match &b.kind {
                                                                RuleBlockKind::Group { clauses, .. } => {
                                                                    clauses.iter().find(|c| c.id == cid).map(|c| c.negated)
                                                                }
                                                                _ => None,
                                                            })
                                                            .unwrap_or(false)
                                                    })
                                                });
                                                let c_field = Memo::new(move |_| {
                                                    draft.with(|d| {
                                                        d.blocks
                                                            .iter()
                                                            .find(|b| b.id == block_id)
                                                            .and_then(|b| match &b.kind {
                                                                RuleBlockKind::Group { clauses, .. } => {
                                                                    clauses.iter().find(|c| c.id == cid).map(|c| c.field)
                                                                }
                                                                _ => None,
                                                            })
                                                            .unwrap_or(RuleField::Tag)
                                                    })
                                                });
                                                let c_val = Memo::new(move |_| {
                                                    draft.with(|d| {
                                                        d.blocks
                                                            .iter()
                                                            .find(|b| b.id == block_id)
                                                            .and_then(|b| match &b.kind {
                                                                RuleBlockKind::Group { clauses, .. } => {
                                                                    clauses.iter().find(|c| c.id == cid).map(|c| c.value.clone())
                                                                }
                                                                _ => None,
                                                            })
                                                            .unwrap_or_default()
                                                    })
                                                });
                                                let c_score = Memo::new(move |_| {
                                                    draft.with(|d| {
                                                        d.blocks
                                                            .iter()
                                                            .find(|b| b.id == block_id)
                                                            .and_then(|b| match &b.kind {
                                                                RuleBlockKind::Group { clauses, .. } => {
                                                                    clauses.iter().find(|c| c.id == cid).and_then(|c| c.min_score)
                                                                }
                                                                _ => None,
                                                            })
                                                    })
                                                });

                                                let remove_inner = move |_| {
                                                    draft.update(|d| {
                                                        let mut drop_group = false;
                                                        if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                                            && let RuleBlockKind::Group { clauses, .. } = &mut b.kind
                                                        {
                                                            clauses.retain(|c| c.id != cid);
                                                            drop_group = clauses.is_empty();
                                                        }
                                                        if drop_group {
                                                            d.blocks.retain(|b| b.id != block_id);
                                                        }
                                                    });
                                                    sync_query_from_blocks();
                                                };

                                                view! {
                                                    <div class="le-rule-inner-row">
                                                        <div class="le-rule-row-main">
                                                            <span class="le-rule-inner-comb">
                                                                {move || if c_idx.get() == 0 {
                                                                    ""
                                                                } else {
                                                                    comb_sig.get().as_str()
                                                                }}
                                                            </span>

                                                            <button
                                                                type="button"
                                                                class=move || if c_neg.get() {
                                                                    "le-not-chip is-active"
                                                                } else {
                                                                    "le-not-chip"
                                                                }
                                                                aria-pressed=move || c_neg.get().to_string()
                                                                title="Negate this clause (NOT)"
                                                                on:click=move |_| {
                                                                    draft.update(|d| {
                                                                        if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                                                            && let RuleBlockKind::Group { clauses, .. } = &mut b.kind
                                                                            && let Some(c) = clauses.iter_mut().find(|c| c.id == cid)
                                                                        {
                                                                            c.negated = !c.negated;
                                                                        }
                                                                    });
                                                                    sync_query_from_blocks();
                                                                }
                                                            >
                                                                "NOT"
                                                            </button>

                                                            <SkySelect
                                                                aria_label="Inner predicate field"
                                                                variant=SelectVariant::IndigoBox
                                                                trigger_class="le-rule-field-select"
                                                                value=Signal::derive(move || c_field.get().as_str().to_string())
                                                                options=field_options
                                                                on_change=Callback::new(move |val: String| {
                                                                    if let Some(f) = RuleField::parse(&val) {
                                                                        draft.update(|d| {
                                                                            if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                                                                && let RuleBlockKind::Group { clauses, .. } = &mut b.kind
                                                                                && let Some(c) = clauses.iter_mut().find(|c| c.id == cid)
                                                                            {
                                                                                c.field = f;
                                                                                if f != RuleField::Tag {
                                                                                    c.min_score = None;
                                                                                }
                                                                                if f == RuleField::Unclassified {
                                                                                    c.value.clear();
                                                                                }
                                                                            }
                                                                        });
                                                                        sync_query_from_blocks();
                                                                    }
                                                                })
                                                            />

                                                            {move || {
                                                                let f = c_field.get();
                                                                if f == RuleField::Unclassified {
                                                                    view! {
                                                                        <span class="le-rule-unclassified-badge">
                                                                            "unclassified"
                                                                        </span>
                                                                    }
                                                                    .into_any()
                                                                } else {
                                                                    view! {
                                                                        <input
                                                                            type="text"
                                                                            class="le-rule-input"
                                                                            aria-label="Inner predicate value"
                                                                            placeholder=f.placeholder()
                                                                            value=move || c_val.get()
                                                                            prop:value=move || c_val.get()
                                                                            on:input=move |ev| {
                                                                                let next = event_target_value(&ev);
                                                                                draft.update(|d| {
                                                                                    if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                                                                        && let RuleBlockKind::Group { clauses, .. } = &mut b.kind
                                                                                        && let Some(c) = clauses.iter_mut().find(|c| c.id == cid)
                                                                                    {
                                                                                        c.value = next;
                                                                                    }
                                                                                });
                                                                                sync_query_from_blocks();
                                                                            }
                                                                        />
                                                                    }
                                                                    .into_any()
                                                                }
                                                            }}

                                                            {move || (c_field.get() == RuleField::Tag).then(|| view! {
                                                                <label class="le-score-box" title="Minimum WD-Tagger confidence score (0.01–1.00)">
                                                                    <span class="le-score-prefix">">="</span>
                                                                    <input
                                                                        type="number"
                                                                        class="le-score-input"
                                                                        aria-label="Minimum tag confidence score"
                                                                        min="0.01"
                                                                        max="1.00"
                                                                        step="0.01"
                                                                        placeholder="0.45"
                                                                        value=move || c_score.get().map(format_score).unwrap_or_default()
                                                                        prop:value=move || c_score.get().map(format_score).unwrap_or_default()
                                                                        on:input=move |ev| {
                                                                            let parsed = parse_optional_score(&event_target_value(&ev));
                                                                            draft.update(|d| {
                                                                                if let Some(b) = d.blocks.iter_mut().find(|b| b.id == block_id)
                                                                                    && let RuleBlockKind::Group { clauses, .. } = &mut b.kind
                                                                                    && let Some(c) = clauses.iter_mut().find(|c| c.id == cid)
                                                                                {
                                                                                    c.min_score = parsed;
                                                                                }
                                                                            });
                                                                            sync_query_from_blocks();
                                                                        }
                                                                    />
                                                                </label>
                                                            })}
                                                        </div>

                                                        <button
                                                            type="button"
                                                            class="le-rule-remove-btn"
                                                            title="Remove inner clause"
                                                            aria-label="Remove inner clause"
                                                            on:click=remove_inner
                                                        >
                                                            "\u{00D7}"
                                                        </button>
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

            // Action bar
            <div class="le-rule-toolbar">
                <button type="button" class="le-btn le-btn--secondary le-btn--sm" on:click=add_clause>
                    "+ Clause"
                </button>
                <button type="button" class="le-btn le-btn--indigo le-btn--sm" on:click=add_or_group>
                    "+ ( OR / AND ) Group"
                </button>
            </div>

            // Live query expression editor / preview
            {show_raw_editor.then(|| {
                let raw_for_id = raw_input_id.clone();
                let raw_el_id = raw_input_id.clone();
                view! {
                <div class="le-rule-raw">
                    <label class="le-field-label" for=raw_for_id>
                        "Safety Rule Expression (metadata-only: tag:, post_tag:, author:, unclassified)"
                    </label>
                    <input
                        id=raw_el_id
                        type="text"
                        class="le-rule-raw-input"
                        placeholder="e.g. (tag:explicit>=0.45 OR tag:nude) AND NOT post_tag:safe"
                        value=move || draft.with(|d| d.query.clone())
                        prop:value=move || draft.with(|d| d.query.clone())
                        on:input=move |ev| {
                            let next_raw = event_target_value(&ev);
                            let mut alloc = alloc_node_id;
                            match parse_safety_rule_to_blocks(&next_raw, &mut alloc) {
                                Ok(parsed_blocks) => {
                                    raw_parse_error.set(None);
                                    draft.update(|d| {
                                        d.query = next_raw;
                                        d.blocks = parsed_blocks;
                                    });
                                    emit_change();
                                }
                                Err(err) => {
                                    raw_parse_error.set(Some(err));
                                    draft.update(|d| {
                                        d.query = next_raw;
                                    });
                                }
                            }
                        }
                    />
                </div>
            }})}

            {move || combined_error().map(|err| view! {
                <div class="le-rule-error" role="alert">{err}</div>
            })}
        </div>
    }
}
