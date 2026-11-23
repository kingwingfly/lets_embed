use crate::components::{
    MenuPlacement, QueryBuilderDraft, QueryBuilderMode, QueryBuilderNode, QueryCombinator,
    QueryConditionOp, QueryFieldKind, clamp_chars, compute_menu_placement_from_metrics,
    format_query_list_condition, format_query_nodes, format_score_for_step, format_threshold,
    merge_chip_values, next_enabled_index, parse_committed_score, parse_live_score,
    parse_query_to_nodes, parse_threshold_hundredths, quantize_score, quantize_threshold,
};
use crate::layout::{format_duration, layout_masonry};
use crate::models::{
    Density, GalleryBlurMode, GalleryMask, GalleryMaskPreset, GalleryMedia, GalleryMediaKind,
    MAX_REPORT_NOTE_CHARS, NoticeContent, PresetTemplate, RuleConnector, SelectOption,
    SelectVariant, ViewerItem,
};
use crate::rule_syntax::{
    MAX_RULE_LEN, MAX_TERMS_PER_RULE, format_rule_blocks, format_score,
    parse_safety_rule_to_blocks,
};

#[test]
fn density_mobile_column_counts_are_distinct_3_2_1() {
    for mobile_w in [0.0, 320.0, 375.0, 414.0, 540.0] {
        assert_eq!(Density::Compact.column_count(mobile_w), 3, "width={mobile_w}");
        assert_eq!(Density::Medium.column_count(mobile_w), 2, "width={mobile_w}");
        assert_eq!(Density::Large.column_count(mobile_w), 1, "width={mobile_w}");
    }
    assert!(Density::Compact.column_count(1200.0) > Density::Medium.column_count(1200.0));
    assert!(Density::Medium.column_count(1200.0) > Density::Large.column_count(1200.0));
}

#[test]
fn masonry_layout_balances_heights_and_preserves_indices() {
    let items = vec![(500, 1500), (1000, 500), (1000, 500), (800, 800)];
    let cols = layout_masonry(&items, 2, |&(w, h)| f64::from(h) / f64::from(w));
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0].iter().map(|p| p.index).collect::<Vec<_>>(), vec![0]);
    assert_eq!(
        cols[1].iter().map(|p| p.index).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[test]
fn format_duration_handles_edge_cases() {
    assert_eq!(format_duration(-10), "0:00");
    assert_eq!(format_duration(0), "0:00");
    assert_eq!(format_duration(65), "1:05");
    assert_eq!(format_duration(3661), "1:01:01");
}

#[test]
fn clamp_chars_counts_unicode_scalars_to_500() {
    let long = "あ".repeat(600);
    let clamped = clamp_chars(&long, MAX_REPORT_NOTE_CHARS);
    assert_eq!(clamped.chars().count(), 500);
}

#[test]
fn sky_select_navigation_and_placement_logic() {
    let opts = vec![
        SelectOption::new("a", "A"),
        SelectOption::new("b", "B").disabled(true),
        SelectOption::new("c", "C"),
    ];
    assert_eq!(next_enabled_index(&opts, Some(0), 1), Some(2));
    assert_eq!(next_enabled_index(&opts, Some(2), 1), Some(0));
    assert_eq!(next_enabled_index(&opts, Some(0), -1), Some(2));

    let pl = compute_menu_placement_from_metrics(
        520.0,
        552.0,
        260.0,
        360.0,
        375.0,
        600.0,
        7,
        SelectVariant::SkyBox,
    );
    assert!(pl.open_above);
    assert!(pl.align_right);
    assert!(pl.top_px.is_none());
    assert_eq!(pl.bottom_px, Some(600.0 - 520.0 + 6.0));
    assert_eq!(pl.max_height_px, 320);
    // Clamped cleanly inside [12px, vw - est_width - 12px] on 375px phone
    assert!(pl.left_px >= 12.0);
    assert!(pl.left_px + pl.min_width_px <= 375.0 - 12.0 + 0.1);
    let style = pl.inline_style();
    assert!(style.contains("position:fixed;"));
    assert!(style.contains("z-index:10050;"));
    assert!(style.contains("bottom:86.0px;"));
    assert!(style.contains("max-height:320px;"));

    // Trigger near top opens below with exact `top` coordinate and horizontal clamping on 360px phone
    let pl_below = compute_menu_placement_from_metrics(
        100.0,
        134.0,
        200.0,
        355.0,
        360.0,
        640.0,
        7,
        SelectVariant::SkyBox,
    );
    assert!(!pl_below.open_above);
    assert_eq!(pl_below.top_px, Some(140.0));
    assert!(pl_below.bottom_px.is_none());
    assert!(pl_below.left_px >= 12.0);
    assert!(pl_below.left_px + pl_below.max_width_px <= 360.0 - 12.0 + 0.1);
    assert_eq!(pl_below.max_height_px, 320);
    assert!(pl_below.inline_style().contains("top:140.0px;"));

    // Verify MenuPlacement default also emits fixed z-index 10050
    let def_style = MenuPlacement::default().inline_style();
    assert!(def_style.contains("position:fixed;z-index:10050;"));
}

#[test]
fn rule_syntax_round_trips_presets_scores_and_rejects_vectors() {
    let mut id = 1u64;
    let mut alloc = || {
        id += 1;
        id
    };

    // Built-in presets parse cleanly
    for tpl in PresetTemplate::builtins() {
        let parsed = parse_safety_rule_to_blocks(&tpl.query, &mut alloc)
            .expect("built-in preset must parse");
        if !tpl.query.is_empty() {
            assert!(!parsed.is_empty());
        }
    }

    // Score threshold + OR group + explicit AND NOT clause round-trip
    let blocks = parse_safety_rule_to_blocks(
        "(tag:explicit>=0.45 OR tag:nude>=0.6) AND NOT post_tag:approved",
        &mut alloc,
    )
    .expect("valid rule parses");
    assert_eq!(blocks.len(), 2);
    let formatted = format_rule_blocks(&blocks);
    assert_eq!(
        formatted,
        "(tag:explicit>=0.45 OR tag:nude>=0.6) AND NOT post_tag:approved"
    );

    // Disallowed vector operators must fail validation
    assert!(parse_safety_rule_to_blocks("clip:sunset", &mut alloc).is_err());
    assert!(parse_safety_rule_to_blocks("dino:12345", &mut alloc).is_err());
    assert!(parse_safety_rule_to_blocks("upload:0", &mut alloc).is_err());
}

#[test]
fn rule_syntax_enforces_strict_grammar_scores_limits_and_or_not_semantics() {
    let mut id = 100u64;
    let mut alloc = || {
        id += 1;
        id
    };

    // Preserve small positive thresholds without rounding to "0"
    assert_eq!(format_score(0.001), "0.001");
    assert_eq!(format_score(0.45), "0.45");
    assert_eq!(format_score(1.0), "1");
    let small = parse_safety_rule_to_blocks("tag:explicit>=0.001", &mut alloc).unwrap();
    assert_eq!(format_rule_blocks(&small), "tag:explicit>=0.001");

    // Preserve OR NOT logic rather than collapsing to AND NOT
    let or_not = parse_safety_rule_to_blocks("tag:a OR NOT tag:b", &mut alloc).unwrap();
    assert_eq!(or_not.len(), 2);
    assert_eq!(or_not[1].connector, RuleConnector::Or);
    assert_eq!(format_rule_blocks(&or_not), "tag:a OR NOT tag:b");

    // Negated OR-group fails explicitly instead of corrupting OR -> AND
    assert!(parse_safety_rule_to_blocks("tag:a OR NOT (tag:b OR tag:c)", &mut alloc).is_err());

    // Kaomoji tags like `=_=` remain valid while numeric `=` thresholds are rejected
    let kaomoji = parse_safety_rule_to_blocks("tag:=_=", &mut alloc).unwrap();
    assert_eq!(kaomoji.len(), 1);

    // Score bounds: (0.0, 1.0]
    for bad in [
        "tag:blood>=0",
        "tag:blood>=0.0",
        "tag:blood>=-0.2",
        "tag:blood>=1.1",
        "tag:blood>=NaN",
        "tag:blood>=0.5>=0.6",
        // Regex literals
        "tag:/blood.*/",
        "tag:/blood/i",
        "post_tag:/nsfw/",
        // Unsupported / fuzzy comparators
        "tag:blood~=0.5",
        "tag:blood>0.5",
        "tag:blood<0.5",
        "tag:blood<=0.5",
        "tag:blood=0.5",
        // Thresholds disallowed on post_tag / author
        "post_tag:nsfw>=0.5",
        "author:alice>=0.5",
        "post_tag:\"nsfw\">=0.5",
        // unclassified takes no value
        "unclassified:garbage",
        "unclassified:",
        // Control / NUL bytes
        "tag:blood\0",
        "tag:\"blood\0\"",
        // Missing explicit AND/OR operators
        "tag:a tag:b",
        "(tag:a) tag:b",
        "(tag:a OR tag:b) NOT post_tag:safe",
        "(tag:a tag:b)",
        // Trailing / leading / consecutive operators
        "tag:a OR",
        "tag:a AND",
        "OR tag:a",
        "AND tag:a",
        "tag:a AND OR tag:b",
        "tag:a AND NOT",
        "(tag:a OR)",
    ] {
        assert!(
            parse_safety_rule_to_blocks(bad, &mut alloc).is_err(),
            "expected error for invalid safety rule: {bad:?}"
        );
    }

    // Length cap (> MAX_RULE_LEN)
    let too_long = format!("tag:{}", "a".repeat(MAX_RULE_LEN));
    assert!(parse_safety_rule_to_blocks(&too_long, &mut alloc).is_err());

    // Term count cap (> MAX_TERMS_PER_RULE)
    let too_many_terms = (0..=MAX_TERMS_PER_RULE)
        .map(|i| format!("tag:t{i}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    assert!(parse_safety_rule_to_blocks(&too_many_terms, &mut alloc).is_err());
}

#[test]
fn notice_content_pre_sanitized_html_cannot_be_deserialized_from_json() {
    let text: NoticeContent = serde_json::from_str(r#"{"Text":"Hello"}"#).expect("Text deserializes");
    assert_eq!(text, NoticeContent::Text("Hello".into()));

    let malicious = r#"{"PreSanitizedHtml":"<img src=x onerror=alert(1)>"}"#;
    assert!(
        serde_json::from_str::<NoticeContent>(malicious).is_err(),
        "PreSanitizedHtml must NEVER deserialize from untrusted JSON"
    );
}

#[test]
fn viewer_item_effective_download_url_gates_spoiler_and_locked_media() {
    let spoiler = ViewerItem {
        id: 55,
        kind: GalleryMediaKind::Image,
        title: "Spoiler".into(),
        media: GalleryMedia::Spoiler {
            id: 55,
            kind: GalleryMediaKind::Image,
            width: 800,
            height: 600,
            preview_url: "/media/preview/55?cap=blur".into(),
            reveal_url: "/media/image/55?cap=SECRET".into(),
            alt: String::new(),
            duration_secs: None,
            rule_id: "r1".into(),
            label: "Sensitive".into(),
            preset: GalleryMaskPreset::Sensitive,
            blur_mode: GalleryBlurMode::ServerTransform,
        },
        details_href: None,
        download_url: Some("/media/image/55?cap=SECRET".into()),
        download_filename: None,
        liked: None,
    };
    assert_eq!(spoiler.effective_download_url(false), None);
    assert_eq!(
        spoiler.effective_download_url(true),
        Some("/media/image/55?cap=SECRET")
    );
}

#[test]
fn ui_css_is_bundled_and_contains_mobile_density_breakpoints() {
    assert!(crate::UI_CSS.contains(".le-mask-card"));
    assert!(crate::UI_CSS.contains(".le-spoiler-img--css"));
    assert!(crate::UI_CSS.contains(".le-rule-group-paren"));
    assert!(crate::UI_CSS.contains(".le-toast-host"));
    assert!(crate::UI_CSS.contains("z-index: 9999;"));
    assert!(crate::UI_CSS.contains("z-index: 10050;"));
    assert!(crate::UI_CSS.contains(".le-qb-chips-box"));
    assert!(crate::UI_CSS.contains(".le-age-gate-dialog"));
    // Requested preset color palettes: R18 = yellow/amber, Sensitive = purple, Blood = red
    assert!(crate::UI_CSS.contains("#eab308"));
    assert!(crate::UI_CSS.contains("#fef9c3"));
    assert!(crate::UI_CSS.contains("#854d0e"));
    assert!(crate::UI_CSS.contains("#9333ea"));
    assert!(crate::UI_CSS.contains("#f3e8ff"));
    assert!(crate::UI_CSS.contains("#581c87"));
    assert!(crate::UI_CSS.contains("#dc2626"));
    assert!(crate::UI_CSS.contains("#fee2e2"));
    assert!(crate::UI_CSS.contains("#991b1b"));
    assert!(crate::UI_CSS.contains(".le-qb-card"));
    assert!(crate::UI_CSS.contains(".le-qb-group"));
    assert!(crate::UI_CSS.contains(".le-qb-subcard"));
    assert!(crate::UI_CSS.contains(".le-qb-group-paren"));
    assert!(crate::UI_CSS.contains(".le-toggle-row"));
    assert!(crate::UI_CSS.contains(".le-toggle-track"));
    assert!(crate::UI_CSS.contains(".le-header"));
    assert!(crate::UI_CSS.contains(".le-score-field"));
    assert!(crate::UI_CSS.contains("@container le-qb"));
    assert!(crate::UI_CSS.contains(r#".gallery-ssr-grid[data-density="compact"]"#));
    assert!(crate::UI_CSS.contains(r#".gallery-ssr-grid[data-density="medium"]"#));
    assert!(crate::UI_CSS.contains(r#".gallery-ssr-grid[data-density="large"]"#));
}

#[test]
fn query_builder_advanced_search_round_trips_per_condition_thresholds() {
    let mut id = 1u64;
    let mut alloc = || {
        id += 1;
        id
    };

    let raw = r#"tag:maid>=0.45 AND clip:"sunlit breeze">=0.25 AND dino:42>=0.70 AND upload:0>=0.65 AND (title:spring OR NOT author:alice)"#;
    let nodes = parse_query_to_nodes(QueryBuilderMode::AdvancedSearch, raw, &mut alloc)
        .expect("advanced search query parses");
    assert_eq!(nodes.len(), 5);

    match &nodes[0] {
        QueryBuilderNode::Condition { condition, .. } => {
            assert_eq!(condition.field, QueryFieldKind::Tag);
            assert_eq!(condition.value, "maid");
            assert_eq!(condition.threshold, Some(0.45));
        }
        other => panic!("expected condition, got {other:?}"),
    }
    match &nodes[1] {
        QueryBuilderNode::Condition { condition, .. } => {
            assert_eq!(condition.field, QueryFieldKind::ClipText);
            assert_eq!(condition.value, "sunlit breeze");
            assert_eq!(condition.threshold, Some(0.25));
        }
        other => panic!("expected clip condition, got {other:?}"),
    }
    match &nodes[2] {
        QueryBuilderNode::Condition { condition, .. } => {
            assert_eq!(condition.field, QueryFieldKind::SimilarId);
            assert_eq!(condition.value, "42");
            assert_eq!(condition.threshold, Some(0.7));
        }
        other => panic!("expected dino condition, got {other:?}"),
    }
    match &nodes[3] {
        QueryBuilderNode::Condition { condition, .. } => {
            assert_eq!(condition.field, QueryFieldKind::UploadImage);
            assert_eq!(condition.value, "0");
            assert_eq!(condition.threshold, Some(0.65));
        }
        other => panic!("expected upload condition, got {other:?}"),
    }
    match &nodes[4] {
        QueryBuilderNode::Group(g) => {
            assert_eq!(g.combinator, QueryCombinator::Or);
            assert_eq!(g.conditions.len(), 2);
            assert_eq!(g.conditions[0].field, QueryFieldKind::Title);
            assert!(!g.conditions[0].negated);
            assert_eq!(g.conditions[1].field, QueryFieldKind::Author);
            assert!(g.conditions[1].negated);
        }
        other => panic!("expected group, got {other:?}"),
    }

    assert_eq!(format_query_nodes(&nodes), raw);
}

#[test]
fn query_builder_supports_all_whitespace_combos_around_gte_and_rejects_invalid_targets() {
    let mut id = 200u64;
    let mut alloc = || {
        id += 1;
        id
    };

    // All 4 whitespace combinations around `>=` on unquoted & quoted threshold fields
    for (mode, expr, expected) in [
        (QueryBuilderMode::AdvancedSearch, "tag:maid>=0.45", "tag:maid>=0.45"),
        (QueryBuilderMode::AdvancedSearch, "tag:maid>= 0.45", "tag:maid>=0.45"),
        (QueryBuilderMode::AdvancedSearch, "tag:maid >=0.45", "tag:maid>=0.45"),
        (QueryBuilderMode::AdvancedSearch, "tag:maid >= 0.45", "tag:maid>=0.45"),
        (
            QueryBuilderMode::AdvancedSearch,
            r#"clip:"sunlit sky">=0.25"#,
            r#"clip:"sunlit sky">=0.25"#,
        ),
        (
            QueryBuilderMode::AdvancedSearch,
            r#"clip:"sunlit sky">= 0.25"#,
            r#"clip:"sunlit sky">=0.25"#,
        ),
        (
            QueryBuilderMode::AdvancedSearch,
            r#"clip:"sunlit sky" >=0.25"#,
            r#"clip:"sunlit sky">=0.25"#,
        ),
        (
            QueryBuilderMode::AdvancedSearch,
            r#"clip:"sunlit sky" >= 0.25"#,
            r#"clip:"sunlit sky">=0.25"#,
        ),
        (
            QueryBuilderMode::AdvancedSearch,
            r#"tag:"long hair" >=0.45 AND dino:42 >= 0.7 AND upload:0>= 0.65"#,
            r#"tag:"long hair">=0.45 AND dino:42>=0.70 AND upload:0>=0.65"#,
        ),
        (QueryBuilderMode::SafetyPolicy, "tag:explicit >= 0.5", "tag:explicit>=0.50"),
        (QueryBuilderMode::SafetyPolicy, "tag:explicit>= 0.45", "tag:explicit>=0.45"),
        (
            QueryBuilderMode::SafetyPolicy,
            r#"(tag:"long hair" >= 0.45 OR tag:nude >=0.60)"#,
            r#"(tag:"long hair">=0.45 OR tag:nude>=0.60)"#,
        ),
    ] {
        let nodes = parse_query_to_nodes(mode, expr, &mut alloc)
            .unwrap_or_else(|e| panic!("failed to parse {expr:?} in {mode:?}: {e}"));
        assert_eq!(format_query_nodes(&nodes), expected, "input={expr:?}");
    }

    // `>=` on non-threshold fields MUST be rejected even when preceded by whitespace
    for (mode, bad) in [
        (QueryBuilderMode::AdvancedSearch, "title:foo>=0.5"),
        (QueryBuilderMode::AdvancedSearch, "title:foo >= 0.5"),
        (QueryBuilderMode::AdvancedSearch, "title:foo >=0.5"),
        (QueryBuilderMode::AdvancedSearch, "author:alice >= 0.5"),
        (QueryBuilderMode::AdvancedSearch, "all:hello >= 0.5"),
        (QueryBuilderMode::AdvancedSearch, "(tag:a) >= 0.5"),
        (QueryBuilderMode::AdvancedSearch, "tag:maid >= 0.45 >= 0.60"),
        (QueryBuilderMode::AdvancedSearch, "tag:maid >="),
        (QueryBuilderMode::AdvancedSearch, ">= 0.5"),
        (QueryBuilderMode::SafetyPolicy, "post_tag:safe >= 0.5"),
        (QueryBuilderMode::SafetyPolicy, "author:alice >= 0.5"),
        (QueryBuilderMode::SafetyPolicy, "unclassified >= 0.5"),
    ] {
        assert!(
            parse_query_to_nodes(mode, bad, &mut alloc).is_err(),
            "expected error for {bad:?} in {mode:?}"
        );
    }
}

#[test]
fn query_builder_enforces_hundredths_precision_unary_minus_and_leading_slash() {
    let mut id = 300u64;
    let mut alloc = || {
        id += 1;
        id
    };

    // Strict hundredths parsing (`0.01..=1.00`)
    assert_eq!(parse_threshold_hundredths("0.01").unwrap(), 0.01);
    assert_eq!(parse_threshold_hundredths("0.45").unwrap(), 0.45);
    assert_eq!(parse_threshold_hundredths("0.5").unwrap(), 0.50);
    assert_eq!(parse_threshold_hundredths("0.50").unwrap(), 0.50);
    assert_eq!(parse_threshold_hundredths(".45").unwrap(), 0.45);
    assert_eq!(parse_threshold_hundredths("1").unwrap(), 1.00);
    assert_eq!(parse_threshold_hundredths("1.0").unwrap(), 1.00);
    assert_eq!(parse_threshold_hundredths("1.00").unwrap(), 1.00);

    for bad in [
        "", "0", "0.0", "0.00", "0.005", "0.456", "1.01", "2", "-0.5", "+0.5", "0.", ".", "NaN",
        "inf", "1e-1", "0.5abc",
    ] {
        assert!(
            parse_threshold_hundredths(bad).is_err(),
            "parse_threshold_hundredths must reject {bad:?}"
        );
    }

    assert_eq!(quantize_threshold(0.456), Some(0.46));
    assert_eq!(quantize_threshold(0.005), Some(0.01));
    assert_eq!(quantize_threshold(1.5), Some(1.0));
    assert_eq!(quantize_threshold(0.0), None);
    assert_eq!(format_threshold(0.456), "0.46");
    assert_eq!(format_threshold(0.5), "0.50");
    assert_eq!(format_threshold(0.001), "0.01");

    // Raw query rejects <0.01 and >2 decimals
    assert!(parse_query_to_nodes(QueryBuilderMode::AdvancedSearch, "tag:maid>=0.005", &mut alloc).is_err());
    assert!(parse_query_to_nodes(QueryBuilderMode::AdvancedSearch, "tag:maid>=0.456", &mut alloc).is_err());
    assert!(parse_query_to_nodes(QueryBuilderMode::SafetyPolicy, "tag:explicit>=0.005", &mut alloc).is_err());
    assert!(parse_query_to_nodes(QueryBuilderMode::SafetyPolicy, "tag:explicit>=0.456", &mut alloc).is_err());

    // Unary `-` parity with `search_types::{query,safety}`
    let neg_adv = parse_query_to_nodes(
        QueryBuilderMode::AdvancedSearch,
        "tag:maid -tag:monochrome -(title:sketch OR -author:bob)",
        &mut alloc,
    )
    .expect("unary minus parses in AdvancedSearch");
    assert_eq!(
        format_query_nodes(&neg_adv),
        "tag:maid AND NOT tag:monochrome AND NOT (title:sketch OR NOT author:bob)"
    );

    let neg_safety = parse_query_to_nodes(
        QueryBuilderMode::SafetyPolicy,
        "tag:explicit AND -post_tag:approved AND -(tag:safe OR -author:alice)",
        &mut alloc,
    )
    .expect("unary minus parses in SafetyPolicy");
    assert_eq!(
        format_query_nodes(&neg_safety),
        "tag:explicit AND NOT post_tag:approved AND NOT (tag:safe OR NOT author:alice)"
    );

    // Any unquoted leading `/` rejected in SafetyPolicy
    for slash_bad in ["tag:/blood", "post_tag:/nsfw", "author:/bob", "/foo"] {
        assert!(
            parse_query_to_nodes(QueryBuilderMode::SafetyPolicy, slash_bad, &mut alloc).is_err(),
            "SafetyPolicy must reject leading slash {slash_bad:?}"
        );
    }
}

#[test]
fn score_input_helpers_preserve_intermediate_typing_and_quantize_on_commit() {
    // Intermediate typing never forces snap-back while user is mid-edit
    assert_eq!(parse_live_score("", 0.01, 1.00, 0.01), None);
    assert_eq!(parse_live_score("0", 0.01, 1.00, 0.01), None);
    assert_eq!(parse_live_score("0.", 0.01, 1.00, 0.01), None);
    assert_eq!(parse_live_score(".", 0.01, 1.00, 0.01), None);
    assert_eq!(parse_live_score("-", 0.01, 1.00, 0.01), None);
    assert_eq!(parse_live_score(".4", 0.01, 1.00, 0.01), Some(0.40));
    assert_eq!(parse_live_score("0.45", 0.01, 1.00, 0.01), Some(0.45));
    assert_eq!(parse_live_score("0.456", 0.01, 1.00, 0.01), Some(0.46));

    // Committed blur clamps & quantizes cleanly to step
    assert_eq!(parse_committed_score("", 0.01, 1.00, 0.01), None);
    assert_eq!(parse_committed_score("0.001", 0.01, 1.00, 0.01), Some(0.01));
    assert_eq!(parse_committed_score("2.5", 0.01, 1.00, 0.01), Some(1.00));
    assert_eq!(parse_committed_score("0.456", 0.01, 1.00, 0.01), Some(0.46));
    assert_eq!(quantize_score(0.5, 0.01, 1.00, 0.01), 0.50);
    assert_eq!(format_score_for_step(0.5, 0.01, 1.00, 0.01), "0.50");
    assert_eq!(format_score_for_step(0.456, 0.01, 1.00, 0.01), "0.46");
}

#[test]
fn query_builder_safety_policy_mode_rejects_vectors_and_supports_or_not_groups() {
    let mut id = 50u64;
    let mut alloc = || {
        id += 1;
        id
    };

    // Allowed fields in SafetyPolicy mode must be strictly metadata-only
    let fields = QueryFieldKind::fields_for_mode(QueryBuilderMode::SafetyPolicy);
    assert_eq!(
        fields,
        &[
            QueryFieldKind::Tag,
            QueryFieldKind::PostTag,
            QueryFieldKind::Author,
            QueryFieldKind::Unclassified,
        ]
    );
    assert!(fields.iter().all(|f| !f.is_vector()));

    // Vector operators and non-safety fields are strictly rejected
    for bad in [
        "clip:sunset",
        "clip:\"sunset\">=0.25",
        "dino:42>=0.7",
        "upload:0>=0.65",
        "title:sketch",
        "all:hello",
        "post_tag:safe>=0.5",
        "author:alice>=0.5",
        "tag:blood>=0",
        "tag:/blood.*/",
    ] {
        assert!(
            parse_query_to_nodes(QueryBuilderMode::SafetyPolicy, bad, &mut alloc).is_err(),
            "SafetyPolicy must reject {bad:?}"
        );
    }

    // Round-trip OR NOT group and per-tag thresholds cleanly
    let valid = "tag:explicit>=0.50 OR NOT (tag:safe OR post_tag:verified)";
    let nodes = parse_query_to_nodes(QueryBuilderMode::SafetyPolicy, valid, &mut alloc)
        .expect("valid safety policy parses");
    assert_eq!(format_query_nodes(&nodes), valid);

    let draft = QueryBuilderDraft::from_query(
        QueryBuilderMode::SafetyPolicy,
        "(tag:explicit>=0.45 OR tag:nude>=0.6) AND NOT post_tag:approved",
    )
    .expect("draft parses");
    assert_eq!(
        draft.format_query(),
        "(tag:explicit>=0.45 OR tag:nude>=0.60) AND NOT post_tag:approved"
    );
}

#[cfg(feature = "ssr")]
mod ssr_render_tests {
    use super::*;
    use leptos::prelude::*;

    use crate::components::{
        AGE_GATE_LEGAL_COPY, AgeGateModal, ContentMaskCard, DensityPicker, FloatingHeader,
        Lightbox, LikeButton, MAX_VISIBLE_TOASTS, MasonryGallery, MinSimilaritySlider,
        NoticeBanner, OptionalScoreInput, QueryBuilder, QueryCondition, QueryConnector, QueryGroup,
        QueryListCondition, QueryRuleBuilder, QueryThresholdDefaults, ReportDialog, SafeModeToggle,
        ScoreInput, SkySelect, SpoilerOverlay, ToastHost, ToastKind, ToggleSwitch, Viewer,
        provide_toast_store, render_select_menu_view, use_toast_store,
    };
    use crate::models::{
        GalleryCard, GalleryCardKind, LightboxAlbum, LikeTargetKind, LikeVariant, NoticeTone,
        ReportReason, ReportTargetKind, RuleBlock, RuleBlockKind, RuleClause, RuleDraft, RuleField,
        RuleGroupCombinator,
    };

    fn sample_locked_mask(preset: GalleryMaskPreset) -> GalleryMask {
        GalleryMask {
            rule_id: format!("rule-{}", preset.as_str()),
            label: preset.label().to_string(),
            preset,
            reason: Some("Restricted by site safety policy.".to_string()),
            requires_login: true,
            requires_age: preset == GalleryMaskPreset::R18,
            requires_terms: true,
            cta_label: None,
        }
    }

    fn render_ssr<V: IntoView>(f: impl FnOnce() -> V) -> String {
        let owner = Owner::new();
        owner.with(|| f().into_view().to_html())
    }

    #[test]
    fn content_mask_card_ssr_emits_svg_and_zero_media_urls() {
        for preset in GalleryMaskPreset::ALL {
            let mask = sample_locked_mask(preset);
            let html = render_ssr(|| {
                view! {
                    <ContentMaskCard
                        mask=mask
                        dimensions=(800, 1200)
                        on_unlock_click=Callback::new(|_| {})
                    />
                }
            });
            assert!(html.contains("<svg"), "preset {:?} missing svg", preset);
            assert!(html.contains("aspect-ratio: 800 / 1200;"));
            assert!(html.contains("Restricted by site safety policy."));
            assert!(html.contains("Sign in to unlock"));
            assert!(!html.contains("<img"), "Locked card must NEVER render <img>");
            assert!(
                !html.contains("<video"),
                "Locked card must NEVER render <video>"
            );
            assert!(
                !html.contains("src="),
                "Locked card must NEVER emit any src attribute"
            );
            assert!(!html.contains("/media/"));
            assert!(!html.contains("/images/"));
        }
    }

    #[test]
    fn spoiler_overlay_ssr_server_transform_never_leaks_reveal_url() {
        let html = render_ssr(|| {
            view! {
                <SpoilerOverlay
                    id=42
                    kind=GalleryMediaKind::Image
                    width=1000
                    height=1500
                    preview_url="/media/preview/42?cap=blur_tok".to_string()
                    reveal_url="/media/image/42?cap=SECRET_CLEAR_TOKEN".to_string()
                    label="Suggestive / Ecchi".to_string()
                    preset=GalleryMaskPreset::Sensitive
                    blur_mode=GalleryBlurMode::ServerTransform
                />
            }
        });
        assert!(html.contains("/media/preview/42?cap=blur_tok"));
        assert!(
            !html.contains("SECRET_CLEAR_TOKEN"),
            "ServerTransform spoiler must NEVER emit reveal_url before click!"
        );
        assert!(html.contains("Click to reveal"));
        assert!(html.contains("le-spoiler-img--server"));
    }

    #[test]
    fn spoiler_overlay_ssr_css_courtesy_emits_blur_class() {
        let html = render_ssr(|| {
            view! {
                <SpoilerOverlay
                    id=43
                    width=800
                    height=600
                    preview_url="/images/soft.webp".to_string()
                    reveal_url="/images/soft.webp".to_string()
                    label="Suggestive".to_string()
                    blur_mode=GalleryBlurMode::CssCourtesy
                />
            }
        });
        assert!(html.contains("le-spoiler-img--css"));
        assert!(html.contains("Suggestive"));
        assert!(html.contains("Click to reveal"));
    }

    #[test]
    fn masonry_gallery_ssr_preserves_badges_and_emits_zero_urls_for_locked_cards() {
        let html = render_ssr(|| {
            let cards = Signal::derive(|| {
                vec![
                    GalleryCard {
                        key: "post:1".into(),
                        id: 1,
                        kind: GalleryCardKind::Post,
                        title: "Safe Cover Album".into(),
                        subtitle: None,
                        media: GalleryMedia::Clear {
                            id: 10,
                            kind: GalleryMediaKind::Image,
                            width: 1200,
                            height: 800,
                            url: "/media/image/10?cap=safe_ok".into(),
                            alt: "Safe cover".into(),
                            duration_secs: None,
                        },
                        image_count: 12,
                        video_count: 2,
                        details_href: Some("/details/10".into()),
                        liked: Some(true),
                    },
                    GalleryCard {
                        key: "post:2".into(),
                        id: 2,
                        kind: GalleryCardKind::Post,
                        title: "Restricted Album".into(),
                        subtitle: None,
                        media: GalleryMedia::Locked {
                            id: 20,
                            kind: GalleryMediaKind::Image,
                            width: 900,
                            height: 1200,
                            mask: sample_locked_mask(GalleryMaskPreset::R18),
                        },
                        image_count: 8,
                        video_count: 1,
                        details_href: Some("/details/SHOULD_NOT_APPEAR".into()),
                        liked: Some(false),
                    },
                ]
            });
            let density = Signal::derive(|| Density::Compact);
            view! {
                <MasonryGallery
                    cards=cards
                    density=density
                    on_unlock_click=Callback::new(|_| {})
                />
            }
        });

        assert!(html.contains(r#"data-density="compact""#));
        assert!(html.contains("12p 2v"));
        assert!(html.contains("8p 1v"), "Locked post must preserve album badge count");
        assert!(html.contains("/media/image/10?cap=safe_ok"));
        assert!(html.contains("le-mask-card--r18"));
        assert!(
            !html.contains("SHOULD_NOT_APPEAR"),
            "Locked card must never leak details_href or raw URLs"
        );
    }

    #[test]
    fn density_picker_ssr_renders_all_three_options() {
        let html = render_ssr(|| {
            let density = RwSignal::new(Density::Medium);
            view! { <DensityPicker density=density /> }
        });
        assert!(html.contains("Compact"));
        assert!(html.contains("Medium"));
        assert!(html.contains("Large"));
        assert!(html.contains(r#"data-density="medium""#));
        assert!(html.contains(r#"aria-pressed="true""#));
    }

    #[test]
    fn report_dialog_ssr_renders_allowlist_and_500_char_cap() {
        let html = render_ssr(|| {
            let open = Signal::derive(|| true);
            let kind = Signal::derive(|| ReportTargetKind::Image);
            let id = Signal::derive(|| 777i64);
            view! {
                <ReportDialog
                    open=open
                    target_kind=kind
                    target_id=id
                    on_submit=Callback::new(|_| {})
                    on_close=Callback::new(|_| {})
                />
            }
        });
        assert!(html.contains("Report Content"));
        assert!(html.contains("image #777"));
        assert!(html.contains(ReportReason::MisclassifiedSafety.label()));
        assert!(html.contains(r#"maxlength="500""#));
        assert!(html.contains("0 / 500"));
    }

    #[test]
    fn query_rule_builder_ssr_renders_presets_or_group_and_min_score() {
        let html = render_ssr(|| {
            let draft = RwSignal::new(RuleDraft {
                name: "Explicit Rule".into(),
                blocks: vec![RuleBlock {
                    id: 1,
                    connector: RuleConnector::And,
                    kind: RuleBlockKind::Group {
                        combinator: RuleGroupCombinator::Or,
                        clauses: vec![
                            RuleClause {
                                id: 2,
                                negated: false,
                                field: RuleField::Tag,
                                value: "explicit".into(),
                                min_score: Some(0.45),
                            },
                            RuleClause {
                                id: 3,
                                negated: false,
                                field: RuleField::Tag,
                                value: "nude".into(),
                                min_score: Some(0.5),
                            },
                        ],
                    },
                }],
                query: "(tag:explicit>=0.45 OR tag:nude>=0.5)".into(),
                ..Default::default()
            });
            view! { <QueryRuleBuilder draft=draft /> }
        });
        assert!(html.contains("R-18 / Explicit"));
        assert!(html.contains("Suggestive / Ecchi"));
        assert!(html.contains("Blood / Violence"));
        assert!(html.contains("Custom"));
        assert!(html.contains("le-rule-group-paren"));
        assert!(html.contains("( ... )"));
        assert!(html.contains("le-rule-remove-btn"));
        assert!(html.contains("0.45"));
        assert!(html.contains("le-score-input"));
        assert!(html.contains(r#"inputmode="decimal""#));
        assert!(html.contains(r#"data-min="0.01""#));
        assert!(html.contains(r#"data-max="1.00""#));
        assert!(html.contains(r#"data-step="0.01""#));
        assert!(!html.contains(r#"step="0.05""#));
        assert!(html.contains("AND NOT post_tag:safe"));

        // Multiple QueryRuleBuilder instances must not collide on hardcoded raw input IDs
        let two_html = render_ssr(|| {
            let d1 = RwSignal::new(RuleDraft::default());
            let d2 = RwSignal::new(RuleDraft::default());
            view! {
                <div>
                    <QueryRuleBuilder draft=d1 />
                    <QueryRuleBuilder draft=d2 />
                </div>
            }
        });
        assert!(!two_html.contains(r#"id="le-rule-raw-input""#));
        assert_eq!(two_html.matches("id=\"le-rule-raw-input-").count(), 2);
    }

    #[test]
    fn notice_banner_pre_sanitized_html_uses_div_wrapper_for_block_elements() {
        let html = render_ssr(|| {
            view! {
                <NoticeBanner
                    content=NoticeContent::PreSanitizedHtml("<p>Safe paragraph</p>".into())
                    tone=NoticeTone::Info
                />
            }
        });
        assert!(html.contains(r#"<div class="le-notice-html"><p>Safe paragraph</p></div>"#));
        assert!(!html.contains(r#"<span class="le-notice-html""#));
    }

    #[test]
    fn viewer_ssr_spoiler_does_not_leak_reveal_download_url() {
        let html = render_ssr(|| {
            let items = Signal::derive(|| {
                vec![ViewerItem {
                    id: 77,
                    kind: GalleryMediaKind::Image,
                    title: "Spoiler Slide".into(),
                    media: GalleryMedia::Spoiler {
                        id: 77,
                        kind: GalleryMediaKind::Image,
                        width: 1000,
                        height: 800,
                        preview_url: "/media/preview/77?cap=blur_ok".into(),
                        reveal_url: "/media/image/77?cap=SECRET_NEVER_LEAK".into(),
                        alt: String::new(),
                        duration_secs: None,
                        rule_id: "r1".into(),
                        label: "Sensitive".into(),
                        preset: GalleryMaskPreset::Sensitive,
                        blur_mode: GalleryBlurMode::ServerTransform,
                    },
                    details_href: None,
                    download_url: Some("/media/image/77?cap=SECRET_NEVER_LEAK".into()),
                    download_filename: None,
                    liked: None,
                }]
            });
            let idx = RwSignal::new(Some(0usize));
            view! { <Viewer items=items index=idx /> }
        });
        assert!(html.contains("/media/preview/77?cap=blur_ok"));
        assert!(
            !html.contains("SECRET_NEVER_LEAK"),
            "Viewer must never emit reveal_url in href/download before click"
        );
    }

    #[test]
    fn auxiliary_components_render_cleanly_in_ssr() {
        let html = render_ssr(|| {
            let safe_mode = RwSignal::new(false);
            let sim = RwSignal::new(0.65f32);
            let select_val = Signal::derive(|| "all".to_string());
            let select_opts = Signal::derive(|| vec![SelectOption::new("all", "Title & Author")]);
            let album = Signal::derive(|| {
                Some(LightboxAlbum {
                    post_id: 99,
                    title: "Album 99".into(),
                    authors: vec![],
                    images: vec![],
                    videos: vec![GalleryMedia::Locked {
                        id: 500,
                        kind: GalleryMediaKind::Video,
                        width: 1920,
                        height: 1080,
                        mask: sample_locked_mask(GalleryMaskPreset::Blood),
                    }],
                    total_images: 0,
                    total_videos: 1,
                    liked: Some(false),
                    loading: false,
                    error: None,
                })
            });
            let density = RwSignal::new(Density::Medium);
            let viewer_items = Signal::derive(|| {
                vec![ViewerItem {
                    id: 900,
                    kind: GalleryMediaKind::Image,
                    title: "Locked Slide".into(),
                    media: GalleryMedia::Locked {
                        id: 900,
                        kind: GalleryMediaKind::Image,
                        width: 800,
                        height: 600,
                        mask: sample_locked_mask(GalleryMaskPreset::Custom),
                    },
                    details_href: Some("/details/NO_LEAK_VIEWER".into()),
                    download_url: Some("/media/image/900?cap=NO_LEAK_DL".into()),
                    download_filename: None,
                    liked: None,
                }]
            });
            let viewer_idx = RwSignal::new(Some(0usize));

            view! {
                <div>
                    <FloatingHeader left=|| view! { <span>"Brand"</span> } />
                    <NoticeBanner
                        content=NoticeContent::Text("<script>alert(1)</script>".into())
                        tone=NoticeTone::Warning
                    />
                    <SafeModeToggle safe_mode=safe_mode />
                    <MinSimilaritySlider value=sim model_badge="DINOv3" />
                    <LikeButton
                        kind=LikeTargetKind::Image
                        target_id=1
                        liked=Signal::derive(|| true)
                        variant=LikeVariant::Inline
                    />
                    <SkySelect
                        aria_label="Field"
                        value=select_val
                        options=select_opts
                        on_change=Callback::new(|_| {})
                    />
                    <Lightbox album=album density=density on_close=Callback::new(|_| {}) />
                    <Viewer items=viewer_items index=viewer_idx />
                </div>
            }
        });

        assert!(html.contains("Brand"));
        // Plain-text NoticeBanner escapes HTML tags safely
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("Safe Mode"));
        assert!(html.contains("DINOv3"));
        assert!(html.contains("0.65"));
        assert!(html.contains("Album 99"));
        assert!(!html.contains("NO_LEAK_VIEWER"));
        assert!(!html.contains("NO_LEAK_DL"));
    }

    #[test]
    fn toast_host_ssr_renders_all_kinds_dismiss_button_and_caps_queue() {
        let html = render_ssr(|| {
            let store = provide_toast_store();
            let same = use_toast_store();
            let id_ok = same.success("Policy published", Some("rev #4 active".into()));
            let _id_err = same.error("Sync failed", Some("503 upstream".into()));
            let _id_warn = same.warning("CSS courtesy blur active", None);
            let _id_info = same.info("Signed in", Some("user@example.com".into()));
            let id_drop = store.push(ToastKind::Info, "Temporary", None);
            store.dismiss(id_drop);
            assert!(id_ok > 0);
            assert_eq!(store.items().len(), 4);
            view! { <ToastHost /> }
        });

        assert!(html.contains("le-toast-host"));
        assert!(html.contains("le-toast--success"));
        assert!(html.contains("le-toast--error"));
        assert!(html.contains("le-toast--warning"));
        assert!(html.contains("le-toast--info"));
        assert!(html.contains("Policy published"));
        assert!(html.contains("rev #4 active"));
        assert!(html.contains("Sync failed"));
        assert!(html.contains("503 upstream"));
        assert!(html.contains("CSS courtesy blur active"));
        assert!(html.contains("Signed in"));
        assert!(!html.contains("Temporary"));
        assert!(html.contains(r#"role="alert""#));
        assert!(html.contains(r#"aria-live="assertive""#));
        assert!(html.contains(r#"role="status""#));
        assert!(html.contains("le-toast-close"));
        // Outer toast host must NOT set aria-live="polite" (avoids nesting assertive alerts)
        assert!(!html.contains(r#"class="le-toast-host" role="region" aria-label="Notifications" aria-live="polite""#));

        // Verify queue cap keeps the latest MAX_VISIBLE_TOASTS entries
        let owner = Owner::new();
        owner.with(|| {
            let store = provide_toast_store();
            for i in 0..(MAX_VISIBLE_TOASTS + 3) {
                store.info(format!("Toast #{i}"), None);
            }
            let items = store.items();
            assert_eq!(items.len(), MAX_VISIBLE_TOASTS);
            assert_eq!(items.first().unwrap().title, "Toast #3");
        });
    }

    #[test]
    fn query_builder_ssr_advanced_search_renders_per_condition_thresholds_and_step_001() {
        let html = render_ssr(|| {
            let draft = RwSignal::new(QueryBuilderDraft {
                mode: QueryBuilderMode::AdvancedSearch,
                nodes: vec![
                    QueryBuilderNode::Condition {
                        connector: QueryConnector::And,
                        condition: QueryCondition {
                            id: 10,
                            field: QueryFieldKind::Tag,
                            value: "maid".into(),
                            negated: false,
                            threshold: Some(0.45),
                        },
                    },
                    QueryBuilderNode::Condition {
                        connector: QueryConnector::And,
                        condition: QueryCondition {
                            id: 11,
                            field: QueryFieldKind::ClipText,
                            value: "sunlit garden".into(),
                            negated: false,
                            threshold: Some(0.25),
                        },
                    },
                    QueryBuilderNode::Condition {
                        connector: QueryConnector::And,
                        condition: QueryCondition {
                            id: 12,
                            field: QueryFieldKind::SimilarId,
                            value: "42".into(),
                            negated: false,
                            threshold: Some(0.7),
                        },
                    },
                    QueryBuilderNode::Condition {
                        connector: QueryConnector::And,
                        condition: QueryCondition {
                            id: 13,
                            field: QueryFieldKind::UploadImage,
                            value: "0".into(),
                            negated: false,
                            threshold: Some(0.65),
                        },
                    },
                    QueryBuilderNode::Group(QueryGroup {
                        id: 14,
                        combinator: QueryCombinator::Or,
                        connector: QueryConnector::And,
                        negated: false,
                        conditions: vec![
                            QueryCondition {
                                id: 15,
                                field: QueryFieldKind::Title,
                                value: "spring".into(),
                                negated: false,
                                threshold: None,
                            },
                            QueryCondition {
                                id: 16,
                                field: QueryFieldKind::Author,
                                value: "alice".into(),
                                negated: true,
                                threshold: None,
                            },
                        ],
                        list_values: Default::default(),
                    }),
                ],
                query: r#"tag:maid>=0.45 AND clip:"sunlit garden">=0.25 AND dino:42>=0.7 AND upload:0>=0.65 AND (title:spring OR NOT author:alice)"#.into(),
                active_preset: None,
            });
            let defaults = Signal::derive(|| QueryThresholdDefaults {
                tag_min_score: Some(0.45),
                clip_min_sim: Some(0.22),
                dino_min_sim: Some(0.60),
            });
            view! {
                <QueryBuilder
                    draft=draft
                    mode=QueryBuilderMode::AdvancedSearch
                    threshold_defaults=defaults
                />
            }
        });

        assert!(html.contains(r#"data-mode="advanced""#));
        assert!(html.contains("le-qb-card"));
        assert!(html.contains("le-qb-card-header"));
        assert!(html.contains("le-qb-group"));
        assert!(html.contains("le-qb-subcard"));
        assert!(html.contains("le-qb-group-paren"));
        assert!(html.contains("( ... )"));
        assert!(html.contains("Min score"));
        assert!(html.contains("Min sim"));
        assert!(html.contains(r#"inputmode="decimal""#));
        assert!(html.contains(r#"data-min="0.01""#));
        assert!(html.contains(r#"data-max="1.00""#));
        assert!(html.contains(r#"data-step="0.01""#));
        assert!(
            !html.contains(r#"step="0.05""#),
            "Must never emit step=0.05"
        );
        assert!(
            !html.contains(r#"type="number""#),
            "Score inputs must use type=text + inputmode=decimal for fluid keyboard editing"
        );
        // 4 threshold inputs (Tag, ClipText, SimilarId, UploadImage)
        assert_eq!(html.matches("le-qb-threshold-input").count(), 4);
        // Distinct remove buttons for 4 cards + 1 group + 2 subcards = 7
        assert_eq!(html.matches("le-qb-remove-btn").count(), 7);
        // Zero CLIP/DINO weighted summation controls
        assert!(!html.contains("clip_weight"));
        assert!(!html.contains("dino_weight"));
        assert!(!html.contains("CLIP weight"));
        // Presets hidden by default in AdvancedSearch mode
        assert!(!html.contains("le-qb-presets"));
    }

    #[test]
    fn query_builder_ssr_safety_policy_renders_presets_step_001_and_zero_vector_fields() {
        let html = render_ssr(|| {
            let draft = RwSignal::new(QueryBuilderDraft {
                mode: QueryBuilderMode::SafetyPolicy,
                nodes: vec![
                    QueryBuilderNode::Group(QueryGroup {
                        id: 1,
                        combinator: QueryCombinator::Or,
                        connector: QueryConnector::And,
                        negated: false,
                        conditions: vec![
                            QueryCondition {
                                id: 2,
                                field: QueryFieldKind::Tag,
                                value: "explicit".into(),
                                negated: false,
                                threshold: Some(0.5),
                            },
                            QueryCondition {
                                id: 3,
                                field: QueryFieldKind::PostTag,
                                value: "r18".into(),
                                negated: false,
                                threshold: None,
                            },
                        ],
                        list_values: Default::default(),
                    }),
                    QueryBuilderNode::Condition {
                        connector: QueryConnector::And,
                        condition: QueryCondition {
                            id: 4,
                            field: QueryFieldKind::Unclassified,
                            value: String::new(),
                            negated: false,
                            threshold: None,
                        },
                    },
                ],
                query: "(tag:explicit>=0.50 OR post_tag:r18) AND unclassified".into(),
                active_preset: Some("r18".into()),
            });
            view! {
                <QueryBuilder draft=draft mode=QueryBuilderMode::SafetyPolicy />
            }
        });

        assert!(html.contains(r#"data-mode="safety""#));
        assert!(html.contains("R-18 / Explicit"));
        assert!(html.contains("Suggestive / Ecchi"));
        assert!(html.contains("Blood / Violence"));
        assert!(html.contains("Custom"));
        assert!(html.contains("WD Tag"));
        assert!(html.contains("Post Tag"));
        assert!(html.contains("Unclassified"));
        assert!(html.contains("Min score"));
        assert!(html.contains("0.50"));
        assert!(html.contains(r#"inputmode="decimal""#));
        assert!(html.contains(r#"data-min="0.01""#));
        assert!(html.contains(r#"data-max="1.00""#));
        assert!(html.contains(r#"data-step="0.01""#));
        assert!(!html.contains(r#"step="0.05""#));
        assert!(!html.contains(r#"type="number""#));
        // Zero vector fields or vector operators in SafetyPolicy mode
        assert!(!html.contains("CLIP Text"));
        assert!(!html.contains("Similar ID"));
        assert!(!html.contains("Upload Image"));
        assert!(!html.contains("clip:"));
        assert!(!html.contains("dino:"));
        assert!(!html.contains("upload:"));
    }

    #[test]
    fn score_input_ssr_renders_keyboard_friendly_decimal_inputs() {
        let html = render_ssr(|| {
            let score = RwSignal::new(0.5f32);
            let opt = RwSignal::new(Some(0.456f32));
            view! {
                <div>
                    <ScoreInput
                        id="default-min-score"
                        value=score
                        on_change=Callback::new(move |v| score.set(v))
                        min=0.01
                        max=1.00
                        step=0.01
                        placeholder="0.45"
                        aria_label="Default Min Score"
                        class="adm-score"
                    />
                    <OptionalScoreInput
                        id="optional-min-sim"
                        value=opt
                        on_change=Callback::new(move |v| opt.set(v))
                        placeholder=Signal::derive(|| "default".to_string())
                        aria_label="Min similarity"
                    />
                </div>
            }
        });

        assert!(html.contains(r#"id="default-min-score""#));
        assert!(html.contains(r#"id="optional-min-sim""#));
        assert!(html.contains(r#"type="text""#));
        assert!(html.contains(r#"inputmode="decimal""#));
        assert!(html.contains(r#"data-min="0.01""#));
        assert!(html.contains(r#"data-max="1.00""#));
        assert!(html.contains(r#"data-step="0.01""#));
        assert!(html.contains(r#"value="0.50""#));
        assert!(html.contains(r#"value="0.46""#));
        assert!(html.contains("le-score-field adm-score"));
        assert!(!html.contains(r#"type="number""#));
    }

    #[test]
    fn toggle_switch_ssr_renders_accessible_left_aligned_switch() {
        let html = render_ssr(|| {
            let enabled = RwSignal::new(true);
            let blur = RwSignal::new(false);
            view! {
                <div>
                    <ToggleSwitch
                        checked=enabled
                        on_change=Callback::new(move |next| enabled.set(next))
                        label="Enable server-side content safety filtering"
                        description="Evaluates policies before HTML, hydration, API, or media delivery."
                    />
                    <ToggleSwitch
                        checked=blur
                        on_change=Callback::new(move |next| blur.set(next))
                        label="Cloudflare Images blur"
                        compact=true
                        disabled=true
                    />
                </div>
            }
        });

        assert!(html.contains(r#"role="switch""#));
        assert!(html.contains(r#"aria-checked="true""#));
        assert!(html.contains(r#"aria-checked="false""#));
        assert!(html.contains("le-toggle-copy"));
        assert!(html.contains("le-toggle-track"));
        assert!(html.contains("le-toggle-thumb"));
        assert!(html.contains("le-toggle-row--compact"));
        assert!(html.contains("is-checked"));
        assert!(html.contains("is-disabled"));
        assert!(html.contains("Enable server-side content safety filtering"));
        assert!(html.contains("Evaluates policies before HTML, hydration, API, or media delivery."));
    }

    #[test]
    fn sky_select_fixed_menu_ssr_markup_emits_position_fixed_z_10050() {
        let html = render_ssr(|| {
            let menu_ref = NodeRef::<leptos::html::Div>::new();
            let active = RwSignal::new(Some(0usize));
            let pl = compute_menu_placement_from_metrics(
                160.0,
                194.0,
                24.0,
                164.0,
                1280.0,
                800.0,
                7,
                SelectVariant::SkyBox,
            );
            render_select_menu_view(
                menu_ref,
                77,
                "le-select-list-77".to_string(),
                "Condition field",
                "sky-box",
                vec![
                    SelectOption::new("tag", "Tag"),
                    SelectOption::new("dino", "Similar ID"),
                    SelectOption::new("upload", "Upload Image"),
                ],
                "dino".to_string(),
                pl,
                active,
                Callback::new(|_| {}),
            )
        });
        assert!(html.contains(r#"role="listbox""#));
        assert!(html.contains("position:fixed;z-index:10050;"));
        assert!(html.contains("top:200.0px;"));
        assert!(html.contains("Similar ID"));
        assert!(html.contains("Upload Image"));
    }

    #[test]
    fn query_builder_ssr_in_not_in_renders_multi_chip_editor_and_presets_colors() {
        let html = render_ssr(|| {
            let draft = RwSignal::new(
                QueryBuilderDraft::from_query(
                    QueryBuilderMode::SafetyPolicy,
                    "tag IN (explicit, nude, nipples) >= 0.45 AND post_tag NOT IN (approved, safe)",
                )
                .expect("IN/NOT IN query parses"),
            );
            view! {
                <QueryBuilder draft=draft mode=QueryBuilderMode::SafetyPolicy />
            }
        });
        assert!(html.contains("le-qb-chips-box"));
        assert!(html.contains("le-qb-chips-box is-negated"));
        assert!(html.contains("le-qb-chip"));
        assert!(html.contains("explicit"));
        assert!(html.contains("nude"));
        assert!(html.contains("nipples"));
        assert!(html.contains("approved"));
        assert!(html.contains("le-qb-op-select"));
        assert!(html.contains("le-preset-btn--r18"));
        assert!(html.contains("le-preset-btn--sensitive"));
        assert!(html.contains("le-preset-btn--blood"));
        assert!(html.contains("0.45"));
    }

    #[test]
    fn content_mask_card_preset_colors_and_cta_resolution() {
        // R18 = yellow/amber, Sensitive = purple, Blood = red
        let r18_html = render_ssr(|| {
            let mask = GalleryMask {
                rule_id: "r18".into(),
                label: "R-18 / Explicit".into(),
                preset: GalleryMaskPreset::R18,
                reason: None,
                requires_login: false,
                requires_age: true,
                requires_terms: false,
                cta_label: None,
            };
            view! { <ContentMaskCard mask=mask on_unlock_click=Callback::new(|_| {}) /> }
        });
        assert!(r18_html.contains("le-mask-card--r18"));
        assert!(r18_html.contains("#eab308"));
        assert!(r18_html.contains("#fef9c3"));
        assert!(r18_html.contains("#854d0e"));
        assert!(r18_html.contains("Confirm 18+ to unlock"));

        let sens_html = render_ssr(|| {
            let mask = GalleryMask {
                rule_id: "sens".into(),
                label: "Suggestive / Ecchi".into(),
                preset: GalleryMaskPreset::Sensitive,
                reason: None,
                requires_login: false,
                requires_age: false,
                requires_terms: true,
                cta_label: None,
            };
            view! { <ContentMaskCard mask=mask on_unlock_click=Callback::new(|_| {}) /> }
        });
        assert!(sens_html.contains("le-mask-card--sensitive"));
        assert!(sens_html.contains("#9333ea"));
        assert!(sens_html.contains("#f3e8ff"));
        assert!(sens_html.contains("#581c87"));
        assert!(sens_html.contains("Accept Terms to unlock"));

        let blood_html = render_ssr(|| {
            let mask = GalleryMask {
                rule_id: "blood".into(),
                label: "Blood / Violence".into(),
                preset: GalleryMaskPreset::Blood,
                reason: None,
                requires_login: false,
                requires_age: false,
                requires_terms: false,
                cta_label: None,
            };
            view! { <ContentMaskCard mask=mask on_unlock_click=Callback::new(|_| {}) /> }
        });
        assert!(blood_html.contains("le-mask-card--blood"));
        assert!(blood_html.contains("#dc2626"));
        assert!(blood_html.contains("#fee2e2"));
        assert!(blood_html.contains("#991b1b"));
        assert!(blood_html.contains("Enable in Account Settings"));

        // Explicit empty cta_label: Some("") cleanly suppresses CTA button even with callback
        let blocked_html = render_ssr(|| {
            let mask = GalleryMask {
                rule_id: "hard".into(),
                label: "Permanently Restricted".into(),
                preset: GalleryMaskPreset::Custom,
                reason: Some("Not available in your region.".into()),
                requires_login: false,
                requires_age: false,
                requires_terms: false,
                cta_label: Some(String::new()),
            };
            view! { <ContentMaskCard mask=mask on_unlock_click=Callback::new(|_| {}) /> }
        });
        assert!(!blocked_html.contains("le-mask-cta"));
    }

    #[test]
    fn age_gate_modal_ssr_renders_badge_copy_error_and_dismissible_state() {
        let closed_html = render_ssr(|| {
            view! {
                <AgeGateModal
                    open=Signal::derive(|| false)
                    on_confirm=Callback::new(|_| {})
                />
            }
        });
        assert!(!closed_html.contains("le-age-gate-dialog"));

        let open_html = render_ssr(|| {
            view! {
                <AgeGateModal
                    open=Signal::derive(|| true)
                    title=Signal::derive(|| "Confirm Your Age".to_string())
                    is_authenticated=Signal::derive(|| true)
                    submitting=Signal::derive(|| false)
                    error=Signal::derive(|| Some("Verification failed — please retry.".to_string()))
                    on_confirm=Callback::new(|_| {})
                    on_leave=Callback::new(|_| {})
                    on_close=Callback::new(|_| {})
                />
            }
        });
        assert!(open_html.contains(r#"role="dialog""#));
        assert!(open_html.contains(r#"aria-modal="true""#));
        assert!(open_html.contains(r#"data-dismissible="true""#));
        assert!(open_html.contains("le-age-gate-close"));
        assert!(open_html.contains("18+"));
        assert!(open_html.contains("Confirm Your Age"));
        assert!(open_html.contains(AGE_GATE_LEGAL_COPY));
        assert!(open_html.contains("I am 18 or older \u{2014} Confirm"));
        assert!(open_html.contains("Leave / Cancel"));
        assert!(open_html.contains("Verification failed"));
        assert!(open_html.contains("saved to your account"));

        // Non-dismissible gate omits close button
        let strict_html = render_ssr(|| {
            view! {
                <AgeGateModal
                    open=Signal::derive(|| true)
                    is_authenticated=Signal::derive(|| false)
                    on_confirm=Callback::new(|_| {})
                    on_leave=Callback::new(|_| {})
                />
            }
        });
        assert!(strict_html.contains(r#"data-dismissible="false""#));
        assert!(!strict_html.contains("le-age-gate-close"));
        assert!(strict_html.contains("this browsing session"));
    }

    #[test]
    fn query_builder_ssr_list_condition_direct_render() {
        let html = render_ssr(|| {
            let draft = RwSignal::new(QueryBuilderDraft {
                mode: QueryBuilderMode::AdvancedSearch,
                nodes: vec![QueryBuilderNode::ListCondition {
                    connector: QueryConnector::And,
                    condition: QueryListCondition {
                        id: 42,
                        field: QueryFieldKind::Tag,
                        values: vec!["maid".into(), "long hair".into()],
                        negated: false,
                        threshold: Some(0.55),
                    },
                }],
                query: r#"tag IN (maid, "long hair") >= 0.55"#.into(),
                active_preset: None,
            });
            view! { <QueryBuilder draft=draft mode=QueryBuilderMode::AdvancedSearch /> }
        });
        assert!(html.contains("le-qb-chips-box"));
        assert!(html.contains("maid"));
        assert!(html.contains("long hair"));
        assert!(html.contains("0.55"));
    }
}

#[test]
fn query_builder_in_and_not_in_parse_format_presets_and_validation() {
    let mut id = 500u64;
    let mut alloc = || {
        id += 1;
        id
    };

    // Built-in Safety Presets produce 1 single compact WD Tag IN [...] >= 0.45 row
    let builtins = PresetTemplate::builtins();
    for preset_id in ["r18", "sensitive", "blood"] {
        let tpl = builtins
            .iter()
            .find(|p| p.id == preset_id)
            .expect("preset exists");
        let nodes = parse_query_to_nodes(QueryBuilderMode::SafetyPolicy, &tpl.query, &mut alloc)
            .unwrap_or_else(|e| panic!("preset {preset_id} must parse: {e}"));
        assert_eq!(
            nodes.len(),
            1,
            "preset {preset_id} must collapse to 1 single compact row"
        );
        match &nodes[0] {
            QueryBuilderNode::ListCondition { condition, .. } => {
                assert_eq!(condition.field, QueryFieldKind::Tag);
                assert_eq!(condition.operator(), QueryConditionOp::In);
                assert_eq!(condition.threshold, Some(0.45));
                assert!(!condition.values.is_empty());
            }
            other => panic!("expected ListCondition for {preset_id}, got {other:?}"),
        }
        assert_eq!(format_query_nodes(&nodes), tpl.query);
    }

    // Round-trip IN, NOT IN, NOT ... IN, quoted items, space-separated lists, >= whitespace combos
    for (mode, input, expected) in [
        (
            QueryBuilderMode::SafetyPolicy,
            r#"tag IN (explicit, nude, "long hair") >= 0.45"#,
            r#"tag IN (explicit, nude, "long hair") >= 0.45"#,
        ),
        (
            QueryBuilderMode::SafetyPolicy,
            "tag in (explicit nude)>=0.5",
            "tag IN (explicit, nude) >= 0.50",
        ),
        (
            QueryBuilderMode::SafetyPolicy,
            "tag NOT IN (safe, general) >= 0.45",
            "tag NOT IN (safe, general) >= 0.45",
        ),
        (
            QueryBuilderMode::SafetyPolicy,
            "NOT tag IN (explicit, nude) >=0.60",
            "tag NOT IN (explicit, nude) >= 0.60",
        ),
        (
            QueryBuilderMode::SafetyPolicy,
            "-tag in (explicit, nude)>= 0.45",
            "tag NOT IN (explicit, nude) >= 0.45",
        ),
        (
            QueryBuilderMode::SafetyPolicy,
            r#"post_tag IN (cosplay, "r 18") AND author NOT IN (alice, bob)"#,
            r#"post_tag IN (cosplay, "r 18") AND author NOT IN (alice, bob)"#,
        ),
        (
            QueryBuilderMode::SafetyPolicy,
            "(tag IN (explicit, nude) >= 0.45 OR post_tag IN (nsfw, r18))",
            "(tag IN (explicit, nude) >= 0.45 OR post_tag IN (nsfw, r18))",
        ),
        (
            QueryBuilderMode::AdvancedSearch,
            r#"tag IN (maid, apron) >= 0.45 AND author NOT IN ("alice smith", bob)"#,
            r#"tag IN (maid, apron) >= 0.45 AND author NOT IN ("alice smith", bob)"#,
        ),
        // Bare English word "in" in AdvancedSearch must NOT break when not a field keyword
        (
            QueryBuilderMode::AdvancedSearch,
            "cat in hat",
            "all:cat AND all:in AND all:hat",
        ),
        (
            QueryBuilderMode::AdvancedSearch,
            "alice in (wonderland)",
            "all:alice AND all:in AND all:wonderland",
        ),
    ] {
        let nodes = parse_query_to_nodes(mode, input, &mut alloc)
            .unwrap_or_else(|e| panic!("failed to parse {input:?} in {mode:?}: {e}"));
        assert_eq!(format_query_nodes(&nodes), expected, "input={input:?}");
    }

    // Invalid IN / NOT IN forms must fail cleanly
    for (mode, bad) in [
        (QueryBuilderMode::SafetyPolicy, "tag IN ()"),
        (QueryBuilderMode::SafetyPolicy, "tag NOT IN ()"),
        (QueryBuilderMode::SafetyPolicy, "tag IN (explicit,)"),
        (QueryBuilderMode::SafetyPolicy, "tag IN (,explicit)"),
        (QueryBuilderMode::SafetyPolicy, "tag IN (explicit,,nude)"),
        (QueryBuilderMode::SafetyPolicy, "tag IN (explicit"),
        (QueryBuilderMode::SafetyPolicy, "NOT tag NOT IN (explicit)"),
        (QueryBuilderMode::SafetyPolicy, "tag IN (explicit) >= 0.456"),
        (QueryBuilderMode::SafetyPolicy, "tag IN (explicit) >= 0"),
        (QueryBuilderMode::SafetyPolicy, "post_tag IN (a, b) >= 0.50"),
        (QueryBuilderMode::SafetyPolicy, "author IN (a, b) >= 0.50"),
        (QueryBuilderMode::SafetyPolicy, "unclassified IN (a)"),
        (QueryBuilderMode::SafetyPolicy, "tag IN (/blood.*/)"),
        // Non-list fields rejected in AdvancedSearch (dino/clip/upload/title/all are single-value only)
        (QueryBuilderMode::AdvancedSearch, "dino IN (12, 34)"),
        (QueryBuilderMode::AdvancedSearch, "clip IN (sunset, dawn)"),
        (QueryBuilderMode::AdvancedSearch, "upload IN (0, 1)"),
        (QueryBuilderMode::AdvancedSearch, "title IN (spring, summer)"),
        (QueryBuilderMode::AdvancedSearch, "all IN (foo, bar)"),
        (QueryBuilderMode::AdvancedSearch, "author IN (alice, bob) >= 0.50"),
    ] {
        assert!(
            parse_query_to_nodes(mode, bad, &mut alloc).is_err(),
            "expected parse error for {bad:?} in {mode:?}"
        );
    }

    // Every element in IN (...) counts toward MAX_TERMS_PER_RULE
    let too_many = format!(
        "tag IN ({})",
        (0..=MAX_TERMS_PER_RULE)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(parse_query_to_nodes(QueryBuilderMode::SafetyPolicy, &too_many, &mut alloc).is_err());

    // Empty QueryListCondition formats to None; merge_chip_values trims, splits & deduplicates
    let mut chips = vec!["explicit".to_string()];
    assert!(merge_chip_values(&mut chips, " nude , explicit, nipples\n  nude  "));
    assert_eq!(chips, vec!["explicit", "nude", "nipples"]);
    assert!(!merge_chip_values(&mut chips, " , explicit , "));
    assert_eq!(
        format_query_list_condition(&crate::components::QueryListCondition {
            id: 1,
            field: QueryFieldKind::Tag,
            values: vec![],
            negated: false,
            threshold: Some(0.45),
        }),
        None
    );
}

#[test]
fn gallery_mask_resolved_cta_distinguishes_requirements_and_empty_override() {
    let base = GalleryMask {
        rule_id: "r1".into(),
        label: "Restricted".into(),
        preset: GalleryMaskPreset::R18,
        reason: None,
        requires_login: false,
        requires_age: false,
        requires_terms: false,
        cta_label: None,
    };
    assert_eq!(base.resolved_cta(), "Enable in Account Settings");
    assert_eq!(
        GalleryMask {
            requires_login: true,
            requires_age: true,
            requires_terms: true,
            ..base.clone()
        }
        .resolved_cta(),
        "Sign in to unlock"
    );
    assert_eq!(
        GalleryMask {
            requires_age: true,
            requires_terms: true,
            ..base.clone()
        }
        .resolved_cta(),
        "Confirm 18+ to unlock"
    );
    assert_eq!(
        GalleryMask {
            requires_terms: true,
            ..base.clone()
        }
        .resolved_cta(),
        "Accept Terms to unlock"
    );
    assert_eq!(
        GalleryMask {
            cta_label: Some("Click to reveal".into()),
            ..base.clone()
        }
        .resolved_cta(),
        "Click to reveal"
    );
    assert_eq!(
        GalleryMask {
            cta_label: Some(String::new()),
            ..base
        }
        .resolved_cta_opt(),
        None
    );
}
