use crate::components::{
    QueryBuilderDraft, QueryBuilderMode, QueryBuilderNode, QueryCombinator, QueryFieldKind,
    clamp_chars, compute_menu_placement_from_metrics, format_query_nodes, next_enabled_index,
    parse_query_to_nodes,
};
use crate::layout::{format_duration, layout_masonry};
use crate::models::{
    Density, GalleryBlurMode, GalleryMaskPreset, GalleryMedia, GalleryMediaKind,
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
    assert_eq!(pl.max_height_px, 256);
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
    assert!(crate::UI_CSS.contains(".le-qb-card"));
    assert!(crate::UI_CSS.contains(".le-qb-group"));
    assert!(crate::UI_CSS.contains(".le-qb-subcard"));
    assert!(crate::UI_CSS.contains(".le-qb-group-paren"));
    assert!(crate::UI_CSS.contains(".le-toggle-row"));
    assert!(crate::UI_CSS.contains(".le-toggle-track"));
    assert!(crate::UI_CSS.contains(".le-header"));
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

    let raw = r#"tag:maid>=0.45 AND clip:"sunlit breeze">=0.25 AND dino:42>=0.7 AND upload:0>=0.65 AND (title:spring OR NOT author:alice)"#;
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
    let valid = "tag:explicit>=0.5 OR NOT (tag:safe OR post_tag:verified)";
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
        "(tag:explicit>=0.45 OR tag:nude>=0.6) AND NOT post_tag:approved"
    );
}

#[cfg(feature = "ssr")]
mod ssr_render_tests {
    use super::*;
    use leptos::prelude::*;

    use crate::components::{
        ContentMaskCard, DensityPicker, FloatingHeader, Lightbox, LikeButton, MAX_VISIBLE_TOASTS,
        MasonryGallery, MinSimilaritySlider, NoticeBanner, QueryBuilder, QueryCondition,
        QueryConnector, QueryGroup, QueryRuleBuilder, QueryThresholdDefaults, ReportDialog,
        SafeModeToggle, SkySelect, SpoilerOverlay, ToastHost, ToastKind, ToggleSwitch, Viewer,
        provide_toast_store, use_toast_store,
    };
    use crate::models::{
        GalleryCard, GalleryCardKind, GalleryMask, LightboxAlbum, LikeTargetKind, LikeVariant,
        NoticeTone, ReportReason, ReportTargetKind, RuleBlock, RuleBlockKind, RuleClause,
        RuleDraft, RuleField, RuleGroupCombinator,
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
        assert!(html.contains(r#"min="0.01""#));
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
        assert!(html.contains(r#"role="status""#));
        assert!(html.contains("le-toast-close"));

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
        assert!(html.contains(r#"min="0.01""#));
        assert!(html.contains(r#"max="1.00""#));
        assert!(html.contains(r#"step="0.01""#));
        assert!(
            !html.contains(r#"step="0.05""#),
            "Must never emit step=0.05 with min=0.01"
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
                query: "(tag:explicit>=0.5 OR post_tag:r18) AND unclassified".into(),
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
        assert!(html.contains(r#"min="0.01""#));
        assert!(html.contains(r#"max="1.00""#));
        assert!(html.contains(r#"step="0.01""#));
        assert!(!html.contains(r#"step="0.05""#));
        // Zero vector fields or vector operators in SafetyPolicy mode
        assert!(!html.contains("CLIP Text"));
        assert!(!html.contains("Similar ID"));
        assert!(!html.contains("Upload Image"));
        assert!(!html.contains("clip:"));
        assert!(!html.contains("dino:"));
        assert!(!html.contains("upload:"));
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
}
