use leptos::prelude::*;

use crate::components::{
    ContentMaskCard, DensityPicker, FloatingHeader, Lightbox, LikeButton, MasonryGallery,
    MinSimilaritySlider, NoticeBanner, QueryRuleBuilder, ReportDialog, SafeModeToggle, SkySelect,
    SpoilerOverlay, Viewer, clamp_chars, compute_menu_placement_from_metrics, next_enabled_index,
};
use crate::layout::{format_duration, layout_masonry};
use crate::models::{
    Density, GalleryBlurMode, GalleryCard, GalleryCardKind, GalleryMask, GalleryMaskPreset,
    GalleryMedia, GalleryMediaKind, LightboxAlbum, LikeTargetKind, LikeVariant,
    MAX_REPORT_NOTE_CHARS, NoticeContent, NoticeTone, PresetTemplate, ReportReason,
    ReportTargetKind, RuleBlock, RuleBlockKind, RuleClause, RuleConnector, RuleDraft, RuleField,
    RuleGroupCombinator, SelectOption, SelectVariant, ViewerItem,
};
use crate::rule_syntax::{format_rule_blocks, parse_safety_rule_to_blocks};

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

    // Score threshold + OR group + NOT clause round-trip
    let blocks = parse_safety_rule_to_blocks(
        "(tag:explicit>=0.45 OR tag:nude>=0.6) NOT post_tag:approved",
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
fn ui_css_is_bundled_and_contains_mobile_density_breakpoints() {
    assert!(crate::UI_CSS.contains(".le-mask-card"));
    assert!(crate::UI_CSS.contains(".le-spoiler-img--css"));
    assert!(crate::UI_CSS.contains(".le-rule-group-paren"));
    assert!(crate::UI_CSS.contains(r#".gallery-ssr-grid[data-density="compact"]"#));
    assert!(crate::UI_CSS.contains(r#".gallery-ssr-grid[data-density="medium"]"#));
    assert!(crate::UI_CSS.contains(r#".gallery-ssr-grid[data-density="large"]"#));
}

#[cfg(feature = "ssr")]
mod ssr_render_tests {
    use super::*;

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
}
