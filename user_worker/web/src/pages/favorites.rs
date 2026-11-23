//! `/user/favorites` — Favorites gallery reusing `lets-embed-ui` components
//! (`FloatingHeader`, `DensityPicker`, `SafeModeToggle`, `MasonryGallery`,
//! `Lightbox`, `Viewer`, `ReportDialog`, `NoticeBanner`) with full `Clear` /
//! `Spoiler` / `Locked` mask support and instant Safe Mode L1 media eviction.

use std::collections::HashMap;

use leptos::{prelude::*, task::spawn_local};
use lets_embed_ui::{
    AuthorChip, Density, DensityPicker, FloatingHeader, GalleryBlurMode, GalleryCard,
    GalleryCardKind, GalleryMask, GalleryMaskPreset, GalleryMedia, GalleryMediaKind, HeaderVariant,
    Lightbox, LightboxAlbum, LikeTargetKind, MasonryGallery, NoticeBanner, NoticeContent,
    NoticeTone, ReportDialog, ReportSubmission, ReportTargetKind, SafeModeToggle, Viewer,
    ViewerItem,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{self, LikeRow, LikesResp, MeResp, PreferencesResp};

#[derive(Clone, Copy, PartialEq, Eq)]
enum FavFilter {
    All,
    Post,
    Image,
    Video,
}

impl FavFilter {
    const fn as_query(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Post => Some("post"),
            Self::Image => Some("image"),
            Self::Video => Some("video"),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Post => "Posts",
            Self::Image => "Images",
            Self::Video => "Videos",
        }
    }
}

/// Parse a flexible `/api/like_previews` or `/api/post_images` JSON item into
/// a `lets_embed_ui::GalleryMedia`, supporting both projected safety states
/// (`clear` / `spoiler` / `locked`) and legacy `{ id, name, width, height }` shapes.
fn parse_media_value(val: &Value, fallback_id: i64, fallback_kind: GalleryMediaKind) -> GalleryMedia {
    let id = val.get("id").and_then(Value::as_i64).unwrap_or(fallback_id);
    let width = val.get("width").and_then(Value::as_i64).unwrap_or(400) as i32;
    let height = val.get("height").and_then(Value::as_i64).unwrap_or(300) as i32;
    let duration_secs = val
        .get("duration")
        .or_else(|| val.get("duration_secs"))
        .and_then(Value::as_i64)
        .map(|d| d as i32);
    let kind = match val.get("kind").and_then(Value::as_str) {
        Some("video") => GalleryMediaKind::Video,
        Some("image") => GalleryMediaKind::Image,
        _ => fallback_kind,
    };

    match val.get("state").and_then(Value::as_str) {
        Some("locked") => {
            let mask_val = val.get("mask").unwrap_or(val);
            let rule_id = mask_val
                .get("rule_id")
                .and_then(Value::as_str)
                .unwrap_or("restricted")
                .to_string();
            let label = mask_val
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or("Restricted Content")
                .to_string();
            let preset = mask_val
                .get("preset")
                .and_then(Value::as_str)
                .map(GalleryMaskPreset::parse)
                .unwrap_or(GalleryMaskPreset::Custom);
            GalleryMedia::Locked {
                id,
                kind,
                width,
                height,
                mask: GalleryMask {
                    rule_id,
                    label,
                    preset,
                    reason: mask_val
                        .get("reason")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    requires_login: mask_val
                        .get("requires_login")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    requires_age: mask_val
                        .get("requires_age")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    requires_terms: mask_val
                        .get("requires_terms")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    cta_label: mask_val
                        .get("cta_label")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                },
            }
        }
        Some("spoiler") => {
            let preview_url = val
                .get("preview_url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let reveal_url = val
                .get("reveal_url")
                .or_else(|| val.get("url"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let blur_mode = match val.get("blur_mode").and_then(Value::as_str) {
                Some("css_courtesy") => GalleryBlurMode::CssCourtesy,
                _ => GalleryBlurMode::ServerTransform,
            };
            GalleryMedia::Spoiler {
                id,
                kind,
                width,
                height,
                preview_url,
                reveal_url,
                alt: val
                    .get("alt")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                duration_secs,
                rule_id: val
                    .get("rule_id")
                    .and_then(Value::as_str)
                    .unwrap_or("spoiler")
                    .to_string(),
                label: val
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("Spoiler")
                    .to_string(),
                preset: val
                    .get("preset")
                    .and_then(Value::as_str)
                    .map(GalleryMaskPreset::parse)
                    .unwrap_or(GalleryMaskPreset::Sensitive),
                blur_mode,
            }
        }
        _ => {
            // Clear (explicit `"clear"` or legacy preview payload)
            let url = val
                .get("url")
                .or_else(|| val.get("media_url"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_default();
            GalleryMedia::Clear {
                id,
                kind,
                width,
                height,
                url,
                alt: val
                    .get("alt")
                    .or_else(|| val.get("title"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                duration_secs,
            }
        }
    }
}

fn build_cards_from_previews(likes: &[LikeRow], previews: &Value) -> Vec<GalleryCard> {
    let mut post_map: HashMap<i64, Value> = HashMap::new();
    let mut image_map: HashMap<i64, Value> = HashMap::new();
    let mut video_map: HashMap<i64, Value> = HashMap::new();

    if let Some(arr) = previews.get("posts").and_then(Value::as_array) {
        for item in arr {
            if let Some(id) = item
                .get("post_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_i64)
            {
                post_map.insert(id, item.clone());
            }
        }
    }
    if let Some(arr) = previews.get("images").and_then(Value::as_array) {
        for item in arr {
            if let Some(id) = item
                .get("id")
                .or_else(|| item.get("image_id"))
                .and_then(Value::as_i64)
            {
                image_map.insert(id, item.clone());
            }
        }
    }
    if let Some(arr) = previews.get("videos").and_then(Value::as_array) {
        for item in arr {
            if let Some(id) = item
                .get("id")
                .or_else(|| item.get("video_id"))
                .and_then(Value::as_i64)
            {
                video_map.insert(id, item.clone());
            }
        }
    }

    let mut cards = Vec::with_capacity(likes.len());
    for row in likes {
        match row.kind.as_str() {
            "post" => {
                let Some(pv) = post_map.get(&row.target_id) else {
                    continue;
                };
                let cover_val = pv.get("cover").unwrap_or(pv);
                let media = parse_media_value(cover_val, row.target_id, GalleryMediaKind::Image);
                let title = pv
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let image_count = pv
                    .get("image_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                let video_count = pv
                    .get("video_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                let details_href = if media.is_locked() {
                    None
                } else {
                    Some(format!("/details/{}?mode=similar&q={}", media.id(), media.id()))
                };
                cards.push(GalleryCard {
                    key: format!("post:{}", row.target_id),
                    id: row.target_id,
                    kind: GalleryCardKind::Post,
                    title,
                    subtitle: None,
                    media,
                    image_count,
                    video_count,
                    details_href,
                    liked: Some(true),
                });
            }
            "video" => {
                let Some(vv) = video_map.get(&row.target_id) else {
                    continue;
                };
                let media = parse_media_value(vv, row.target_id, GalleryMediaKind::Video);
                let title = vv
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                cards.push(GalleryCard {
                    key: format!("video:{}", row.target_id),
                    id: row.target_id,
                    kind: GalleryCardKind::Video,
                    title,
                    subtitle: None,
                    media,
                    image_count: 0,
                    video_count: 1,
                    details_href: None,
                    liked: Some(true),
                });
            }
            _ => {
                let Some(iv) = image_map.get(&row.target_id) else {
                    continue;
                };
                let media = parse_media_value(iv, row.target_id, GalleryMediaKind::Image);
                let details_href = if media.is_locked() {
                    None
                } else {
                    Some(format!("/details/{}?mode=similar&q={}", row.target_id, row.target_id))
                };
                cards.push(GalleryCard {
                    key: format!("image:{}", row.target_id),
                    id: row.target_id,
                    kind: GalleryCardKind::Image,
                    title: iv
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    subtitle: None,
                    media,
                    image_count: 0,
                    video_count: 0,
                    details_href,
                    liked: Some(true),
                });
            }
        }
    }
    cards
}

#[derive(Deserialize)]
struct PostDetailResp {
    #[serde(default)]
    title: String,
    #[serde(default)]
    authors: Vec<String>,
    #[serde(default)]
    images: Vec<Value>,
    #[serde(default)]
    videos: Vec<Value>,
}

#[component]
pub fn FavoritesPage() -> impl IntoView {
    let filter = RwSignal::new(FavFilter::All);
    let density = RwSignal::new(Density::Medium);
    let safe_mode = RwSignal::new(false);
    let panic_epoch = RwSignal::new(0u64);
    let saved_switchers = RwSignal::new(Vec::<String>::new());

    let cards = RwSignal::new(Vec::<GalleryCard>::new());
    let next_cursor = RwSignal::new(None::<i64>);
    let loading = RwSignal::new(false);
    let error_msg = RwSignal::new(None::<String>);

    // Undo toast after unliking an item
    let undo_item = RwSignal::new(None::<(LikeTargetKind, i64)>);

    // Lightbox & Viewer state
    let active_album = RwSignal::new(None::<LightboxAlbum>);
    let viewer_items = RwSignal::new(Vec::<ViewerItem>::new());
    let viewer_index = RwSignal::new(None::<usize>);

    // ReportDialog state
    let report_open = RwSignal::new(false);
    let report_kind = RwSignal::new(ReportTargetKind::Image);
    let report_id = RwSignal::new(0i64);
    let report_busy = RwSignal::new(false);
    let report_err = RwSignal::new(None::<String>);
    let report_ok = RwSignal::new(None::<String>);

    let load_page = Callback::new(move |(append, cursor): (bool, Option<i64>)| {
        loading.set(true);
        error_msg.set(None);
        let cur_filter = filter.get_untracked();
        spawn_local(async move {
            let mut url = String::from("/user/api/likes?limit=48");
            if let Some(k) = cur_filter.as_query() {
                url.push_str("&kind=");
                url.push_str(k);
            }
            if let Some(c) = cursor {
                url.push_str(&format!("&cursor={c}"));
            }
            let likes_resp = match api::get_json::<LikesResp>(&url).await {
                Ok(r) => r,
                Err(e) if e.status == 401 => {
                    api::navigate_hard("/user/login?next=/user/favorites");
                    return;
                }
                Err(e) => {
                    error_msg.set(Some(e.display()));
                    loading.set(false);
                    return;
                }
            };
            next_cursor.set(likes_resp.next_cursor);
            if likes_resp.items.is_empty() {
                if !append {
                    cards.set(Vec::new());
                }
                loading.set(false);
                return;
            }

            let mut posts = Vec::new();
            let mut images = Vec::new();
            let mut videos = Vec::new();
            for row in &likes_resp.items {
                match row.kind.as_str() {
                    "post" => posts.push(row.target_id),
                    "video" => videos.push(row.target_id),
                    _ => images.push(row.target_id),
                }
            }
            match api::post_json::<_, Value>(
                "/api/like_previews",
                &json!({ "posts": posts, "images": images, "videos": videos }),
            )
            .await
            {
                Ok(previews) => {
                    let batch = build_cards_from_previews(&likes_resp.items, &previews);
                    if append {
                        cards.update(|list| list.extend(batch));
                    } else {
                        cards.set(batch);
                    }
                }
                Err(e) => error_msg.set(Some(e.display())),
            }
            loading.set(false);
        });
    });

    // Initial load: fetch `/user/api/me` for safe_mode & switchers, then load likes.
    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(m) = api::get_json::<MeResp>("/user/api/me").await {
                safe_mode.set(m.safe_mode);
                saved_switchers.set(m.enabled_switchers);
            }
        });
        load_page.run((false, None));
    });

    // Safe Mode toggle: persist via POST /user/api/preferences and immediately refetch projected previews!
    let on_safe_toggle = Callback::new(move |next_safe: bool| {
        let sw = saved_switchers.get_untracked();
        spawn_local(async move {
            let _ = api::post_json::<_, PreferencesResp>(
                "/user/api/preferences",
                &json!({ "enabled_switchers": sw, "safe_mode": next_safe }),
            )
            .await;
            load_page.run((false, None));
        });
    });

    // Open card -> Post Lightbox or Image/Video Viewer
    let on_open_card = Callback::new(move |card: GalleryCard| {
        if card.media.is_locked() {
            api::navigate_hard("/user/account");
            return;
        }
        if card.kind == GalleryCardKind::Post {
            let post_id = card.id;
            active_album.set(Some(LightboxAlbum {
                post_id,
                title: card.title.clone(),
                authors: Vec::new(),
                images: Vec::new(),
                videos: Vec::new(),
                total_images: card.image_count,
                total_videos: card.video_count,
                liked: card.liked,
                loading: true,
                error: None,
            }));
            spawn_local(async move {
                let url = format!("/api/post_images?post_id={post_id}");
                match api::get_json::<PostDetailResp>(&url).await {
                    Ok(detail) => {
                        let imgs: Vec<GalleryCard> = detail
                            .images
                            .iter()
                            .enumerate()
                            .map(|(idx, val)| {
                                let media =
                                    parse_media_value(val, idx as i64, GalleryMediaKind::Image);
                                let id = media.id();
                                GalleryCard {
                                    key: format!("img:{id}"),
                                    id,
                                    kind: GalleryCardKind::Image,
                                    title: String::new(),
                                    subtitle: None,
                                    media,
                                    image_count: 0,
                                    video_count: 0,
                                    details_href: Some(format!("/details/{id}?mode=similar&q={id}")),
                                    liked: None,
                                }
                            })
                            .collect();
                        let vids: Vec<GalleryMedia> = detail
                            .videos
                            .iter()
                            .enumerate()
                            .map(|(idx, val)| {
                                parse_media_value(val, idx as i64, GalleryMediaKind::Video)
                            })
                            .collect();
                        active_album.set(Some(LightboxAlbum {
                            post_id,
                            title: detail.title,
                            authors: detail
                                .authors
                                .into_iter()
                                .map(|a| AuthorChip { name: a, href: None })
                                .collect(),
                            total_images: imgs.len(),
                            total_videos: vids.len(),
                            images: imgs,
                            videos: vids,
                            liked: Some(true),
                            loading: false,
                            error: None,
                        }));
                    }
                    Err(e) => {
                        active_album.update(|a| {
                            if let Some(alb) = a {
                                alb.loading = false;
                                alb.error = Some(e.display());
                            }
                        });
                    }
                }
            });
        } else {
            let list: Vec<ViewerItem> = cards
                .get_untracked()
                .iter()
                .filter(|c| c.kind != GalleryCardKind::Post && !c.media.is_locked())
                .map(ViewerItem::from_card)
                .collect();
            if let Some(pos) = list.iter().position(|it| it.id == card.media.id()) {
                viewer_items.set(list);
                viewer_index.set(Some(pos));
            }
        }
    });

    let on_like_toggle = Callback::new(move |(kind, target_id, next_liked): (LikeTargetKind, i64, bool)| {
        spawn_local(async move {
            let payload = json!({ "kind": kind.as_str(), "target_id": target_id });
            let res = if next_liked {
                api::post_json_empty("/user/api/like", &payload).await
            } else {
                api::delete_json_empty("/user/api/like", &payload).await
            };
            match res {
                Ok(()) => {
                    if !next_liked {
                        let key = format!("{}:{target_id}", kind.as_str());
                        cards.update(|list| list.retain(|c| c.key != key));
                        undo_item.set(Some((kind, target_id)));
                    } else {
                        undo_item.set(None);
                        load_page.run((false, None));
                    }
                }
                Err(e) => error_msg.set(Some(e.display())),
            }
        });
    });

    let on_unlock_click = Callback::new(move |_mask: GalleryMask| {
        api::navigate_hard("/user/account");
    });

    let on_report_click = Callback::new(move |(kind, id): (ReportTargetKind, i64)| {
        report_kind.set(kind);
        report_id.set(id);
        report_err.set(None);
        report_ok.set(None);
        report_open.set(true);
    });

    let on_report_submit = Callback::new(move |sub: ReportSubmission| {
        report_busy.set(true);
        report_err.set(None);
        spawn_local(async move {
            match api::post_json_empty(
                "/user/api/reports",
                &json!({
                    "target_kind": sub.target_kind.as_str(),
                    "target_id": sub.target_id,
                    "reason": sub.reason.as_str(),
                    "note": if sub.note.is_empty() { None } else { Some(sub.note) },
                }),
            )
            .await
            {
                Ok(()) => {
                    report_ok.set(Some("Thank you — your report has been submitted for review.".into()));
                }
                Err(e) => report_err.set(Some(e.display())),
            }
            report_busy.set(false);
        });
    });

    view! {
        <div class="u-shell">
            <FloatingHeader
                variant=HeaderVariant::Nav
                left=move || view! {
                    <nav class="u-nav-links">
                        <a class="u-nav-link" href="/">"Gallery"</a>
                        <a class="u-nav-link" href="/user/account">"Account"</a>
                        <a class="u-nav-link is-active" href="/user/favorites">"Favorites"</a>
                    </nav>
                }.into_any()
                center=move || view! {
                    <div class="u-tabs" role="tablist" aria-label="Filter favorites">
                        {[FavFilter::All, FavFilter::Post, FavFilter::Image, FavFilter::Video]
                            .into_iter()
                            .map(|f| {
                                view! {
                                    <button
                                        type="button"
                                        class=move || if filter.get() == f { "u-tab is-active" } else { "u-tab" }
                                        on:click=move |_| {
                                            filter.set(f);
                                            load_page.run((false, None));
                                        }
                                    >
                                        {f.label()}
                                    </button>
                                }
                            })
                            .collect_view()}
                    </div>
                }.into_any()
                right=move || view! {
                    <div class="u-row">
                        <DensityPicker density=density />
                        <SafeModeToggle
                            safe_mode=safe_mode
                            panic_epoch=panic_epoch
                            on_toggle=on_safe_toggle
                        />
                    </div>
                }.into_any()
            />

            <div class="u-stack">
                {move || error_msg.get().map(|msg| view! {
                    <NoticeBanner
                        content=NoticeContent::Text(msg)
                        tone=NoticeTone::Danger
                        dismissible=true
                        on_dismiss=Callback::new(move |_| error_msg.set(None))
                    />
                })}

                <MasonryGallery
                    cards=cards.into()
                    density=density.into()
                    panic_epoch=panic_epoch.into()
                    empty_message="No favorites saved yet. Click the heart on any post or image in the gallery to save it here."
                    on_open=on_open_card
                    on_unlock_click=on_unlock_click
                    on_like_toggle=on_like_toggle
                    on_report_click=on_report_click
                />

                {move || next_cursor.get().map(|cur| view! {
                    <div class="u-row" style="justify-content:center;">
                        <button
                            type="button"
                            class="u-btn u-btn--secondary"
                            disabled=move || loading.get()
                            on:click=move |_| load_page.run((true, Some(cur)))
                        >
                            {move || if loading.get() { "Loading..." } else { "Load more" }}
                        </button>
                    </div>
                })}
            </div>

            <Lightbox
                album=active_album.into()
                density=density
                panic_epoch=panic_epoch.into()
                on_close=Callback::new(move |()| active_album.set(None))
                on_open_viewer=Callback::new(move |(idx, list)| {
                    viewer_items.set(list);
                    viewer_index.set(Some(idx));
                })
                on_like_post=Callback::new(move |(pid, next)| {
                    on_like_toggle.run((LikeTargetKind::Post, pid, next));
                })
                on_like_item=on_like_toggle
                on_report=on_report_click
                on_unlock_click=on_unlock_click
            />

            <Viewer
                items=viewer_items.into()
                index=viewer_index
                panic_epoch=panic_epoch.into()
                on_like_toggle=on_like_toggle
                on_report=on_report_click
                on_unlock_click=on_unlock_click
            />

            <ReportDialog
                open=report_open.into()
                target_kind=report_kind.into()
                target_id=report_id.into()
                submitting=report_busy.into()
                error=report_err.into()
                success_message=report_ok.into()
                on_submit=on_report_submit
                on_close=Callback::new(move |()| report_open.set(false))
            />

            {move || undo_item.get().map(|(kind, id)| view! {
                <div class="u-toast" role="status">
                    <span>"Removed from favorites."</span>
                    <button
                        type="button"
                        class="u-btn u-btn--small"
                        on:click=move |_| on_like_toggle.run((kind, id, true))
                    >
                        "Undo"
                    </button>
                </div>
            })}
        </div>
    }
}
