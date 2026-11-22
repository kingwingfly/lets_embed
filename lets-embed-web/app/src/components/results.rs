use std::iter::repeat_with;

#[cfg(any(feature = "ssr", test))]
use crate::types::MAX_SEARCH_LIMIT;
use crate::{
    components::{LikeButton, LikeVariant, lightbox::Lightbox, viewer::Viewer},
    types::{
        AdvancedUploads, ImageQuery, Mode, PostItem, SearchResponse, UploadedImageSlot,
        parse_url_limit,
    },
    util::{encode_path, set_document_title},
};

use leptos::{ev, prelude::*, task::spawn_local};
use leptos_router::{
    NavigateOptions,
    hooks::{use_location, use_navigate, use_query_map},
};
use leptos_use_element_size::{UseElementSizeReturn, use_element_size};
#[cfg(feature = "hydrate")]
use leptos_use_event_listener::use_event_listener;
use leptos_use_intersection_observer::{
    UseIntersectionObserverOptions, use_intersection_observer_with_options,
};
use leptos_use_signal_debounce_throttle::signal_debounced;
use search_types::{
    Image,
    query::{AdvancedSort, QueryExpr, SearchField, VectorTier, parse_and_compile},
};

const COLUMN_GAP: u32 = 12;
const MOBILE_COLUMN_GAP: u32 = 8;
const INTERSECTION_ROOT_MARGIN: &str = "600px 0px";
#[cfg(feature = "ssr")]
const MAX_SEARCH_OFFSET: i64 = 10_000;
#[cfg(feature = "hydrate")]
const GALLERY_DENSITY_KEY: &str = "lets-embed:gallery-density";
#[cfg(feature = "hydrate")]
const FAV_DENSITY_KEY: &str = "lets-embed:fav-density";
#[cfg(feature = "ssr")]
const MAX_UPLOAD_DECODED_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Density {
    Compact,
    Medium,
    Large,
}

impl Density {
    const fn target_width(self) -> f64 {
        match self {
            Self::Compact => 200.0,
            Self::Medium => 300.0,
            Self::Large => 440.0,
        }
    }

    const fn desktop_bounds(self) -> (usize, usize) {
        match self {
            Self::Compact => (2, 12),
            Self::Medium => (1, 8),
            Self::Large => (1, 6),
        }
    }

    #[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }

    #[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
    fn parse(s: &str) -> Option<Self> {
        match s {
            "compact" => Some(Self::Compact),
            "medium" => Some(Self::Medium),
            "large" => Some(Self::Large),
            _ => None,
        }
    }
}

#[cfg(feature = "hydrate")]
fn load_density() -> Option<Density> {
    let storage = web_sys::window()?.local_storage().ok()??;
    storage
        .get_item(GALLERY_DENSITY_KEY)
        .ok()
        .flatten()
        .and_then(|s| Density::parse(&s))
        .or_else(|| {
            storage
                .get_item(FAV_DENSITY_KEY)
                .ok()
                .flatten()
                .and_then(|s| Density::parse(&s))
        })
}

#[cfg(feature = "hydrate")]
fn save_density(density: Density) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(GALLERY_DENSITY_KEY, density.as_str());
    }
}

#[cfg(not(feature = "hydrate"))]
fn save_density(_density: Density) {}

#[cfg(feature = "hydrate")]
fn read_window_width() -> f64 {
    web_sys::window()
        .and_then(|w| w.inner_width().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
}

#[cfg(feature = "hydrate")]
fn read_window_height() -> f64 {
    web_sys::window()
        .and_then(|w| w.inner_height().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
}

fn target_column_count(width: f64, density: Density) -> usize {
    if width <= 0.0 {
        return 1;
    }
    if width <= 540.0 {
        return match density {
            Density::Compact => {
                if width >= 340.0 {
                    3
                } else {
                    2
                }
            }
            Density::Medium => 2,
            Density::Large => 1,
        };
    }
    let (min_cols, max_cols) = density.desktop_bounds();
    ((width / density.target_width()).round() as usize).clamp(min_cols, max_cols)
}

fn column_gap_for(vp_w: f64) -> u32 {
    if vp_w > 0.0 && vp_w <= 640.0 {
        MOBILE_COLUMN_GAP
    } else {
        COLUMN_GAP
    }
}

fn column_pixel_width(width: f64, col_count: usize, gap: u32) -> u32 {
    let count = col_count.max(1);
    ((width - f64::from(gap) * (count.saturating_sub(1) as f64)) / count as f64)
        .round()
        .max(80.0) as u32
}

fn make_empty_columns(width: f64, vp_w: f64, density: Density) -> Vec<Column> {
    let col_count = target_column_count(width, density);
    let gap = column_gap_for(if vp_w > 0.0 { vp_w } else { width });
    let col_width = column_pixel_width(width, col_count, gap);
    repeat_with(|| Column {
        items: vec![],
        width: col_width,
        height: 0,
    })
    .take(col_count)
    .collect()
}

fn horizontal_padding_for(embedded: bool, vp_w: f64) -> f64 {
    if embedded {
        0.0
    } else if vp_w > 0.0 && vp_w <= 640.0 {
        16.0
    } else {
        28.0
    }
}

fn resolve_gallery_width(
    size_el: NodeRef<leptos::html::Div>,
    elem_w: f64,
    vp_w: f64,
    embedded: bool,
) -> f64 {
    let direct_w = size_el
        .get_untracked()
        .map(|el| {
            let cw = el.client_width() as f64;
            let ref_w = if vp_w > 0.0 { vp_w } else { cw };
            (cw - horizontal_padding_for(embedded, ref_w)).max(0.0)
        })
        .filter(|&w| w > 0.0);
    if elem_w > 0.0 {
        match direct_w {
            Some(dw) if (dw - elem_w).abs() > 4.0 => dw,
            _ => elem_w,
        }
    } else if let Some(dw) = direct_w {
        dw
    } else if vp_w > 0.0 {
        (vp_w - horizontal_padding_for(embedded, vp_w)).max(240.0)
    } else {
        0.0
    }
}

#[cfg(feature = "hydrate")]
fn sentinel_near_viewport(sentinel: NodeRef<leptos::html::Div>) -> bool {
    let Some(el) = sentinel.get_untracked() else {
        return false;
    };
    let vh = read_window_height();
    if vh <= 0.0 {
        return true;
    }
    el.get_bounding_client_rect().top() <= vh + 700.0
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResultsParams {
    mode: Mode,
    q: String,
    adv: String,
    sort: AdvancedSort,
    clip_weight: i32,
    img_nonce: String,
    limit: i64,
    seed: i64,
}

fn parse_results_params_with_default(
    get: impl Fn(&str) -> Option<String>,
    embedded: bool,
    default_similar_id: Option<&str>,
) -> ResultsParams {
    let explicit_mode = get("mode").filter(|s| !s.trim().is_empty());
    let (mode, q) = match explicit_mode {
        Some(m) => (Mode::parse(&m), get("q").unwrap_or_default()),
        None if embedded => match default_similar_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(id) => (Mode::Similar, id.to_string()),
            None => (Mode::All, get("q").unwrap_or_default()),
        },
        None => (Mode::All, get("q").unwrap_or_default()),
    };
    ResultsParams {
        mode,
        q,
        adv: get("adv").unwrap_or_default(),
        sort: AdvancedSort::parse(get("sort").as_deref().unwrap_or("relevance")),
        clip_weight: get("cw")
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(50)
            .clamp(5, 95),
        img_nonce: get("img").unwrap_or_default(),
        limit: parse_url_limit(get("limit").as_deref()),
        seed: get("seed").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
    }
}

#[cfg(test)]
fn parse_results_params(get: impl Fn(&str) -> Option<String>) -> ResultsParams {
    parse_results_params_with_default(get, false, None)
}

#[derive(Debug, Clone)]
enum Item {
    Post(PostItem),
    Image(Image),
}

impl Item {
    fn cover_dimensions(&self) -> Option<(i32, i32)> {
        let (w, h) = match self {
            Self::Image(im) => (im.width, im.height),
            Self::Post(post) => post
                .images
                .first()
                .map(|im| (im.width, im.height))
                .or_else(|| post.videos.first().map(|v| (v.width, v.height)))?,
        };
        Some(if w > 0 && h > 0 { (w, h) } else { (16, 9) })
    }
}

/// An item already placed into a column, carrying its rendered pixel box so we can
/// hand the browser a `contain-intrinsic-size` and skip off-screen decode/layout.
#[derive(Debug, Clone)]
struct Placed {
    item: Item,
    w: u32,
    h: u32,
    order: usize,
}

#[derive(Debug, Clone)]
struct Column {
    items: Vec<Placed>,
    width: u32,
    height: u64,
}

#[derive(Clone, Copy)]
struct GalleryLoadCtx {
    params: Memo<ResultsParams>,
    img_query: ImageQuery,
    adv_uploads: AdvancedUploads,
    columns: RwSignal<Vec<Column>>,
    density: RwSignal<Density>,
    size_el: NodeRef<leptos::html::Div>,
    elem_width: Signal<f64>,
    viewport_w: RwSignal<f64>,
    embedded: bool,
    images: StoredValue<Vec<Image>>,
    next_order: StoredValue<usize>,
    has_more: RwSignal<bool>,
    loading: RwSignal<bool>,
    loaded_first: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    req_id: StoredValue<u64>,
}

fn uploads_complete_for_plan(
    plan: &search_types::query::QueryPlan,
    slots: &[UploadedImageSlot],
) -> bool {
    let mut any_ref = false;
    for &idx in plan.upload_pos.iter().chain(plan.upload_neg.iter()) {
        any_ref = true;
        if slots.get(idx).is_none_or(|s| s.b64.is_empty()) {
            return false;
        }
    }
    any_ref && slots.iter().all(|s| !s.b64.is_empty())
}

fn resolve_advanced_upload_csv(
    plan: &search_types::query::QueryPlan,
    img_nonce: &str,
    adv_uploads: AdvancedUploads,
) -> Option<String> {
    if img_nonce.is_empty() {
        return None;
    }
    adv_uploads.0.with_untracked(|u| {
        u.as_ref()
            .filter(|payload| payload.nonce == img_nonce)
            .filter(|payload| uploads_complete_for_plan(plan, &payload.slots))
            .map(|payload| {
                payload
                    .slots
                    .iter()
                    .map(|s| s.b64.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
    })
}

fn is_missing_advanced_uploads(p: &ResultsParams, adv_uploads: AdvancedUploads) -> bool {
    if p.mode != Mode::Advanced || p.adv.trim().is_empty() {
        return false;
    }
    let Ok((_, plan)) = parse_and_compile(&p.adv) else {
        return false;
    };
    if plan.tier != VectorTier::ImageUpload {
        return false;
    }
    if p.img_nonce.is_empty() {
        return true;
    }
    adv_uploads.0.with(|u| {
        u.as_ref().is_none_or(|payload| {
            payload.nonce != p.img_nonce || !uploads_complete_for_plan(&plan, &payload.slots)
        })
    })
}

#[component]
pub fn Results(
    #[prop(default = false)] embedded: bool,
    #[prop(optional)] default_similar_id: Option<Signal<Option<String>>>,
) -> impl IntoView {
    let qmap = use_query_map();
    let pathname = use_location().pathname;

    let params = Memo::new(move |_| {
        let fallback_id = default_similar_id.and_then(|sig| sig.get());
        qmap.with(|m| {
            parse_results_params_with_default(|k| m.get(k), embedded, fallback_id.as_deref())
        })
    });

    // Update browser tab title strictly on the client (never via SSR `<Title>`).
    Effect::new(move |_| {
        if pathname.with(|p| p != "/") {
            return;
        }
        let p = params.get();
        let text = match p.mode {
            Mode::Advanced => {
                let trimmed = p.adv.trim();
                if trimmed.is_empty() {
                    "Advanced Search".to_string()
                } else {
                    format!("Search: {trimmed}")
                }
            }
            Mode::SearchImage => {
                if p.q.is_empty() {
                    "Gallery".to_string()
                } else {
                    "Image search".to_string()
                }
            }
            Mode::Random => {
                if p.q.is_empty() {
                    "Random".to_string()
                } else {
                    format!("Random {}", p.q)
                }
            }
            _ if p.q.trim().is_empty() => "Gallery".to_string(),
            Mode::All => format!("Search: {}", p.q),
            Mode::Author => format!("Author: {}", p.q),
            Mode::Title => format!("Title: {}", p.q),
            Mode::Tag => format!("Tag: {}", p.q),
            Mode::Clip => format!("CLIP: {}", p.q),
            Mode::Similar => format!("Similar to #{}", p.q),
        };
        set_document_title(&text);
    });

    let density = RwSignal::new(Density::Medium);
    let size_el = NodeRef::<leptos::html::Div>::new();
    let UseElementSizeReturn {
        width: elem_width, ..
    } = use_element_size(size_el);
    let viewport_w = RwSignal::new(0.0f64);

    // Restore saved density and measure viewport strictly on the client after
    // hydration so SSR and initial hydrate markup stay 100% identical.
    #[cfg(feature = "hydrate")]
    {
        let _ = use_event_listener(window(), ev::resize, move |_| {
            viewport_w.set(read_window_width());
        });
        Effect::new(move |_| {
            if let Some(saved) = load_density() {
                density.set(saved);
            }
            viewport_w.set(read_window_width());
        });
    }

    let measured_width = Signal::derive(move || {
        let el_w = elem_width.get();
        let vp_w = viewport_w.get();
        resolve_gallery_width(size_el, el_w, vp_w, embedded)
    });
    let debounced_width: Signal<f64> = signal_debounced(measured_width, 120.0);

    // Start identically empty on both SSR and initial hydrate so Leptos `<For>`
    // hydration never mismatches DOM nodes between server and client viewports.
    let columns: RwSignal<Vec<Column>> = RwSignal::new(Vec::new());
    let col_count = Memo::new(move |_| columns.with(Vec::len));
    let col_width_sig =
        Memo::new(move |_| columns.with(|cs| cs.first().map(|c| c.width).unwrap_or(0)));

    // Reflow existing columns when column count changes (from viewport
    // breakpoint changes or switching Compact / Medium / Large). When column
    // count stays constant across resize but `column_width` changes by > 2px,
    // recompute every placed item's `(w, h)` and column height totals in place.
    Effect::new(move || {
        let cur_density = density.get();
        let dw = debounced_width.get();
        let width = if dw > 0.0 { dw } else { measured_width.get() };
        if width <= 0.0 {
            return;
        }
        let vp_w = viewport_w.get_untracked();
        let gap = column_gap_for(if vp_w > 0.0 { vp_w } else { width });
        let column_count = target_column_count(width, cur_density);
        let column_width = column_pixel_width(width, column_count, gap);
        let current_count = columns.with_untracked(Vec::len);
        if current_count == column_count {
            let prev_width = columns.with_untracked(|cs| cs.first().map(|c| c.width).unwrap_or(0));
            if prev_width.abs_diff(column_width) > 2 {
                columns.update(|cs| {
                    resize_columns_in_place(cs, column_width, gap);
                });
            } else {
                columns.update_untracked(|cs| {
                    for c in cs {
                        c.width = column_width;
                    }
                });
            }
            return;
        }
        let mut new = repeat_with(|| Column {
            items: vec![],
            width: column_width,
            height: 0,
        })
        .take(column_count)
        .collect::<Vec<_>>();
        let mut existing: Vec<Placed> = columns
            .get_untracked()
            .into_iter()
            .flat_map(|c| c.items)
            .collect();
        existing.sort_by_key(|p| p.order);
        for placed in existing {
            place_item(&mut new, placed.item, placed.order, gap);
        }
        columns.set(new);
    });

    let offset = RwSignal::new(0i64);
    let has_more = RwSignal::new(true);
    let loading = RwSignal::new(false);
    let loaded_first = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let lightbox: RwSignal<Option<PostItem>> = RwSignal::new(None);
    let viewer: RwSignal<Option<usize>> = RwSignal::new(None);
    let images: StoredValue<Vec<Image>> = StoredValue::new(Vec::new());
    let next_order: StoredValue<usize> = StoredValue::new(0);

    let viewer_open = Memo::new(move |_| viewer.get().is_some());

    let img_query = expect_context::<ImageQuery>();
    let adv_uploads = expect_context::<AdvancedUploads>();
    // Monotonic id used to discard responses from superseded requests: a new
    // search or the next page bumps it, and stale in-flight calls return early.
    let req_id: StoredValue<u64> = StoredValue::new(0);

    let load_ctx = GalleryLoadCtx {
        params,
        img_query,
        adv_uploads,
        columns,
        density,
        size_el,
        elem_width,
        viewport_w,
        embedded,
        images,
        next_order,
        has_more,
        loading,
        loaded_first,
        error,
        req_id,
    };

    Effect::new(move |_| {
        let _ = params.get();
        viewer.set(None);
        lightbox.set(None);
        columns.update(|cs| {
            cs.iter_mut().for_each(|c| {
                c.items.clear();
                c.height = 0;
            })
        });
        images.update_value(|v| v.clear());
        next_order.set_value(0);
        offset.set(0);
        has_more.set(true);
        loaded_first.set(false);
        error.set(None);
        load_page(0, load_ctx);
    });

    let sentinel = NodeRef::<leptos::html::Div>::new();
    let is_intersecting = RwSignal::new(false);
    use_intersection_observer_with_options(
        sentinel,
        move |entries, _| {
            is_intersecting.set(entries.last().is_some_and(|e| e.is_intersecting()));
        },
        UseIntersectionObserverOptions::default().root_margin(INTERSECTION_ROOT_MARGIN),
    );
    Effect::new(move |_| {
        let intersecting = is_intersecting.get();
        let is_loading = loading.get();
        let more = has_more.get();
        let first_done = loaded_first.get();

        if intersecting && !is_loading && more && first_done {
            #[cfg(feature = "hydrate")]
            if !sentinel_near_viewport(sentinel) {
                is_intersecting.set(false);
                return;
            }
            let limit = params.with_untracked(|p| p.limit);
            offset.update(|old| *old += limit);
            let next = offset.get_untracked();
            load_page(next, load_ctx);
        }
    });

    let render_item = move |placed: Placed| -> AnyView {
        let (width, height) = placed
            .item
            .cover_dimensions()
            .expect("placed item has media");
        let init_w = placed.w;
        let init_h = placed.h;
        // Off-screen items skip render/decode; put `content-visibility:auto` on
        // `.gallery-frame` (which already clips via `overflow:hidden`) so
        // `contain:paint` never clips `.gallery-post::before` or tile shadows.
        let cv = move || {
            let w = col_width_sig.get();
            let (rw, rh) = if w > 0 {
                let ratio = f64::from(height) / f64::from(width);
                (w, (ratio * f64::from(w)).round().max(1.0) as u32)
            } else {
                (init_w, init_h)
            };
            format!("content-visibility:auto;contain-intrinsic-size:{rw}px {rh}px;")
        };
        let aspect = format!("aspect-ratio: {width} / {height}");
        match placed.item {
            Item::Post(p) => {
                let post_id = p.id;
                let title = p.title.clone();
                let open_label = format!("Open post: {title}");
                let cover = p.images.first().cloned();
                let img_count = p.image_count.max(p.images.len());
                let video_count = p.video_count.max(p.videos.len());
                let media_badge = match (img_count > 0, video_count > 0) {
                    (true, true) => Some(format!("{img_count}p {video_count}v")),
                    (true, false) => Some(format!("{img_count}p")),
                    (false, true) => Some(format!("{video_count}v")),
                    (false, false) => None,
                };
                view! {
                    <article class="gallery-tile gallery-post group">
                        <div class="gallery-frame" style=cv>
                            <button
                                type="button"
                                aria-label=open_label
                                class="block w-full p-0 border-0 bg-transparent text-left cursor-pointer focus-visible:outline-2 focus-visible:outline-sky-500"
                                on:click=move |_| lightbox.set(Some(p.clone()))
                            >
                                {cover.map(|c| view! {
                                    <img
                                        loading="lazy"
                                        decoding="async"
                                        alt=title.clone()
                                        style=aspect.clone()
                                        class="gallery-img"
                                        src=format!("/images/{}.webp", encode_path(&c.name))
                                    />
                                }.into_any()).unwrap_or_else(|| view! {
                                    <div class="w-full grid place-items-center text-sky-700 text-3xl bg-[#e4f3fc]"
                                        style=aspect>
                                        <span aria-hidden="true">"▶"</span>
                                    </div>
                                }.into_any())}
                            </button>
                            {media_badge.map(|badge| view! {
                                <div class="gallery-top-left">
                                    <span class="gallery-post-pill">
                                        <span class="star" aria-hidden="true">"\u{2605}"</span>
                                        <span>{badge}</span>
                                    </span>
                                </div>
                            })}
                            <div class="gallery-top-right">
                                <LikeButton
                                    kind="post"
                                    target_id=post_id
                                    variant=LikeVariant::Card
                                />
                            </div>
                            <div class="gallery-overlay">
                                <span class="gallery-overlay-meta">{title}</span>
                            </div>
                        </div>
                    </article>
                }
                .into_any()
            }
            Item::Image(im) => {
                let url = format!("/images/{}.webp", encode_path(&im.name));
                let alt = im.name.clone();
                let id = im.id;
                let href = format!("/details/{id}?mode=similar&q={id}&limit=50");
                let click_href = href.clone();
                let nav = use_navigate();
                view! {
                    <article class="gallery-tile group">
                        <div class="gallery-frame" style=cv>
                            <button
                                type="button"
                                aria-label=format!("Zoom image #{id}")
                                class="block w-full p-0 border-0 bg-transparent cursor-zoom-in focus-visible:outline-2 focus-visible:outline-sky-500"
                                on:click=move |_| {
                                    if let Some(i) = images.with_value(|v| v.iter().position(|x| x.id == id)) {
                                        viewer.set(Some(i));
                                    }
                                }
                            >
                                <img
                                    loading="lazy"
                                    decoding="async"
                                    alt=alt
                                    style=aspect
                                    class="gallery-img"
                                    src=url
                                />
                            </button>
                            <div class="gallery-top-right">
                                <LikeButton
                                    kind="image"
                                    target_id=id
                                    variant=LikeVariant::Card
                                />
                            </div>
                            <div class="gallery-overlay">
                                <span class="gallery-overlay-meta">{format!("#{id}")}</span>
                                <a
                                    href=href
                                    title="Open image details & similar"
                                    class="gallery-overlay-link"
                                    on:click=move |ev: ev::MouseEvent| {
                                        ev.stop_propagation();
                                        if !(ev.ctrl_key() || ev.meta_key() || ev.shift_key() || ev.alt_key() || ev.button() != 0) {
                                            ev.prevent_default();
                                            nav(&click_href, NavigateOptions::default());
                                        }
                                    }
                                >
                                    "Details \u{2197}"
                                </a>
                            </div>
                        </div>
                    </article>
                }
                .into_any()
            }
        }
    };

    let error_view = move || {
        error.get().map(|e| {
            view! {
                <div class="w-full max-w-md mx-auto my-4 px-5 py-4 rounded-2xl bg-rose-50/90 ring-1 ring-rose-200
                            text-center text-rose-600 shadow-sm flex flex-col items-center gap-2.5">
                    <p class="text-sm font-medium break-words">{format!("Error: {e}")}</p>
                    <button
                        type="button"
                        class="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-sm font-medium
                               bg-white text-rose-600 ring-1 ring-rose-300 hover:bg-rose-100/70
                               active:scale-95 transition-all cursor-pointer"
                        on:click=move |_| {
                            let cur_offset = offset.get_untracked();
                            load_page(cur_offset, load_ctx);
                        }
                    >
                        "Retry"
                    </button>
                </div>
            }
        })
    };

    let loading_view = move || {
        loading.get().then(|| {
            view! {
                <div class="w-full text-sky-500 p-4 text-center animate-pulse">"Loading\u{2026} \u{1f4ab}"</div>
            }
        })
    };

    let empty_view = move || {
        let is_empty = !loading.get()
            && !has_more.get()
            && error.get().is_none()
            && columns.with(|cs| cs.iter().all(|c| c.items.is_empty()));
        is_empty.then(|| {
            let p = params.get();
            let missing_image_payload = p.mode == Mode::SearchImage
                && img_query
                    .0
                    .with(|payload| payload.as_ref().is_none_or(|x| x.nonce != p.q));
            if missing_image_payload {
                return view! {
                    <div class="w-full max-w-md mx-auto my-10 p-6 rounded-2xl bg-white/80 ring-1 ring-sky-200
                                text-center text-slate-600 shadow-sm shadow-sky-200/40">
                        <div class="text-2xl mb-1">"\u{1F5BC}\u{FE0F}"</div>
                        <p class="font-medium text-sky-800">"Image search isn\u{2019}t stored in the URL"</p>
                        <p class="text-sm text-slate-500 mt-1">
                            "Open Advanced Search above (or drag to crop on a details page) to pick an image and search again."
                        </p>
                    </div>
                }.into_any();
            }
            if is_missing_advanced_uploads(&p, adv_uploads) {
                return view! {
                    <div class="w-full max-w-md mx-auto my-10 p-6 rounded-2xl bg-white/80 ring-1 ring-sky-200
                                text-center text-slate-600 shadow-sm shadow-sky-200/40">
                        <div class="text-2xl mb-1">"\u{1F5BC}\u{FE0F}"</div>
                        <p class="font-medium text-sky-800">"Uploaded images aren\u{2019}t stored in the URL"</p>
                        <p class="text-sm text-slate-500 mt-1">
                            "Open Advanced Search above to re-attach your reference image(s) and run this query again."
                        </p>
                    </div>
                }.into_any();
            }

            let trimmed_q = p.q.trim();
            let trimmed_adv = p.adv.trim();
            let heading = match p.mode {
                Mode::Advanced if trimmed_adv.is_empty() => "No query entered.".to_string(),
                Mode::Advanced => format!("No matches for \u{201c}{trimmed_adv}\u{201d}"),
                _ if trimmed_q.is_empty() => "No items found.".to_string(),
                _ => format!("No matches for \u{201c}{trimmed_q}\u{201d}"),
            };

            let hint = match p.mode {
                Mode::All => "Default search matches post titles and author names. Try shorter keywords, or open Advanced Search for tags, CLIP descriptions, and image similarity.",
                Mode::Author => "Try part of the author\u{2019}s name — suggestions appear as you type.",
                Mode::Title => "Try fewer keywords from the post title, or switch to All to match authors too.",
                Mode::Advanced if trimmed_adv.is_empty() => "Open Advanced Search above to combine tags, authors, titles, CLIP text, and visually similar images.",
                Mode::Advanced => match parse_and_compile(trimmed_adv) {
                    Ok((_, plan)) if plan.meta_filter.is_some() && plan.has_vectors() => {
                        "Try relaxing one of your metadata filters (AND / NOT) or broadening the tag/author conditions."
                    }
                    Ok((_, plan)) if !plan.positive_tags.is_empty() => {
                        "Try fewer AND conditions, check tag spelling or aliases (EN / 中文 / 日本語), or combine alternatives with OR."
                    }
                    _ => "Try fewer AND / NOT conditions, shorter keywords, or broaden your query with OR.",
                },
                Mode::Tag => "Try a shorter keyword, a tag alias (EN / 中文 / 日本語), or describe the scene with CLIP.",
                _ => "Try a different query or open Advanced Search above.",
            };

            let tag_cta_href = (p.mode == Mode::All && !trimmed_q.is_empty()).then(|| {
                let expr = QueryExpr::Term {
                    field: SearchField::Tag,
                    value: trimmed_q.to_string(),
                }
                .format_query();
                format!(
                    "/?mode=advanced&adv={}&limit={}",
                    urlencoding::encode(&expr),
                    p.limit
                )
            });

            let clip_cta_href = if p.mode == Mode::All && !trimmed_q.is_empty() {
                let expr = QueryExpr::Term {
                    field: SearchField::Clip,
                    value: trimmed_q.to_string(),
                }
                .format_query();
                Some(format!(
                    "/?mode=advanced&adv={}&limit={}",
                    urlencoding::encode(&expr),
                    p.limit
                ))
            } else if p.mode == Mode::Tag && !trimmed_q.is_empty() {
                Some(format!(
                    "/?mode=clip&q={}&limit={}",
                    urlencoding::encode(trimmed_q),
                    p.limit
                ))
            } else {
                None
            };

            view! {
                <div class="w-full max-w-md mx-auto my-10 p-6 rounded-2xl bg-white/80 ring-1 ring-sky-200
                            text-center text-slate-600 shadow-sm shadow-sky-200/40">
                    <div class="text-2xl mb-1">"\u{1F50D}"</div>
                    <p class="font-semibold text-sky-800">{heading}</p>
                    <p class="text-sm text-slate-500 mt-1">{hint}</p>
                    {(tag_cta_href.is_some() || clip_cta_href.is_some()).then(|| view! {
                        <div class="flex flex-wrap items-center justify-center gap-2 mt-4">
                            {tag_cta_href.map(|href| view! {
                                <a
                                    href=href
                                    class="inline-flex items-center gap-1 px-4 py-1.5 rounded-full text-sm font-medium
                                           bg-sky-100 text-sky-700 ring-1 ring-sky-200
                                           hover:bg-sky-200/80 transition-all"
                                >
                                    "Search as Tag"
                                </a>
                            })}
                            {clip_cta_href.map(|href| view! {
                                <a
                                    href=href
                                    class="inline-flex items-center gap-1 px-4 py-1.5 rounded-full text-sm font-medium
                                           bg-gradient-to-r from-sky-400 to-blue-500 text-white shadow-sm
                                           hover:from-sky-500 hover:to-blue-600 transition-all"
                                >
                                    "Try CLIP search instead \u{2728}"
                                </a>
                            })}
                        </div>
                    })}
                </div>
            }.into_any()
        })
    };

    let end_view = move || {
        (!loading.get()
            && !has_more.get()
            && error.get().is_none()
            && columns.with(|cs| cs.iter().any(|c| !c.items.is_empty())))
        .then(|| {
            view! {
                <div class="w-full text-sky-400 p-4 text-center">"\u{2014} \u{1f33f} \u{2014}"</div>
            }
        })
    };

    let lightbox_view = move || {
        lightbox
            .get()
            .map(|post| view! { <Lightbox post lightbox/> })
    };

    let viewer_view = move || {
        viewer_open.get().then(|| {
            view! { <Viewer images=images index=viewer /> }
        })
    };

    let wrap_cls = if embedded {
        "gallery-wrap gallery-embedded flex flex-col"
    } else {
        "gallery-wrap flex flex-col"
    };

    let render_density_btn = move |d: Density, label: &'static str| {
        view! {
            <button
                type="button"
                class="gallery-density-btn"
                aria-pressed=move || (density.get() == d).to_string()
                on:click=move |_| {
                    density.set(d);
                    save_density(d);
                }
            >
                {label}
            </button>
        }
    };

    view! {
        <div node_ref=size_el class=wrap_cls>
            {(!embedded).then(|| view! {
                <div class="gallery-toolbar">
                    <div class="gallery-density" role="group" aria-label="Grid size">
                        {render_density_btn(Density::Compact, "Compact")}
                        {render_density_btn(Density::Medium, "Medium")}
                        {render_density_btn(Density::Large, "Large")}
                    </div>
                </div>
            })}
            <div class="gallery-masonry">
                <For
                    each=move || 0..col_count.get()
                    key=|i| *i
                    let(i)
                >
                    <div class="gallery-col">
                        <For
                            each=move || {
                                columns
                                    .with(|cs| cs.get(i).map(|c| c.items.clone()).unwrap_or_default())
                            }
                            key=|placed| {
                                (
                                    placed.order,
                                    match &placed.item {
                                        Item::Post(p) => (0u8, p.id),
                                        Item::Image(im) => (1u8, im.id),
                                    },
                                )
                            }
                            let(placed)
                        >
                            {render_item(placed)}
                        </For>
                    </div>
                </For>
            </div>

            <div node_ref=sentinel class="w-full min-h-10"></div>

            {loading_view}
            {error_view}
            {empty_view}
            {end_view}
            {lightbox_view}
            {viewer_view}
        </div>
    }
}

fn item_rendered_height(item: &Item, col_width: u32) -> Option<u32> {
    let (width, height) = item.cover_dimensions()?;
    let ratio = f64::from(height) / f64::from(width);
    Some((ratio * f64::from(col_width)).round().max(1.0) as u32)
}

/// Recompute every placed item's `(w, h)` and each column's height total in place
/// when column count stays constant across a resize.
fn resize_columns_in_place(columns: &mut [Column], new_width: u32, gap: u32) {
    for col in columns.iter_mut() {
        col.width = new_width;
        let mut total_h = 0u64;
        for placed in &mut col.items {
            if let Some(h) = item_rendered_height(&placed.item, new_width) {
                placed.w = new_width;
                placed.h = h;
                let extra = if matches!(placed.item, Item::Post(_)) {
                    6
                } else {
                    0
                };
                total_h += u64::from(h) + u64::from(gap) + extra;
            }
        }
        col.height = total_h;
    }
}

/// Use the same cover and aspect ratio when loading a page and when reflowing it.
fn place_item(columns: &mut [Column], item: Item, order: usize, gap: u32) {
    let Some(column) = columns.iter_mut().min_by_key(|c| c.height) else {
        return;
    };
    let w = column.width;
    let Some(h) = item_rendered_height(&item, w) else {
        return;
    };
    let extra = if matches!(item, Item::Post(_)) { 6 } else { 0 };
    column.height += u64::from(h) + u64::from(gap) + extra;
    column.items.push(Placed { item, w, h, order });
}

/// Fetch one page of results through the REST search endpoints and merge it into
/// the columns. Superseded requests (a new search or an earlier page) are dropped
/// via `req_id` so their late responses can't corrupt the current view.
fn load_page(offset_val: i64, ctx: GalleryLoadCtx) {
    let p = ctx.params.get_untracked();

    // Claim the newest request id; any in-flight call becomes stale.
    let this_id = ctx.req_id.get_value() + 1;
    ctx.req_id.set_value(this_id);

    ctx.loading.set(true);
    ctx.error.set(None);

    spawn_local(async move {
        let result = match p.mode {
            Mode::Advanced => {
                let trimmed = p.adv.trim();
                if trimmed.is_empty() {
                    if ctx.req_id.try_get_value() == Some(this_id) {
                        ctx.has_more.set(false);
                        ctx.loaded_first.set(true);
                        ctx.loading.set(false);
                    }
                    return;
                }
                let plan = match parse_and_compile(trimmed) {
                    Ok((_, plan)) => plan,
                    Err(e) => {
                        if ctx.req_id.try_get_value() == Some(this_id) {
                            ctx.error.set(Some(e.to_string()));
                            ctx.has_more.set(false);
                            ctx.loaded_first.set(true);
                            ctx.loading.set(false);
                        }
                        return;
                    }
                };
                let adv_query = trimmed.to_string();
                match plan.tier {
                    VectorTier::None => {
                        search_advanced(adv_query, p.sort.as_str().to_string(), p.limit, offset_val)
                            .await
                    }
                    VectorTier::EmbedId => {
                        search_advanced_embed(adv_query, p.limit, offset_val).await
                    }
                    VectorTier::Clip => {
                        search_advanced_clip(adv_query, p.clip_weight, p.limit, offset_val).await
                    }
                    VectorTier::ImageUpload => {
                        match resolve_advanced_upload_csv(&plan, &p.img_nonce, ctx.adv_uploads) {
                            None => {
                                // Uploaded image bytes live only in client memory bound to
                                // their navigation nonce; reloaded URLs degrade cleanly.
                                if ctx.req_id.try_get_value() == Some(this_id) {
                                    ctx.has_more.set(false);
                                    ctx.loaded_first.set(true);
                                    ctx.loading.set(false);
                                }
                                return;
                            }
                            Some(images_csv) => {
                                search_advanced_image(
                                    adv_query,
                                    images_csv,
                                    p.clip_weight,
                                    p.limit,
                                    offset_val,
                                )
                                .await
                            }
                        }
                    }
                }
            }
            Mode::SearchImage => {
                let matching_b64 = ctx.img_query.0.with_untracked(|payload| {
                    payload
                        .as_ref()
                        .filter(|x| x.nonce == p.q)
                        .map(|x| x.b64.clone())
                });
                match matching_b64 {
                    // The image bytes live only in client memory and are bound to their
                    // navigation nonce, so a reloaded or Back-navigated `search_image` URL
                    // degrades cleanly instead of running with stale bytes.
                    None => {
                        if ctx.req_id.try_get_value() == Some(this_id) {
                            ctx.has_more.set(false);
                            ctx.loaded_first.set(true);
                            ctx.loading.set(false);
                        }
                        return;
                    }
                    Some(b64) => search_by_image(b64, p.limit, offset_val).await,
                }
            }
            Mode::Similar => search_similar(p.q, p.limit, offset_val).await,
            Mode::Clip => search_by_desc(p.q, p.limit, offset_val).await,
            _ => {
                search_query(
                    p.mode.as_str().to_string(),
                    p.q,
                    p.seed,
                    p.limit,
                    offset_val,
                )
                .await
            }
        };

        // A newer request started while we were awaiting: discard this response.
        if ctx.req_id.try_get_value() != Some(this_id) {
            return;
        }

        match result {
            Ok(resp) => {
                ctx.images
                    .update_value(|v| v.extend(resp.images.iter().cloned()));
                ctx.columns.update(|cs| {
                    let vp_w = {
                        let v = ctx.viewport_w.get_untracked();
                        #[cfg(feature = "hydrate")]
                        {
                            if v <= 0.0 { read_window_width() } else { v }
                        }
                        #[cfg(not(feature = "hydrate"))]
                        {
                            v
                        }
                    };
                    if cs.is_empty() {
                        let el_w = ctx.elem_width.get_untracked();
                        let w = resolve_gallery_width(ctx.size_el, el_w, vp_w, ctx.embedded);
                        let fallback_w = if w > 0.0 { w } else { 1120.0 };
                        *cs = make_empty_columns(fallback_w, vp_w, ctx.density.get_untracked());
                    }
                    let gap = column_gap_for(vp_w);
                    let mut order = ctx.next_order.get_value();
                    for post in resp.posts {
                        place_item(cs, Item::Post(post), order, gap);
                        order += 1;
                    }
                    for image in resp.images {
                        place_item(cs, Item::Image(image), order, gap);
                        order += 1;
                    }
                    ctx.next_order.set_value(order);
                });
                ctx.has_more.set(resp.has_more);
            }
            Err(e) => {
                ctx.error.set(Some(e.to_string()));
                ctx.has_more.set(false);
            }
        }
        ctx.loaded_first.set(true);
        ctx.loading.set(false);
    });
}

#[cfg(feature = "ssr")]
fn to_server_err(e: impl std::fmt::Display) -> ServerFnError {
    ServerFnError::Response(e.to_string())
}

#[cfg(feature = "ssr")]
fn to_args_err(msg: impl Into<String>) -> ServerFnError {
    ServerFnError::Args(msg.into())
}

#[cfg(feature = "ssr")]
async fn hydrate_posts(
    engine: &search_engine::Engine,
    posts: Vec<search_engine::search_types::Post>,
) -> Result<Vec<PostItem>, ServerFnError> {
    if posts.is_empty() {
        return Ok(Vec::new());
    }
    let post_ids: Vec<i64> = posts.iter().map(|p| p.id).collect();
    let covers = engine
        .post_gallery_covers_by_ids(&post_ids)
        .await
        .map_err(to_server_err)?;
    let mut by_id: std::collections::HashMap<i64, search_engine::PostGalleryCover> =
        covers.into_iter().map(|c| (c.post_id, c)).collect();
    let mut items = Vec::with_capacity(posts.len());
    for post in posts {
        if let Some(cover) = by_id.remove(&post.id) {
            items.push(PostItem {
                id: post.id,
                title: if post.title.is_empty() {
                    cover.title
                } else {
                    post.title
                },
                images: cover.cover_image.into_iter().collect(),
                videos: cover.cover_video.into_iter().collect(),
                image_count: cover.image_count,
                video_count: cover.video_count,
            });
        } else {
            items.push(PostItem {
                id: post.id,
                title: post.title,
                images: Vec::new(),
                videos: Vec::new(),
                image_count: 0,
                video_count: 0,
            });
        }
    }
    Ok(items)
}

#[cfg(feature = "ssr")]
fn decode_single_upload_image(raw: &str, label: &str) -> Result<Vec<u8>, ServerFnError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let max_b64_len = (MAX_UPLOAD_DECODED_BYTES * 4).div_ceil(3);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(to_args_err(format!("{label} is empty")));
    }
    if trimmed.len() > max_b64_len {
        return Err(to_args_err(format!("{label} exceeds 512KB limit")));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map_err(|e| to_args_err(format!("invalid image data in {label}: {e}")))?;
    if bytes.is_empty() {
        return Err(to_args_err(format!("{label} is empty")));
    }
    if bytes.len() > MAX_UPLOAD_DECODED_BYTES {
        return Err(to_args_err(format!("{label} exceeds 512KB limit")));
    }
    Ok(bytes)
}

#[cfg(feature = "ssr")]
fn decode_upload_images(images: &str) -> Result<Vec<Vec<u8>>, ServerFnError> {
    use search_types::query::MAX_UPLOAD_TERMS;

    if images.trim().is_empty() {
        return Err(to_args_err("uploaded image data is missing"));
    }
    let mut raw_slots = Vec::with_capacity(MAX_UPLOAD_TERMS + 1);
    for raw in images.split(',').take(MAX_UPLOAD_TERMS + 1) {
        raw_slots.push(raw);
    }
    if raw_slots.len() > MAX_UPLOAD_TERMS {
        return Err(to_args_err(format!(
            "at most {MAX_UPLOAD_TERMS} uploaded images are allowed"
        )));
    }
    let mut uploads = Vec::with_capacity(raw_slots.len());
    for (idx, raw) in raw_slots.into_iter().enumerate() {
        let label = format!("uploaded image #{idx}");
        uploads.push(decode_single_upload_image(raw, &label)?);
    }
    Ok(uploads)
}

#[cfg(feature = "ssr")]
async fn run_advanced_tier(
    q: String,
    expected_tier: VectorTier,
    uploads: Vec<Vec<u8>>,
    sort: AdvancedSort,
    clip_weight: i32,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::AppState;
    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::{AdvancedSearchRequest, AdvancedSearchResult, Engine};

    let (_, plan) = parse_and_compile(&q).map_err(|e| to_args_err(e.to_string()))?;
    if plan.tier != expected_tier {
        return Err(to_args_err(format!(
            "query tier {:?} is not allowed on this endpoint",
            plan.tier
        )));
    }
    for &idx in plan.upload_pos.iter().chain(plan.upload_neg.iter()) {
        if idx >= uploads.len() {
            return Err(to_args_err(format!(
                "Uploaded image #{idx} is missing — re-upload the image and try again"
            )));
        }
    }

    let limit = limit.clamp(1, MAX_SEARCH_LIMIT);
    let offset = offset.max(0);
    if offset >= MAX_SEARCH_OFFSET {
        return Ok(SearchResponse::default());
    }
    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let req = AdvancedSearchRequest {
        query: q,
        uploads,
        sort,
        clip_weight: (clip_weight.clamp(5, 95) as f32) / 100.0,
        limit,
        offset,
    };

    let res = engine
        .execute_advanced_plan(&plan, &req)
        .await
        .map_err(to_server_err)?;

    match res {
        AdvancedSearchResult::Posts(posts) => {
            let count = posts.len() as i64;
            let items = hydrate_posts(&engine, posts).await?;
            Ok(SearchResponse {
                has_more: count >= limit,
                posts: items,
                images: vec![],
            })
        }
        AdvancedSearchResult::Images(images) => {
            let count = images.len() as i64;
            Ok(SearchResponse {
                has_more: count >= limit,
                posts: vec![],
                images,
            })
        }
    }
}

#[server(endpoint = "search_query")]
async fn search_query(
    mode: String,
    q: String,
    seed: i64,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::AppState;

    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::{Engine, search_types};

    if q.len() > search_types::query::MAX_QUERY_LEN {
        return Err(to_args_err(format!(
            "query exceeds maximum length of {} bytes",
            search_types::query::MAX_QUERY_LEN
        )));
    }

    let mode = Mode::parse(&mode);
    let limit = limit.clamp(1, MAX_SEARCH_LIMIT);
    let offset = offset.max(0);
    let q_trimmed = q.trim();

    if !q_trimmed.is_empty() && matches!(mode, Mode::Similar | Mode::Advanced) {
        return match mode {
            Mode::Similar => Err(to_args_err("similar search moved")),
            Mode::Advanced => Err(to_args_err("advanced search uses dedicated endpoints")),
            _ => unreachable!(),
        };
    }
    if offset >= MAX_SEARCH_OFFSET {
        return Ok(SearchResponse::default());
    }

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    // Random images mode.
    if mode == Mode::Random && q_trimmed == "images" {
        let items = engine
            .random_images_vec(seed, limit, offset)
            .await
            .map_err(to_server_err)?;
        return Ok(SearchResponse {
            has_more: !items.is_empty(),
            posts: vec![],
            images: items,
        });
    }

    // Post-oriented modes: newest (empty query), All (Title OR Author), Author, Title, or Random posts.
    if q_trimmed.is_empty() || matches!(mode, Mode::All | Mode::Author | Mode::Title | Mode::Random)
    {
        let raw_posts: Vec<search_types::Post> = if mode == Mode::Random {
            engine
                .random_posts_vec(seed, limit, offset)
                .await
                .map_err(to_server_err)?
        } else if q_trimmed.is_empty() {
            engine
                .newest_posts_vec(limit, offset)
                .await
                .map_err(to_server_err)?
        } else if mode == Mode::All {
            engine
                .search_posts_by_title_or_author(q_trimmed, limit, offset)
                .await
                .map_err(to_server_err)?
        } else if mode == Mode::Author {
            engine
                .search_posts_by_author_vec(q_trimmed, limit, offset)
                .await
                .map_err(to_server_err)?
        } else {
            engine
                .search_posts_by_title_vec(q_trimmed, limit, offset)
                .await
                .map_err(to_server_err)?
        };

        let count = raw_posts.len() as i64;
        let items = hydrate_posts(&engine, raw_posts).await?;
        // Random pages skip ids with no row, so `count < limit` is normal; keep
        // paging (endless reshuffle) until a whole window resolves to nothing.
        let has_more = if mode == Mode::Random {
            count > 0
        } else {
            count >= limit
        };
        return Ok(SearchResponse {
            has_more,
            posts: items,
            images: vec![],
        });
    }

    // Legacy image-oriented modes.
    let items = match mode {
        Mode::Tag => engine
            .search_images_by_tag_vec(q_trimmed, limit, offset)
            .await
            .map_err(to_server_err)?,
        _ => return Ok(SearchResponse::default()),
    };

    Ok(SearchResponse {
        has_more: (items.len() as i64) >= limit,
        posts: vec![],
        images: items,
    })
}

#[server(endpoint = "search_advanced")]
async fn search_advanced(
    q: String,
    sort: String,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    run_advanced_tier(
        q,
        VectorTier::None,
        Vec::new(),
        AdvancedSort::parse(&sort),
        50,
        limit,
        offset,
    )
    .await
}

#[server(endpoint = "search_advanced_embed")]
async fn search_advanced_embed(
    q: String,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    run_advanced_tier(
        q,
        VectorTier::EmbedId,
        Vec::new(),
        AdvancedSort::Relevance,
        50,
        limit,
        offset,
    )
    .await
}

#[server(endpoint = "search_advanced_clip")]
async fn search_advanced_clip(
    q: String,
    clip_weight: i32,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    run_advanced_tier(
        q,
        VectorTier::Clip,
        Vec::new(),
        AdvancedSort::Relevance,
        clip_weight,
        limit,
        offset,
    )
    .await
}

#[server(endpoint = "search_advanced_image")]
async fn search_advanced_image(
    q: String,
    images: String,
    clip_weight: i32,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    let uploads = decode_upload_images(&images)?;
    run_advanced_tier(
        q,
        VectorTier::ImageUpload,
        uploads,
        AdvancedSort::Relevance,
        clip_weight,
        limit,
        offset,
    )
    .await
}

#[server(endpoint = "search_by_image")]
async fn search_by_image(
    image: String,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::AppState;

    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    let limit = limit.clamp(1, MAX_SEARCH_LIMIT);
    let offset = offset.max(0);

    let bytes = decode_single_upload_image(&image, "uploaded image")?;
    if offset >= MAX_SEARCH_OFFSET {
        return Ok(SearchResponse::default());
    }

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let items = engine
        .search_dinov3_upload_vec(bytes, limit, offset)
        .await
        .map_err(to_server_err)?;

    Ok(SearchResponse {
        has_more: (items.len() as i64) >= limit,
        posts: vec![],
        images: items,
    })
}

#[server(endpoint = "search_similar")]
async fn search_similar(
    q: String,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::AppState;

    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    let id = q
        .trim()
        .parse::<i64>()
        .map_err(|e| to_args_err(e.to_string()))?;
    let limit = limit.clamp(1, MAX_SEARCH_LIMIT);
    let offset = offset.max(0);
    if offset >= MAX_SEARCH_OFFSET {
        return Ok(SearchResponse::default());
    }

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let details = engine.image_details(id).await.map_err(to_server_err)?;
    let exclude_post_id = details.post.as_ref().map(|p| p.id);
    let items = engine
        .search_similar_images(id, exclude_post_id, limit, offset)
        .await
        .map_err(to_server_err)?;

    Ok(SearchResponse {
        has_more: (items.len() as i64) >= limit,
        posts: vec![],
        images: items,
    })
}

#[server(endpoint = "search_by_desc")]
async fn search_by_desc(
    q: String,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::AppState;

    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    if q.len() > search_types::query::MAX_QUERY_LEN {
        return Err(to_args_err(format!(
            "query exceeds maximum length of {} bytes",
            search_types::query::MAX_QUERY_LEN
        )));
    }
    let q_trimmed = q.trim();
    if q_trimmed.is_empty() {
        return Ok(SearchResponse::default());
    }

    let limit = limit.clamp(1, MAX_SEARCH_LIMIT);
    let offset = offset.max(0);
    if offset >= MAX_SEARCH_OFFSET {
        return Ok(SearchResponse::default());
    }

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let items = engine
        .search_clip_cached_vec(q_trimmed, limit, offset)
        .await
        .map_err(to_server_err)?;

    Ok(SearchResponse {
        has_more: (items.len() as i64) >= limit,
        posts: vec![],
        images: items,
    })
}

#[cfg(feature = "ssr")]
#[test]
fn pinned_paths() {
    use leptos::server_fn::ServerFn;
    assert_eq!(SearchQuery::PATH, "/api/search_query");
    assert_eq!(SearchSimilar::PATH, "/api/search_similar");
    assert_eq!(SearchByImage::PATH, "/api/search_by_image");
    assert_eq!(SearchByDesc::PATH, "/api/search_by_desc");
    assert_eq!(SearchAdvanced::PATH, "/api/search_advanced");
    assert_eq!(SearchAdvancedEmbed::PATH, "/api/search_advanced_embed");
    assert_eq!(SearchAdvancedClip::PATH, "/api/search_advanced_clip");
    assert_eq!(SearchAdvancedImage::PATH, "/api/search_advanced_image");
}

#[cfg(feature = "ssr")]
#[test]
fn decode_upload_images_validates_slots_and_limits() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let a = URL_SAFE_NO_PAD.encode(b"img-one");
    let b = URL_SAFE_NO_PAD.encode(b"img-two");
    let decoded = decode_upload_images(&format!("{a},{b}")).expect("valid two slots");
    assert_eq!(decoded, vec![b"img-one".to_vec(), b"img-two".to_vec()]);

    assert!(decode_upload_images("").is_err());
    assert!(decode_upload_images(&format!("{a},")).is_err());
    assert!(decode_upload_images("!!!not-base64!!!").is_err());
    // More than 4 slots rejected (including huge comma-spam without unbounded allocation).
    assert!(decode_upload_images(&format!("{a},{a},{a},{a},{a}")).is_err());
    let comma_spam = format!("{a}{}", ",x".repeat(10_000));
    assert!(decode_upload_images(&comma_spam).is_err());
    // Oversized (> 512KB) rejected for both multi-slot and single-image endpoints.
    let huge = URL_SAFE_NO_PAD.encode(vec![0u8; MAX_UPLOAD_DECODED_BYTES + 1]);
    assert!(decode_upload_images(&huge).is_err());
    assert!(decode_single_upload_image(&huge, "uploaded image").is_err());
    assert!(decode_single_upload_image("", "uploaded image").is_err());
    assert_eq!(
        decode_single_upload_image(&a, "uploaded image").expect("valid single image"),
        b"img-one".to_vec()
    );
}

#[test]
fn video_only_post_keeps_its_place_at_different_widths() {
    let post = Item::Post(PostItem {
        id: 42,
        title: "Video album".into(),
        images: vec![],
        videos: vec![search_types::Video {
            width: 0,
            height: 0,
            ..Default::default()
        }],
        image_count: 0,
        video_count: 1,
    });
    for width in [160, 320] {
        let mut columns = [Column {
            items: vec![],
            width,
            height: 0,
        }];
        place_item(&mut columns, post.clone(), 0, COLUMN_GAP);
        assert_eq!(columns[0].items.len(), 1);
        assert_eq!(columns[0].items[0].h, width * 9 / 16);
    }
}

#[test]
fn responsive_gap_and_resize_recomputes_placed_boxes_and_heights() {
    assert_eq!(column_gap_for(375.0), 8);
    assert_eq!(column_gap_for(640.0), 8);
    assert_eq!(column_gap_for(641.0), 12);
    // 3 compact cols at 359px with 8px gap -> (359 - 16) / 3 = 114px (not clamped to 120).
    assert_eq!(column_pixel_width(359.0, 3, 8), 114);
    // Very narrow fallback floors at 80px.
    assert_eq!(column_pixel_width(150.0, 3, 8), 80);

    let img = Item::Image(Image {
        id: 7,
        name: "a".into(),
        width: 1000,
        height: 2000,
    });
    let mut columns = [Column {
        items: vec![],
        width: 200,
        height: 0,
    }];
    place_item(&mut columns, img, 0, COLUMN_GAP);
    assert_eq!(columns[0].items[0].w, 200);
    assert_eq!(columns[0].items[0].h, 400);
    assert_eq!(columns[0].height, 412);

    resize_columns_in_place(&mut columns, 300, COLUMN_GAP);
    assert_eq!(columns[0].width, 300);
    assert_eq!(columns[0].items[0].w, 300);
    assert_eq!(columns[0].items[0].h, 600);
    assert_eq!(columns[0].height, 612);
}

#[test]
fn uploads_complete_validates_referenced_slots() {
    let slot = UploadedImageSlot {
        filename: "a.webp".into(),
        b64: "AAAA".into(),
        preview_url: "data:image/webp;base64,AAAA".into(),
    };
    let empty_slot = UploadedImageSlot {
        filename: "empty.webp".into(),
        b64: String::new(),
        preview_url: String::new(),
    };
    let (_, plan_two) = parse_and_compile("upload:0 AND NOT upload:1").unwrap();
    assert!(!uploads_complete_for_plan(&plan_two, &[]));
    assert!(!uploads_complete_for_plan(
        &plan_two,
        std::slice::from_ref(&slot)
    ));
    assert!(!uploads_complete_for_plan(
        &plan_two,
        &[slot.clone(), empty_slot]
    ));
    assert!(uploads_complete_for_plan(&plan_two, &[slot.clone(), slot]));
}

#[test]
fn masonry_column_count_breakpoints_are_distinct_across_widths() {
    assert_eq!(target_column_count(0.0, Density::Medium), 1);

    // Narrow phone (320px viewport minus 16px horizontal padding = 304px inner width).
    assert_eq!(target_column_count(304.0, Density::Compact), 2);
    assert_eq!(target_column_count(304.0, Density::Medium), 2);
    assert_eq!(target_column_count(304.0, Density::Large), 1);
    assert_eq!(target_column_count(320.0, Density::Compact), 2);
    assert_eq!(target_column_count(320.0, Density::Medium), 2);
    assert_eq!(target_column_count(320.0, Density::Large), 1);

    // Standard phones (375px viewport minus 16px horizontal padding = 359px inner width): all 3 densities distinct.
    assert_eq!(target_column_count(359.0, Density::Compact), 3);
    assert_eq!(target_column_count(359.0, Density::Medium), 2);
    assert_eq!(target_column_count(359.0, Density::Large), 1);
    assert_eq!(target_column_count(375.0, Density::Compact), 3);
    assert_eq!(target_column_count(375.0, Density::Medium), 2);
    assert_eq!(target_column_count(375.0, Density::Large), 1);
    assert_eq!(target_column_count(540.0, Density::Compact), 3);
    assert_eq!(target_column_count(540.0, Density::Medium), 2);
    assert_eq!(target_column_count(540.0, Density::Large), 1);

    // Desktop & laptop widths.
    assert_eq!(target_column_count(1120.0, Density::Compact), 6);
    assert_eq!(target_column_count(1120.0, Density::Medium), 4);
    assert_eq!(target_column_count(1120.0, Density::Large), 3);
    assert_eq!(target_column_count(1440.0, Density::Compact), 7);
    assert_eq!(target_column_count(1440.0, Density::Medium), 5);
    assert_eq!(target_column_count(1440.0, Density::Large), 3);

    // Ultrawide scaling (up to 12 / 8 / 6).
    assert_eq!(target_column_count(2400.0, Density::Compact), 12);
    assert_eq!(target_column_count(2400.0, Density::Medium), 8);
    assert_eq!(target_column_count(2400.0, Density::Large), 5);
    assert_eq!(target_column_count(3440.0, Density::Compact), 12);
    assert_eq!(target_column_count(3440.0, Density::Medium), 8);
    assert_eq!(target_column_count(3440.0, Density::Large), 6);
}

#[test]
fn parse_results_params_defaults_and_clamps() {
    let empty = parse_results_params(|_| None);
    assert_eq!(empty.mode, Mode::All);
    assert_eq!(empty.q, "");
    assert_eq!(empty.adv, "");
    assert_eq!(empty.sort, AdvancedSort::Relevance);
    assert_eq!(empty.clip_weight, 50);
    assert_eq!(empty.img_nonce, "");
    assert_eq!(empty.limit, 50);
    assert_eq!(empty.seed, 0);

    let adv = parse_results_params(|k| match k {
        "mode" => Some("advanced".into()),
        "adv" => Some("tag:maid AND clip:\"cafe\"".into()),
        "sort" => Some("newest".into()),
        "cw" => Some("120".into()),
        "img" => Some("n42".into()),
        "limit" => Some("0".into()),
        "seed" => Some("99".into()),
        _ => None,
    });
    assert_eq!(adv.mode, Mode::Advanced);
    assert_eq!(adv.adv, "tag:maid AND clip:\"cafe\"");
    assert_eq!(adv.sort, AdvancedSort::Newest);
    assert_eq!(adv.clip_weight, 95);
    assert_eq!(adv.img_nonce, "n42");
    assert_eq!(adv.limit, crate::types::DEFAULT_SEARCH_LIMIT);
    assert_eq!(adv.seed, 99);

    let capped = parse_results_params(|k| match k {
        "limit" => Some("999999".into()),
        _ => None,
    });
    assert_eq!(capped.limit, MAX_SEARCH_LIMIT);

    // Direct `/details/:id` without `?mode=similar` defaults to Similar for `:id`.
    let embedded_default = parse_results_params_with_default(|_| None, true, Some("2286979"));
    assert_eq!(embedded_default.mode, Mode::Similar);
    assert_eq!(embedded_default.q, "2286979");

    // Explicit crop-search mode overrides embedded default.
    let embedded_crop = parse_results_params_with_default(
        |k| match k {
            "mode" => Some("search_image".into()),
            "q" => Some("nonce1".into()),
            _ => None,
        },
        true,
        Some("2286979"),
    );
    assert_eq!(embedded_crop.mode, Mode::SearchImage);
    assert_eq!(embedded_crop.q, "nonce1");
}
