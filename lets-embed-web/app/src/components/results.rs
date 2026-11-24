use std::iter::repeat_with;

#[cfg(any(feature = "ssr", test))]
use crate::types::MAX_SEARCH_LIMIT;
use crate::{
    components::{BlurredMediaCard, LikeButton, LikeVariant, lightbox::Lightbox, viewer::Viewer},
    types::{
        AdvancedUploads, DEFAULT_SEARCH_LIMIT, GalleryDensity as Density, GalleryDensityState,
        ImageQuery, Mode, PostItem, SafetyUiState, SearchResponse, UploadedImageSlot,
        handle_mask_unlock, mask_to_ui, parse_url_limit, parse_url_min_similarity,
    },
    util::{public_origin, set_document_title},
};

use leptos::{ev, prelude::*, task::spawn_local};
use leptos_meta::{Link, Meta, Title};
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
use lets_embed_ui::{
    ContentMaskCard, DensityPicker, GalleryMask, MinSimilaritySlider, ReportTargetKind,
};
use search_types::{
    MediaKind, ProjectedImage, ProjectedVideo,
    query::{AdvancedSort, QueryExpr, SearchField, VectorTier, parse_and_compile},
};

const COLUMN_GAP: u32 = 12;
const MOBILE_COLUMN_GAP: u32 = 8;
const INTERSECTION_ROOT_MARGIN: &str = "600px 0px";
#[cfg(feature = "ssr")]
const MAX_SEARCH_OFFSET: i64 = 10_000;
#[cfg(feature = "ssr")]
const MAX_UPLOAD_DECODED_BYTES: usize = 512 * 1024;

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
    /// Optional cosine similarity cutoff encoded in basis points (`0..=1000`).
    min_sim_bps: Option<u16>,
    img_nonce: String,
    limit: i64,
    seed: i64,
}

impl ResultsParams {
    fn min_similarity(&self) -> Option<f32> {
        self.min_sim_bps.map(|b| f32::from(b) / 1000.0)
    }
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
    let min_sim_bps = parse_url_min_similarity(get("min_sim").as_deref())
        .map(|v| (v * 1000.0).round().clamp(0.0, 1000.0) as u16);
    ResultsParams {
        mode,
        q,
        adv: get("adv").unwrap_or_default(),
        sort: AdvancedSort::parse(get("sort").as_deref().unwrap_or("relevance")),
        min_sim_bps,
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
    Image(ProjectedImage),
}

impl Item {
    fn cover_dimensions(&self) -> Option<(i32, i32)> {
        let (w, h) = match self {
            Self::Image(im) => (im.width(), im.height()),
            Self::Post(post) => post
                .images
                .first()
                .map(|im| (im.width(), im.height()))
                .or_else(|| post.videos.first().map(|v| (v.width(), v.height())))?,
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
    embedded_min_sim: Option<(RwSignal<f32>, RwSignal<bool>)>,
    images: StoredValue<Vec<ProjectedImage>>,
    next_order: StoredValue<usize>,
    has_more: RwSignal<bool>,
    loading: RwSignal<bool>,
    loaded_first: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    req_id: StoredValue<u64>,
}

impl GalleryLoadCtx {
    fn effective_min_similarity(&self, p: &ResultsParams) -> Option<f32> {
        if let Some((slider, touched)) = self.embedded_min_sim
            && touched.get_untracked()
        {
            return Some(slider.get_untracked().clamp(0.0, 1.0));
        }
        p.min_similarity()
    }
}

fn uploads_complete_for_plan(
    plan: &search_types::query::QueryPlan,
    slots: &[UploadedImageSlot],
) -> bool {
    let mut any_ref = false;
    for clause in plan.upload_pos.iter().chain(plan.upload_neg.iter()) {
        any_ref = true;
        if slots.get(clause.slot).is_none_or(|s| s.b64.is_empty()) {
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
    #[prop(optional)] heading: Option<&'static str>,
) -> impl IntoView {
    let qmap = use_query_map();
    let pathname = use_location().pathname;
    let safety = use_context::<SafetyUiState>();

    let params = Memo::new(move |_| {
        let fallback_id = default_similar_id.and_then(|sig| sig.get());
        qmap.with(|m| {
            parse_results_params_with_default(|k| m.get(k), embedded, fallback_id.as_deref())
        })
    });

    // Embedded `/details/:id` Similar floating bar similarity cutoff slider.
    let sim_slider = RwSignal::new(0.0_f32);
    let sim_slider_touched = RwSignal::new(false);
    if embedded && let Some(s) = safety {
        Effect::new(move |_| {
            let pol_default = s.default_dinov3_min.get();
            if !sim_slider_touched.get_untracked() && (sim_slider.get_untracked() - pol_default).abs() > 0.001 {
                sim_slider.set(pol_default);
            }
        });
    }
    let sim_slider_sig: Signal<f32> = Signal::derive(move || sim_slider.get());
    let debounced_sim_slider: Signal<f32> = signal_debounced(sim_slider_sig, 220.0);

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

    let density = use_context::<GalleryDensityState>().unwrap_or_default().0;
    let size_el = NodeRef::<leptos::html::Div>::new();
    let UseElementSizeReturn {
        width: elem_width, ..
    } = use_element_size(size_el);
    let viewport_w = RwSignal::new(0.0f64);

    #[cfg(feature = "hydrate")]
    {
        let _ = use_event_listener(window(), ev::resize, move |_| {
            viewport_w.set(read_window_width());
        });
        Effect::new(move |_| {
            viewport_w.set(read_window_width());
        });
    }

    let measured_width = Signal::derive(move || {
        let el_w = elem_width.get();
        let vp_w = viewport_w.get();
        resolve_gallery_width(size_el, el_w, vp_w, embedded)
    });
    let debounced_width: Signal<f64> = signal_debounced(measured_width, 120.0);

    let columns: RwSignal<Vec<Column>> = RwSignal::new(Vec::new());
    let col_count = Memo::new(move |_| columns.with(Vec::len));
    let col_width_sig =
        Memo::new(move |_| columns.with(|cs| cs.first().map(|c| c.width).unwrap_or(0)));

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
    let images: StoredValue<Vec<ProjectedImage>> = StoredValue::new(Vec::new());
    let next_order: StoredValue<usize> = StoredValue::new(0);

    let viewer_open = Memo::new(move |_| viewer.get().is_some());

    let img_query = expect_context::<ImageQuery>();
    let adv_uploads = expect_context::<AdvancedUploads>();
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
        embedded_min_sim: embedded.then_some((sim_slider, sim_slider_touched)),
        images,
        next_order,
        has_more,
        loading,
        loaded_first,
        error,
        req_id,
    };

    // Invalidation epoch watcher: immediately discard in-flight fetches, close modals, and clear media.
    if let Some(s) = safety {
        let last_inv = StoredValue::new(s.invalidation_epoch.get_untracked());
        Effect::new(move |_| {
            let cur = s.invalidation_epoch.get();
            if cur != last_inv.get_value() {
                last_inv.set_value(cur);
                req_id.set_value(req_id.get_value().wrapping_add(1));
                lets_embed_ui::browser::wipe_media_elements_in(None);
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
                loading.set(false);
            }
        });
    }

    let initial_is_default_home = !embedded
        && pathname.with_untracked(|p| p == "/")
        && params.with_untracked(|p| {
            p.mode == Mode::All
                && p.q.trim().is_empty()
                && p.adv.trim().is_empty()
                && p.limit == DEFAULT_SEARCH_LIMIT
        });
    let ssr_home = initial_is_default_home.then(|| {
        OnceResource::new(async move {
            search_query("all".to_string(), String::new(), 0, DEFAULT_SEARCH_LIMIT, 0)
                .await
                .ok()
        })
    });
    let ssr_consumed: StoredValue<bool> = StoredValue::new(false);

    Effect::new(move |_| {
        let p = params.get();
        let reload_epoch = safety.map(|s| s.reload_epoch.get()).unwrap_or(0);
        let embedded_sim_trigger = if embedded {
            (debounced_sim_slider.get() * 1000.0).round() as i32
        } else {
            0
        };
        let _ = embedded_sim_trigger;

        let is_default_home = !embedded
            && reload_epoch == 0
            && p.mode == Mode::All
            && p.q.trim().is_empty()
            && p.adv.trim().is_empty()
            && p.limit == DEFAULT_SEARCH_LIMIT;
        if is_default_home
            && !ssr_consumed.get_value()
            && let Some(res) = ssr_home
        {
            match res.get() {
                None => {
                    loading.set(true);
                    return;
                }
                Some(Some(resp)) if !resp.posts.is_empty() => {
                    ssr_consumed.set_value(true);
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
                    error.set(None);
                    apply_page_response(resp, load_ctx);
                    loaded_first.set(true);
                    loading.set(false);
                    return;
                }
                Some(_) => {
                    ssr_consumed.set_value(true);
                }
            }
        } else if ssr_home.is_some() {
            ssr_consumed.set_value(true);
        }

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

    let on_unlock = Callback::new(move |mask: GalleryMask| {
        handle_mask_unlock(&mask, safety);
    });

    let render_item = move |placed: Placed| -> AnyView {
        let (width, height) = placed
            .item
            .cover_dimensions()
            .expect("placed item has media");
        let init_w = placed.w;
        let init_h = placed.h;
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
                let cover_video = p.videos.first().cloned();
                let cover_details_href = cover
                    .as_ref()
                    .filter(|c| c.is_bypassable_or_clear())
                    .map(|c| format!("/details/{}", c.id()));
                let nav = use_navigate();
                let img_count = p.image_count.max(p.images.len());
                let video_count = p.video_count.max(p.videos.len());
                let media_badge = match (img_count > 0, video_count > 0) {
                    (true, true) => Some(format!("{img_count}p {video_count}v")),
                    (true, false) => Some(format!("{img_count}p")),
                    (false, true) => Some(format!("{video_count}v")),
                    (false, false) => None,
                };

                let post_for_open = p.clone();
                let post_for_spoiler = p.clone();
                let cover_view = match cover {
                    Some(ProjectedImage::Clear { url, .. }) => view! {
                        <button
                            type="button"
                            aria-label=open_label
                            class="block w-full p-0 border-0 bg-transparent text-left cursor-pointer focus-visible:outline-2 focus-visible:outline-sky-500"
                            on:click=move |_| lightbox.set(Some(post_for_open.clone()))
                        >
                            <img
                                loading="lazy"
                                decoding="async"
                                alt=title.clone()
                                style=aspect.clone()
                                class="gallery-img"
                                src=url
                            />
                        </button>
                    }
                    .into_any(),
                    Some(ProjectedImage::Blurred {
                        id,
                        preview_url,
                        can_click_reveal,
                        policy_rev,
                        width: sw,
                        height: sh,
                        label,
                        preset,
                        ..
                    }) => {
                        let open_cb = Callback::new(move |()| {
                            lightbox.set(Some(post_for_spoiler.clone()));
                        });
                        let alt = title.clone();
                        view! {
                            <BlurredMediaCard
                                kind=MediaKind::Image
                                asset_id=id
                                width=sw
                                height=sh
                                preview_url=preview_url.unwrap_or_default()
                                can_click_reveal=can_click_reveal
                                policy_rev=policy_rev
                                label=label
                                preset=preset
                                alt=alt
                                compact=true
                                on_open=open_cb
                            />
                        }
                        .into_any()
                    }
                    Some(ProjectedImage::Placeholder {
                        width: lw,
                        height: lh,
                        mask,
                        ..
                    }) => {
                        let ui_mask = mask_to_ui(&mask);
                        view! {
                            <div
                                class="w-full cursor-pointer"
                                on:click=move |_| lightbox.set(Some(post_for_open.clone()))
                            >
                                <ContentMaskCard
                                    mask=ui_mask
                                    dimensions=(lw, lh)
                                    compact=true
                                    on_unlock_click=on_unlock
                                />
                            </div>
                        }
                        .into_any()
                    }
                    None => match cover_video {
                        Some(ProjectedVideo::Placeholder {
                            width: vw,
                            height: vh,
                            mask,
                            ..
                        }) => {
                            let ui_mask = mask_to_ui(&mask);
                            view! {
                                <div
                                    class="w-full cursor-pointer"
                                    on:click=move |_| lightbox.set(Some(post_for_open.clone()))
                                >
                                    <ContentMaskCard
                                        mask=ui_mask
                                        dimensions=(vw, vh)
                                        compact=true
                                        on_unlock_click=on_unlock
                                    />
                                </div>
                            }
                            .into_any()
                        }
                        Some(ProjectedVideo::Blurred {
                            id: vid_id,
                            preview_url,
                            can_click_reveal,
                            policy_rev,
                            label,
                            preset,
                            width: vw,
                            height: vh,
                            ..
                        }) => {
                            let open_cb = Callback::new(move |()| {
                                lightbox.set(Some(post_for_spoiler.clone()));
                            });
                            view! {
                                <div
                                    class="w-full cursor-pointer"
                                    on:click=move |_| lightbox.set(Some(post_for_open.clone()))
                                >
                                    <BlurredMediaCard
                                        kind=MediaKind::Video
                                        asset_id=vid_id
                                        width=vw
                                        height=vh
                                        preview_url=preview_url.unwrap_or_default()
                                        can_click_reveal=can_click_reveal
                                        policy_rev=policy_rev
                                        label=label
                                        preset=preset
                                        alt=title.clone()
                                        compact=true
                                        on_open=open_cb
                                    />
                                </div>
                            }
                            .into_any()
                        }
                        _ => view! {
                            <button
                                type="button"
                                aria-label=open_label
                                class="block w-full p-0 border-0 bg-transparent text-left cursor-pointer focus-visible:outline-2 focus-visible:outline-sky-500"
                                on:click=move |_| lightbox.set(Some(post_for_open.clone()))
                            >
                                <div class="w-full grid place-items-center text-sky-700 text-3xl bg-[#e4f3fc]"
                                    style=aspect>
                                    <span aria-hidden="true">"▶"</span>
                                </div>
                            </button>
                        }
                        .into_any(),
                    },
                };

                view! {
                    <article class="gallery-tile gallery-post group">
                        <div class="gallery-frame" style=cv>
                            {cover_view}
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
                                {cover_details_href.map(|href| {
                                    let click_href = href.clone();
                                    view! {
                                        <a
                                            href=href
                                            title="Open cover details & similar"
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
                                    }
                                })}
                            </div>
                        </div>
                    </article>
                }
                .into_any()
            }
            Item::Image(im) => {
                let id = im.id();
                let show_details_link = im.is_bypassable_or_clear();
                let href = format!("/details/{id}");
                let click_href = href.clone();
                let nav = use_navigate();

                let media_view = match im {
                    ProjectedImage::Clear { url, name, .. } => {
                        let alt = name
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| format!("Image #{id}"));
                        view! {
                            <button
                                type="button"
                                aria-label=format!("Zoom image #{id}")
                                class="block w-full p-0 border-0 bg-transparent cursor-zoom-in focus-visible:outline-2 focus-visible:outline-sky-500"
                                on:click=move |_| {
                                    if let Some(i) = images.with_value(|v| v.iter().position(|x| x.id() == id)) {
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
                        }
                        .into_any()
                    }
                    ProjectedImage::Blurred {
                        preview_url,
                        can_click_reveal,
                        policy_rev,
                        width: sw,
                        height: sh,
                        label,
                        preset,
                        ..
                    } => {
                        let open_cb = Callback::new(move |()| {
                            if let Some(i) = images.with_value(|v| v.iter().position(|x| x.id() == id)) {
                                viewer.set(Some(i));
                            }
                        });
                        let alt = format!("Image #{id}");
                        view! {
                            <BlurredMediaCard
                                kind=MediaKind::Image
                                asset_id=id
                                width=sw
                                height=sh
                                preview_url=preview_url.unwrap_or_default()
                                can_click_reveal=can_click_reveal
                                policy_rev=policy_rev
                                label=label
                                preset=preset
                                alt=alt
                                compact=true
                                on_open=open_cb
                            />
                        }
                        .into_any()
                    }
                    ProjectedImage::Placeholder {
                        width: lw,
                        height: lh,
                        mask,
                        ..
                    } => {
                        let ui_mask = mask_to_ui(&mask);
                        view! {
                            <ContentMaskCard
                                mask=ui_mask
                                dimensions=(lw, lh)
                                compact=true
                                on_unlock_click=on_unlock
                            />
                        }
                        .into_any()
                    }
                };

                view! {
                    <article class="gallery-tile group">
                        <div class="gallery-frame" style=cv>
                            {media_view}
                            <div class="gallery-top-right">
                                <LikeButton
                                    kind="image"
                                    target_id=id
                                    variant=LikeVariant::Card
                                />
                            </div>
                            <div class="gallery-overlay">
                                <span class="gallery-overlay-meta">{format!("#{id}")}</span>
                                <div class="flex items-center gap-1">
                                    {move || safety.filter(|s| s.is_managed.get()).map(|s| view! {
                                        <button
                                            type="button"
                                            title="Report image"
                                            class="gallery-overlay-link bg-slate-900/60 hover:bg-rose-500 cursor-pointer"
                                            on:click=move |ev: ev::MouseEvent| {
                                                ev.stop_propagation();
                                                s.open_report(
                                                    ReportTargetKind::Image,
                                                    id,
                                                    format!("Image #{id}"),
                                                );
                                            }
                                        >
                                            "Report"
                                        </button>
                                    })}
                                    {show_details_link.then(|| view! {
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
                                    })}
                                </div>
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
            let lower = e.to_ascii_lowercase();
            let is_locked = lower.contains("locked") || lower.contains("403");
            if is_locked {
                return view! {
                    <div class="web-results-locked w-full max-w-md mx-auto my-6 px-5 py-4 rounded-2xl bg-sky-50/90 ring-1 ring-sky-200
                                text-center text-slate-600 shadow-sm flex flex-col items-center gap-2">
                        <p class="text-sm font-medium text-sky-800">
                            "Visual similarity is unavailable while this item is locked under your current safety settings."
                        </p>
                    </div>
                }
                .into_any();
            }
            let is_allowance = embedded
                && (lower.contains("402")
                    || lower.contains("payment")
                    || lower.contains("allowance")
                    || lower.contains("out of points")
                    || lower.contains("/user/upgrade"));
            if is_allowance {
                return view! {
                    <div class="web-results-allowance w-full max-w-md mx-auto my-6 px-5 py-4 rounded-2xl bg-sky-50/90 ring-1 ring-sky-200
                                text-center text-slate-600 shadow-sm flex flex-col items-center gap-2.5">
                        <p class="text-sm font-medium text-sky-800">
                            "Sign in or upgrade to explore visually similar images."
                        </p>
                        <a
                            href="/user/upgrade"
                            rel="external"
                            class="web-results-upgrade-btn inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-sm font-medium
                                   bg-gradient-to-r from-sky-400 to-blue-500 text-white shadow-sm
                                   hover:from-sky-500 hover:to-blue-600 transition-all"
                        >
                            "Continue exploring \u{2192}"
                        </a>
                    </div>
                }
                .into_any();
            }
            view! {
                <div class="web-results-error w-full max-w-md mx-auto my-4 px-5 py-4 rounded-2xl bg-rose-50/90 ring-1 ring-rose-200
                            text-center text-rose-600 shadow-sm flex flex-col items-center gap-2.5">
                    <p class="text-sm font-medium break-words">{format!("Error: {e}")}</p>
                    <button
                        type="button"
                        class="web-results-retry-btn inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-sm font-medium
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
            .into_any()
        })
    };

    let loading_view = move || {
        loading.get().then(|| {
            view! {
                <div class="web-results-loading w-full text-sky-500 p-4 text-center animate-pulse">"Loading\u{2026} \u{1f4ab}"</div>
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
                        "Try relaxing one of your metadata filters (AND / NOT) or lowering the minimum similarity threshold."
                    }
                    Ok((_, plan)) if !plan.positive_tags.is_empty() => {
                        "Try fewer AND conditions, check tag spelling or aliases (EN / 中文 / 日本語), or combine alternatives with OR."
                    }
                    _ => "Try fewer AND / NOT conditions, shorter keywords, or broaden your query with OR.",
                },
                Mode::Tag => "Try a shorter keyword, a tag alias (EN / 中文 / 日本語), or describe the scene with CLIP.",
                _ => "Try a different query, lower the similarity cutoff, or open Advanced Search above.",
            };

            let tag_cta_href = (p.mode == Mode::All && !trimmed_q.is_empty()).then(|| {
                let expr = QueryExpr::Term {
                    field: SearchField::Tag,
                    value: trimmed_q.to_string(),
                    threshold: None,
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
                    threshold: None,
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
                <div class="web-results-empty w-full max-w-md mx-auto my-10 p-6 rounded-2xl bg-white/80 ring-1 ring-sky-200
                            text-center text-slate-600 shadow-sm shadow-sky-200/40">
                    <div class="text-2xl mb-1">"\u{1F50D}"</div>
                    <p class="font-semibold text-sky-800">{heading}</p>
                    <p class="text-sm text-slate-500 mt-1">{hint}</p>
                    {(tag_cta_href.is_some() || clip_cta_href.is_some()).then(|| view! {
                        <div class="web-results-empty-actions flex flex-wrap items-center justify-center gap-2 mt-4">
                            {tag_cta_href.map(|href| view! {
                                <a
                                    href=href
                                    class="web-results-cta-tag inline-flex items-center gap-1 px-4 py-1.5 rounded-full text-sm font-medium
                                           bg-sky-100 text-sky-700 ring-1 ring-sky-200
                                           hover:bg-sky-200/80 transition-all"
                                >
                                    "Search as Tag"
                                </a>
                            })}
                            {clip_cta_href.map(|href| view! {
                                <a
                                    href=href
                                    class="web-results-cta-clip inline-flex items-center gap-1 px-4 py-1.5 rounded-full text-sm font-medium
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
                <div class="web-results-end w-full text-sky-400 p-4 text-center">"\u{2014} \u{1f33f} \u{2014}"</div>
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
        "web-results-wrap web-results-wrap--embedded gallery-wrap gallery-embedded flex flex-col"
    } else {
        "web-results-wrap gallery-wrap flex flex-col"
    };

    let has_masonry_items =
        Memo::new(move |_| columns.with(|cs| cs.iter().any(|c| !c.items.is_empty())));
    let is_ephemeral_search = Memo::new(move |_| {
        params.with(|p| p.mode != Mode::All || !p.q.trim().is_empty() || !p.adv.trim().is_empty())
    });
    let home_canonical = (!embedded)
        .then(|| public_origin().map(|o| format!("{o}/")))
        .flatten();

    let ssr_fallback_view = ssr_home.map(|res| {
        view! {
            <Transition fallback=|| ()>
                {move || {
                    if has_masonry_items.get() {
                        return None;
                    }
                    let resp = res.get().flatten()?;
                    if resp.posts.is_empty() {
                        return None;
                    }
                    Some(view! {
                        <div class="gallery-ssr-grid">
                            {resp.posts.into_iter().map(|p| {
                                let title = p.title;
                                let cover = p.images.first().cloned();
                                let cover_video = p.videos.first().cloned();
                                let img_count = p.image_count.max(p.images.len());
                                let video_count = p.video_count.max(p.videos.len());
                                let media_badge = match (img_count > 0, video_count > 0) {
                                    (true, true) => Some(format!("{img_count}p {video_count}v")),
                                    (true, false) => Some(format!("{img_count}p")),
                                    (false, true) => Some(format!("{video_count}v")),
                                    (false, false) => None,
                                };
                                let (w, h) = cover
                                    .as_ref()
                                    .map(|c| (c.width(), c.height()))
                                    .or_else(|| cover_video.as_ref().map(|v| (v.width(), v.height())))
                                    .filter(|&(w, h)| w > 0 && h > 0)
                                    .unwrap_or((4, 3));
                                let aspect = format!("aspect-ratio: {w} / {h}");
                                let details_href = cover
                                    .as_ref()
                                    .filter(|c| c.is_bypassable_or_clear())
                                    .map(|c| format!("/details/{}", c.id()));
                                let cover_view = match cover {
                                    Some(ProjectedImage::Clear { url, .. }) => {
                                        let href = details_href.clone().unwrap_or_default();
                                        view! {
                                            <a href=href class="block w-full">
                                                <img
                                                    loading="lazy"
                                                    decoding="async"
                                                    alt=title.clone()
                                                    style=aspect.clone()
                                                    class="gallery-img"
                                                    src=url
                                                />
                                            </a>
                                        }
                                        .into_any()
                                    }
                                    Some(ProjectedImage::Blurred {
                                        id,
                                        preview_url,
                                        can_click_reveal,
                                        policy_rev,
                                        width: sw,
                                        height: sh,
                                        label,
                                        preset,
                                        ..
                                    }) => view! {
                                        <BlurredMediaCard
                                            kind=MediaKind::Image
                                            asset_id=id
                                            width=sw
                                            height=sh
                                            preview_url=preview_url.unwrap_or_default()
                                            can_click_reveal=can_click_reveal
                                            policy_rev=policy_rev
                                            label=label
                                            preset=preset
                                            alt=title.clone()
                                            compact=true
                                        />
                                    }
                                    .into_any(),
                                    Some(ProjectedImage::Placeholder { mask, .. }) => view! {
                                        <ContentMaskCard
                                            mask=mask_to_ui(&mask)
                                            dimensions=(w, h)
                                            compact=true
                                            on_unlock_click=on_unlock
                                        />
                                    }
                                    .into_any(),
                                    None => match cover_video {
                                        Some(ProjectedVideo::Placeholder { mask, .. }) => view! {
                                            <ContentMaskCard
                                                mask=mask_to_ui(&mask)
                                                dimensions=(w, h)
                                                compact=true
                                                on_unlock_click=on_unlock
                                            />
                                        }
                                        .into_any(),
                                        Some(ProjectedVideo::Blurred {
                                            id: vid_id,
                                            preview_url,
                                            can_click_reveal,
                                            policy_rev,
                                            label,
                                            preset,
                                            ..
                                        }) => view! {
                                            <BlurredMediaCard
                                                kind=MediaKind::Video
                                                asset_id=vid_id
                                                width=w
                                                height=h
                                                preview_url=preview_url.unwrap_or_default()
                                                can_click_reveal=can_click_reveal
                                                policy_rev=policy_rev
                                                label=label
                                                preset=preset
                                                alt=title.clone()
                                                compact=true
                                            />
                                        }
                                        .into_any(),
                                        _ => view! {
                                            <div class="w-full grid place-items-center text-sky-700 text-3xl bg-[#e4f3fc]"
                                                style=aspect>
                                                <span aria-hidden="true">"▶"</span>
                                            </div>
                                        }
                                        .into_any(),
                                    },
                                };
                                view! {
                                    <article class="gallery-tile gallery-post group">
                                        <div class="gallery-frame">
                                            {cover_view}
                                            {media_badge.map(|badge| view! {
                                                <div class="gallery-top-left">
                                                    <span class="gallery-post-pill">
                                                        <span class="star" aria-hidden="true">"\u{2605}"</span>
                                                        <span>{badge}</span>
                                                    </span>
                                                </div>
                                            })}
                                            <div class="gallery-overlay">
                                                <span class="gallery-overlay-meta">{title}</span>
                                                {details_href.map(|href| view! {
                                                    <a href=href class="gallery-overlay-link">
                                                        "Details \u{2197}"
                                                    </a>
                                                })}
                                            </div>
                                        </div>
                                    </article>
                                }
                            }).collect_view()}
                        </div>
                    })
                }}
            </Transition>
        }
    });

    view! {
        {(!embedded).then(|| view! {
            <Title text="Let's Embed"/>
            <Meta name="description" content=crate::SITE_DESCRIPTION/>
            <Meta property="og:type" content="website"/>
            <Meta property="og:title" content="Let's Embed"/>
            <Meta property="og:description" content=crate::SITE_DESCRIPTION/>
            <h1 class="sr-only">"Let\u{2019}s Embed \u{2014} Visual & Semantic Image Gallery"</h1>
            {home_canonical.clone().map(|url| view! {
                <Link rel="canonical" href=url.clone()/>
                <Meta property="og:url" content=url/>
            })}
            {move || is_ephemeral_search.get().then(|| view! {
                <Meta name="robots" content="noindex, follow"/>
            })}
        })}
        <div node_ref=size_el class=wrap_cls>
            {embedded.then(|| view! {
                <div class="web-results-toolbar gallery-floating-bar flex-wrap gap-2">
                    {heading.map(|h| view! {
                        <h2 class="web-results-heading text-sky-700 text-base sm:text-lg md:text-xl font-semibold leading-tight m-0">
                            {h}
                        </h2>
                    })}
                    <div class="web-results-toolbar-controls ml-auto flex flex-wrap items-center gap-2 sm:gap-3">
                        <MinSimilaritySlider
                            value=sim_slider
                            label="Min sim"
                            model_badge="DINOv3"
                            compact=true
                            on_change=Callback::new(move |_: f32| {
                                sim_slider_touched.set(true);
                            })
                        />
                        <DensityPicker density=density persist=true />
                    </div>
                </div>
            })}
            {ssr_fallback_view}
            <div class="web-results-masonry gallery-masonry">
                <For
                    each=move || 0..col_count.get()
                    key=|i| *i
                    let(i)
                >
                    <div class="web-results-col gallery-col">
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
                                        Item::Image(im) => (1u8, im.id()),
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

            <div node_ref=sentinel class="web-results-sentinel w-full min-h-10"></div>

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

fn load_page(offset_val: i64, ctx: GalleryLoadCtx) {
    let p = ctx.params.get_untracked();
    let min_sim = ctx.effective_min_similarity(&p);

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
                        search_advanced_embed(adv_query, p.limit, offset_val, min_sim).await
                    }
                    VectorTier::Clip => {
                        search_advanced_clip(adv_query, p.limit, offset_val, min_sim).await
                    }
                    VectorTier::ImageUpload => {
                        match resolve_advanced_upload_csv(&plan, &p.img_nonce, ctx.adv_uploads) {
                            None => {
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
                                    p.limit,
                                    offset_val,
                                    min_sim,
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
                    None => {
                        if ctx.req_id.try_get_value() == Some(this_id) {
                            ctx.has_more.set(false);
                            ctx.loaded_first.set(true);
                            ctx.loading.set(false);
                        }
                        return;
                    }
                    Some(b64) => search_by_image(b64, p.limit, offset_val, min_sim).await,
                }
            }
            Mode::Similar => search_similar(p.q, p.limit, offset_val, min_sim).await,
            Mode::Clip => search_by_desc(p.q, p.limit, offset_val, min_sim).await,
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

        if ctx.req_id.try_get_value() != Some(this_id) {
            return;
        }

        match result {
            Ok(resp) => {
                apply_page_response(resp, ctx);
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

fn apply_page_response(resp: SearchResponse, ctx: GalleryLoadCtx) {
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

#[cfg(feature = "ssr")]
fn to_server_err(e: impl std::fmt::Display) -> ServerFnError {
    tracing::error!("gallery server error: {e}");
    ServerFnError::Response("Request failed. Please try again.".to_string())
}

#[cfg(feature = "ssr")]
fn map_search_err(err: anyhow::Error) -> ServerFnError {
    if err.downcast_ref::<search_engine::SeedLockedError>().is_some() {
        if let Some(resp) = use_context::<leptos_axum::ResponseOptions>() {
            resp.set_status(axum::http::StatusCode::FORBIDDEN);
        }
        return ServerFnError::Response(
            "Seed image is locked under current safety settings".to_string(),
        );
    }
    tracing::error!("search server error: {err:#}");
    ServerFnError::Response("Search failed. Please try again.".to_string())
}

#[cfg(feature = "ssr")]
fn to_args_err(msg: impl Into<String>) -> ServerFnError {
    ServerFnError::Args(msg.into())
}

#[cfg(feature = "ssr")]
async fn hydrate_posts(
    engine: &search_engine::Engine,
    ctx: &crate::state::RequestSafetyContext,
    posts: Vec<search_engine::search_types::Post>,
) -> Result<Vec<PostItem>, ServerFnError> {
    use std::collections::HashMap;

    if posts.is_empty() {
        return Ok(Vec::new());
    }
    let post_ids: Vec<i64> = posts.iter().map(|p| p.id).collect();
    let covers = engine
        .post_gallery_covers_by_ids(&post_ids)
        .await
        .map_err(to_server_err)?;

    let cover_images: Vec<search_types::Image> = covers
        .iter()
        .filter_map(|c| c.cover_image.clone())
        .collect();
    let cover_videos: Vec<search_types::Video> = covers
        .iter()
        .filter_map(|c| c.cover_video.clone())
        .collect();

    let (proj_imgs, proj_vids) = tokio::try_join!(
        engine.project_images(&cover_images, &ctx.policy, &ctx.caller, &ctx.signer),
        engine.project_videos(&cover_videos, &ctx.policy, &ctx.caller, &ctx.signer),
    )
    .map_err(to_server_err)?;

    let mut proj_img_map: HashMap<i64, ProjectedImage> =
        proj_imgs.into_iter().map(|im| (im.id(), im)).collect();
    let mut proj_vid_map: HashMap<i64, ProjectedVideo> =
        proj_vids.into_iter().map(|v| (v.id(), v)).collect();
    let mut by_id: HashMap<i64, search_engine::PostGalleryCover> =
        covers.into_iter().map(|c| (c.post_id, c)).collect();

    // Withhold post titles whenever safety policy is active and a post has ZERO displayable
    // (Clear or user-bypassable) media — hard-blocked (e.g. Extreme / Gore & Illegal) and
    // unclassified posts redact to `"Restricted Post #<id>"`, while bypassable posts (e.g.
    // NSFW / Sensitive) retain their real titles for visitors and search indexing.
    let extra_displayable_posts = if ctx.policy.is_enabled() {
        let need_check: Vec<i64> = posts
            .iter()
            .filter_map(|post| {
                let has_displayable_cover = by_id.get(&post.id).is_some_and(|c| {
                    c.cover_image
                        .as_ref()
                        .and_then(|im| proj_img_map.get(&im.id))
                        .is_some_and(ProjectedImage::is_bypassable_or_clear)
                        || c.cover_video
                            .as_ref()
                            .and_then(|v| proj_vid_map.get(&v.id))
                            .is_some_and(ProjectedVideo::is_bypassable_or_clear)
                });
                (!has_displayable_cover).then_some(post.id)
            })
            .collect();
        if need_check.is_empty() {
            std::collections::HashSet::new()
        } else {
            engine
                .posts_with_any_displayable_media(&need_check, &ctx.policy, &ctx.caller)
                .await
                .map_err(to_server_err)?
        }
    } else {
        std::collections::HashSet::new()
    };

    let mut items = Vec::with_capacity(posts.len());
    for post in posts {
        if let Some(cover) = by_id.remove(&post.id) {
            let images: Vec<ProjectedImage> = cover
                .cover_image
                .and_then(|im| proj_img_map.remove(&im.id))
                .into_iter()
                .collect();
            let videos: Vec<ProjectedVideo> = cover
                .cover_video
                .and_then(|v| proj_vid_map.remove(&v.id))
                .into_iter()
                .collect();
            let show_title = !ctx.policy.is_enabled()
                || images.iter().any(ProjectedImage::is_bypassable_or_clear)
                || videos.iter().any(ProjectedVideo::is_bypassable_or_clear)
                || extra_displayable_posts.contains(&post.id);
            let title = if show_title {
                if post.title.is_empty() {
                    cover.title
                } else {
                    post.title
                }
            } else {
                format!("Restricted Post #{}", post.id)
            };
            items.push(PostItem {
                id: post.id,
                title,
                images,
                videos,
                image_count: cover.image_count,
                video_count: cover.video_count,
            });
        } else {
            let show_title =
                !ctx.policy.is_enabled() || extra_displayable_posts.contains(&post.id);
            items.push(PostItem {
                id: post.id,
                title: if show_title {
                    post.title
                } else {
                    format!("Restricted Post #{}", post.id)
                },
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
#[allow(clippy::too_many_arguments)]
async fn run_advanced_tier(
    q: String,
    expected_tier: VectorTier,
    uploads: Vec<Vec<u8>>,
    sort: AdvancedSort,
    min_similarity: Option<f32>,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::{AppState, RequestSafetyContext};
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
    for clause in plan.upload_pos.iter().chain(plan.upload_neg.iter()) {
        let idx = clause.slot;
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
    let Some(state) = use_context::<AppState>() else {
        return Ok(SearchResponse::default());
    };
    let ctx = RequestSafetyContext::from_leptos_context(&state)?;
    let sf = ctx.safety_filter();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let req = AdvancedSearchRequest {
        query: q,
        uploads,
        sort,
        clip_min_similarity: ctx.effective_siglip2_min(min_similarity),
        dino_min_similarity: ctx.effective_dinov3_min(min_similarity),
        limit,
        offset,
    };

    let res = engine
        .execute_advanced_plan_with_safety(&plan, &req, Some(&sf))
        .await
        .map_err(map_search_err)?;

    match res {
        AdvancedSearchResult::Posts(posts) => {
            let count = posts.len() as i64;
            let items = hydrate_posts(&engine, &ctx, posts).await?;
            Ok(SearchResponse {
                has_more: count >= limit,
                posts: items,
                images: vec![],
            })
        }
        AdvancedSearchResult::Images(raw_images) => {
            let count = raw_images.len() as i64;
            let images = engine
                .project_images(&raw_images, &ctx.policy, &ctx.caller, &ctx.signer)
                .await
                .map_err(to_server_err)?;
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
    use crate::state::{AppState, RequestSafetyContext};
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

    let Some(state) = use_context::<AppState>() else {
        return Ok(SearchResponse::default());
    };
    let ctx = RequestSafetyContext::from_leptos_context(&state)?;
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    // Random images mode (browse feed: project each image so locked placeholders appear cleanly).
    if mode == Mode::Random && q_trimmed == "images" {
        let raw_items = engine
            .random_images_vec(seed, limit, offset)
            .await
            .map_err(to_server_err)?;
        let has_more = !raw_items.is_empty();
        let images = engine
            .project_images(&raw_items, &ctx.policy, &ctx.caller, &ctx.signer)
            .await
            .map_err(to_server_err)?;
        return Ok(SearchResponse {
            has_more,
            posts: vec![],
            images,
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
        let items = hydrate_posts(&engine, &ctx, raw_posts).await?;
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

    // Legacy image-oriented modes (anti-oracle safety filter applied).
    let sf = ctx.safety_filter();
    let raw_items = match mode {
        Mode::Tag => engine
            .search_images_by_tag_vec_with_safety(q_trimmed, limit, offset, Some(&sf))
            .await
            .map_err(to_server_err)?,
        _ => return Ok(SearchResponse::default()),
    };
    let count = raw_items.len() as i64;
    let images = engine
        .project_images(&raw_items, &ctx.policy, &ctx.caller, &ctx.signer)
        .await
        .map_err(to_server_err)?;

    Ok(SearchResponse {
        has_more: count >= limit,
        posts: vec![],
        images,
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
        None,
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
    min_similarity: Option<f32>,
) -> Result<SearchResponse, ServerFnError> {
    run_advanced_tier(
        q,
        VectorTier::EmbedId,
        Vec::new(),
        AdvancedSort::Relevance,
        min_similarity,
        limit,
        offset,
    )
    .await
}

#[server(endpoint = "search_advanced_clip")]
async fn search_advanced_clip(
    q: String,
    limit: i64,
    offset: i64,
    min_similarity: Option<f32>,
) -> Result<SearchResponse, ServerFnError> {
    run_advanced_tier(
        q,
        VectorTier::Clip,
        Vec::new(),
        AdvancedSort::Relevance,
        min_similarity,
        limit,
        offset,
    )
    .await
}

#[server(endpoint = "search_advanced_image")]
async fn search_advanced_image(
    q: String,
    images: String,
    limit: i64,
    offset: i64,
    min_similarity: Option<f32>,
) -> Result<SearchResponse, ServerFnError> {
    let uploads = decode_upload_images(&images)?;
    run_advanced_tier(
        q,
        VectorTier::ImageUpload,
        uploads,
        AdvancedSort::Relevance,
        min_similarity,
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
    min_similarity: Option<f32>,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::{AppState, RequestSafetyContext};
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

    let Some(state) = use_context::<AppState>() else {
        return Ok(SearchResponse::default());
    };
    let ctx = RequestSafetyContext::from_leptos_context(&state)?;
    let sf = ctx.safety_filter();
    let eff_min = ctx.effective_dinov3_min(min_similarity);
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let raw_items = engine
        .search_dinov3_upload_vec(bytes, limit, offset, eff_min, Some(&sf))
        .await
        .map_err(map_search_err)?;
    let count = raw_items.len() as i64;
    let images = engine
        .project_images(&raw_items, &ctx.policy, &ctx.caller, &ctx.signer)
        .await
        .map_err(to_server_err)?;

    Ok(SearchResponse {
        has_more: count >= limit,
        posts: vec![],
        images,
    })
}

#[server(endpoint = "search_similar")]
async fn search_similar(
    q: String,
    limit: i64,
    offset: i64,
    min_similarity: Option<f32>,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::{AppState, RequestSafetyContext};
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

    let Some(state) = use_context::<AppState>() else {
        return Ok(SearchResponse::default());
    };
    let ctx = RequestSafetyContext::from_leptos_context(&state)?;
    let sf = ctx.safety_filter();
    let eff_min = ctx.effective_dinov3_min(min_similarity);
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    // Single-snapshot seed authorization + own-post lookup + embedding read + similar search.
    let raw_items = engine
        .search_similar_images_for_seed(id, limit, offset, eff_min, Some(&sf))
        .await
        .map_err(map_search_err)?;
    let count = raw_items.len() as i64;
    let images = engine
        .project_images(&raw_items, &ctx.policy, &ctx.caller, &ctx.signer)
        .await
        .map_err(to_server_err)?;

    Ok(SearchResponse {
        has_more: count >= limit,
        posts: vec![],
        images,
    })
}

#[server(endpoint = "search_by_desc")]
async fn search_by_desc(
    q: String,
    limit: i64,
    offset: i64,
    min_similarity: Option<f32>,
) -> Result<SearchResponse, ServerFnError> {
    use crate::state::{AppState, RequestSafetyContext};
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

    let Some(state) = use_context::<AppState>() else {
        return Ok(SearchResponse::default());
    };
    let ctx = RequestSafetyContext::from_leptos_context(&state)?;
    let sf = ctx.safety_filter();
    let eff_min = ctx.effective_siglip2_min(min_similarity);
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    let raw_items = engine
        .search_clip_cached_vec(q_trimmed, limit, offset, eff_min, Some(&sf))
        .await
        .map_err(map_search_err)?;
    let count = raw_items.len() as i64;
    let images = engine
        .project_images(&raw_items, &ctx.policy, &ctx.caller, &ctx.signer)
        .await
        .map_err(to_server_err)?;

    Ok(SearchResponse {
        has_more: count >= limit,
        posts: vec![],
        images,
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
    assert!(decode_upload_images(&format!("{a},{a},{a},{a},{a}")).is_err());
    let comma_spam = format!("{a}{}", ",x".repeat(10_000));
    assert!(decode_upload_images(&comma_spam).is_err());
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
        videos: vec![ProjectedVideo::Clear {
            id: 1,
            url: "/videos/v.mp4".into(),
            name: Some("v.mp4".into()),
            width: 0,
            height: 0,
            duration: 10,
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
    assert_eq!(column_pixel_width(359.0, 3, 8), 114);
    assert_eq!(column_pixel_width(150.0, 3, 8), 80);

    let img = Item::Image(ProjectedImage::Clear {
        id: 7,
        url: "/images/a.webp".into(),
        name: Some("a".into()),
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

    assert_eq!(target_column_count(304.0, Density::Compact), 2);
    assert_eq!(target_column_count(304.0, Density::Medium), 2);
    assert_eq!(target_column_count(304.0, Density::Large), 1);
    assert_eq!(target_column_count(320.0, Density::Compact), 2);
    assert_eq!(target_column_count(320.0, Density::Medium), 2);
    assert_eq!(target_column_count(320.0, Density::Large), 1);

    assert_eq!(target_column_count(359.0, Density::Compact), 3);
    assert_eq!(target_column_count(359.0, Density::Medium), 2);
    assert_eq!(target_column_count(359.0, Density::Large), 1);
    assert_eq!(target_column_count(375.0, Density::Compact), 3);
    assert_eq!(target_column_count(375.0, Density::Medium), 2);
    assert_eq!(target_column_count(375.0, Density::Large), 1);
    assert_eq!(target_column_count(540.0, Density::Compact), 3);
    assert_eq!(target_column_count(540.0, Density::Medium), 2);
    assert_eq!(target_column_count(540.0, Density::Large), 1);

    assert_eq!(target_column_count(1120.0, Density::Compact), 6);
    assert_eq!(target_column_count(1120.0, Density::Medium), 4);
    assert_eq!(target_column_count(1120.0, Density::Large), 3);
    assert_eq!(target_column_count(1440.0, Density::Compact), 7);
    assert_eq!(target_column_count(1440.0, Density::Medium), 5);
    assert_eq!(target_column_count(1440.0, Density::Large), 3);

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
    assert_eq!(empty.min_sim_bps, None);
    assert_eq!(empty.img_nonce, "");
    assert_eq!(empty.limit, 50);
    assert_eq!(empty.seed, 0);

    let adv = parse_results_params(|k| match k {
        "mode" => Some("advanced".into()),
        "adv" => Some("tag:maid AND clip:\"cafe\"".into()),
        "sort" => Some("newest".into()),
        "min_sim" => Some("0.45".into()),
        "img" => Some("n42".into()),
        "limit" => Some("0".into()),
        "seed" => Some("99".into()),
        _ => None,
    });
    assert_eq!(adv.mode, Mode::Advanced);
    assert_eq!(adv.adv, "tag:maid AND clip:\"cafe\"");
    assert_eq!(adv.sort, AdvancedSort::Newest);
    assert_eq!(adv.min_sim_bps, Some(450));
    assert_eq!(adv.min_similarity(), Some(0.45));
    assert_eq!(adv.img_nonce, "n42");
    assert_eq!(adv.limit, crate::types::DEFAULT_SEARCH_LIMIT);
    assert_eq!(adv.seed, 99);

    let capped = parse_results_params(|k| match k {
        "limit" => Some("999999".into()),
        _ => None,
    });
    assert_eq!(capped.limit, MAX_SEARCH_LIMIT);

    let embedded_default = parse_results_params_with_default(|_| None, true, Some("2286979"));
    assert_eq!(embedded_default.mode, Mode::Similar);
    assert_eq!(embedded_default.q, "2286979");

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
