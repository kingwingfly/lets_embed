use crate::components::{
    AccountWidget, AdvancedSearchPanel, BackToTop, SelectOption, SelectVariant, SkySelect,
};
use crate::types::{
    DEFAULT_SEARCH_LIMIT, GalleryDensityState, Mode, SafetyUiState, parse_url_limit,
    parse_url_min_similarity,
};
use js_sys::futures::JsFuture;
use leptos::{prelude::*, task::spawn_local};
use leptos_router::{
    NavigateOptions,
    components::Outlet,
    hooks::{use_location, use_navigate, use_query_map},
};
#[cfg(feature = "hydrate")]
use leptos_use_element_size::{UseElementSizeReturn, use_element_size};
use leptos_use_signal_debounce_throttle::signal_debounced;
use lets_embed_ui::{DensityPicker, NoticeBanner, NoticeContent, NoticeTone, SafeModeToggle};
use search_types::query::{AdvancedSort, QueryExpr, ResultKind, SearchField, parse_and_compile};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast as _, JsValue};
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, ImageBitmap};

pub(crate) const DEFAULT_LIMIT: usize = DEFAULT_SEARCH_LIMIT as usize;
const MAX_SUGGEST_LEN: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchSuggestion {
    /// Canonical value to search when picked (English tag name, author name, or post title).
    pub value: String,
    /// Suggestion kind: `"author"`, `"title"`, `"tag"`, or `""`.
    #[serde(default)]
    pub kind: String,
    /// Optional multilingual aliases/translations (populated for `Tag`).
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// Parsed URL search parameters on the main gallery route (`/`), matching `Results`.
#[derive(Clone, Debug, PartialEq)]
pub struct UrlSearchState {
    pub mode: Mode,
    pub q: String,
    pub adv: String,
    pub sort: AdvancedSort,
    pub clip_weight: i32,
    pub min_similarity: Option<f32>,
    pub img_nonce: String,
    pub limit: usize,
}

impl Default for UrlSearchState {
    fn default() -> Self {
        Self {
            mode: Mode::All,
            q: String::new(),
            adv: String::new(),
            sort: AdvancedSort::Relevance,
            clip_weight: 50,
            min_similarity: None,
            img_nonce: String::new(),
            limit: DEFAULT_LIMIT,
        }
    }
}

#[cfg(feature = "hydrate")]
async fn persist_safe_mode(enabled: bool) -> bool {
    use web_sys::{Headers, RequestInit, Response};

    let Some(win) = web_sys::window() else {
        return false;
    };
    let opts = RequestInit::new();
    opts.set_method("POST");
    if let Ok(headers) = Headers::new() {
        let _ = headers.set("Content-Type", "application/json");
        let _ = headers.set(site_access::USER_CSRF_HEADER, "1");
        opts.set_headers(&headers);
    }
    // Omit `enabled_switchers` so `user_worker` preserves the user's saved switchers
    // while toggling only `safe_mode`.
    let body = serde_json::json!({ "safe_mode": enabled }).to_string();
    opts.set_body(&JsValue::from_str(&body));
    match JsFuture::from(win.fetch_with_str_and_init("/user/api/preferences", &opts)).await {
        Ok(val) => val
            .dyn_into::<Response>()
            .map(|r| r.ok())
            .unwrap_or(false),
        Err(_) => false,
    }
}

#[cfg(not(feature = "hydrate"))]
async fn persist_safe_mode(_enabled: bool) -> bool {
    false
}

#[cfg(feature = "hydrate")]
fn broadcast_safe_mode_synced(enabled: bool) {
    if let Ok(ch) = web_sys::BroadcastChannel::new(lets_embed_ui::browser::SAFETY_CHANNEL_NAME) {
        let payload = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &payload,
            &JsValue::from_str("type"),
            &JsValue::from_str("safe_mode_synced"),
        );
        let _ = js_sys::Reflect::set(
            &payload,
            &JsValue::from_str("enabled"),
            &JsValue::from_bool(enabled),
        );
        let _ = ch.post_message(&payload);
        ch.close();
    }
}

#[cfg(not(feature = "hydrate"))]
fn broadcast_safe_mode_synced(_enabled: bool) {}

/// Summary descriptor rendered in the Active Advanced Query Summary Strip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActiveQuerySummary {
    pub result_kind: ResultKind,
    pub query_text: String,
    pub meta_badge: Option<String>,
}

pub(crate) fn should_suggest_field(field: SearchField, q: &str) -> bool {
    if q.len() > MAX_SUGGEST_LEN {
        return false;
    }
    let trimmed = q.trim();
    if trimmed.is_empty() {
        return false;
    }
    let has_non_ascii = !trimmed.is_ascii();
    match field {
        SearchField::All | SearchField::Title | SearchField::Author | SearchField::Tag => {
            has_non_ascii || trimmed.chars().count() >= 2
        }
        SearchField::Clip | SearchField::Dino | SearchField::Upload => false,
    }
}

fn should_suggest(mode: Mode, q: &str) -> bool {
    if q.len() > MAX_SUGGEST_LEN {
        return false;
    }
    let trimmed = q.trim();
    if trimmed.is_empty() {
        return false;
    }
    let has_non_ascii = !trimmed.is_ascii();
    match mode {
        Mode::All | Mode::Author | Mode::Title | Mode::Tag => {
            has_non_ascii || trimmed.chars().count() >= 2
        }
        _ => false,
    }
}

/// Shared URL parser for the main gallery route so initial render and subsequent
/// navigations always agree with `Results` on defaults (`Mode::All`, `limit = 50`).
#[allow(clippy::too_many_arguments)]
fn parse_url_state(
    mode_raw: Option<String>,
    q_raw: Option<String>,
    adv_raw: Option<String>,
    sort_raw: Option<String>,
    cw_raw: Option<String>,
    min_sim_raw: Option<String>,
    img_raw: Option<String>,
    limit_raw: Option<String>,
) -> UrlSearchState {
    let mode = mode_raw.as_deref().map(Mode::parse).unwrap_or(Mode::All);
    let q = q_raw.unwrap_or_default();
    let adv = adv_raw.unwrap_or_default();
    let sort = sort_raw
        .as_deref()
        .map(AdvancedSort::parse)
        .unwrap_or(AdvancedSort::Relevance);
    let clip_weight = cw_raw
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(50)
        .clamp(5, 95);
    let min_similarity = parse_url_min_similarity(min_sim_raw.as_deref());
    let img_nonce = img_raw.unwrap_or_default();
    let limit = parse_url_limit(limit_raw.as_deref()) as usize;
    UrlSearchState {
        mode,
        q,
        adv,
        sort,
        clip_weight,
        min_similarity,
        img_nonce,
        limit,
    }
}

fn active_query_summary(state: &UrlSearchState) -> Option<ActiveQuerySummary> {
    match state.mode {
        Mode::Advanced => {
            let trimmed = state.adv.trim();
            if trimmed.is_empty() {
                return None;
            }
            match parse_and_compile(trimmed) {
                Ok((_, plan)) => {
                    let meta_badge = if plan.has_clip() && plan.has_dino() {
                        Some(format!("CLIP {}%", state.clip_weight))
                    } else if !plan.has_vectors()
                        && !plan.positive_tags.is_empty()
                        && state.sort == AdvancedSort::Newest
                    {
                        Some("Newest".to_string())
                    } else {
                        None
                    };
                    Some(ActiveQuerySummary {
                        result_kind: plan.result_kind,
                        query_text: trimmed.to_string(),
                        meta_badge,
                    })
                }
                Err(_) => Some(ActiveQuerySummary {
                    result_kind: ResultKind::Images,
                    query_text: trimmed.to_string(),
                    meta_badge: None,
                }),
            }
        }
        Mode::Tag => {
            let trimmed = state.q.trim();
            if trimmed.is_empty() {
                return None;
            }
            let query_text = QueryExpr::Term {
                field: SearchField::Tag,
                value: trimmed.to_string(),
            }
            .format_query();
            Some(ActiveQuerySummary {
                result_kind: ResultKind::Images,
                query_text,
                meta_badge: None,
            })
        }
        Mode::Clip => {
            let trimmed = state.q.trim();
            if trimmed.is_empty() {
                return None;
            }
            let query_text = QueryExpr::Term {
                field: SearchField::Clip,
                value: trimmed.to_string(),
            }
            .format_query();
            Some(ActiveQuerySummary {
                result_kind: ResultKind::Images,
                query_text,
                meta_badge: Some("CLIP".to_string()),
            })
        }
        Mode::Similar => {
            let trimmed = state.q.trim();
            if trimmed.is_empty() {
                return None;
            }
            let query_text = QueryExpr::Term {
                field: SearchField::Dino,
                value: trimmed.to_string(),
            }
            .format_query();
            Some(ActiveQuerySummary {
                result_kind: ResultKind::Images,
                query_text,
                meta_badge: Some("Visual".to_string()),
            })
        }
        Mode::SearchImage => {
            let trimmed = state.q.trim();
            if trimmed.is_empty() {
                return None;
            }
            Some(ActiveQuerySummary {
                result_kind: ResultKind::Images,
                query_text: "Reverse image search".to_string(),
                meta_badge: Some("Visual".to_string()),
            })
        }
        _ => None,
    }
}

/// Resize an uploaded image file to <=256px WebP and return `(url_safe_b64, preview_data_url)`.
pub(crate) async fn encode_image_file(file: web_sys::File) -> Option<(String, String)> {
    const MAX_EDGE: f64 = 256.0;

    let window = web_sys::window()?;
    let promise = window.create_image_bitmap_with_blob(&file).ok()?;
    let bitmap: ImageBitmap = JsFuture::from(promise).await.ok()?.dyn_into().ok()?;

    let sw = bitmap.width() as f64;
    let sh = bitmap.height() as f64;
    if sw < 1.0 || sh < 1.0 {
        bitmap.close();
        return None;
    }
    let scale = (MAX_EDGE / sw.max(sh)).min(1.0);
    let dw = (sw * scale).round().max(1.0);
    let dh = (sh * scale).round().max(1.0);

    let document = window.document()?;
    let canvas: HtmlCanvasElement = document.create_element("canvas").ok()?.dyn_into().ok()?;
    canvas.set_width(dw as u32);
    canvas.set_height(dh as u32);
    let ctx: CanvasRenderingContext2d = canvas.get_context("2d").ok()??.dyn_into().ok()?;

    let draw_ok = ctx
        .draw_image_with_image_bitmap_and_dw_and_dh(&bitmap, 0.0, 0.0, dw, dh)
        .is_ok();
    bitmap.close();
    if !draw_ok {
        return None;
    }

    let data_url = canvas
        .to_data_url_with_type_and_encoder_options("image/webp", &JsValue::from_f64(0.7))
        .ok()?;
    let b64 = data_url.split_once(',')?.1;
    let url_safe = b64
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string();
    Some((url_safe, data_url))
}

/// Shared autocomplete fetcher reused by both `SearchBar` and `AdvancedSearchPanel`.
pub(crate) async fn fetch_suggestions(field: SearchField, q: String) -> Vec<SearchSuggestion> {
    if !should_suggest_field(field, &q) {
        return Vec::new();
    }
    let mode_str = match field {
        SearchField::All => "all",
        SearchField::Author => "author",
        SearchField::Title => "title",
        SearchField::Tag => "tag",
        _ => return Vec::new(),
    };
    suggest_search(mode_str.to_string(), q)
        .await
        .unwrap_or_default()
}

fn suggestion_target_mode(current_mode: Mode, suggestion_kind: &str) -> Mode {
    if current_mode == Mode::All {
        match suggestion_kind {
            "author" => Mode::Author,
            "title" => Mode::Title,
            _ => Mode::All,
        }
    } else {
        current_mode
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
struct PostDrafts {
    all: String,
    title: String,
    author: String,
}

impl PostDrafts {
    fn get(&self, mode: Mode) -> &str {
        match mode {
            Mode::All => &self.all,
            Mode::Title => &self.title,
            Mode::Author => &self.author,
            _ => &self.all,
        }
    }

    fn set(&mut self, mode: Mode, val: String) {
        match mode {
            Mode::All => self.all = val,
            Mode::Title => self.title = val,
            Mode::Author => self.author = val,
            _ => self.all = val,
        }
    }
}

fn random_target_from_q(q: &str) -> &'static str {
    if q == "images" { "images" } else { "posts" }
}

fn build_default_search_url(mode: Mode, q: &str, limit: usize) -> String {
    let trimmed = q.trim();
    if trimmed.is_empty() && mode == Mode::All && limit == DEFAULT_LIMIT {
        return "/".to_string();
    }
    let mut url = format!(
        "/?mode={}&q={}",
        mode.as_str(),
        urlencoding::encode(trimmed)
    );
    if limit != DEFAULT_LIMIT {
        url.push_str(&format!("&limit={}", limit.max(1)));
    }
    url
}

fn build_random_url(target: &str, seed: i64, limit: usize) -> String {
    let clean = random_target_from_q(target);
    let mut url = format!("/?mode=random&q={clean}&seed={seed}");
    if limit != DEFAULT_LIMIT {
        url.push_str(&format!("&limit={}", limit.max(1)));
    }
    url
}

#[component]
pub fn SearchBar() -> impl IntoView {
    let qmap = use_query_map();
    let pathname = use_location().pathname;
    let navigate = use_navigate();

    let url_state = Memo::new(move |_| {
        if pathname.with(|p| p != "/") {
            return UrlSearchState::default();
        }
        qmap.with(|m| {
            parse_url_state(
                m.get("mode"),
                m.get("q"),
                m.get("adv"),
                m.get("sort"),
                m.get("cw"),
                m.get("min_sim"),
                m.get("img"),
                m.get("limit"),
            )
        })
    });

    let init_state = url_state.get_untracked();
    let init_field = if init_state.mode.is_default_post_mode() {
        init_state.mode
    } else {
        Mode::All
    };
    let mut init_drafts = PostDrafts::default();
    if init_state.mode.is_default_post_mode() && !init_state.q.is_empty() {
        init_drafts.set(init_state.mode, init_state.q.clone());
    }

    let field_mode = RwSignal::new(init_field);
    let drafts = RwSignal::new(init_drafts);
    // MUST start `false` on both SSR and initial hydrate so initial DOM matches 100%.
    let adv_open = RwSignal::new(false);

    let active_q = Signal::derive(move || {
        let cur = field_mode.get();
        drafts.with(|d| d.get(cur).to_string())
    });

    // Live debounced autocomplete for Default Post Search (`All`, `Title`, `Author`).
    let input_focused = RwSignal::new(false);
    let suggestions: RwSignal<Vec<SearchSuggestion>> = RwSignal::new(Vec::new());
    let suggestions_for: RwSignal<(String, String)> = RwSignal::new((String::new(), String::new()));
    let active_idx: RwSignal<Option<usize>> = RwSignal::new(None);
    let suggest_req_id: StoredValue<u64> = StoredValue::new(0);
    let suggest_key = Signal::derive(move || (field_mode.get(), active_q.get()));
    let debounced_key: Signal<(Mode, String)> = signal_debounced(suggest_key, 180.0);

    let cancel_suggestions = move || {
        suggest_req_id.set_value(suggest_req_id.get_value().wrapping_add(1));
        suggestions.set(Vec::new());
        suggestions_for.set((String::new(), String::new()));
        active_idx.set(None);
    };

    Effect::new(move |_| {
        let (cur_mode, cur_q) = suggest_key.get();
        let cur_key = (cur_mode.as_str().to_string(), cur_q.trim().to_string());
        if !should_suggest(cur_mode, &cur_q)
            || suggestions_for.with_untracked(|k| !k.1.is_empty() && *k != cur_key)
        {
            cancel_suggestions();
        }
    });

    Effect::new(move |_| {
        let (cur_mode, cur_q) = debounced_key.get();
        let focused = input_focused.get();
        if !focused || !should_suggest(cur_mode, &cur_q) {
            cancel_suggestions();
            return;
        }
        if field_mode.get_untracked() != cur_mode || active_q.get_untracked() != cur_q {
            return;
        }
        let next_id = suggest_req_id.get_value().wrapping_add(1);
        suggest_req_id.set_value(next_id);
        let field = match cur_mode {
            Mode::Author => SearchField::Author,
            Mode::Title => SearchField::Title,
            _ => SearchField::All,
        };
        let expected_q = cur_q.clone();
        spawn_local(async move {
            let items = fetch_suggestions(field, cur_q).await;
            if suggest_req_id.try_get_value() != Some(next_id) {
                return;
            }
            if field_mode.try_get_untracked() != Some(cur_mode)
                || active_q.try_get_untracked().as_deref() != Some(expected_q.as_str())
                || input_focused.try_get_untracked() != Some(true)
            {
                return;
            }
            let arrived_key = (cur_mode.as_str().to_string(), expected_q.trim().to_string());
            let _ = suggestions_for.try_set(arrived_key);
            let _ = suggestions.try_set(items);
            let _ = active_idx.try_set(None);
        });
    });

    // Keep top search bar synchronized with gallery URL changes (author links, Back, Home).
    Effect::new(move |_| {
        if pathname.with(|p| p != "/") {
            return;
        }
        let st = url_state.get();
        if st.mode.is_default_post_mode() {
            field_mode.set(st.mode);
            drafts.update(|d| d.set(st.mode, st.q));
        }
        input_focused.set(false);
        cancel_suggestions();
    });

    let go_search = {
        let nav = navigate.clone();
        move |target_mode: Mode, q: String| {
            input_focused.set(false);
            cancel_suggestions();
            adv_open.set(false);
            let lim = url_state.get_untracked().limit;
            let url = build_default_search_url(target_mode, &q, lim);
            nav(&url, NavigateOptions::default());
        }
    };

    let go_random = {
        let nav = navigate.clone();
        move |target: &'static str| {
            input_focused.set(false);
            cancel_suggestions();
            adv_open.set(false);
            let seed = (js_sys::Math::random() * i64::MAX as f64) as i64;
            let lim = url_state.get_untracked().limit;
            let url = build_random_url(target, seed, lim);
            nav(&url, NavigateOptions::default());
        }
    };

    let submit = {
        let go_search = go_search.clone();
        move |ev: leptos::ev::SubmitEvent| {
            ev.prevent_default();
            let cur_mode = field_mode.get_untracked();
            let q = drafts.with_untracked(|d| d.get(cur_mode).to_string());
            go_search(cur_mode, q);
        }
    };

    let pick_suggestion = {
        let go_search = go_search.clone();
        move |s: SearchSuggestion| {
            let cur_mode = field_mode.get_untracked();
            let target_mode = suggestion_target_mode(cur_mode, &s.kind);
            field_mode.set(target_mode);
            drafts.update(|d| d.set(target_mode, s.value.clone()));
            go_search(target_mode, s.value);
        }
    };

    let scroll_option_into_view = move |idx: usize| {
        #[cfg(feature = "hydrate")]
        {
            if let Some(el) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.get_element_by_id(&format!("search-opt-{idx}")))
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
            let _ = idx;
        }
    };

    let active_summary = Memo::new(move |_| {
        if pathname.with(|p| p != "/") {
            return None;
        }
        url_state.with(active_query_summary)
    });

    let has_active_advanced = move || active_summary.with(Option::is_some);
    let is_random_mode =
        move || pathname.with(|p| p == "/") && url_state.with(|s| s.mode == Mode::Random);
    let random_target = move || url_state.with(|s| random_target_from_q(&s.q));

    let dropdown_open = move || input_focused.get() && !suggestions.with(Vec::is_empty);

    let density = use_context::<GalleryDensityState>().unwrap_or_default().0;
    let safety = expect_context::<SafetyUiState>();
    // Monotonic generation counter to serialize rapid local Safe Mode toggles and
    // ignore superseded `/user/api/preferences` responses.
    let safe_persist_gen: StoredValue<u64> = StoredValue::new(0);
    #[cfg(feature = "hydrate")]
    let remote_reload_gen: StoredValue<u64> = StoredValue::new(0);

    // Subscribe to cross-tab Safe Mode broadcasts directly so remote tabs immediately
    // wipe media and refresh without firing redundant `POST /user/api/preferences` calls.
    #[cfg(feature = "hydrate")]
    {
        use wasm_bindgen::closure::Closure;
        struct LocalChannelCleanup(Option<Box<dyn FnOnce()>>);
        impl Drop for LocalChannelCleanup {
            fn drop(&mut self) {
                if let Some(f) = self.0.take() {
                    f();
                }
            }
        }

        if let Ok(ch) = web_sys::BroadcastChannel::new(lets_embed_ui::browser::SAFETY_CHANNEL_NAME)
        {
            let cb =
                Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |ev: web_sys::MessageEvent| {
                    let data = ev.data();
                    let (msg_type, enabled) = if let Some(b) = data.as_bool() {
                        (Some("safe_mode".to_string()), Some(b))
                    } else if data.is_object() {
                        let t = js_sys::Reflect::get(&data, &JsValue::from_str("type"))
                            .ok()
                            .and_then(|v| v.as_string());
                        let b = js_sys::Reflect::get(&data, &JsValue::from_str("enabled"))
                            .ok()
                            .and_then(|v| v.as_bool());
                        (t, b)
                    } else {
                        (None, None)
                    };
                    let Some(enabled) = enabled else {
                        return;
                    };
                    match msg_type.as_deref() {
                        Some("safe_mode") => {
                            let _ = safety.safe_mode.try_set(enabled);
                            if enabled {
                                let _ = safety
                                    .panic_epoch
                                    .try_update(|e| *e = e.wrapping_add(1));
                                lets_embed_ui::browser::wipe_media_elements_in(None);
                            }
                            if safety.is_managed.try_get_untracked().unwrap_or(false) {
                                // Wait briefly for the originating tab's `safe_mode_synced` signal
                                // after its POST completes; fall back to reload if the broadcast
                                // came from another SPA (e.g. `/user/favorites`).
                                let rgen = remote_reload_gen
                                    .try_get_value()
                                    .unwrap_or(0)
                                    .wrapping_add(1);
                                let _ = remote_reload_gen.try_set_value(rgen);
                                set_timeout(
                                    move || {
                                        if remote_reload_gen.try_get_value() == Some(rgen) {
                                            let _ = safety
                                                .reload_epoch
                                                .try_update(|e| *e = e.wrapping_add(1));
                                        }
                                    },
                                    std::time::Duration::from_millis(250),
                                );
                            } else {
                                let _ = safety
                                    .reload_epoch
                                    .try_update(|e| *e = e.wrapping_add(1));
                            }
                        }
                        Some("safe_mode_synced") => {
                            let rgen = remote_reload_gen
                                .try_get_value()
                                .unwrap_or(0)
                                .wrapping_add(1);
                            let _ = remote_reload_gen.try_set_value(rgen);
                            let _ = safety.safe_mode.try_set(enabled);
                            let _ = safety
                                .reload_epoch
                                .try_update(|e| *e = e.wrapping_add(1));
                        }
                        _ => {}
                    }
                });
            ch.set_onmessage(Some(cb.as_ref().unchecked_ref()));
            let _ = StoredValue::new_local(LocalChannelCleanup(Some(Box::new(move || {
                ch.set_onmessage(None);
                ch.close();
                drop(cb);
            }))));
        }
    }

    let on_safe_mode_toggle = Callback::new(move |next: bool| {
        if next {
            lets_embed_ui::browser::wipe_media_elements_in(None);
        }
        // Immediately notify sibling tabs so they wipe media and update UI synchronously.
        lets_embed_ui::browser::broadcast_safe_mode(next);
        let persist_gen = safe_persist_gen.get_value().wrapping_add(1);
        safe_persist_gen.set_value(persist_gen);

        if safety.is_managed.get_untracked() {
            spawn_local(async move {
                let _ok = persist_safe_mode(next).await;
                if safe_persist_gen.try_get_value() != Some(persist_gen) {
                    return;
                }
                let _ = safety.reload_epoch.try_update(|e| *e = e.wrapping_add(1));
                broadcast_safe_mode_synced(next);
            });
        } else {
            safety.reload_epoch.update(|e| *e = e.wrapping_add(1));
        }
    });
    let is_home = move || pathname.with(|p| p == "/");
    let header_card_ref = NodeRef::<leptos::html::Div>::new();

    #[cfg(feature = "hydrate")]
    {
        let UseElementSizeReturn {
            height: header_h, ..
        } = use_element_size(header_card_ref);
        Effect::new(move |_| {
            let h = header_h.get();
            if h <= 0.0 {
                return;
            }
            if let Some(win) = web_sys::window() {
                let card_h = header_card_ref
                    .get_untracked()
                    .map(|el| el.get_bounding_client_rect().height())
                    .filter(|&bh| bh > 0.0)
                    .unwrap_or(h);
                let vp_w = win
                    .inner_width()
                    .ok()
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1024.0);
                let top_offset = if vp_w < 640.0 { 8.0 } else { 12.0 };
                let nav_bottom = (top_offset + card_h + 8.0).round() as i32;
                if let Some(root) = win
                    .document()
                    .and_then(|d| d.document_element())
                    .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    let _ = root
                        .style()
                        .set_property("--floating-nav-bottom", &format!("{nav_bottom}px"));
                }
            }
        });
    }

    let bar_row_cls = move || {
        if is_home() {
            "flex flex-wrap xl:flex-nowrap w-full items-center gap-x-1.5 sm:gap-x-2 gap-y-2 py-2 sm:py-2.5 px-2 sm:px-3.5"
        } else {
            "flex flex-wrap lg:flex-nowrap w-full items-center gap-x-1.5 sm:gap-x-2 gap-y-2 py-2 sm:py-2.5 px-2 sm:px-3.5"
        }
    };
    let account_slot_cls = move || {
        if is_home() {
            "order-2 md:order-3 xl:order-5 ml-auto md:ml-0 shrink-0"
        } else {
            "order-2 md:order-3 lg:order-5 ml-auto md:ml-0 shrink-0"
        }
    };
    let row_break_cls = move || {
        if is_home() {
            "hidden md:block xl:hidden basis-full h-0 -my-1 order-4"
        } else {
            "hidden md:block lg:hidden basis-full h-0 -my-1 order-4"
        }
    };
    let actions_slot_cls = move || {
        if is_home() {
            "order-5 md:order-6 xl:order-3 ml-auto xl:ml-0 flex items-center gap-1.5 sm:gap-2 shrink-0"
        } else {
            "order-5 md:order-6 lg:order-3 ml-auto lg:ml-0 flex items-center gap-1.5 sm:gap-2 shrink-0"
        }
    };

    let go_random_main = go_random.clone();
    let go_random_posts = go_random.clone();
    let go_random_images = go_random;
    let pick_key = pick_suggestion.clone();
    let pick_click = pick_suggestion;
    let nav_clear = navigate;

    view! {
        <header class="sticky top-2 sm:top-3 z-40 w-full px-2 sm:px-3.5 mt-2 sm:mt-3 pointer-events-none">
            <div
                node_ref=header_card_ref
                class="floating-nav-card pointer-events-auto relative flex flex-col w-full max-w-[1640px] mx-auto"
            >
                <div class=bar_row_cls>
                    // Brand logo
                    <a
                        href="/"
                        on:click=move |_| adv_open.set(false)
                        class="order-1 font-display text-lg sm:text-2xl font-bold text-left shrink-0 whitespace-nowrap
                            bg-gradient-to-r from-sky-500 via-blue-500 to-cyan-400 bg-clip-text text-transparent
                            drop-shadow-sm hover:scale-105 transition-transform"
                    >
                        "Let\u{2019}s Embed \u{2728}"
                    </a>

                    // Unified Web-of-Science pill search form (Posts only: Title & Author, Title, Author)
                    <form
                        class="order-3 md:order-2 flex w-full md:w-auto md:flex-1 min-w-0 items-center"
                        on:submit=submit
                    >
                        <div class="relative flex flex-1 min-w-0 items-center bg-white border border-sky-200 rounded-full
                                    shadow-xs shadow-sky-100/80 focus-within:border-sky-400 focus-within:ring-2
                                    focus-within:ring-sky-200/80 transition">
                            // Custom themed field dropdown (floats cleanly below rounded pill)
                            <SkySelect
                                aria_label="Search field"
                                variant=SelectVariant::SearchPill
                                value=Signal::derive(move || field_mode.get().as_str().to_string())
                                options=Signal::derive(move || {
                                    vec![
                                        SelectOption::new("all", "Title & Author"),
                                        SelectOption::new("title", "Title"),
                                        SelectOption::new("author", "Author"),
                                    ]
                                })
                                on_change=Callback::new(move |val: String| {
                                    let next = match val.as_str() {
                                        "title" => Mode::Title,
                                        "author" => Mode::Author,
                                        _ => Mode::All,
                                    };
                                    // Carry over the typed text when switching between Title & Author / Title / Author.
                                    let cur_text = active_q.get_untracked();
                                    field_mode.set(next);
                                    if !cur_text.is_empty() && drafts.with_untracked(|d| d.get(next).is_empty()) {
                                        drafts.update(|d| d.set(next, cur_text));
                                    }
                                    cancel_suggestions();
                                })
                            />

                            // Spacious input + inline clear button
                            <div class="relative flex-1 min-w-0 flex items-center">
                                <input
                                    role="combobox"
                                    aria-label="Search posts"
                                    aria-autocomplete="list"
                                    aria-controls="search-suggestions"
                                    aria-expanded=move || dropdown_open().to_string()
                                    aria-activedescendant=move || {
                                        dropdown_open()
                                            .then(|| active_idx.get().map(|i| format!("search-opt-{i}")))
                                            .flatten()
                                    }
                                    class="w-full min-w-0 bg-transparent py-2 pl-3 pr-8 text-sm sm:text-[15px] outline-none
                                           text-slate-700 placeholder:text-sky-400/75"
                                    autocomplete="off"
                                    placeholder=move || match field_mode.get() {
                                        Mode::Title => "Search post titles\u{2026}",
                                        Mode::Author => "Search author name\u{2026}",
                                        _ => "Search post titles or authors\u{2026}",
                                    }
                                    value=move || active_q.get()
                                    prop:value=move || active_q.get()
                                    on:focus=move |_| input_focused.set(true)
                                    on:click=move |_| input_focused.set(true)
                                    on:blur=move |_| input_focused.set(false)
                                    on:input=move |ev| {
                                        let cur = field_mode.get_untracked();
                                        let val = event_target_value(&ev);
                                        let next_key = (cur.as_str().to_string(), val.trim().to_string());
                                        drafts.update(|d| d.set(cur, val));
                                        active_idx.set(None);
                                        if suggestions_for.with_untracked(|k| *k != next_key) {
                                            suggestions.set(Vec::new());
                                            suggestions_for.set((String::new(), String::new()));
                                        }
                                        input_focused.set(true);
                                    }
                                    on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                                        // Never hijack keys while an IME (Chinese/Japanese/Korean) is composing.
                                        if ev.is_composing() || ev.key_code() == 229 {
                                            return;
                                        }
                                        let len = suggestions.with_untracked(Vec::len);
                                        if len == 0 || !input_focused.get_untracked() {
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
                                                input_focused.set(false);
                                            }
                                            "Enter" => {
                                                let cur_mode = field_mode.get_untracked();
                                                let cur_q = active_q.get_untracked();
                                                let matches_current = suggestions_for.with_untracked(|k| {
                                                    k.0 == cur_mode.as_str() && k.1 == cur_q.trim()
                                                });
                                                if matches_current
                                                    && let Some(i) = active_idx.get_untracked()
                                                    && let Some(picked) = suggestions
                                                        .with_untracked(|s| s.get(i).cloned())
                                                {
                                                    ev.prevent_default();
                                                    pick_key(picked);
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                />
                                {move || (!active_q.get().is_empty()).then(|| view! {
                                    <button
                                        type="button"
                                        aria-label="Clear search"
                                        title="Clear"
                                        class="absolute right-1.5 top-1/2 -translate-y-1/2 w-6 h-6 rounded-full
                                               flex items-center justify-center text-sky-400 hover:text-sky-700
                                               hover:bg-sky-100 transition-colors cursor-pointer"
                                        on:mousedown=|ev| ev.prevent_default()
                                        on:click=move |_| {
                                            let cur = field_mode.get_untracked();
                                            drafts.update(|d| d.set(cur, String::new()));
                                            cancel_suggestions();
                                        }
                                    >
                                        "\u{00D7}"
                                    </button>
                                })}
                            </div>

                            // Primary Search button inside right edge of WoS pill
                            <button
                                type="submit"
                                class="shrink-0 m-0.5 bg-gradient-to-r from-sky-400 to-blue-500 text-white text-xs sm:text-sm font-medium
                                       rounded-full py-1.5 sm:py-2 px-3.5 sm:px-4 shadow-sm shadow-sky-300/60
                                       hover:from-sky-500 hover:to-blue-600 active:scale-95 transition-all cursor-pointer"
                            >
                                "Search"
                            </button>

                            // Autocomplete dropdown anchored to the full pill width
                            {move || {
                                let items = suggestions.get();
                                let open = input_focused.get() && !items.is_empty();
                                let is_all = field_mode.get() == Mode::All;
                                let pick_list = pick_click.clone();
                                open.then(move || {
                                    view! {
                                        <div
                                            id="search-suggestions"
                                            role="listbox"
                                            on:mousedown=|ev| ev.prevent_default()
                                            class="absolute left-0 right-0 top-full mt-2 z-50 max-h-72 overflow-y-auto overscroll-contain
                                                   rounded-2xl bg-white/95 backdrop-blur-md ring-1 ring-sky-200/90
                                                   shadow-xl shadow-sky-200/60 p-1.5 flex flex-col gap-0.5"
                                        >
                                            {items.into_iter().enumerate().map(|(i, s)| {
                                                let pick_item = pick_list.clone();
                                                let picked = s.clone();
                                                let alias_line = (!s.aliases.is_empty())
                                                    .then(|| s.aliases.join(" \u{00B7} "));
                                                let badge = if is_all {
                                                    match s.kind.as_str() {
                                                        "author" => Some(("@ Author", "bg-sky-100 text-sky-700 ring-sky-200/80")),
                                                        "title" => Some(("Title", "bg-indigo-50 text-indigo-700 ring-indigo-200/80")),
                                                        _ => None,
                                                    }
                                                } else {
                                                    None
                                                };
                                                let opt_id = format!("search-opt-{i}");
                                                view! {
                                                    <button
                                                        id=opt_id
                                                        type="button"
                                                        role="option"
                                                        aria-selected=move || (active_idx.get() == Some(i)).to_string()
                                                        class=move || if active_idx.get() == Some(i) {
                                                            "w-full text-left px-3 py-2 rounded-xl flex flex-col gap-0.5 bg-sky-100/90 text-sky-900 cursor-pointer transition-colors"
                                                        } else {
                                                            "w-full text-left px-3 py-2 rounded-xl flex flex-col gap-0.5 hover:bg-sky-50 text-slate-700 cursor-pointer transition-colors"
                                                        }
                                                        on:mousedown=|ev| ev.prevent_default()
                                                        on:mouseenter=move |_| active_idx.set(Some(i))
                                                        on:click=move |_| pick_item(picked.clone())
                                                    >
                                                        <div class="flex items-center justify-between gap-2 min-w-0">
                                                            <span class="text-sm font-medium truncate">{s.value}</span>
                                                            {badge.map(|(label, cls)| view! {
                                                                <span class=format!(
                                                                    "shrink-0 px-2 py-0.5 rounded-full text-[11px] font-semibold ring-1 whitespace-nowrap {cls}"
                                                                )>
                                                                    {label}
                                                                </span>
                                                            })}
                                                        </div>
                                                        {alias_line.map(|line| view! {
                                                            <span class="text-xs text-slate-400 truncate">{line}</span>
                                                        })}
                                                    </button>
                                                }
                                            }).collect_view()}
                                        </div>
                                    }
                                })
                            }}
                        </div>
                    </form>

                    // User center & Favorites button integrated directly into the floating header card
                    <div class=account_slot_cls>
                        <AccountWidget />
                    </div>

                    // Clean 2-row separator on tablet breakpoints (`md..xl` on home, `md..lg` on details)
                    <div class=row_break_cls aria-hidden="true" />

                    // Gallery density selector integrated into the floating header on the home page
                    {move || is_home().then(|| view! {
                        <div class="order-4 md:order-5 xl:order-4 shrink-0">
                            <DensityPicker density=density persist=true />
                        </div>
                    })}

                    // Compact action buttons: Safe Mode, Random (+ inline Posts|Images when active) & Advanced
                    <div class=actions_slot_cls>
                        <SafeModeToggle
                            safe_mode=safety.safe_mode
                            panic_epoch=safety.panic_epoch
                            sync_tabs=false
                            compact=true
                            on_toggle=on_safe_mode_toggle
                        />
                        {move || if is_random_mode() {
                            let cur_target = random_target();
                            let reroll = go_random_main.clone();
                            let roll_posts = go_random_posts.clone();
                            let roll_images = go_random_images.clone();
                            let posts_cls = if cur_target == "posts" {
                                "px-2.5 py-1 rounded-full text-xs font-semibold bg-sky-500 text-white shadow-xs transition-all cursor-pointer"
                            } else {
                                "px-2.5 py-1 rounded-full text-xs font-medium text-sky-700 hover:bg-sky-200/70 transition-all cursor-pointer"
                            };
                            let images_cls = if cur_target == "images" {
                                "px-2.5 py-1 rounded-full text-xs font-semibold bg-sky-500 text-white shadow-xs transition-all cursor-pointer"
                            } else {
                                "px-2.5 py-1 rounded-full text-xs font-medium text-sky-700 hover:bg-sky-200/70 transition-all cursor-pointer"
                            };
                            view! {
                                <div class="inline-flex items-center gap-0.5 p-0.5 rounded-full bg-sky-100/90 ring-1 ring-sky-200/90">
                                    <button
                                        type="button"
                                        title="Re-roll random shuffle"
                                        class="inline-flex items-center gap-1 px-2 sm:px-2.5 py-1 rounded-full text-xs font-semibold
                                               text-sky-700 hover:bg-white/80 transition-colors cursor-pointer whitespace-nowrap"
                                        on:click=move |_| reroll(cur_target)
                                    >
                                        <span aria-hidden="true">"\u{1F3B2}"</span>
                                        <span class="hidden sm:inline">"Random"</span>
                                    </button>
                                    <button
                                        type="button"
                                        aria-pressed=(cur_target == "posts").to_string()
                                        class=posts_cls
                                        on:click=move |_| roll_posts("posts")
                                    >
                                        "Posts"
                                    </button>
                                    <button
                                        type="button"
                                        aria-pressed=(cur_target == "images").to_string()
                                        class=images_cls
                                        on:click=move |_| roll_images("images")
                                    >
                                        "Images"
                                    </button>
                                </div>
                            }.into_any()
                        } else {
                            let roll = go_random_main.clone();
                            view! {
                                <button
                                    type="button"
                                    title="Roll random posts"
                                    class="inline-flex items-center gap-1.5 px-2 sm:px-3 py-1.5 sm:py-2 rounded-full text-xs sm:text-sm
                                           font-medium text-sky-700 bg-sky-50 hover:bg-sky-100 ring-1 ring-sky-200/90
                                           active:scale-95 transition-all cursor-pointer whitespace-nowrap"
                                    on:click=move |_| roll("posts")
                                >
                                    <span aria-hidden="true">"\u{1F3B2}"</span>
                                    <span class="hidden sm:inline">"Random"</span>
                                </button>
                            }.into_any()
                        }}

                        <button
                            type="button"
                            aria-expanded=move || adv_open.get().to_string()
                            aria-controls="advanced-search-panel"
                            title="Open Web-of-Science Advanced Query Builder (Tag, Author, Title, CLIP, Visual)"
                            class=move || {
                                if adv_open.get() || has_active_advanced() {
                                    "relative inline-flex items-center gap-1 sm:gap-1.5 px-2 sm:px-3 py-1.5 sm:py-2 rounded-full text-xs sm:text-sm \
                                     font-semibold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 ring-1 ring-indigo-300 \
                                     shadow-xs shadow-indigo-200/50 active:scale-95 transition-all cursor-pointer whitespace-nowrap"
                                } else {
                                    "relative inline-flex items-center gap-1 sm:gap-1.5 px-2 sm:px-3 py-1.5 sm:py-2 rounded-full text-xs sm:text-sm \
                                     font-medium text-slate-700 bg-white hover:bg-sky-50 hover:text-sky-700 ring-1 ring-sky-200 \
                                     active:scale-95 transition-all cursor-pointer whitespace-nowrap"
                                }
                            }
                            on:click=move |_| {
                                input_focused.set(false);
                                cancel_suggestions();
                                adv_open.update(|v| *v = !*v);
                            }
                        >
                            <svg
                                class="w-3.5 h-3.5 sm:w-4 sm:h-4 shrink-0"
                                fill="none"
                                viewBox="0 0 24 24"
                                stroke="currentColor"
                                stroke-width="2"
                                aria-hidden="true"
                            >
                                <path
                                    stroke-linecap="round"
                                    stroke-linejoin="round"
                                    d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"
                                />
                            </svg>
                            <span>"Advanced"</span>
                            {move || has_active_advanced().then(|| view! {
                                <span
                                    class="w-2 h-2 rounded-full bg-indigo-500 ring-2 ring-white shrink-0"
                                    aria-label="Advanced query active"
                                />
                            })}
                        </button>
                    </div>
                </div>

                // Active Advanced Query Summary Strip (kept mounted even while Advanced Search is open
                // so closing a modal opened via "Edit query" cleanly restores focus to that button).
                {move || {
                    let nav_clear = nav_clear.clone();
                    active_summary.get().map(move |summary| {
                            let (kind_label, kind_cls) = match summary.result_kind {
                                ResultKind::Posts => (
                                    "Posts",
                                    "bg-sky-100 text-sky-700 ring-sky-200",
                                ),
                                ResultKind::Images => (
                                    "Images",
                                    "bg-indigo-100 text-indigo-700 ring-indigo-200",
                                ),
                            };
                            let query_title = summary.query_text.clone();
                            let query_display = summary.query_text;
                            view! {
                                <div class="w-full bg-gradient-to-r from-sky-50/90 via-indigo-50/70 to-sky-50/90 border-t border-sky-200/70 rounded-b-[19px]">
                                    <div class="px-3 sm:px-4 py-1.5 flex items-center gap-2 min-w-0">
                                        <span class=format!(
                                            "shrink-0 px-2 py-0.5 rounded-full text-[11px] font-semibold ring-1 whitespace-nowrap {kind_cls}"
                                        )>
                                            {kind_label}
                                        </span>
                                        {summary.meta_badge.map(|b| view! {
                                            <span class="shrink-0 px-2 py-0.5 rounded-full text-[11px] font-medium bg-white/85 text-slate-600 ring-1 ring-slate-200 whitespace-nowrap">
                                                {b}
                                            </span>
                                        })}
                                        <code
                                            title=query_title
                                            class="flex-1 min-w-0 truncate text-xs sm:text-[13px] font-mono text-slate-700 bg-white/75
                                                   px-2.5 py-0.5 rounded-lg ring-1 ring-sky-200/60"
                                        >
                                            {query_display}
                                        </code>
                                        <button
                                            type="button"
                                            class="shrink-0 px-2.5 py-1 rounded-full text-xs font-semibold text-indigo-700
                                                   bg-white hover:bg-indigo-50 ring-1 ring-indigo-200 transition-colors cursor-pointer whitespace-nowrap"
                                            on:click=move |_| adv_open.set(true)
                                        >
                                            "Edit query"
                                        </button>
                                        <button
                                            type="button"
                                            class="shrink-0 px-2.5 py-1 rounded-full text-xs font-medium text-slate-600
                                                   hover:text-rose-600 hover:bg-rose-50 ring-1 ring-slate-200/80
                                                   transition-colors cursor-pointer whitespace-nowrap"
                                            on:click=move |_| {
                                                nav_clear("/", NavigateOptions::default());
                                            }
                                        >
                                            "Clear"
                                        </button>
                                    </div>
                                </div>
                            }
                        })
                }}
            </div>
        </header>

        // Mount AdvancedSearchPanel as a sibling outside `backdrop-blur-md` so `fixed inset-0`
        // covers the full viewport cleanly and SSR/hydrate initial markup stays 100% identical.
        {move || adv_open.get().then(|| {
            let initial_state = if pathname.with_untracked(|p| p == "/") {
                let mut st = url_state.get_untracked();
                if st.mode.is_default_post_mode() && st.q.trim().is_empty() {
                    let typed = active_q.get_untracked();
                    if !typed.trim().is_empty() {
                        st.mode = field_mode.get_untracked();
                        st.q = typed;
                    }
                }
                Some(st)
            } else {
                None
            };
            view! {
                <AdvancedSearchPanel
                    open=adv_open
                    initial_state=initial_state
                />
            }
        })}

        {move || {
            if !safety.notice_banner_enabled.get() {
                return None;
            }
            let html = safety.notice_banner_html.get()?;
            let dismiss_key = safety.notice_banner_key.get_untracked();
            Some(view! {
                <div class="w-full px-2 sm:px-3.5 mt-2">
                    <div class="max-w-[1640px] mx-auto">
                        {if dismiss_key.is_empty() {
                            view! {
                                <NoticeBanner
                                    content=NoticeContent::PreSanitizedHtml(html)
                                    tone=NoticeTone::Info
                                />
                            }.into_any()
                        } else {
                            view! {
                                <NoticeBanner
                                    content=NoticeContent::PreSanitizedHtml(html)
                                    tone=NoticeTone::Info
                                    dismiss_key=dismiss_key
                                />
                            }.into_any()
                        }}
                    </div>
                </div>
            })
        }}

        <Outlet />
        <BackToTop />
    }
}

#[server(endpoint = "suggest_search")]
async fn suggest_search(mode: String, q: String) -> Result<Vec<SearchSuggestion>, ServerFnError> {
    use crate::state::{AppState, RequestSafetyContext};
    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    if q.len() > MAX_SUGGEST_LEN {
        return Err(ServerFnError::Args(format!(
            "suggestion query exceeds maximum length of {MAX_SUGGEST_LEN} bytes"
        )));
    }
    let parsed_mode = match mode.trim().to_ascii_lowercase().as_str() {
        "all" => Mode::All,
        "author" => Mode::Author,
        "title" => Mode::Title,
        "tag" => Mode::Tag,
        _ => return Ok(Vec::new()),
    };
    if !should_suggest(parsed_mode, &q) {
        return Ok(Vec::new());
    }

    let state = expect_context::<AppState>();
    let safety_ctx = RequestSafetyContext::from_leptos_context(&state)?;
    let safety_filter = safety_ctx.safety_filter();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    fn to_err(e: impl std::fmt::Display) -> ServerFnError {
        ServerFnError::Response(e.to_string())
    }

    let items = match parsed_mode {
        Mode::All => {
            let (authors, titles) =
                tokio::try_join!(engine.suggest_authors(&q, 5), engine.suggest_titles(&q, 5))
                    .map_err(to_err)?;
            let mut out = Vec::with_capacity(authors.len() + titles.len());
            for a in authors {
                out.push(SearchSuggestion {
                    value: a.name,
                    kind: "author".to_string(),
                    aliases: vec![],
                });
            }
            for p in titles {
                out.push(SearchSuggestion {
                    value: p.title,
                    kind: "title".to_string(),
                    aliases: vec![],
                });
            }
            out
        }
        Mode::Tag => engine
            .suggest_tags_with_safety(&q, 10, Some(&safety_filter))
            .await
            .map_err(to_err)?
            .into_iter()
            .map(|t| SearchSuggestion {
                value: t.name,
                kind: "tag".to_string(),
                aliases: t.aliases,
            })
            .collect(),
        Mode::Author => engine
            .suggest_authors(&q, 10)
            .await
            .map_err(to_err)?
            .into_iter()
            .map(|a| SearchSuggestion {
                value: a.name,
                kind: "author".to_string(),
                aliases: vec![],
            })
            .collect(),
        Mode::Title => engine
            .suggest_titles(&q, 8)
            .await
            .map_err(to_err)?
            .into_iter()
            .map(|p| SearchSuggestion {
                value: p.title,
                kind: "title".to_string(),
                aliases: vec![],
            })
            .collect(),
        _ => Vec::new(),
    };

    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ssr")]
    #[test]
    fn pinned_path() {
        use leptos::server_fn::ServerFn;
        assert_eq!(SuggestSearch::PATH, "/api/suggest_search");
    }

    #[test]
    fn suggest_threshold_allows_single_cjk_and_requires_two_ascii() {
        assert!(!should_suggest(Mode::All, ""));
        assert!(!should_suggest(Mode::All, "a"));
        assert!(should_suggest(Mode::All, "ab"));
        assert!(should_suggest(Mode::All, "猫"));
        assert!(!should_suggest(Mode::Tag, "a"));
        assert!(should_suggest(Mode::Tag, "bl"));
        assert!(should_suggest(Mode::Tag, "花"));
        assert!(!should_suggest(Mode::Author, "a"));
        assert!(should_suggest(Mode::Author, "ab"));
        assert!(!should_suggest(Mode::Clip, "sunset"));
        assert!(!should_suggest_field(SearchField::Clip, "sunset"));
        assert!(should_suggest_field(SearchField::Tag, "猫"));
    }

    #[test]
    fn url_state_defaults_to_all_and_limit_50() {
        let st = parse_url_state(None, None, None, None, None, None, None, None);
        assert_eq!(st.mode, Mode::All);
        assert_eq!(st.q, "");
        assert_eq!(st.limit, 50);
        assert_eq!(st.clip_weight, 50);
        assert_eq!(st.min_similarity, None);
        assert_eq!(st.sort, AdvancedSort::Relevance);

        let adv = parse_url_state(
            Some("advanced".into()),
            None,
            Some("tag:maid".into()),
            Some("newest".into()),
            Some("120".into()),
            Some("0.42".into()),
            Some("999".into()),
            Some("25".into()),
        );
        assert_eq!(adv.mode, Mode::Advanced);
        assert_eq!(adv.adv, "tag:maid");
        assert_eq!(adv.sort, AdvancedSort::Newest);
        assert_eq!(adv.clip_weight, 95);
        assert_eq!(adv.min_similarity, Some(0.42));
        assert_eq!(adv.img_nonce, "999");
        assert_eq!(adv.limit, 25);

        let zero_lim = parse_url_state(None, None, None, None, None, None, None, Some("0".into()));
        assert_eq!(zero_lim.limit, 50);
        let neg_lim = parse_url_state(None, None, None, None, None, None, None, Some("-5".into()));
        assert_eq!(neg_lim.limit, 50);
        let huge_lim =
            parse_url_state(None, None, None, None, None, None, None, Some("999".into()));
        assert_eq!(huge_lim.limit, 100);
    }

    #[test]
    fn all_mode_suggestion_routes_to_author_or_title() {
        assert_eq!(suggestion_target_mode(Mode::All, "author"), Mode::Author);
        assert_eq!(suggestion_target_mode(Mode::All, "title"), Mode::Title);
        assert_eq!(suggestion_target_mode(Mode::All, ""), Mode::All);
        assert_eq!(suggestion_target_mode(Mode::Title, "author"), Mode::Title);
        assert_eq!(suggestion_target_mode(Mode::Author, "title"), Mode::Author);
    }

    #[test]
    fn active_query_summary_covers_advanced_and_legacy_modes() {
        let post_adv = UrlSearchState {
            mode: Mode::Advanced,
            adv: "author:渡久山 NOT title:预告".into(),
            ..Default::default()
        };
        let summary = active_query_summary(&post_adv).expect("post advanced summary");
        assert_eq!(summary.result_kind, ResultKind::Posts);

        let img_adv = UrlSearchState {
            mode: Mode::Advanced,
            adv: "tag:maid AND clip:\"cafe\"".into(),
            ..Default::default()
        };
        let summary = active_query_summary(&img_adv).expect("image advanced summary");
        assert_eq!(summary.result_kind, ResultKind::Images);

        let legacy_tag = UrlSearchState {
            mode: Mode::Tag,
            q: "black hair".into(),
            ..Default::default()
        };
        let summary = active_query_summary(&legacy_tag).expect("legacy tag summary");
        assert_eq!(summary.result_kind, ResultKind::Images);
        assert_eq!(summary.query_text, "tag:\"black hair\"");

        let default_all = UrlSearchState {
            mode: Mode::All,
            q: "hello".into(),
            ..Default::default()
        };
        assert!(active_query_summary(&default_all).is_none());
    }

    #[test]
    fn post_drafts_are_isolated_across_default_fields() {
        let mut drafts = PostDrafts::default();
        drafts.set(Mode::All, "星光".into());
        drafts.set(Mode::Author, "渡久山".into());
        drafts.set(Mode::Title, "咖啡".into());
        assert_eq!(drafts.get(Mode::All), "星光");
        assert_eq!(drafts.get(Mode::Author), "渡久山");
        assert_eq!(drafts.get(Mode::Title), "咖啡");
    }
}
