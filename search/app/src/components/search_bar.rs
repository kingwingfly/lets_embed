use crate::components::{AccountWidget, BackToTop};
use crate::types::{ImageQuery, ImageQueryPayload, Mode};
use js_sys::futures::JsFuture;
#[cfg(feature = "hydrate")]
use leptos::ev;
use leptos::{prelude::*, task::spawn_local};
use leptos_router::{
    NavigateOptions,
    components::Outlet,
    hooks::{use_location, use_navigate, use_query_map},
};
#[cfg(feature = "hydrate")]
use leptos_use_event_listener::use_event_listener;
use leptos_use_signal_debounce_throttle::signal_debounced;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast as _, JsValue};
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, ImageBitmap};

const DEFAULT_LIMIT: usize = 50;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchSuggestion {
    /// Canonical value to search when picked (English tag name, author name, or post title).
    pub value: String,
    /// Optional multilingual aliases/translations (populated for `Mode::Tag`).
    #[serde(default)]
    pub aliases: Vec<String>,
}

fn should_suggest(mode: Mode, q: &str) -> bool {
    let trimmed = q.trim();
    if trimmed.is_empty() {
        return false;
    }
    let has_non_ascii = !trimmed.is_ascii();
    match mode {
        Mode::Tag | Mode::Author | Mode::Title => has_non_ascii || trimmed.chars().count() >= 2,
        _ => false,
    }
}

/// Shared URL parser for the main gallery route so initial render and subsequent
/// navigations always agree with `Results` on defaults (including `limit = 50`).
fn parse_gallery_params(
    mode_raw: Option<String>,
    q_raw: Option<String>,
    limit_raw: Option<String>,
) -> (Mode, String, usize) {
    let mode = mode_raw.as_deref().map(Mode::parse).unwrap_or(Mode::Tag);
    let q = q_raw.unwrap_or_default();
    let limit = limit_raw
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&v| v >= 1)
        .unwrap_or(DEFAULT_LIMIT);
    (mode, q, limit)
}

async fn encode_file(file: web_sys::File) -> Option<String> {
    const MAX_EDGE: f64 = 256.0;

    let window = web_sys::window()?;
    let promise = window.create_image_bitmap_with_blob(&file).ok()?;
    let bitmap: ImageBitmap = JsFuture::from(promise).await.ok()?.dyn_into().ok()?;

    let sw = bitmap.width() as f64;
    let sh = bitmap.height() as f64;
    if sw < 1.0 || sh < 1.0 {
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

    ctx.draw_image_with_image_bitmap_and_dw_and_dh(&bitmap, 0.0, 0.0, dw, dh)
        .ok()?;
    bitmap.close();

    let data_url = canvas
        .to_data_url_with_type_and_encoder_options("image/webp", &JsValue::from_f64(0.7))
        .ok()?;
    let b64 = data_url.split_once(',')?.1;
    Some(
        b64.replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string(),
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ModeDrafts {
    tag: String,
    author: String,
    title: String,
    clip: String,
    similar: String,
    random_target: String,
}

impl Default for ModeDrafts {
    fn default() -> Self {
        Self {
            tag: String::new(),
            author: String::new(),
            title: String::new(),
            clip: String::new(),
            similar: String::new(),
            random_target: "posts".to_string(),
        }
    }
}

impl ModeDrafts {
    fn get(&self, mode: Mode) -> &str {
        match mode {
            Mode::Tag => &self.tag,
            Mode::Author => &self.author,
            Mode::Title => &self.title,
            Mode::Clip => &self.clip,
            Mode::Similar => &self.similar,
            Mode::Random => &self.random_target,
            Mode::SearchImage => "",
        }
    }

    fn set(&mut self, mode: Mode, val: String) {
        match mode {
            Mode::Tag => self.tag = val,
            Mode::Author => self.author = val,
            Mode::Title => self.title = val,
            Mode::Clip => self.clip = val,
            Mode::Similar => self.similar = val,
            Mode::Random => {
                self.random_target = if val == "images" {
                    "images".to_string()
                } else {
                    "posts".to_string()
                };
            }
            Mode::SearchImage => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ModeTooltip {
    mode: Mode,
    title: &'static str,
    desc: &'static str,
    x: f64,
    y: f64,
}

fn mode_help(mode: Mode) -> (&'static str, &'static str) {
    match mode {
        Mode::Tag => (
            "Tag search",
            "Find images by AI tag — supports English & multilingual aliases (中文 / 日本語).",
        ),
        Mode::Author => ("Author search", "Find posts by creator or artist name."),
        Mode::Title => ("Title search", "Search posts by keywords in the title."),
        Mode::Clip => (
            "Text-to-Image (CLIP)",
            "Describe a scene, mood, or object in plain words to find matching images.",
        ),
        Mode::Similar => (
            "Visual Similarity (DINO)",
            "Paste an image ID to find visually similar images by style & composition.",
        ),
        Mode::SearchImage => (
            "Reverse Image Search",
            "Upload a photo to find visually similar images across the gallery.",
        ),
        Mode::Random => (
            "Random Shuffle",
            "Explore random posts or single images with a reproducible shuffle.",
        ),
    }
}

fn build_mode_tooltip(mode: Mode, el: &web_sys::Element) -> ModeTooltip {
    let (title, desc) = mode_help(mode);
    let rect = el.get_bounding_client_rect();
    let vw = web_sys::window()
        .and_then(|w| w.inner_width().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(1024.0);
    let x = (rect.left() + rect.width() / 2.0).clamp(132.0, (vw - 132.0).max(132.0));
    let y = rect.bottom() + 8.0;
    ModeTooltip {
        mode,
        title,
        desc,
        x,
        y,
    }
}

#[component]
pub fn SearchBar() -> impl IntoView {
    let qmap = use_query_map();
    let pathname = use_location().pathname;

    let (init_mode, init_drafts, init_limit) = if pathname.with_untracked(|p| p == "/") {
        qmap.with_untracked(|m| {
            let (m_val, q, lim) = parse_gallery_params(m.get("mode"), m.get("q"), m.get("limit"));
            let mut drafts = ModeDrafts::default();
            if !q.is_empty() {
                drafts.set(m_val, q);
            }
            (m_val, drafts, lim)
        })
    } else {
        (Mode::Tag, ModeDrafts::default(), DEFAULT_LIMIT)
    };

    let mode = RwSignal::new(init_mode);
    let drafts = RwSignal::new(init_drafts);
    let limit = RwSignal::new(init_limit);
    let file_name = RwSignal::new(String::new());
    let file_error = RwSignal::new(false);
    let encode_req_id: StoredValue<u64> = StoredValue::new(0);
    let img_query = expect_context::<ImageQuery>();
    let hovered_mode: RwSignal<Option<ModeTooltip>> = RwSignal::new(None);

    let active_q = Signal::derive(move || {
        let cur_mode = mode.get();
        drafts.with(|d| d.get(cur_mode).to_string())
    });

    // Autocomplete state for Tag (with multilingual aliases), Author, and Title modes.
    let input_focused = RwSignal::new(false);
    let suggestions: RwSignal<Vec<SearchSuggestion>> = RwSignal::new(Vec::new());
    let active_idx: RwSignal<Option<usize>> = RwSignal::new(None);
    let suggest_req_id: StoredValue<u64> = StoredValue::new(0);
    let suggest_key = Signal::derive(move || (mode.get(), active_q.get()));
    let debounced_key: Signal<(Mode, String)> = signal_debounced(suggest_key, 180.0);

    let cancel_suggestions = move || {
        suggest_req_id.set_value(suggest_req_id.get_value().wrapping_add(1));
        suggestions.set(Vec::new());
        active_idx.set(None);
    };

    // Dismiss mode tooltip on window scroll or Escape (WCAG 1.4.13).
    #[cfg(feature = "hydrate")]
    {
        let _ = use_event_listener(window(), ev::scroll, move |_| {
            if hovered_mode.with_untracked(Option::is_some) {
                hovered_mode.set(None);
            }
        });
        let _ = use_event_listener(window(), ev::keydown, move |e: ev::KeyboardEvent| {
            if e.key() == "Escape" && hovered_mode.with_untracked(Option::is_some) {
                hovered_mode.set(None);
            }
        });
    }

    // Immediately invalidate stale dropdown entries if raw input becomes ineligible
    // (e.g. while clearing during the debounce window).
    Effect::new(move |_| {
        let (cur_mode, cur_q) = suggest_key.get();
        if !should_suggest(cur_mode, &cur_q) {
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
        // Guard against firing for an outdated mode/query if state changed right before debounce fired.
        if mode.get_untracked() != cur_mode || active_q.get_untracked() != cur_q {
            return;
        }
        let next_id = suggest_req_id.get_value().wrapping_add(1);
        suggest_req_id.set_value(next_id);
        let mode_str = cur_mode.as_str().to_string();
        let expected_q = cur_q.clone();
        spawn_local(async move {
            let res = suggest_search(mode_str, cur_q).await;
            if suggest_req_id.try_get_value() != Some(next_id) {
                return;
            }
            if mode.try_get_untracked() != Some(cur_mode)
                || active_q.try_get_untracked().as_deref() != Some(expected_q.as_str())
                || input_focused.try_get_untracked() != Some(true)
            {
                return;
            }
            match res {
                Ok(items) => {
                    let _ = suggestions.try_set(items);
                    let _ = active_idx.try_set(None);
                }
                Err(_) => {
                    let _ = suggestions.try_set(Vec::new());
                    let _ = active_idx.try_set(None);
                }
            }
        });
    });

    // Keep the search bar synchronized with the URL on the main gallery route
    // (tag/author/title links, browser Back, and clicking the home logo),
    // without clobbering the user's query with internal `/details/:id` params
    // or leaking one mode's query into another mode's standalone input.
    Effect::new(move |_| {
        if pathname.with(|p| p != "/") {
            return;
        }
        qmap.with(|m| {
            let (url_mode, url_q, url_limit) =
                parse_gallery_params(m.get("mode"), m.get("q"), m.get("limit"));
            mode.set(url_mode);
            drafts.update(|d| d.set(url_mode, url_q));
            limit.set(url_limit);
            input_focused.set(false);
            cancel_suggestions();
        });
    });

    let go = {
        let nav = use_navigate();
        move |q: String| {
            input_focused.set(false);
            cancel_suggestions();
            hovered_mode.set(None);
            let mode = mode.get_untracked();
            let mut url = format!(
                "/?mode={}&q={}&limit={}",
                mode.as_str(),
                urlencoding::encode(&q),
                limit.get_untracked().max(1),
            );
            // Each random roll gets a fresh seed carried in the URL, so paging and
            // reloads reproduce the same shuffle until the user re-rolls.
            if mode == Mode::Random {
                let seed = (js_sys::Math::random() * i64::MAX as f64) as i64;
                url.push_str(&format!("&seed={seed}"));
            }
            nav(&url, NavigateOptions::default());
        }
    };

    let submit = {
        let go = go.clone();
        move |ev: leptos::ev::SubmitEvent| {
            ev.prevent_default();
            let cur_mode = mode.get_untracked();
            if cur_mode == Mode::SearchImage {
                if let Some(existing) = img_query.0.get_untracked() {
                    let nonce = format!("{}", js_sys::Date::now() as u64);
                    img_query.0.set(Some(ImageQueryPayload {
                        nonce: nonce.clone(),
                        b64: existing.b64,
                    }));
                    go(nonce);
                }
                return;
            }
            let q = drafts.with_untracked(|d| d.get(cur_mode).to_string());
            go(q);
        }
    };

    let select_mode = move |next: Mode| {
        mode.set(next);
        input_focused.set(false);
        cancel_suggestions();
        hovered_mode.set(None);
    };

    let on_file = {
        let go = go.clone();
        move |ev: leptos::ev::Event| {
            let input: web_sys::HtmlInputElement = event_target(&ev);
            let Some(file) = input.files().and_then(|fs| fs.get(0)) else {
                return;
            };
            let picked_name = file.name();
            let req = encode_req_id.get_value().wrapping_add(1);
            encode_req_id.set_value(req);
            // Clear any previous image bytes before encoding so a failed decode
            // can never submit an older image under the new filename.
            img_query.0.set(None);
            file_error.set(false);
            let go = go.clone();
            spawn_local(async move {
                let encoded = encode_file(file).await;
                if encode_req_id.try_get_value() != Some(req) {
                    return;
                }
                if let Some(b64) = encoded {
                    let nonce = format!("{}", js_sys::Date::now() as u64);
                    let _ = file_name.try_set(picked_name);
                    let _ = img_query.0.try_set(Some(ImageQueryPayload {
                        nonce: nonce.clone(),
                        b64,
                    }));
                    go(nonce);
                } else {
                    let _ = file_name.try_set(String::new());
                    let _ = file_error.try_set(true);
                }
            });
        }
    };

    let tab_cls = move |m: Mode| {
        format!(
            "px-3 py-1 rounded-full text-sm font-medium transition-all shrink-0 whitespace-nowrap cursor-pointer {}",
            if mode.get() == m {
                "bg-sky-400 text-white shadow-sm shadow-sky-300/60"
            } else {
                "text-sky-600 hover:bg-sky-200/70"
            }
        )
    };
    let random_cls = move |r: &str| {
        format!(
            "px-3 py-1 rounded-full text-sm font-medium transition-all shrink-0 whitespace-nowrap cursor-pointer {}",
            if drafts.with(|d| d.random_target == r) {
                "bg-sky-400 text-white shadow-sm shadow-sky-300/60"
            } else {
                "text-sky-600 hover:bg-sky-200/70"
            }
        )
    };

    let show_mode_tip = move |m: Mode, target: Option<web_sys::EventTarget>| {
        if let Some(el) = target.and_then(|t| t.dyn_into::<web_sys::Element>().ok()) {
            hovered_mode.set(Some(build_mode_tooltip(m, &el)));
        }
    };

    let render_mode_tab = move |m: Mode, label: &'static str| {
        view! {
            <button
                type="button"
                aria-describedby=move || {
                    hovered_mode
                        .with(|t| t.as_ref().is_some_and(|tip| tip.mode == m))
                        .then_some("mode-help-tooltip")
                }
                class=move || tab_cls(m)
                on:mouseenter=move |ev: leptos::ev::MouseEvent| show_mode_tip(m, ev.current_target())
                on:mouseleave=move |_| hovered_mode.set(None)
                on:focus=move |ev: leptos::ev::FocusEvent| show_mode_tip(m, ev.current_target())
                on:blur=move |_| hovered_mode.set(None)
                on:click=move |_| select_mode(m)
            >
                {label}
            </button>
        }
    };

    let mode_tooltip_view = move || {
        hovered_mode.get().map(|tip| {
            let style = format!(
                "left:{:.1}px;top:{:.1}px;transform:translate(-50%, 0);",
                tip.x, tip.y
            );
            view! {
                <div
                    id="mode-help-tooltip"
                    role="tooltip"
                    style=style
                    class="fixed z-[45] pointer-events-none max-w-64 px-3 py-2 rounded-xl
                           bg-slate-900/95 text-white shadow-xl ring-1 ring-white/15 backdrop-blur-md"
                >
                    <div class="text-xs font-semibold text-sky-200">{tip.title}</div>
                    <div class="text-[11px] text-slate-200/95 leading-snug mt-0.5">{tip.desc}</div>
                </div>
            }
        })
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

    view! {
        <div class="relative flex flex-col w-full h-fit sticky top-0 z-40 bg-white/85 backdrop-blur-md shadow-sm shadow-sky-200/50">
            <div class="flex flex-wrap w-full items-center gap-2.5 py-2.5 px-4 justify-center lg:justify-start">
                <a href="/" class="font-display text-2xl sm:text-3xl font-bold text-left shrink-0
                    bg-gradient-to-r from-sky-500 via-blue-500 to-cyan-400 bg-clip-text text-transparent
                    drop-shadow-sm hover:scale-105 transition-transform">
                    "Let\u{2019}s Embed \u{2728}"
                </a>
                <form class="contents" on:submit=submit>
                    <div class="flex w-full md:w-auto min-w-0 justify-center md:justify-start">
                        <div
                            class="flex gap-1 bg-sky-100/80 rounded-full p-1 max-w-full
                                   overflow-x-auto scrollbar-none overscroll-contain"
                            on:scroll=move |_| hovered_mode.set(None)
                        >
                            {render_mode_tab(Mode::Tag, "Tag")}
                            {render_mode_tab(Mode::Author, "Author")}
                            {render_mode_tab(Mode::Title, "Title")}
                            {render_mode_tab(Mode::Clip, "CLIP")}
                            {render_mode_tab(Mode::Similar, "DINO")}
                            {render_mode_tab(Mode::SearchImage, "Image")}
                            <button
                                type="button"
                                aria-describedby=move || {
                                    hovered_mode
                                        .with(|t| t.as_ref().is_some_and(|tip| tip.mode == Mode::Random))
                                        .then_some("mode-help-tooltip")
                                }
                                class=move || tab_cls(Mode::Random)
                                on:mouseenter=move |ev: leptos::ev::MouseEvent| show_mode_tip(Mode::Random, ev.current_target())
                                on:mouseleave=move |_| hovered_mode.set(None)
                                on:focus=move |ev: leptos::ev::FocusEvent| show_mode_tip(Mode::Random, ev.current_target())
                                on:blur=move |_| hovered_mode.set(None)
                                on:click={
                                    let go = go.clone();
                                    move |_| {
                                        select_mode(Mode::Random);
                                        let target = drafts.with_untracked(|d| d.random_target.clone());
                                        go(target);
                                    }
                                }
                            >"Random"</button>
                        </div>
                    </div>

                    <div class="flex w-full lg:w-auto lg:flex-1 lg:min-w-[16rem] items-center gap-2 min-w-0">
                        {
                            let go_suggest = go.clone();
                            move || if mode.get() == Mode::SearchImage {
                                let label = move || {
                                    if file_error.get() {
                                        "Could not read image — choose another…".to_string()
                                    } else {
                                        let n = file_name.get();
                                        if n.is_empty() { "Choose an image…".to_string() } else { n }
                                    }
                                };
                                view! {
                                    <label class="w-full min-w-0 truncate cursor-pointer bg-white border border-sky-200
                                                  rounded-full py-2 px-4 text-slate-600 hover:bg-sky-50 transition-colors">
                                        { label }
                                        <input
                                            type="file"
                                            accept="image/*"
                                            class="hidden"
                                            on:change=on_file.clone()
                                        />
                                    </label>
                                }.into_any()
                            } else if mode.get() == Mode::Random {
                                view! {
                                    <div class="flex grow justify-center lg:justify-start min-w-0">
                                        <div class="flex flex-wrap justify-center gap-1 bg-sky-100/80 rounded-full p-1 max-w-full">
                                            <button type="submit" class=move || random_cls("posts")
                                                on:click=move |_| drafts.update(|d| d.set(Mode::Random, "posts".to_string()))>"Posts"</button>
                                            <button type="submit" class=move || random_cls("images")
                                                on:click=move |_| drafts.update(|d| d.set(Mode::Random, "images".to_string()))>"Images"</button>
                                        </div>
                                    </div>
                                }.into_any()
                            } else {
                                let go_key = go_suggest.clone();
                                let go_pick = go_suggest.clone();
                                let dropdown_open = move || {
                                    input_focused.get() && !suggestions.with(Vec::is_empty)
                                };
                                view! {
                                    <div class="relative w-full min-w-0">
                                        <input
                                            role="combobox"
                                            aria-autocomplete="list"
                                            aria-controls="search-suggestions"
                                            aria-expanded=move || dropdown_open().to_string()
                                            aria-activedescendant=move || {
                                                dropdown_open()
                                                    .then(|| active_idx.get().map(|i| format!("search-opt-{i}")))
                                                    .flatten()
                                            }
                                            class="w-full min-w-0 bg-white border border-sky-200 rounded-full py-2 pl-4 pr-8 outline-none
                                                text-slate-700 placeholder:text-sky-400/70 focus:border-sky-400 focus:ring-2 focus:ring-sky-200 transition"
                                            autocomplete="off"
                                            placeholder=move || match mode.get() {
                                                Mode::Tag => "Tag or alias (EN / 中文 / 日本語)",
                                                Mode::Author => "Author name…",
                                                Mode::Title => "Post title…",
                                                Mode::Clip => "Describe the image…",
                                                Mode::Similar => "Image ID (e.g. 12345)",
                                                _ => ""
                                            }
                                            value=move || active_q.get()
                                            prop:value=move || active_q.get()
                                            on:focus=move |_| input_focused.set(true)
                                            on:click=move |_| input_focused.set(true)
                                            on:blur=move |_| input_focused.set(false)
                                            on:input=move |ev| {
                                                let cur_mode = mode.get_untracked();
                                                let val = event_target_value(&ev);
                                                drafts.update(|d| d.set(cur_mode, val));
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
                                                        if let Some(i) = active_idx.get_untracked()
                                                            && let Some(picked) = suggestions
                                                                .with_untracked(|s| s.get(i).map(|x| x.value.clone()))
                                                        {
                                                            ev.prevent_default();
                                                            let cur_mode = mode.get_untracked();
                                                            drafts.update(|d| d.set(cur_mode, picked.clone()));
                                                            go_key(picked);
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
                                                class="absolute right-2 top-1/2 -translate-y-1/2 w-6 h-6 rounded-full
                                                       flex items-center justify-center text-sky-400 hover:text-sky-700
                                                       hover:bg-sky-100 transition-colors cursor-pointer"
                                                on:mousedown=|ev| ev.prevent_default()
                                                on:click=move |_| {
                                                    let cur_mode = mode.get_untracked();
                                                    drafts.update(|d| d.set(cur_mode, String::new()));
                                                    cancel_suggestions();
                                                }
                                            >
                                                "×"
                                            </button>
                                        })}
                                        {move || {
                                            let items = suggestions.get();
                                            let open = input_focused.get() && !items.is_empty();
                                            let go_list = go_pick.clone();
                                            open.then(move || {
                                                view! {
                                                    <div
                                                        id="search-suggestions"
                                                        role="listbox"
                                                        class="absolute left-0 right-0 top-full mt-1.5 z-50 max-h-72 overflow-y-auto
                                                               rounded-2xl bg-white/95 backdrop-blur-md ring-1 ring-sky-200
                                                               shadow-xl shadow-sky-200/60 py-1"
                                                    >
                                                        {items.into_iter().enumerate().map(|(i, s)| {
                                                            let val = s.value.clone();
                                                            let go_item = go_list.clone();
                                                            let alias_line = (!s.aliases.is_empty())
                                                                .then(|| s.aliases.join(" · "));
                                                            let opt_id = format!("search-opt-{i}");
                                                            view! {
                                                                <button
                                                                    id=opt_id
                                                                    type="button"
                                                                    role="option"
                                                                    aria-selected=move || (active_idx.get() == Some(i)).to_string()
                                                                    class=move || if active_idx.get() == Some(i) {
                                                                        "w-full text-left px-3.5 py-2 flex flex-col gap-0.5 bg-sky-100/90 text-sky-900 cursor-pointer transition-colors"
                                                                    } else {
                                                                        "w-full text-left px-3.5 py-2 flex flex-col gap-0.5 hover:bg-sky-50 text-slate-700 cursor-pointer transition-colors"
                                                                    }
                                                                    on:mousedown=|ev| ev.prevent_default()
                                                                    on:mouseenter=move |_| active_idx.set(Some(i))
                                                                    on:click=move |_| {
                                                                        let cur_mode = mode.get_untracked();
                                                                        drafts.update(|d| d.set(cur_mode, val.clone()));
                                                                        go_item(val.clone());
                                                                    }
                                                                >
                                                                    <span class="text-sm font-medium truncate">{s.value}</span>
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
                                }.into_any()
                            }
                        }

                        {
                            move || (mode() != Mode::Random).then(|| view! {
                                <button type="submit"
                                    class="shrink-0 bg-gradient-to-r from-sky-400 to-blue-500 text-white font-medium rounded-full
                                        py-2 px-5 shadow-sm shadow-sky-300/60 hover:from-sky-500 hover:to-blue-600
                                        hover:scale-105 active:scale-95 transition-all cursor-pointer">
                                    "Search"
                                </button>
                            })
                        }
                    </div>
                </form>
            </div>
            // Floats just below the sticky bar at the top-right corner so the
            // search bar always keeps generous breathing room at every width.
            <div class="absolute top-full right-4 mt-2 z-40">
                <AccountWidget />
            </div>
            <div class="w-full h-px bg-gradient-to-r from-transparent via-sky-300 to-transparent" />
        </div>
        {mode_tooltip_view}
        <Outlet />
        <BackToTop />
    }
}

#[server(endpoint = "suggest_search")]
async fn suggest_search(mode: String, q: String) -> Result<Vec<SearchSuggestion>, ServerFnError> {
    use crate::state::AppState;
    use std::sync::Arc;

    use axum::extract::State;
    use leptos_axum::extract_with_state;
    use search_engine::Engine;

    let mode = Mode::parse(&mode);
    if !should_suggest(mode, &q) {
        return Ok(Vec::new());
    }

    let state = expect_context::<AppState>();
    let State(engine): State<Arc<Engine>> = extract_with_state(&state).await?;

    fn to_err(e: impl std::fmt::Display) -> ServerFnError {
        ServerFnError::Response(e.to_string())
    }

    let items = match mode {
        Mode::Tag => engine
            .suggest_tags(&q, 10)
            .await
            .map_err(to_err)?
            .into_iter()
            .map(|t| SearchSuggestion {
                value: t.name,
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
        assert!(!should_suggest(Mode::Tag, ""));
        assert!(!should_suggest(Mode::Tag, "a"));
        assert!(should_suggest(Mode::Tag, "bl"));
        assert!(should_suggest(Mode::Tag, "花"));
        assert!(!should_suggest(Mode::Author, "a"));
        assert!(should_suggest(Mode::Author, "ab"));
        assert!(should_suggest(Mode::Author, "猫"));
        assert!(!should_suggest(Mode::Clip, "sunset"));
    }

    #[test]
    fn gallery_url_parser_resets_limit_to_default_when_absent() {
        assert_eq!(
            parse_gallery_params(None, None, None),
            (Mode::Tag, String::new(), 50)
        );
        assert_eq!(
            parse_gallery_params(Some("clip".into()), Some("sky".into()), Some("10".into())),
            (Mode::Clip, "sky".to_string(), 10)
        );
    }

    #[test]
    fn mode_drafts_are_isolated_across_modes() {
        let mut drafts = ModeDrafts::default();
        assert_eq!(drafts.get(Mode::Random), "posts");
        assert_eq!(drafts.get(Mode::Tag), "");

        drafts.set(Mode::Random, "images".to_string());
        drafts.set(Mode::Tag, "blue_sky".to_string());
        drafts.set(Mode::Clip, "sunset on the coast".to_string());
        drafts.set(Mode::Similar, "42".to_string());

        assert_eq!(drafts.get(Mode::Random), "images");
        assert_eq!(drafts.get(Mode::Tag), "blue_sky");
        assert_eq!(drafts.get(Mode::Clip), "sunset on the coast");
        assert_eq!(drafts.get(Mode::Similar), "42");
        assert_eq!(drafts.get(Mode::Author), "");
        assert_eq!(drafts.get(Mode::Title), "");
    }
}
