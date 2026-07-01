use crate::components::BackToTop;
use crate::types::{ImageQuery, Mode};
use js_sys::futures::JsFuture;
use leptos::{prelude::*, task::spawn_local};
use leptos_router::{
    NavigateOptions,
    components::Outlet,
    hooks::{use_navigate, use_query_map},
};
use wasm_bindgen::{JsCast as _, JsValue};
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, ImageBitmap};

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

#[component]
pub fn SearchBar() -> impl IntoView {
    let qmap = use_query_map();

    let (init_mode, init_q, init_limit) = qmap.with_untracked(|m| {
        (
            m.get("mode")
                .as_deref()
                .map(Mode::parse)
                .unwrap_or(Mode::Tag),
            m.get("q").unwrap_or_default(),
            m.get("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(50),
        )
    });

    let mode = RwSignal::new(init_mode);
    let q_input = RwSignal::new(init_q);
    let limit = RwSignal::new(init_limit);
    let file_name = RwSignal::new(String::new());
    let img_query = expect_context::<ImageQuery>();

    let go = {
        let nav = use_navigate();
        move |q: String| {
            let url = format!(
                "/?mode={}&q={}&limit={}",
                mode.get_untracked().as_str(),
                urlencoding::encode(&q),
                limit.get_untracked().max(1),
            );
            nav(&url, NavigateOptions::default());
        }
    };

    let submit = {
        let go = go.clone();
        move |ev: leptos::ev::SubmitEvent| {
            ev.prevent_default();
            go(q_input.get_untracked());
        }
    };

    let on_file = {
        let go = go.clone();
        move |ev: leptos::ev::Event| {
            let input: web_sys::HtmlInputElement = event_target(&ev);
            let Some(file) = input.files().and_then(|fs| fs.get(0)) else {
                return;
            };
            file_name.set(file.name());
            let go = go.clone();
            spawn_local(async move {
                if let Some(b64) = encode_file(file).await {
                    // Keep the (potentially large) image out of the URL: stash it
                    // in client memory and navigate with only a short nonce so the
                    // Results component re-runs its search against the stored bytes.
                    img_query.0.set(Some(b64));
                    go(format!("{}", js_sys::Date::now() as u64));
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
            if q_input.read().as_str() == r {
                "bg-sky-400 text-white shadow-sm shadow-sky-300/60"
            } else {
                "text-sky-600 hover:bg-sky-200/70"
            }
        )
    };

    view! {
        <div class="flex flex-col w-full h-fit sticky top-0 z-40 bg-white/80 backdrop-blur-md shadow-sm shadow-sky-200/50">
            <div class="flex flex-wrap w-full items-center gap-2 py-2 px-4 justify-center lg:justify-start">
                <a href="/" class="font-display text-3xl font-bold text-center w-full md:w-auto max-w-64 mx-auto md:mx-0 shrink-0
                    bg-gradient-to-r from-sky-500 via-blue-500 to-cyan-400 bg-clip-text text-transparent
                    drop-shadow-sm hover:scale-105 transition-transform">
                    "Let\u{2019}s Embed \u{2728}"
                </a>
                <form class="contents" on:submit=submit>
                    <div class="flex w-full md:w-auto min-w-0 justify-center md:justify-start">
                        <div class="flex gap-1 bg-sky-100/80 rounded-full p-1 max-w-full
                            overflow-x-auto scrollbar-none overscroll-contain scrollbar-gutter-auto"
                        >
                            <button type="button" class=move || tab_cls(Mode::Tag)
                                on:click=move |_| mode.set(Mode::Tag)>"Tag"</button>
                            <button type="button" class=move || tab_cls(Mode::Author)
                                on:click=move |_| mode.set(Mode::Author)>"Author"</button>
                            <button type="button" class=move || tab_cls(Mode::Title)
                                on:click=move |_| mode.set(Mode::Title)>"Title"</button>
                            <button type="button" class=move || tab_cls(Mode::Clip)
                                on:click=move |_| mode.set(Mode::Clip)>"CLIP"</button>
                            <button type="button" class=move || tab_cls(Mode::Similar)
                                on:click=move |_| mode.set(Mode::Similar)>"DINO"</button>
                            <button type="button" class=move || tab_cls(Mode::SearchImage)
                                on:click=move |_| mode.set(Mode::SearchImage)>"Image"</button>
                            <button type="button" class=move || tab_cls(Mode::Random)
                                on:click={
                                    let go = go.clone();
                                    move |_| {
                                        mode.set(Mode::Random);
                                        if q_input.with_untracked(|q| !["posts", "images"].contains(&q.as_str())) {
                                            q_input.set("posts".to_string());
                                        }
                                        go(q_input.get_untracked());
                                    }
                                }
                            >"Random"</button>
                        </div>
                    </div>

                    <div class="flex w-full lg:w-auto lg:flex-1 items-center gap-2 min-w-0">
                        {
                            move || if mode.get() == Mode::SearchImage {
                                let label = move || {
                                    let n = file_name.get();
                                    if n.is_empty() { "Choose an image…".to_string() } else { n }
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
                                    <div class="flex grow justify-center min-w-0">
                                        <div class="flex flex-wrap justify-center gap-1 bg-sky-100/80 rounded-full p-1 max-w-full">
                                            <button type="submit" class=move || random_cls("posts")
                                                on:click=move |_| q_input.set("posts".to_string())>"Posts"</button>
                                            <button type="submit" class=move || random_cls("images")
                                                on:click=move |_| q_input.set("images".to_string())>"Images"</button>
                                        </div>
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <input
                                        class="w-full min-w-0 bg-white border border-sky-200 rounded-full py-2 px-4 outline-none
                                            text-slate-700 placeholder:text-sky-400/70 focus:border-sky-400 focus:ring-2 focus:ring-sky-200 transition"
                                        placeholder=move || match mode.get() {
                                            Mode::Tag => "One tag",
                                            Mode::Author => "One author name",
                                            Mode::Title => "One title",
                                            Mode::Clip => "Describe the image...",
                                            Mode::Similar => "Image ID",
                                            _ => ""
                                        }
                                        prop:value=move || q_input.get()
                                        on:input=move |ev| q_input.set(event_target_value(&ev))
                                    />
                                }.into_any()
                            }
                        }

                        <input type="number" min="1"
                            class="w-16 sm:w-20 shrink-0 bg-white border border-sky-200 rounded-full py-2 px-3 outline-none
                                text-slate-700 focus:border-sky-400 focus:ring-2 focus:ring-sky-200 transition"
                            prop:value=move || limit.get().to_string()
                            on:change=move |ev| {
                                if let Ok(v) = event_target_value(&ev).parse::<usize>() && v >= 1 {
                                    limit.set(v);
                                }
                            }
                        />

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
            <div class="w-full h-px bg-gradient-to-r from-transparent via-sky-300 to-transparent" />
        </div>
        <Outlet />
        <BackToTop />
    }
}
