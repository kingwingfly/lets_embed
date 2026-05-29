use crate::types::Mode;
use leptos::prelude::*;
use leptos_router::NavigateOptions;
use leptos_router::components::Outlet;
use leptos_router::hooks::{use_navigate, use_query_map};

#[component]
pub fn SearchBar() -> impl IntoView {
    let qmap = use_query_map();
    let nav = use_navigate();

    let (init_mode, init_q, init_limit) = qmap.with_untracked(|m| {
        (
            Mode::parse(m.get("mode").as_deref().unwrap_or("tag")),
            m.get("q").unwrap_or_default(),
            m.get("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(50),
        )
    });

    let mode = RwSignal::new(init_mode);
    let q_input = RwSignal::new(init_q);
    let limit = RwSignal::new(init_limit);

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let url = format!(
            "/?mode={}&q={}&limit={}",
            mode.read().as_str(),
            urlencoding::encode(q_input.read().as_str()),
            limit.read().max(1),
        );
        nav(&url, NavigateOptions::default());
    };

    let tab_cls = move |m: Mode| {
        format!(
            "px-3 py-1 rounded text-sm transition-colors {}",
            if mode.get() == m {
                "bg-gray-500 text-white"
            } else {
                "text-gray-300 hover:text-white"
            }
        )
    };

    view! {
        <div class="flex flex-col w-full h-fit sticky top-0 z-40 bg-black">
            <div class="flex flex-col md:flex-row w-full items-center gap-2 py-2">
                <a href="/" class="text-white text-3xl font-bold text-center w-full md:w-1/4 max-w-64 shrink-0">
                    "Let's Embed"
                </a>
                <form class="flex w-full items-center gap-2 px-4" on:submit=submit>
                    <div class="flex gap-1 bg-gray-800 rounded-lg p-1 shrink-0">
                        <button type="button"
                            class=move || tab_cls(Mode::Tag)
                            on:click=move |_| mode.set(Mode::Tag)>"Tag"</button>
                        <button type="button"
                            class=move || tab_cls(Mode::Clip)
                            on:click=move |_| mode.set(Mode::Clip)>"CLIP"</button>
                    </div>
                    <input
                        class="w-full bg-gray-200 rounded-lg py-2 px-4 outline-none"
                        placeholder=move || match mode.get() {
                            Mode::Tag => "regex to match tags",
                            Mode::Clip => "Describe the image...",
                            _ => "Describe the image...",
                        }
                        prop:value=move || q_input.get()
                        on:input=move |ev| q_input.set(event_target_value(&ev))
                    />
                    <input type="number" min="1"
                        class="w-20 bg-gray-200 rounded-lg py-2 px-2 outline-none"
                        prop:value=move || limit.get().to_string()
                        on:change=move |ev| {
                            if let Ok(v) = event_target_value(&ev).parse::<usize>() && v >= 1 {
                                limit.set(v);
                            }
                        }
                    />
                    <button type="submit"
                        class="shrink-0 bg-gray-500 text-white rounded-lg py-2 px-4 hover:bg-gray-400">
                        "Search"
                    </button>
                </form>
            </div>
            <hr class="w-full h-1 bg-gray-200 border-0" />
        </div>
        <Outlet />
    }
}
