use leptos::prelude::*;
use leptos_use::{use_window, use_window_scroll};
use web_sys::{ScrollBehavior, ScrollToOptions};

#[component]
pub fn BackToTop(#[prop(default = 300.0)] threshold: f64) -> impl IntoView {
    let (_x, y) = use_window_scroll();

    let visible = move || y.get() > threshold;

    let scroll_to_top = move |_| {
        let options = ScrollToOptions::new();
        options.set_top(0.0);
        options.set_behavior(ScrollBehavior::Smooth);
        use_window()
            .as_ref()
            .unwrap() // always Some on client
            .scroll_to_with_scroll_to_options(&options);
    };

    view! {
        <button
            on:click=scroll_to_top
            aria-label="back to top"
            title="back to top"
            class=move || {
                let base = "fixed right-6 bottom-6 z-50 flex h-11 w-11 items-center justify-center \
                            rounded-full bg-gradient-to-br from-sky-400 to-blue-500 text-xl text-white \
                            shadow-lg shadow-sky-400/40 cursor-pointer \
                            transition-all duration-300 ease-out hover:from-sky-500 hover:to-blue-600 hover:scale-110 \
                            active:scale-95";
                if visible() {
                    format!("{base} opacity-100 translate-y-0 pointer-events-auto")
                } else {
                    format!("{base} opacity-0 translate-y-4 pointer-events-none")
                }
            }
        >
            "🔝"
        </button>
    }
}
