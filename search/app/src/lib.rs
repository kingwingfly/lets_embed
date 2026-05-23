use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::{
    StaticSegment,
    components::{Route, Router, Routes},
};
use serde::{Deserialize, Serialize};

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options islands=true />
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Title formatter=|text| format!("{text} - Let's Embed")/>
        <Stylesheet href="/pkg/search.css"/>
        <Router>
            <main class="bg-black w-screen h-screen">
                <Routes fallback=|| "Page not found.".into_view()>
                    <Route path=StaticSegment("") view=HomePage/>
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    view! {
        <div class="flex flex-col md:flex-row w-full items-center justify-items-center gap-2 py-2">
            <div class="text-white text-4xl font-bold text-center w-full md:w-1/3 max-w-64 shrink-0">
                "Let's Embed"
            </div>
            <div class="w-full">
                <SearchBar />
            </div>
        </div>
        <hr class="w-full h-1 bg-gray-200 border-0" />
    }
}

#[island]
fn SearchBar() -> impl IntoView {
    let action = ServerAction::<Search>::new();
    view! {
        <ActionForm action attr:class="flex w-full items-center gap-4 px-4">
            <input
                class="w-full bg-gray-200 rounded-lg py-2 px-4"
                name="query"
                placeholder="Type something here."
            />
            <button
                class="w-fit bg-gray-500 text-white rounded-lg py-2 px-2 hover:bg-gray-400"
            >
                "Search"
            </button>
        </ActionForm>
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SearchForm {
    query: String,
}

#[server]
async fn search(_q: SearchForm) -> Result<(), ServerFnError> {
    Ok(())
}
