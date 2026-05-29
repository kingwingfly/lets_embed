pub mod components;
pub mod types;

#[cfg(feature = "ssr")]
pub mod state;

use crate::components::{ImageDetails, Results, SearchBar};
use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::{
    components::{ParentRoute, Route, Router, Routes},
    path,
};

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options />
                <MetaTags/>
            </head>
            <body class="bg-black">
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
            <main class="bg-black h-screen w-screen max-h-screen max-w-screen">
                <Routes fallback=|| "Page not found.".into_view()>
                    <ParentRoute path=path!("") view=SearchBar>
                        <Route path=path!("/details/:id") view=ImageDetails/>
                        <Route path=path!("") view=Results/>
                    </ParentRoute>
                </Routes>
            </main>
        </Router>
    }
}
