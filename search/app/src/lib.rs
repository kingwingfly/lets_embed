pub mod components;
pub mod types;

mod util;

#[cfg(feature = "ssr")]
pub mod state;

use crate::components::{ImageDetails, Results, SearchBar};
use leptos::prelude::*;
use leptos_meta::{HashedStylesheet, Link, MetaTags, Title, provide_meta_context};
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
                <HydrationScripts options=options.clone() />
                <MetaTags />
                <Link
                    rel="icon"
                    href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🍌</text></svg>"
                />
                <HashedStylesheet options />
            </head>
            <body class="bg-black">
                <App />
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <Title formatter=|text| format!("{text} - Let's Embed")/>
        <Router>
            <main class="bg-black w-screen max-w-screen">
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
