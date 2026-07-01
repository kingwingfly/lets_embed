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
                    href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>💠</text></svg>"
                />
                <Link rel="preconnect" href="https://fonts.googleapis.com" />
                <Link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="" />
                <Link
                    rel="stylesheet"
                    href="https://fonts.googleapis.com/css2?family=Fredoka:wght@500;600;700&display=swap"
                />
                <HashedStylesheet options />
            </head>
            <body class="bg-sky-50 text-slate-700">
                <App />
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    provide_context(crate::types::ImageQuery(RwSignal::new(None)));
    view! {
        <Title formatter=|text| format!("{text} - Let's Embed")/>
        <Router>
            <main class="min-h-screen w-screen max-w-screen bg-gradient-to-b from-sky-50 via-white to-sky-100">
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
