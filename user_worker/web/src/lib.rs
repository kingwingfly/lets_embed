//! Leptos 0.8 CSR SPA for `/user/*` (`user_worker`), reusing `lets-embed-ui`.

mod api;
mod pages;
mod wallet;

use leptos::prelude::*;
use wasm_bindgen::{JsCast, prelude::wasm_bindgen};

const USER_APP_CSS: &str = include_str!("styles.css");

#[component]
fn UserApp() -> impl IntoView {
    let path = api::current_pathname();
    let route_view = match path.trim_end_matches('/') {
        "/user/login/approve" => view! { <pages::approve::ApprovePage /> }.into_any(),
        "/user/account" => view! { <pages::account::AccountPage /> }.into_any(),
        "/user/favorites" => view! { <pages::favorites::FavoritesPage /> }.into_any(),
        "/user/upgrade" => view! { <pages::upgrade::UpgradePage /> }.into_any(),
        _ => view! { <pages::login::LoginPage /> }.into_any(),
    };

    view! {
        <style>{lets_embed_ui::UI_CSS}{USER_APP_CSS}</style>
        {route_view}
    }
}

#[wasm_bindgen(start)]
pub fn start() {
    let root = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id("user-app-root"))
        .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok());

    if let Some(el) = root {
        el.set_inner_html("");
        leptos::mount::mount_to(el, UserApp).forget();
    } else {
        leptos::mount::mount_to_body(UserApp);
    }
}
