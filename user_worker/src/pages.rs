//! UNIT 6: HTML pages (inline HTML + JS, gateway_worker aesthetic).
//!
//! Three server-rendered shells with inline vanilla JS that talks to the
//! `/user/api/*` endpoints:
//! - GET /user/login: SIWE wallet sign-in (EIP-4361 message, strict shape).
//! - GET /user/account: balance / plan / top-up / payments / logout.
//! - GET /user/favorites: paged list of likes with preview thumbnails.
//!
//! The markup/JS lives in the `pages/` directory next to this file and is pulled
//! in with `include_str!`; only the dynamic values are substituted here. Values
//! coming from Rust are passed through [`html_escape`]; JSON fetched client-side
//! is rendered with `textContent` (never innerHTML).

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use tower_cookies::Cookies;

use crate::{AppState, config, session::session_address};

// ---------------------------------------------------------------------------
// shared shell
// ---------------------------------------------------------------------------

/// Outer HTML document. `__TITLE__`, `__STYLE__` and `__BODY__` are substituted
/// per request.
const SHELL: &str = include_str!("pages/shell.html");
/// Shared stylesheet, inlined into the shell's `<style>`.
const STYLE: &str = include_str!("pages/style.css");

fn page(title: &str, body: &str) -> String {
    SHELL
        .replace("__TITLE__", title)
        .replace("__STYLE__", STYLE)
        .replace("__BODY__", body)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// 302 to the login page with a `next` back-reference.
fn redirect_to_login(next: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, format!("/user/login?next={next}"))],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /user/login
// ---------------------------------------------------------------------------

/// `__CHAIN_ID__` and `__SIWE_DOMAIN__` are substituted server-side.
const LOGIN_BODY: &str = include_str!("pages/login.html");

#[worker::send]
pub async fn login_page(State(st): State<AppState>) -> Response {
    let body = LOGIN_BODY
        .replace("__CHAIN_ID__", &st.chain_id.to_string())
        .replace("__SIWE_DOMAIN__", &st.siwe_domain);
    Html(page("Sign in — lets_embed", &body)).into_response()
}

// ---------------------------------------------------------------------------
// GET /user/account
// ---------------------------------------------------------------------------

/// Server-rendered subscription plans table (from the frozen `config::PLANS`).
fn plans_table() -> String {
    let mut rows = String::new();
    for p in config::PLANS {
        let id = html_escape(p.id);
        let views = p
            .views_per_window
            .map_or_else(|| "unlimited".to_string(), |v| v.to_string());
        rows.push_str(&format!(
            r##"<tr><td>{id}</td><td>{price}</td><td>{views}</td><td>{searches}</td><td>{days}</td>
<td><button class="btn small subscribe-btn" type="button" data-plan="{id}" data-price="{price}">Subscribe</button></td></tr>"##,
            price = p.price_points,
            searches = p.searches_per_window,
            days = p.period_secs / 86_400,
        ));
    }
    format!(
        r##"<div class="tablewrap"><table>
<thead><tr><th>Plan</th><th>Price (points)</th><th>Views / 5h</th><th>Searches / 5h</th><th>Period (days)</th><th></th></tr></thead>
<tbody>{rows}</tbody></table></div>"##
    )
}

/// Server-rendered pay-as-you-go pricing summary, derived entirely from the
/// `config::*` cost constants so it stays in sync with billing.
fn pricing_table() -> String {
    // USD equivalent of a point cost, e.g. 100 points -> "$0.0100".
    let usd = |points: i64| -> String {
        format!("${:.4}", points as f64 / config::POINTS_PER_USD as f64)
    };
    let dedupe_hours = config::DEDUPE_WINDOW_SECS / 3_600;
    format!(
        r##"<dl class="stats">
<dt>Rate</dt><dd>$1 = {rate} points</dd>
<dt>Free signup grant</dt><dd>{grant} points ({grant_usd})</dd>
</dl>
<div class="tablewrap"><table>
<thead><tr><th>Action</th><th>Cost (points)</th><th>&asymp; USD</th></tr></thead>
<tbody>
<tr><td>Image view</td><td>{img}</td><td>{img_usd}</td></tr>
<tr><td>Video view</td><td>{vid}</td><td>{vid_usd}</td></tr>
<tr><td>Description search (by text)</td><td>{sim}</td><td>{sim_usd}</td></tr>
<tr><td>Similarity search (upload image)</td><td>{desc}</td><td>{desc_usd}</td></tr>
<tr><td>Similarity search (by id)</td><td>{emb}</td><td>{emb_usd}</td></tr>
</tbody></table></div>
<p class="sub meta">Repeat views of the same item within {dedupe_hours} hours are free.</p>"##,
        rate = config::POINTS_PER_USD,
        grant = config::FREE_GRANT_POINTS,
        grant_usd = usd(config::FREE_GRANT_POINTS),
        img = config::COST_IMAGE_VIEW,
        img_usd = usd(config::COST_IMAGE_VIEW),
        vid = config::COST_VIDEO_VIEW,
        vid_usd = usd(config::COST_VIDEO_VIEW),
        sim = config::COST_SEARCH,
        sim_usd = usd(config::COST_SEARCH),
        desc = config::COST_SEARCH,
        desc_usd = usd(config::COST_SEARCH),
        emb = config::COST_EMBED_SEARCH,
        emb_usd = usd(config::COST_EMBED_SEARCH),
    )
}

/// `__DEPOSIT_ADDRESS__` (HTML-escaped), `__SOL_DEPOSIT_ADDRESS__`, `__PRICING__`
/// and `__PLANS_TABLE__` are substituted server-side.
const ACCOUNT_BODY: &str = include_str!("pages/account.html");

#[worker::send]
pub async fn account_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    if session_address(&cookies, &st.jwt_secret).is_none() {
        return redirect_to_login("/user/account");
    }
    let body = ACCOUNT_BODY
        .replace("__DEPOSIT_ADDRESS__", &html_escape(&st.deposit_address))
        .replace(
            "__SOL_DEPOSIT_ADDRESS__",
            &html_escape(&st.sol_deposit_address),
        )
        .replace("__PRICING__", &pricing_table())
        .replace("__PLANS_TABLE__", &plans_table());
    Html(page("Account — lets_embed", &body)).into_response()
}

// ---------------------------------------------------------------------------
// GET /user/favorites
// ---------------------------------------------------------------------------

// Thumbnails are resolved via the search server's /api/like_previews endpoint;
// loading them (and post covers) may consume points. Preview links carry
// `?mode=similar&q=<image_id>` so the /details page shows similar images.
const FAVORITES_BODY: &str = include_str!("pages/favorites.html");

#[worker::send]
pub async fn favorites_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    if session_address(&cookies, &st.jwt_secret).is_none() {
        return redirect_to_login("/user/favorites");
    }
    Html(page("Favorites — lets_embed", FAVORITES_BODY)).into_response()
}
