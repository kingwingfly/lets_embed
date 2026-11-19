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

/// Render the plan terms currently offered to customers.
fn plans_table(policy: &crate::settings::Policy) -> String {
    let mut rows = String::new();
    for p in config::PLANS.iter().filter_map(|p| policy.plan(p.id)) {
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

/// Display prices and free allowances from the same revision used by the account service.
fn pricing_table(policy: &crate::settings::Policy) -> String {
    use std::fmt::Write;
    let mut rows = String::new();
    for kind in site_access::ChargeKind::ALL {
        let item = policy.item(kind);
        let free = match item.daily_free {
            -1 => "Unlimited".to_owned(),
            n => n.to_string(),
        };
        let usd = item.price as f64 / policy.points_per_usd as f64;
        write!(
            rows,
            "<tr><th>{}</th><td>{}</td><td>${usd:.4}</td><td>{free}</td></tr>",
            kind.label(),
            item.price
        )
        .unwrap();
    }
    format!(
        r#"<dl class="stats"><dt>Points per USD</dt><dd>{}</dd><dt>Minimum top-up</dt><dd>{} points</dd><dt>New wallet grant</dt><dd>{} points</dd></dl>
<div class="tablewrap"><table><thead><tr><th>Item</th><th>Points</th><th>USD</th><th>Free per UTC day</th></tr></thead><tbody>{rows}</tbody></table></div>
<p class="sub meta">Repeat views of the same item within {} hours are free.</p>"#,
        policy.points_per_usd,
        policy.minimum_topup,
        policy.signup_points,
        config::DEDUPE_WINDOW_SECS / 3600
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
    let policy = match crate::settings::load(&st.env).await {
        Ok(p) => p,
        Err(_) => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Account settings unavailable",
            )
                .into_response();
        }
    };
    let body = ACCOUNT_BODY
        .replace("__DEPOSIT_ADDRESS__", &html_escape(&policy.eth_deposit))
        .replace("__SOL_DEPOSIT_ADDRESS__", &html_escape(&policy.sol_deposit))
        .replace("__PRICING__", &pricing_table(&policy))
        .replace("__PLANS_TABLE__", &plans_table(&policy));
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
