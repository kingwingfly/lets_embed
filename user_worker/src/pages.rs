//! Server-rendered gallery pages. Wallet and payment actions use the existing user APIs.

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
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

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Page {
    Login,
    Approve,
    Upgrade,
    Account,
    Favorites,
    Admin,
}

impl Page {
    pub(crate) fn render(self, body: &str) -> String {
        let title = match self {
            Self::Login => "Sign in",
            Self::Approve => "Approve sign-in",
            Self::Upgrade => "Continue exploring",
            Self::Account => "Your account",
            Self::Favorites => "Favorites",
            Self::Admin => "Gallery controls",
        };
        let gallery = if self == Self::Admin {
            "View gallery"
        } else {
            "Gallery"
        };
        let mut nav = format!(r#"<a href="/">{gallery}</a>"#);
        if matches!(self, Self::Account | Self::Favorites) {
            for (screen, path, label) in [
                (Self::Account, "/user/account", "Account"),
                (Self::Favorites, "/user/favorites", "Favorites"),
            ] {
                let current = if self == screen {
                    r#" aria-current="page""#
                } else {
                    ""
                };
                nav.push_str(&format!(r#"<a href="{path}"{current}>{label}</a>"#));
            }
        } else if self == Self::Admin {
            nav.push_str(r#"<a href="/user/admin" aria-current="page">Admin</a>"#);
        }
        let extra_css = match self {
            Self::Admin => include_str!("pages/admin.css"),
            Self::Favorites => include_str!("pages/favorites.css"),
            _ => "",
        };
        let media_script = if self == Self::Favorites {
            include_str!("../../assets/gallery-allowance.js")
        } else {
            ""
        };
        SHELL
            .replace("__TITLE__", title)
            .replace("__STYLE__", STYLE)
            .replace("__EXTRA_STYLE__", extra_css)
            .replace("__MEDIA_SCRIPT__", media_script)
            .replace("__NAV__", &nav)
            .replace("__BODY__", body)
    }
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
const APPROVE_BODY: &str = include_str!("pages/approve.html");

#[worker::send]
pub async fn login_page(State(st): State<AppState>) -> Response {
    wallet_page(&st, Page::Login, "")
}

#[worker::send]
pub async fn approve_page(State(st): State<AppState>) -> Response {
    let body = APPROVE_BODY
        .replace("__CHAIN_ID__", &st.chain_id.to_string())
        .replace("__SIWE_DOMAIN__", &st.siwe_domain);
    Html(Page::Approve.render(&body)).into_response()
}

#[worker::send]
pub async fn upgrade_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    if session_address(&cookies, &st.jwt_secret).is_some() {
        return Redirect::to("/user/account#topup").into_response();
    }
    let terms = match crate::settings::load(&st.env).await {
        Ok(p)
            if !crate::settings::valid_deposit_address(config::Chain::Ethereum, &p.eth_deposit)
                && !crate::settings::valid_deposit_address(
                    config::Chain::Solana,
                    &p.sol_deposit,
                ) =>
        {
            "<p class=\"hint\">New deposits are currently closed. You can still use existing points.</p>".to_owned()
        }
        Ok(p) => format!(
            r#"<dl class="wallet-terms"><div><dt>Points per USD</dt><dd>{}</dd></div><div><dt>Minimum top-up</dt><dd>{}</dd></div></dl>"#,
            p.points_per_usd, points(p.minimum_topup)
        ),
        Err(_) => String::new(),
    };
    wallet_page(&st, Page::Upgrade, &terms)
}

fn wallet_page(st: &AppState, screen: Page, terms: &str) -> Response {
    let (heading, intro) = if screen == Page::Upgrade {
        (
            "Continue exploring",
            "This item is outside your free allowance. Sign in to use your wallet’s points and see your payment options.",
        )
    } else {
        ("Sign in", "Choose a wallet to open your gallery account.")
    };
    let body = LOGIN_BODY
        .replace("__HEADING__", heading)
        .replace("__INTRO__", intro)
        .replace("__TERMS__", terms)
        .replace("__CHAIN_ID__", &st.chain_id.to_string())
        .replace("__SIWE_DOMAIN__", &st.siwe_domain);
    Html(screen.render(&body)).into_response()
}

// ---------------------------------------------------------------------------
// GET /user/account
// ---------------------------------------------------------------------------

fn points(amount: i64) -> String {
    let unit = if amount == 1 { "point" } else { "points" };
    format!("{amount} {unit}")
}

/// Render the plan terms currently offered to customers.
fn plans_table(policy: &crate::settings::Policy) -> String {
    let mut rows = String::new();
    for p in config::PLANS.iter().filter_map(|p| policy.plan(p.id)) {
        let id = html_escape(p.id);
        let views = p
            .views_per_window
            .map_or_else(|| "unlimited".to_string(), |v| v.to_string());
        rows.push_str(&format!(
            r#"<div class="plan-offer"><div><h3>{id}</h3><strong>{display_price} · {days} days</strong>
<p>{views} view units · {searches} searches per 5h</p></div>
<button class="btn small secondary subscribe-btn" type="button" aria-label="Subscribe to {id}" data-plan="{id}" data-price="{price}">Subscribe</button></div>"#,
            price = p.price_points,
            display_price = points(p.price_points),
            searches = p.searches_per_window,
            days = p.period_secs / 86_400,
        ));
    }
    rows
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
        r#"<dl class="stats"><dt>Points per USD</dt><dd>{}</dd><dt>Minimum top-up</dt><dd>{}</dd><dt>New wallet grant</dt><dd>{}</dd></dl>
<div class="tablewrap"><table><thead><tr><th>Item</th><th>Points</th><th>USD</th><th>Free per UTC day</th></tr></thead><tbody>{rows}</tbody></table></div>
<p class="sub meta">Repeat views of the same item within {} hours are free.</p>"#,
        policy.points_per_usd,
        points(policy.minimum_topup),
        points(policy.signup_points),
        config::DEDUPE_WINDOW_SECS / 3600
    )
}

const ACCOUNT_BODY: &str = include_str!("pages/account.html");

#[worker::send]
pub async fn account_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(account) = session_address(&cookies, &st.jwt_secret) else {
        return redirect_to_login("/user/account");
    };
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
    let options: String = config::TOKENS
        .iter()
        .map(|spec| {
            format!(
                r#"<option data-chain="{}" data-decimals="{}" value="{}">{}</option>"#,
                spec.chain.as_str(),
                spec.decimals,
                spec.symbol,
                spec.symbol.to_ascii_uppercase()
            )
        })
        .collect();
    let eth_deposit =
        if crate::settings::valid_deposit_address(config::Chain::Ethereum, &policy.eth_deposit) {
            policy.eth_deposit.as_str()
        } else {
            ""
        };
    let sol_deposit =
        if crate::settings::valid_deposit_address(config::Chain::Solana, &policy.sol_deposit) {
            policy.sol_deposit.as_str()
        } else {
            ""
        };
    let body = ACCOUNT_BODY
        .replace("__ACCOUNT__", &html_escape(&account))
        .replace("__ASSET_OPTIONS__", &options)
        .replace("__POINTS_PER_USD__", &policy.points_per_usd.to_string())
        .replace("__MINIMUM__", &points(policy.minimum_topup))
        .replace("__DEPOSIT_ADDRESS__", &html_escape(eth_deposit))
        .replace("__SOL_DEPOSIT_ADDRESS__", &html_escape(sol_deposit))
        .replace("__PRICING__", &pricing_table(&policy))
        .replace("__PLANS_TABLE__", &plans_table(&policy))
        .replace("__TOPUP_SCRIPT__", include_str!("pages/topup.js"));
    Html(Page::Account.render(&body)).into_response()
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
    let body = FAVORITES_BODY.replace("__FAVORITES_SCRIPT__", include_str!("pages/favorites.js"));
    Html(Page::Favorites.render(&body)).into_response()
}
