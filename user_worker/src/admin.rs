//! UNIT 7: admin user management, protected by Cloudflare Access.
//!
//! Only the dedicated, platform-configured admin service binding can convey the
//! identity authenticated at the gateway. Direct HTTP and ordinary bindings deny access.

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use std::collections::HashMap;
use worker::{Env, Method, Result};

use crate::{
    AppState, do_client,
    session::is_valid_principal,
    types::{BanReq, CreditReq, StatusResp},
};

#[derive(Debug, Deserialize)]
pub struct AdminQuery {
    /// Optional address-prefix filter for the user list.
    pub q: Option<String>,
    /// Show DO status + actions for this user.
    pub address: Option<String>,
    pub saved: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct CreditForm {
    pub address: String,
    /// May be negative to deduct.
    pub points: i64,
    pub reason: String,
    /// Per-render idempotency token embedded in the credit form. Reused verbatim
    /// as the DO credit key so an accidental resubmission (browser refresh /
    /// double-click) dedupes instead of applying the credit twice. Optional for
    /// backward compatibility with an already-open older form.
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct BanForm {
    pub address: String,
    /// 1 = ban, 0 = unban.
    pub banned: i64,
}

// ---------------------------------------------------------------------------
// Administrator identity forwarded by the gateway through its privileged binding
// ---------------------------------------------------------------------------

fn require_approver<'a>(st: &AppState, headers: &'a HeaderMap) -> Option<&'a str> {
    if !st.admin_binding {
        return None;
    }
    headers
        .get(site_access::ADMIN_HEADER)?
        .to_str()
        .ok()
        .filter(|s| !s.trim().is_empty())
}

fn same_origin(headers: &HeaderMap, domain: &str) -> bool {
    headers
        .get("origin")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|origin| {
            origin == format!("https://{domain}")
                || (domain
                    .split(':')
                    .next()
                    .is_some_and(|h| matches!(h, "localhost" | "127.0.0.1"))
                    && origin == format!("http://{domain}"))
        })
}

fn editor<'a>(st: &AppState, h: &'a HeaderMap) -> Option<&'a str> {
    if !same_origin(h, &st.siwe_domain) {
        return None;
    }
    require_approver(st, h)
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Administrator access required").into_response()
}

fn internal_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

// ---------------------------------------------------------------------------
// D1
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UserRow {
    address: String,
    created_at: i64,
    last_login: i64,
    plan: Option<String>,
    banned: i64,
}

async fn db_list_users(env: &Env, q: Option<&str>) -> Result<Vec<UserRow>> {
    let db = env.d1(crate::D1_BINDING)?;
    let stmt = match q {
        Some(q) => db
            .prepare(
                "SELECT address, created_at, last_login, plan, banned FROM users \
                 WHERE address LIKE ?||'%' ORDER BY last_login DESC LIMIT 200",
            )
            .bind(&[q.into()])?,
        None => db.prepare(
            "SELECT address, created_at, last_login, plan, banned FROM users \
             ORDER BY last_login DESC LIMIT 200",
        ),
    };
    stmt.all().await?.results::<UserRow>()
}

async fn db_user_exists(env: &Env, address: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct Row {
        #[allow(dead_code)]
        address: String,
    }
    Ok(env
        .d1(crate::D1_BINDING)?
        .prepare("SELECT address FROM users WHERE address = ?")
        .bind(&[address.into()])?
        .first::<Row>(None)
        .await?
        .is_some())
}

/// Validate a form address: must look like a lowercase eth address (400) and
/// exist in `users` (404). Returns an error response on failure.
async fn validate_form_address(env: &Env, address: &str) -> std::result::Result<(), Response> {
    if !is_valid_principal(address) {
        return Err((StatusCode::BAD_REQUEST, "invalid address").into_response());
    }
    match db_user_exists(env, address).await {
        Ok(true) => Ok(()),
        Ok(false) => Err((StatusCode::NOT_FOUND, "unknown user").into_response()),
        Err(e) => {
            worker::console_error!("user lookup failed: {e:?}");
            Err(internal_error())
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[worker::send]
pub async fn admin_page(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AdminQuery>,
) -> Response {
    let Some(admin) = require_approver(&st, &headers) else {
        return forbidden();
    };

    let filter =
        q.q.as_deref()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty());
    let rows = match db_list_users(&st.env, filter.as_deref()).await {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("user list failed: {e:?}");
            return internal_error();
        }
    };

    let detail = match q.address.as_deref().filter(|a| is_valid_principal(a)) {
        Some(addr) => match do_client::do_status(&st.env, addr).await {
            Ok(s) => Some(s),
            Err(e) => {
                worker::console_error!("do status for {addr} failed: {e:?}");
                return internal_error();
            }
        },
        None => None,
    };

    let published = match crate::settings::Published::load(&st.env).await {
        Ok(p) => p,
        Err(e) => {
            worker::console_error!("site settings: {e}");
            return internal_error();
        }
    };
    let page = render_admin(
        admin,
        filter.as_deref().unwrap_or(""),
        &rows,
        detail.as_ref(),
        &published,
        q.saved == Some(1),
    );
    Html(page).into_response()
}

#[worker::send]
pub async fn credit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreditForm>,
) -> Response {
    let Some(actor) = editor(&st, &headers) else {
        return forbidden();
    };
    if let Err(resp) = validate_form_address(&st.env, &form.address).await {
        return resp;
    }

    if form.points == 0
        || form.points.unsigned_abs() > crate::settings::MAX_VALUE as u64
        || form.reason.trim().is_empty()
        || form.reason.len() > 300
    {
        return (
            StatusCode::BAD_REQUEST,
            "Enter a nonzero adjustment and a reason",
        )
            .into_response();
    }
    // Prefer the form's idempotency token so a refresh/replay of the same form
    // dedupes in the DO; fall back to a fresh uuid only if it's missing.
    let token = if form.token.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        form.token.clone()
    };
    let req = CreditReq {
        points: form.points,
        key: format!("admin:{token}"),
        reason: form.reason,
    };
    match do_client::do_credit(&st.env, &form.address, &req).await {
        Ok(receipt) if receipt.applied => worker::console_log!(
            "Administrator {actor} adjusted {} by {} points, reason {:?}",
            form.address,
            req.points,
            req.reason
        ),
        Ok(_) => {}
        Err(e) => {
            worker::console_error!("do credit for {} failed: {e:?}", form.address);
            return internal_error();
        }
    }

    Redirect::to(&format!("/user/admin?address={}#accounts", form.address)).into_response()
}

#[worker::send]
pub async fn ban(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BanForm>,
) -> Response {
    if editor(&st, &headers).is_none() {
        return forbidden();
    }
    if let Err(resp) = validate_form_address(&st.env, &form.address).await {
        return resp;
    }
    let banned = form.banned != 0;

    // DO is the enforcement authority — update it first.
    match do_client::call_do(
        &st.env,
        &form.address,
        Method::Post,
        "/ban",
        Some(&BanReq { banned }),
    )
    .await
    {
        Ok(resp) if resp.status_code() == 200 => {}
        Ok(resp) => {
            worker::console_error!("do ban for {} failed: {}", form.address, resp.status_code());
            return internal_error();
        }
        Err(e) => {
            worker::console_error!("do ban for {} failed: {e:?}", form.address);
            return internal_error();
        }
    }

    // Mirror into D1 for the admin list.
    let stmt = st.env.d1(crate::D1_BINDING).and_then(|db| {
        db.prepare("UPDATE users SET banned = ? WHERE address = ?")
            .bind(&[((banned as i64) as f64).into(), form.address.clone().into()])
    });
    match stmt {
        Ok(s) if s.run().await.is_ok() => {}
        _ => {
            worker::console_error!("ban mirror for {} failed", form.address);
            return internal_error();
        }
    }

    Redirect::to(&format!("/user/admin?address={}#accounts", form.address)).into_response()
}

// ---------------------------------------------------------------------------
// Persist admin changes

#[worker::send]
pub async fn save_settings(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    let Some(admin) = editor(&st, &headers) else {
        return forbidden();
    };
    let (revision, policy) = match crate::settings::Policy::from_form(&fields) {
        Ok(p) => p,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    match crate::settings::Published::save(&st.env, revision, &policy, admin).await {
        Ok(true) => Redirect::to("/user/admin?saved=1").into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            "Settings changed in another tab. Reload the dashboard and reapply your edits.",
        )
            .into_response(),
        Err(e) => {
            worker::console_error!("save settings: {e}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct PlanForm {
    address: String,
    plan: String,
    days: u32,
    token: String,
}
#[worker::send]
pub async fn set_plan(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<PlanForm>,
) -> Response {
    if editor(&st, &headers).is_none() {
        return forbidden();
    }
    if let Err(r) = validate_form_address(&st.env, &f.address).await {
        return r;
    }
    if (f.plan != "none" && crate::config::plan(&f.plan).is_none())
        || !(1..=3650).contains(&f.days)
        || uuid::Uuid::parse_str(&f.token).is_err()
    {
        return (StatusCode::BAD_REQUEST, "Invalid subscription adjustment").into_response();
    }
    let req = crate::types::AdminPlanReq {
        plan: f.plan,
        days: f.days,
        token: f.token,
    };
    let status = match do_client::call_do(
        &st.env,
        &f.address,
        Method::Post,
        "/admin-plan",
        Some(&req),
    )
    .await
    {
        Ok(mut r) if r.status_code() == 200 => r.json::<StatusResp>().await,
        _ => return internal_error(),
    };
    let Ok(status) = status else {
        return internal_error();
    };
    let mirror = st.env.d1(crate::D1_BINDING).and_then(|db| {
        db.prepare("UPDATE users SET plan=? WHERE address=?")
            .bind(&[
                status
                    .plan
                    .map(Into::into)
                    .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
                f.address.as_str().into(),
            ])
    });
    match mirror {
        Ok(q) if q.run().await.is_ok() => {}
        _ => return internal_error(),
    }
    Redirect::to(&format!("/user/admin?address={}#accounts", f.address)).into_response()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn banned_badge(banned: bool) -> &'static str {
    if banned {
        r#"<span class="badge err">Banned</span>"#
    } else {
        r#"<span class="badge ok">Active</span>"#
    }
}

fn render_detail(s: &StatusResp) -> String {
    let addr = html_escape(&s.address);
    let plan = html_escape(s.plan.as_deref().unwrap_or("none"));
    let period_end = if s.period_end == 0 {
        "—".to_string()
    } else {
        fmt_ts(s.period_end as i64)
    };
    // No plan → "—"; active plan with no cap (pro) → "Unlimited"; else the count.
    let views_rem = match s.views_remaining {
        Some(v) => v.to_string(),
        None if s.plan.is_none() => "—".to_string(),
        None => "Unlimited".to_string(),
    };
    let searches_rem = s
        .searches_remaining
        .map_or_else(|| "—".to_string(), |v| v.to_string());
    let window_reset = if s.window_reset == 0 {
        "—".to_string()
    } else {
        fmt_ts(s.window_reset as i64)
    };
    let (ban_value, ban_label) = if s.banned { (0, "Unban") } else { (1, "Ban") };
    format!(
        r#"<div class="card">
<h2>User <span class="mono">{addr}</span></h2>
<dl class="status">
<dt>Balance</dt><dd>{balance}</dd>
<dt>Plan</dt><dd>{plan}</dd>
<dt>Period end</dt><dd>{period_end}</dd>
<dt>Views remaining</dt><dd>{views_rem}</dd>
<dt>Searches remaining</dt><dd>{searches_rem}</dd>
<dt>Window reset</dt><dd>{window_reset}</dd>
<dt>Total views</dt><dd>{views}</dd>
<dt>Status</dt><dd>{badge}</dd>
</dl>
<div class="actions">
<form method="post" action="/user/admin/credit">
<input type="hidden" name="address" value="{addr}">
<input type="hidden" name="token" value="{token}">
<input type="number" name="points" aria-label="Point adjustment" required placeholder="points (&plusmn;)">
<input type="text" name="reason" aria-label="Adjustment reason" required placeholder="reason">
<button class="btn" type="submit">Adjust credit</button>
</form>
<form method="post" action="/user/admin/ban">
<input type="hidden" name="address" value="{addr}">
<input type="hidden" name="banned" value="{ban_value}">
<button class="btn ghost" type="submit">{ban_label}</button>
</form>
</div><form class="plan-action" method="post" action="/user/admin/plan">
<input type="hidden" name="address" value="{addr}"><input type="hidden" name="token" value="{plan_token}">
<label>Subscription<select name="plan"><option value="basic">Grant Basic</option><option value="pro">Grant Pro</option><option value="none">Revoke plan</option></select></label>
<label>Days<input type="number" min="1" max="3650" name="days" value="30" required></label>
<button class="btn" type="submit">Apply subscription</button>
</form><p class="hint">Replacing a plan refunds its unused paid portion. Granted days carry no refund value.</p></div>"#,
        plan_token = uuid::Uuid::new_v4(),
        balance = s.balance,
        views = s.total_views,
        badge = banned_badge(s.banned),
        token = uuid::Uuid::new_v4(),
    )
}

fn render_admin(
    email: &str,
    q: &str,
    rows: &[UserRow],
    detail: Option<&StatusResp>,
    published: &crate::settings::Published,
    saved: bool,
) -> String {
    let mut body = crate::dashboard::settings_form(published, saved);
    body.push_str(r#"<section id="accounts"><h2>Accounts</h2>"#);
    if let Some(s) = detail {
        body.push_str(&render_detail(s));
    }

    body.push_str(&format!(
        r#"<div class="card">
<form method="get" action="/user/admin#accounts" class="actions" style="margin-bottom:14px">
<input type="text" name="q" value="{q}" aria-label="Wallet address prefix" placeholder="Search wallet address">
<button class="btn" type="submit">Filter</button>
</form>"#,
        q = html_escape(q)
    ));

    if rows.is_empty() {
        body.push_str(r#"<div class="empty">No users found.</div>"#);
    } else {
        body.push_str(
            r#"<div class="tablewrap"><table>
<tr><th>Address</th><th>Created</th><th>Last login</th><th>Plan</th><th>Status</th></tr>"#,
        );
        for r in rows {
            let addr = html_escape(&r.address);
            body.push_str(&format!(
                r#"<tr><td class="mono"><a href="/user/admin?address={addr}#accounts">{addr}</a></td>
<td>{created}</td><td>{login}</td><td>{plan}</td><td>{badge}</td></tr>"#,
                created = fmt_ts(r.created_at),
                login = fmt_ts(r.last_login),
                plan = html_escape(r.plan.as_deref().unwrap_or("—")),
                badge = banned_badge(r.banned != 0),
            ));
        }
        body.push_str("</table></div>");
    }
    body.push_str("</div>");

    body.push_str("</section>");
    let content = include_str!("pages/admin.html")
        .replace("__EMAIL__", &html_escape(email))
        .replace("__CONTENT__", &body);
    crate::pages::Page::Admin.render(&content)
}

fn fmt_ts(secs: i64) -> String {
    worker::Date::new(worker::DateInit::Millis((secs.max(0) as u64) * 1000)).to_string()
}

pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(
            html_escape(r#"<a href="x">&"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;"
        );
        assert_eq!(html_escape("plain"), "plain");
    }

    #[test]
    fn ban_toggle_labels() {
        assert!(banned_badge(true).contains("Banned"));
        assert!(banned_badge(false).contains("Active"));
    }
}
