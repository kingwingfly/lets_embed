//! UNIT 7: admin user management, protected by Cloudflare Access.
//!
//! Only the dedicated, platform-configured admin service binding can convey the
//! identity authenticated at the gateway. Direct HTTP and ordinary bindings deny access.

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use futures::future::join_all;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Write as _;
use worker::{Env, Method, Result, wasm_bindgen::JsValue};

use crate::{
    AppState, auth, do_client,
    session::{is_eth_address, is_valid_principal},
    types::{BanReq, CreditReq, StatusResp},
};

const ACCOUNTS_PAGE_SIZE: usize = 25;
/// Bound concurrent Durable Object status reads per request to stay well under
/// Cloudflare Workers subrequest limits even on free plans.
const MAX_LIVE_DO_FETCH: usize = 30;

#[derive(Debug, Default, Deserialize)]
pub struct AdminQuery {
    /// Optional wallet / linked Solana substring filter.
    pub q: Option<String>,
    /// Subscription filter: `all` | `paid` | `pro` | `basic` | `none`.
    pub plan: Option<String>,
    /// Status filter: `all` | `active` | `banned`.
    pub status: Option<String>,
    /// Wallet type filter: `all` | `eth` | `sol`.
    pub wallet: Option<String>,
    /// Sort order: `login_desc` | `created_desc` | `credits_desc` | `credits_asc` | `views_desc`.
    pub sort: Option<String>,
    /// 1-based accounts page index.
    pub page: Option<usize>,
    /// Show DO status + actions for this user.
    pub address: Option<String>,
    /// Active dashboard tab override (`access` | `pricing` | `plans` | `payments` | `accounts`).
    pub tab: Option<String>,
    pub saved: Option<u8>,
    /// Action feedback toast (`credit` | `plan` | `ban`).
    pub ok: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct AccountFilters {
    q: String,
    plan: String,
    status: String,
    wallet: String,
    sort: String,
    page: usize,
}

impl AccountFilters {
    fn from_query(q: &AdminQuery) -> Self {
        Self::normalize(
            q.q.as_deref().unwrap_or(""),
            q.plan.as_deref().unwrap_or("all"),
            q.status.as_deref().unwrap_or("all"),
            q.wallet.as_deref().unwrap_or("all"),
            q.sort.as_deref().unwrap_or("login_desc"),
            q.page.unwrap_or(1),
        )
    }

    fn normalize(q: &str, plan: &str, status: &str, wallet: &str, sort: &str, page: usize) -> Self {
        let q = q.trim().chars().take(64).collect::<String>();
        let plan = match plan {
            "paid" | "pro" | "basic" | "none" => plan,
            _ => "all",
        }
        .to_string();
        let status = match status {
            "active" | "banned" => status,
            _ => "all",
        }
        .to_string();
        let wallet = match wallet {
            "eth" | "sol" => wallet,
            _ => "all",
        }
        .to_string();
        let sort = match sort {
            "created_desc" | "credits_desc" | "credits_asc" | "views_desc" => sort,
            _ => "login_desc",
        }
        .to_string();
        Self {
            q,
            plan,
            status,
            wallet,
            sort,
            page: page.max(1),
        }
    }

    fn has_active_filters(&self) -> bool {
        !self.q.is_empty()
            || self.plan != "all"
            || self.status != "all"
            || self.wallet != "all"
            || self.sort != "login_desc"
    }

    fn needs_live_sort(&self) -> bool {
        matches!(
            self.sort.as_str(),
            "credits_desc" | "credits_asc" | "views_desc"
        )
    }

    fn build_url(&self, address: Option<&str>, page: Option<usize>, ok: Option<&str>) -> String {
        let mut params: Vec<(String, String)> = Vec::new();
        if let Some(addr) = address.filter(|a| !a.is_empty()) {
            params.push(("address".into(), addr.to_string()));
        }
        if !self.q.is_empty() {
            params.push(("q".into(), self.q.clone()));
        }
        if self.plan != "all" {
            params.push(("plan".into(), self.plan.clone()));
        }
        if self.status != "all" {
            params.push(("status".into(), self.status.clone()));
        }
        if self.wallet != "all" {
            params.push(("wallet".into(), self.wallet.clone()));
        }
        if self.sort != "login_desc" {
            params.push(("sort".into(), self.sort.clone()));
        }
        let target_page = page.unwrap_or(self.page);
        if target_page > 1 {
            params.push(("page".into(), target_page.to_string()));
        }
        if let Some(ok) = ok.filter(|v| !v.is_empty()) {
            params.push(("ok".into(), ok.to_string()));
        }
        if params.is_empty() {
            return "/user/admin#accounts".to_string();
        }
        let qs = params
            .into_iter()
            .map(|(k, v)| format!("{k}={}", encode_query(&v)))
            .collect::<Vec<_>>()
            .join("&");
        format!("/user/admin?{qs}#accounts")
    }

    fn hidden_inputs(&self) -> String {
        let mut out = String::new();
        if !self.q.is_empty() {
            let _ = write!(
                out,
                r#"<input type="hidden" name="q" value="{}">"#,
                html_escape(&self.q)
            );
        }
        if self.plan != "all" {
            let _ = write!(
                out,
                r#"<input type="hidden" name="plan" value="{}">"#,
                html_escape(&self.plan)
            );
        }
        if self.status != "all" {
            let _ = write!(
                out,
                r#"<input type="hidden" name="status" value="{}">"#,
                html_escape(&self.status)
            );
        }
        if self.wallet != "all" {
            let _ = write!(
                out,
                r#"<input type="hidden" name="wallet" value="{}">"#,
                html_escape(&self.wallet)
            );
        }
        if self.sort != "login_desc" {
            let _ = write!(
                out,
                r#"<input type="hidden" name="sort" value="{}">"#,
                html_escape(&self.sort)
            );
        }
        if self.page > 1 {
            let _ = write!(
                out,
                r#"<input type="hidden" name="page" value="{}">"#,
                self.page
            );
        }
        out
    }
}

#[derive(Debug, Default, Deserialize)]
struct FilterRedirectFields {
    #[serde(default)]
    q: String,
    #[serde(default)]
    plan: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    wallet: String,
    #[serde(default)]
    sort: String,
    #[serde(default)]
    page: Option<usize>,
}

impl FilterRedirectFields {
    fn to_filters(&self) -> AccountFilters {
        AccountFilters::normalize(
            &self.q,
            &self.plan,
            &self.status,
            &self.wallet,
            &self.sort,
            self.page.unwrap_or(1),
        )
    }
}

#[derive(Debug, Deserialize)]
pub struct CreditForm {
    pub address: String,
    /// May be negative to deduct.
    pub points: i64,
    /// Optional adjustment note.
    #[serde(default)]
    pub reason: String,
    /// Per-render idempotency token embedded in the credit form. Reused verbatim
    /// as the DO credit key so an accidental resubmission (browser refresh /
    /// double-click) dedupes instead of applying the credit twice.
    #[serde(default)]
    pub token: String,
    #[serde(flatten)]
    filters: FilterRedirectFields,
}

#[derive(Debug, Deserialize)]
pub struct BanForm {
    pub address: String,
    /// 1 = ban, 0 = unban.
    pub banned: i64,
    #[serde(flatten)]
    filters: FilterRedirectFields,
}

#[derive(Debug, Deserialize)]
pub struct PlanForm {
    pub address: String,
    pub plan: String,
    #[serde(default)]
    pub days: Option<u32>,
    pub token: String,
    #[serde(flatten)]
    filters: FilterRedirectFields,
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

fn editor<'a>(st: &AppState, h: &'a HeaderMap) -> Option<&'a str> {
    if !auth::same_origin(h, &st.siwe_domain) {
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

fn valid_tab(tab: Option<&str>) -> Option<&'static str> {
    match tab? {
        "access" => Some("access"),
        "pricing" => Some("pricing"),
        "plans" => Some("plans"),
        "payments" => Some("payments"),
        "accounts" => Some("accounts"),
        _ => None,
    }
}

fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

fn encode_query(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

// ---------------------------------------------------------------------------
// D1
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UserRow {
    address: String,
    solana_address: Option<String>,
    created_at: i64,
    last_login: i64,
    plan: Option<String>,
    banned: i64,
    #[serde(default)]
    topup_count: i64,
    #[serde(default)]
    topup_points: String,
    #[serde(default)]
    like_count: i64,
}

#[derive(Default, Deserialize)]
struct UserSummary {
    total: i64,
    active: i64,
    banned: i64,
    basic: i64,
    pro: i64,
    eth: i64,
    sol: i64,
}

struct AccountEntry {
    row: UserRow,
    status: Option<StatusResp>,
}

impl AccountEntry {
    fn live_plan(&self) -> Option<&str> {
        match self.status.as_ref() {
            Some(s) => s.plan.as_deref(),
            None => self.row.plan.as_deref(),
        }
    }

    fn live_banned(&self) -> bool {
        match self.status.as_ref() {
            Some(s) => s.banned,
            None => self.row.banned != 0,
        }
    }

    fn live_balance(&self) -> Option<i64> {
        self.status.as_ref().map(|s| s.balance)
    }

    fn live_total_views(&self) -> Option<i64> {
        self.status.as_ref().map(|s| s.total_views)
    }

    fn period_end(&self) -> u64 {
        self.status.as_ref().map_or(0, |s| s.period_end)
    }
}

fn build_user_where_clause(filters: &AccountFilters) -> (String, Vec<String>) {
    let mut clauses: Vec<&'static str> = Vec::new();
    let mut binds: Vec<String> = Vec::new();

    if !filters.q.is_empty() {
        let pat = format!("%{}%", escape_like(&filters.q.to_lowercase()));
        clauses.push(
            "(LOWER(u.address) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(u.solana_address, '')) LIKE ? ESCAPE '\\')",
        );
        binds.push(pat.clone());
        binds.push(pat);
    }

    match filters.plan.as_str() {
        "paid" => clauses.push("u.plan IS NOT NULL AND u.plan != ''"),
        "pro" => {
            clauses.push("u.plan = ?");
            binds.push("pro".to_string());
        }
        "basic" => {
            clauses.push("u.plan = ?");
            binds.push("basic".to_string());
        }
        "none" => clauses.push("(u.plan IS NULL OR u.plan = '')"),
        _ => {}
    }

    match filters.status.as_str() {
        "active" => clauses.push("u.banned = 0"),
        "banned" => clauses.push("u.banned != 0"),
        _ => {}
    }

    match filters.wallet.as_str() {
        "eth" => clauses.push("u.address LIKE '0x%'"),
        "sol" => clauses.push("u.address NOT LIKE '0x%'"),
        _ => {}
    }

    if clauses.is_empty() {
        (String::new(), binds)
    } else {
        (format!("WHERE {}", clauses.join(" AND ")), binds)
    }
}

async fn db_user_summary(env: &Env) -> Result<UserSummary> {
    let db = env.d1(crate::D1_BINDING)?;
    let row = db
        .prepare(
            "SELECT \
               COUNT(*) AS total, \
               COALESCE(SUM(CASE WHEN banned = 0 THEN 1 ELSE 0 END), 0) AS active, \
               COALESCE(SUM(CASE WHEN banned != 0 THEN 1 ELSE 0 END), 0) AS banned, \
               COALESCE(SUM(CASE WHEN plan = 'basic' THEN 1 ELSE 0 END), 0) AS basic, \
               COALESCE(SUM(CASE WHEN plan = 'pro' THEN 1 ELSE 0 END), 0) AS pro, \
               COALESCE(SUM(CASE WHEN address LIKE '0x%' THEN 1 ELSE 0 END), 0) AS eth, \
               COALESCE(SUM(CASE WHEN address NOT LIKE '0x%' THEN 1 ELSE 0 END), 0) AS sol \
             FROM users",
        )
        .first::<UserSummary>(None)
        .await?;
    Ok(row.unwrap_or_default())
}

async fn db_list_users(env: &Env, filters: &AccountFilters) -> Result<(Vec<UserRow>, usize)> {
    let db = env.d1(crate::D1_BINDING)?;
    let (where_sql, bind_strs) = build_user_where_clause(filters);

    #[derive(Deserialize)]
    struct CountRow {
        n: i64,
    }
    let count_sql = format!("SELECT COUNT(*) AS n FROM users u {where_sql}");
    let count_binds: Vec<JsValue> = bind_strs.iter().map(|s| s.as_str().into()).collect();
    let total = db
        .prepare(&count_sql)
        .bind(&count_binds)?
        .first::<CountRow>(None)
        .await?
        .map_or(0, |r| r.n.max(0) as usize);

    let order_sql = match filters.sort.as_str() {
        "created_desc" => "u.created_at DESC, u.address ASC",
        _ => "u.last_login DESC, u.created_at DESC",
    };

    let (limit, offset) = if filters.needs_live_sort() {
        (MAX_LIVE_DO_FETCH, 0usize)
    } else {
        (
            ACCOUNTS_PAGE_SIZE,
            filters.page.saturating_sub(1) * ACCOUNTS_PAGE_SIZE,
        )
    };

    let list_sql = format!(
        "SELECT \
           u.address, \
           u.solana_address, \
           u.created_at, \
           u.last_login, \
           u.plan, \
           u.banned, \
           COALESCE(p.cnt, 0) AS topup_count, \
           CAST(COALESCE(p.pts, 0) AS TEXT) AS topup_points, \
           COALESCE(l.cnt, 0) AS like_count \
         FROM users u \
         LEFT JOIN ( \
           SELECT address, COUNT(*) AS cnt, SUM(points) AS pts \
           FROM payments WHERE status = 'credited' GROUP BY address \
         ) p ON p.address = u.address \
         LEFT JOIN ( \
           SELECT address, COUNT(*) AS cnt FROM likes GROUP BY address \
         ) l ON l.address = u.address \
         {where_sql} \
         ORDER BY {order_sql} \
         LIMIT ? OFFSET ?"
    );
    let mut list_binds: Vec<JsValue> = bind_strs.iter().map(|s| s.as_str().into()).collect();
    list_binds.push((limit as f64).into());
    list_binds.push((offset as f64).into());
    let rows = db
        .prepare(&list_sql)
        .bind(&list_binds)?
        .all()
        .await?
        .results::<UserRow>()?;
    Ok((rows, total))
}

async fn db_user_row(env: &Env, address: &str) -> Result<Option<UserRow>> {
    let db = env.d1(crate::D1_BINDING)?;
    db.prepare(
        "SELECT \
           u.address, \
           u.solana_address, \
           u.created_at, \
           u.last_login, \
           u.plan, \
           u.banned, \
           COALESCE(p.cnt, 0) AS topup_count, \
           CAST(COALESCE(p.pts, 0) AS TEXT) AS topup_points, \
           COALESCE(l.cnt, 0) AS like_count \
         FROM users u \
         LEFT JOIN ( \
           SELECT address, COUNT(*) AS cnt, SUM(points) AS pts \
           FROM payments WHERE status = 'credited' GROUP BY address \
         ) p ON p.address = u.address \
         LEFT JOIN ( \
           SELECT address, COUNT(*) AS cnt FROM likes GROUP BY address \
         ) l ON l.address = u.address \
         WHERE u.address = ?",
    )
    .bind(&[address.into()])?
    .first::<UserRow>(None)
    .await
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

/// Validate a form address: must be a valid principal (400) and exist in `users` (404).
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

    let filters = AccountFilters::from_query(&q);
    let summary = match db_user_summary(&st.env).await {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("user summary failed: {e:?}");
            return internal_error();
        }
    };

    let (rows, filtered_total) = match db_list_users(&st.env, &filters).await {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("user list failed: {e:?}");
            return internal_error();
        }
    };

    let selected_addr = q.address.as_deref().filter(|a| is_valid_principal(a));

    // Fetch live Durable Object status (credits, active subscription, window quotas, views)
    // concurrently for every account on the current page.
    let status_futs = rows.iter().map(|r| {
        let env = &st.env;
        let addr = r.address.as_str();
        async move {
            match do_client::do_status(env, addr).await {
                Ok(s) => Some(s),
                Err(e) => {
                    worker::console_error!("do status for {addr} failed: {e:?}");
                    None
                }
            }
        }
    });
    let statuses = join_all(status_futs).await;

    let mut entries: Vec<AccountEntry> = rows
        .into_iter()
        .zip(statuses)
        .map(|(row, status)| AccountEntry { row, status })
        .collect();

    match filters.sort.as_str() {
        "credits_desc" => entries.sort_by(|a, b| {
            b.live_balance()
                .unwrap_or(i64::MIN)
                .cmp(&a.live_balance().unwrap_or(i64::MIN))
                .then_with(|| b.row.last_login.cmp(&a.row.last_login))
        }),
        "credits_asc" => entries.sort_by(|a, b| {
            a.live_balance()
                .unwrap_or(i64::MAX)
                .cmp(&b.live_balance().unwrap_or(i64::MAX))
                .then_with(|| b.row.last_login.cmp(&a.row.last_login))
        }),
        "views_desc" => entries.sort_by(|a, b| {
            b.live_total_views()
                .unwrap_or(-1)
                .cmp(&a.live_total_views().unwrap_or(-1))
                .then_with(|| b.row.last_login.cmp(&a.row.last_login))
        }),
        _ => {}
    }

    // Selected account inspector: reuse status from the loaded page if already present.
    let detail: Option<(StatusResp, Option<UserRow>)> = match selected_addr {
        Some(addr) => {
            let status = if let Some(found) = entries
                .iter()
                .find(|e| e.row.address == addr)
                .and_then(|e| e.status.as_ref())
            {
                StatusResp {
                    address: if found.address.is_empty() {
                        addr.to_string()
                    } else {
                        found.address.clone()
                    },
                    balance: found.balance,
                    plan: found.plan.clone(),
                    period_end: found.period_end,
                    views_remaining: found.views_remaining,
                    searches_remaining: found.searches_remaining,
                    window_reset: found.window_reset,
                    banned: found.banned,
                    total_views: found.total_views,
                }
            } else {
                match do_client::do_status(&st.env, addr).await {
                    Ok(mut s) => {
                        if s.address.is_empty() {
                            s.address = addr.to_string();
                        }
                        s
                    }
                    Err(e) => {
                        worker::console_error!("do status for {addr} failed: {e:?}");
                        return internal_error();
                    }
                }
            };
            let meta = db_user_row(&st.env, addr).await.ok().flatten();
            Some((status, meta))
        }
        None => None,
    };

    let published = match crate::settings::Published::load(&st.env).await {
        Ok(p) => p,
        Err(e) => {
            worker::console_error!("site settings: {e}");
            return internal_error();
        }
    };

    let account_query_active = selected_addr.is_some()
        || q.ok.is_some()
        || filters.has_active_filters()
        || q.page.is_some();
    let initial_tab = if account_query_active {
        "accounts"
    } else {
        valid_tab(q.tab.as_deref()).unwrap_or("access")
    };

    let now = (worker::Date::now().as_millis() / 1000) as i64;
    let page = render_admin(
        admin,
        &filters,
        &summary,
        &entries,
        filtered_total,
        detail.as_ref(),
        &published,
        q.saved == Some(1),
        q.ok.as_deref(),
        initial_tab,
        now,
    );
    (
        [
            (header::REFERRER_POLICY, "same-origin"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
        ],
        Html(page),
    )
        .into_response()
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

    let reason = form.reason.trim().to_string();
    if form.points == 0
        || form.points.unsigned_abs() > crate::settings::MAX_VALUE as u64
        || reason.len() > 300
    {
        return (
            StatusCode::BAD_REQUEST,
            "Enter a nonzero point adjustment (reason up to 300 characters)",
        )
            .into_response();
    }
    let token = if form.token.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        form.token.clone()
    };
    let req = CreditReq {
        points: form.points,
        key: format!("admin:{token}"),
        reason,
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

    let filters = form.filters.to_filters();
    Redirect::to(&filters.build_url(Some(&form.address), None, Some("credit"))).into_response()
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

    let filters = form.filters.to_filters();
    let ok = if banned { "banned" } else { "unbanned" };
    Redirect::to(&filters.build_url(Some(&form.address), None, Some(ok))).into_response()
}

// ---------------------------------------------------------------------------
// Persist admin changes
// ---------------------------------------------------------------------------

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
    let tab = valid_tab(fields.get("active_tab").map(String::as_str))
        .filter(|t| *t != "accounts")
        .unwrap_or("access");
    match crate::settings::Published::save(&st.env, revision, &policy, admin).await {
        Ok(true) => Redirect::to(&format!("/user/admin?saved=1&tab={tab}#{tab}")).into_response(),
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
    let days = if f.plan == "none" {
        f.days.unwrap_or(1).clamp(1, 3650)
    } else {
        match f.days {
            Some(d) if (1..=3650).contains(&d) => d,
            _ => {
                return (StatusCode::BAD_REQUEST, "Invalid subscription adjustment")
                    .into_response();
            }
        }
    };
    if (f.plan != "none" && crate::config::plan(&f.plan).is_none())
        || uuid::Uuid::parse_str(&f.token).is_err()
    {
        return (StatusCode::BAD_REQUEST, "Invalid subscription adjustment").into_response();
    }
    let req = crate::types::AdminPlanReq {
        plan: f.plan,
        days,
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
    let filters = f.filters.to_filters();
    Redirect::to(&filters.build_url(Some(&f.address), None, Some("plan"))).into_response()
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

fn plan_badge(plan: Option<&str>) -> String {
    match plan {
        Some("pro") => r#"<span class="plan-pill pro">Pro</span>"#.to_string(),
        Some("basic") => r#"<span class="plan-pill basic">Basic</span>"#.to_string(),
        Some(other) if !other.is_empty() => {
            format!(
                r#"<span class="plan-pill basic">{}</span>"#,
                html_escape(other)
            )
        }
        _ => r#"<span class="plan-pill none">PAYG</span>"#.to_string(),
    }
}

fn chain_chip(address: &str) -> &'static str {
    if is_eth_address(address) {
        r#"<span class="chain-chip eth" title="Ethereum wallet">ETH</span>"#
    } else {
        r#"<span class="chain-chip sol" title="Solana wallet">SOL</span>"#
    }
}

fn short_addr(address: &str) -> String {
    let chars: Vec<char> = address.chars().collect();
    if chars.len() <= 14 {
        return address.to_string();
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

fn fmt_num(n: i64) -> String {
    let neg = n < 0;
    let digits = n.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + usize::from(neg));
    if neg {
        out.push('-');
    }
    let len = digits.len();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Pure-Rust UTC date-time formatter (`YYYY-MM-DD HH:MM UTC`) — compact, readable,
/// and host-testable without JS `Date.toString()`.
fn fmt_ts_utc(secs: i64) -> String {
    if secs <= 0 {
        return "—".to_string();
    }
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    // Howard Hinnant's civil_from_days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02} UTC")
}

fn fmt_remaining(period_end: u64, now: i64) -> String {
    let now_u = now.max(0) as u64;
    if period_end == 0 || period_end <= now_u {
        return "No active period".to_string();
    }
    let diff = period_end - now_u;
    let days = diff / 86_400;
    let hours = (diff % 86_400) / 3_600;
    if days > 0 {
        format!("{days}d {hours}h left")
    } else if hours > 0 {
        format!("{hours}h left")
    } else {
        "< 1h left".to_string()
    }
}

fn selected_attr(cur: &str, val: &str) -> &'static str {
    if cur == val { " selected" } else { "" }
}

fn render_detail(
    s: &StatusResp,
    meta: Option<&UserRow>,
    filters: &AccountFilters,
    now: i64,
) -> String {
    let addr = html_escape(&s.address);
    let plan_html = plan_badge(s.plan.as_deref());
    let period_sub = if s.period_end > 0 {
        format!(
            "{} · Ends {}",
            fmt_remaining(s.period_end, now),
            fmt_ts_utc(s.period_end as i64)
        )
    } else {
        "Pay-as-you-go".to_string()
    };
    let views_rem = match s.views_remaining {
        Some(v) => fmt_num(v),
        None if s.plan.is_none() => "—".to_string(),
        None => "Unlimited".to_string(),
    };
    let searches_rem = s
        .searches_remaining
        .map_or_else(|| "—".to_string(), fmt_num);
    let window_sub = if s.window_reset > 0 {
        format!("Resets {}", fmt_ts_utc(s.window_reset as i64))
    } else {
        "No open 5h window".to_string()
    };

    let (topup_sub, activity_sub, linked_html) = match meta {
        Some(m) => {
            let topups = if m.topup_count > 0 {
                let pts = m
                    .topup_points
                    .parse::<i64>()
                    .map(fmt_num)
                    .unwrap_or_else(|_| m.topup_points.clone());
                format!("{} top-ups · {pts} pts credited", fmt_num(m.topup_count))
            } else {
                "No on-chain top-ups yet".to_string()
            };
            let act = format!(
                "{} favorites · Joined {} · Last login {}",
                fmt_num(m.like_count),
                fmt_ts_utc(m.created_at),
                fmt_ts_utc(m.last_login)
            );
            let linked = m
                .solana_address
                .as_deref()
                .filter(|sol| !sol.is_empty())
                .map(|sol| {
                    let esc = html_escape(sol);
                    format!(
                        r#"<div class="inspector-linked"><span class="chain-chip linked">Linked SOL</span><span class="mono">{esc}</span><button type="button" class="copy-btn" data-copy="{esc}" aria-label="Copy linked Solana address">Copy</button></div>"#
                    )
                })
                .unwrap_or_default();
            (topups, act, linked)
        }
        None => (
            "Live Durable Object balance".to_string(),
            "Activity mirrored from DO".to_string(),
            String::new(),
        ),
    };

    let (ban_value, ban_label, ban_cls) = if s.banned {
        (0, "Unban account", "btn small secondary")
    } else {
        (1, "Ban account", "btn small ghost")
    };
    let close_href = filters.build_url(None, None, None);
    let hidden_filters = filters.hidden_inputs();
    let default_plan_basic = if s.plan.as_deref() == Some("basic") {
        " selected"
    } else {
        ""
    };
    let default_plan_pro = if s.plan.as_deref() != Some("basic") {
        " selected"
    } else {
        ""
    };

    format!(
        r#"<div class="card inspector-card" id="account-inspector">
<div class="inspector-head">
  <div class="inspector-id">
    <div class="inspector-addr-row">
      {chain}
      <span class="inspector-addr">{addr}</span>
      <button type="button" class="copy-btn" data-copy="{addr}" aria-label="Copy wallet address">Copy</button>
      {badge}
    </div>
    {linked_html}
  </div>
  <div class="inspector-head-actions">
    <form method="post" action="/user/admin/ban">
      <input type="hidden" name="address" value="{addr}">
      <input type="hidden" name="banned" value="{ban_value}">
      {hidden_filters}
      <button class="{ban_cls}" type="submit">{ban_label}</button>
    </form>
    <a class="btn small secondary" href="{close_href}">Close &times;</a>
  </div>
</div>

<div class="inspector-metrics">
  <div class="metric-box">
    <div class="metric-k">Credits balance</div>
    <div class="metric-v credits">{balance} pts</div>
    <div class="metric-s">{topup_sub}</div>
  </div>
  <div class="metric-box">
    <div class="metric-k">Subscription</div>
    <div class="metric-v">{plan_html}</div>
    <div class="metric-s">{period_sub}</div>
  </div>
  <div class="metric-box">
    <div class="metric-k">5h window quota</div>
    <div class="metric-v">{views_rem} views · {searches_rem} search</div>
    <div class="metric-s">{window_sub}</div>
  </div>
  <div class="metric-box">
    <div class="metric-k">Lifetime usage</div>
    <div class="metric-v">{views} views</div>
    <div class="metric-s">{activity_sub}</div>
  </div>
</div>

<div class="inspector-actions">
  <div class="action-box">
    <h3>Airdrop / Adjust credits</h3>
    <p class="action-desc">Add positive points to airdrop credits, or use a negative number to deduct.</p>
    <div class="preset-row" aria-label="Quick credit amounts">
      <button type="button" class="preset-chip" data-fill-target="admin-credit-points" data-fill-value="100">+100</button>
      <button type="button" class="preset-chip" data-fill-target="admin-credit-points" data-fill-value="500">+500</button>
      <button type="button" class="preset-chip" data-fill-target="admin-credit-points" data-fill-value="1000">+1,000</button>
      <button type="button" class="preset-chip" data-fill-target="admin-credit-points" data-fill-value="10000">+10,000</button>
      <button type="button" class="preset-chip neg" data-fill-target="admin-credit-points" data-fill-value="-100">&minus;100</button>
    </div>
    <form method="post" action="/user/admin/credit">
      <input type="hidden" name="address" value="{addr}">
      <input type="hidden" name="token" value="{token}">
      {hidden_filters}
      <div class="action-form-grid">
        <label>Points (&plusmn;)
          <input id="admin-credit-points" type="number" name="points" required placeholder="e.g. 1000">
        </label>
        <label>Reason <span style="font-weight:400;color:var(--muted)">(optional)</span>
          <input type="text" name="reason" maxlength="300" placeholder="Optional note (e.g. promo airdrop)">
        </label>
      </div>
      <div class="action-submit-row">
        <span class="hint" style="margin:0">Balance clamps at 0 minimum.</span>
        <button class="btn small" type="submit">Adjust credit</button>
      </div>
    </form>
  </div>

  <div class="action-box">
    <h3>Airdrop / Manage subscription</h3>
    <p class="action-desc">Grant complimentary plan days or revoke an active subscription.</p>
    <div class="preset-row" aria-label="Quick subscription durations">
      <button type="button" class="preset-chip" data-fill-target="admin-plan-days" data-fill-value="7">7d</button>
      <button type="button" class="preset-chip" data-fill-target="admin-plan-days" data-fill-value="30">30d</button>
      <button type="button" class="preset-chip" data-fill-target="admin-plan-days" data-fill-value="90">90d</button>
      <button type="button" class="preset-chip" data-fill-target="admin-plan-days" data-fill-value="365">365d</button>
    </div>
    <form method="post" action="/user/admin/plan">
      <input type="hidden" name="address" value="{addr}">
      <input type="hidden" name="token" value="{plan_token}">
      {hidden_filters}
      <div class="action-form-grid">
        <label>Subscription
          <select id="admin-plan-select" name="plan">
            <option value="pro"{default_plan_pro}>Grant Pro</option>
            <option value="basic"{default_plan_basic}>Grant Basic</option>
            <option value="none">Revoke plan</option>
          </select>
        </label>
        <label id="admin-plan-days-wrap">Duration (days)
          <input id="admin-plan-days" type="number" min="1" max="3650" name="days" value="30" required>
        </label>
      </div>
      <div class="action-submit-row">
        <span class="hint" style="margin:0">Replacing a paid plan refunds its unused portion; granted days carry no refund value.</span>
        <button class="btn small" type="submit">Apply subscription</button>
      </div>
    </form>
  </div>
</div>
</div>"#,
        chain = chain_chip(&s.address),
        badge = banned_badge(s.banned),
        balance = fmt_num(s.balance),
        views = fmt_num(s.total_views),
        token = uuid::Uuid::new_v4(),
        plan_token = uuid::Uuid::new_v4(),
    )
}

#[allow(clippy::too_many_arguments)]
fn render_admin(
    email: &str,
    filters: &AccountFilters,
    summary: &UserSummary,
    entries: &[AccountEntry],
    filtered_total: usize,
    detail: Option<&(StatusResp, Option<UserRow>)>,
    published: &crate::settings::Published,
    saved: bool,
    ok_action: Option<&str>,
    initial_tab: &str,
    now: i64,
) -> String {
    let mut body = crate::dashboard::settings_form(published, saved, initial_tab);

    let accounts_cls = if initial_tab == "accounts" {
        "tab-panel is-active"
    } else {
        "tab-panel"
    };
    let _ = write!(
        body,
        r#"<section id="accounts" class="{accounts_cls}" data-tab="accounts" role="tabpanel" aria-labelledby="tab-accounts">"#
    );

    if let Some(msg) = match ok_action {
        Some("credit") => Some("✓ Credits updated for the selected account."),
        Some("plan") => Some("✓ Subscription updated for the selected account."),
        Some("banned") => Some("✓ Account has been banned."),
        Some("unbanned") => Some("✓ Account ban lifted."),
        _ => None,
    } {
        let _ = write!(
            body,
            r#"<div class="admin-banner ok" role="status"><span>{msg}</span><button type="button" class="banner-close" aria-label="Dismiss">&times;</button></div>"#
        );
    }

    // 4-column clickable KPI overview strip
    let subscribed_total = summary.basic + summary.pro;
    let kpi_all_cls = if filters.plan == "all" && filters.status == "all" {
        "kpi-card is-selected"
    } else {
        "kpi-card"
    };
    let kpi_paid_cls = if filters.plan == "paid" {
        "kpi-card is-selected"
    } else {
        "kpi-card"
    };
    let kpi_active_cls = if filters.status == "active" && filters.plan == "all" {
        "kpi-card is-selected"
    } else {
        "kpi-card"
    };
    let kpi_banned_cls = if filters.status == "banned" {
        "kpi-card is-selected"
    } else {
        "kpi-card"
    };
    let _ = write!(
        body,
        r#"<div class="acct-kpis">
  <a class="{kpi_all_cls}" href="/user/admin#accounts">
    <span class="kpi-label">Total accounts</span>
    <span class="kpi-value">{total}</span>
    <span class="kpi-sub">{eth} ETH · {sol} SOL</span>
  </a>
  <a class="{kpi_paid_cls}" href="/user/admin?plan=paid#accounts">
    <span class="kpi-label">Subscribed</span>
    <span class="kpi-value">{subscribed}</span>
    <span class="kpi-sub">{pro} Pro · {basic} Basic</span>
  </a>
  <a class="{kpi_active_cls}" href="/user/admin?status=active#accounts">
    <span class="kpi-label">Active</span>
    <span class="kpi-value">{active}</span>
    <span class="kpi-sub">In good standing</span>
  </a>
  <a class="{kpi_banned_cls}" href="/user/admin?status=banned#accounts">
    <span class="kpi-label">Banned</span>
    <span class="kpi-value">{banned}</span>
    <span class="kpi-sub">Suspended accounts</span>
  </a>
</div>"#,
        total = fmt_num(summary.total),
        eth = fmt_num(summary.eth),
        sol = fmt_num(summary.sol),
        subscribed = fmt_num(subscribed_total),
        pro = fmt_num(summary.pro),
        basic = fmt_num(summary.basic),
        active = fmt_num(summary.active),
        banned = fmt_num(summary.banned),
    );

    if let Some((status, meta)) = detail {
        body.push_str(&render_detail(status, meta.as_ref(), filters, now));
    }

    // Accounts directory card with rich filters & live DO credits table
    let reset_btn = if filters.has_active_filters() {
        r#"<a class="btn small secondary" href="/user/admin#accounts">Reset</a>"#
    } else {
        ""
    };
    let _ = write!(
        body,
        r#"<div class="card accounts-card">
<div class="section-head">
  <div>
    <h2>Accounts directory</h2>
    <p class="section-sub">Filter by wallet, subscription tier, or status. Click any account to inspect quotas, airdrop credits, or grant a plan.</p>
  </div>
</div>
<form method="get" action="/user/admin#accounts" class="accounts-toolbar">
  <label class="filter-search">Wallet or linked SOL
    <input type="text" name="q" value="{q}" aria-label="Search wallet address" placeholder="0x… or Solana address">
  </label>
  <label>Subscription
    <select name="plan" aria-label="Filter by subscription">
      <option value="all"{p_all}>All plans</option>
      <option value="paid"{p_paid}>Any paid (Pro / Basic)</option>
      <option value="pro"{p_pro}>Pro</option>
      <option value="basic"{p_basic}>Basic</option>
      <option value="none"{p_none}>No plan (PAYG)</option>
    </select>
  </label>
  <label>Status
    <select name="status" aria-label="Filter by status">
      <option value="all"{s_all}>All statuses</option>
      <option value="active"{s_active}>Active</option>
      <option value="banned"{s_banned}>Banned</option>
    </select>
  </label>
  <label>Chain
    <select name="wallet" aria-label="Filter by wallet chain">
      <option value="all"{w_all}>All chains</option>
      <option value="eth"{w_eth}>Ethereum (0x)</option>
      <option value="sol"{w_sol}>Solana</option>
    </select>
  </label>
  <label>Sort by
    <select name="sort" aria-label="Sort accounts">
      <option value="login_desc"{o_login}>Last login</option>
      <option value="created_desc"{o_created}>Newest joined</option>
      <option value="credits_desc"{o_cdesc}>Highest credits</option>
      <option value="credits_asc"{o_casc}>Lowest credits</option>
      <option value="views_desc"{o_views}>Most views</option>
    </select>
  </label>
  <div class="filter-btns">
    <button class="btn small" type="submit">Apply</button>
    {reset_btn}
  </div>
</form>"#,
        q = html_escape(&filters.q),
        p_all = selected_attr(&filters.plan, "all"),
        p_paid = selected_attr(&filters.plan, "paid"),
        p_pro = selected_attr(&filters.plan, "pro"),
        p_basic = selected_attr(&filters.plan, "basic"),
        p_none = selected_attr(&filters.plan, "none"),
        s_all = selected_attr(&filters.status, "all"),
        s_active = selected_attr(&filters.status, "active"),
        s_banned = selected_attr(&filters.status, "banned"),
        w_all = selected_attr(&filters.wallet, "all"),
        w_eth = selected_attr(&filters.wallet, "eth"),
        w_sol = selected_attr(&filters.wallet, "sol"),
        o_login = selected_attr(&filters.sort, "login_desc"),
        o_created = selected_attr(&filters.sort, "created_desc"),
        o_cdesc = selected_attr(&filters.sort, "credits_desc"),
        o_casc = selected_attr(&filters.sort, "credits_asc"),
        o_views = selected_attr(&filters.sort, "views_desc"),
    );

    if entries.is_empty() {
        body.push_str(r#"<div class="empty">No accounts match your current filters.</div>"#);
    } else {
        let showing_note = if filters.needs_live_sort() && filtered_total > MAX_LIVE_DO_FETCH {
            format!(
                "Showing top {} of {} matching accounts (sorted by live Durable Object metrics)",
                entries.len(),
                fmt_num(filtered_total as i64)
            )
        } else {
            let start = (filters.page - 1) * ACCOUNTS_PAGE_SIZE + 1;
            let end = start + entries.len() - 1;
            format!(
                "Showing {start}–{end} of {} matching accounts",
                fmt_num(filtered_total as i64)
            )
        };
        let _ = write!(
            body,
            r#"<div class="directory-meta"><span>{showing_note}</span></div>
<div class="tablewrap"><table class="acct-table">
<thead><tr><th>Account</th><th class="num-col">Credits</th><th>Subscription</th><th>Activity</th><th>Status</th><th></th></tr></thead>
<tbody>"#
        );

        let selected_addr = detail.map(|(s, _)| s.address.as_str());
        for e in entries {
            let addr_esc = html_escape(&e.row.address);
            let addr_short = html_escape(&short_addr(&e.row.address));
            let is_selected = selected_addr == Some(e.row.address.as_str());
            let row_cls = if is_selected {
                r#" class="is-selected""#
            } else {
                ""
            };
            let inspect_href = filters.build_url(Some(&e.row.address), None, None);

            let linked_chip = e
                .row
                .solana_address
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    format!(
                        r#" <span class="chain-chip linked" title="Linked Solana: {}">+SOL</span>"#,
                        html_escape(s)
                    )
                })
                .unwrap_or_default();

            let credits_main = e
                .live_balance()
                .map(|b| format!("{} pts", fmt_num(b)))
                .unwrap_or_else(|| "—".to_string());
            let credits_sub = if e.row.topup_count > 0 {
                let pts = e
                    .row
                    .topup_points
                    .parse::<i64>()
                    .map(fmt_num)
                    .unwrap_or_else(|_| e.row.topup_points.clone());
                format!(
                    r#"<div class="acct-sub">{} top-ups · {pts} pts</div>"#,
                    e.row.topup_count
                )
            } else {
                String::new()
            };

            let plan_html = plan_badge(e.live_plan());
            let plan_sub = if e.period_end() > 0 && e.live_plan().is_some() {
                format!(
                    r#"<div class="acct-sub">{}</div>"#,
                    fmt_remaining(e.period_end(), now)
                )
            } else {
                String::new()
            };

            let views_text = e
                .live_total_views()
                .map(|v| format!("{} views", fmt_num(v)))
                .unwrap_or_else(|| "—".to_string());
            let likes_text = format!("♥ {}", fmt_num(e.row.like_count));
            let login_text = fmt_ts_utc(e.row.last_login);
            let created_text = fmt_ts_utc(e.row.created_at);
            let action_btn = if is_selected {
                format!(r#"<a class="btn small" href="{inspect_href}">Inspecting</a>"#)
            } else {
                format!(r#"<a class="btn small secondary" href="{inspect_href}">Manage</a>"#)
            };

            let _ = write!(
                body,
                r#"<tr{row_cls}>
  <td>
    <div class="acct-cell-addr">
      {chain}
      <a class="acct-link" href="{inspect_href}" title="{addr_esc}">{addr_short}</a>
      <button type="button" class="copy-btn" data-copy="{addr_esc}" aria-label="Copy address">Copy</button>
      {linked_chip}
    </div>
    <div class="acct-sub">Joined {created_text}</div>
  </td>
  <td class="num-col"><span class="credits-val">{credits_main}</span>{credits_sub}</td>
  <td>{plan_html}{plan_sub}</td>
  <td><div>{views_text} · {likes_text}</div><div class="acct-sub">Login {login_text}</div></td>
  <td>{badge}</td>
  <td class="num-col">{action_btn}</td>
</tr>"#,
                chain = chain_chip(&e.row.address),
                badge = banned_badge(e.live_banned()),
            );
        }
        body.push_str("</tbody></table></div>");

        if !filters.needs_live_sort() && filtered_total > ACCOUNTS_PAGE_SIZE {
            let total_pages = filtered_total.div_ceil(ACCOUNTS_PAGE_SIZE);
            let prev = if filters.page > 1 {
                format!(
                    r#"<a class="btn small secondary" href="{}">&larr; Previous</a>"#,
                    filters.build_url(selected_addr, Some(filters.page - 1), None)
                )
            } else {
                String::new()
            };
            let next = if filters.page < total_pages {
                format!(
                    r#"<a class="btn small secondary" href="{}">Next &rarr;</a>"#,
                    filters.build_url(selected_addr, Some(filters.page + 1), None)
                )
            } else {
                String::new()
            };
            let _ = write!(
                body,
                r#"<div class="pager"><span>Page {} of {total_pages}</span><div class="pager-btns">{prev}{next}</div></div>"#,
                filters.page
            );
        }
    }

    body.push_str("</div></section>");

    let (mode_label, mode_dot) = if published.policy.login_required {
        ("Wallet required", "warn")
    } else {
        ("Public browsing", "")
    };
    let content = include_str!("pages/admin.html")
        .replace("__EMAIL__", &html_escape(email))
        .replace("__MODE_LABEL__", mode_label)
        .replace("__MODE_DOT__", mode_dot)
        .replace("__USER_TOTAL__", &fmt_num(summary.total))
        .replace("__INITIAL_TAB__", initial_tab)
        .replace("__CONTENT__", &body);
    crate::pages::Page::Admin.render(&content)
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

    #[test]
    fn formats_numbers_and_utc_timestamps() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(10050), "10,050");
        assert_eq!(fmt_num(-1234567), "-1,234,567");
        assert_eq!(fmt_ts_utc(0), "—");
        assert_eq!(fmt_ts_utc(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(fmt_remaining(1_700_090_000, 1_700_000_000), "1d 1h left");
    }

    #[test]
    fn same_origin_handles_null_origin_only_with_same_origin_fetch_metadata() {
        let mut h = HeaderMap::new();
        h.insert("origin", "null".parse().unwrap());
        assert!(!auth::same_origin(&h, "lets-embed.louisfly.icu"));

        h.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(!auth::same_origin(&h, "lets-embed.louisfly.icu"));

        h.insert("sec-fetch-site", "same-origin".parse().unwrap());
        assert!(auth::same_origin(&h, "lets-embed.louisfly.icu"));

        let mut foreign = HeaderMap::new();
        foreign.insert("origin", "https://evil.test".parse().unwrap());
        foreign.insert("sec-fetch-site", "same-origin".parse().unwrap());
        assert!(!auth::same_origin(&foreign, "lets-embed.louisfly.icu"));

        let mut matching = HeaderMap::new();
        matching.insert("origin", "https://lets-embed.louisfly.icu".parse().unwrap());
        assert!(auth::same_origin(&matching, "lets-embed.louisfly.icu"));
    }

    #[test]
    fn builds_sql_where_for_account_filters() {
        let f = AccountFilters::normalize("0xab_%", "pro", "active", "eth", "credits_desc", 2);
        let (where_sql, binds) = build_user_where_clause(&f);
        assert!(where_sql.contains("ESCAPE '\\'"));
        assert!(where_sql.contains("u.plan = ?"));
        assert!(where_sql.contains("u.banned = 0"));
        assert!(where_sql.contains("u.address LIKE '0x%'"));
        assert_eq!(binds[0], r"%0xab\_\%%");
        assert_eq!(binds[2], "pro");
    }
}
