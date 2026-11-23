//! Accounts (`users_v2` + `user_identities` + live `UserAccount` DO) and payments endpoints.
//!
//! - `GET  /admin/api/accounts`
//! - `POST /admin/api/accounts/plan`
//! - `POST /admin/api/accounts/credit`
//! - `POST /admin/api/accounts/ban` (also revokes all active v2 sessions via `/session-revoke-all`!)
//! - `GET  /admin/api/payments`

use std::collections::HashMap;

use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use futures::future::join_all;
use serde::Deserialize;
use site_access::AuthProviderId;
use worker::wasm_bindgen::JsValue;

use crate::{
    AppState, D1_BINDING,
    api::{
        AccountEntryResp, AccountsListResp, AdminBanMutationReq, AdminBanMutationResp,
        AdminCreditMutationReq, AdminCreditMutationResp, AdminPlanMutationReq,
        AdminPlanMutationResp, IdentitySummary, PaymentRecordResp, PaymentsListResp,
    },
    do_client::{self, DoAdminPlanReq, DoCreditReq},
    handlers::{
        bad_request, guard_mutation, guard_read, internal_error, not_found,
        overview::load_accounts_summary,
    },
    settings::{MAX_VALUE, PLAN_IDS},
};

const ACCOUNTS_PAGE_SIZE: usize = 25;
const MAX_LIVE_DO_FETCH: usize = 30;

#[derive(Debug, Default, Deserialize)]
pub struct AccountsQuery {
    pub q: Option<String>,
    pub plan: Option<String>,
    pub status: Option<String>,
    pub provider: Option<String>,
    pub sort: Option<String>,
    pub page: Option<usize>,
    pub user_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PaymentsQuery {
    pub q: Option<String>,
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Deserialize)]
struct UserV2Row {
    id: String,
    account_do_key: String,
    display_name: Option<String>,
    email: Option<String>,
    created_at: i64,
    last_login: i64,
    plan: Option<String>,
    banned: i64,
    terms_version_accepted: Option<i64>,
    terms_accepted_at: Option<i64>,
    #[serde(default)]
    topup_count: i64,
    #[serde(default)]
    topup_points: String,
    #[serde(default)]
    like_count: i64,
}

#[derive(Deserialize)]
struct IdentityDbRow {
    user_id: String,
    provider_id: String,
    issuer: String,
    subject: String,
    purpose: String,
    label: Option<String>,
    verified_email: Option<String>,
    assurance_level: String,
    assurance_method: Option<String>,
    assurance_verified_at: Option<i64>,
    assurance_expires_at: Option<i64>,
    created_at: i64,
}

#[derive(Deserialize)]
struct UserKeyRow {
    id: String,
    account_do_key: String,
}

#[derive(Deserialize)]
struct CountRow {
    n: i64,
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

async fn lookup_user_key(
    env: &worker::Env,
    user_id: &str,
) -> std::result::Result<UserKeyRow, Response> {
    let trimmed = user_id.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(bad_request("Invalid user_id"));
    }
    let db = env.d1(D1_BINDING).map_err(|e| {
        worker::console_error!("d1 binding failed: {e:?}");
        internal_error()
    })?;
    let row = db
        .prepare("SELECT id, account_do_key FROM users_v2 WHERE id = ? OR account_do_key = ? LIMIT 1")
        .bind(&[trimmed.into(), trimmed.into()])
        .map_err(|e| {
            worker::console_error!("user lookup bind failed: {e:?}");
            internal_error()
        })?
        .first::<UserKeyRow>(None)
        .await
        .map_err(|e| {
            worker::console_error!("user lookup failed: {e:?}");
            internal_error()
        })?;
    row.ok_or_else(|| not_found("Account not found"))
}

async fn load_identities_for_users(
    env: &worker::Env,
    user_ids: &[String],
) -> worker::Result<HashMap<String, Vec<IdentitySummary>>> {
    let mut map: HashMap<String, Vec<IdentitySummary>> = HashMap::new();
    if user_ids.is_empty() {
        return Ok(map);
    }
    let db = env.d1(D1_BINDING)?;
    let placeholders = vec!["?"; user_ids.len()].join(",");
    let sql = format!(
        "SELECT user_id, provider_id, issuer, subject, purpose, label, verified_email, \
                assurance_level, assurance_method, assurance_verified_at, assurance_expires_at, created_at \
         FROM user_identities WHERE user_id IN ({placeholders}) ORDER BY created_at ASC"
    );
    let binds: Vec<JsValue> = user_ids.iter().map(|id| id.as_str().into()).collect();
    let rows = db
        .prepare(&sql)
        .bind(&binds)?
        .all()
        .await?
        .results::<IdentityDbRow>()?;
    for r in rows {
        map.entry(r.user_id).or_default().push(IdentitySummary {
            provider_id: r.provider_id,
            issuer: r.issuer,
            subject: r.subject,
            purpose: r.purpose,
            label: r.label,
            verified_email: r.verified_email,
            assurance_level: r.assurance_level,
            assurance_method: r.assurance_method,
            assurance_verified_at: r.assurance_verified_at,
            assurance_expires_at: r.assurance_expires_at,
            created_at: r.created_at,
        });
    }
    Ok(map)
}

#[worker::send]
pub async fn list_accounts(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AccountsQuery>,
) -> Response {
    if let Err(resp) = guard_read(&st, &headers) {
        return resp;
    }

    let search = q
        .q
        .as_deref()
        .unwrap_or("")
        .trim()
        .chars()
        .take(64)
        .collect::<String>();
    let plan = match q.plan.as_deref().unwrap_or("all") {
        "paid" | "pro" | "basic" | "none" => q.plan.as_deref().unwrap(),
        _ => "all",
    };
    let status = match q.status.as_deref().unwrap_or("all") {
        "active" | "banned" => q.status.as_deref().unwrap(),
        _ => "all",
    };
    let provider = q
        .provider
        .as_deref()
        .filter(|p| AuthProviderId::ALL.iter().any(|id| id.as_str() == *p));
    let sort = match q.sort.as_deref().unwrap_or("login_desc") {
        "created_desc" | "credits_desc" | "credits_asc" | "views_desc" => {
            q.sort.as_deref().unwrap()
        }
        _ => "login_desc",
    };
    let page = q.page.unwrap_or(1).max(1);
    let needs_live_sort = matches!(sort, "credits_desc" | "credits_asc" | "views_desc");

    let summary = match load_accounts_summary(&st.env).await {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("accounts summary failed: {e:?}");
            return internal_error();
        }
    };

    let mut clauses: Vec<&'static str> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if !search.is_empty() {
        let pat = format!("%{}%", escape_like(&search.to_lowercase()));
        clauses.push(
            "(LOWER(u.id) LIKE ? ESCAPE '\\' \
              OR LOWER(u.account_do_key) LIKE ? ESCAPE '\\' \
              OR LOWER(COALESCE(u.display_name, '')) LIKE ? ESCAPE '\\' \
              OR LOWER(COALESCE(u.email, '')) LIKE ? ESCAPE '\\' \
              OR EXISTS (SELECT 1 FROM user_identities ui WHERE ui.user_id = u.id \
                 AND (LOWER(ui.subject) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(ui.verified_email, '')) LIKE ? ESCAPE '\\')))",
        );
        for _ in 0..6 {
            binds.push(pat.clone());
        }
    }
    match plan {
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
    match status {
        "active" => clauses.push("u.banned = 0"),
        "banned" => clauses.push("u.banned != 0"),
        _ => {}
    }
    if let Some(prov) = provider {
        clauses.push(
            "EXISTS (SELECT 1 FROM user_identities ui WHERE ui.user_id = u.id AND ui.provider_id = ?)",
        );
        binds.push(prov.to_string());
    }

    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };

    let db = match st.env.d1(D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };

    let count_sql = format!("SELECT COUNT(*) AS n FROM users_v2 u {where_sql}");
    let count_binds: Vec<JsValue> = binds.iter().map(|s| s.as_str().into()).collect();
    let total = match db.prepare(&count_sql).bind(&count_binds) {
        Ok(stmt) => match stmt.first::<CountRow>(None).await {
            Ok(row) => row.map_or(0, |r| r.n.max(0) as usize),
            Err(e) => {
                worker::console_error!("accounts count query failed: {e:?}");
                return internal_error();
            }
        },
        Err(e) => {
            worker::console_error!("accounts count bind failed: {e:?}");
            return internal_error();
        }
    };

    let order_sql = match sort {
        "created_desc" => "u.created_at DESC, u.id ASC",
        _ => "u.last_login DESC, u.created_at DESC",
    };
    let (limit, offset) = if needs_live_sort {
        (MAX_LIVE_DO_FETCH, 0usize)
    } else {
        (ACCOUNTS_PAGE_SIZE, page.saturating_sub(1) * ACCOUNTS_PAGE_SIZE)
    };

    let list_sql = format!(
        "SELECT \
           u.id, u.account_do_key, u.display_name, u.email, u.created_at, u.last_login, \
           u.plan, u.banned, u.terms_version_accepted, u.terms_accepted_at, \
           COALESCE((SELECT COUNT(*) FROM payments p WHERE p.status = 'credited' AND (p.address = u.id OR p.address = u.account_do_key)), 0) AS topup_count, \
           CAST(COALESCE((SELECT SUM(p.points) FROM payments p WHERE p.status = 'credited' AND (p.address = u.id OR p.address = u.account_do_key)), 0) AS TEXT) AS topup_points, \
           COALESCE((SELECT COUNT(*) FROM likes l WHERE l.address = u.id OR l.address = u.account_do_key), 0) AS like_count \
         FROM users_v2 u \
         {where_sql} \
         ORDER BY {order_sql} \
         LIMIT ? OFFSET ?"
    );
    let mut list_binds: Vec<JsValue> = binds.iter().map(|s| s.as_str().into()).collect();
    list_binds.push((limit as f64).into());
    list_binds.push((offset as f64).into());
    let rows = match db.prepare(&list_sql).bind(&list_binds) {
        Ok(stmt) => match stmt.all().await.and_then(|r| r.results::<UserV2Row>()) {
            Ok(rows) => rows,
            Err(e) => {
                worker::console_error!("accounts list query failed: {e:?}");
                return internal_error();
            }
        },
        Err(e) => {
            worker::console_error!("accounts list bind failed: {e:?}");
            return internal_error();
        }
    };

    let user_ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    let mut identities_map = match load_identities_for_users(&st.env, &user_ids).await {
        Ok(m) => m,
        Err(e) => {
            worker::console_error!("identities query failed: {e:?}");
            HashMap::new()
        }
    };

    let status_futs = rows.iter().map(|r| {
        let env = &st.env;
        let do_key = r.account_do_key.as_str();
        async move {
            match do_client::user_status(env, do_key).await {
                Ok(s) => Some(s),
                Err(e) => {
                    worker::console_error!("do status failed for account key: {e:?}");
                    None
                }
            }
        }
    });
    let statuses = join_all(status_futs).await;

    let mut accounts: Vec<AccountEntryResp> = rows
        .into_iter()
        .zip(statuses)
        .map(|(r, live_status)| {
            let identities = identities_map.remove(&r.id).unwrap_or_default();
            let live_plan = live_status
                .as_ref()
                .and_then(|s| s.plan.clone())
                .or(r.plan);
            let live_banned = live_status
                .as_ref()
                .map_or(r.banned != 0, |s| s.banned);
            AccountEntryResp {
                id: r.id,
                account_do_key: r.account_do_key,
                display_name: r.display_name,
                email: r.email,
                created_at: r.created_at,
                last_login: r.last_login,
                plan: live_plan,
                banned: live_banned,
                terms_version_accepted: r.terms_version_accepted,
                terms_accepted_at: r.terms_accepted_at,
                topup_count: r.topup_count,
                topup_points: if r.topup_points.is_empty() {
                    "0".to_string()
                } else {
                    r.topup_points
                },
                like_count: r.like_count,
                identities,
                live_status,
            }
        })
        .collect();

    match sort {
        "credits_desc" => accounts.sort_by(|a, b| {
            b.live_status
                .as_ref()
                .map_or(i64::MIN, |s| s.balance)
                .cmp(&a.live_status.as_ref().map_or(i64::MIN, |s| s.balance))
                .then_with(|| b.last_login.cmp(&a.last_login))
        }),
        "credits_asc" => accounts.sort_by(|a, b| {
            a.live_status
                .as_ref()
                .map_or(i64::MAX, |s| s.balance)
                .cmp(&b.live_status.as_ref().map_or(i64::MAX, |s| s.balance))
                .then_with(|| b.last_login.cmp(&a.last_login))
        }),
        "views_desc" => accounts.sort_by(|a, b| {
            b.live_status
                .as_ref()
                .map_or(-1, |s| s.total_views)
                .cmp(&a.live_status.as_ref().map_or(-1, |s| s.total_views))
                .then_with(|| b.last_login.cmp(&a.last_login))
        }),
        _ => {}
    }

    let selected = if let Some(target_id) = q.user_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(found) = accounts.iter().find(|a| a.id == target_id) {
            Some(found.clone())
        } else {
            load_single_account(&st.env, target_id).await.ok().flatten()
        }
    } else {
        None
    };

    Json(AccountsListResp {
        summary,
        total,
        page,
        page_size: ACCOUNTS_PAGE_SIZE,
        accounts,
        selected,
    })
    .into_response()
}

async fn load_single_account(
    env: &worker::Env,
    user_id: &str,
) -> worker::Result<Option<AccountEntryResp>> {
    let db = env.d1(D1_BINDING)?;
    let row = db
        .prepare(
            "SELECT \
               u.id, u.account_do_key, u.display_name, u.email, u.created_at, u.last_login, \
               u.plan, u.banned, u.terms_version_accepted, u.terms_accepted_at, \
               COALESCE((SELECT COUNT(*) FROM payments p WHERE p.status = 'credited' AND (p.address = u.id OR p.address = u.account_do_key)), 0) AS topup_count, \
               CAST(COALESCE((SELECT SUM(p.points) FROM payments p WHERE p.status = 'credited' AND (p.address = u.id OR p.address = u.account_do_key)), 0) AS TEXT) AS topup_points, \
               COALESCE((SELECT COUNT(*) FROM likes l WHERE l.address = u.id OR l.address = u.account_do_key), 0) AS like_count \
             FROM users_v2 u \
             WHERE u.id = ? LIMIT 1",
        )
        .bind(&[user_id.into()])?
        .first::<UserV2Row>(None)
        .await?;
    let Some(r) = row else {
        return Ok(None);
    };
    let mut id_map = load_identities_for_users(env, std::slice::from_ref(&r.id))
        .await
        .unwrap_or_default();
    let live_status = do_client::user_status(env, &r.account_do_key).await.ok();
    let live_plan = live_status
        .as_ref()
        .and_then(|s| s.plan.clone())
        .or(r.plan);
    let live_banned = live_status.as_ref().map_or(r.banned != 0, |s| s.banned);
    Ok(Some(AccountEntryResp {
        id: r.id.clone(),
        account_do_key: r.account_do_key,
        display_name: r.display_name,
        email: r.email,
        created_at: r.created_at,
        last_login: r.last_login,
        plan: live_plan,
        banned: live_banned,
        terms_version_accepted: r.terms_version_accepted,
        terms_accepted_at: r.terms_accepted_at,
        topup_count: r.topup_count,
        topup_points: if r.topup_points.is_empty() {
            "0".to_string()
        } else {
            r.topup_points
        },
        like_count: r.like_count,
        identities: id_map.remove(&r.id).unwrap_or_default(),
        live_status,
    }))
}

#[worker::send]
pub async fn set_account_plan(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminPlanMutationReq>,
) -> Response {
    let actor = match guard_mutation(&st, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let user = match lookup_user_key(&st.env, &req.user_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let plan = req.plan.trim().to_ascii_lowercase();
    if plan != "none" && !PLAN_IDS.contains(&plan.as_str()) {
        return bad_request("Invalid plan (expected 'none', 'basic', or 'pro')");
    }

    let days = if plan == "none" {
        req.days.unwrap_or(1).clamp(1, 3650)
    } else {
        match req.days {
            Some(d) if (1..=3650).contains(&d) => d,
            _ => return bad_request("Plan duration days must be between 1 and 3650"),
        }
    };

    let token = match req.token.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(t) => {
            if uuid::Uuid::parse_str(t).is_err() {
                return bad_request("Idempotency token must be a valid UUID");
            }
            t.to_string()
        }
        None => uuid::Uuid::new_v4().to_string(),
    };

    let do_req = DoAdminPlanReq {
        plan: plan.clone(),
        days,
        token,
    };
    let status = match do_client::user_admin_plan(&st.env, &user.account_do_key, &do_req).await {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("DO admin-plan failed: {e:?}");
            return internal_error();
        }
    };

    let plan_val: JsValue = status
        .plan
        .clone()
        .map(Into::into)
        .unwrap_or(JsValue::NULL);

    if let Ok(db) = st.env.d1(D1_BINDING) {
        let mut stmts = Vec::new();
        if let Ok(s) = db
            .prepare("UPDATE users_v2 SET plan = ? WHERE id = ?")
            .bind(&[plan_val.clone(), user.id.as_str().into()])
        {
            stmts.push(s);
        }
        if let Ok(s) = db
            .prepare("UPDATE users SET plan = ? WHERE address = ?")
            .bind(&[plan_val, user.account_do_key.as_str().into()])
        {
            stmts.push(s);
        }
        if !stmts.is_empty()
            && let Err(e) = db.batch(stmts).await
        {
            worker::console_error!("mirror plan to D1 failed: {e:?}");
            return internal_error();
        }
    }

    worker::console_log!("Admin {actor} updated plan for {} to {:?}", user.id, status.plan);
    Json(AdminPlanMutationResp {
        user_id: user.id,
        plan: status.plan.clone(),
        period_end: status.period_end,
        status,
    })
    .into_response()
}

#[worker::send]
pub async fn credit_account(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminCreditMutationReq>,
) -> Response {
    let actor = match guard_mutation(&st, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let user = match lookup_user_key(&st.env, &req.user_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let reason = req.reason.trim().to_string();
    if req.points == 0
        || req.points.unsigned_abs() > MAX_VALUE as u64
        || reason.len() > 300
        || reason.chars().any(char::is_control)
    {
        return bad_request(
            "Points must be nonzero within bounds and reason up to 300 printable characters",
        );
    }

    let token = match req.token.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(t) if t.len() <= 128 && !t.chars().any(char::is_control) => t.to_string(),
        Some(_) => return bad_request("Invalid idempotency token"),
        None => uuid::Uuid::new_v4().to_string(),
    };

    let do_req = DoCreditReq {
        points: req.points,
        key: format!("admin:{token}"),
        reason: reason.clone(),
    };

    let receipt = match do_client::user_credit(&st.env, &user.account_do_key, &do_req).await {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("DO credit failed: {e:?}");
            return internal_error();
        }
    };

    if receipt.applied {
        worker::console_log!(
            "Admin {actor} adjusted {} by {} points (reason: {:?})",
            user.id,
            req.points,
            reason
        );
    }

    Json(AdminCreditMutationResp {
        user_id: user.id,
        balance: receipt.balance,
        applied: receipt.applied,
    })
    .into_response()
}

#[worker::send]
pub async fn ban_account(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminBanMutationReq>,
) -> Response {
    let actor = match guard_mutation(&st, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let user = match lookup_user_key(&st.env, &req.user_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // 1. Update authoritative ban state in UserAccount DO.
    if let Err(e) = do_client::user_ban(&st.env, &user.account_do_key, req.banned).await {
        worker::console_error!("DO ban failed: {e:?}");
        return internal_error();
    }

    // 2. When banning, immediately revoke ALL active v2 sessions in the UserAccount DO!
    let mut sessions_revoked = false;
    if req.banned {
        if let Err(e) = do_client::user_revoke_all_sessions(&st.env, &user.account_do_key).await {
            worker::console_error!("DO session-revoke-all failed: {e:?}");
            return internal_error();
        }
        sessions_revoked = true;
    }

    // 3. Mirror ban flag into D1 (`users_v2` + legacy `users` if present).
    let banned_num = f64::from(i32::from(req.banned));
    if let Ok(db) = st.env.d1(D1_BINDING) {
        let mut stmts = Vec::new();
        if let Ok(s) = db
            .prepare("UPDATE users_v2 SET banned = ? WHERE id = ?")
            .bind(&[banned_num.into(), user.id.as_str().into()])
        {
            stmts.push(s);
        }
        if let Ok(s) = db
            .prepare("UPDATE users SET banned = ? WHERE address = ?")
            .bind(&[banned_num.into(), user.account_do_key.as_str().into()])
        {
            stmts.push(s);
        }
        if !stmts.is_empty()
            && let Err(e) = db.batch(stmts).await
        {
            worker::console_error!("mirror ban to D1 failed: {e:?}");
            return internal_error();
        }
    }

    worker::console_log!(
        "Admin {actor} set banned={} for {} (sessions_revoked={})",
        req.banned,
        user.id,
        sessions_revoked
    );

    Json(AdminBanMutationResp {
        user_id: user.id,
        banned: req.banned,
        sessions_revoked,
    })
    .into_response()
}

#[worker::send]
pub async fn list_payments(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PaymentsQuery>,
) -> Response {
    if let Err(resp) = guard_read(&st, &headers) {
        return resp;
    }

    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);
    let status_filter = match q.status.as_deref().unwrap_or("all") {
        "pending" | "credited" | "rejected" => q.status.as_deref(),
        _ => None,
    };
    let search = q
        .q
        .as_deref()
        .unwrap_or("")
        .trim()
        .chars()
        .take(128)
        .collect::<String>();

    let mut clauses: Vec<&'static str> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if let Some(st_val) = status_filter {
        clauses.push("status = ?");
        binds.push(st_val.to_string());
    }
    if !search.is_empty() {
        let pat = format!("%{}%", escape_like(&search.to_lowercase()));
        clauses.push(
            "(LOWER(tx_hash) LIKE ? ESCAPE '\\' OR LOWER(address) LIKE ? ESCAPE '\\')",
        );
        binds.push(pat.clone());
        binds.push(pat);
    }

    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };

    let db = match st.env.d1(D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };

    let count_sql = format!("SELECT COUNT(*) AS n FROM payments {where_sql}");
    let count_binds: Vec<JsValue> = binds.iter().map(|s| s.as_str().into()).collect();
    let total = match db.prepare(&count_sql).bind(&count_binds) {
        Ok(stmt) => match stmt.first::<CountRow>(None).await {
            Ok(row) => row.map_or(0, |r| r.n.max(0) as usize),
            Err(e) => {
                worker::console_error!("payments count failed: {e:?}");
                return internal_error();
            }
        },
        Err(e) => {
            worker::console_error!("payments count bind failed: {e:?}");
            return internal_error();
        }
    };

    let list_sql = format!(
        "SELECT tx_hash, address, chain, token, amount, CAST(points AS TEXT) AS points, status, created_at \
         FROM payments {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    );
    let mut list_binds: Vec<JsValue> = binds.iter().map(|s| s.as_str().into()).collect();
    list_binds.push((limit as f64).into());
    list_binds.push((offset as f64).into());

    let payments = match db.prepare(&list_sql).bind(&list_binds) {
        Ok(stmt) => match stmt.all().await.and_then(|r| r.results::<PaymentRecordResp>()) {
            Ok(rows) => rows,
            Err(e) => {
                worker::console_error!("payments query failed: {e:?}");
                return internal_error();
            }
        },
        Err(e) => {
            worker::console_error!("payments bind failed: {e:?}");
            return internal_error();
        }
    };

    Json(PaymentsListResp {
        total,
        limit,
        offset,
        payments,
    })
    .into_response()
}
