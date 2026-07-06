//! UNIT 7: admin user management, protected by Cloudflare Access.
//!
//! Every handler first verifies the `Cf-Access-Jwt-Assertion` header (RS256,
//! JWKS from `https://{team_domain}/cdn-cgi/access/certs` cached in KV
//! `crate::JWKS_BINDING`). The `require_approver` implementation is
//! deliberately duplicated from the old gateway_worker admin (the gateway
//! copy is being removed): it is a deployment-level trust boundary, not
//! shared Rust.

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rsa::{BoxedUint, Pkcs1v15Sign, RsaPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use worker::{Env, Fetch, Method, Result};

use crate::{
    AppState, do_client,
    session::{is_valid_principal, now_secs},
    types::{BanReq, CreditReq, StatusResp},
};

#[derive(Debug, Deserialize)]
pub struct AdminQuery {
    /// Optional address-prefix filter for the user list.
    pub q: Option<String>,
    /// Show DO status + actions for this user.
    pub address: Option<String>,
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
// Cloudflare Access gate (RS256 + JWKS)
// ---------------------------------------------------------------------------

async fn require_approver(st: &AppState, headers: &HeaderMap) -> Option<String> {
    #[derive(Deserialize)]
    struct Jwk {
        kid: String,
        n: String,
        e: String,
    }
    #[derive(Deserialize)]
    struct Jwks {
        keys: Vec<Jwk>,
    }
    #[derive(Deserialize)]
    struct JwtHeader {
        kid: String,
        alg: String,
    }
    #[derive(Deserialize)]
    struct AccessClaims {
        aud: serde_json::Value,
        email: Option<String>,
        iss: String,
        exp: u64,
        nbf: Option<u64>,
    }

    fn b64url(s: &str) -> Option<Vec<u8>> {
        B64.decode(s).ok()
    }

    async fn load_jwks(env: &Env, team_domain: &str, force: bool) -> Option<Jwks> {
        let kv = env.kv(crate::JWKS_BINDING).ok()?;

        if !force
            && let Ok(Some(text)) = kv.get(crate::JWKS_KEY).text().await
            && let Ok(j) = serde_json::from_str::<Jwks>(&text)
        {
            return Some(j);
        }

        let url = format!("https://{team_domain}/cdn-cgi/access/certs");
        let mut resp = Fetch::Url(url.parse().ok()?).send().await.ok()?;
        let text = resp.text().await.ok()?;
        let jwks: Jwks = serde_json::from_str(&text).ok()?;

        if let Ok(builder) = kv.put(crate::JWKS_KEY, &text) {
            let _ = builder.expiration_ttl(crate::JWKS_TTL).execute().await;
        }
        Some(jwks)
    }

    async fn verify_access_jwt(
        env: &Env,
        token: &str,
        team_domain: &str,
        expected_aud: &str,
        now: u64,
    ) -> Option<AccessClaims> {
        let mut parts = token.split('.');
        let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }

        let header: JwtHeader = serde_json::from_slice(&b64url(h)?).ok()?;
        if header.alg != "RS256" {
            return None;
        }

        let (n_str, e_str) = {
            let cached = load_jwks(env, team_domain, false).await?;
            match cached.keys.iter().find(|k| k.kid == header.kid) {
                Some(j) => (j.n.clone(), j.e.clone()),
                None => {
                    let fresh = load_jwks(env, team_domain, true).await?;
                    let j = fresh.keys.iter().find(|k| k.kid == header.kid)?;
                    (j.n.clone(), j.e.clone())
                }
            }
        };
        let n = BoxedUint::from_be_slice_vartime(&b64url(&n_str)?);
        let e = BoxedUint::from_be_slice_vartime(&b64url(&e_str)?);
        let key = RsaPublicKey::new(n, e).ok()?;

        let signing_input = format!("{h}.{p}");
        let digest = Sha256::digest(signing_input.as_bytes());
        let sig = b64url(s)?;
        key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &sig)
            .ok()?;

        let claims: AccessClaims = serde_json::from_slice(&b64url(p)?).ok()?;

        // exp
        if claims.exp < now {
            return None;
        }
        if matches!(claims.nbf, Some(nbf) if nbf > now) {
            return None;
        }
        // iss
        if claims.iss.trim_end_matches('/')
            != format!("https://{team_domain}").trim_end_matches('/')
        {
            return None;
        }
        // aud
        let aud_ok = match &claims.aud {
            serde_json::Value::String(a) => a == expected_aud,
            serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected_aud)),
            _ => false,
        };
        if !aud_ok {
            return None;
        }

        Some(claims)
    }

    let token = headers.get("cf-access-jwt-assertion")?.to_str().ok()?;
    let claims =
        verify_access_jwt(&st.env, token, &st.team_domain, &st.access_aud, now_secs()).await?;
    claims.email
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Access not configured").into_response()
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
    let Some(email) = require_approver(&st, &headers).await else {
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

    Html(render_admin(
        &email,
        filter.as_deref().unwrap_or(""),
        &rows,
        detail.as_ref(),
    ))
    .into_response()
}

#[worker::send]
pub async fn credit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreditForm>,
) -> Response {
    if require_approver(&st, &headers).await.is_none() {
        return forbidden();
    }
    if let Err(resp) = validate_form_address(&st.env, &form.address).await {
        return resp;
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
    if let Err(e) = do_client::do_credit(&st.env, &form.address, &req).await {
        worker::console_error!("do credit for {} failed: {e:?}", form.address);
        return internal_error();
    }

    Redirect::to(&format!("/user/admin?address={}", form.address)).into_response()
}

#[worker::send]
pub async fn ban(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BanForm>,
) -> Response {
    if require_approver(&st, &headers).await.is_none() {
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

    Redirect::to(&format!("/user/admin?address={}", form.address)).into_response()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const STYLE: &str = r#"<style>
:root{--bg:#f5f6f8;--card:#fff;--fg:#1f2329;--muted:#6b7280;--border:#e5e7eb;
--accent:#4f46e5;--accent-h:#4338ca;--danger:#dc2626;--ok:#059669;--warn:#d97706;
--radius:14px;--shadow:0 10px 30px rgba(0,0,0,.08)}
@media(prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#171b22;--fg:#e6e8eb;
--muted:#9aa4b2;--border:#262c36;--shadow:0 10px 30px rgba(0,0,0,.45)}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;justify-content:center;align-items:flex-start;
background:radial-gradient(1200px 600px at 50% -10%,rgba(79,70,229,.14),transparent),var(--bg);
color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
line-height:1.55;padding:8vh 16px 6vh}
.wrap{width:100%;max-width:960px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
box-shadow:var(--shadow);padding:24px;margin:14px 0}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:17px;margin:0 0 12px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:14px;margin:0 0 22px}
input[type=text],input[type=number]{padding:9px 10px;border:1px solid var(--border);border-radius:9px;
background:transparent;color:var(--fg);font:inherit;transition:border-color .15s,box-shadow .15s}
input[type=text]:focus,input[type=number]:focus{outline:none;border-color:var(--accent);
box-shadow:0 0 0 3px rgba(79,70,229,.2)}
.btn{display:inline-flex;align-items:center;gap:6px;border:0;border-radius:10px;padding:10px 18px;font:inherit;
font-weight:600;cursor:pointer;color:#fff;background:var(--accent);transition:background .15s,transform .05s}
.btn:hover{background:var(--accent-h)}.btn:active{transform:translateY(1px)}
.btn.ghost{background:transparent;color:var(--danger);border:1px solid var(--border)}
.btn.ghost:hover{background:rgba(220,38,38,.08);border-color:var(--danger)}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:4px 11px;border-radius:999px}
.badge.ok{color:var(--ok);background:rgba(5,150,105,.13)}
.badge.warn{color:var(--warn);background:rgba(217,119,6,.13)}
.badge.err{color:var(--danger);background:rgba(220,38,38,.13)}
a{color:var(--accent);text-decoration:none;font-weight:600}a:hover{text-decoration:underline}
.meta{color:var(--muted);font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{color:var(--muted);font-size:12px;font-weight:600;text-align:left;text-transform:uppercase;letter-spacing:.04em}
th,td{padding:9px 12px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:0}
.tablewrap{overflow-x:auto}
dl.status{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;margin:0 0 18px}
dl.status dt{color:var(--muted);font-size:13px;font-weight:600}
dl.status dd{margin:0;font-size:14px}
.actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.actions form{display:inline-flex;gap:8px;align-items:center;margin:0}
.empty{text-align:center;color:var(--muted);padding:48px 0;font-size:15px}
.headrow{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px}
.you{color:var(--muted);font-size:13px}
</style>"#;

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>{STYLE}
</head><body><div class="wrap">{body}</div></body></html>"#
    )
}

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
<input type="number" name="points" required placeholder="points (&plusmn;)">
<input type="text" name="reason" required placeholder="reason">
<button class="btn" type="submit">Credit</button>
</form>
<form method="post" action="/user/admin/ban">
<input type="hidden" name="address" value="{addr}">
<input type="hidden" name="banned" value="{ban_value}">
<button class="btn ghost" type="submit">{ban_label}</button>
</form>
</div></div>"#,
        balance = s.balance,
        views = s.total_views,
        badge = banned_badge(s.banned),
        token = uuid::Uuid::new_v4(),
    )
}

fn render_admin(email: &str, q: &str, rows: &[UserRow], detail: Option<&StatusResp>) -> String {
    let mut body = format!(
        r#"<div class="headrow">
<h1>Users</h1>
<span class="you">👤 {email}</span>
</div>"#,
        email = html_escape(email)
    );

    if let Some(s) = detail {
        body.push_str(&render_detail(s));
    }

    body.push_str(&format!(
        r#"<div class="card">
<form method="get" action="/user/admin" class="actions" style="margin-bottom:14px">
<input type="text" name="q" value="{q}" placeholder="0x address prefix">
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
                r#"<tr><td class="mono"><a href="/user/admin?address={addr}">{addr}</a></td>
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

    page("User Admin", &body)
}

fn fmt_ts(secs: i64) -> String {
    worker::Date::new(worker::DateInit::Millis((secs.max(0) as u64) * 1000)).to_string()
}

fn html_escape(s: &str) -> String {
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
