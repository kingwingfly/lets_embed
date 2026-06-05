use std::sync::Arc;

use axum::{
    Form, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit as _, Mac};
use rsa::{BoxedUint, Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_cookies::{
    Cookie, CookieManagerLayer, Cookies,
    cookie::{SameSite, time::Duration as CookieDuration},
};
use tower_service::Service;
use worker::{
    Context, Env, Error, Fetch, HttpRequest, RequestInit, Result, event, js_sys::Uint8Array,
};

const UPSTREAM: &str = "https://lets-embed-api.louisfly.icu";
const TOKEN_COOKIE: &str = "gw_token";
const APP_COOKIE: &str = "gw_app";
const D1_BINDING: &str = "DB";
const JWKS_BINDING: &str = "JWKS_CACHE";
const JWKS_KEY: &str = "cf-access-jwks";
const JWKS_TTL: u64 = 3600;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    env: Arc<Env>,
    jwt_secret: Arc<Vec<u8>>,
    client_id: Arc<String>,
    client_secret: Arc<String>,
    team_domain: Arc<String>,
    access_aud: Arc<String>,
}

async fn secret(env: &Env, name: &str) -> Result<String> {
    env.secret_store(name)?
        .get()
        .await?
        .ok_or_else(|| Error::BindingError(format!("`{name}` not provided")))
}

async fn router(env: Env, _ctx: Context) -> Result<Router> {
    let client_id = secret(&env, "lets-embed-client-id").await?;
    let client_secret = secret(&env, "lets-embed-client-secret").await?;
    let jwt_secret = secret(&env, "lets-embed-jwt-secret").await?;
    let team_domain = env.var("CF_ACCESS_TEAM_DOMAIN")?.to_string();
    let access_aud = env.var("CF_ACCESS_AUD")?.to_string();

    let state = AppState {
        env: Arc::new(env),
        jwt_secret: Arc::new(jwt_secret.into_bytes()),
        client_id: Arc::new(client_id),
        client_secret: Arc::new(client_secret),
        team_domain: Arc::new(team_domain),
        access_aud: Arc::new(access_aud),
    };

    Ok(Router::new()
        // Public
        .route("/apply", get(apply_page).post(apply_submit))
        // Protected by Access
        .route("/admin", get(admin_page))
        .route("/admin/approve", post(admin_approve))
        .route("/admin/deny", post(admin_deny))
        // Protected by service token
        .fallback(any(gateway))
        .layer(CookieManagerLayer::new())
        .with_state(state))
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, ctx: Context) -> Result<Response> {
    Ok(router(env, ctx).await?.call(req).await?)
}

// ---------------------------------------------------------------------------
// JWT (HS256)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String, // application id
    iat: u64,
    exp: u64,
}

fn now_secs() -> u64 {
    worker::Date::now().as_millis() / 1000
}

fn jwt_sign(c: &Claims, secret: &[u8]) -> String {
    let payload = B64.encode(serde_json::to_vec(c).unwrap());
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(payload.as_bytes());
    let sig = B64.encode(mac.finalize().into_bytes());
    format!("{payload}.{sig}")
}

fn jwt_verify(token: &str, secret: &[u8], now: u64) -> Option<Claims> {
    let (payload, sig) = token.split_once('.')?;
    let sig = B64.decode(sig).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig).ok()?;
    let c: Claims = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
    (c.exp >= now).then_some(c)
}

// ---------------------------------------------------------------------------
// D1
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AppRow {
    id: String,
    reason: String,
    status: String,
    duration_secs: Option<i64>,
    created_at: i64,
}

async fn db_find(env: &Env, id: &str) -> Result<Option<AppRow>> {
    env.d1(D1_BINDING)?
        .prepare(
            "SELECT id, reason, status, duration_secs, created_at FROM applications WHERE id = ?",
        )
        .bind(&[id.into()])?
        .first::<AppRow>(None)
        .await
}

async fn db_list_pending(env: &Env) -> Result<Vec<AppRow>> {
    env.d1(D1_BINDING)?
        .prepare("SELECT id, reason, status, duration_secs, created_at FROM applications WHERE status = 'pending' ORDER BY created_at DESC LIMIT 200")
        .all()
        .await?
        .results::<AppRow>()
}

// ---------------------------------------------------------------------------
// /apply
// ---------------------------------------------------------------------------

#[worker::send]
async fn apply_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    if let Some(cookie) = cookies.get(APP_COOKIE)
        && let Ok(Some(row)) = db_find(&st.env, cookie.value()).await
    {
        if row.status == "denied" {
            cookies.remove(cookie.into_owned());
        }
        return render_apply_status(&row.status).into_response();
    }
    render_apply_form().into_response()
}

#[derive(Deserialize)]
struct ApplyForm {
    reason: String,
}

#[worker::send]
async fn apply_submit(
    State(st): State<AppState>,
    cookies: Cookies,
    Form(form): Form<ApplyForm>,
) -> Response {
    let reason = form.reason.trim();
    if reason.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "Reason cannot be empty",
        )
            .into_response();
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = now_secs() as i64;

    let res = st.env.d1(D1_BINDING).and_then(|db| {
        db.prepare(
            "INSERT INTO applications (id, reason, status, created_at) VALUES (?, ?, 'pending', ?)",
        )
        .bind(&[id.clone().into(), reason.into(), (now as f64).into()])
    });

    match res {
        Ok(stmt) => {
            if let Err(e) = stmt.run().await {
                worker::console_error!("insert failed: {e:?}");
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to commit",
                )
                    .into_response();
            }
        }
        Err(e) => {
            worker::console_error!("bind failed: {e:?}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to commit",
            )
                .into_response();
        }
    }

    // app id cookie
    let mut c = Cookie::new(APP_COOKIE, id);
    c.set_http_only(true);
    c.set_secure(true);
    c.set_same_site(SameSite::Lax);
    c.set_path("/");
    c.set_max_age(CookieDuration::days(30));
    cookies.add(c);

    Redirect::to("/apply").into_response()
}

// ---------------------------------------------------------------------------
// /admin （Access Protected）
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
        let kv = env.kv(JWKS_BINDING).ok()?;

        if !force
            && let Ok(Some(text)) = kv.get(JWKS_KEY).text().await
            && let Ok(j) = serde_json::from_str::<Jwks>(&text)
        {
            return Some(j);
        }

        let url = format!("https://{team_domain}/cdn-cgi/access/certs");
        let mut resp = Fetch::Url(url.parse().ok()?).send().await.ok()?;
        let text = resp.text().await.ok()?;
        let jwks: Jwks = serde_json::from_str(&text).ok()?;

        if let Ok(builder) = kv.put(JWKS_KEY, &text) {
            let _ = builder.expiration_ttl(JWKS_TTL).execute().await;
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

#[worker::send]
async fn admin_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    // No Access
    let Some(email) = require_approver(&st, &headers).await else {
        return (axum::http::StatusCode::FORBIDDEN, "Access not configured").into_response();
    };

    let rows = match db_list_pending(&st.env).await {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("list failed: {e:?}");
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "load failed").into_response();
        }
    };
    Html(render_admin(&email, &rows)).into_response()
}

#[derive(Deserialize)]
struct ApproveForm {
    id: String,
    duration_secs: i64,
}

#[worker::send]
async fn admin_approve(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ApproveForm>,
) -> Response {
    let Some(email) = require_approver(&st, &headers).await else {
        return (axum::http::StatusCode::FORBIDDEN, "Access not configured").into_response();
    };
    let now = now_secs() as i64;

    let stmt = st.env.d1(D1_BINDING).and_then(|db| {
        db.prepare(
            "UPDATE applications SET status='approved', duration_secs=?, approved_by=?, approved_at=? WHERE id=? AND status='pending'",
        )
        .bind(&[
            (form.duration_secs as f64).into(),
            email.into(),
            (now as f64).into(),
            form.id.into(),
        ])
    });

    match stmt {
        Ok(s) if s.run().await.is_ok() => Redirect::to("/admin").into_response(),
        _ => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "approve failed",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DenyForm {
    id: String,
}

#[worker::send]
async fn admin_deny(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DenyForm>,
) -> Response {
    if require_approver(&st, &headers).await.is_none() {
        return (axum::http::StatusCode::FORBIDDEN, "Access not configured").into_response();
    };
    let stmt = st.env.d1(D1_BINDING).and_then(|db| {
        db.prepare("UPDATE applications SET status='denied' WHERE id=? AND status='pending'")
            .bind(&[form.id.into()])
    });
    match stmt {
        Ok(s) if s.run().await.is_ok() => Redirect::to("/admin").into_response(),
        _ => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "deny failed").into_response(),
    }
}

// ---------------------------------------------------------------------------
// gateway：verify JWT → sign if necessary → proxy
// ---------------------------------------------------------------------------

#[worker::send]
async fn gateway(
    State(st): State<AppState>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    cookies: Cookies,
    body: Bytes,
) -> Response {
    let now = now_secs();

    // 1) valid JWT → proxy
    if let Some(tok) = cookies.get(TOKEN_COOKIE)
        && jwt_verify(tok.value(), &st.jwt_secret, now).is_some()
    {
        return proxy(uri, method, headers, body, &st.client_id, &st.client_secret).await;
    }

    // 2) app cookie & approved → sign JWT，redirect
    if let Some(id) = cookies.get(APP_COOKIE).map(|c| c.value().to_string())
        && let Ok(Some(row)) = db_find(&st.env, &id).await
        && row.status == "approved"
    {
        let dur = row.duration_secs.unwrap_or(3600).max(0) as u64;
        let claims = Claims {
            sub: row.id,
            iat: now,
            exp: now + dur,
        };
        let token = jwt_sign(&claims, &st.jwt_secret);

        let mut c = Cookie::new(TOKEN_COOKIE, token);
        c.set_http_only(true);
        c.set_secure(true);
        c.set_same_site(SameSite::Lax);
        c.set_path("/");
        c.set_max_age(CookieDuration::seconds(dur as i64));
        cookies.add(c);

        let dest = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        return Redirect::to(dest).into_response();
    }

    // 3) other → /apply
    Redirect::to("/apply").into_response()
}

// ---------------------------------------------------------------------------
// proxy（with Service Token）
// ---------------------------------------------------------------------------

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

/// remove gateway cookie
fn sanitize_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    let kept: Vec<&str> = raw
        .split(';')
        .map(str::trim)
        .filter(|c| {
            let name = c.split('=').next().unwrap_or("");
            name != TOKEN_COOKIE && name != APP_COOKIE
        })
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

async fn proxy(
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    client_id: &str,
    client_secret: &str,
) -> Response {
    let mut target = UPSTREAM.to_string();
    if let Some(pq) = uri.path_and_query() {
        target += pq.as_str();
    }

    let mut req_init = RequestInit::new();
    req_init.with_method(method.to_string().into());

    if !matches!(method, Method::GET | Method::HEAD) && !body.is_empty() {
        req_init.with_body(Some(Uint8Array::from(&body[..]).into()));
    }

    for (k, v) in &headers {
        let name = k.as_str();
        if is_hop_by_hop(name) || name == "cookie" {
            continue;
        }
        if let Ok(v) = v.to_str() {
            let _ = req_init.headers.set(name, v);
        }
    }
    if let Some(c) = sanitize_cookie(&headers) {
        let _ = req_init.headers.set("cookie", &c);
    }

    // Service Token
    let _ = req_init.headers.set("CF-Access-Client-Id", client_id);
    let _ = req_init
        .headers
        .set("CF-Access-Client-Secret", client_secret);

    let request = match worker::Request::new_with_init(&target, &req_init) {
        Ok(r) => r,
        Err(e) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("build request failed: {e}"),
            )
                .into_response();
        }
    };

    match Fetch::Request(request).send().await {
        Ok(resp) => Response::from(resp),
        Err(e) => {
            worker::console_error!("fetch to {target} failed: {e:?}");
            (
                axum::http::StatusCode::BAD_GATEWAY,
                format!("upstream fetch failed: {e}"),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// simple pages
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
.wrap{width:100%;max-width:580px}
.card,.app{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}
.card{padding:30px}.app{padding:20px;margin:14px 0}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:14px;margin:0 0 22px}
label{display:block;font-size:13px;font-weight:600;color:var(--muted);margin-bottom:8px}
textarea{width:100%;min-height:132px;padding:12px 14px;border:1px solid var(--border);border-radius:10px;
background:transparent;color:var(--fg);font:inherit;resize:vertical;transition:border-color .15s,box-shadow .15s}
textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,70,229,.2)}
select{padding:9px 10px;border:1px solid var(--border);border-radius:9px;background:var(--card);color:var(--fg);font:inherit}
.btn{display:inline-flex;align-items:center;gap:6px;border:0;border-radius:10px;padding:10px 18px;font:inherit;
font-weight:600;cursor:pointer;color:#fff;background:var(--accent);transition:background .15s,transform .05s}
.btn:hover{background:var(--accent-h)}.btn:active{transform:translateY(1px)}
.btn.ghost{background:transparent;color:var(--danger);border:1px solid var(--border)}
.btn.ghost:hover{background:rgba(220,38,38,.08);border-color:var(--danger)}
.full{width:100%;justify-content:center;margin-top:20px}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:4px 11px;border-radius:999px}
.badge.ok{color:var(--ok);background:rgba(5,150,105,.13)}
.badge.warn{color:var(--warn);background:rgba(217,119,6,.13)}
.badge.err{color:var(--danger);background:rgba(220,38,38,.13)}
a{color:var(--accent);text-decoration:none;font-weight:600}a:hover{text-decoration:underline}
.center{text-align:center}.icon{font-size:46px;line-height:1;margin-bottom:12px}
.meta{color:var(--muted);font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.reason{white-space:pre-wrap;margin:12px 0 16px;padding:12px 14px;background:rgba(127,127,127,.07);
border:1px solid var(--border);border-radius:10px}
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

fn render_apply_form() -> Html<String> {
    let body = r#"<div class="card">
<h1>Request Access</h1>
<p class="sub">Tell us why you need access. An approver will review your request shortly.</p>
<form method="post" action="/apply">
<label for="reason">Statement of Purpose</label>
<textarea id="reason" name="reason" required placeholder="Please specify the purpose..."></textarea>
<button class="btn full" type="submit">Submit Application</button>
</form></div>"#;
    Html(page("Request Access", body))
}

fn render_apply_status(status: &str) -> Html<String> {
    let (title, icon, badge_cls, badge, msg) = match status {
        "approved" => (
            "Approved",
            "✅",
            "ok",
            "Approved",
            r#"Your application has been approved. <a href="/">Enter now &rarr;</a>"#,
        ),
        "denied" => (
            "Rejected",
            "⛔",
            "err",
            "Rejected",
            "Sorry, this application was not approved.",
        ),
        _ => (
            "Under Review",
            "⏳",
            "warn",
            "Pending",
            "Your application is awaiting approval. Please refresh this page later.",
        ),
    };
    let body = format!(
        r#"<div class="card center">
<div class="icon">{icon}</div>
<span class="badge {badge_cls}">{badge}</span>
<h1 style="margin-top:14px">{title}</h1>
<p class="sub" style="margin-bottom:0">{msg}</p>
</div>"#
    );
    Html(page(title, &body))
}

fn render_admin(email: &str, rows: &[AppRow]) -> String {
    let mut items = String::new();
    if rows.is_empty() {
        items.push_str(r#"<div class="empty">🎉 No pending applications.</div>"#);
    }
    for r in rows {
        let id = html_escape(&r.id);
        let reason = html_escape(&r.reason);
        let ts = fmt_ts(r.created_at);
        items.push_str(&format!(
            r#"<div class="app">
<div class="headrow"><span class="badge warn">Pending</span><span class="meta">{ts}</span></div>
<div class="meta">id: {id}</div>
<div class="reason">{reason}</div>
<div class="actions">
<form method="post" action="/admin/approve">
<input type="hidden" name="id" value="{id}">
<select name="duration_secs">
<option value="3600">1 hour</option>
<option value="86400">1 day</option>
<option value="604800">7 days</option>
<option value="2592000">30 days</option>
</select>
<button class="btn" type="submit">Approve</button>
</form>
<form method="post" action="/admin/deny">
<input type="hidden" name="id" value="{id}">
<button class="btn ghost" type="submit">Reject</button>
</form>
</div></div>"#
        ));
    }
    let body = format!(
        r#"<div class="headrow">
<h1>Pending Applications</h1>
<span class="you">👤 {email}</span>
</div>{items}"#,
        email = html_escape(email)
    );
    page("Approve", &body)
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
