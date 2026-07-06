use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Redirect, Response},
    routing::any,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_cookies::{CookieManagerLayer, Cookies};
use tower_service::Service;
use worker::{
    Context, Env, Error, Fetch, HttpRequest, Request, RequestInit, Result, event,
    js_sys::Uint8Array, wasm_bindgen::JsValue,
};

const API_UPSTREAM: &str = "https://lets-embed-api.louisfly.icu";
const IMAGE_UPSTREAM: &str = "https://lets-embed-image.louisfly.icu";
const VIDEO_UPSTREAM: &str = "https://lets-embed-video.louisfly.icu";
const SESSION_COOKIE: &str = "ue_session";
// retired cookies from the old apply/approve flow, still stripped before proxying
const LEGACY_TOKEN_COOKIE: &str = "gw_token";
const LEGACY_APP_COOKIE: &str = "gw_app";

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

    let state = AppState {
        env: Arc::new(env),
        jwt_secret: Arc::new(jwt_secret.into_bytes()),
        client_id: Arc::new(client_id),
        client_secret: Arc::new(client_secret),
    };

    Ok(Router::new()
        .fallback(any(gateway))
        .layer(CookieManagerLayer::new())
        .with_state(state))
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, ctx: Context) -> Result<Response> {
    Ok(router(env, ctx).await?.call(req).await?)
}

// ---------------------------------------------------------------------------
// Session JWT (HS256, issued by user-worker with the same secret)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SessionClaims {
    sub: String, // lowercase 0x eth address
    iat: u64,
    exp: u64,
}

fn now_secs() -> u64 {
    worker::Date::now().as_millis() / 1000
}

fn jwt_verify(token: &str, secret: &[u8], now: u64) -> Option<SessionClaims> {
    let (payload, sig) = token.split_once('.')?;
    let sig = B64.decode(sig).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig).ok()?;
    let c: SessionClaims = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
    // the address check rejects legacy `gw_token` values (UUID subs) signed
    // with the same secret
    (c.exp >= now && is_eth_address(&c.sub)).then_some(c)
}

/// Lowercase 0x-prefixed 20-byte hex address.
fn is_eth_address(s: &str) -> bool {
    s.len() == 42
        && s.starts_with("0x")
        && s[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// UserAccount DO wire contract — duplicated verbatim from
// `user_worker/src/types.rs` (deliberate: it is a wire contract between two
// separately deployed workers, not shared Rust)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChargeKind {
    Image,
    Video,
    Search,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeReq {
    /// Dedupe key — a media path ("/images/abc.webp") or a search key.
    pub path: String,
    pub kind: ChargeKind,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeResp {
    /// false = deduped (seen within the window) or refused; nothing deducted.
    pub charged: bool,
    pub cost: i64,
    /// PAYG points after the charge.
    pub balance: i64,
    /// Remaining view-units in the current window; `None` = no plan / unlimited.
    pub views_remaining: Option<i64>,
    /// Remaining searches in the current window; `None` = no active plan.
    pub searches_remaining: Option<i64>,
    /// Epoch secs when the usage window resets; 0 = no active window.
    pub window_reset: u64,
}

// ---------------------------------------------------------------------------
// gateway：/user/* → user-worker；verify session → charge media → proxy
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
    let path = uri.path();

    // /user/* reaches the user-worker before any auth: login must be reachable
    if path == "/user" || path.starts_with("/user/") {
        return forward_user(&st, &uri, &method, &headers, body).await;
    }

    let claims = cookies
        .get(SESSION_COOKIE)
        .and_then(|tok| jwt_verify(tok.value(), &st.jwt_secret, now_secs()));
    let Some(claims) = claims else {
        let media = path.starts_with("/images/") || path.starts_with("/videos/");
        if media && matches!(method, Method::GET | Method::HEAD) {
            // an <img> tag can't follow a login redirect
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
        let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        return Redirect::to(&format!("/user/login?next={}", encode_next(pq))).into_response();
    };

    // charge GET media views against the user's account DO (HEAD is free)
    if method == Method::GET {
        let kind = if path.starts_with("/images/") {
            Some(ChargeKind::Image)
        } else if path.starts_with("/videos/") {
            Some(ChargeKind::Video)
        } else {
            None
        };
        if let Some(kind) = kind {
            match charge_do(&st, &claims.sub, path, kind).await {
                Ok(200) => {}
                Ok(402) => return out_of_points(),
                Ok(403) => return (StatusCode::FORBIDDEN, "account suspended").into_response(),
                Ok(status) => {
                    worker::console_error!("charge returned {status}");
                    return (StatusCode::BAD_GATEWAY, "charge failed").into_response();
                }
                Err(e) => {
                    // fail closed
                    worker::console_error!("charge failed: {e:?}");
                    return (StatusCode::BAD_GATEWAY, "charge failed").into_response();
                }
            }
        }
    }

    // Meter the two similarity-search server-fn endpoints (POST). These are
    // XHR/fetch calls from the Leptos app (not browser navigations), so on 402
    // we return a JSON error the app can surface — never the HTML out_of_points
    // page. Only these exact paths + POST are intercepted; all else falls
    // through unchanged. Dedupe (same key within 24h) lives in the DO, so
    // paginated re-searches with the same `q` are automatically free.
    if method == Method::POST
        && let Some(charge_key) = match path {
            "/api/search_similar" => form_field(&body, "q").map(|q| format!("search:sim:{q}")),
            "/api/search_by_image" => {
                form_field(&body, "image").map(|img| format!("search:img:{}", &sha256_hex(&img)[..32]))
            }
            _ => None,
        }
    {
        // If the field is absent/unparseable we PROXY WITHOUT CHARGING (and warn):
        // a body-shape change must never break search. `None` charge_key means we
        // did match an intercepted path but couldn't read the field.
        match charge_do(&st, &claims.sub, &charge_key, ChargeKind::Search).await {
            Ok(200) => {}
            Ok(402) => {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    [(CONTENT_TYPE, "application/json")],
                    r#"{"error":"out of points"}"#,
                )
                    .into_response();
            }
            Ok(403) => return (StatusCode::FORBIDDEN, "account suspended").into_response(),
            Ok(status) => {
                worker::console_error!("search charge returned {status}");
                return (StatusCode::BAD_GATEWAY, "charge failed").into_response();
            }
            Err(e) => {
                // fail closed, mirroring the media path
                worker::console_error!("search charge failed: {e:?}");
                return (StatusCode::BAD_GATEWAY, "charge failed").into_response();
            }
        }
    } else if method == Method::POST
        && matches!(path, "/api/search_similar" | "/api/search_by_image")
    {
        // matched an intercepted path but the expected form field was missing:
        // proxy uncharged rather than break search on an unexpected body shape.
        worker::console_warn!("search charge skipped: missing form field on {path}");
    }

    proxy(uri, method, headers, body, &st.client_id, &st.client_secret).await
}

/// Minimal percent-encoding for the `next` query value.
fn encode_next(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '?' => out.push_str("%3F"),
            '#' => out.push_str("%23"),
            '&' => out.push_str("%26"),
            _ => out.push(ch),
        }
    }
    out
}

/// POST /charge to the user's UserAccount durable object; returns the DO status.
async fn charge_do(st: &AppState, sub: &str, path: &str, kind: ChargeKind) -> Result<u16> {
    let body = serde_json::to_string(&ChargeReq {
        path: path.to_string(),
        kind,
    })
    .unwrap();

    let mut init = RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_body(Some(JsValue::from_str(&body)));
    init.headers.set("content-type", "application/json")?;
    let req = Request::new_with_init("https://do/charge", &init)?;

    let stub = st
        .env
        .durable_object("USER_ACCOUNT")?
        .id_from_name(sub)?
        .get_stub()?;
    Ok(stub.fetch_with_request(req).await?.status_code())
}

fn out_of_points() -> Response {
    let body = r#"<div class="card center">
<div class="icon">🪙</div>
<span class="badge warn">Out of points</span>
<h1 style="margin-top:14px">Out of points</h1>
<p class="sub" style="margin-bottom:0">You have run out of points.
<a href="/user/account">Top up your account &rarr;</a></p>
</div>"#;
    (
        StatusCode::PAYMENT_REQUIRED,
        Html(page("Out of points", body)),
    )
        .into_response()
}

/// Lowercase hex SHA-256 of `s` (reuses the sha2 dep already pulled in for HS256).
fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Read one `application/x-www-form-urlencoded` field value from a raw body,
/// without adding a dependency. Splits on `&`, then `=`, matches `key`, and
/// percent-decodes the value (`+` → space, `%XX` → byte). Returns `None` if the
/// field is absent (caller then proxies without charging).
fn form_field(body: &Bytes, key: &str) -> Option<String> {
    let s = String::from_utf8_lossy(body);
    s.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Minimal `application/x-www-form-urlencoded` value decoder.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len()
                && let Some(hi) = (bytes[i + 1] as char).to_digit(16)
                && let Some(lo) = (bytes[i + 2] as char).to_digit(16) =>
            {
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// /user/* → user-worker (service binding)
// ---------------------------------------------------------------------------

async fn forward_user(
    st: &AppState,
    uri: &Uri,
    method: &Method,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target = format!("https://user-worker{pq}");

    let mut init = RequestInit::new();
    init.with_method(method.to_string().into());

    if !matches!(*method, Method::GET | Method::HEAD) && !body.is_empty() {
        init.with_body(Some(Uint8Array::from(&body[..]).into()));
    }

    // forward all headers — cookie included, the user-worker needs `ue_session`
    for (k, v) in headers {
        let name = k.as_str();
        if is_hop_by_hop(name) {
            continue;
        }
        if let Ok(v) = v.to_str() {
            let _ = init.headers.set(name, v);
        }
    }

    let sent = async {
        let req = Request::new_with_init(&target, &init)?;
        st.env.service("USER_WORKER")?.fetch_request(req).await
    }
    .await;

    match sent {
        Ok(resp) => resp.map(axum::body::Body::new),
        Err(e) => {
            worker::console_error!("user-worker fetch failed: {e:?}");
            (StatusCode::BAD_GATEWAY, "user service unavailable").into_response()
        }
    }
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

/// remove gateway cookies
fn sanitize_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    let kept: Vec<&str> = raw
        .split(';')
        .map(str::trim)
        .filter(|c| {
            let name = c.split('=').next().unwrap_or("");
            name != SESSION_COOKIE && name != LEGACY_TOKEN_COOKIE && name != LEGACY_APP_COOKIE
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
    let target = match uri.path_and_query() {
        Some(pq) if let Some(pq) = pq.as_str().strip_prefix("/images") => {
            format!("{IMAGE_UPSTREAM}{pq}")
        }
        Some(pq) if let Some(pq) = pq.as_str().strip_prefix("/videos") => {
            format!("{VIDEO_UPSTREAM}{pq}")
        }
        Some(pq) => format!("{API_UPSTREAM}{pq}"),
        None => API_UPSTREAM.to_string(),
    };

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

    let request = match Request::new_with_init(&target, &req_init) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
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
                StatusCode::BAD_GATEWAY,
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
