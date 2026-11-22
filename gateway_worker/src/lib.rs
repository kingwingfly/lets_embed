use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header::CONTENT_TYPE},
    response::{IntoResponse, Redirect, Response},
    routing::any,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_cookies::{CookieManagerLayer, Cookies};
use tower_service::Service;
use worker::{
    Context, Env, Fetch, HttpRequest, Request, RequestInit, Result, event, js_sys::Uint8Array,
    wasm_bindgen::JsValue,
};

const SESSION_COOKIE: &str = "ue_session";
// retired cookies from the old apply/approve flow, still stripped before proxying
const LEGACY_TOKEN_COOKIE: &str = "gw_token";
const LEGACY_APP_COOKIE: &str = "gw_app";

const USER_ALLOWED_METHODS: &str = "GET, HEAD, POST, DELETE, PUT, PATCH, OPTIONS";
const GALLERY_ALLOWED_METHODS: &str = "GET, HEAD, POST";
const MAX_GATEWAY_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_IMAGE_SEARCH_BODY_BYTES: usize = 1024 * 1024;
const MAX_TEXT_SEARCH_BODY_BYTES: usize = 32 * 1024;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Upstreams {
    api: String,
    image: String,
    video: String,
}

fn parse_upstream_origin(raw: &str) -> std::result::Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty upstream URL");
    }
    let url = worker::Url::parse(trimmed).map_err(|_| "malformed upstream URL")?;
    let without_trailing_slash = trimmed.strip_suffix('/').unwrap_or(trimmed);
    let authority_clean = without_trailing_slash
        .get(8..)
        .is_some_and(|rest| !rest.contains('/') && !rest.contains('\\'));
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !authority_clean
    {
        return Err("upstream must be an https origin without userinfo, path, query, or fragment");
    }
    Ok(url.origin().ascii_serialization())
}

impl Upstreams {
    fn from_env(env: &Env) -> Result<Self> {
        let var = |name: &str| -> Result<String> {
            let raw = env.var(name)?.to_string();
            parse_upstream_origin(&raw)
                .map_err(|reason| worker::Error::RustError(format!("invalid {name}: {reason}")))
        };
        Ok(Self {
            api: var("API_UPSTREAM")?,
            image: var("IMAGE_UPSTREAM")?,
            video: var("VIDEO_UPSTREAM")?,
        })
    }
}

#[derive(Clone)]
struct AppState {
    env: Arc<Env>,
    jwt_secret: Arc<Vec<u8>>,
    admin_email: Option<String>,
    client_id: Arc<String>,
    client_secret: Arc<String>,
    upstreams: Arc<Upstreams>,
}

async fn access_admin(ctx: &Context, env: &Env) -> Result<Option<String>> {
    use worker::{
        js_sys::{Function, Promise, Reflect, futures::JsFuture},
        wasm_bindgen::JsCast,
    };
    let access = Reflect::get(ctx.as_ref(), &"access".into())?;
    if !access.is_object() {
        return Ok(None);
    }
    let expected = env.var("CF_ACCESS_AUD")?.to_string();
    let aud = Reflect::get(&access, &"aud".into())?.as_string();
    if expected.is_empty() || aud.as_deref() != Some(&expected) {
        return Ok(None);
    }
    let get: Function = Reflect::get(&access, &"getIdentity".into())?.dyn_into()?;
    let identity = JsFuture::from(Promise::resolve(&get.call0(&access)?)).await?;
    if !identity.is_object() {
        return Ok(None);
    }
    Ok(Reflect::get(&identity, &"email".into())?
        .as_string()
        .filter(|s| !s.trim().is_empty()))
}

async fn router(env: Env, ctx: Context) -> Result<Router> {
    let client_id = env.secret("CF_ACCESS_CLIENT_ID")?.to_string();
    let client_secret = env.secret("CF_ACCESS_CLIENT_SECRET")?.to_string();
    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let upstreams = Upstreams::from_env(&env)?;

    let state = AppState {
        admin_email: access_admin(&ctx, &env).await?,
        env: Arc::new(env),
        jwt_secret: Arc::new(jwt_secret.into_bytes()),
        client_id: Arc::new(client_id),
        client_secret: Arc::new(client_secret),
        upstreams: Arc::new(upstreams),
    };

    Ok(Router::new()
        .fallback(any(gateway))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_GATEWAY_BODY_BYTES))
        .layer(CookieManagerLayer::new())
        .with_state(state))
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, ctx: Context) -> Result<Response> {
    Ok(router(env, ctx).await?.call(req).await?)
}

// ---------------------------------------------------------------------------
// Session JWT (HS256, issued by lets-embed-user-worker with the same secret)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SessionClaims {
    sub: String, // session principal: lowercase 0x eth address (SIWE) or base58 Solana pubkey (SIWS)
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
    // the principal check rejects legacy `gw_token` values (UUID subs) signed
    // with the same secret
    (c.exp >= now && is_valid_principal(&c.sub)).then_some(c)
}

/// Lowercase 0x-prefixed 20-byte hex address.
fn is_eth_address(s: &str) -> bool {
    s.len() == 42
        && s.starts_with("0x")
        && s[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A base58-encoded 32-byte Solana ed25519 public key. Format-disjoint from
/// `is_eth_address` (base58 excludes `0`, so `0x…` never decodes). MUST match
/// `user_worker::session::is_sol_principal` — this is a duplicated trust boundary.
fn is_sol_principal(s: &str) -> bool {
    (32..=44).contains(&s.len()) && matches!(bs58::decode(s).into_vec(), Ok(v) if v.len() == 32)
}

/// A valid session principal: an Ethereum address (SIWE) or a Solana pubkey (SIWS).
fn is_valid_principal(s: &str) -> bool {
    is_eth_address(s) || is_sol_principal(s)
}

// ---------------------------------------------------------------------------
use site_access::{ADMIN_VIEW_COOKIE, ChargeKind, ChargeReq, GuestReq, HoldReq, HoldResp};

fn checked_user_method(method: &Method) -> Option<worker::Method> {
    match *method {
        Method::GET => Some(worker::Method::Get),
        Method::HEAD => Some(worker::Method::Head),
        Method::POST => Some(worker::Method::Post),
        Method::DELETE => Some(worker::Method::Delete),
        Method::PUT => Some(worker::Method::Put),
        Method::PATCH => Some(worker::Method::Patch),
        Method::OPTIONS => Some(worker::Method::Options),
        _ => None,
    }
}

fn checked_gallery_method(method: &Method) -> Option<worker::Method> {
    match *method {
        Method::GET => Some(worker::Method::Get),
        Method::HEAD => Some(worker::Method::Head),
        Method::POST => Some(worker::Method::Post),
        _ => None,
    }
}

fn method_not_allowed(allow: &'static str) -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [("allow", allow), ("cache-control", "private, no-store")],
        "Method Not Allowed",
    )
        .into_response()
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> std::result::Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

fn host_without_port(host: &str) -> &str {
    if let Some((h, port)) = host.rsplit_once(':')
        && !h.contains(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return h;
    }
    host
}

fn request_host<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> Option<&'a str> {
    let raw = uri
        .authority()
        .map(|a| a.as_str())
        .or_else(|| single_header(headers, "host").ok().flatten())?;
    let host = raw.trim();
    if host.is_empty() || host.contains('/') || host.contains('@') {
        return None;
    }
    Some(host)
}

fn is_same_origin(uri: &Uri, headers: &HeaderMap) -> bool {
    let Ok(sec_fetch_site) = single_header(headers, "sec-fetch-site") else {
        return false;
    };
    if let Some(site) = sec_fetch_site
        && !site.trim().eq_ignore_ascii_case("same-origin")
    {
        return false;
    }
    let Ok(origin) = single_header(headers, "origin") else {
        return false;
    };
    let Some(origin) = origin else {
        return sec_fetch_site.is_some();
    };
    let Some(host) = request_host(uri, headers) else {
        return false;
    };
    let origin = origin.trim();
    let bare_host = host_without_port(host);
    let allow_http = bare_host.eq_ignore_ascii_case("localhost") || bare_host == "127.0.0.1";
    if let Some(rest) = origin.strip_prefix("https://") {
        rest.eq_ignore_ascii_case(host)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        allow_http && rest.eq_ignore_ascii_case(host)
    } else {
        false
    }
}

fn is_rfc3986_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// Canonicalize a gallery media path for billing/deduplication by percent-decoding
/// each segment and re-encoding every byte outside RFC 3986 unreserved as uppercase `%XX`.
fn canonical_media_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut out = String::with_capacity(path.len());
    for (idx, seg) in path.split('/').enumerate() {
        if idx > 0 {
            out.push('/');
        }
        let decoded = percent_decode_segment_bytes(seg)?;
        for b in decoded {
            if is_rfc3986_unreserved(b) {
                out.push(b as char);
            } else {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    Some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeterError {
    BadRequest,
    PayloadTooLarge,
}

impl MeterError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "Invalid search request").into_response(),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Search request body too large",
            )
                .into_response(),
        }
    }
}

/// Validate `images` has 1..=4 non-empty comma-separated slots, scanning at most 5 entries.
fn valid_advanced_image_slots(images: &str) -> bool {
    let mut count = 0usize;
    for slot in images.split(',') {
        count += 1;
        if count > 4 || slot.trim().is_empty() {
            return false;
        }
    }
    count >= 1
}

fn guest_id(st: &AppState, headers: &HeaderMap) -> String {
    let ip = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    // A missing client address shares a single quota, including local development.
    ip.map(|ip| site_access::guest_account(&st.jwt_secret, ip))
        .unwrap_or_else(|| "guest:unknown".into())
}

// ---------------------------------------------------------------------------
// gateway：/user/* → lets-embed-user-worker；verify session → charge media → proxy
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
    if !is_canonical_path(path) {
        return (StatusCode::BAD_REQUEST, "Invalid request path").into_response();
    }

    if is_segment_prefix(path, "/user") {
        let Some(worker_method) = checked_user_method(&method) else {
            return method_not_allowed(USER_ALLOWED_METHODS);
        };
        if is_segment_prefix(path, "/user/admin") {
            let Some(email) = st.admin_email.as_deref() else {
                return (StatusCode::FORBIDDEN, "Administrator access required").into_response();
            };
            let browse_entry = method == Method::GET && path == "/user/admin/browse";
            let mut response = if browse_entry {
                Redirect::to("/").into_response()
            } else {
                forward_user(&st, &uri, worker_method, &headers, body, Some(email)).await
            };
            response
                .headers_mut()
                .insert("cache-control", "private, no-store".parse().unwrap());
            if method == Method::GET && (browse_entry || response.status().is_success()) {
                let pass = site_access::admin_view_pass(
                    &st.jwt_secret,
                    now_secs() + site_access::VIEW_TTL,
                );
                let cookie = format!(
                    "{ADMIN_VIEW_COOKIE}={pass}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
                    site_access::VIEW_TTL
                );
                response
                    .headers_mut()
                    .append("set-cookie", cookie.parse().expect("ASCII signed pass"));
            }
            return response;
        }
        return forward_user(&st, &uri, worker_method, &headers, body, None).await;
    }

    let Some(worker_method) = checked_gallery_method(&method) else {
        return method_not_allowed(GALLERY_ALLOWED_METHODS);
    };

    let browse = browse_route(&method, path);
    let now = now_secs();
    let pass = cookies
        .get(ADMIN_VIEW_COOKIE)
        .is_some_and(|c| site_access::valid_admin_view(&st.jwt_secret, c.value(), now));
    if browse && (pass || st.admin_email.is_some()) {
        return proxy(
            uri,
            worker_method,
            headers,
            body,
            &st.upstreams,
            &st.client_id,
            &st.client_secret,
        )
        .await;
    }

    let claims = cookies
        .get(SESSION_COOKIE)
        .and_then(|tok| jwt_verify(tok.value(), &st.jwt_secret, now));
    if claims.is_none() && !browse {
        return login_response(&uri, &method);
    }
    let item = match metered_item(&method, path, &headers, &body) {
        Ok(item) => item,
        Err(err) => return err.into_response(),
    };

    let metered_post = method == Method::POST && item.is_some();
    if metered_post && !is_same_origin(&uri, &headers) {
        return (
            StatusCode::FORBIDDEN,
            [("cache-control", "private, no-store")],
            "Cross-origin search request rejected",
        )
            .into_response();
    }

    let guest = claims.is_none();
    if metered_post {
        let item = item.expect("metered_post implies item is Some");
        let (account_id, reserve_res) = match claims {
            Some(claims) => {
                let res = account_reserve(&st, &claims.sub, "reserve", &item).await;
                (claims.sub, res)
            }
            None => {
                let id = guest_id(&st, &headers);
                let res = account_reserve(
                    &st,
                    &id,
                    "reserve-guest",
                    &GuestReq {
                        item: Some(item),
                        head: false,
                    },
                )
                .await;
                (id, res)
            }
        };
        return match reserve_res {
            Ok((200, hold_id)) => {
                let response = proxy(
                    uri,
                    worker_method,
                    headers,
                    body,
                    &st.upstreams,
                    &st.client_id,
                    &st.client_secret,
                )
                .await;
                if let Some(hold_id) = hold_id {
                    let op = match (guest, response.status().is_success()) {
                        (false, true) => "commit",
                        (false, false) => "release",
                        (true, true) => "commit-guest",
                        (true, false) => "release-guest",
                    };
                    match account_call(&st, &account_id, op, &HoldReq { hold_id }).await {
                        Ok(200) => {}
                        other => worker::console_error!("hold {op} failed: {other:?}"),
                    }
                }
                response
            }
            Ok((401, _)) => login_response(&uri, &method),
            Ok((402, _)) => payment_required(&headers, guest),
            Ok((403, _)) => (StatusCode::FORBIDDEN, "Account suspended").into_response(),
            other => {
                worker::console_error!("access reserve failed: {other:?}");
                (StatusCode::BAD_GATEWAY, "Access service unavailable").into_response()
            }
        };
    }

    let decision = match (claims, item) {
        (Some(claims), Some(item)) => {
            let operation = if method == Method::HEAD {
                "can-charge"
            } else {
                "charge"
            };
            account_call(&st, &claims.sub, operation, &item).await
        }
        (Some(claims), None) if is_segment_prefix(path, "/api") => {
            account_call(&st, &claims.sub, "check-active", &serde_json::json!({})).await
        }
        (Some(_), _) => Ok(200),
        (None, item) => {
            let id = guest_id(&st, &headers);
            account_call(
                &st,
                &id,
                "guest",
                &GuestReq {
                    item,
                    head: method == Method::HEAD,
                },
            )
            .await
        }
    };
    match decision {
        Ok(200) => {
            proxy(
                uri,
                worker_method,
                headers,
                body,
                &st.upstreams,
                &st.client_id,
                &st.client_secret,
            )
            .await
        }
        Ok(401) => login_response(&uri, &method),
        Ok(402) => payment_required(&headers, guest),
        Ok(403) => (StatusCode::FORBIDDEN, "Account suspended").into_response(),
        other => {
            worker::console_error!("access decision failed: {other:?}");
            (StatusCode::BAD_GATEWAY, "Access service unavailable").into_response()
        }
    }
}

fn login_response(uri: &Uri, method: &Method) -> Response {
    let path = uri.path();
    if is_segment_prefix(path, "/api")
        || is_segment_prefix(path, "/images")
        || is_segment_prefix(path, "/videos")
        || !matches!(*method, Method::GET | Method::HEAD)
    {
        return (StatusCode::UNAUTHORIZED, "Login required").into_response();
    }
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    Redirect::to(&format!("/user/login?next={}", encode_next(pq))).into_response()
}

fn browse_route(method: &Method, path: &str) -> bool {
    if matches!(*method, Method::GET | Method::HEAD) {
        return matches!(path, "/" | "/favicon.ico")
            || ["/pkg", "/images", "/videos", "/details"]
                .iter()
                .any(|p| is_segment_prefix(path, p));
    }
    if method != Method::POST {
        return false;
    }
    if matches!(
        path,
        "/api/search_similar"
            | "/api/search_by_image"
            | "/api/search_by_desc"
            | "/api/search_advanced"
            | "/api/search_advanced_embed"
            | "/api/search_advanced_clip"
            | "/api/search_advanced_image"
            | "/api/fetch_post_meta"
            | "/api/suggest_search"
    ) {
        return true;
    }
    // Leptos appends a decimal u64 build hash to its unnamed server functions.
    let Some(name) = path.strip_prefix("/api/") else {
        return false;
    };
    [
        "search_query",
        "list_post_images",
        "list_post_videos",
        "fetch_image_details",
    ]
    .iter()
    .any(|p| {
        name.strip_prefix(p).is_some_and(|suffix| {
            suffix.is_empty() || (suffix.len() <= 20 && suffix.bytes().all(|b| b.is_ascii_digit()))
        })
    })
}

fn require_form_urlencoded(headers: &HeaderMap) -> std::result::Result<(), MeterError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(first) = values.next() else {
        return Err(MeterError::BadRequest);
    };
    if values.next().is_some() {
        return Err(MeterError::BadRequest);
    }
    let ok = first.to_str().ok().is_some_and(|v| {
        v.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    });
    if ok {
        Ok(())
    } else {
        Err(MeterError::BadRequest)
    }
}

fn metered_item(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> std::result::Result<Option<ChargeReq>, MeterError> {
    if matches!(*method, Method::GET | Method::HEAD) {
        let kind = if is_segment_prefix(path, "/images") {
            ChargeKind::Image
        } else if is_segment_prefix(path, "/videos") {
            ChargeKind::Video
        } else {
            return Ok(None);
        };
        let canonical = canonical_media_path(path).ok_or(MeterError::BadRequest)?;
        return Ok(Some(ChargeReq {
            path: canonical,
            kind,
        }));
    }
    if method != Method::POST {
        return Ok(None);
    }
    match path {
        "/api/search_similar" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let q = form_field(body, "q").ok_or(MeterError::BadRequest)?;
            let trimmed = q.trim();
            let id: i64 = trimmed.parse().map_err(|_| MeterError::BadRequest)?;
            if id <= 0 {
                return Err(MeterError::BadRequest);
            }
            Ok(Some(ChargeReq {
                kind: ChargeKind::EmbedSearch,
                path: format!("search:sim:{}", &sha256_hex(trimmed)[..32]),
            }))
        }
        "/api/search_by_image" => {
            if body.len() > MAX_IMAGE_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let image = form_field(body, "image")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::Search,
                path: format!("search:img:{}", &sha256_hex(&image)[..32]),
            }))
        }
        "/api/search_by_desc" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let q = form_field(body, "q").ok_or(MeterError::BadRequest)?;
            let trimmed = q.trim();
            if trimmed.is_empty() || q.len() > 2000 {
                return Err(MeterError::BadRequest);
            }
            Ok(Some(ChargeReq {
                kind: ChargeKind::Description,
                path: format!("search:desc:{}", &sha256_hex(trimmed)[..32]),
            }))
        }
        "/api/search_advanced" => Ok(None),
        "/api/search_advanced_embed" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let q = form_field(body, "q")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::EmbedSearch,
                path: format!("search:adv_embed:{}", &sha256_hex(&q)[..32]),
            }))
        }
        "/api/search_advanced_clip" => {
            if body.len() > MAX_TEXT_SEARCH_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let q = form_field(body, "q")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::Description,
                path: format!("search:adv_clip:{}", &sha256_hex(&q)[..32]),
            }))
        }
        "/api/search_advanced_image" => {
            if body.len() > MAX_GATEWAY_BODY_BYTES {
                return Err(MeterError::PayloadTooLarge);
            }
            require_form_urlencoded(headers)?;
            let q = form_field(body, "q")
                .filter(|s| !s.trim().is_empty())
                .ok_or(MeterError::BadRequest)?;
            let images = form_field(body, "images")
                .filter(|s| valid_advanced_image_slots(s))
                .ok_or(MeterError::BadRequest)?;
            Ok(Some(ChargeReq {
                kind: ChargeKind::Search,
                path: format!(
                    "search:adv_img:{}",
                    &sha256_hex(&format!("{q}\0{images}"))[..32]
                ),
            }))
        }
        _ => Ok(None),
    }
}

/// Minimal percent-encoding for the `next` query value.
fn encode_next(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '+' => out.push_str("%2B"),
            '?' => out.push_str("%3F"),
            '#' => out.push_str("%23"),
            '&' => out.push_str("%26"),
            _ => out.push(ch),
        }
    }
    out
}

async fn account_call(
    st: &AppState,
    sub: &str,
    operation: &str,
    payload: &impl Serialize,
) -> Result<u16> {
    let body = serde_json::to_string(payload)?;
    let mut init = RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_body(Some(JsValue::from_str(&body)));
    init.headers.set("content-type", "application/json")?;
    let req = Request::new_with_init(&format!("https://do/{operation}"), &init)?;

    let stub = st
        .env
        .durable_object("USER_ACCOUNT")?
        .id_from_name(sub)?
        .get_stub()?;
    Ok(stub.fetch_with_request(req).await?.status_code())
}

async fn account_reserve(
    st: &AppState,
    sub: &str,
    operation: &str,
    payload: &impl Serialize,
) -> Result<(u16, Option<String>)> {
    let body = serde_json::to_string(payload)?;
    let mut init = RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_body(Some(JsValue::from_str(&body)));
    init.headers.set("content-type", "application/json")?;
    let req = Request::new_with_init(&format!("https://do/{operation}"), &init)?;

    let stub = st
        .env
        .durable_object("USER_ACCOUNT")?
        .id_from_name(sub)?
        .get_stub()?;
    let mut resp = stub.fetch_with_request(req).await?;
    let status = resp.status_code();
    if status == 200 {
        let hold: HoldResp = resp.json().await?;
        Ok((status, hold.hold_id))
    } else {
        Ok((status, None))
    }
}

fn payment_required(headers: &HeaderMap, guest: bool) -> Response {
    use axum::http::header::{ACCEPT, CACHE_CONTROL};
    use site_access::UPGRADE_PATH;

    let mode = headers.get("sec-fetch-mode");
    let dest = headers.get("sec-fetch-dest");
    let navigation = if mode.is_some() || dest.is_some() {
        mode.is_some_and(|value| value == "navigate")
            || dest.is_some_and(|value| value == "document")
    } else {
        headers
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',').any(|item| {
                    let mut parts = item.split(';').map(str::trim);
                    parts
                        .next()
                        .is_some_and(|mime| mime.eq_ignore_ascii_case("text/html"))
                        && parts
                            .filter_map(|param| param.split_once('='))
                            .filter(|(key, _)| key.trim().eq_ignore_ascii_case("q"))
                            .all(|(_, value)| {
                                value
                                    .trim()
                                    .parse::<f32>()
                                    .is_ok_and(|q| q > 0.0 && q <= 1.0)
                            })
                })
            })
    };
    let mut response = if navigation {
        Redirect::to(UPGRADE_PATH).into_response()
    } else {
        let reason = if guest {
            "Free access does not cover this item"
        } else {
            "out of points"
        };
        (
            StatusCode::PAYMENT_REQUIRED,
            [
                ("location", UPGRADE_PATH),
                ("server-timing", "gallery-allowance"),
            ],
            axum::Json(serde_json::json!({"error": reason, "redirect_to": UPGRADE_PATH})),
        )
            .into_response()
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, "private, no-store".parse().unwrap());
    response
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
/// decoding both field names and values (`+` -> space, `%XX` -> byte).
/// Rejects non-UTF-8 or duplicate matching keys so gateway metering stays
/// aligned with `serde_urlencoded`.
fn form_field(body: &Bytes, key: &str) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    let mut found: Option<String> = None;
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=')?;
        let decoded_k = percent_decode(k)?;
        if decoded_k == key {
            if found.is_some() {
                return None;
            }
            found = Some(percent_decode(v)?);
        }
    }
    found
}

/// Strict `application/x-www-form-urlencoded` component decoder (UTF-8).
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16)?;
                let lo = (bytes[i + 2] as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b'%' => return None,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn is_segment_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

// ---------------------------------------------------------------------------
// /user/* → lets-embed-user-worker (service binding)
// ---------------------------------------------------------------------------

async fn forward_user(
    st: &AppState,
    uri: &Uri,
    worker_method: worker::Method,
    headers: &HeaderMap,
    body: Bytes,
    admin_email: Option<&str>,
) -> Response {
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target = format!("https://lets-embed-user-worker{pq}");

    let mut init = RequestInit::new();
    let has_body = !matches!(worker_method, worker::Method::Get | worker::Method::Head);
    init.with_method(worker_method);
    init.with_redirect(worker::RequestRedirect::Manual);

    if has_body && !body.is_empty() {
        init.with_body(Some(Uint8Array::from(&body[..]).into()));
    }

    // forward all headers — cookie included, lets-embed-user-worker needs `ue_session`
    for (k, v) in headers {
        let name = k.as_str();
        if is_hop_by_hop(name)
            || name.eq_ignore_ascii_case(site_access::ADMIN_HEADER)
            || name.eq_ignore_ascii_case("cf-access-jwt-assertion")
        {
            continue;
        }
        if let Ok(v) = v.to_str() {
            let _ = init.headers.set(name, v);
        }
    }

    let sent = async {
        if let Some(email) = admin_email {
            init.headers.set(site_access::ADMIN_HEADER, email)?;
        }
        let binding = if admin_email.is_some() {
            "ADMIN_WORKER"
        } else {
            "USER_WORKER"
        };
        let req = Request::new_with_init(&target, &init)?;
        st.env.service(binding)?.fetch_request(req).await
    }
    .await;

    match sent {
        Ok(resp) => {
            let mut response = resp.map(axum::body::Body::new);
            response
                .headers_mut()
                .insert("cache-control", "private, no-store".parse().unwrap());
            response
        }
        Err(e) => {
            worker::console_error!("lets-embed-user-worker fetch failed: {e:?}");
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
            !matches!(
                name,
                SESSION_COOKIE
                    | ADMIN_VIEW_COOKIE
                    | "CF_Authorization"
                    | LEGACY_TOKEN_COOKIE
                    | LEGACY_APP_COOKIE
            )
        })
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

/// Percent-decode a single RFC 3986 path segment into raw bytes (preserving `+`
/// literally). Malformed `%` escapes return `None`.
fn percent_decode_segment_bytes(seg: &str) -> Option<Vec<u8>> {
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16)?;
                let lo = (bytes[i + 2] as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b'%' => return None,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Reject any non-canonical or traversal-bearing request path before route
/// matching, metering, or proxying so gateway checks and upstream URL parsing
/// always see the exact same path.
fn is_canonical_path(path: &str) -> bool {
    if !path.starts_with('/') || path.contains("//") || path.contains('\\') {
        return false;
    }
    for seg in path.split('/') {
        if seg == "." || seg == ".." {
            return false;
        }
        let Some(decoded) = percent_decode_segment_bytes(seg) else {
            return false;
        };
        if decoded == b"."
            || decoded == b".."
            || decoded.contains(&b'/')
            || decoded.contains(&b'\\')
        {
            return false;
        }
    }
    let Ok(parsed) = worker::Url::parse(&format!("https://invalid.local{path}")) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.host_str() == Some("invalid.local")
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.path() == path
}

fn build_upstream_target(uri: &Uri, upstreams: &Upstreams) -> std::result::Result<worker::Url, ()> {
    let path = uri.path();
    if !is_canonical_path(path) {
        return Err(());
    }
    let (upstream, upstream_path) = if is_segment_prefix(path, "/images") {
        (
            upstreams.image.as_str(),
            path.strip_prefix("/images").unwrap_or(""),
        )
    } else if is_segment_prefix(path, "/videos") {
        (
            upstreams.video.as_str(),
            path.strip_prefix("/videos").unwrap_or(""),
        )
    } else {
        (upstreams.api.as_str(), path)
    };
    let upstream = parse_upstream_origin(upstream).map_err(|_| ())?;
    let expected_path = if upstream_path.is_empty() {
        "/"
    } else {
        upstream_path
    };

    let mut target = format!("{upstream}{expected_path}");
    if let Some(q) = uri.query() {
        target.push('?');
        target.push_str(q);
    }

    let base_url = worker::Url::parse(&upstream).map_err(|_| ())?;
    let target_url = worker::Url::parse(&target).map_err(|_| ())?;
    if target_url.scheme() != base_url.scheme()
        || target_url.host_str() != base_url.host_str()
        || target_url.port_or_known_default() != base_url.port_or_known_default()
        || !target_url.username().is_empty()
        || target_url.password().is_some()
        || target_url.path() != expected_path
        || target_url.fragment().is_some()
    {
        return Err(());
    }
    Ok(target_url)
}

async fn proxy(
    uri: Uri,
    worker_method: worker::Method,
    headers: HeaderMap,
    body: Bytes,
    upstreams: &Upstreams,
    client_id: &str,
    client_secret: &str,
) -> Response {
    let Ok(target_url) = build_upstream_target(&uri, upstreams) else {
        return (StatusCode::BAD_REQUEST, "invalid request URI").into_response();
    };

    let mut req_init = RequestInit::new();
    let has_body = !matches!(worker_method, worker::Method::Get | worker::Method::Head);
    req_init.with_method(worker_method);
    req_init.with_redirect(worker::RequestRedirect::Manual);

    if has_body && !body.is_empty() {
        req_init.with_body(Some(Uint8Array::from(&body[..]).into()));
    }

    for (k, v) in &headers {
        let name = k.as_str();
        if is_hop_by_hop(name)
            || name == "cookie"
            || name.eq_ignore_ascii_case(site_access::ADMIN_HEADER)
            || name.eq_ignore_ascii_case("cf-access-jwt-assertion")
            || name.eq_ignore_ascii_case("cf-access-authenticated-user-email")
            || name.eq_ignore_ascii_case("cf-access-client-id")
            || name.eq_ignore_ascii_case("cf-access-client-secret")
        {
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

    let request = match Request::new_with_init(target_url.as_str(), &req_init) {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("build request for {target_url} failed: {e:?}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "upstream request failed").into_response();
        }
    };

    match Fetch::Request(request).send().await {
        Ok(resp) => {
            let mut response = Response::from(resp);
            if !is_segment_prefix(uri.path(), "/pkg") {
                response
                    .headers_mut()
                    .insert("cache-control", "private, no-store".parse().unwrap());
            }
            response
        }
        Err(e) => {
            worker::console_error!("fetch to {target_url} failed: {e:?}");
            (StatusCode::BAD_GATEWAY, "upstream fetch failed").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_upstreams() -> Upstreams {
        Upstreams {
            api: "https://api.gallery.test".into(),
            image: "https://image.gallery.test".into(),
            video: "https://video.gallery.test".into(),
        }
    }

    fn form_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8"
                .parse()
                .unwrap(),
        );
        h
    }

    #[test]
    fn clients_without_fetch_metadata_can_negotiate_the_upgrade_page() {
        let mut headers = HeaderMap::new();
        for (accept, expected) in [
            ("application/json, text/html;q=0.8", StatusCode::SEE_OTHER),
            (
                "text/html; q=0, application/json",
                StatusCode::PAYMENT_REQUIRED,
            ),
        ] {
            headers.insert("accept", accept.parse().unwrap());
            assert_eq!(payment_required(&headers, true).status(), expected);
        }
    }

    #[test]
    fn segment_prefix_matches_whole_segments_only() {
        assert!(is_segment_prefix("/images", "/images"));
        assert!(is_segment_prefix("/images/a.webp", "/images"));
        assert!(!is_segment_prefix("/images@evil.com", "/images"));
        assert!(!is_segment_prefix("/images.evil.com/x", "/images"));
        assert!(is_segment_prefix("/videos/a.mp4", "/videos"));
        assert!(!is_segment_prefix("/videos@evil.com", "/videos"));
    }

    #[test]
    fn form_field_decodes_keys_and_rejects_duplicates() {
        let body = Bytes::from_static(b"limit=20&%71=cat+ears&offset=0");
        assert_eq!(form_field(&body, "q").as_deref(), Some("cat ears"));

        let dup = Bytes::from_static(b"q=first&%71=second");
        assert_eq!(form_field(&dup, "q"), None);

        let missing = Bytes::from_static(b"limit=20");
        assert_eq!(form_field(&missing, "q"), None);
    }

    #[test]
    fn parse_upstream_origin_accepts_https_origins_and_rejects_extras() {
        assert_eq!(
            parse_upstream_origin("https://api.gallery.test").unwrap(),
            "https://api.gallery.test"
        );
        assert_eq!(
            parse_upstream_origin("  https://api.gallery.test/  ").unwrap(),
            "https://api.gallery.test"
        );
        assert_eq!(
            parse_upstream_origin("https://api.gallery.test:443/").unwrap(),
            "https://api.gallery.test"
        );
        assert_eq!(
            parse_upstream_origin("https://api.gallery.test:8443/").unwrap(),
            "https://api.gallery.test:8443"
        );

        for bad in [
            "",
            "   ",
            "not-a-url",
            "http://api.gallery.test",
            "ftp://api.gallery.test",
            "https://user:pass@api.gallery.test",
            "https://user@api.gallery.test",
            "https://:pass@api.gallery.test",
            "https://api.gallery.test/base",
            "https://api.gallery.test/base/",
            "https://api.gallery.test/a/..",
            "https://api.gallery.test//",
            "https://api.gallery.test?x=1",
            "https://api.gallery.test/?x=1",
            "https://api.gallery.test?",
            "https://api.gallery.test#frag",
            "https://api.gallery.test/#frag",
            "https://api.gallery.test#",
        ] {
            assert!(parse_upstream_origin(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn canonical_path_and_upstream_target_block_normalization_differentials() {
        for ok in [
            "/",
            "/images",
            "/images/Demo%20album/a.webp",
            "/images/a+b.webp",
            "/videos/clip.mp4",
            "/api/search_advanced_clip",
            "/pkg/app.wasm",
        ] {
            assert!(is_canonical_path(ok), "must accept {ok:?}");
        }

        let attacks = [
            "/x/%2e%2e/api/search_advanced_clip",
            "/api/%2e/search_by_desc",
            "/pkg/%2e%2e/api/search_query",
            "//api/search_advanced_clip",
            "/api%2fsearch_advanced_clip",
            "/api%2Fsearch_advanced_clip",
            "/api%5csearch_advanced_clip",
            "/api%5Csearch_advanced_clip",
            "/images/%2e%2e/secret",
            "/images/%2E%2E/secret",
            "/images/.%2e/secret",
            "/images/%2e./secret",
            "/images/..",
            "/images/.",
            "/images/a\\b.webp",
            "/images/bad%2",
        ];
        let upstreams = test_upstreams();
        for attack in attacks {
            assert!(!is_canonical_path(attack), "must reject path {attack:?}");
            // Wrap with dummy origin when building Uri so `//api/...` stays in the path component.
            if let Ok(uri) = format!("https://gallery.test{attack}").parse::<Uri>() {
                assert_eq!(uri.path(), attack);
                assert!(
                    build_upstream_target(&uri, &upstreams).is_err(),
                    "build_upstream_target must reject {attack:?}"
                );
            }
        }
    }

    #[test]
    fn build_upstream_target_routes_by_prefix_and_trims_trailing_slashes() {
        let upstreams = Upstreams {
            api: "https://api.gallery.test/".into(),
            image: "https://image.gallery.test/".into(),
            video: "https://video.gallery.test/".into(),
        };

        let api_url = build_upstream_target(
            &"/api/search_advanced?sort=newest".parse().unwrap(),
            &upstreams,
        )
        .unwrap();
        assert_eq!(
            api_url.as_str(),
            "https://api.gallery.test/api/search_advanced?sort=newest"
        );
        assert_eq!(api_url.host_str(), Some("api.gallery.test"));
        assert_eq!(api_url.path(), "/api/search_advanced");

        let img_url =
            build_upstream_target(&"/images/album/pic.webp?v=2".parse().unwrap(), &upstreams)
                .unwrap();
        assert_eq!(
            img_url.as_str(),
            "https://image.gallery.test/album/pic.webp?v=2"
        );
        assert_eq!(img_url.host_str(), Some("image.gallery.test"));
        assert_eq!(img_url.path(), "/album/pic.webp");

        let img_root = build_upstream_target(&"/images".parse().unwrap(), &upstreams).unwrap();
        assert_eq!(img_root.as_str(), "https://image.gallery.test/");
        assert_eq!(img_root.path(), "/");

        let vid_url =
            build_upstream_target(&"/videos/clip.mp4".parse().unwrap(), &upstreams).unwrap();
        assert_eq!(vid_url.as_str(), "https://video.gallery.test/clip.mp4");
        assert_eq!(vid_url.host_str(), Some("video.gallery.test"));
        assert_eq!(vid_url.path(), "/clip.mp4");

        // Prefix lookalikes do not match /images or /videos and stay pinned to API upstream.
        let lookalike_url = build_upstream_target(
            &"/images.evil.com/steal".parse().unwrap(),
            &test_upstreams(),
        )
        .unwrap();
        assert_eq!(
            lookalike_url.as_str(),
            "https://api.gallery.test/images.evil.com/steal"
        );
        assert_eq!(lookalike_url.host_str(), Some("api.gallery.test"));

        // Invalid upstream origin is rejected.
        let bad = Upstreams {
            api: "http://api.gallery.test".into(),
            ..test_upstreams()
        };
        assert!(build_upstream_target(&"/".parse().unwrap(), &bad).is_err());
    }

    #[test]
    fn browse_route_allows_pinned_metadata_advanced_search_and_blocks_guest_like_previews() {
        for pinned in [
            "/api/fetch_post_meta",
            "/api/suggest_search",
            "/api/search_similar",
            "/api/search_by_image",
            "/api/search_by_desc",
            "/api/search_advanced",
            "/api/search_advanced_embed",
            "/api/search_advanced_clip",
            "/api/search_advanced_image",
        ] {
            assert!(browse_route(&Method::POST, pinned), "POST {pinned}");
            assert!(!browse_route(&Method::GET, pinned), "GET {pinned}");
            assert!(!browse_route(&Method::HEAD, pinned), "HEAD {pinned}");
        }

        // Unpinned numeric or extra suffixes on pinned endpoints must stay blocked.
        for blocked in [
            "/api/suggest_search123456",
            "/api/suggest_search_evil",
            "/api/search_advanced123",
            "/api/search_advanced_embed1",
            "/api/search_advanced_clip1",
            "/api/search_advanced_image1",
            "/api/search_advanced_evil",
        ] {
            assert!(!browse_route(&Method::POST, blocked), "POST {blocked}");
        }

        // Existing unpinned Leptos server functions still match optional numeric build hash.
        assert!(browse_route(&Method::POST, "/api/search_query"));
        assert!(browse_route(&Method::POST, "/api/search_query1234567890"));
        assert!(!browse_route(&Method::GET, "/api/like_previews"));
    }

    #[test]
    fn require_form_urlencoded_rejects_duplicate_content_type_headers() {
        let mut mixed_dup = form_headers();
        mixed_dup.append(CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(require_form_urlencoded(&mixed_dup).is_err());

        let mut same_dup = form_headers();
        same_dup.append(
            CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        assert!(require_form_urlencoded(&same_dup).is_err());

        assert!(
            metered_item(
                &Method::POST,
                "/api/search_advanced_clip",
                &mixed_dup,
                &Bytes::from_static(b"q=clip:sky"),
            )
            .is_err()
        );
    }

    #[test]
    fn metered_item_meters_all_four_advanced_search_endpoints() {
        let form = form_headers();
        let mut json = HeaderMap::new();
        json.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        let no_headers = HeaderMap::new();

        // 1. /api/search_advanced: free metadata-only advanced search.
        let free = metered_item(
            &Method::POST,
            "/api/search_advanced",
            &form,
            &Bytes::from_static(b"q=tag%3Amaid&sort=relevance&limit=50&offset=0"),
        )
        .unwrap();
        assert!(free.is_none());

        // 2. /api/search_advanced_embed: ChargeKind::EmbedSearch, sha256(q)[..32].
        let embed_q = "dino:42 AND tag:maid";
        let embed_req = metered_item(
            &Method::POST,
            "/api/search_advanced_embed",
            &form,
            &Bytes::from_static(b"q=dino%3A42+AND+tag%3Amaid&limit=50&offset=0"),
        )
        .unwrap()
        .expect("embed search must be metered");
        assert_eq!(embed_req.kind, ChargeKind::EmbedSearch);
        assert_eq!(
            embed_req.path,
            format!("search:adv_embed:{}", &sha256_hex(embed_q)[..32])
        );
        for (hdrs, body) in [
            (&json, &b"q=dino:42"[..]),
            (&no_headers, &b"q=dino:42"[..]),
            (&form, &b"limit=50"[..]),
            (&form, &b"q=&limit=50"[..]),
            (&form, &b"q=+++&limit=50"[..]),
            (&form, &b"q=dino:42&%71=dino:43"[..]),
        ] {
            assert!(
                metered_item(
                    &Method::POST,
                    "/api/search_advanced_embed",
                    hdrs,
                    &Bytes::copy_from_slice(body),
                )
                .is_err()
            );
        }

        // 3. /api/search_advanced_clip: ChargeKind::Description, sha256(q)[..32].
        let clip_q = "clip:\"sunset sky\" NOT tag:monochrome";
        let clip_req = metered_item(
            &Method::POST,
            "/api/search_advanced_clip",
            &form,
            &Bytes::from_static(
                b"q=clip%3A%22sunset+sky%22+NOT+tag%3Amonochrome&clip_weight=50&limit=50",
            ),
        )
        .unwrap()
        .expect("clip search must be metered");
        assert_eq!(clip_req.kind, ChargeKind::Description);
        assert_eq!(
            clip_req.path,
            format!("search:adv_clip:{}", &sha256_hex(clip_q)[..32])
        );
        for (hdrs, body) in [
            (&json, &b"q=clip:sky"[..]),
            (&no_headers, &b"q=clip:sky"[..]),
            (&form, &b"clip_weight=50"[..]),
            (&form, &b"q=&clip_weight=50"[..]),
            (&form, &b"q=%20%09"[..]),
        ] {
            assert!(
                metered_item(
                    &Method::POST,
                    "/api/search_advanced_clip",
                    hdrs,
                    &Bytes::copy_from_slice(body),
                )
                .is_err()
            );
        }

        // 4. /api/search_advanced_image: ChargeKind::Search, requires both q and images (non-empty).
        let img_q = "img:1 AND tag:maid";
        let img_slots = "AAAA,BBBB";
        let img_req = metered_item(
            &Method::POST,
            "/api/search_advanced_image",
            &form,
            &Bytes::from_static(b"q=img%3A1+AND+tag%3Amaid&images=AAAA%2CBBBB&clip_weight=50"),
        )
        .unwrap()
        .expect("image upload advanced search must be metered");
        assert_eq!(img_req.kind, ChargeKind::Search);
        assert_eq!(
            img_req.path,
            format!(
                "search:adv_img:{}",
                &sha256_hex(&format!("{img_q}\0{img_slots}"))[..32]
            )
        );
        // Null-byte delimiter prevents boundary collisions between q and images.
        let a = metered_item(
            &Method::POST,
            "/api/search_advanced_image",
            &form,
            &Bytes::from_static(b"q=ab&images=c"),
        )
        .unwrap()
        .unwrap();
        let b = metered_item(
            &Method::POST,
            "/api/search_advanced_image",
            &form,
            &Bytes::from_static(b"q=a&images=bc"),
        )
        .unwrap()
        .unwrap();
        assert_ne!(a.path, b.path);

        for (hdrs, body) in [
            (&json, &b"q=img:1&images=AAAA"[..]),
            (&no_headers, &b"q=img:1&images=AAAA"[..]),
            (&form, &b"q=img:1"[..]),
            (&form, &b"images=AAAA"[..]),
            (&form, &b"q=&images=AAAA"[..]),
            (&form, &b"q=+++&images=AAAA"[..]),
            (&form, &b"q=img:1&images="[..]),
            (&form, &b"q=img:1&images=+%09"[..]),
            (&form, &b"q=img:1&images=AAAA&images=BBBB"[..]),
            (&form, &b"q=img:1&images=A,B,C,D,E"[..]),
            (&form, &b"q=img:1&images=A,,B"[..]),
            (&form, &b"q=img:1&images=A,"[..]),
            (&form, &b"q=img:1&images=,A"[..]),
        ] {
            assert_eq!(
                metered_item(
                    &Method::POST,
                    "/api/search_advanced_image",
                    hdrs,
                    &Bytes::copy_from_slice(body),
                )
                .unwrap_err(),
                MeterError::BadRequest
            );
        }

        // Up to 4 non-empty comma-separated slots are accepted.
        assert!(
            metered_item(
                &Method::POST,
                "/api/search_advanced_image",
                &form,
                &Bytes::from_static(b"q=img%3A1&images=A%2CB%2CC%2CD"),
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn checked_methods_enforce_user_and_gallery_allowlists() {
        for (method, expected) in [
            (Method::GET, worker::Method::Get),
            (Method::HEAD, worker::Method::Head),
            (Method::POST, worker::Method::Post),
            (Method::DELETE, worker::Method::Delete),
            (Method::PUT, worker::Method::Put),
            (Method::PATCH, worker::Method::Patch),
            (Method::OPTIONS, worker::Method::Options),
        ] {
            assert_eq!(checked_user_method(&method), Some(expected));
        }
        for (method, expected) in [
            (Method::GET, worker::Method::Get),
            (Method::HEAD, worker::Method::Head),
            (Method::POST, worker::Method::Post),
        ] {
            assert_eq!(checked_gallery_method(&method), Some(expected));
        }
        for disallowed in [Method::DELETE, Method::PUT, Method::PATCH, Method::OPTIONS] {
            assert_eq!(checked_gallery_method(&disallowed), None);
        }
        let custom = Method::from_bytes(b"PURGE").unwrap();
        assert_eq!(checked_user_method(&custom), None);
        assert_eq!(checked_gallery_method(&custom), None);
        assert_eq!(checked_user_method(&Method::TRACE), None);
        assert_eq!(checked_gallery_method(&Method::TRACE), None);
    }

    #[test]
    fn is_same_origin_validates_origin_and_fetch_metadata() {
        let https_uri: Uri = "https://gallery.test/api/search_by_desc".parse().unwrap();
        let rel_uri: Uri = "/api/search_by_desc".parse().unwrap();
        let local_uri: Uri = "http://localhost:8787/api/search_by_desc".parse().unwrap();
        let loopback_uri: Uri = "http://127.0.0.1:8787/api/search_by_desc".parse().unwrap();

        let hdrs = |pairs: &[(&str, &str)]| {
            let mut h = HeaderMap::new();
            for &(k, v) in pairs {
                h.append(
                    axum::http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                );
            }
            h
        };

        // Allowed cases
        assert!(is_same_origin(
            &https_uri,
            &hdrs(&[("origin", "https://gallery.test")])
        ));
        assert!(is_same_origin(
            &https_uri,
            &hdrs(&[("origin", "https://GALLERY.TEST")])
        ));
        assert!(is_same_origin(
            &https_uri,
            &hdrs(&[
                ("origin", "https://gallery.test"),
                ("sec-fetch-site", "same-origin"),
            ])
        ));
        assert!(is_same_origin(
            &rel_uri,
            &hdrs(&[("host", "gallery.test"), ("origin", "https://gallery.test")])
        ));
        assert!(is_same_origin(
            &https_uri,
            &hdrs(&[("sec-fetch-site", "same-origin")])
        ));
        assert!(is_same_origin(
            &https_uri,
            &hdrs(&[("sec-fetch-site", "SAME-ORIGIN")])
        ));
        assert!(is_same_origin(
            &local_uri,
            &hdrs(&[("origin", "http://localhost:8787")])
        ));
        assert!(is_same_origin(
            &loopback_uri,
            &hdrs(&[("origin", "http://127.0.0.1:8787")])
        ));

        // Rejected cases
        assert!(!is_same_origin(&https_uri, &hdrs(&[])));
        assert!(!is_same_origin(
            &https_uri,
            &hdrs(&[("origin", "https://evil.gallery.test")])
        ));
        assert!(!is_same_origin(
            &https_uri,
            &hdrs(&[("origin", "https://unrelated.test")])
        ));
        assert!(!is_same_origin(
            &https_uri,
            &hdrs(&[("origin", "http://gallery.test")])
        ));
        assert!(!is_same_origin(
            &https_uri,
            &hdrs(&[
                ("origin", "https://gallery.test"),
                ("sec-fetch-site", "same-site"),
            ])
        ));
        assert!(!is_same_origin(
            &https_uri,
            &hdrs(&[
                ("origin", "https://gallery.test"),
                ("sec-fetch-site", "cross-site"),
            ])
        ));
        assert!(!is_same_origin(
            &https_uri,
            &hdrs(&[("sec-fetch-site", "same-site")])
        ));
        assert!(!is_same_origin(
            &https_uri,
            &hdrs(&[("sec-fetch-site", "none")])
        ));
        assert!(!is_same_origin(
            &local_uri,
            &hdrs(&[("origin", "http://localhost:9999")])
        ));
        assert!(!is_same_origin(
            &https_uri,
            &hdrs(&[
                ("origin", "https://gallery.test"),
                ("origin", "https://evil.gallery.test"),
            ])
        ));
    }

    #[test]
    fn canonical_media_path_dedupes_equivalent_encodings() {
        let raw = metered_item(
            &Method::GET,
            "/images/a(1).webp",
            &HeaderMap::new(),
            &Bytes::new(),
        )
        .unwrap()
        .unwrap();
        let encoded = metered_item(
            &Method::GET,
            "/images/a%281%29.webp",
            &HeaderMap::new(),
            &Bytes::new(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(raw.path, "/images/a%281%29.webp");
        assert_eq!(raw.path, encoded.path);
        assert_eq!(
            canonical_media_path("/images/Demo%20album/a+b%2a%7e.webp").as_deref(),
            Some("/images/Demo%20album/a%2Bb%2A~.webp")
        );
        assert_eq!(canonical_media_path("/images/bad%2"), None);
    }

    #[test]
    fn metered_item_enforces_body_limits_and_hashed_search_keys() {
        let form = form_headers();

        // /api/search_similar: positive i64 only, hashed key on q.trim()
        let sim = metered_item(
            &Method::POST,
            "/api/search_similar",
            &form,
            &Bytes::from_static(b"q=+42+"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(sim.kind, ChargeKind::EmbedSearch);
        assert_eq!(sim.path, format!("search:sim:{}", &sha256_hex("42")[..32]));
        for bad in [&b"q="[..], &b"q=0"[..], &b"q=-5"[..], &b"q=abc"[..]] {
            assert_eq!(
                metered_item(
                    &Method::POST,
                    "/api/search_similar",
                    &form,
                    &Bytes::copy_from_slice(bad),
                )
                .unwrap_err(),
                MeterError::BadRequest
            );
        }

        // /api/search_by_desc: non-empty, <= 2000 bytes, hashed key on q.trim()
        let desc = metered_item(
            &Method::POST,
            "/api/search_by_desc",
            &form,
            &Bytes::from_static(b"q=+blue+sky+"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(desc.kind, ChargeKind::Description);
        assert_eq!(
            desc.path,
            format!("search:desc:{}", &sha256_hex("blue sky")[..32])
        );
        let max_desc = format!("q={}", "a".repeat(2000));
        assert!(
            metered_item(
                &Method::POST,
                "/api/search_by_desc",
                &form,
                &Bytes::from(max_desc),
            )
            .is_ok()
        );
        let too_long_desc = format!("q={}", "a".repeat(2001));
        assert_eq!(
            metered_item(
                &Method::POST,
                "/api/search_by_desc",
                &form,
                &Bytes::from(too_long_desc),
            )
            .unwrap_err(),
            MeterError::BadRequest
        );
        assert_eq!(
            metered_item(
                &Method::POST,
                "/api/search_by_desc",
                &form,
                &Bytes::from_static(b"q=+++"),
            )
            .unwrap_err(),
            MeterError::BadRequest
        );

        // /api/search_by_image: non-empty image, 1 MiB body limit
        assert_eq!(
            metered_item(
                &Method::POST,
                "/api/search_by_image",
                &form,
                &Bytes::from_static(b"image="),
            )
            .unwrap_err(),
            MeterError::BadRequest
        );

        // Per-route 413 body limits
        let over_32k = Bytes::from(vec![b'a'; MAX_TEXT_SEARCH_BODY_BYTES + 1]);
        for route in [
            "/api/search_similar",
            "/api/search_by_desc",
            "/api/search_advanced_embed",
            "/api/search_advanced_clip",
        ] {
            assert_eq!(
                metered_item(&Method::POST, route, &form, &over_32k).unwrap_err(),
                MeterError::PayloadTooLarge,
                "expected 413 on {route}"
            );
        }
        let over_1m = Bytes::from(vec![b'a'; MAX_IMAGE_SEARCH_BODY_BYTES + 1]);
        assert_eq!(
            metered_item(&Method::POST, "/api/search_by_image", &form, &over_1m).unwrap_err(),
            MeterError::PayloadTooLarge
        );
        let over_4m = Bytes::from(vec![b'a'; MAX_GATEWAY_BODY_BYTES + 1]);
        assert_eq!(
            metered_item(&Method::POST, "/api/search_advanced_image", &form, &over_4m).unwrap_err(),
            MeterError::PayloadTooLarge
        );
    }

    #[test]
    fn hold_wire_types_round_trip() {
        let req = HoldReq {
            hold_id: "hold-123".into(),
        };
        let encoded = serde_json::to_string(&req).unwrap();
        let decoded: HoldReq = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.hold_id, "hold-123");

        for expected in [Some("hold-123".to_string()), None] {
            let resp = HoldResp {
                hold_id: expected.clone(),
            };
            let encoded = serde_json::to_string(&resp).unwrap();
            let decoded: HoldResp = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded.hold_id, expected);
        }
    }
}
