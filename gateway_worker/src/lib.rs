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
    admin_email: Option<String>,
    client_id: Arc<String>,
    client_secret: Arc<String>,
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

    let state = AppState {
        admin_email: access_admin(&ctx, &env).await?,
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
use site_access::{ADMIN_VIEW_COOKIE, ChargeKind, ChargeReq, GuestReq};

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

    if is_segment_prefix(path, "/user/admin") {
        let Some(email) = st.admin_email.as_deref() else {
            return (StatusCode::FORBIDDEN, "Administrator access required").into_response();
        };
        let browse_entry = method == Method::GET && path == "/user/admin/browse";
        let mut response = if browse_entry {
            Redirect::to("/").into_response()
        } else {
            forward_user(&st, &uri, &method, &headers, body, Some(email)).await
        };
        response
            .headers_mut()
            .insert("cache-control", "private, no-store".parse().unwrap());
        if method == Method::GET && (browse_entry || response.status().is_success()) {
            let pass =
                site_access::admin_view_pass(&st.jwt_secret, now_secs() + site_access::VIEW_TTL);
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
    if is_segment_prefix(path, "/user") {
        return forward_user(&st, &uri, &method, &headers, body, None).await;
    }
    let browse = browse_route(&method, path);
    let now = now_secs();
    let pass = cookies
        .get(ADMIN_VIEW_COOKIE)
        .is_some_and(|c| site_access::valid_admin_view(&st.jwt_secret, c.value(), now));
    if browse && (pass || st.admin_email.is_some()) {
        return proxy(uri, method, headers, body, &st.client_id, &st.client_secret).await;
    }

    let claims = cookies
        .get(SESSION_COOKIE)
        .and_then(|tok| jwt_verify(tok.value(), &st.jwt_secret, now));
    if claims.is_none() && !browse {
        return login_response(&uri, &method);
    }
    let item = match metered_item(&method, path, &headers, &body) {
        Ok(item) => item,
        Err(()) => return (StatusCode::BAD_REQUEST, "Invalid search request").into_response(),
    };
    let guest = claims.is_none();
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
            let ip = headers
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok());
            // A missing client address shares a single quota, including local development.
            let id = ip
                .map(|ip| site_access::guest_account(&st.jwt_secret, ip))
                .unwrap_or_else(|| "guest:unknown".into());
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
        Ok(200) => proxy(uri, method, headers, body, &st.client_id, &st.client_secret).await,
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

fn metered_item(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> std::result::Result<Option<ChargeReq>, ()> {
    if matches!(*method, Method::GET | Method::HEAD) {
        let kind = if is_segment_prefix(path, "/images") {
            ChargeKind::Image
        } else if is_segment_prefix(path, "/videos") {
            ChargeKind::Video
        } else {
            return Ok(None);
        };
        return Ok(Some(ChargeReq {
            path: path.to_owned(),
            kind,
        }));
    }
    if method != Method::POST {
        return Ok(None);
    }
    let (kind, field, prefix) = match path {
        "/api/search_similar" => (ChargeKind::EmbedSearch, "q", "search:sim:"),
        "/api/search_by_image" => (ChargeKind::Search, "image", "search:img:"),
        "/api/search_by_desc" => (ChargeKind::Description, "q", "search:desc:"),
        _ => return Ok(None),
    };
    let ok = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !ok {
        return Err(());
    }
    let value = form_field(body, field).ok_or(())?;
    let key = if kind == ChargeKind::Search {
        sha256_hex(&value)[..32].to_owned()
    } else {
        value
    };
    Ok(Some(ChargeReq {
        kind,
        path: format!("{prefix}{key}"),
    }))
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
// /user/* → user-worker (service binding)
// ---------------------------------------------------------------------------

async fn forward_user(
    st: &AppState,
    uri: &Uri,
    method: &Method,
    headers: &HeaderMap,
    body: Bytes,
    admin_email: Option<&str>,
) -> Response {
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target = format!("https://user-worker{pq}");

    let mut init = RequestInit::new();
    init.with_method(method.to_string().into());
    init.with_redirect(worker::RequestRedirect::Manual);

    if !matches!(*method, Method::GET | Method::HEAD) && !body.is_empty() {
        init.with_body(Some(Uint8Array::from(&body[..]).into()));
    }

    // forward all headers — cookie included, the user-worker needs `ue_session`
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

fn build_upstream_target(uri: &Uri) -> std::result::Result<(String, worker::Url), ()> {
    let path = uri.path();
    if !path.starts_with('/') {
        return Err(());
    }
    let (upstream, upstream_path) = if is_segment_prefix(path, "/images") {
        (IMAGE_UPSTREAM, path.strip_prefix("/images").unwrap_or(""))
    } else if is_segment_prefix(path, "/videos") {
        (VIDEO_UPSTREAM, path.strip_prefix("/videos").unwrap_or(""))
    } else {
        (API_UPSTREAM, path)
    };

    let mut target = format!("{upstream}{upstream_path}");
    if let Some(q) = uri.query() {
        target.push('?');
        target.push_str(q);
    }

    let base_url = worker::Url::parse(upstream).map_err(|_| ())?;
    let target_url = worker::Url::parse(&target).map_err(|_| ())?;
    if target_url.scheme() != base_url.scheme()
        || target_url.host_str() != base_url.host_str()
        || target_url.port_or_known_default() != base_url.port_or_known_default()
        || !target_url.username().is_empty()
        || target_url.password().is_some()
    {
        return Err(());
    }
    Ok((target, target_url))
}

async fn proxy(
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    client_id: &str,
    client_secret: &str,
) -> Response {
    let Ok((target, _target_url)) = build_upstream_target(&uri) else {
        return (StatusCode::BAD_REQUEST, "invalid request URI").into_response();
    };

    let mut req_init = RequestInit::new();
    req_init.with_method(method.to_string().into());
    req_init.with_redirect(worker::RequestRedirect::Manual);

    if !matches!(method, Method::GET | Method::HEAD) && !body.is_empty() {
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
            worker::console_error!("fetch to {target} failed: {e:?}");
            (
                StatusCode::BAD_GATEWAY,
                format!("upstream fetch failed: {e}"),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn browse_route_allows_pinned_metadata_and_blocks_guest_like_previews() {
        assert!(browse_route(&Method::POST, "/api/fetch_post_meta"));
        assert!(browse_route(&Method::POST, "/api/suggest_search"));
        assert!(!browse_route(&Method::POST, "/api/suggest_search123456"));
        assert!(!browse_route(&Method::POST, "/api/suggest_search_evil"));
        assert!(!browse_route(&Method::GET, "/api/like_previews"));
    }
}
