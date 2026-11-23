//! Hardened edge gateway Worker (`lets-embed-gateway-worker`).
//!
//! Enforces:
//! - Step 0 authoritative geo-blocking via `request.cf().country()` (exempting `/admin*`)
//! - Fail-closed policy sync from singleton `SITE_POLICY` DO (`"global"`, `GET /policy`)
//! - Cloudflare Access-verified `/admin*` routing to `ADMIN_DASHBOARD_WORKER`
//! - Unconditional `404` retirement of `/user/admin*`
//! - Revocable `v2` sessions + legacy cutover with live `USER_ACCOUNT` DO `/session-context`
//! - Raw `/images/*` & `/videos/*` `404` blocking and capability-based `/media/*` enforcement
//! - Authorize-before-bill canonical metering & separated `/preview-budget` with locked CF blur
//! - Privileged header/cookie stripping + signed short-lived `X-Gateway-Assertion`

mod auth;
mod http_util;
mod media;

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::any,
};
use serde::{Deserialize, Serialize};
use site_access::{
    ADMIN_HEADER, ADMIN_VIEW_COOKIE, GATEWAY_ASSERTION_AUDIENCE, GATEWAY_ASSERTION_HEADER,
    GATEWAY_ASSERTION_TTL, GATEWAY_ASSERTION_VERSION, GatewayAssertion, GuestReq, HoldReq,
    HoldResp, MediaCapKind, PublicSitePolicy, SESSION_COOKIE, SessionContext,
    compute_policy_digest, is_privileged_request_header, sign_gateway_assertion,
    verify_media_capability, verify_session_any,
};
use tower_cookies::{CookieManagerLayer, Cookies};
use tower_service::Service;
use worker::{
    Context, Env, Fetch, HttpRequest, Request, RequestInit, Result, event, js_sys::Uint8Array,
    wasm_bindgen::JsValue,
};

use crate::auth::{
    ADMIN_VIEW_SUB, LiveSession, SessionContextReq, admin_eligible_switchers,
    clear_session_cookie_header, compute_eligible_switchers,
};
use crate::http_util::{
    GALLERY_ALLOWED_METHODS, MAX_GATEWAY_BODY_BYTES, MEDIA_ALLOWED_METHODS, USER_ALLOWED_METHODS,
    Upstreams, browse_route, build_api_upstream_target, checked_gallery_method,
    checked_media_method, checked_user_method, guest_id, is_always_public_path, is_canonical_path,
    is_hop_by_hop, is_public_cacheable_path, is_same_origin, is_segment_prefix, is_sitemap_path,
    login_response, metered_item, method_not_allowed, payment_required, private_no_store,
    request_host, sanitize_origin_cookie, sanitize_user_worker_cookie,
    should_strip_api_request_header,
};
use crate::media::{
    PreviewBlurConfig, PreviewBudgetReq, authorize_media_capability, build_media_upstream_target,
    extract_media_cap_query, is_allowed_media_request_header, parse_media_route,
    resolve_preview_blur,
};

// ---------------------------------------------------------------------------
// Policy Snapshot & Validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SitePolicyResponse {
    policy: PublicSitePolicy,
    digest: String,
}

#[derive(Debug, Clone)]
struct SitePolicySnapshot {
    policy: PublicSitePolicy,
    digest: String,
}

fn validate_site_policy_response(
    resp: SitePolicyResponse,
) -> std::result::Result<SitePolicySnapshot, &'static str> {
    if resp.policy.min_enforce_rev > resp.policy.revision {
        return Err("min_enforce_rev exceeds policy revision");
    }
    let computed = compute_policy_digest(&resp.policy);
    if resp.digest != computed {
        return Err("policy digest mismatch");
    }
    Ok(SitePolicySnapshot {
        policy: resp.policy,
        digest: computed,
    })
}

// ---------------------------------------------------------------------------
// Gateway Configuration & Backend Abstraction (enables full host E2E tests)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct GatewayConfig {
    jwt_secret: Arc<Vec<u8>>,
    session_v2_secret: Arc<Vec<u8>>,
    gateway_assertion_secret: Arc<Vec<u8>>,
    media_cap_secret: Arc<Vec<u8>>,
    admin_email: Option<String>,
    visitor_country: Option<String>,
    client_id: Arc<String>,
    client_secret: Arc<String>,
    upstreams: Arc<Upstreams>,
}

#[derive(Clone)]
struct AppState {
    env: Arc<Env>,
    cfg: GatewayConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceTarget {
    UserWorker,
    AdminDashboard,
}

impl ServiceTarget {
    const fn binding_name(self) -> &'static str {
        match self {
            Self::UserWorker => "USER_WORKER",
            Self::AdminDashboard => "ADMIN_DASHBOARD_WORKER",
        }
    }

    const fn target_origin(self) -> &'static str {
        match self {
            Self::UserWorker => "https://lets-embed-user-worker",
            Self::AdminDashboard => "https://lets-embed-admin-dashboard-worker",
        }
    }
}

#[derive(Debug)]
struct ForwardedServiceReq {
    path_and_query: String,
    method: worker::Method,
    headers: Vec<(String, String)>,
    body: Bytes,
}

#[derive(Debug)]
struct UpstreamFetchReq {
    url: worker::Url,
    method: worker::Method,
    headers: Vec<(String, String)>,
    body: Bytes,
    no_cache: bool,
    preview_blur: Option<PreviewBlurConfig>,
}

#[derive(Debug)]
struct BackendError(String);

impl From<worker::Error> for BackendError {
    fn from(err: worker::Error) -> Self {
        Self(format!("{err:?}"))
    }
}

#[allow(async_fn_in_trait)]
trait GatewayBackend {
    fn now_secs(&self) -> u64;
    async fn load_site_policy(&self) -> std::result::Result<SitePolicySnapshot, BackendError>;
    async fn load_session_context(
        &self,
        do_key: &str,
        sid: Option<&str>,
    ) -> std::result::Result<SessionContext, BackendError>;
    async fn account_call(
        &self,
        do_key: &str,
        operation: &str,
        payload: serde_json::Value,
    ) -> std::result::Result<u16, BackendError>;
    async fn account_reserve(
        &self,
        do_key: &str,
        operation: &str,
        payload: serde_json::Value,
    ) -> std::result::Result<(u16, Option<String>), BackendError>;
    async fn forward_service(
        &self,
        target: ServiceTarget,
        req: ForwardedServiceReq,
    ) -> std::result::Result<Response, BackendError>;
    async fn fetch_upstream(
        &self,
        req: UpstreamFetchReq,
    ) -> std::result::Result<Response, BackendError>;
}

// ---------------------------------------------------------------------------
// Cloudflare Workers Runtime Backend
// ---------------------------------------------------------------------------

struct WorkerBackend<'a> {
    env: &'a Env,
}

fn build_cf_object(
    no_cache: bool,
    blur: Option<PreviewBlurConfig>,
) -> Option<worker::js_sys::Object> {
    if !no_cache && blur.is_none() {
        return None;
    }
    let cf = worker::js_sys::Object::new();
    if no_cache {
        let _ = worker::js_sys::Reflect::set(&cf, &"cacheTtl".into(), &JsValue::from_f64(0.0));
        let _ = worker::js_sys::Reflect::set(&cf, &"cacheEverything".into(), &JsValue::FALSE);
    }
    if let Some(cfg) = blur {
        let img = worker::js_sys::Object::new();
        let _ = worker::js_sys::Reflect::set(
            &img,
            &"blur".into(),
            &JsValue::from_f64(f64::from(cfg.blur)),
        );
        let _ = worker::js_sys::Reflect::set(
            &img,
            &"width".into(),
            &JsValue::from_f64(cfg.width as f64),
        );
        let _ = worker::js_sys::Reflect::set(
            &img,
            &"quality".into(),
            &JsValue::from_f64(f64::from(cfg.quality)),
        );
        let _ = worker::js_sys::Reflect::set(&img, &"format".into(), &JsValue::from_str(cfg.format));
        let _ = worker::js_sys::Reflect::set(&cf, &"image".into(), &img);
    }
    Some(cf)
}

impl GatewayBackend for WorkerBackend<'_> {
    fn now_secs(&self) -> u64 {
        worker::Date::now().as_millis() / 1000
    }

    async fn load_site_policy(&self) -> std::result::Result<SitePolicySnapshot, BackendError> {
        let req = Request::new("https://site-policy/policy", worker::Method::Get)?;
        let stub = self
            .env
            .durable_object("SITE_POLICY")?
            .id_from_name("global")?
            .get_stub()?;
        let mut resp = stub.fetch_with_request(req).await?;
        let status = resp.status_code();
        if status != 200 {
            return Err(BackendError(format!("SITE_POLICY returned HTTP {status}")));
        }
        let parsed: SitePolicyResponse = resp.json().await?;
        validate_site_policy_response(parsed).map_err(|reason| BackendError(reason.to_string()))
    }

    async fn load_session_context(
        &self,
        do_key: &str,
        sid: Option<&str>,
    ) -> std::result::Result<SessionContext, BackendError> {
        let body = serde_json::to_string(&SessionContextReq {
            sid: sid.map(str::to_string),
        })
        .map_err(|e| BackendError(format!("serialize session-context req: {e}")))?;
        let mut init = RequestInit::new();
        init.with_method(worker::Method::Post);
        init.with_body(Some(JsValue::from_str(&body)));
        init.headers.set("content-type", "application/json")?;
        let req = Request::new_with_init("https://do/session-context", &init)?;

        let stub = self
            .env
            .durable_object("USER_ACCOUNT")?
            .id_from_name(do_key)?
            .get_stub()?;
        let mut resp = stub.fetch_with_request(req).await?;
        let status = resp.status_code();
        if status != 200 {
            return Err(BackendError(format!(
                "USER_ACCOUNT /session-context returned HTTP {status}"
            )));
        }
        Ok(resp.json().await?)
    }

    async fn account_call(
        &self,
        do_key: &str,
        operation: &str,
        payload: serde_json::Value,
    ) -> std::result::Result<u16, BackendError> {
        let body = serde_json::to_string(&payload)
            .map_err(|e| BackendError(format!("serialize DO payload: {e}")))?;
        let mut init = RequestInit::new();
        init.with_method(worker::Method::Post);
        init.with_body(Some(JsValue::from_str(&body)));
        init.headers.set("content-type", "application/json")?;
        let req = Request::new_with_init(&format!("https://do/{operation}"), &init)?;

        let stub = self
            .env
            .durable_object("USER_ACCOUNT")?
            .id_from_name(do_key)?
            .get_stub()?;
        Ok(stub.fetch_with_request(req).await?.status_code())
    }

    async fn account_reserve(
        &self,
        do_key: &str,
        operation: &str,
        payload: serde_json::Value,
    ) -> std::result::Result<(u16, Option<String>), BackendError> {
        let body = serde_json::to_string(&payload)
            .map_err(|e| BackendError(format!("serialize DO reserve payload: {e}")))?;
        let mut init = RequestInit::new();
        init.with_method(worker::Method::Post);
        init.with_body(Some(JsValue::from_str(&body)));
        init.headers.set("content-type", "application/json")?;
        let req = Request::new_with_init(&format!("https://do/{operation}"), &init)?;

        let stub = self
            .env
            .durable_object("USER_ACCOUNT")?
            .id_from_name(do_key)?
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

    async fn forward_service(
        &self,
        target: ServiceTarget,
        req: ForwardedServiceReq,
    ) -> std::result::Result<Response, BackendError> {
        let url = format!("{}{}", target.target_origin(), req.path_and_query);
        let mut init = RequestInit::new();
        let has_body = !matches!(req.method, worker::Method::Get | worker::Method::Head);
        init.with_method(req.method);
        init.with_redirect(worker::RequestRedirect::Manual);
        if has_body && !req.body.is_empty() {
            init.with_body(Some(Uint8Array::from(&req.body[..]).into()));
        }
        for (name, val) in &req.headers {
            let _ = init.headers.append(name, val);
        }
        let worker_req = Request::new_with_init(&url, &init)?;
        let resp = self
            .env
            .service(target.binding_name())?
            .fetch_request(worker_req)
            .await?;
        Ok(resp.map(axum::body::Body::new))
    }

    async fn fetch_upstream(
        &self,
        req: UpstreamFetchReq,
    ) -> std::result::Result<Response, BackendError> {
        let mut init = RequestInit::new();
        let has_body = !matches!(req.method, worker::Method::Get | worker::Method::Head);
        init.with_method(req.method);
        init.with_redirect(worker::RequestRedirect::Manual);
        if has_body && !req.body.is_empty() {
            init.with_body(Some(Uint8Array::from(&req.body[..]).into()));
        }
        for (name, val) in &req.headers {
            let _ = init.headers.append(name, val);
        }
        let js_init: worker::web_sys::RequestInit = (&init).into();
        if let Some(cf) = build_cf_object(req.no_cache, req.preview_blur) {
            let _ = worker::js_sys::Reflect::set(js_init.as_ref(), &"cf".into(), &cf);
        }
        let web_req = worker::web_sys::Request::new_with_str_and_init(req.url.as_str(), &js_init)
            .map_err(|e| BackendError(format!("build upstream request failed: {e:?}")))?;
        let worker_req = Request::from(web_req);
        let resp = Fetch::Request(worker_req).send().await?;
        Ok(Response::from(resp))
    }
}

// ---------------------------------------------------------------------------
// Entry Point & Cloudflare Access Extraction
// ---------------------------------------------------------------------------

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
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty()))
}

fn required_secret_bytes(env: &Env, name: &str) -> Result<Vec<u8>> {
    let val = env.secret(name)?.to_string();
    if val.is_empty() {
        return Err(worker::Error::RustError(format!("empty secret: {name}")));
    }
    Ok(val.into_bytes())
}

fn required_secret_string(env: &Env, name: &str) -> Result<String> {
    let val = env.secret(name)?.to_string();
    if val.is_empty() {
        return Err(worker::Error::RustError(format!("empty secret: {name}")));
    }
    Ok(val)
}

async fn router(env: Env, ctx: Context, visitor_country: Option<String>) -> Result<Router> {
    let client_id = required_secret_string(&env, "CF_ACCESS_CLIENT_ID")?;
    let client_secret = required_secret_string(&env, "CF_ACCESS_CLIENT_SECRET")?;
    let jwt_secret = required_secret_bytes(&env, "JWT_SECRET")?;
    // Dedicated SESSION_V2_SECRET is recommended; during cutover, if unset or empty,
    // fall back to JWT_SECRET (domain-separated inside site_access::verify_session_v2
    // with the `"session/v2\0"` HMAC domain prefix).
    let session_v2_secret = match env.secret("SESSION_V2_SECRET") {
        Ok(secret) => {
            let s = secret.to_string();
            if s.is_empty() {
                jwt_secret.clone()
            } else {
                s.into_bytes()
            }
        }
        Err(_) => jwt_secret.clone(),
    };
    let gateway_assertion_secret = required_secret_bytes(&env, "GATEWAY_ASSERTION_SECRET")?;
    let media_cap_secret = required_secret_bytes(&env, "MEDIA_CAP_SECRET")?;
    let upstreams = Upstreams::from_env(&env)?;
    let admin_email = access_admin(&ctx, &env).await?;

    let state = AppState {
        env: Arc::new(env),
        cfg: GatewayConfig {
            jwt_secret: Arc::new(jwt_secret),
            session_v2_secret: Arc::new(session_v2_secret),
            gateway_assertion_secret: Arc::new(gateway_assertion_secret),
            media_cap_secret: Arc::new(media_cap_secret),
            admin_email,
            visitor_country,
            client_id: Arc::new(client_id),
            client_secret: Arc::new(client_secret),
            upstreams: Arc::new(upstreams),
        },
    };

    Ok(Router::new()
        .fallback(any(gateway))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_GATEWAY_BODY_BYTES))
        .layer(CookieManagerLayer::new())
        .with_state(state))
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, ctx: Context) -> Result<Response> {
    // Authoritative Cloudflare runtime country (from `request.cf.country`).
    // NEVER read the spoofable `CF-IPCountry` header.
    let visitor_country = req
        .extensions()
        .get::<worker::Cf>()
        .and_then(|cf| cf.country());
    Ok(router(env, ctx, visitor_country).await?.call(req).await?)
}

#[worker::send]
async fn gateway(
    State(st): State<AppState>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    cookies: Cookies,
    body: Bytes,
) -> Response {
    let backend = WorkerBackend { env: &st.env };
    handle_gateway_request(&backend, &st.cfg, uri, method, headers, cookies, body).await
}

// ---------------------------------------------------------------------------
// Core Hardened Request Pipeline
// ---------------------------------------------------------------------------

enum SessionResolution {
    Authenticated(LiveSession),
    Unauthenticated { clear_cookie: bool },
    Banned,
    BackendUnavailable,
}

async fn resolve_live_session(
    backend: &impl GatewayBackend,
    cfg: &GatewayConfig,
    cookies: &Cookies,
    policy: &PublicSitePolicy,
    now: u64,
) -> SessionResolution {
    let Some(raw_cookie) = cookies.get(SESSION_COOKIE) else {
        return SessionResolution::Unauthenticated {
            clear_cookie: false,
        };
    };
    let Ok(verified) = verify_session_any(
        raw_cookie.value(),
        &cfg.session_v2_secret,
        Some(&cfg.jwt_secret),
        now,
    ) else {
        return SessionResolution::Unauthenticated { clear_cookie: true };
    };

    match backend
        .load_session_context(verified.do_key(), verified.sid())
        .await
    {
        Ok(ctx) => {
            if !ctx.active || ctx.banned {
                return SessionResolution::Banned;
            }
            if !ctx.sid_valid {
                return SessionResolution::Unauthenticated { clear_cookie: true };
            }
            let eligible_switchers = compute_eligible_switchers(&ctx, policy);
            SessionResolution::Authenticated(LiveSession {
                session: verified,
                ctx,
                eligible_switchers,
            })
        }
        Err(err) => {
            log_backend_error("session-context check failed", &err);
            SessionResolution::BackendUnavailable
        }
    }
}

fn maybe_clear_session_cookie(mut response: Response, clear_cookie: bool) -> Response {
    if clear_cookie {
        response.headers_mut().append(
            "set-cookie",
            clear_session_cookie_header()
                .parse()
                .expect("ASCII Set-Cookie"),
        );
        response = private_no_store(response);
    }
    response
}

fn log_backend_error(context: &str, err: &BackendError) {
    #[cfg(target_arch = "wasm32")]
    worker::console_error!("{context}: {}", err.0);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (context, err.0.as_str());
}

fn build_service_headers(
    headers: &HeaderMap,
    target: ServiceTarget,
    admin_email: Option<&str>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in headers {
        let name = k.as_str();
        if is_hop_by_hop(name)
            || is_privileged_request_header(name)
            || name.eq_ignore_ascii_case("x-forwarded-host")
            || name.eq_ignore_ascii_case("x-forwarded-proto")
            || name.eq_ignore_ascii_case("forwarded")
            || name.eq_ignore_ascii_case("cf-ipcountry")
            || name.eq_ignore_ascii_case("cookie")
        {
            continue;
        }
        if let Ok(val) = v.to_str() {
            out.push((name.to_string(), val.to_string()));
        }
    }

    match target {
        ServiceTarget::UserWorker => {
            if let Some(cookie) = sanitize_user_worker_cookie(headers) {
                out.push(("cookie".to_string(), cookie));
            }
        }
        ServiceTarget::AdminDashboard => {
            // Preserve admin SPA cookies (e.g., CSRF cookie) while stripping all
            // sensitive origin/auth cookies (`STRIPPED_ORIGIN_COOKIES`).
            if let Some(cookie) = sanitize_origin_cookie(headers) {
                out.push(("cookie".to_string(), cookie));
            }
            if let Some(email) = admin_email {
                out.push((ADMIN_HEADER.to_string(), email.to_string()));
            }
        }
    }
    out
}

fn build_api_headers(
    uri: &Uri,
    headers: &HeaderMap,
    cfg: &GatewayConfig,
    signed_assertion: &str,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in headers {
        let name = k.as_str();
        if should_strip_api_request_header(name) {
            continue;
        }
        if let Ok(val) = v.to_str() {
            out.push((name.to_string(), val.to_string()));
        }
    }
    if let Some(host) = request_host(uri, headers) {
        let proto = if uri
            .scheme_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("http"))
        {
            "http"
        } else {
            "https"
        };
        out.push(("x-forwarded-host".to_string(), host.to_string()));
        out.push(("x-forwarded-proto".to_string(), proto.to_string()));
    }
    if let Some(cookie) = sanitize_origin_cookie(headers) {
        out.push(("cookie".to_string(), cookie));
    }
    out.push(("CF-Access-Client-Id".to_string(), cfg.client_id.to_string()));
    out.push((
        "CF-Access-Client-Secret".to_string(),
        cfg.client_secret.to_string(),
    ));
    out.push((
        GATEWAY_ASSERTION_HEADER.to_string(),
        signed_assertion.to_string(),
    ));
    out
}

fn build_media_headers(headers: &HeaderMap, cfg: &GatewayConfig) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in headers {
        let name = k.as_str();
        if is_allowed_media_request_header(name)
            && !is_privileged_request_header(name)
            && let Ok(val) = v.to_str()
        {
            out.push((name.to_string(), val.to_string()));
        }
    }
    out.push(("CF-Access-Client-Id".to_string(), cfg.client_id.to_string()));
    out.push((
        "CF-Access-Client-Secret".to_string(),
        cfg.client_secret.to_string(),
    ));
    out
}

#[derive(Debug, Default)]
struct AssertionSubject {
    sub: Option<String>,
    sid: Option<String>,
    switchers: Vec<String>,
    safe_mode: bool,
    is_admin_view: bool,
}

fn sign_assertion_for_request(
    cfg: &GatewayConfig,
    snapshot: &SitePolicySnapshot,
    now: u64,
    subject: AssertionSubject,
) -> std::result::Result<String, site_access::TokenError> {
    let assertion = GatewayAssertion {
        v: GATEWAY_ASSERTION_VERSION,
        aud: GATEWAY_ASSERTION_AUDIENCE.to_string(),
        rev: snapshot.policy.revision,
        min_enforce_rev: snapshot.policy.min_enforce_rev,
        policy_digest: snapshot.digest.clone(),
        sub: subject.sub,
        sid: subject.sid,
        switchers: subject.switchers,
        safe_mode: subject.safe_mode,
        is_admin_view: subject.is_admin_view,
        exp: now.saturating_add(GATEWAY_ASSERTION_TTL),
    };
    sign_gateway_assertion(&assertion, &cfg.gateway_assertion_secret)
}

fn assertion_sign_error_response() -> Response {
    private_no_store(
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to sign gateway assertion",
        )
            .into_response(),
    )
}

#[allow(clippy::too_many_arguments)]
async fn proxy_to_api(
    backend: &impl GatewayBackend,
    cfg: &GatewayConfig,
    uri: &Uri,
    worker_method: worker::Method,
    headers: &HeaderMap,
    body: Bytes,
    signed_assertion: &str,
    allow_public_cache: bool,
) -> Response {
    let Ok(target_url) = build_api_upstream_target(uri, &cfg.upstreams) else {
        return private_no_store((StatusCode::BAD_REQUEST, "invalid request URI").into_response());
    };
    let req = UpstreamFetchReq {
        url: target_url,
        method: worker_method,
        headers: build_api_headers(uri, headers, cfg, signed_assertion),
        body,
        no_cache: !allow_public_cache,
        preview_blur: None,
    };
    match backend.fetch_upstream(req).await {
        Ok(resp) => {
            if allow_public_cache
                && resp.status().is_success()
                && !resp.headers().contains_key("set-cookie")
            {
                resp
            } else {
                private_no_store(resp)
            }
        }
        Err(err) => {
            log_backend_error("upstream API fetch failed", &err);
            private_no_store((StatusCode::BAD_GATEWAY, "upstream fetch failed").into_response())
        }
    }
}

async fn handle_admin_route(
    backend: &impl GatewayBackend,
    cfg: &GatewayConfig,
    uri: &Uri,
    method: &Method,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let Some(worker_method) = checked_user_method(method) else {
        return method_not_allowed(USER_ALLOWED_METHODS);
    };
    let Some(email) = cfg.admin_email.as_deref() else {
        return private_no_store(
            (StatusCode::FORBIDDEN, "Administrator access required").into_response(),
        );
    };

    let path = uri.path();
    let browse_entry = *method == Method::GET && path == "/admin/browse";
    let mut response = if browse_entry {
        Redirect::to("/").into_response()
    } else {
        let pq = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/admin")
            .to_string();
        let req = ForwardedServiceReq {
            path_and_query: pq,
            method: worker_method,
            headers: build_service_headers(headers, ServiceTarget::AdminDashboard, Some(email)),
            body,
        };
        match backend
            .forward_service(ServiceTarget::AdminDashboard, req)
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                log_backend_error("lets-embed-admin-dashboard-worker fetch failed", &err);
                (StatusCode::BAD_GATEWAY, "admin service unavailable").into_response()
            }
        }
    };

    response = private_no_store(response);
    if *method == Method::GET
        && (browse_entry
            || (!is_segment_prefix(path, "/admin/api") && response.status().is_success()))
    {
        let pass = site_access::admin_view_pass(
            &cfg.jwt_secret,
            backend.now_secs().saturating_add(site_access::VIEW_TTL),
        );
        let cookie = format!(
            "{ADMIN_VIEW_COOKIE}={pass}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
            site_access::VIEW_TTL
        );
        response
            .headers_mut()
            .append("set-cookie", cookie.parse().expect("ASCII signed pass"));
    }
    response
}

#[allow(clippy::too_many_arguments)]
async fn handle_media_route(
    backend: &impl GatewayBackend,
    cfg: &GatewayConfig,
    snapshot: &SitePolicySnapshot,
    uri: &Uri,
    method: &Method,
    worker_method: worker::Method,
    headers: &HeaderMap,
    cookies: &Cookies,
    is_admin_view: bool,
    now: u64,
) -> Response {
    let Some((kind, id)) = parse_media_route(uri.path()) else {
        return private_no_store((StatusCode::NOT_FOUND, "Not Found").into_response());
    };
    // Fail closed BEFORE billing or upstream fetch when server-side preview blur
    // is disabled, preventing `/media/preview/*` from serving untransformed clear bytes.
    if kind == MediaCapKind::Preview && !snapshot.policy.cloudflare_images_blur {
        return private_no_store(
            (StatusCode::FORBIDDEN, "Server-side preview blur is disabled").into_response(),
        );
    }
    let Some(cap_token) = extract_media_cap_query(uri.query()) else {
        return private_no_store(
            (StatusCode::FORBIDDEN, "Missing or invalid media capability").into_response(),
        );
    };
    let Ok(cap) = verify_media_capability(
        &cap_token,
        &cfg.media_cap_secret,
        kind,
        id,
        now,
        snapshot.policy.min_enforce_rev,
    ) else {
        return private_no_store(
            (StatusCode::FORBIDDEN, "Invalid or expired media capability").into_response(),
        );
    };

    // Resolve live caller session (if any `ue_session` cookie was presented).
    let (auth, clear_cookie) =
        match resolve_live_session(backend, cfg, cookies, &snapshot.policy, now).await {
            SessionResolution::Authenticated(live) => (Some(live), false),
            SessionResolution::Unauthenticated { clear_cookie } => (None, clear_cookie),
            SessionResolution::Banned => {
                return private_no_store(
                    (StatusCode::FORBIDDEN, "Account suspended").into_response(),
                );
            }
            SessionResolution::BackendUnavailable => {
                return private_no_store(
                    (StatusCode::BAD_GATEWAY, "Access service unavailable").into_response(),
                );
            }
        };

    // Step 5.2: Authorize caller BEFORE any billing or preview-budget check (M1).
    if !authorize_media_capability(&cap, auth.as_ref(), is_admin_view, &snapshot.policy) {
        return maybe_clear_session_cookie(
            private_no_store((StatusCode::FORBIDDEN, "Media access denied").into_response()),
            clear_cookie,
        );
    }

    // Validate canonical upstream URL BEFORE any billing check.
    let Ok(target_url) = build_media_upstream_target(kind, &cap.path, &cfg.upstreams) else {
        return maybe_clear_session_cookie(
            private_no_store((StatusCode::FORBIDDEN, "Invalid media target").into_response()),
            clear_cookie,
        );
    };

    // Step 5.3: Billing / preview budget (only after authorization passes; waived by admin view).
    if !is_admin_view {
        let guest = auth.is_none();
        let billing_status = match kind {
            MediaCapKind::Preview => {
                let do_key = match auth.as_ref() {
                    Some(live) => live.session.do_key().to_string(),
                    None => guest_id(&cfg.jwt_secret, headers),
                };
                let req = PreviewBudgetReq {
                    key: site_access::MediaBillingKey::preview_budget_key(id),
                    head: *method == Method::HEAD,
                    guest,
                };
                backend
                    .account_call(
                        &do_key,
                        "preview-budget",
                        serde_json::to_value(&req).expect("serialize PreviewBudgetReq"),
                    )
                    .await
            }
            MediaCapKind::Image | MediaCapKind::Video => {
                let charge_req = cap
                    .billing_key()
                    .expect("image/video is billable")
                    .to_charge_req();
                if let Some(live) = auth.as_ref() {
                    let op = if *method == Method::HEAD {
                        "can-charge"
                    } else {
                        "charge"
                    };
                    backend
                        .account_call(
                            live.session.do_key(),
                            op,
                            serde_json::to_value(&charge_req).expect("serialize ChargeReq"),
                        )
                        .await
                } else {
                    let g_id = guest_id(&cfg.jwt_secret, headers);
                    let guest_req = GuestReq {
                        item: Some(charge_req),
                        head: *method == Method::HEAD,
                    };
                    backend
                        .account_call(
                            &g_id,
                            "guest",
                            serde_json::to_value(&guest_req).expect("serialize GuestReq"),
                        )
                        .await
                }
            }
        };

        match billing_status {
            Ok(200) => {}
            Ok(401) => {
                return maybe_clear_session_cookie(login_response(uri, method), clear_cookie);
            }
            Ok(402) => {
                return maybe_clear_session_cookie(payment_required(headers, guest), clear_cookie);
            }
            Ok(403) => {
                return maybe_clear_session_cookie(
                    private_no_store((StatusCode::FORBIDDEN, "Account suspended").into_response()),
                    clear_cookie,
                );
            }
            Ok(429) => {
                return maybe_clear_session_cookie(
                    private_no_store(
                        (StatusCode::TOO_MANY_REQUESTS, "Preview rate limit exceeded")
                            .into_response(),
                    ),
                    clear_cookie,
                );
            }
            other => {
                if let Err(err) = &other {
                    log_backend_error("media billing call failed", err);
                }
                return maybe_clear_session_cookie(
                    private_no_store(
                        (StatusCode::BAD_GATEWAY, "Access service unavailable").into_response(),
                    ),
                    clear_cookie,
                );
            }
        }
    }

    // Step 5.4: Upstream media fetch with locked blur (when enabled), no shared cache,
    // manual redirects, and explicit 3xx rejection.
    let preview_blur = resolve_preview_blur(kind, &snapshot.policy);
    let fetch_req = UpstreamFetchReq {
        url: target_url,
        method: worker_method,
        headers: build_media_headers(headers, cfg),
        body: Bytes::new(),
        no_cache: true,
        preview_blur,
    };

    let response = match backend.fetch_upstream(fetch_req).await {
        Ok(mut resp) => {
            if resp.status().is_redirection() {
                private_no_store(
                    (StatusCode::BAD_GATEWAY, "Upstream redirect rejected").into_response(),
                )
            } else {
                resp.headers_mut().remove("set-cookie");
                private_no_store(resp)
            }
        }
        Err(err) => {
            log_backend_error("media upstream fetch failed", &err);
            private_no_store((StatusCode::BAD_GATEWAY, "upstream fetch failed").into_response())
        }
    };

    maybe_clear_session_cookie(response, clear_cookie)
}

async fn handle_gateway_request(
    backend: &impl GatewayBackend,
    cfg: &GatewayConfig,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    cookies: Cookies,
    body: Bytes,
) -> Response {
    let path = uri.path();
    if !is_canonical_path(path) {
        return private_no_store((StatusCode::BAD_REQUEST, "Invalid request path").into_response());
    }

    // `/admin` and `/admin/*` are explicitly exempt from Step 0 geo-block and
    // `SITE_POLICY` availability so administrators can never lock themselves out.
    if is_segment_prefix(path, "/admin") {
        return handle_admin_route(backend, cfg, &uri, &method, &headers, body).await;
    }

    // Load authoritative policy from singleton `SITE_POLICY` DO (fail closed!).
    let snapshot = match backend.load_site_policy().await {
        Ok(snapshot) => snapshot,
        Err(err) => {
            log_backend_error("SITE_POLICY unavailable", &err);
            return private_no_store(
                (StatusCode::SERVICE_UNAVAILABLE, "Policy service unavailable").into_response(),
            );
        }
    };

    // Step 0: Authoritative Geo Enforcement (M4) — runs BEFORE admin browse pass,
    // routing, or caching. Uses Cloudflare runtime `request.cf().country()` only.
    if snapshot.policy.geo.is_blocked(cfg.visitor_country.as_deref()) {
        return private_no_store(
            (
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                "Unavailable in your region",
            )
                .into_response(),
        );
    }

    // `/user/admin` & `/user/admin/*` retired unconditionally -> 404 (H13).
    if is_segment_prefix(path, "/user") {
        if is_segment_prefix(path, "/user/admin") {
            return private_no_store((StatusCode::NOT_FOUND, "Not Found").into_response());
        }
        let Some(worker_method) = checked_user_method(&method) else {
            return method_not_allowed(USER_ALLOWED_METHODS);
        };
        let pq = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/user")
            .to_string();
        let req = ForwardedServiceReq {
            path_and_query: pq,
            method: worker_method,
            headers: build_service_headers(&headers, ServiceTarget::UserWorker, None),
            body,
        };
        return match backend.forward_service(ServiceTarget::UserWorker, req).await {
            Ok(resp) => private_no_store(resp),
            Err(err) => {
                log_backend_error("lets-embed-user-worker fetch failed", &err);
                private_no_store(
                    (StatusCode::BAD_GATEWAY, "user service unavailable").into_response(),
                )
            }
        };
    }

    let now = backend.now_secs();
    let admin_pass = cookies
        .get(ADMIN_VIEW_COOKIE)
        .is_some_and(|c| site_access::valid_admin_view(&cfg.jwt_secret, c.value(), now));
    let is_admin_view = admin_pass || cfg.admin_email.is_some();

    // Capability-gated `/media/{image,video,preview}/{id}?cap=...` route (C1, H1, H2, M1).
    if is_segment_prefix(path, "/media") {
        let Some(worker_method) = checked_media_method(&method) else {
            return method_not_allowed(MEDIA_ALLOWED_METHODS);
        };
        return handle_media_route(
            backend,
            cfg,
            &snapshot,
            &uri,
            &method,
            worker_method,
            &headers,
            &cookies,
            is_admin_view,
            now,
        )
        .await;
    }

    let Some(worker_method) = checked_gallery_method(&method) else {
        return method_not_allowed(GALLERY_ALLOWED_METHODS);
    };

    // Block raw `/images/*` and `/videos/*` unconditionally (C1).
    if is_segment_prefix(path, "/images") || is_segment_prefix(path, "/videos") {
        return private_no_store((StatusCode::NOT_FOUND, "Not Found").into_response());
    }

    // Always-public static/SEO/legal paths (`GET`/`HEAD`): `/robots.txt`,
    // `/favicon.ico`, `/terms`, `/privacy`, `/dmca`, `/content-policy`, `/pkg/*`.
    if matches!(method, Method::GET | Method::HEAD) && is_always_public_path(path) {
        let Ok(signed) = sign_assertion_for_request(cfg, &snapshot, now, AssertionSubject::default())
        else {
            return assertion_sign_error_response();
        };
        let allow_public_cache = is_public_cacheable_path(path, true);
        return proxy_to_api(
            backend,
            cfg,
            &uri,
            worker_method,
            &headers,
            body,
            &signed,
            allow_public_cache,
        )
        .await;
    }

    // Resolve live caller session via `USER_ACCOUNT` DO (`POST /session-context`).
    let (auth, clear_cookie) =
        match resolve_live_session(backend, cfg, &cookies, &snapshot.policy, now).await {
            SessionResolution::Authenticated(live) => (Some(live), false),
            SessionResolution::Unauthenticated { clear_cookie } => (None, clear_cookie),
            SessionResolution::Banned => {
                return private_no_store(
                    (StatusCode::FORBIDDEN, "Account suspended").into_response(),
                );
            }
            SessionResolution::BackendUnavailable => {
                return private_no_store(
                    (StatusCode::BAD_GATEWAY, "Access service unavailable").into_response(),
                );
            }
        };

    let browse = browse_route(&method, path);
    if auth.is_none() && !browse {
        return maybe_clear_session_cookie(login_response(&uri, &method), clear_cookie);
    }

    // Search metering validation runs for ALL callers (including `ADMIN_VIEW_COOKIE`).
    let item = match metered_item(&method, path, &headers, &body) {
        Ok(item) => item,
        Err(err) => return maybe_clear_session_cookie(err.into_response(), clear_cookie),
    };

    // Same-origin CSRF check runs for ALL POST requests to `API_UPSTREAM`
    // (both metered and unmetered), for ALL callers including `ADMIN_VIEW_COOKIE` (H13).
    if method == Method::POST && !is_same_origin(&uri, &headers) {
        return maybe_clear_session_cookie(
            private_no_store(
                (StatusCode::FORBIDDEN, "Cross-origin POST request rejected").into_response(),
            ),
            clear_cookie,
        );
    }
    let metered_post = method == Method::POST && item.is_some();

    // Build signed `X-Gateway-Assertion` for `lets-embed-web`.
    // Sitemaps are always projected strictly as the anonymous safe view.
    let subject = if is_sitemap_path(path) {
        AssertionSubject::default()
    } else if let Some(live) = auth.as_ref() {
        AssertionSubject {
            sub: Some(live.session.user_id().to_string()),
            sid: live.session.sid().map(str::to_string),
            switchers: live.eligible_switchers.clone(),
            safe_mode: live.ctx.safe_mode,
            is_admin_view,
        }
    } else if is_admin_view {
        AssertionSubject {
            sub: Some(ADMIN_VIEW_SUB.to_string()),
            sid: None,
            switchers: admin_eligible_switchers(&snapshot.policy),
            safe_mode: false,
            is_admin_view: true,
        }
    } else {
        AssertionSubject::default()
    };
    let Ok(signed_assertion) = sign_assertion_for_request(cfg, &snapshot, now, subject) else {
        return maybe_clear_session_cookie(assertion_sign_error_response(), clear_cookie);
    };

    // Admin browse pass waives login wall & quota/payment metering ONLY — geo,
    // CSRF, assertion signing, and capability verification already executed above.
    if is_admin_view {
        let resp = proxy_to_api(
            backend,
            cfg,
            &uri,
            worker_method,
            &headers,
            body,
            &signed_assertion,
            false,
        )
        .await;
        return maybe_clear_session_cookie(resp, clear_cookie);
    }

    let guest = auth.is_none();
    if metered_post {
        let item = item.expect("metered_post implies item is Some");
        let (account_key, reserve_res) = match auth.as_ref() {
            Some(live) => {
                let do_key = live.session.do_key().to_string();
                let res = backend
                    .account_reserve(
                        &do_key,
                        "reserve",
                        serde_json::to_value(&item).expect("serialize ChargeReq"),
                    )
                    .await;
                (do_key, res)
            }
            None => {
                let id = guest_id(&cfg.jwt_secret, &headers);
                let res = backend
                    .account_reserve(
                        &id,
                        "reserve-guest",
                        serde_json::to_value(&GuestReq {
                            item: Some(item),
                            head: false,
                        })
                        .expect("serialize GuestReq"),
                    )
                    .await;
                (id, res)
            }
        };

        let resp = match reserve_res {
            Ok((200, hold_id)) => {
                let response = proxy_to_api(
                    backend,
                    cfg,
                    &uri,
                    worker_method,
                    &headers,
                    body,
                    &signed_assertion,
                    false,
                )
                .await;
                if let Some(hold_id) = hold_id {
                    let op = match (guest, response.status().is_success()) {
                        (false, true) => "commit",
                        (false, false) => "release",
                        (true, true) => "commit-guest",
                        (true, false) => "release-guest",
                    };
                    match backend
                        .account_call(
                            &account_key,
                            op,
                            serde_json::to_value(&HoldReq { hold_id }).expect("serialize HoldReq"),
                        )
                        .await
                    {
                        Ok(200) => {}
                        Err(err) => log_backend_error(&format!("hold {op} failed"), &err),
                        Ok(status) => {
                            log_backend_error(
                                &format!("hold {op} failed"),
                                &BackendError(format!("HTTP {status}")),
                            );
                        }
                    }
                }
                response
            }
            Ok((401, _)) => login_response(&uri, &method),
            Ok((402, _)) => payment_required(&headers, guest),
            Ok((403, _)) => {
                private_no_store((StatusCode::FORBIDDEN, "Account suspended").into_response())
            }
            other => {
                if let Err(err) = &other {
                    log_backend_error("access reserve failed", err);
                }
                private_no_store(
                    (StatusCode::BAD_GATEWAY, "Access service unavailable").into_response(),
                )
            }
        };
        return maybe_clear_session_cookie(resp, clear_cookie);
    }

    // Authenticated non-metered gallery request: already verified live via `/session-context`.
    if auth.is_some() {
        let resp = proxy_to_api(
            backend,
            cfg,
            &uri,
            worker_method,
            &headers,
            body,
            &signed_assertion,
            false,
        )
        .await;
        return maybe_clear_session_cookie(resp, clear_cookie);
    }

    // Guest non-metered gallery request: check `USER_ACCOUNT` guest gate (`login_required`).
    let g_id = guest_id(&cfg.jwt_secret, &headers);
    let decision = backend
        .account_call(
            &g_id,
            "guest",
            serde_json::to_value(&GuestReq {
                item: None,
                head: method == Method::HEAD,
            })
            .expect("serialize GuestReq"),
        )
        .await;
    let resp = match decision {
        Ok(200) => {
            let allow_public_cache = is_public_cacheable_path(path, true) && !clear_cookie;
            proxy_to_api(
                backend,
                cfg,
                &uri,
                worker_method,
                &headers,
                body,
                &signed_assertion,
                allow_public_cache,
            )
            .await
        }
        Ok(401) => login_response(&uri, &method),
        Ok(402) => payment_required(&headers, true),
        Ok(403) => private_no_store((StatusCode::FORBIDDEN, "Account suspended").into_response()),
        other => {
            if let Err(err) = &other {
                log_backend_error("access decision failed", err);
            }
            private_no_store(
                (StatusCode::BAD_GATEWAY, "Access service unavailable").into_response(),
            )
        }
    };
    maybe_clear_session_cookie(resp, clear_cookie)
}

// ---------------------------------------------------------------------------
// Comprehensive Host Unit & End-to-End Mock-Backend Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context as TaskContext, Poll, Waker};

    use axum::http::header::CONTENT_TYPE;
    use site_access::{
        AgeGateTrigger, AgeVerificationPolicy, AssuranceLevel, ChargeKind, GeoPolicy,
        LegacySessionClaims, MEDIA_CAP_ANON_SUB, MEDIA_CAP_VERSION, MediaBillingKey,
        MediaCapability, PlaceholderPreset, RuleMode, SESSION_V2_VERSION, SafetyRuleConfig,
        SessionV2Claims, builtin_safety_presets, sign_legacy_session, sign_media_capability,
        sign_session_v2, verify_gateway_assertion,
    };

    use super::*;
    use crate::http_util::{
        MeterError, form_field, parse_upstream_origin, require_form_urlencoded, sha256_hex,
    };
    use crate::media::{LOCKED_PREVIEW_BLUR, encode_canonical_cap_path};

    const TEST_NOW: u64 = 1_700_000_000;
    const TEST_JWT_SECRET: &[u8] = b"test-jwt-secret-key-0123456789";
    const TEST_V2_SECRET: &[u8] = b"test-session-v2-secret-9876543210";
    const TEST_ASSERTION_SECRET: &[u8] = b"test-gateway-assertion-secret-abcd";
    const TEST_MEDIA_CAP_SECRET: &[u8] = b"test-media-cap-secret-efgh";
    const ETH_WALLET: &str = "0x1111111111111111111111111111111111111111";

    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = pin!(fut);
        let waker = Waker::noop();
        let mut cx = TaskContext::from_waker(waker);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("mock backend futures must complete synchronously"),
        }
    }

    fn test_upstreams() -> Upstreams {
        Upstreams {
            api: "https://api.gallery.test".into(),
            image: "https://image.gallery.test".into(),
            video: "https://video.gallery.test".into(),
        }
    }

    fn test_cfg() -> GatewayConfig {
        GatewayConfig {
            jwt_secret: Arc::new(TEST_JWT_SECRET.to_vec()),
            session_v2_secret: Arc::new(TEST_V2_SECRET.to_vec()),
            gateway_assertion_secret: Arc::new(TEST_ASSERTION_SECRET.to_vec()),
            media_cap_secret: Arc::new(TEST_MEDIA_CAP_SECRET.to_vec()),
            admin_email: None,
            visitor_country: Some("US".to_string()),
            client_id: Arc::new("svc-id".to_string()),
            client_secret: Arc::new("svc-secret".to_string()),
            upstreams: Arc::new(test_upstreams()),
        }
    }

    fn sample_safety_policy() -> PublicSitePolicy {
        PublicSitePolicy {
            revision: 5,
            min_enforce_rev: 3,
            safety_enabled: true,
            rules: builtin_safety_presets(),
            cloudflare_images_blur: true,
            age_policy: AgeVerificationPolicy::SelfAttestation,
            age_gate_trigger: AgeGateTrigger::JustInTime,
            geo: GeoPolicy {
                blocked_countries: vec!["KP".to_string()],
                block_unknown: false,
                block_tor: true,
            },
            ..PublicSitePolicy::default()
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

    #[derive(Debug, Clone)]
    struct RecordedAccountCall {
        do_key: String,
        operation: String,
        payload: serde_json::Value,
    }

    #[derive(Debug, Clone)]
    struct RecordedServiceCall {
        target: ServiceTarget,
        path_and_query: String,
        headers: Vec<(String, String)>,
    }

    #[derive(Debug, Clone)]
    struct RecordedUpstreamCall {
        url: String,
        method: worker::Method,
        headers: Vec<(String, String)>,
        no_cache: bool,
        preview_blur: Option<PreviewBlurConfig>,
    }

    struct MockBackend {
        now: u64,
        policy_result: std::result::Result<SitePolicyResponse, String>,
        session_contexts: HashMap<String, SessionContext>,
        account_statuses: HashMap<String, u16>,
        default_account_status: u16,
        reserve_hold_id: Option<String>,
        upstream_status: StatusCode,
        upstream_cache_control: Option<&'static str>,
        upstream_set_cookie: Option<&'static str>,
        account_calls: RefCell<Vec<RecordedAccountCall>>,
        session_calls: RefCell<Vec<(String, Option<String>)>>,
        service_calls: RefCell<Vec<RecordedServiceCall>>,
        upstream_calls: RefCell<Vec<RecordedUpstreamCall>>,
    }

    impl MockBackend {
        fn with_policy(policy: PublicSitePolicy) -> Self {
            let digest = compute_policy_digest(&policy);
            Self {
                now: TEST_NOW,
                policy_result: Ok(SitePolicyResponse { policy, digest }),
                session_contexts: HashMap::new(),
                account_statuses: HashMap::new(),
                default_account_status: 200,
                reserve_hold_id: Some("hold-1".to_string()),
                upstream_status: StatusCode::OK,
                upstream_cache_control: Some("public, max-age=3600"),
                upstream_set_cookie: None,
                account_calls: RefCell::new(Vec::new()),
                session_calls: RefCell::new(Vec::new()),
                service_calls: RefCell::new(Vec::new()),
                upstream_calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl GatewayBackend for MockBackend {
        fn now_secs(&self) -> u64 {
            self.now
        }

        async fn load_site_policy(&self) -> std::result::Result<SitePolicySnapshot, BackendError> {
            match &self.policy_result {
                Ok(resp) => validate_site_policy_response(resp.clone())
                    .map_err(|reason| BackendError(reason.to_string())),
                Err(msg) => Err(BackendError(msg.clone())),
            }
        }

        async fn load_session_context(
            &self,
            do_key: &str,
            sid: Option<&str>,
        ) -> std::result::Result<SessionContext, BackendError> {
            self.session_calls
                .borrow_mut()
                .push((do_key.to_string(), sid.map(str::to_string)));
            self.session_contexts
                .get(do_key)
                .cloned()
                .ok_or_else(|| BackendError(format!("missing session context for {do_key}")))
        }

        async fn account_call(
            &self,
            do_key: &str,
            operation: &str,
            payload: serde_json::Value,
        ) -> std::result::Result<u16, BackendError> {
            self.account_calls.borrow_mut().push(RecordedAccountCall {
                do_key: do_key.to_string(),
                operation: operation.to_string(),
                payload,
            });
            Ok(*self
                .account_statuses
                .get(operation)
                .unwrap_or(&self.default_account_status))
        }

        async fn account_reserve(
            &self,
            do_key: &str,
            operation: &str,
            payload: serde_json::Value,
        ) -> std::result::Result<(u16, Option<String>), BackendError> {
            self.account_calls.borrow_mut().push(RecordedAccountCall {
                do_key: do_key.to_string(),
                operation: operation.to_string(),
                payload,
            });
            let status = *self
                .account_statuses
                .get(operation)
                .unwrap_or(&self.default_account_status);
            Ok((
                status,
                if status == 200 {
                    self.reserve_hold_id.clone()
                } else {
                    None
                },
            ))
        }

        async fn forward_service(
            &self,
            target: ServiceTarget,
            req: ForwardedServiceReq,
        ) -> std::result::Result<Response, BackendError> {
            self.service_calls.borrow_mut().push(RecordedServiceCall {
                target,
                path_and_query: req.path_and_query,
                headers: req.headers,
            });
            Ok((StatusCode::OK, "service ok").into_response())
        }

        async fn fetch_upstream(
            &self,
            req: UpstreamFetchReq,
        ) -> std::result::Result<Response, BackendError> {
            self.upstream_calls.borrow_mut().push(RecordedUpstreamCall {
                url: req.url.to_string(),
                method: req.method,
                headers: req.headers,
                no_cache: req.no_cache,
                preview_blur: req.preview_blur,
            });
            let mut resp = (self.upstream_status, "upstream body").into_response();
            if let Some(cc) = self.upstream_cache_control {
                resp.headers_mut()
                    .insert("cache-control", cc.parse().unwrap());
            }
            if let Some(sc) = self.upstream_set_cookie {
                resp.headers_mut().insert("set-cookie", sc.parse().unwrap());
            }
            Ok(resp)
        }
    }

    fn cookies_from_headers(headers: &HeaderMap) -> Cookies {
        // Parse `Cookie` header(s) into a `tower_cookies::Cookies` via its cookie jar layer.
        use axum::http::Request as HttpReq;
        use std::sync::Mutex;
        use tower_service::Service as _;

        let extracted = Arc::new(Mutex::new(None));
        let sink = extracted.clone();
        let mut app = Router::new()
            .fallback(any(move |c: Cookies| {
                let sink = sink.clone();
                async move {
                    *sink.lock().unwrap() = Some(c);
                    StatusCode::OK
                }
            }))
            .layer(CookieManagerLayer::new());

        let mut req_builder = HttpReq::builder().uri("/");
        for v in headers.get_all("cookie") {
            req_builder = req_builder.header("cookie", v);
        }
        let req = req_builder.body(axum::body::Body::empty()).unwrap();
        let _ = block_on(app.call(req)).unwrap();
        extracted.lock().unwrap().take().unwrap()
    }

    fn dispatch(
        backend: &MockBackend,
        cfg: &GatewayConfig,
        method: Method,
        uri: &str,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let cookies = cookies_from_headers(&headers);
        let parsed_uri: Uri = uri.parse().expect("valid test URI");
        block_on(handle_gateway_request(
            backend, cfg, parsed_uri, method, headers, cookies, body,
        ))
    }

    fn make_v2_cookie(user_id: &str, do_key: &str, sid: &str) -> String {
        let tok = sign_session_v2(
            &SessionV2Claims {
                v: SESSION_V2_VERSION,
                sub: user_id.to_string(),
                do_key: do_key.to_string(),
                sid: sid.to_string(),
                iat: TEST_NOW - 60,
                exp: TEST_NOW + 3600,
            },
            TEST_V2_SECRET,
        )
        .unwrap();
        format!("{SESSION_COOKIE}={tok}")
    }

    fn make_admin_view_cookie() -> String {
        let pass = site_access::admin_view_pass(TEST_JWT_SECRET, TEST_NOW + site_access::VIEW_TTL);
        format!("{ADMIN_VIEW_COOKIE}={pass}")
    }

    fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    // -----------------------------------------------------------------------
    // Step 0 Geo-Block & Fail-Closed SITE_POLICY Tests
    // -----------------------------------------------------------------------

    #[test]
    fn geo_block_enforces_cf_country_ignores_spoofed_header_and_exempts_admin() {
        let mut policy = sample_safety_policy();
        policy.geo = GeoPolicy {
            blocked_countries: vec!["KP".to_string()],
            block_unknown: true,
            block_tor: true,
        };
        let backend = MockBackend::with_policy(policy);

        // 1. Blocked country KP with spoofed `CF-IPCountry: US` header AND valid admin browse cookie -> still 451!
        let mut cfg = test_cfg();
        cfg.visitor_country = Some("KP".to_string());
        let mut hdrs = HeaderMap::new();
        hdrs.insert("cf-ipcountry", "US".parse().unwrap());
        hdrs.insert("cookie", make_admin_view_cookie().parse().unwrap());
        let resp = dispatch(&backend, &cfg, Method::GET, "/", hdrs, Bytes::new());
        assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "private, no-store"
        );
        assert!(backend.upstream_calls.borrow().is_empty());

        // 2. Tor (`T1`), unknown (`XX`), and missing country (`None`) all blocked when configured.
        for country in [Some("T1"), Some("XX"), None] {
            cfg.visitor_country = country.map(str::to_string);
            let mut h = HeaderMap::new();
            h.insert("cf-ipcountry", "US".parse().unwrap());
            let r = dispatch(&backend, &cfg, Method::GET, "/robots.txt", h, Bytes::new());
            assert_eq!(r.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        }

        // 3. `/admin` and `/admin/*` are EXEMPT from geo-block so admins cannot lock themselves out.
        cfg.visitor_country = Some("KP".to_string());
        cfg.admin_email = Some("ops@gallery.test".to_string());
        let admin_resp = dispatch(&backend, &cfg, Method::GET, "/admin", HeaderMap::new(), Bytes::new());
        assert_eq!(admin_resp.status(), StatusCode::OK);
        assert_eq!(
            admin_resp.headers().get("cache-control").unwrap(),
            "private, no-store"
        );
        let calls = backend.service_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].target, ServiceTarget::AdminDashboard);
        assert_eq!(calls[0].path_and_query, "/admin");
        assert_eq!(
            header_value(&calls[0].headers, ADMIN_HEADER),
            Some("ops@gallery.test")
        );

        // 4. Allowed country `US` with spoofed `CF-IPCountry: KP` header -> NOT blocked (header ignored).
        cfg.visitor_country = Some("US".to_string());
        cfg.admin_email = None;
        let mut spoof = HeaderMap::new();
        spoof.insert("cf-ipcountry", "KP".parse().unwrap());
        let ok_resp = dispatch(&backend, &cfg, Method::GET, "/robots.txt", spoof, Bytes::new());
        assert_eq!(ok_resp.status(), StatusCode::OK);
    }

    #[test]
    fn site_policy_outage_or_bad_digest_fails_closed_while_admin_stays_reachable() {
        let mut backend = MockBackend::with_policy(sample_safety_policy());
        backend.policy_result = Err("DO unreachable".to_string());

        let mut cfg = test_cfg();
        let resp = dispatch(&backend, &cfg, Method::GET, "/", HeaderMap::new(), Bytes::new());
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "private, no-store"
        );

        // Tampered digest also fails closed with 503.
        let mut bad_digest_backend = MockBackend::with_policy(sample_safety_policy());
        bad_digest_backend.policy_result = Ok(SitePolicyResponse {
            policy: sample_safety_policy(),
            digest: "0".repeat(64),
        });
        let r2 = dispatch(
            &bad_digest_backend,
            &cfg,
            Method::GET,
            "/robots.txt",
            HeaderMap::new(),
            Bytes::new(),
        );
        assert_eq!(r2.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Admin path remains accessible during SITE_POLICY outage to allow recovery.
        cfg.admin_email = Some("ops@gallery.test".to_string());
        let admin_ok = dispatch(&backend, &cfg, Method::GET, "/admin", HeaderMap::new(), Bytes::new());
        assert_eq!(admin_ok.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // Admin Routing, /user/admin* Retirement & /user/* Header Stripping (H13)
    // -----------------------------------------------------------------------

    #[test]
    fn user_admin_retired_404_and_admin_dashboard_requires_access() {
        let backend = MockBackend::with_policy(sample_safety_policy());
        let mut cfg = test_cfg();

        // Unauthenticated `/admin` -> 403 (even with ADMIN_VIEW_COOKIE!).
        let mut with_view = HeaderMap::new();
        with_view.insert("cookie", make_admin_view_cookie().parse().unwrap());
        let r = dispatch(&backend, &cfg, Method::GET, "/admin", with_view, Bytes::new());
        assert_eq!(r.status(), StatusCode::FORBIDDEN);

        // `/user/admin` and `/user/admin/*` unconditionally return 404 even with CF Access admin!
        cfg.admin_email = Some("ops@gallery.test".to_string());
        for (m, p) in [
            (Method::GET, "/user/admin"),
            (Method::GET, "/user/admin/browse"),
            (Method::POST, "/user/admin/settings"),
            (Method::DELETE, "/user/admin/foo"),
        ] {
            let resp = dispatch(&backend, &cfg, m, p, HeaderMap::new(), Bytes::new());
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "expected 404 on {p}");
            assert_eq!(
                resp.headers().get("cache-control").unwrap(),
                "private, no-store"
            );
        }
        assert!(backend.service_calls.borrow().is_empty());

        // `/admin/browse` sets __Host-ue_admin_view and redirects to `/`.
        let browse = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "/admin/browse",
            HeaderMap::new(),
            Bytes::new(),
        );
        assert_eq!(browse.status(), StatusCode::SEE_OTHER);
        assert_eq!(browse.headers().get("location").unwrap(), "/");
        assert_eq!(
            browse.headers().get("cache-control").unwrap(),
            "private, no-store"
        );
        let sc = browse.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(sc.starts_with("__Host-ue_admin_view="));
        assert!(sc.contains("HttpOnly"));

        // `/user/account` forwards to USER_WORKER stripping ALL privileged + forwarded headers
        // and admin/Access cookies, and never setting ADMIN_HEADER.
        let mut spoofed = HeaderMap::new();
        spoofed.insert("x-gallery-admin-email", "evil@test".parse().unwrap());
        spoofed.insert("x-gateway-assertion", "ga1.fake.sig".parse().unwrap());
        spoofed.insert("cf-access-jwt-assertion", "fake-jwt".parse().unwrap());
        spoofed.insert("x-forwarded-host", "evil.host".parse().unwrap());
        spoofed.insert("x-forwarded-proto", "http".parse().unwrap());
        spoofed.insert("forwarded", "host=evil.host".parse().unwrap());
        spoofed.insert(
            "cookie",
            format!("{}; {}=abc", make_admin_view_cookie(), SESSION_COOKIE)
                .parse()
                .unwrap(),
        );
        let user_resp = dispatch(&backend, &cfg, Method::GET, "/user/account", spoofed, Bytes::new());
        assert_eq!(user_resp.status(), StatusCode::OK);
        {
            let calls = backend.service_calls.borrow();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].target, ServiceTarget::UserWorker);
            assert_eq!(header_value(&calls[0].headers, ADMIN_HEADER), None);
            assert_eq!(
                header_value(&calls[0].headers, GATEWAY_ASSERTION_HEADER),
                None
            );
            assert_eq!(
                header_value(&calls[0].headers, "cf-access-jwt-assertion"),
                None
            );
            assert_eq!(header_value(&calls[0].headers, "x-forwarded-host"), None);
            assert_eq!(header_value(&calls[0].headers, "x-forwarded-proto"), None);
            assert_eq!(header_value(&calls[0].headers, "forwarded"), None);
            let fwd_cookie = header_value(&calls[0].headers, "cookie").unwrap();
            assert!(fwd_cookie.contains("ue_session=abc"));
            assert!(!fwd_cookie.contains(ADMIN_VIEW_COOKIE));
        }

        // `/admin/api/settings` forwards to ADMIN_DASHBOARD_WORKER stripping forwarded headers
        // and all STRIPPED_ORIGIN_COOKIES while preserving admin SPA CSRF cookie.
        let mut admin_spoof = HeaderMap::new();
        admin_spoof.insert("x-forwarded-host", "evil.host".parse().unwrap());
        admin_spoof.insert("x-forwarded-proto", "http".parse().unwrap());
        admin_spoof.insert("forwarded", "for=1.2.3.4".parse().unwrap());
        admin_spoof.insert(
            "cookie",
            format!(
                "__Host-admin_csrf=tok1; {}=s1; {}; gw_token=g; __Host-auth_tx=t; CF_Authorization=c",
                SESSION_COOKIE,
                make_admin_view_cookie()
            )
            .parse()
            .unwrap(),
        );
        let admin_api = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "/admin/api/settings",
            admin_spoof,
            Bytes::new(),
        );
        assert_eq!(admin_api.status(), StatusCode::OK);
        let calls = backend.service_calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].target, ServiceTarget::AdminDashboard);
        assert_eq!(header_value(&calls[1].headers, "x-forwarded-host"), None);
        assert_eq!(header_value(&calls[1].headers, "x-forwarded-proto"), None);
        assert_eq!(header_value(&calls[1].headers, "forwarded"), None);
        assert_eq!(
            header_value(&calls[1].headers, "cookie"),
            Some("__Host-admin_csrf=tok1")
        );
    }

    // -----------------------------------------------------------------------
    // Raw /images/* & /videos/* Block + Capability /media/* Enforcement (C1, H1, H2, M1)
    // -----------------------------------------------------------------------

    #[test]
    fn raw_images_and_videos_are_blocked_with_404_even_for_admins() {
        let backend = MockBackend::with_policy(sample_safety_policy());
        let mut cfg = test_cfg();
        cfg.admin_email = Some("ops@gallery.test".to_string());

        for p in ["/images/a.webp", "/images/album/pic.webp", "/videos/clip.mp4", "/images", "/videos"] {
            let mut h = HeaderMap::new();
            h.insert("cookie", make_admin_view_cookie().parse().unwrap());
            let r = dispatch(&backend, &cfg, Method::GET, p, h, Bytes::new());
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "must 404 {p}");
            assert_eq!(
                r.headers().get("cache-control").unwrap(),
                "private, no-store"
            );
        }
        assert!(backend.account_calls.borrow().is_empty());
        assert!(backend.upstream_calls.borrow().is_empty());
    }

    #[test]
    fn media_capability_rejects_tampered_expired_stale_rev_and_wrong_target_with_zero_charge() {
        let policy = sample_safety_policy(); // rev = 5, min_enforce_rev = 3
        let backend = MockBackend::with_policy(policy);
        let cfg = test_cfg();

        let valid_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            kind: MediaCapKind::Image,
            id: 42,
            path: "2026/01/photo_42.webp".to_string(),
            rev: 5,
            sub: MEDIA_CAP_ANON_SUB.to_string(),
            sid: None,
            req_switchers: Vec::new(),
            exp: TEST_NOW + 300,
        };
        let valid_tok = sign_media_capability(&valid_cap, TEST_MEDIA_CAP_SECRET).unwrap();

        // 1. Missing cap -> 403
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, "/media/image/42", HeaderMap::new(), Bytes::new()).status(),
            StatusCode::FORBIDDEN
        );
        // 2. Duplicate cap -> 403
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/image/42?cap={valid_tok}&cap={valid_tok}"),
                HeaderMap::new(),
                Bytes::new()
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        // 3. Tampered signature -> 403
        let mut tampered = valid_tok.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/image/42?cap={tampered}"),
                HeaderMap::new(),
                Bytes::new()
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        // 4. Wrong ID -> 403
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/image/43?cap={valid_tok}"),
                HeaderMap::new(),
                Bytes::new()
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        // 5. Wrong kind -> 403
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/preview/42?cap={valid_tok}"),
                HeaderMap::new(),
                Bytes::new()
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        // 6. Expired cap -> 403
        let expired_tok = sign_media_capability(
            &MediaCapability {
                exp: TEST_NOW - 1,
                ..valid_cap.clone()
            },
            TEST_MEDIA_CAP_SECRET,
        )
        .unwrap();
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/image/42?cap={expired_tok}"),
                HeaderMap::new(),
                Bytes::new()
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        // 7. Stale rev (< min_enforce_rev = 3) -> 403
        let stale_tok = sign_media_capability(
            &MediaCapability {
                rev: 2,
                ..valid_cap.clone()
            },
            TEST_MEDIA_CAP_SECRET,
        )
        .unwrap();
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/image/42?cap={stale_tok}"),
                HeaderMap::new(),
                Bytes::new()
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        // 8. POST to /media/* -> 405 Method Not Allowed
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::POST,
                &format!("/media/image/42?cap={valid_tok}"),
                HeaderMap::new(),
                Bytes::new()
            )
            .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        // ZERO DO calls and ZERO upstream calls on any denied request!
        assert!(backend.account_calls.borrow().is_empty());
        assert!(backend.upstream_calls.borrow().is_empty());

        // 9. Valid anonymous safe cap -> 200, guest billing with canonical `media:image:42`,
        //    private no-store, no shared cache.
        let ok = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/image/42?cap={valid_tok}"),
            HeaderMap::new(),
            Bytes::new(),
        );
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(ok.headers().get("cache-control").unwrap(), "private, no-store");
        assert_eq!(backend.account_calls.borrow().len(), 1);
        assert_eq!(backend.account_calls.borrow()[0].operation, "guest");
        assert_eq!(
            backend.account_calls.borrow()[0].payload["item"]["path"],
            "media:image:42"
        );
        let up = backend.upstream_calls.borrow();
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].url, "https://image.gallery.test/2026/01/photo_42.webp");
        assert!(up[0].no_cache);
        assert_eq!(up[0].preview_blur, None);
    }

    #[test]
    fn restricted_media_enforces_switchers_age_terms_safe_mode_sid_and_zero_charge_on_denial() {
        let mut policy = sample_safety_policy();
        policy.age_policy = AgeVerificationPolicy::StrictProviderVerified18;
        let terms_v = policy.legal.terms_version;
        let terms_d = policy.legal.terms_digest.clone();

        let do_key = "usr:550e8400-e29b-41d4-a716-446655440000";
        let user_id = "user-42";
        let sid = "sid-live-1";

        let restricted_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            kind: MediaCapKind::Image,
            id: 99,
            path: "restricted/item 99.webp".to_string(),
            rev: 5,
            sub: user_id.to_string(),
            sid: Some(sid.to_string()),
            req_switchers: vec!["r18".to_string()],
            exp: TEST_NOW + 300,
        };
        let cap_tok = sign_media_capability(&restricted_cap, TEST_MEDIA_CAP_SECRET).unwrap();
        let uri = format!("/media/image/99?cap={cap_tok}");
        let cfg = test_cfg();

        let make_hdrs = |cookie: String| {
            let mut h = HeaderMap::new();
            h.insert("cookie", cookie.parse().unwrap());
            h
        };

        let base_ctx = SessionContext {
            active: true,
            banned: false,
            sid_valid: true,
            assurance_level: AssuranceLevel::Verified18,
            strict_age_ok: true,
            terms_version_accepted: Some(terms_v),
            terms_digest_accepted: Some(terms_d.clone()),
            enabled_switchers: vec!["r18".to_string()],
            safe_mode: false,
        };

        // Failure cases — EVERY ONE must return 403 and incur ZERO account_call billing!
        let denied_cases: Vec<(&str, SessionContext)> = vec![
            (
                "safe_mode active",
                SessionContext {
                    safe_mode: true,
                    ..base_ctx.clone()
                },
            ),
            (
                "missing switcher",
                SessionContext {
                    enabled_switchers: vec!["blood".to_string()],
                    ..base_ctx.clone()
                },
            ),
            (
                "unaccepted terms version",
                SessionContext {
                    terms_version_accepted: Some(terms_v + 1),
                    ..base_ctx.clone()
                },
            ),
            (
                "unaccepted terms digest",
                SessionContext {
                    terms_digest_accepted: Some("a".repeat(64)),
                    ..base_ctx.clone()
                },
            ),
            (
                "strict age not satisfied (self attestation only)",
                SessionContext {
                    assurance_level: AssuranceLevel::SelfAttestation,
                    strict_age_ok: false,
                    ..base_ctx.clone()
                },
            ),
            (
                "banned user",
                SessionContext {
                    banned: true,
                    ..base_ctx.clone()
                },
            ),
            (
                "revoked sid",
                SessionContext {
                    sid_valid: false,
                    ..base_ctx.clone()
                },
            ),
        ];

        for (label, ctx) in denied_cases {
            let mut backend = MockBackend::with_policy(policy.clone());
            backend.session_contexts.insert(do_key.to_string(), ctx.clone());
            let resp = dispatch(
                &backend,
                &cfg,
                Method::GET,
                &uri,
                make_hdrs(make_v2_cookie(user_id, do_key, sid)),
                Bytes::new(),
            );
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "case: {label}");
            assert!(
                backend.account_calls.borrow().is_empty(),
                "case {label} MUST NOT charge or call billing DO"
            );
            assert!(
                backend.upstream_calls.borrow().is_empty(),
                "case {label} MUST NOT fetch media upstream"
            );
            if !ctx.sid_valid && !ctx.banned {
                let sc = resp
                    .headers()
                    .get("set-cookie")
                    .expect("revoked sid must clear cookie")
                    .to_str()
                    .unwrap();
                assert!(sc.contains("Max-Age=0"));
            }
        }

        // Wrong sid on caller session -> 403, ZERO charge!
        {
            let mut backend = MockBackend::with_policy(policy.clone());
            backend
                .session_contexts
                .insert(do_key.to_string(), base_ctx.clone());
            let r = dispatch(
                &backend,
                &cfg,
                Method::GET,
                &uri,
                make_hdrs(make_v2_cookie(user_id, do_key, "sid-different")),
                Bytes::new(),
            );
            assert_eq!(r.status(), StatusCode::FORBIDDEN);
            assert!(backend.account_calls.borrow().is_empty());
        }

        // Authorized caller: HEAD uses `can-charge`, GET uses `charge`, canonical `media:image:99`.
        {
            let mut backend = MockBackend::with_policy(policy.clone());
            backend
                .session_contexts
                .insert(do_key.to_string(), base_ctx.clone());
            let head_r = dispatch(
                &backend,
                &cfg,
                Method::HEAD,
                &uri,
                make_hdrs(make_v2_cookie(user_id, do_key, sid)),
                Bytes::new(),
            );
            assert_eq!(head_r.status(), StatusCode::OK);
            assert_eq!(backend.account_calls.borrow()[0].operation, "can-charge");
            assert_eq!(backend.account_calls.borrow()[0].do_key, do_key);
            assert_eq!(
                backend.account_calls.borrow()[0].payload["path"],
                MediaBillingKey::image(99).canonical_key()
            );

            let get_r = dispatch(
                &backend,
                &cfg,
                Method::GET,
                &uri,
                make_hdrs(make_v2_cookie(user_id, do_key, sid)),
                Bytes::new(),
            );
            assert_eq!(get_r.status(), StatusCode::OK);
            assert_eq!(backend.account_calls.borrow()[1].operation, "charge");
            assert_eq!(
                backend.upstream_calls.borrow()[1].url,
                "https://image.gallery.test/restricted/item%2099.webp"
            );
        }
    }

    #[test]
    fn preview_uses_separate_budget_locked_cf_blur_and_rejects_upstream_redirects() {
        let policy = sample_safety_policy(); // cloudflare_images_blur: true
        let mut backend = MockBackend::with_policy(policy);
        backend.upstream_set_cookie = Some("evil=1");
        let cfg = test_cfg();

        let preview_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            kind: MediaCapKind::Preview,
            id: 77,
            path: "2026/01/spicy_77.webp".to_string(),
            rev: 5,
            sub: MEDIA_CAP_ANON_SUB.to_string(),
            sid: None,
            req_switchers: Vec::new(),
            exp: TEST_NOW + 600,
        };
        let tok = sign_media_capability(&preview_cap, TEST_MEDIA_CAP_SECRET).unwrap();

        // Client attempts to inject blur=0&width=4000 query overrides — must be ignored!
        let uri = format!("/media/preview/77?cap={tok}&blur=0&width=4000");

        // HEAD is side-effect-free (`head: true`) on `/preview-budget`.
        let head = dispatch(&backend, &cfg, Method::HEAD, &uri, HeaderMap::new(), Bytes::new());
        assert_eq!(head.status(), StatusCode::OK);
        let calls = backend.account_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].operation, "preview-budget");
        assert_eq!(calls[0].payload["key"], MediaBillingKey::preview_budget_key(77));
        assert_eq!(calls[0].payload["head"], true);
        drop(calls);

        // GET uses `/preview-budget` (NEVER `charge`/`guest`), locked blur config, strips origin Set-Cookie.
        let get = dispatch(&backend, &cfg, Method::GET, &uri, HeaderMap::new(), Bytes::new());
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(get.headers().get("cache-control").unwrap(), "private, no-store");
        assert!(get.headers().get("set-cookie").is_none());
        let calls = backend.account_calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].operation, "preview-budget");
        assert_eq!(calls[1].payload["head"], false);
        assert!(calls.iter().all(|c| c.operation == "preview-budget"));
        drop(calls);

        let up = backend.upstream_calls.borrow();
        assert_eq!(up[0].method, worker::Method::Head);
        assert_eq!(up[1].method, worker::Method::Get);
        assert_eq!(up[1].url, "https://image.gallery.test/2026/01/spicy_77.webp");
        assert!(up[1].no_cache);
        assert_eq!(up[1].preview_blur, Some(LOCKED_PREVIEW_BLUR));
        assert_eq!(up[1].preview_blur.unwrap().blur, 80);
        assert_eq!(up[1].preview_blur.unwrap().width, 360);
        assert_eq!(up[1].preview_blur.unwrap().quality, 30);
        assert_eq!(up[1].preview_blur.unwrap().format, "webp");
        drop(up);

        // Upstream 3xx redirect MUST be rejected with 502 Bad Gateway!
        backend.upstream_status = StatusCode::FOUND;
        let redirect_rejected =
            dispatch(&backend, &cfg, Method::GET, &uri, HeaderMap::new(), Bytes::new());
        assert_eq!(redirect_rejected.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            redirect_rejected.headers().get("cache-control").unwrap(),
            "private, no-store"
        );
    }

    #[test]
    fn admin_view_cookie_waives_login_and_billing_but_enforces_csrf_assertion_and_media_cap() {
        let policy = sample_safety_policy();
        let mut backend = MockBackend::with_policy(policy.clone());
        // Simulate login_required = yes for guests
        backend.account_statuses.insert("guest".to_string(), 401);
        let cfg = test_cfg();

        // 1. Cross-origin metered POST search with ADMIN_VIEW_COOKIE MUST still be rejected with 403!
        let mut csrf_hdrs = form_headers();
        csrf_hdrs.insert("cookie", make_admin_view_cookie().parse().unwrap());
        csrf_hdrs.insert("origin", "https://evil.test".parse().unwrap());
        let csrf_resp = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/search_by_desc",
            csrf_hdrs,
            Bytes::from_static(b"q=sunset"),
        );
        assert_eq!(csrf_resp.status(), StatusCode::FORBIDDEN);
        assert!(backend.upstream_calls.borrow().is_empty());

        // 2. Same-origin metered POST search with ADMIN_VIEW_COOKIE succeeds, waives billing,
        //    strips spoofed headers/cookies, and signs X-Gateway-Assertion with `is_admin_view: true`!
        let mut ok_hdrs = form_headers();
        ok_hdrs.insert("cookie", format!("{}; other=ok", make_admin_view_cookie()).parse().unwrap());
        ok_hdrs.insert("origin", "https://gallery.test".parse().unwrap());
        ok_hdrs.insert("x-gateway-assertion", "ga1.forged.sig".parse().unwrap());
        ok_hdrs.insert("x-gallery-switchers", "r18".parse().unwrap());
        ok_hdrs.insert("x-policy-revision", "999".parse().unwrap());
        let ok_resp = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/search_by_desc",
            ok_hdrs,
            Bytes::from_static(b"q=sunset"),
        );
        assert_eq!(ok_resp.status(), StatusCode::OK);
        assert!(backend.account_calls.borrow().is_empty());

        let up = backend.upstream_calls.borrow();
        assert_eq!(up.len(), 1);
        assert_eq!(header_value(&up[0].headers, "x-gallery-switchers"), None);
        assert_eq!(header_value(&up[0].headers, "x-policy-revision"), None);
        let fwd_cookie = header_value(&up[0].headers, "cookie").unwrap();
        assert_eq!(fwd_cookie, "other=ok");

        let assertion_raw = header_value(&up[0].headers, GATEWAY_ASSERTION_HEADER).unwrap();
        let verified = verify_gateway_assertion(
            assertion_raw,
            TEST_ASSERTION_SECRET,
            GATEWAY_ASSERTION_AUDIENCE,
            TEST_NOW,
            5,
        )
        .unwrap();
        assert!(verified.is_admin_view);
        assert_eq!(verified.sub.as_deref(), Some(ADMIN_VIEW_SUB));
        assert_eq!(verified.rev, policy.revision);
        assert_eq!(verified.min_enforce_rev, policy.min_enforce_rev);
        assert_eq!(verified.policy_digest, compute_policy_digest(&policy));
        assert!(verified.switchers.iter().any(|s| s == "r18"));
        drop(up);

        // 3. Admin-subject media capability requires active ADMIN_VIEW_COOKIE (denied without it!).
        let admin_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            kind: MediaCapKind::Video,
            id: 12,
            path: "clips/vid_12.mp4".to_string(),
            rev: 5,
            sub: ADMIN_VIEW_SUB.to_string(),
            sid: None,
            req_switchers: vec!["r18".to_string()],
            exp: TEST_NOW + 300,
        };
        let admin_cap_tok = sign_media_capability(&admin_cap, TEST_MEDIA_CAP_SECRET).unwrap();
        let media_uri = format!("/media/video/12?cap={admin_cap_tok}");
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, &media_uri, HeaderMap::new(), Bytes::new()).status(),
            StatusCode::FORBIDDEN
        );
        let mut admin_media_hdrs = HeaderMap::new();
        admin_media_hdrs.insert("cookie", make_admin_view_cookie().parse().unwrap());
        let admin_media_ok =
            dispatch(&backend, &cfg, Method::GET, &media_uri, admin_media_hdrs, Bytes::new());
        assert_eq!(admin_media_ok.status(), StatusCode::OK);
        assert!(backend.account_calls.borrow().is_empty());
        assert_eq!(
            backend.upstream_calls.borrow().last().unwrap().url,
            "https://video.gallery.test/clips/vid_12.mp4"
        );
    }

    #[test]
    fn public_legal_seo_static_paths_and_cache_control_rules() {
        let mut backend = MockBackend::with_policy(sample_safety_policy());
        // Simulate login_required=yes first
        backend.account_statuses.insert("guest".to_string(), 401);
        let cfg = test_cfg();

        // Always-public legal & static paths succeed even when login_required=yes.
        for path in [
            "/robots.txt",
            "/pkg/app.wasm",
            "/favicon.ico",
            "/terms",
            "/privacy",
            "/dmca",
            "/content-policy",
        ] {
            let r = dispatch(&backend, &cfg, Method::GET, path, HeaderMap::new(), Bytes::new());
            assert_eq!(r.status(), StatusCode::OK, "expected 200 on {path}");
            let cc = r.headers().get("cache-control").unwrap().to_str().unwrap();
            if path == "/robots.txt" || path.starts_with("/pkg/") {
                assert_eq!(cc, "public, max-age=3600", "public cache preserved on {path}");
            } else {
                assert_eq!(cc, "private, no-store", "private no-store on {path}");
            }
        }
        // Sitemap stays gated when login_required=yes.
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, "/sitemap.xml", HeaderMap::new(), Bytes::new())
                .status(),
            StatusCode::SEE_OTHER
        );

        // When login_required=no, anonymous sitemap is 200 and preserves public Cache-Control,
        // while gallery `/` emits private, no-store.
        backend.account_statuses.insert("guest".to_string(), 200);
        let sitemap = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "/sitemap/1.xml",
            HeaderMap::new(),
            Bytes::new(),
        );
        assert_eq!(sitemap.status(), StatusCode::OK);
        assert_eq!(
            sitemap.headers().get("cache-control").unwrap(),
            "public, max-age=3600"
        );
        let home = dispatch(&backend, &cfg, Method::GET, "/", HeaderMap::new(), Bytes::new());
        assert_eq!(home.status(), StatusCode::OK);
        assert_eq!(
            home.headers().get("cache-control").unwrap(),
            "private, no-store"
        );

        // Public-cacheable routes MUST force `private, no-store` on non-2xx responses
        // or whenever upstream attaches `Set-Cookie`.
        for status in [
            StatusCode::FOUND,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            backend.upstream_status = status;
            for p in ["/robots.txt", "/pkg/app.wasm", "/sitemap/1.xml"] {
                let r = dispatch(&backend, &cfg, Method::GET, p, HeaderMap::new(), Bytes::new());
                assert_eq!(r.status(), status);
                assert_eq!(
                    r.headers().get("cache-control").unwrap(),
                    "private, no-store",
                    "non-2xx {status} on {p} must not be publicly cached"
                );
            }
        }
        backend.upstream_status = StatusCode::OK;
        backend.upstream_set_cookie = Some("sid=leak; Path=/");
        for p in ["/robots.txt", "/pkg/app.wasm", "/sitemap/1.xml"] {
            let r = dispatch(&backend, &cfg, Method::GET, p, HeaderMap::new(), Bytes::new());
            assert_eq!(r.status(), StatusCode::OK);
            assert_eq!(
                r.headers().get("cache-control").unwrap(),
                "private, no-store",
                "Set-Cookie on {p} must force private, no-store"
            );
        }
    }

    #[test]
    fn unmetered_post_routes_enforce_same_origin_csrf_for_all_callers() {
        let policy = sample_safety_policy();
        let mut backend = MockBackend::with_policy(policy);
        let do_key = "usr:550e8400-e29b-41d4-a716-446655440000";
        backend.session_contexts.insert(
            do_key.to_string(),
            SessionContext {
                active: true,
                banned: false,
                sid_valid: true,
                ..SessionContext::default()
            },
        );
        let cfg = test_cfg();

        for path in [
            "/api/search_advanced",
            "/api/fetch_post_meta",
            "/api/suggest_search",
            "/api/site_config",
            "/api/search_query",
            "/api/list_post_images",
            "/api/fetch_image_details",
        ] {
            let full_uri = format!("https://gallery.test{path}");
            for caller_cookie in [
                make_v2_cookie("user-42", do_key, "sid-1"),
                make_admin_view_cookie(),
            ] {
                // Missing Origin / Sec-Fetch-Site -> 403
                let mut missing = form_headers();
                missing.insert("cookie", caller_cookie.parse().unwrap());
                let r_missing = dispatch(
                    &backend,
                    &cfg,
                    Method::POST,
                    &full_uri,
                    missing,
                    Bytes::from_static(b"q=tag%3Amaid"),
                );
                assert_eq!(r_missing.status(), StatusCode::FORBIDDEN, "missing origin on {path}");

                // Cross-origin -> 403
                let mut cross = form_headers();
                cross.insert("cookie", caller_cookie.parse().unwrap());
                cross.insert("origin", "https://evil.test".parse().unwrap());
                let r_cross = dispatch(
                    &backend,
                    &cfg,
                    Method::POST,
                    &full_uri,
                    cross,
                    Bytes::from_static(b"q=tag%3Amaid"),
                );
                assert_eq!(r_cross.status(), StatusCode::FORBIDDEN, "cross-origin on {path}");
            }
        }
        assert!(backend.upstream_calls.borrow().is_empty());

        // Same-origin succeeds cleanly.
        let mut ok_hdrs = form_headers();
        ok_hdrs.insert("origin", "https://gallery.test".parse().unwrap());
        ok_hdrs.insert("cookie", make_admin_view_cookie().parse().unwrap());
        let ok = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/search_advanced",
            ok_hdrs,
            Bytes::from_static(b"q=tag%3Amaid"),
        );
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[test]
    fn compute_eligible_switchers_checks_terms_age_safe_mode_and_rule_mode() {
        let mut policy = sample_safety_policy();
        policy.age_policy = AgeVerificationPolicy::SelfAttestation;
        policy.age_gate_trigger = AgeGateTrigger::Off;
        policy.rules.push(SafetyRuleConfig {
            id: "disabled_rule".into(),
            name: "Disabled".into(),
            mode: RuleMode::Switcher,
            query: "tag:blood".into(),
            default_min_score: 0.5,
            preset: PlaceholderPreset::Custom,
            requires_login: false,
            requires_age_18: false,
            enabled: false,
        });

        let mut ctx = SessionContext {
            active: true,
            banned: false,
            sid_valid: true,
            assurance_level: AssuranceLevel::SelfAttestation,
            strict_age_ok: false,
            terms_version_accepted: Some(policy.legal.terms_version),
            terms_digest_accepted: Some(policy.legal.terms_digest.clone()),
            enabled_switchers: vec![
                "r18".into(),
                "sensitive".into(), // SpoilerBlur, not Switcher
                "blood".into(),
                "disabled_rule".into(),
            ],
            safe_mode: false,
        };

        // Under SelfAttestation with accepted terms: both r18 and blood eligible (not sensitive/disabled).
        assert_eq!(compute_eligible_switchers(&ctx, &policy), vec!["r18", "blood"]);

        // Without age assurance under SelfAttestation: r18 dropped, blood remains.
        ctx.assurance_level = AssuranceLevel::None;
        assert_eq!(compute_eligible_switchers(&ctx, &policy), vec!["blood"]);

        // Under StrictProviderVerified18: SelfAttestation is insufficient; needs strict_age_ok + Verified18.
        policy.age_policy = AgeVerificationPolicy::StrictProviderVerified18;
        ctx.assurance_level = AssuranceLevel::SelfAttestation;
        assert_eq!(compute_eligible_switchers(&ctx, &policy), vec!["blood"]);
        ctx.assurance_level = AssuranceLevel::Verified18;
        ctx.strict_age_ok = true;
        assert_eq!(compute_eligible_switchers(&ctx, &policy), vec!["r18", "blood"]);

        // Safe mode immediately wipes all switchers.
        ctx.safe_mode = true;
        assert!(compute_eligible_switchers(&ctx, &policy).is_empty());
    }

    #[test]
    fn legacy_session_cutover_and_revoked_v2_session_handling() {
        let policy = sample_safety_policy();
        let mut backend = MockBackend::with_policy(policy);
        backend.session_contexts.insert(
            ETH_WALLET.to_string(),
            SessionContext {
                active: true,
                banned: false,
                sid_valid: true,
                ..SessionContext::default()
            },
        );
        let cfg = test_cfg();

        // Legacy wallet session verifies via cutover and checks DO with `sid: None`.
        let legacy_tok = sign_legacy_session(
            &LegacySessionClaims {
                sub: ETH_WALLET.to_string(),
                iat: TEST_NOW - 10,
                exp: TEST_NOW + 3600,
            },
            TEST_JWT_SECRET,
        )
        .unwrap();
        let mut h = HeaderMap::new();
        h.insert("cookie", format!("{SESSION_COOKIE}={legacy_tok}").parse().unwrap());
        let resp = dispatch(&backend, &cfg, Method::GET, "/api/like_previews?items=post:1", h, Bytes::new());
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            backend.session_calls.borrow().as_slice(),
            &[(ETH_WALLET.to_string(), None)]
        );

        // Revoked v2 session on authenticated-only route -> 401 + Set-Cookie clearing ue_session!
        backend.session_contexts.insert(
            ETH_WALLET.to_string(),
            SessionContext {
                active: true,
                banned: false,
                sid_valid: false,
                ..SessionContext::default()
            },
        );
        let mut h2 = HeaderMap::new();
        h2.insert(
            "cookie",
            make_v2_cookie(ETH_WALLET, ETH_WALLET, "revoked-sid")
                .parse()
                .unwrap(),
        );
        let revoked = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "/api/like_previews?items=post:1",
            h2,
            Bytes::new(),
        );
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
        let sc = revoked.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(sc.starts_with("ue_session=;"));
        assert!(sc.contains("Max-Age=0"));
    }

    // -----------------------------------------------------------------------
    // Retained & Updated Pure Unit Tests
    // -----------------------------------------------------------------------

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
        assert!(is_segment_prefix("/admin", "/admin"));
        assert!(is_segment_prefix("/admin/api/policy", "/admin"));
        assert!(!is_segment_prefix("/admin2", "/admin"));
        assert!(!is_segment_prefix("/administrator", "/admin"));
        assert!(is_segment_prefix("/user/admin", "/user/admin"));
        assert!(is_segment_prefix("/user/admin/settings", "/user/admin"));
        assert!(!is_segment_prefix("/user/admin2", "/user/admin"));
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
            "https://api.gallery.test/base",
            "https://api.gallery.test?x=1",
            "https://api.gallery.test#frag",
        ] {
            assert!(parse_upstream_origin(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn canonical_path_and_media_cap_path_block_traversal_attacks() {
        for ok in [
            "/",
            "/admin",
            "/media/image/42",
            "/api/search_advanced_clip",
            "/pkg/app.wasm",
        ] {
            assert!(is_canonical_path(ok), "must accept {ok:?}");
        }

        for attack in [
            "/x/%2e%2e/api/search_advanced_clip",
            "/admin/%2e%2e/secret",
            "//admin",
            "/api%2fsearch_advanced_clip",
            "/api%5csearch_advanced_clip",
            "/media/image/bad%2",
        ] {
            assert!(!is_canonical_path(attack), "must reject {attack:?}");
        }

        // Media cap path canonicalization & traversal defense (rejects `%` and `:` directly,
        // matching hardened `site_access::is_safe_media_path`).
        assert_eq!(
            encode_canonical_cap_path("Demo album/a(1).webp").as_deref(),
            Some("/Demo%20album/a%281%29.webp")
        );
        for bad_cap in [
            "",
            "/leading.webp",
            "trailing/",
            "../secret.webp",
            "%2e%2e/secret.webp",
            "Demo%20album/a.webp",
            "a/%2e/b.webp",
            "a%2fb.webp",
            "a%5cb.webp",
            "a:b.webp",
            "https://evil.test/x.webp",
            "a?b=1",
            "a#frag",
            "bad%2",
        ] {
            assert!(
                build_media_upstream_target(MediaCapKind::Image, bad_cap, &test_upstreams())
                    .is_err(),
                "must reject cap.path {bad_cap:?}"
            );
        }
    }

    #[test]
    fn sanitize_origin_cookie_strips_all_sensitive_cookies_across_multiple_headers() {
        let mut h = HeaderMap::new();
        h.append("cookie", "pref=dark; ue_session=s1; __Host-ue_admin_view=a1".parse().unwrap());
        h.append(
            "cookie",
            "gw_token=old; gw_app=old2; __Host-auth_tx=tx; CF_Authorization=cf; keep=yes"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            sanitize_origin_cookie(&h).as_deref(),
            Some("pref=dark; keep=yes")
        );
    }

    #[test]
    fn browse_route_allows_legal_seo_and_pinned_search_and_blocks_raw_media_and_like_previews() {
        for ok_get in [
            "/",
            "/favicon.ico",
            "/robots.txt",
            "/sitemap.xml",
            "/sitemap/1.xml",
            "/terms",
            "/privacy",
            "/dmca",
            "/content-policy",
            "/pkg/app.js",
            "/details/42",
        ] {
            assert!(browse_route(&Method::GET, ok_get), "GET {ok_get}");
        }
        assert!(!browse_route(&Method::GET, "/images/a.webp"));
        assert!(!browse_route(&Method::GET, "/videos/a.mp4"));
        assert!(!browse_route(&Method::GET, "/api/like_previews"));

        for pinned in [
            "/api/fetch_post_meta",
            "/api/suggest_search",
            "/api/site_config",
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
        }
        assert!(browse_route(&Method::POST, "/api/search_query1234567890"));
    }

    #[test]
    fn anonymous_post_site_config_allowed_under_open_guest_browsing() {
        let policy = sample_safety_policy();
        let mut backend = MockBackend::with_policy(policy.clone());
        // login_required = false -> guest DO returns 200.
        backend.account_statuses.insert("guest".to_string(), 200);
        let cfg = test_cfg();

        // Same-origin anonymous POST /api/site_config succeeds and proxies with anonymous assertion.
        let mut ok_hdrs = HeaderMap::new();
        ok_hdrs.insert("origin", "https://gallery.test".parse().unwrap());
        let ok = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/site_config",
            ok_hdrs.clone(),
            Bytes::new(),
        );
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(
            ok.headers().get("cache-control").unwrap(),
            "private, no-store"
        );
        {
            let calls = backend.account_calls.borrow();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].operation, "guest");
            assert!(calls[0].payload["item"].is_null());
        }
        {
            let up = backend.upstream_calls.borrow();
            assert_eq!(up.len(), 1);
            assert_eq!(up[0].url, "https://api.gallery.test/api/site_config");
            let assertion_raw = header_value(&up[0].headers, GATEWAY_ASSERTION_HEADER).unwrap();
            let verified = verify_gateway_assertion(
                assertion_raw,
                TEST_ASSERTION_SECRET,
                GATEWAY_ASSERTION_AUDIENCE,
                TEST_NOW,
                5,
            )
            .unwrap();
            assert_eq!(verified.sub, None);
            assert!(verified.switchers.is_empty());
            assert_eq!(verified.rev, policy.revision);
        }

        // Cross-origin anonymous POST /api/site_config is still rejected with 403 CSRF.
        let mut cross_hdrs = HeaderMap::new();
        cross_hdrs.insert("origin", "https://evil.test".parse().unwrap());
        let cross = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/site_config",
            cross_hdrs,
            Bytes::new(),
        );
        assert_eq!(cross.status(), StatusCode::FORBIDDEN);

        // Anonymous GET /api/site_config stays gated (401).
        let get_resp = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "https://gallery.test/api/site_config",
            HeaderMap::new(),
            Bytes::new(),
        );
        assert_eq!(get_resp.status(), StatusCode::UNAUTHORIZED);

        // Under login_required = true (guest DO returns 401), anonymous POST /api/site_config -> 401.
        backend.account_statuses.insert("guest".to_string(), 401);
        let gated = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/site_config",
            ok_hdrs,
            Bytes::new(),
        );
        assert_eq!(gated.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_form_urlencoded_and_metered_item_validate_search_endpoints() {
        let mut mixed_dup = form_headers();
        mixed_dup.append(CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(require_form_urlencoded(&mixed_dup).is_err());

        let form = form_headers();
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

        let over_32k = Bytes::from(vec![b'a'; 32 * 1024 + 1]);
        assert_eq!(
            metered_item(&Method::POST, "/api/search_by_desc", &form, &over_32k).unwrap_err(),
            MeterError::PayloadTooLarge
        );
    }

    #[test]
    fn checked_methods_enforce_user_gallery_and_media_allowlists() {
        assert_eq!(checked_media_method(&Method::GET), Some(worker::Method::Get));
        assert_eq!(checked_media_method(&Method::HEAD), Some(worker::Method::Head));
        assert_eq!(checked_media_method(&Method::POST), None);
        assert_eq!(checked_gallery_method(&Method::POST), Some(worker::Method::Post));
        assert_eq!(checked_gallery_method(&Method::DELETE), None);
        assert_eq!(checked_user_method(&Method::DELETE), Some(worker::Method::Delete));
        assert_eq!(checked_user_method(&Method::TRACE), None);
    }

    #[test]
    fn is_same_origin_validates_origin_and_fetch_metadata() {
        let https_uri: Uri = "https://gallery.test/api/search_by_desc".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("origin", "https://gallery.test".parse().unwrap());
        assert!(is_same_origin(&https_uri, &h));

        h.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(!is_same_origin(&https_uri, &h));
    }

    #[test]
    fn metered_post_search_reserves_commits_on_2xx_and_releases_on_error() {
        let policy = sample_safety_policy();
        let mut backend = MockBackend::with_policy(policy);
        let do_key = "usr:550e8400-e29b-41d4-a716-446655440000";
        backend.session_contexts.insert(
            do_key.to_string(),
            SessionContext {
                active: true,
                banned: false,
                sid_valid: true,
                ..SessionContext::default()
            },
        );
        let cfg = test_cfg();

        let mut h = form_headers();
        h.insert("origin", "https://gallery.test".parse().unwrap());
        h.insert(
            "cookie",
            make_v2_cookie("user-42", do_key, "sid-1").parse().unwrap(),
        );

        // Upstream 200 -> reserve then commit
        let ok = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/search_by_desc",
            h.clone(),
            Bytes::from_static(b"q=ocean"),
        );
        assert_eq!(ok.status(), StatusCode::OK);
        {
            let calls = backend.account_calls.borrow();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].operation, "reserve");
            assert_eq!(calls[1].operation, "commit");
            assert_eq!(calls[1].payload["hold_id"], "hold-1");
        }

        // Upstream 500 -> reserve then release
        backend.account_calls.borrow_mut().clear();
        backend.upstream_status = StatusCode::INTERNAL_SERVER_ERROR;
        let err = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/search_by_desc",
            h,
            Bytes::from_static(b"q=ocean"),
        );
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let calls = backend.account_calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].operation, "reserve");
        assert_eq!(calls[1].operation, "release");
        assert_eq!(calls[1].payload["hold_id"], "hold-1");
    }

    #[test]
    fn preview_without_cf_blur_and_admin_safe_mode_override_behave_securely() {
        let mut policy = sample_safety_policy();
        policy.cloudflare_images_blur = false;
        let mut backend = MockBackend::with_policy(policy.clone());
        let do_key = "usr:550e8400-e29b-41d4-a716-446655440000";
        backend.session_contexts.insert(
            do_key.to_string(),
            SessionContext {
                active: true,
                banned: false,
                sid_valid: true,
                safe_mode: true,
                ..SessionContext::default()
            },
        );
        let cfg = test_cfg();

        // When cloudflare_images_blur is false, /media/preview/* MUST fail closed (403)
        // with ZERO billing calls and ZERO upstream clear-image fetches!
        let preview_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            kind: MediaCapKind::Preview,
            id: 55,
            path: "p/55.webp".to_string(),
            rev: 5,
            sub: MEDIA_CAP_ANON_SUB.to_string(),
            sid: None,
            req_switchers: Vec::new(),
            exp: TEST_NOW + 300,
        };
        let preview_tok = sign_media_capability(&preview_cap, TEST_MEDIA_CAP_SECRET).unwrap();
        let resp = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/preview/55?cap={preview_tok}"),
            HeaderMap::new(),
            Bytes::new(),
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "private, no-store"
        );
        assert!(backend.account_calls.borrow().is_empty());
        assert!(backend.upstream_calls.borrow().is_empty());

        // Admin browse pass combined with a user session in `safe_mode = true` MUST deny admin restricted media!
        let admin_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            kind: MediaCapKind::Image,
            id: 56,
            path: "r/56.webp".to_string(),
            rev: 5,
            sub: ADMIN_VIEW_SUB.to_string(),
            sid: None,
            req_switchers: vec!["r18".to_string()],
            exp: TEST_NOW + 300,
        };
        let admin_tok = sign_media_capability(&admin_cap, TEST_MEDIA_CAP_SECRET).unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            format!(
                "{}; {}",
                make_admin_view_cookie(),
                make_v2_cookie("user-42", do_key, "sid-1")
            )
            .parse()
            .unwrap(),
        );
        let denied = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/image/56?cap={admin_tok}"),
            h,
            Bytes::new(),
        );
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn hold_wire_types_round_trip() {
        let req = HoldReq {
            hold_id: "hold-123".into(),
        };
        let decoded: HoldReq = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(decoded.hold_id, "hold-123");

        let resp = HoldResp {
            hold_id: Some("hold-123".into()),
        };
        let decoded_resp: HoldResp =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(decoded_resp.hold_id.as_deref(), Some("hold-123"));
    }
}
