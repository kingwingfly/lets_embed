//! Hardened edge gateway Worker (`lets-embed-gateway-worker`).
//!
//! Enforces Policy v3 end-to-end:
//! - Canonical path validation
//! - Cloudflare Access-verified `/admin*` routing (with optional `ADMIN_ALLOWED_EMAILS`),
//!   lazy `KeyDomain::AdminAssertion` loading, and request-bound `AdminAssertion` v2 (`aa2.`)
//! - Fail-closed strict `decode_active_policy_v3` sync from singleton `SITE_POLICY` DO
//! - Step 0 authoritative geo-blocking via `request.cf().country()` (exempting `/admin*`)
//! - Unconditional `404` retirement of `/user/admin*` and blocking of raw `/images/*`,
//!   `/videos/*`, and `/internal/*`
//! - HKDF `SITE_SECRET` key derivation with optional per-purpose overrides
//! - Zero implicit admin auto-unlock (`ADMIN_VIEW_COOKIE` strictly limited to billing/wall waiver)
//! - Revocable `v2` sessions + legacy cutover with live `USER_ACCOUNT` DO `/session-context`
//! - Policy v3 `compute_policy_access` + `ActorBinding` + `GatewayAssertion` v3 (`ga3.`)
//! - Object-bound click-to-reveal (`POST /api/safety/reveal`) with signed `le_guest_sid` cookie
//! - `MediaCapability` v3 (`mc3.`) redemption with authoritative `/internal/facts-rev/{kind}/{id}`
//!   checks, `authorize_media_capability_v3`, authorize-before-bill canonical metering,
//!   and fail-closed locked Cloudflare Images preview blur (`cf-resized: internal=ok`)

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
use site_access::{
    ADMIN_ASSERTION_AUDIENCE, ADMIN_ASSERTION_HEADER, ADMIN_ASSERTION_TTL,
    ADMIN_ASSERTION_VERSION, ADMIN_HEADER, ADMIN_VIEW_COOKIE, ActorBinding, AdminAssertionClaims,
    GATEWAY_ASSERTION_AUDIENCE, GATEWAY_ASSERTION_HEADER, GATEWAY_ASSERTION_TTL,
    GATEWAY_ASSERTION_VERSION, GUEST_SESSION_COOKIE, GUEST_SESSION_VERSION, GatewayAssertion,
    GuestReq, GuestSessionToken, HoldReq, HoldResp, MEDIA_CAP_AUDIENCE, MediaCapKind,
    PolicyAccessResult, PolicyCallerContext, PublicSitePolicy, SESSION_COOKIE, SessionContext,
    authorize_media_capability_v3, compute_policy_access, compute_policy_digest,
    decode_active_policy_v3, is_privileged_request_header, sign_admin_assertion,
    sign_gateway_assertion, sign_guest_session, verify_media_capability, verify_session_any,
};
use tower_cookies::{CookieManagerLayer, Cookies};
use tower_service::Service;
use worker::{
    Context, Env, Fetch, HttpRequest, Request, RequestInit, Result, event, js_sys::Uint8Array,
    wasm_bindgen::JsValue,
};

use crate::auth::{
    GUEST_SESSION_TTL, GatewaySecretInputs, LiveSession, SessionContextReq,
    clear_session_cookie_header, filter_allowed_admin_email, guest_session_set_cookie_header,
    parse_admin_allowed_emails, resolve_actor_binding, resolve_admin_assertion_secret,
    resolve_gateway_secrets,
};
use crate::http_util::{
    GALLERY_ALLOWED_METHODS, MAX_ADMIN_BODY_BYTES, MAX_GATEWAY_BODY_BYTES, MAX_REVEAL_BODY_BYTES,
    MEDIA_ALLOWED_METHODS, USER_ALLOWED_METHODS, Upstreams, browse_route,
    build_api_upstream_target, checked_gallery_method, checked_media_method, checked_user_method,
    guest_id, has_reveal_csrf_header, is_always_public_path, is_canonical_path, is_hop_by_hop,
    is_https_request, is_public_cacheable_path, is_same_origin, is_segment_prefix, is_sitemap_path,
    login_response, metered_item, method_not_allowed, payment_required, private_no_store,
    request_host, sanitize_origin_cookie, sanitize_user_worker_cookie,
    should_strip_api_request_header,
};
use crate::media::{
    PreviewBlurConfig, PreviewBudgetReq, build_facts_rev_target, build_media_upstream_target,
    extract_media_cap_query, is_allowed_media_request_header,
    is_verified_preview_transform_response, parse_facts_rev_response, parse_media_route,
    resolve_preview_blur,
};

// ---------------------------------------------------------------------------
// Strict Policy v3 Snapshot Decoding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SitePolicySnapshot {
    policy: PublicSitePolicy,
    digest: String,
}

/// Strictly parses the `SitePolicyDO` `GET /policy` JSON envelope
/// (`{"policy": ..., "digest": "..."}`) using [`decode_active_policy_v3`].
///
/// Fails closed on unsupported `schema_version`, legacy `"rules"` field,
/// malformed JSON, invalid Policy v3 invariants, or digest mismatch.
fn parse_site_policy_envelope_v3(
    raw_envelope: &str,
) -> std::result::Result<SitePolicySnapshot, String> {
    let envelope: serde_json::Value = serde_json::from_str(raw_envelope)
        .map_err(|e| format!("malformed SITE_POLICY JSON: {e}"))?;
    let obj = envelope
        .as_object()
        .ok_or_else(|| "SITE_POLICY response must be a JSON object".to_string())?;
    let policy_val = obj
        .get("policy")
        .ok_or_else(|| "SITE_POLICY response missing 'policy' field".to_string())?;
    let envelope_digest = obj
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "SITE_POLICY response missing string 'digest' field".to_string())?;

    let policy_json = serde_json::to_string(policy_val)
        .map_err(|e| format!("serialize SITE_POLICY policy object: {e}"))?;
    let mut policy = decode_active_policy_v3(&policy_json)
        .map_err(|e| format!("invalid active policy v3: {e}"))?;

    let computed = compute_policy_digest(&policy);
    if envelope_digest != computed {
        return Err("SITE_POLICY envelope digest mismatch".to_string());
    }
    if policy.policy_digest.is_empty() {
        policy.policy_digest = computed.clone();
    } else if policy.policy_digest != computed {
        return Err("policy_digest mismatch".to_string());
    }
    Ok(SitePolicySnapshot {
        policy,
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
    internal_api_secret: Arc<Vec<u8>>,
    guest_session_secret: Arc<Vec<u8>>,
    admin_email: Option<String>,
    admin_allowed_emails: Option<Arc<Vec<String>>>,
    visitor_country: Option<String>,
    cf_access_service_token: Option<Arc<(String, String)>>,
    upstreams: Arc<Upstreams>,
}

impl GatewayConfig {
    /// Returns the live verified staff CF Access email ONLY if it passes the
    /// optional `ADMIN_ALLOWED_EMAILS` allowlist.
    ///
    /// NEVER populated from `ADMIN_VIEW_COOKIE`.
    fn live_admin_email(&self) -> Option<&str> {
        filter_allowed_admin_email(
            self.admin_email.as_deref(),
            self.admin_allowed_emails.as_deref().map(Vec::as_slice),
        )
    }
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
    /// Generates a cryptographically random 128-bit lowercase hex string (32 chars).
    fn random_hex_128(&self) -> std::result::Result<String, BackendError>;
    /// Lazily resolves `KeyDomain::AdminAssertion` ONLY when handling `/admin*` routes.
    fn load_admin_assertion_secret(&self) -> std::result::Result<Vec<u8>, BackendError>;
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
    async fn fetch_facts_rev(
        &self,
        req: UpstreamFetchReq,
    ) -> std::result::Result<(u16, String), BackendError>;
}

// ---------------------------------------------------------------------------
// Cloudflare Workers Runtime Backend
// ---------------------------------------------------------------------------

struct WorkerBackend<'a> {
    env: &'a Env,
}

fn optional_env_str(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|s| s.to_string())
        .or_else(|| env.var(name).ok().map(|v| v.to_string()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn optional_cf_access_service_token(env: &Env) -> Result<Option<(String, String)>> {
    let id = optional_env_str(env, "CF_ACCESS_CLIENT_ID");
    let secret = optional_env_str(env, "CF_ACCESS_CLIENT_SECRET");
    match (id, secret) {
        (Some(id), Some(secret)) => Ok(Some((id, secret))),
        (None, None) => Ok(None),
        _ => Err(worker::Error::RustError(
            "CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET must both be set or both unset"
                .into(),
        )),
    }
}

fn build_cf_object(
    no_cache: bool,
    cache_everything: bool,
    blur: Option<PreviewBlurConfig>,
) -> Option<worker::js_sys::Object> {
    if !no_cache && !cache_everything && blur.is_none() {
        return None;
    }
    let cf = worker::js_sys::Object::new();
    if no_cache {
        let _ = worker::js_sys::Reflect::set(&cf, &"cacheTtl".into(), &JsValue::from_f64(0.0));
        let _ = worker::js_sys::Reflect::set(&cf, &"cacheEverything".into(), &JsValue::FALSE);
    } else if cache_everything {
        // Explicitly allow Cloudflare edge caching for public `.wasm`, `.txt`, and `.xml` assets.
        let _ = worker::js_sys::Reflect::set(&cf, &"cacheEverything".into(), &JsValue::TRUE);
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

fn build_worker_upstream_request(
    req: UpstreamFetchReq,
) -> std::result::Result<Request, BackendError> {
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
    if let Some(cf) = build_cf_object(req.no_cache, !req.no_cache, req.preview_blur) {
        let _ = worker::js_sys::Reflect::set(js_init.as_ref(), &"cf".into(), &cf);
    }
    let web_req = worker::web_sys::Request::new_with_str_and_init(req.url.as_str(), &js_init)
        .map_err(|e| BackendError(format!("build upstream request failed: {e:?}")))?;
    Ok(Request::from(web_req))
}

impl GatewayBackend for WorkerBackend<'_> {
    fn now_secs(&self) -> u64 {
        worker::Date::now().as_millis() / 1000
    }

    fn random_hex_128(&self) -> std::result::Result<String, BackendError> {
        use worker::{
            js_sys::{Function, Reflect, Uint8Array, global},
            wasm_bindgen::JsCast,
        };
        let crypto = Reflect::get(&global(), &"crypto".into())
            .map_err(|e| BackendError(format!("global crypto unavailable: {e:?}")))?;
        let get_random_values: Function = Reflect::get(&crypto, &"getRandomValues".into())
            .map_err(|e| BackendError(format!("crypto.getRandomValues unavailable: {e:?}")))?
            .dyn_into()
            .map_err(|_| BackendError("crypto.getRandomValues is not a function".into()))?;
        let buf = Uint8Array::new_with_length(16);
        get_random_values
            .call1(&crypto, buf.as_ref())
            .map_err(|e| BackendError(format!("crypto.getRandomValues failed: {e:?}")))?;
        let mut bytes = [0u8; 16];
        buf.copy_to(&mut bytes);
        Ok(bytes.iter().fold(String::with_capacity(32), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        }))
    }

    fn load_admin_assertion_secret(&self) -> std::result::Result<Vec<u8>, BackendError> {
        let explicit = optional_env_str(self.env, "ADMIN_ASSERTION_SECRET");
        let site_secret = optional_env_str(self.env, "SITE_SECRET");
        resolve_admin_assertion_secret(explicit.as_deref(), site_secret.as_deref())
            .map_err(|e| BackendError(e.to_string()))
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
        let raw = resp.text().await?;
        parse_site_policy_envelope_v3(&raw).map_err(BackendError)
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
        let worker_req = build_worker_upstream_request(req)?;
        let resp = Fetch::Request(worker_req).send().await?;
        Ok(Response::from(resp))
    }

    async fn fetch_facts_rev(
        &self,
        req: UpstreamFetchReq,
    ) -> std::result::Result<(u16, String), BackendError> {
        let worker_req = build_worker_upstream_request(req)?;
        let mut resp = Fetch::Request(worker_req).send().await?;
        let status = resp.status_code();
        if status == 200 {
            let text = resp.text().await?;
            Ok((status, text))
        } else {
            Ok((status, String::new()))
        }
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
    let Some(expected) = optional_env_str(env, "CF_ACCESS_AUD") else {
        return Ok(None);
    };
    let aud = Reflect::get(&access, &"aud".into())?.as_string();
    if aud.as_deref() != Some(expected.as_str()) {
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

async fn router(env: Env, ctx: Context, visitor_country: Option<String>) -> Result<Router> {
    let site_secret = optional_env_str(&env, "SITE_SECRET");
    let jwt_secret = optional_env_str(&env, "JWT_SECRET");
    let session_v2_secret = optional_env_str(&env, "SESSION_V2_SECRET");
    let session_secret = optional_env_str(&env, "SESSION_SECRET");
    let media_cap_secret = optional_env_str(&env, "MEDIA_CAP_SECRET");
    let gateway_assertion_secret = optional_env_str(&env, "GATEWAY_ASSERTION_SECRET");
    let internal_api_secret = optional_env_str(&env, "INTERNAL_API_SECRET");
    let guest_session_secret = optional_env_str(&env, "GUEST_SESSION_SECRET");

    // NOTE: AdminAssertion is intentionally NOT resolved here — it is loaded lazily
    // ONLY on `/admin*` inside `handle_admin_route` so rolling out an override key
    // can never break gallery traffic!
    let resolved = resolve_gateway_secrets(&GatewaySecretInputs {
        site_secret: site_secret.as_deref(),
        jwt_secret: jwt_secret.as_deref(),
        session_v2_secret: session_v2_secret.as_deref(),
        session_secret: session_secret.as_deref(),
        media_cap_secret: media_cap_secret.as_deref(),
        gateway_assertion_secret: gateway_assertion_secret.as_deref(),
        internal_api_secret: internal_api_secret.as_deref(),
        guest_session_secret: guest_session_secret.as_deref(),
    })
    .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let cf_access_service_token = optional_cf_access_service_token(&env)?.map(Arc::new);
    let admin_allowed_emails =
        parse_admin_allowed_emails(optional_env_str(&env, "ADMIN_ALLOWED_EMAILS").as_deref())
            .map(Arc::new);
    let upstreams = Upstreams::from_env(&env)?;
    let admin_email = access_admin(&ctx, &env).await?;

    let state = AppState {
        env: Arc::new(env),
        cfg: GatewayConfig {
            jwt_secret: Arc::new(resolved.jwt_secret),
            session_v2_secret: Arc::new(resolved.session_v2_secret),
            gateway_assertion_secret: Arc::new(resolved.gateway_assertion_secret),
            media_cap_secret: Arc::new(resolved.media_cap_secret),
            internal_api_secret: Arc::new(resolved.internal_api_secret),
            guest_session_secret: Arc::new(resolved.guest_session_secret),
            admin_email,
            admin_allowed_emails,
            visitor_country,
            cf_access_service_token,
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
// Core Hardened Policy v3 Request Pipeline
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
            if !ctx.active || ctx.banned || ctx.suspended {
                return SessionResolution::Banned;
            }
            if !ctx.sid_valid {
                return SessionResolution::Unauthenticated { clear_cookie: true };
            }
            SessionResolution::Authenticated(LiveSession {
                session: verified,
                ctx,
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

fn append_cf_access_service_headers(out: &mut Vec<(String, String)>, cfg: &GatewayConfig) {
    if let Some((client_id, client_secret)) = cfg.cf_access_service_token.as_deref() {
        out.push(("CF-Access-Client-Id".to_string(), client_id.clone()));
        out.push(("CF-Access-Client-Secret".to_string(), client_secret.clone()));
    }
}

fn build_service_headers(
    headers: &HeaderMap,
    target: ServiceTarget,
    admin_auth: Option<(&str, &str)>,
    visitor_country: Option<&str>,
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
            || name.eq_ignore_ascii_case("x-internal-api-secret")
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
            if let Some(country) = visitor_country
                .map(str::trim)
                .filter(|c| !c.is_empty() && !c.chars().any(char::is_control))
            {
                out.push(("cf-ipcountry".to_string(), country.to_string()));
            }
        }
        ServiceTarget::AdminDashboard => {
            // Preserve admin SPA cookies (e.g., CSRF cookie) while stripping all
            // sensitive origin/auth cookies (`STRIPPED_ORIGIN_COOKIES`).
            if let Some(cookie) = sanitize_origin_cookie(headers) {
                out.push(("cookie".to_string(), cookie));
            }
            if let Some((email, signed_assertion)) = admin_auth {
                out.push((ADMIN_HEADER.to_string(), email.to_string()));
                out.push((
                    ADMIN_ASSERTION_HEADER.to_string(),
                    signed_assertion.to_string(),
                ));
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
        let proto = if is_https_request(uri) {
            "https"
        } else {
            "http"
        };
        out.push(("x-forwarded-host".to_string(), host.to_string()));
        out.push(("x-forwarded-proto".to_string(), proto.to_string()));
    }
    if let Some(cookie) = sanitize_origin_cookie(headers) {
        out.push(("cookie".to_string(), cookie));
    }
    append_cf_access_service_headers(&mut out, cfg);
    out.push((
        GATEWAY_ASSERTION_HEADER.to_string(),
        signed_assertion.to_string(),
    ));
    out
}

fn build_facts_rev_headers(cfg: &GatewayConfig, signed_assertion: &str) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(5);
    out.push(("accept".to_string(), "application/json".to_string()));
    append_cf_access_service_headers(&mut out, cfg);
    out.push((
        GATEWAY_ASSERTION_HEADER.to_string(),
        signed_assertion.to_string(),
    ));
    if let Ok(internal_str) = std::str::from_utf8(&cfg.internal_api_secret)
        && !internal_str.is_empty()
    {
        out.push(("x-internal-api-secret".to_string(), internal_str.to_string()));
    }
    out
}

fn build_media_headers(
    kind: MediaCapKind,
    headers: &HeaderMap,
    cfg: &GatewayConfig,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in headers {
        let name = k.as_str();
        if is_allowed_media_request_header(kind, name)
            && !is_privileged_request_header(name)
            && let Ok(val) = v.to_str()
        {
            out.push((name.to_string(), val.to_string()));
        }
    }
    append_cf_access_service_headers(&mut out, cfg);
    out
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AssertionFlags {
    is_billing_waived: bool,
    caller_age_verified: bool,
    caller_terms_accepted: bool,
}

fn caller_assertion_flags(
    auth: Option<&LiveSession>,
    policy: &PublicSitePolicy,
    is_billing_waived: bool,
) -> AssertionFlags {
    AssertionFlags {
        is_billing_waived,
        caller_age_verified: auth
            .is_some_and(|live| live.ctx.satisfies_age_18(policy.age_policy)),
        caller_terms_accepted: auth.is_some_and(|live| live.ctx.satisfies_terms(&policy.legal)),
    }
}

fn sign_assertion_v3(
    cfg: &GatewayConfig,
    snapshot: &SitePolicySnapshot,
    now: u64,
    actor: ActorBinding,
    access: PolicyAccessResult,
    flags: AssertionFlags,
) -> std::result::Result<String, site_access::TokenError> {
    let assertion = GatewayAssertion {
        v: GATEWAY_ASSERTION_VERSION,
        aud: GATEWAY_ASSERTION_AUDIENCE.to_string(),
        actor,
        rev: snapshot.policy.revision,
        min_enforce_rev: snapshot.policy.min_enforce_rev,
        digest: snapshot.digest.clone(),
        direct_grants: access.direct_grants,
        click_eligible: access.click_eligible,
        is_billing_waived: flags.is_billing_waived,
        caller_age_verified: flags.caller_age_verified,
        caller_terms_accepted: flags.caller_terms_accepted,
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
    let Some(email) = cfg.live_admin_email() else {
        return private_no_store(
            (StatusCode::FORBIDDEN, "Administrator access required").into_response(),
        );
    };

    let path = uri.path();
    let browse_entry = *method == Method::GET && path == "/admin/browse";
    let mut response = if browse_entry {
        Redirect::to("/").into_response()
    } else {
        let has_body = !matches!(*method, Method::GET | Method::HEAD);
        if has_body && body.len() > MAX_ADMIN_BODY_BYTES {
            return private_no_store(
                (StatusCode::PAYLOAD_TOO_LARGE, "Admin request body too large").into_response(),
            );
        }

        // Load KeyDomain::AdminAssertion lazily ONLY on the `/admin*` branch.
        let admin_assertion_secret = match backend.load_admin_assertion_secret() {
            Ok(secret) => secret,
            Err(err) => {
                log_backend_error("admin assertion secret unavailable", &err);
                return private_no_store(
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "admin assertion secret unavailable",
                    )
                        .into_response(),
                );
            }
        };

        let pq = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/admin")
            .to_string();
        if pq.len() > 2048 {
            return private_no_store(
                (StatusCode::URI_TOO_LONG, "Admin request URI too long").into_response(),
            );
        }
        let effective_body = if has_body { body } else { Bytes::new() };
        let bh = site_access::sha256_hex(&effective_body);
        let Ok(jti) = backend.random_hex_128() else {
            return private_no_store(
                (StatusCode::INTERNAL_SERVER_ERROR, "admin nonce failed").into_response(),
            );
        };

        let admin_assertion = AdminAssertionClaims {
            v: ADMIN_ASSERTION_VERSION,
            aud: ADMIN_ASSERTION_AUDIENCE.to_string(),
            email: email.to_string(),
            m: method.as_str().to_ascii_uppercase(),
            p: pq.clone(),
            bh,
            jti,
            exp: backend.now_secs().saturating_add(ADMIN_ASSERTION_TTL),
        };
        let Ok(signed_admin_assertion) =
            sign_admin_assertion(&admin_assertion, &admin_assertion_secret)
        else {
            return private_no_store(
                (StatusCode::INTERNAL_SERVER_ERROR, "admin assertion failed").into_response(),
            );
        };
        let req = ForwardedServiceReq {
            path_and_query: pq,
            method: worker_method,
            headers: build_service_headers(
                headers,
                ServiceTarget::AdminDashboard,
                Some((email, &signed_admin_assertion)),
                None,
            ),
            body: effective_body,
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
    is_billing_waived: bool,
    now: u64,
) -> Response {
    let Some((kind, id)) = parse_media_route(uri.path()) else {
        return private_no_store((StatusCode::NOT_FOUND, "Not Found").into_response());
    };
    // Fail closed BEFORE billing, origin calls, or upstream fetch when fixed server-side
    // preview blur is disabled, preventing `/media/preview/*` from ever leaking clear bytes.
    if kind == MediaCapKind::Preview && !snapshot.policy.fixed_blur_enabled {
        return private_no_store(
            (StatusCode::FORBIDDEN, "Server-side preview blur is disabled").into_response(),
        );
    }
    let Some(cap_token) = extract_media_cap_query(uri.query()) else {
        return private_no_store(
            (StatusCode::FORBIDDEN, "Missing or invalid media capability").into_response(),
        );
    };

    // Step 1: Strictly verify Policy v3 `MediaCapability` (`mc3.`, rejecting v1/v2!)
    // BEFORE billing, cache delivery, or upstream fetch on GET, HEAD, AND Range requests.
    let Ok(cap) = verify_media_capability(
        &cap_token,
        &cfg.media_cap_secret,
        MEDIA_CAP_AUDIENCE,
        kind,
        id,
        now,
        snapshot.policy.min_enforce_rev,
        snapshot.policy.revision,
    ) else {
        return private_no_store(
            (StatusCode::FORBIDDEN, "Invalid or expired media capability").into_response(),
        );
    };

    // Step 2: Resolve live caller session, ActorBinding, and PolicyAccessResult.
    let (auth, clear_cookie) = match resolve_live_session(backend, cfg, cookies, now).await {
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

    let live_admin_email = if clear_cookie {
        None
    } else {
        cfg.live_admin_email()
    };
    let guest_cookie = cookies.get(GUEST_SESSION_COOKIE);
    let live_actor = resolve_actor_binding(
        auth.as_ref(),
        clear_cookie,
        live_admin_email,
        guest_cookie.as_ref().map(|c| c.value()),
        &cfg.guest_session_secret,
        now,
    );
    let live_access = compute_policy_access(
        &snapshot.policy,
        &PolicyCallerContext {
            session: auth.as_ref().map(|l| l.ctx.clone()),
            session_revoked_or_invalid: clear_cookie,
            live_admin_email: live_admin_email.map(str::to_string),
            country: cfg.visitor_country.clone(),
        },
    );

    // Step 3: Fast pre-check actor & entitlement match BEFORE hitting origin `/internal/facts-rev`
    // or billing DO. If this fails, no `facts_rev` value could ever authorize the capability.
    if !authorize_media_capability_v3(
        &cap,
        &live_actor,
        &live_access,
        &snapshot.policy,
        Some(cap.facts_rev),
    ) {
        return maybe_clear_session_cookie(
            private_no_store((StatusCode::FORBIDDEN, "Media access denied").into_response()),
            clear_cookie,
        );
    }

    // Step 4: When `policy.safety_enabled == true`, query authoritative `facts_rev` from
    // `APP_ORIGIN/internal/facts-rev/{kind}/{id}` (applies to previously public `Anon` caps too!).
    if snapshot.policy.safety_enabled {
        let Ok(facts_url) = build_facts_rev_target(kind, id, &cfg.upstreams) else {
            return maybe_clear_session_cookie(
                private_no_store((StatusCode::FORBIDDEN, "Invalid media target").into_response()),
                clear_cookie,
            );
        };
        let Ok(signed_assertion) = sign_assertion_v3(
            cfg,
            snapshot,
            now,
            live_actor.clone(),
            live_access.clone(),
            caller_assertion_flags(auth.as_ref(), &snapshot.policy, is_billing_waived),
        ) else {
            return maybe_clear_session_cookie(assertion_sign_error_response(), clear_cookie);
        };
        let facts_req = UpstreamFetchReq {
            url: facts_url,
            method: worker::Method::Get,
            headers: build_facts_rev_headers(cfg, &signed_assertion),
            body: Bytes::new(),
            no_cache: true,
            preview_blur: None,
        };
        let current_facts_rev = match backend.fetch_facts_rev(facts_req).await {
            Ok((200, body_text)) => match parse_facts_rev_response(&body_text) {
                Ok(rev) => rev,
                Err(reason) => {
                    log_backend_error(
                        "invalid facts-rev response from origin",
                        &BackendError(reason.to_string()),
                    );
                    return maybe_clear_session_cookie(
                        private_no_store(
                            (StatusCode::SERVICE_UNAVAILABLE, "Media verification unavailable")
                                .into_response(),
                        ),
                        clear_cookie,
                    );
                }
            },
            Ok((404, _)) => {
                return maybe_clear_session_cookie(
                    private_no_store(
                        (StatusCode::FORBIDDEN, "Media asset unavailable").into_response(),
                    ),
                    clear_cookie,
                );
            }
            Ok((status, _)) => {
                log_backend_error(
                    "facts-rev lookup returned error status",
                    &BackendError(format!("HTTP {status}")),
                );
                return maybe_clear_session_cookie(
                    private_no_store(
                        (StatusCode::SERVICE_UNAVAILABLE, "Media verification unavailable")
                            .into_response(),
                    ),
                    clear_cookie,
                );
            }
            Err(err) => {
                log_backend_error("facts-rev origin lookup failed", &err);
                return maybe_clear_session_cookie(
                    private_no_store(
                        (StatusCode::SERVICE_UNAVAILABLE, "Media verification unavailable")
                            .into_response(),
                    ),
                    clear_cookie,
                );
            }
        };

        if !authorize_media_capability_v3(
            &cap,
            &live_actor,
            &live_access,
            &snapshot.policy,
            Some(current_facts_rev),
        ) {
            return maybe_clear_session_cookie(
                private_no_store((StatusCode::FORBIDDEN, "Media capability stale").into_response()),
                clear_cookie,
            );
        }
    }

    // Step 5: Validate canonical upstream URL BEFORE any billing check.
    let Ok(target_url) = build_media_upstream_target(kind, &cap.immutable_locator, &cfg.upstreams)
    else {
        return maybe_clear_session_cookie(
            private_no_store((StatusCode::FORBIDDEN, "Invalid media target").into_response()),
            clear_cookie,
        );
    };

    // Step 6: Billing / preview budget (ONLY after full authorization passes; waived by browse pass or live staff).
    if !is_billing_waived {
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

    // Step 7: Upstream media fetch with locked blur (for Preview), no shared cache,
    // manual redirects, and fail-closed transform verification.
    let preview_blur = resolve_preview_blur(kind, &snapshot.policy);
    if kind == MediaCapKind::Preview && preview_blur.is_none() {
        return maybe_clear_session_cookie(
            private_no_store(
                (StatusCode::FORBIDDEN, "Server-side preview blur is disabled").into_response(),
            ),
            clear_cookie,
        );
    }
    let fetch_req = UpstreamFetchReq {
        url: target_url,
        method: worker_method,
        headers: build_media_headers(kind, headers, cfg),
        body: Bytes::new(),
        no_cache: true,
        preview_blur,
    };

    let response = match backend.fetch_upstream(fetch_req).await {
        Ok(mut resp) => {
            if kind == MediaCapKind::Preview {
                // Fail closed (502) unless Cloudflare Images explicitly confirmed
                // transformation (`cf-resized: internal=ok...`) on a 200 OK response!
                if !is_verified_preview_transform_response(resp.status(), resp.headers()) {
                    private_no_store(
                        (StatusCode::BAD_GATEWAY, "Preview blur transform unavailable")
                            .into_response(),
                    )
                } else {
                    resp.headers_mut().remove("set-cookie");
                    private_no_store(resp)
                }
            } else if resp.status().is_redirection() {
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

#[allow(clippy::too_many_arguments)]
async fn forward_gallery_request(
    backend: &impl GatewayBackend,
    cfg: &GatewayConfig,
    snapshot: &SitePolicySnapshot,
    uri: &Uri,
    worker_method: worker::Method,
    headers: &HeaderMap,
    body: Bytes,
    now: u64,
    mut actor: ActorBinding,
    access: PolicyAccessResult,
    flags: AssertionFlags,
    is_reveal_route: bool,
    clear_cookie: bool,
    allow_public_cache: bool,
) -> Response {
    // On `POST /api/safety/reveal`, ensure guests without User/LiveAdmin/le_guest_sid
    // receive a freshly minted signed `le_guest_sid` cookie so reveal capabilities are
    // NEVER bound to `ActorBinding::Anon`.
    let mut minted_guest_cookie: Option<String> = None;
    if is_reveal_route && actor.is_anon() && !clear_cookie {
        let Ok(rand_hex) = backend.random_hex_128() else {
            return private_no_store(
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to mint guest session")
                    .into_response(),
            );
        };
        let gid = format!("gs_{rand_hex}");
        let guest_claims = GuestSessionToken {
            v: GUEST_SESSION_VERSION,
            gid: gid.clone(),
            iat: now,
            exp: now.saturating_add(GUEST_SESSION_TTL),
        };
        let Ok(signed_guest) = sign_guest_session(&guest_claims, &cfg.guest_session_secret) else {
            return private_no_store(
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to sign guest session")
                    .into_response(),
            );
        };
        actor = ActorBinding::GuestSession { gid };
        minted_guest_cookie = Some(guest_session_set_cookie_header(
            &signed_guest,
            is_https_request(uri),
        ));
    }

    let Ok(signed_assertion) = sign_assertion_v3(cfg, snapshot, now, actor, access, flags) else {
        return assertion_sign_error_response();
    };

    let mut resp = proxy_to_api(
        backend,
        cfg,
        uri,
        worker_method,
        headers,
        body,
        &signed_assertion,
        allow_public_cache && minted_guest_cookie.is_none(),
    )
    .await;

    if let Some(cookie_hdr) = minted_guest_cookie {
        resp.headers_mut().append(
            "set-cookie",
            cookie_hdr.parse().expect("ASCII le_guest_sid Set-Cookie"),
        );
        resp = private_no_store(resp);
    }
    resp
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

    // Load authoritative Policy v3 from singleton `SITE_POLICY` DO (fail closed!).
    let snapshot = match backend.load_site_policy().await {
        Ok(snapshot) => snapshot,
        Err(err) => {
            log_backend_error("SITE_POLICY unavailable", &err);
            return private_no_store(
                (StatusCode::SERVICE_UNAVAILABLE, "Policy service unavailable").into_response(),
            );
        }
    };

    // Step 0: Authoritative Geo Enforcement — runs BEFORE admin browse pass,
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

    // `/user/admin` & `/user/admin/*` retired unconditionally -> 404.
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
            headers: build_service_headers(
                &headers,
                ServiceTarget::UserWorker,
                None,
                cfg.visitor_country.as_deref(),
            ),
            body,
        };
        return match backend.forward_service(ServiceTarget::UserWorker, req).await {
            Ok(resp) => {
                // Preserve public Cache-Control on immutable/static `/user/assets/*` files
                // while forcing `private, no-store` on all auth/account/API responses.
                if matches!(method, Method::GET | Method::HEAD)
                    && is_segment_prefix(path, "/user/assets")
                    && resp.status().is_success()
                    && !resp.headers().contains_key("set-cookie")
                {
                    resp
                } else {
                    private_no_store(resp)
                }
            }
            Err(err) => {
                log_backend_error("lets-embed-user-worker fetch failed", &err);
                private_no_store(
                    (StatusCode::BAD_GATEWAY, "user service unavailable").into_response(),
                )
            }
        };
    }

    let now = backend.now_secs();
    let live_admin_email = cfg.live_admin_email();
    let admin_pass = cookies
        .get(ADMIN_VIEW_COOKIE)
        .is_some_and(|c| site_access::valid_admin_view(&cfg.jwt_secret, c.value(), now));
    // `ADMIN_VIEW_COOKIE` is STRICTLY limited to billing & guest login-wall waiver;
    // it NEVER populates `live_admin_email` or grants content bypass!
    let is_billing_waived = admin_pass || live_admin_email.is_some();

    // Capability-gated `/media/{image,video,preview}/{id}?cap=...` route.
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
            is_billing_waived,
            now,
        )
        .await;
    }

    let Some(worker_method) = checked_gallery_method(&method) else {
        return method_not_allowed(GALLERY_ALLOWED_METHODS);
    };

    // Block raw `/images/*`, `/videos/*`, and `/internal/*` unconditionally.
    if is_segment_prefix(path, "/images")
        || is_segment_prefix(path, "/videos")
        || is_segment_prefix(path, "/internal")
    {
        return private_no_store((StatusCode::NOT_FOUND, "Not Found").into_response());
    }

    // Always-public static/SEO/legal paths (`GET`/`HEAD`): `/robots.txt`,
    // `/favicon.ico`, `/terms`, `/privacy`, `/dmca`, `/content-policy`, `/pkg/*`.
    if matches!(method, Method::GET | Method::HEAD) && is_always_public_path(path) {
        let Ok(signed) = sign_assertion_v3(
            cfg,
            &snapshot,
            now,
            ActorBinding::Anon,
            PolicyAccessResult::default(),
            AssertionFlags::default(),
        ) else {
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
    let (auth, clear_cookie) = match resolve_live_session(backend, cfg, &cookies, now).await {
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

    let is_reveal_route = path == "/api/safety/reveal";
    if is_reveal_route && method != Method::POST {
        return maybe_clear_session_cookie(method_not_allowed("POST"), clear_cookie);
    }

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
    // (both metered and unmetered), for ALL callers including `ADMIN_VIEW_COOKIE`.
    if method == Method::POST && !is_same_origin(&uri, &headers) {
        return maybe_clear_session_cookie(
            private_no_store(
                (StatusCode::FORBIDDEN, "Cross-origin POST request rejected").into_response(),
            ),
            clear_cookie,
        );
    }

    // Additional CSRF & size defense on `POST /api/safety/reveal`.
    if is_reveal_route {
        if !has_reveal_csrf_header(&headers) {
            return maybe_clear_session_cookie(
                private_no_store(
                    (StatusCode::FORBIDDEN, "Missing X-Requested-With: fetch header")
                        .into_response(),
                ),
                clear_cookie,
            );
        }
        if body.len() > MAX_REVEAL_BODY_BYTES {
            return maybe_clear_session_cookie(
                private_no_store(
                    (StatusCode::PAYLOAD_TOO_LARGE, "Reveal request body too large")
                        .into_response(),
                ),
                clear_cookie,
            );
        }
    }

    let metered_post = method == Method::POST && item.is_some();

    // Compute live Policy v3 ActorBinding, PolicyAccessResult & caller verification flags.
    // Sitemaps are always projected strictly as the anonymous safe view.
    let effective_live_admin = if clear_cookie { None } else { live_admin_email };
    let (actor, access, assertion_flags) = if is_sitemap_path(path) {
        (
            ActorBinding::Anon,
            PolicyAccessResult::default(),
            AssertionFlags::default(),
        )
    } else {
        let guest_cookie = cookies.get(GUEST_SESSION_COOKIE);
        let resolved_actor = resolve_actor_binding(
            auth.as_ref(),
            clear_cookie,
            effective_live_admin,
            guest_cookie.as_ref().map(|c| c.value()),
            &cfg.guest_session_secret,
            now,
        );
        let resolved_access = compute_policy_access(
            &snapshot.policy,
            &PolicyCallerContext {
                session: auth.as_ref().map(|l| l.ctx.clone()),
                session_revoked_or_invalid: clear_cookie,
                live_admin_email: effective_live_admin.map(str::to_string),
                country: cfg.visitor_country.clone(),
            },
        );
        let flags = caller_assertion_flags(auth.as_ref(), &snapshot.policy, is_billing_waived);
        (resolved_actor, resolved_access, flags)
    };

    // Browse pass / live staff waives login wall & quota/payment metering ONLY —
    // geo, CSRF, Policy v3 access evaluation (with zero implicit auto-unlock), and
    // capability verification already executed above.
    if is_billing_waived {
        let resp = forward_gallery_request(
            backend,
            cfg,
            &snapshot,
            &uri,
            worker_method,
            &headers,
            body,
            now,
            actor,
            access,
            assertion_flags,
            is_reveal_route,
            clear_cookie,
            false,
        )
        .await;
        return maybe_clear_session_cookie(resp, clear_cookie);
    }

    let guest = auth.is_none();
    if metered_post {
        let Ok(signed_assertion) =
            sign_assertion_v3(cfg, &snapshot, now, actor, access, assertion_flags)
        else {
            return maybe_clear_session_cookie(assertion_sign_error_response(), clear_cookie);
        };
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
        let resp = forward_gallery_request(
            backend,
            cfg,
            &snapshot,
            &uri,
            worker_method,
            &headers,
            body,
            now,
            actor,
            access,
            assertion_flags,
            is_reveal_route,
            clear_cookie,
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
            forward_gallery_request(
                backend,
                cfg,
                &snapshot,
                &uri,
                worker_method,
                &headers,
                body,
                now,
                actor,
                access,
                assertion_flags,
                is_reveal_route,
                clear_cookie,
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
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context as TaskContext, Poll, Waker};

    use axum::http::header::CONTENT_TYPE;
    use site_access::{
        AgeGateTrigger, AgeVerificationPolicy, AssuranceLevel, ChargeKind, ContentPolicy,
        GeoPolicy, KeyDomain, LegacySessionClaims, MEDIA_CAP_VERSION, MediaBillingKey,
        MediaCapability, PlaceholderPreset, PolicyAction, PolicyBypass, PolicyRef,
        SESSION_V2_VERSION, SessionV2Claims, builtin_safety_presets, canonical_policy_json,
        derive_domain_secret, sign_legacy_session, sign_media_capability, sign_session_v2,
        verify_admin_assertion, verify_gateway_assertion, verify_guest_session,
    };

    use super::*;
    use crate::auth::ResolvedGatewaySecrets;
    use crate::http_util::{
        MeterError, form_field, parse_upstream_origin, require_form_urlencoded, sha256_hex,
    };
    use crate::media::{LOCKED_PREVIEW_BLUR, encode_canonical_cap_path};

    const TEST_NOW: u64 = 1_700_000_000;
    const TEST_SITE_SECRET: &str = "test-master-site-secret-at-least-32-bytes-long!!";
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

    fn test_resolved_secrets() -> ResolvedGatewaySecrets {
        resolve_gateway_secrets(&GatewaySecretInputs {
            site_secret: Some(TEST_SITE_SECRET),
            ..GatewaySecretInputs::default()
        })
        .expect("resolve from SITE_SECRET")
    }

    fn test_admin_secret() -> Vec<u8> {
        resolve_admin_assertion_secret(None, Some(TEST_SITE_SECRET))
            .expect("resolve AdminAssertion from SITE_SECRET")
    }

    fn test_cfg() -> GatewayConfig {
        let secrets = test_resolved_secrets();
        GatewayConfig {
            jwt_secret: Arc::new(secrets.jwt_secret),
            session_v2_secret: Arc::new(secrets.session_v2_secret),
            gateway_assertion_secret: Arc::new(secrets.gateway_assertion_secret),
            media_cap_secret: Arc::new(secrets.media_cap_secret),
            internal_api_secret: Arc::new(secrets.internal_api_secret),
            guest_session_secret: Arc::new(secrets.guest_session_secret),
            admin_email: None,
            admin_allowed_emails: None,
            visitor_country: Some("US".to_string()),
            cf_access_service_token: Some(Arc::new((
                "svc-id".to_string(),
                "svc-secret".to_string(),
            ))),
            upstreams: Arc::new(test_upstreams()),
        }
    }

    fn sample_safety_policy() -> PublicSitePolicy {
        let mut p = PublicSitePolicy {
            revision: 5,
            min_enforce_rev: 3,
            safety_enabled: true,
            fixed_blur_enabled: true,
            policies: builtin_safety_presets(),
            age_policy: AgeVerificationPolicy::SelfAttestation,
            age_gate_trigger: AgeGateTrigger::JustInTime,
            geo: GeoPolicy {
                blocked_countries: vec!["KP".to_string()],
                block_unknown: false,
                block_tor: true,
            },
            ..PublicSitePolicy::default()
        };
        // Enable require_age_18 on r18 for strict age testing
        p.policies[0].bypass.require_age_18 = true;
        p.refresh_policy_digest();
        p
    }

    fn policy_envelope_json(policy: &PublicSitePolicy) -> String {
        let mut cloned = policy.clone();
        cloned.refresh_policy_digest();
        let canonical = canonical_policy_json(&cloned);
        let digest = compute_policy_digest(&cloned);
        format!(r#"{{"policy":{canonical},"digest":"{digest}"}}"#)
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
        method: worker::Method,
        path_and_query: String,
        headers: Vec<(String, String)>,
        body: Bytes,
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
        rng_counter: Cell<u64>,
        admin_secret_result: std::result::Result<Vec<u8>, String>,
        admin_secret_loads: Cell<usize>,
        policy_envelope: std::result::Result<String, String>,
        session_contexts: HashMap<String, SessionContext>,
        account_statuses: HashMap<String, u16>,
        default_account_status: u16,
        reserve_hold_id: Option<String>,
        facts_rev_responses: HashMap<String, std::result::Result<(u16, String), String>>,
        default_facts_rev: std::result::Result<(u16, String), String>,
        upstream_status: StatusCode,
        upstream_cache_control: Option<&'static str>,
        upstream_set_cookie: Option<&'static str>,
        upstream_cf_resized: Option<&'static str>,
        account_calls: RefCell<Vec<RecordedAccountCall>>,
        session_calls: RefCell<Vec<(String, Option<String>)>>,
        service_calls: RefCell<Vec<RecordedServiceCall>>,
        upstream_calls: RefCell<Vec<RecordedUpstreamCall>>,
    }

    impl MockBackend {
        fn with_policy(policy: PublicSitePolicy) -> Self {
            let env_json = policy_envelope_json(&policy);
            Self {
                now: TEST_NOW,
                rng_counter: Cell::new(1),
                admin_secret_result: Ok(test_admin_secret()),
                admin_secret_loads: Cell::new(0),
                policy_envelope: Ok(env_json),
                session_contexts: HashMap::new(),
                account_statuses: HashMap::new(),
                default_account_status: 200,
                reserve_hold_id: Some("hold-1".to_string()),
                facts_rev_responses: HashMap::new(),
                default_facts_rev: Ok((200, r#"{"facts_rev":7}"#.to_string())),
                upstream_status: StatusCode::OK,
                upstream_cache_control: Some("public, max-age=3600"),
                upstream_set_cookie: None,
                upstream_cf_resized: Some("internal=ok/q=30 t=0.05"),
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

        fn random_hex_128(&self) -> std::result::Result<String, BackendError> {
            let n = self.rng_counter.get();
            self.rng_counter.set(n + 1);
            Ok(format!("{n:032x}"))
        }

        fn load_admin_assertion_secret(&self) -> std::result::Result<Vec<u8>, BackendError> {
            self.admin_secret_loads
                .set(self.admin_secret_loads.get() + 1);
            self.admin_secret_result
                .clone()
                .map_err(BackendError)
        }

        async fn load_site_policy(&self) -> std::result::Result<SitePolicySnapshot, BackendError> {
            match &self.policy_envelope {
                Ok(raw) => parse_site_policy_envelope_v3(raw).map_err(BackendError),
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
                method: req.method,
                path_and_query: req.path_and_query,
                headers: req.headers,
                body: req.body,
            });
            Ok((StatusCode::OK, "service ok").into_response())
        }

        async fn fetch_upstream(
            &self,
            req: UpstreamFetchReq,
        ) -> std::result::Result<Response, BackendError> {
            let is_preview = req.preview_blur.is_some();
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
            if is_preview && let Some(cf_resized) = self.upstream_cf_resized {
                resp.headers_mut()
                    .insert("cf-resized", cf_resized.parse().unwrap());
            }
            Ok(resp)
        }

        async fn fetch_facts_rev(
            &self,
            req: UpstreamFetchReq,
        ) -> std::result::Result<(u16, String), BackendError> {
            let path = req.url.path().to_string();
            self.upstream_calls.borrow_mut().push(RecordedUpstreamCall {
                url: req.url.to_string(),
                method: req.method,
                headers: req.headers,
                no_cache: req.no_cache,
                preview_blur: req.preview_blur,
            });
            let outcome = self
                .facts_rev_responses
                .get(&path)
                .unwrap_or(&self.default_facts_rev);
            outcome.clone().map_err(BackendError)
        }
    }

    fn cookies_from_headers(headers: &HeaderMap) -> Cookies {
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

    fn make_v2_cookie(cfg: &GatewayConfig, user_id: &str, do_key: &str, sid: &str) -> String {
        let tok = sign_session_v2(
            &SessionV2Claims {
                v: SESSION_V2_VERSION,
                sub: user_id.to_string(),
                do_key: do_key.to_string(),
                sid: sid.to_string(),
                iat: TEST_NOW - 60,
                exp: TEST_NOW + 3600,
            },
            &cfg.session_v2_secret,
        )
        .unwrap();
        format!("{SESSION_COOKIE}={tok}")
    }

    fn make_guest_cookie(cfg: &GatewayConfig, gid: &str) -> String {
        let tok = sign_guest_session(
            &GuestSessionToken {
                v: GUEST_SESSION_VERSION,
                gid: gid.to_string(),
                iat: TEST_NOW - 10,
                exp: TEST_NOW + 3600,
            },
            &cfg.guest_session_secret,
        )
        .unwrap();
        format!("{GUEST_SESSION_COOKIE}={tok}")
    }

    fn make_admin_view_cookie(cfg: &GatewayConfig) -> String {
        let pass = site_access::admin_view_pass(&cfg.jwt_secret, TEST_NOW + site_access::VIEW_TTL);
        format!("{ADMIN_VIEW_COOKIE}={pass}")
    }

    fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    // -----------------------------------------------------------------------
    // 1. HKDF Master Secret (`SITE_SECRET`) & Lazy AdminAssertion Key Loading
    // -----------------------------------------------------------------------

    #[test]
    fn site_secret_hkdf_derives_distinct_domain_keys_and_honors_overrides() {
        let derived = resolve_gateway_secrets(&GatewaySecretInputs {
            site_secret: Some(TEST_SITE_SECRET),
            ..GatewaySecretInputs::default()
        })
        .expect("SITE_SECRET alone must resolve all non-admin domains");

        assert_eq!(
            derived.jwt_secret,
            derive_domain_secret(TEST_SITE_SECRET, KeyDomain::Session).into_bytes()
        );
        assert_eq!(
            derived.session_v2_secret,
            derive_domain_secret(TEST_SITE_SECRET, KeyDomain::Session).into_bytes()
        );
        assert_eq!(
            derived.media_cap_secret,
            derive_domain_secret(TEST_SITE_SECRET, KeyDomain::MediaCap).into_bytes()
        );
        assert_eq!(
            derived.gateway_assertion_secret,
            derive_domain_secret(TEST_SITE_SECRET, KeyDomain::GatewayAssertion).into_bytes()
        );
        assert_eq!(
            derived.internal_api_secret,
            derive_domain_secret(TEST_SITE_SECRET, KeyDomain::InternalApi).into_bytes()
        );
        assert_eq!(
            derived.guest_session_secret,
            derive_domain_secret(TEST_SITE_SECRET, KeyDomain::GuestSession).into_bytes()
        );
        // All distinct domains derive distinct secrets
        assert_ne!(derived.session_v2_secret, derived.media_cap_secret);
        assert_ne!(derived.media_cap_secret, derived.gateway_assertion_secret);
        assert_ne!(derived.gateway_assertion_secret, derived.internal_api_secret);
        assert_ne!(derived.internal_api_secret, derived.guest_session_secret);

        let admin_derived = resolve_admin_assertion_secret(None, Some(TEST_SITE_SECRET)).unwrap();
        assert_eq!(
            admin_derived,
            derive_domain_secret(TEST_SITE_SECRET, KeyDomain::AdminAssertion).into_bytes()
        );
        assert_ne!(admin_derived, derived.gateway_assertion_secret);

        // Explicit per-purpose overrides win over SITE_SECRET
        let overridden = resolve_gateway_secrets(&GatewaySecretInputs {
            site_secret: Some(TEST_SITE_SECRET),
            session_v2_secret: Some("override-sess-v2"),
            media_cap_secret: Some("override-media"),
            gateway_assertion_secret: Some("override-gw"),
            internal_api_secret: Some("override-internal"),
            guest_session_secret: Some("override-guest"),
            jwt_secret: Some("override-jwt"),
            session_secret: None,
        })
        .unwrap();
        assert_eq!(overridden.jwt_secret, b"override-jwt");
        assert_eq!(overridden.session_v2_secret, b"override-sess-v2");
        assert_eq!(overridden.media_cap_secret, b"override-media");
        assert_eq!(overridden.gateway_assertion_secret, b"override-gw");
        assert_eq!(overridden.internal_api_secret, b"override-internal");
        assert_eq!(overridden.guest_session_secret, b"override-guest");
        assert_eq!(
            resolve_admin_assertion_secret(Some("override-admin"), Some(TEST_SITE_SECRET)).unwrap(),
            b"override-admin"
        );

        // Missing both SITE_SECRET and overrides fails closed
        assert!(resolve_gateway_secrets(&GatewaySecretInputs::default()).is_err());
        assert!(resolve_admin_assertion_secret(None, None).is_err());

        // Lazy AdminAssertion loading: gallery routes NEVER touch admin_assertion_secret!
        let mut backend = MockBackend::with_policy(sample_safety_policy());
        backend.admin_secret_result = Err("ADMIN_ASSERTION_SECRET missing".to_string());
        let mut cfg = test_cfg();
        let gallery_resp = dispatch(&backend, &cfg, Method::GET, "/", HeaderMap::new(), Bytes::new());
        assert_eq!(gallery_resp.status(), StatusCode::OK);
        assert_eq!(
            backend.admin_secret_loads.get(),
            0,
            "gallery traffic must NEVER load AdminAssertion secret"
        );

        // `/admin` DOES load AdminAssertion lazily and fails closed (500) if missing!
        cfg.admin_email = Some("ops@gallery.test".to_string());
        let admin_resp = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "/admin/api/settings",
            HeaderMap::new(),
            Bytes::new(),
        );
        assert_eq!(admin_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(backend.admin_secret_loads.get(), 1);
    }

    // -----------------------------------------------------------------------
    // 2. Zero Implicit Admin Auto-Unlock, ADMIN_ALLOWED_EMAILS & Browse-Pass Isolation
    // -----------------------------------------------------------------------

    #[test]
    fn zero_implicit_admin_auto_unlock_and_browse_pass_isolation() {
        let mut policy = sample_safety_policy();
        // Add an explicit `include_live_admin: true` policy to distinguish browse pass vs live staff
        policy.policies.push(ContentPolicy {
            id: "staff_bypass".into(),
            grant_generation: 1,
            enabled: true,
            priority: 40,
            name: "Staff Bypass".into(),
            preset: PlaceholderPreset::Custom,
            match_expr: "tag:blood".into(),
            except_expr: None,
            default_tag_min: 0.45,
            action: PolicyAction::Block,
            bypass: PolicyBypass {
                include_live_admin: true,
                ..PolicyBypass::default()
            },
        });
        policy.refresh_policy_digest();

        let mut backend = MockBackend::with_policy(policy.clone());
        backend.account_statuses.insert("guest".to_string(), 401);
        let mut cfg = test_cfg();

        // 1. ADMIN_VIEW_COOKIE (browse pass) waives guest wall & billing (`is_billing_waived: true`),
        //    but grants ZERO `direct_grants` and NEVER sets `ActorBinding::LiveAdmin`!
        let mut h = HeaderMap::new();
        h.insert("cookie", make_admin_view_cookie(&cfg).parse().unwrap());
        let resp = dispatch(&backend, &cfg, Method::GET, "/", h, Bytes::new());
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(backend.account_calls.borrow().is_empty(), "browse pass waives guest DO call");
        {
            let up = backend.upstream_calls.borrow();
            let raw = header_value(&up[0].headers, GATEWAY_ASSERTION_HEADER).unwrap();
            let ga = verify_gateway_assertion(
                raw,
                &cfg.gateway_assertion_secret,
                GATEWAY_ASSERTION_AUDIENCE,
                TEST_NOW,
                5,
            )
            .unwrap();
            assert!(ga.is_billing_waived);
            assert_eq!(ga.actor, ActorBinding::Anon);
            assert!(
                ga.direct_grants.is_empty(),
                "ADMIN_VIEW_COOKIE MUST NOT grant ANY direct_grants (not even include_live_admin!)"
            );
            assert_eq!(ga.click_eligible, vec![PolicyRef::new("sensitive", 1)]);
        }

        // 2. Live CF Access staff identity (without gallery session):
        //    - Gets `ActorBinding::LiveAdmin { email }`
        //    - Grants ONLY `staff_bypass` (explicit `include_live_admin: true`),
        //      and NEVER implicitly unlocks `r18` or `blood` (`include_live_admin: false`)!
        backend.upstream_calls.borrow_mut().clear();
        cfg.admin_email = Some("Staff@Gallery.Test".to_string());
        let resp2 = dispatch(&backend, &cfg, Method::GET, "/", HeaderMap::new(), Bytes::new());
        assert_eq!(resp2.status(), StatusCode::OK);
        {
            let up = backend.upstream_calls.borrow();
            let raw = header_value(&up[0].headers, GATEWAY_ASSERTION_HEADER).unwrap();
            let ga = verify_gateway_assertion(
                raw,
                &cfg.gateway_assertion_secret,
                GATEWAY_ASSERTION_AUDIENCE,
                TEST_NOW,
                5,
            )
            .unwrap();
            assert!(ga.is_billing_waived);
            assert_eq!(
                ga.actor,
                ActorBinding::LiveAdmin {
                    email: "Staff@Gallery.Test".into()
                }
            );
            assert_eq!(ga.direct_grants, vec![PolicyRef::new("staff_bypass", 1)]);
            assert!(!ga.direct_grants.contains(&PolicyRef::new("r18", 1)));
            assert!(!ga.direct_grants.contains(&PolicyRef::new("blood", 1)));
        }
    }

    #[test]
    fn admin_allowed_emails_restricts_admin_routes_and_live_admin_email() {
        let mut policy = sample_safety_policy();
        policy.policies[2].bypass.include_live_admin = true;
        policy.refresh_policy_digest();

        let backend = MockBackend::with_policy(policy);
        let mut cfg = test_cfg();
        cfg.admin_allowed_emails = parse_admin_allowed_emails(Some(
            "  Alice@Gallery.Test , bob@gallery.test ",
        ))
        .map(Arc::new);

        // Malformed non-empty allowlist (e.g. ",,,") fails closed!
        assert_eq!(
            filter_allowed_admin_email(
                Some("alice@gallery.test"),
                parse_admin_allowed_emails(Some(",,,")).as_deref()
            ),
            None
        );

        // Non-listed CF Access email -> rejected (403) on `/admin` AND denied `live_admin_email`!
        cfg.admin_email = Some("eve@gallery.test".to_string());
        assert_eq!(cfg.live_admin_email(), None);
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, "/admin", HeaderMap::new(), Bytes::new()).status(),
            StatusCode::FORBIDDEN
        );
        let r_gallery = dispatch(&backend, &cfg, Method::GET, "/", HeaderMap::new(), Bytes::new());
        assert_eq!(r_gallery.status(), StatusCode::OK);
        {
            let up = backend.upstream_calls.borrow();
            let raw = header_value(&up[0].headers, GATEWAY_ASSERTION_HEADER).unwrap();
            let ga = verify_gateway_assertion(
                raw,
                &cfg.gateway_assertion_secret,
                GATEWAY_ASSERTION_AUDIENCE,
                TEST_NOW,
                5,
            )
            .unwrap();
            assert_eq!(ga.actor, ActorBinding::Anon);
            assert!(!ga.is_billing_waived);
            assert!(ga.direct_grants.is_empty());
        }

        // Case-insensitive match in `ADMIN_ALLOWED_EMAILS` -> allowed on `/admin` AND `LiveAdmin`!
        cfg.admin_email = Some("ALICE@gallery.test".to_string());
        assert_eq!(cfg.live_admin_email(), Some("ALICE@gallery.test"));
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, "/admin", HeaderMap::new(), Bytes::new()).status(),
            StatusCode::OK
        );
        backend.upstream_calls.borrow_mut().clear();
        let r_staff = dispatch(&backend, &cfg, Method::GET, "/", HeaderMap::new(), Bytes::new());
        assert_eq!(r_staff.status(), StatusCode::OK);
        let up = backend.upstream_calls.borrow();
        let raw = header_value(&up[0].headers, GATEWAY_ASSERTION_HEADER).unwrap();
        let ga = verify_gateway_assertion(
            raw,
            &cfg.gateway_assertion_secret,
            GATEWAY_ASSERTION_AUDIENCE,
            TEST_NOW,
            5,
        )
        .unwrap();
        assert_eq!(
            ga.actor,
            ActorBinding::LiveAdmin {
                email: "ALICE@gallery.test".into()
            }
        );
        assert_eq!(ga.direct_grants, vec![PolicyRef::new("blood", 1)]);
    }

    // -----------------------------------------------------------------------
    // 3. Strict Policy v3 Decoding, Geo-Block & `/internal/*` Protection
    // -----------------------------------------------------------------------

    #[test]
    fn site_policy_rejects_legacy_schema_rules_malformed_and_bad_digest_fail_closed() {
        let cfg = test_cfg();

        let bad_envelopes = [
            // Missing schema_version + legacy rules
            r#"{"policy":{"revision":1,"safety_enabled":true,"rules":[]},"digest":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
            // schema_version: 2
            r#"{"policy":{"schema_version":2,"revision":1,"safety_enabled":true},"digest":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
            // Tampered envelope digest
            &policy_envelope_json(&sample_safety_policy())
                .replace(&compute_policy_digest(&sample_safety_policy()), &"0".repeat(64)),
            // Malformed JSON
            "not-json",
        ];

        for raw in bad_envelopes {
            let mut backend = MockBackend::with_policy(sample_safety_policy());
            backend.policy_envelope = Ok(raw.to_string());
            let resp = dispatch(&backend, &cfg, Method::GET, "/", HeaderMap::new(), Bytes::new());
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                resp.headers().get("cache-control").unwrap(),
                "private, no-store"
            );
        }
    }

    #[test]
    fn geo_block_enforces_cf_country_ignores_spoofed_header_and_exempts_admin() {
        let mut policy = sample_safety_policy();
        policy.geo = GeoPolicy {
            blocked_countries: vec!["KP".to_string()],
            block_unknown: true,
            block_tor: true,
        };
        policy.refresh_policy_digest();
        let backend = MockBackend::with_policy(policy);

        let mut cfg = test_cfg();
        cfg.visitor_country = Some("KP".to_string());
        let mut hdrs = HeaderMap::new();
        hdrs.insert("cf-ipcountry", "US".parse().unwrap());
        hdrs.insert("cookie", make_admin_view_cookie(&cfg).parse().unwrap());
        let resp = dispatch(&backend, &cfg, Method::GET, "/", hdrs, Bytes::new());
        assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "private, no-store"
        );
        assert!(backend.upstream_calls.borrow().is_empty());

        for country in [Some("T1"), Some("XX"), None] {
            cfg.visitor_country = country.map(str::to_string);
            let mut h = HeaderMap::new();
            h.insert("cf-ipcountry", "US".parse().unwrap());
            let r = dispatch(&backend, &cfg, Method::GET, "/robots.txt", h, Bytes::new());
            assert_eq!(r.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        }

        // `/admin` exempt from geo-block
        cfg.visitor_country = Some("KP".to_string());
        cfg.admin_email = Some("ops@gallery.test".to_string());
        let admin_resp =
            dispatch(&backend, &cfg, Method::GET, "/admin", HeaderMap::new(), Bytes::new());
        assert_eq!(admin_resp.status(), StatusCode::OK);
    }

    #[test]
    fn raw_images_videos_and_internal_routes_blocked_with_404() {
        let backend = MockBackend::with_policy(sample_safety_policy());
        let mut cfg = test_cfg();
        cfg.admin_email = Some("ops@gallery.test".to_string());

        for (m, p) in [
            (Method::GET, "/images/a.webp"),
            (Method::GET, "/videos/clip.mp4"),
            (Method::GET, "/internal/facts-rev/image/42"),
            (Method::POST, "/internal/validate-safety-catalog"),
            (Method::GET, "/user/admin"),
            (Method::POST, "/user/admin/settings"),
        ] {
            let mut h = HeaderMap::new();
            h.insert("cookie", make_admin_view_cookie(&cfg).parse().unwrap());
            let r = dispatch(&backend, &cfg, m, p, h, Bytes::new());
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "must 404 {p}");
            assert_eq!(
                r.headers().get("cache-control").unwrap(),
                "private, no-store"
            );
        }
        assert!(backend.upstream_calls.borrow().is_empty());
    }

    // -----------------------------------------------------------------------
    // 4. `POST /api/safety/reveal` CSRF & `le_guest_sid` Minting
    // -----------------------------------------------------------------------

    #[test]
    fn safety_reveal_enforces_csrf_mints_guest_session_and_reuses_existing_cookie() {
        let policy = sample_safety_policy();
        let mut backend = MockBackend::with_policy(policy);
        backend.account_statuses.insert("guest".to_string(), 200);
        let cfg = test_cfg();

        let body = Bytes::from_static(br#"{"kind":"image","asset_id":42,"policy_rev":5}"#);

        // 1. Missing Origin -> 403
        let mut no_origin = HeaderMap::new();
        no_origin.insert("x-requested-with", "fetch".parse().unwrap());
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::POST,
                "https://gallery.test/api/safety/reveal",
                no_origin,
                body.clone(),
            )
            .status(),
            StatusCode::FORBIDDEN
        );

        // 2. Missing X-Requested-With: fetch -> 403
        let mut no_xrw = HeaderMap::new();
        no_xrw.insert("origin", "https://gallery.test".parse().unwrap());
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::POST,
                "https://gallery.test/api/safety/reveal",
                no_xrw,
                body.clone(),
            )
            .status(),
            StatusCode::FORBIDDEN
        );

        // 3. GET /api/safety/reveal -> 405
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                "https://gallery.test/api/safety/reveal",
                HeaderMap::new(),
                Bytes::new(),
            )
            .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert!(backend.upstream_calls.borrow().is_empty());

        // 4. Valid guest POST /api/safety/reveal without le_guest_sid (even with spoofed X-Forwarded-Proto: http!):
        //    mints fresh le_guest_sid, passes ActorBinding::GuestSession in ga3., sets HttpOnly Secure cookie,
        //    and ignores untrusted X-Forwarded-Proto: http (forwards x-forwarded-proto: https)!
        let mut ok_hdrs = HeaderMap::new();
        ok_hdrs.insert("origin", "https://gallery.test".parse().unwrap());
        ok_hdrs.insert("x-requested-with", "fetch".parse().unwrap());
        ok_hdrs.insert("x-forwarded-proto", "http".parse().unwrap());
        let resp = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/safety/reveal",
            ok_hdrs.clone(),
            body.clone(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("cache-control").unwrap(), "private, no-store");
        let sc = resp
            .headers()
            .get("set-cookie")
            .expect("must set le_guest_sid")
            .to_str()
            .unwrap();
        assert!(sc.starts_with("le_guest_sid=gs1."));
        assert!(sc.contains("HttpOnly"));
        assert!(sc.contains("SameSite=Lax"));
        assert!(sc.contains("Path=/"));
        assert!(sc.contains("Secure"));

        let cookie_pair = sc.split(';').next().unwrap();
        let raw_guest_tok = cookie_pair.strip_prefix("le_guest_sid=").unwrap();
        let verified_guest =
            verify_guest_session(raw_guest_tok, &cfg.guest_session_secret, TEST_NOW).unwrap();

        {
            let up = backend.upstream_calls.borrow();
            assert_eq!(up.len(), 1);
            assert_eq!(
                header_value(&up[0].headers, "x-forwarded-proto"),
                Some("https"),
                "untrusted X-Forwarded-Proto: http on HTTPS request must never spoof forwarded proto"
            );
            let ga = verify_gateway_assertion(
                header_value(&up[0].headers, GATEWAY_ASSERTION_HEADER).unwrap(),
                &cfg.gateway_assertion_secret,
                GATEWAY_ASSERTION_AUDIENCE,
                TEST_NOW,
                5,
            )
            .unwrap();
            assert_eq!(
                ga.actor,
                ActorBinding::GuestSession {
                    gid: verified_guest.gid.clone()
                }
            );
            assert!(ga.direct_grants.is_empty());
            assert_eq!(ga.click_eligible, vec![PolicyRef::new("sensitive", 1)]);
        }

        // 5. Subsequent reveal with existing valid `le_guest_sid` reuses same gid and does NOT re-mint Set-Cookie
        backend.upstream_calls.borrow_mut().clear();
        ok_hdrs.insert("cookie", cookie_pair.parse().unwrap());
        let resp2 = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/safety/reveal",
            ok_hdrs,
            body,
        );
        assert_eq!(resp2.status(), StatusCode::OK);
        assert!(resp2.headers().get("set-cookie").is_none());
        let up = backend.upstream_calls.borrow();
        let ga2 = verify_gateway_assertion(
            header_value(&up[0].headers, GATEWAY_ASSERTION_HEADER).unwrap(),
            &cfg.gateway_assertion_secret,
            GATEWAY_ASSERTION_AUDIENCE,
            TEST_NOW,
            5,
        )
        .unwrap();
        assert_eq!(
            ga2.actor,
            ActorBinding::GuestSession {
                gid: verified_guest.gid
            }
        );
        // le_guest_sid must be stripped from forwarded Cookie header to APP_ORIGIN
        assert_eq!(header_value(&up[0].headers, "cookie"), None);
    }

    // -----------------------------------------------------------------------
    // 5. MediaCapability v3 Redemption, `facts_rev`, `revealed_refs`, and Preview Blur
    // -----------------------------------------------------------------------

    #[test]
    fn media_cap_v3_rejects_v1_and_enforces_facts_rev_even_on_anon_caps_and_range() {
        let policy = sample_safety_policy();
        let mut backend = MockBackend::with_policy(policy);
        let cfg = test_cfg();

        // 1. Reject legacy v1 token BEFORE any origin or DO call
        let legacy_v1 = "eyJ2IjoxLCJraW5kIjoiaW1hZ2UiLCJpZCI6NDJ9.fake_sig";
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/image/42?cap={legacy_v1}"),
                HeaderMap::new(),
                Bytes::new(),
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        assert!(backend.upstream_calls.borrow().is_empty());
        assert!(backend.account_calls.borrow().is_empty());

        // 2. Public Anon cap (matched_blocks=[], matched_blurs=[]):
        //    STILL queries `/internal/facts-rev/image/42` when safety_enabled == true!
        let anon_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            aud: MEDIA_CAP_AUDIENCE.into(),
            kind: MediaCapKind::Image,
            asset_id: 42,
            immutable_locator: "2026/01/pic_42.webp".into(),
            facts_rev: 7,
            policy_rev: 5,
            actor_binding: ActorBinding::Anon,
            matched_blocks: vec![],
            matched_blurs: vec![],
            revealed_refs: vec![],
            exp: TEST_NOW + 300,
        };
        let anon_tok = sign_media_capability(&anon_cap, &cfg.media_cap_secret).unwrap();

        // 2a. facts_rev mismatch (8 != 7) on Anon cap (even with Range header!) -> 403, ZERO billing!
        backend.default_facts_rev = Ok((200, r#"{"facts_rev":8}"#.to_string()));
        let mut range_hdrs = HeaderMap::new();
        range_hdrs.insert("range", "bytes=0-1023".parse().unwrap());
        let stale_resp = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/image/42?cap={anon_tok}"),
            range_hdrs.clone(),
            Bytes::new(),
        );
        assert_eq!(stale_resp.status(), StatusCode::FORBIDDEN);
        assert!(backend.account_calls.borrow().is_empty());
        {
            let up = backend.upstream_calls.borrow();
            assert_eq!(up.len(), 1);
            assert_eq!(up[0].method, worker::Method::Get);
            assert!(up[0].no_cache);
            assert_eq!(
                up[0].url,
                "https://api.gallery.test/internal/facts-rev/image/42"
            );
            // Verify facts-rev request carries valid ga3. X-Gateway-Assertion + CF Access service token
            assert!(
                header_value(&up[0].headers, GATEWAY_ASSERTION_HEADER)
                    .unwrap()
                    .starts_with("ga3.")
            );
            assert_eq!(header_value(&up[0].headers, "cf-access-client-id"), Some("svc-id"));
        }

        // 2b. Origin 404 on facts-rev -> 403
        backend.default_facts_rev = Ok((404, String::new()));
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::HEAD,
                &format!("/media/image/42?cap={anon_tok}"),
                HeaderMap::new(),
                Bytes::new(),
            )
            .status(),
            StatusCode::FORBIDDEN
        );

        // 2c. Origin 500 or transport error on facts-rev -> fail closed 503
        backend.default_facts_rev = Ok((500, String::new()));
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/image/42?cap={anon_tok}"),
                HeaderMap::new(),
                Bytes::new(),
            )
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        backend.default_facts_rev = Err("timeout".to_string());
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/image/42?cap={anon_tok}"),
                HeaderMap::new(),
                Bytes::new(),
            )
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(backend.account_calls.borrow().is_empty());

        // 2d. Matching facts_rev == 7 -> 200 OK with Range forwarded and private, no-store!
        backend.default_facts_rev = Ok((200, r#"{"facts_rev":7}"#.to_string()));
        backend.upstream_calls.borrow_mut().clear();
        let ok = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/image/42?cap={anon_tok}"),
            range_hdrs,
            Bytes::new(),
        );
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(ok.headers().get("cache-control").unwrap(), "private, no-store");
        assert_eq!(backend.account_calls.borrow().len(), 1);
        assert_eq!(backend.upstream_calls.borrow().len(), 2);
        assert_eq!(
            backend.upstream_calls.borrow()[1].url,
            "https://image.gallery.test/2026/01/pic_42.webp"
        );
        assert_eq!(
            header_value(&backend.upstream_calls.borrow()[1].headers, "range"),
            Some("bytes=0-1023")
        );
    }

    #[test]
    fn media_cap_v3_enforces_revealed_refs_intersect_live_click_eligible_and_preview_fail_closed() {
        let mut policy = sample_safety_policy();
        policy.policies[1].bypass.exclude_countries = vec!["GB".into()];
        policy.refresh_policy_digest();

        let mut backend = MockBackend::with_policy(policy.clone());
        let mut cfg = test_cfg();

        let gid = "gs_0123456789abcdef0123456789abcdef";
        let blur_ref = PolicyRef::new("sensitive", 1);
        let revealed_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            aud: MEDIA_CAP_AUDIENCE.into(),
            kind: MediaCapKind::Image,
            asset_id: 88,
            immutable_locator: "2026/01/blur_88.webp".into(),
            facts_rev: 7,
            policy_rev: 5,
            actor_binding: ActorBinding::GuestSession { gid: gid.into() },
            matched_blocks: vec![],
            matched_blurs: vec![blur_ref.clone()],
            revealed_refs: vec![blur_ref.clone()],
            exp: TEST_NOW + 600,
        };
        let tok = sign_media_capability(&revealed_cap, &cfg.media_cap_secret).unwrap();

        let mut guest_hdrs = HeaderMap::new();
        guest_hdrs.insert("cookie", make_guest_cookie(&cfg, gid).parse().unwrap());

        // 1. Country US + matching le_guest_sid + facts_rev 7 -> 200 OK
        let ok = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/image/88?cap={tok}"),
            guest_hdrs.clone(),
            Bytes::new(),
        );
        assert_eq!(ok.status(), StatusCode::OK);

        // 2. Country switches to excluded GB -> `live_click_eligible` no longer contains `sensitive@1`
        //    -> previously minted revealed cap IMMEDIATELY DENIED (403, ZERO billing)!
        backend.account_calls.borrow_mut().clear();
        cfg.visitor_country = Some("GB".into());
        let geo_denied = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/image/88?cap={tok}"),
            guest_hdrs.clone(),
            Bytes::new(),
        );
        assert_eq!(geo_denied.status(), StatusCode::FORBIDDEN);
        assert!(backend.account_calls.borrow().is_empty());

        // 3. Different guest session cookie -> actor mismatch -> 403
        cfg.visitor_country = Some("US".into());
        let mut other_guest = HeaderMap::new();
        other_guest.insert(
            "cookie",
            make_guest_cookie(&cfg, "gs_ffffffffffffffffffffffffffffffff")
                .parse()
                .unwrap(),
        );
        assert_eq!(
            dispatch(
                &backend,
                &cfg,
                Method::GET,
                &format!("/media/image/88?cap={tok}"),
                other_guest,
                Bytes::new(),
            )
            .status(),
            StatusCode::FORBIDDEN
        );

        // 4. Preview capability checks:
        let preview_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            aud: MEDIA_CAP_AUDIENCE.into(),
            kind: MediaCapKind::Preview,
            asset_id: 88,
            immutable_locator: "2026/01/blur_88.webp".into(),
            facts_rev: 7,
            policy_rev: 5,
            actor_binding: ActorBinding::GuestSession { gid: gid.into() },
            matched_blocks: vec![],
            matched_blurs: vec![blur_ref],
            revealed_refs: vec![],
            exp: TEST_NOW + 600,
        };
        let ptok = sign_media_capability(&preview_cap, &cfg.media_cap_secret).unwrap();

        // 4a. With fixed_blur_enabled == true and cf-resized: internal=ok -> 200 OK, locked blur,
        //     Range/If-Range and conditional validator headers stripped!
        backend.upstream_calls.borrow_mut().clear();
        let mut preview_hdrs = guest_hdrs.clone();
        preview_hdrs.insert("range", "bytes=0-100".parse().unwrap());
        preview_hdrs.insert("if-range", "\"etag-1\"".parse().unwrap());
        preview_hdrs.insert("if-none-match", "\"etag-1\"".parse().unwrap());
        preview_hdrs.insert(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        preview_hdrs.insert("if-match", "\"etag-1\"".parse().unwrap());
        preview_hdrs.insert(
            "if-unmodified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        preview_hdrs.insert("accept", "image/webp,*/*".parse().unwrap());
        let p_ok = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/preview/88?cap={ptok}&blur=0"),
            preview_hdrs,
            Bytes::new(),
        );
        assert_eq!(p_ok.status(), StatusCode::OK);
        {
            let up = backend.upstream_calls.borrow();
            // Preview queries /internal/facts-rev/image/88 (NOT /preview/88!)
            assert_eq!(up[0].url, "https://api.gallery.test/internal/facts-rev/image/88");
            assert_eq!(up[1].preview_blur, Some(LOCKED_PREVIEW_BLUR));
            for stripped in [
                "range",
                "if-range",
                "if-none-match",
                "if-modified-since",
                "if-match",
                "if-unmodified-since",
            ] {
                assert_eq!(
                    header_value(&up[1].headers, stripped),
                    None,
                    "Preview must strip {stripped}"
                );
            }
            assert_eq!(
                header_value(&up[1].headers, "accept"),
                Some("image/webp,*/*")
            );
        }

        // 4b. Transform unavailable (missing cf-resized) or error (`err=9524`) -> 502 Bad Gateway!
        backend.upstream_cf_resized = None;
        let p_no_hdr = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/preview/88?cap={ptok}"),
            guest_hdrs.clone(),
            Bytes::new(),
        );
        assert_eq!(p_no_hdr.status(), StatusCode::BAD_GATEWAY);

        backend.upstream_cf_resized = Some("err=9524");
        let p_err = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/preview/88?cap={ptok}"),
            guest_hdrs.clone(),
            Bytes::new(),
        );
        assert_eq!(p_err.status(), StatusCode::BAD_GATEWAY);

        // 4c. When fixed_blur_enabled == false -> immediate 403 with ZERO origin/DO calls!
        policy.fixed_blur_enabled = false;
        policy.refresh_policy_digest();
        backend.policy_envelope = Ok(policy_envelope_json(&policy));
        backend.account_calls.borrow_mut().clear();
        backend.upstream_calls.borrow_mut().clear();
        let p_disabled = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/preview/88?cap={ptok}"),
            guest_hdrs,
            Bytes::new(),
        );
        assert_eq!(p_disabled.status(), StatusCode::FORBIDDEN);
        assert!(backend.account_calls.borrow().is_empty());
        assert!(backend.upstream_calls.borrow().is_empty());
    }

    // -----------------------------------------------------------------------
    // 6. AdminAssertion v2 Signing & Method/Target/Body-Hash/Nonce Binding
    // -----------------------------------------------------------------------

    #[test]
    fn admin_route_signs_v2_assertion_bound_to_method_target_body_hash_and_unique_jti() {
        let backend = MockBackend::with_policy(sample_safety_policy());
        let mut cfg = test_cfg();
        cfg.admin_email = Some("ops@gallery.test".to_string());

        let body = Bytes::from_static(br#"{"safety_enabled":true,"revision":6}"#);
        let mut hdrs = HeaderMap::new();
        // Client attempts to smuggle spoofed admin assertion — must be stripped & replaced with single valid aa2.!
        hdrs.insert(ADMIN_ASSERTION_HEADER, "aa2.forged.sig".parse().unwrap());
        hdrs.insert("content-type", "application/json".parse().unwrap());

        let r1 = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "/admin/api/policy?draft=1",
            hdrs.clone(),
            body.clone(),
        );
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "/admin/api/policy?draft=1",
            hdrs,
            body.clone(),
        );
        assert_eq!(r2.status(), StatusCode::OK);

        let aa1 = {
            let calls = backend.service_calls.borrow();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].target, ServiceTarget::AdminDashboard);
            assert_eq!(calls[0].method, worker::Method::Post);
            assert_eq!(calls[0].path_and_query, "/admin/api/policy?draft=1");
            assert_eq!(calls[0].body, body);

            // Exactly ONE X-Gallery-Admin-Assertion header forwarded
            let count_aa = calls[0]
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(ADMIN_ASSERTION_HEADER))
                .count();
            assert_eq!(count_aa, 1);

            let aa1 = header_value(&calls[0].headers, ADMIN_ASSERTION_HEADER)
                .unwrap()
                .to_string();
            let aa2 = header_value(&calls[1].headers, ADMIN_ASSERTION_HEADER)
                .unwrap()
                .to_string();
            assert!(aa1.starts_with("aa2."));

            let secret = test_admin_secret();
            let c1 = verify_admin_assertion(
                &aa1,
                &secret,
                ADMIN_ASSERTION_AUDIENCE,
                "POST",
                "/admin/api/policy?draft=1",
                &body,
                TEST_NOW,
                5,
            )
            .expect("valid AdminAssertion v2");
            let c2 = verify_admin_assertion(
                &aa2,
                &secret,
                ADMIN_ASSERTION_AUDIENCE,
                "POST",
                "/admin/api/policy?draft=1",
                &body,
                TEST_NOW,
                5,
            )
            .expect("valid second AdminAssertion v2");

            assert_eq!(c1.email, "ops@gallery.test");
            assert_eq!(c1.m, "POST");
            assert_eq!(c1.p, "/admin/api/policy?draft=1");
            assert_eq!(c1.bh, site_access::sha256_hex(&body));
            assert_eq!(c1.jti.len(), 32);
            assert_ne!(c1.jti, c2.jti, "each admin request must mint a unique jti nonce");

            // Wrong method / wrong target / tampered body must all fail verification!
            assert!(
                verify_admin_assertion(
                    &aa1,
                    &secret,
                    ADMIN_ASSERTION_AUDIENCE,
                    "DELETE",
                    "/admin/api/policy?draft=1",
                    &body,
                    TEST_NOW,
                    5,
                )
                .is_err()
            );
            assert!(
                verify_admin_assertion(
                    &aa1,
                    &secret,
                    ADMIN_ASSERTION_AUDIENCE,
                    "POST",
                    "/admin/api/policy?draft=2",
                    &body,
                    TEST_NOW,
                    5,
                )
                .is_err()
            );
            assert!(
                verify_admin_assertion(
                    &aa1,
                    &secret,
                    ADMIN_ASSERTION_AUDIENCE,
                    "POST",
                    "/admin/api/policy?draft=1",
                    br#"{"safety_enabled":false}"#,
                    TEST_NOW,
                    5,
                )
                .is_err()
            );
            aa1
        };

        // Non-`/admin` routes strip spoofed `X-Gallery-Admin-Assertion`!
        let mut spoof = HeaderMap::new();
        spoof.insert(ADMIN_ASSERTION_HEADER, aa1.parse().unwrap());
        let user_resp = dispatch(&backend, &cfg, Method::GET, "/user/account", spoof.clone(), Bytes::new());
        assert_eq!(user_resp.status(), StatusCode::OK);
        assert_eq!(
            header_value(&backend.service_calls.borrow().last().unwrap().headers, ADMIN_ASSERTION_HEADER),
            None
        );
        let gallery_resp = dispatch(&backend, &cfg, Method::GET, "/", spoof, Bytes::new());
        assert_eq!(gallery_resp.status(), StatusCode::OK);
        assert_eq!(
            header_value(&backend.upstream_calls.borrow().last().unwrap().headers, ADMIN_ASSERTION_HEADER),
            None
        );
    }

    // -----------------------------------------------------------------------
    // 7. Retained Core Session, Metering, Routing & Sanitization Tests
    // -----------------------------------------------------------------------

    #[test]
    fn restricted_user_media_enforces_age_terms_generation_ban_suspended_and_zero_charge() {
        let mut policy = sample_safety_policy();
        policy.age_policy = AgeVerificationPolicy::StrictProviderVerified18;
        policy.refresh_policy_digest();
        let terms_v = policy.legal.terms_version;
        let terms_d = policy.legal.terms_digest.clone();

        let do_key = "usr:550e8400-e29b-41d4-a716-446655440000";
        let user_id = "user-42";
        let sid = "sid-live-1";
        let cfg = test_cfg();

        let restricted_cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            aud: MEDIA_CAP_AUDIENCE.into(),
            kind: MediaCapKind::Image,
            asset_id: 99,
            immutable_locator: "restricted/item 99.webp".into(),
            facts_rev: 7,
            policy_rev: 5,
            actor_binding: ActorBinding::User {
                sub: user_id.into(),
                sid: sid.into(),
            },
            matched_blocks: vec![PolicyRef::new("r18", 1)],
            matched_blurs: vec![],
            revealed_refs: vec![],
            exp: TEST_NOW + 300,
        };
        let cap_tok = sign_media_capability(&restricted_cap, &cfg.media_cap_secret).unwrap();
        let uri = format!("/media/image/99?cap={cap_tok}");

        let make_hdrs = |cookie: String| {
            let mut h = HeaderMap::new();
            h.insert("cookie", cookie.parse().unwrap());
            h
        };

        let base_ctx = SessionContext {
            active: true,
            banned: false,
            suspended: false,
            sid_valid: true,
            assurance_level: AssuranceLevel::Verified18,
            strict_age_ok: true,
            terms_version_accepted: Some(terms_v),
            terms_digest_accepted: Some(terms_d),
            enabled_switchers: vec![PolicyRef::new("r18", 1)],
            pref_version: 1,
        };

        let denied_cases: Vec<(&str, SessionContext)> = vec![
            (
                "stale grant_generation",
                SessionContext {
                    enabled_switchers: vec![PolicyRef::new("r18", 2)],
                    ..base_ctx.clone()
                },
            ),
            (
                "suspended user",
                SessionContext {
                    suspended: true,
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
            (
                "insufficient age assurance",
                SessionContext {
                    assurance_level: AssuranceLevel::SelfAttestation,
                    strict_age_ok: false,
                    ..base_ctx.clone()
                },
            ),
            (
                "mismatched terms version",
                SessionContext {
                    terms_version_accepted: Some(terms_v + 1),
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
                make_hdrs(make_v2_cookie(&cfg, user_id, do_key, sid)),
                Bytes::new(),
            );
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "case: {label}");
            assert!(
                backend.account_calls.borrow().is_empty(),
                "case {label} MUST NOT charge"
            );
            assert!(
                backend.upstream_calls.borrow().is_empty(),
                "case {label} MUST NOT hit origin"
            );
        }

        // Authorized caller -> HEAD uses can-charge, GET uses charge with canonical media:image:99
        let mut backend = MockBackend::with_policy(policy);
        backend.session_contexts.insert(do_key.to_string(), base_ctx);
        let head_r = dispatch(
            &backend,
            &cfg,
            Method::HEAD,
            &uri,
            make_hdrs(make_v2_cookie(&cfg, user_id, do_key, sid)),
            Bytes::new(),
        );
        assert_eq!(head_r.status(), StatusCode::OK);
        assert_eq!(backend.account_calls.borrow()[0].do_key, do_key);
        assert_eq!(backend.account_calls.borrow()[0].operation, "can-charge");
        assert_eq!(
            backend.account_calls.borrow()[0].payload["path"],
            MediaBillingKey::image(99).canonical_key()
        );

        let get_r = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &uri,
            make_hdrs(make_v2_cookie(&cfg, user_id, do_key, sid)),
            Bytes::new(),
        );
        assert_eq!(get_r.status(), StatusCode::OK);
        assert_eq!(backend.account_calls.borrow()[1].operation, "charge");
        assert_eq!(
            backend.upstream_calls.borrow().last().unwrap().url,
            "https://image.gallery.test/restricted/item%2099.webp"
        );
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
                suspended: false,
                sid_valid: true,
                ..SessionContext::default()
            },
        );
        let cfg = test_cfg();

        let legacy_tok = sign_legacy_session(
            &LegacySessionClaims {
                sub: ETH_WALLET.to_string(),
                iat: TEST_NOW - 10,
                exp: TEST_NOW + 3600,
            },
            &cfg.jwt_secret,
        )
        .unwrap();
        let mut h = HeaderMap::new();
        h.insert("cookie", format!("{SESSION_COOKIE}={legacy_tok}").parse().unwrap());
        let resp = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "/api/like_previews?items=post:1",
            h,
            Bytes::new(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            backend.session_calls.borrow().as_slice(),
            &[(ETH_WALLET.to_string(), None)]
        );
        let ga = verify_gateway_assertion(
            header_value(&backend.upstream_calls.borrow()[0].headers, GATEWAY_ASSERTION_HEADER)
                .unwrap(),
            &cfg.gateway_assertion_secret,
            GATEWAY_ASSERTION_AUDIENCE,
            TEST_NOW,
            5,
        )
        .unwrap();
        assert_eq!(
            ga.actor,
            ActorBinding::User {
                sub: ETH_WALLET.to_string(),
                sid: "legacy".to_string()
            }
        );

        // Revoked v2 session on authenticated route -> 401 + Set-Cookie clearing ue_session!
        backend.session_contexts.insert(
            ETH_WALLET.to_string(),
            SessionContext {
                active: true,
                banned: false,
                suspended: false,
                sid_valid: false,
                ..SessionContext::default()
            },
        );
        let mut h2 = HeaderMap::new();
        h2.insert(
            "cookie",
            make_v2_cookie(&cfg, ETH_WALLET, ETH_WALLET, "revoked-sid")
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

    #[test]
    fn public_legal_seo_static_paths_and_cache_control_rules() {
        let mut backend = MockBackend::with_policy(sample_safety_policy());
        backend.account_statuses.insert("guest".to_string(), 401);
        let cfg = test_cfg();

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
                assert_eq!(cc, "public, max-age=3600");
            } else {
                assert_eq!(cc, "private, no-store");
            }
        }
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, "/sitemap.xml", HeaderMap::new(), Bytes::new())
                .status(),
            StatusCode::SEE_OTHER
        );

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
                suspended: false,
                sid_valid: true,
                ..SessionContext::default()
            },
        );
        let cfg = test_cfg();

        let mut h = form_headers();
        h.insert("origin", "https://gallery.test".parse().unwrap());
        h.insert(
            "cookie",
            make_v2_cookie(&cfg, "user-42", do_key, "sid-1")
                .parse()
                .unwrap(),
        );

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
        }

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
    }

    #[test]
    fn http_util_canonicalization_sanitization_and_metering_helpers() {
        assert_eq!(
            parse_upstream_origin("  https://api.gallery.test/  ").unwrap(),
            "https://api.gallery.test"
        );
        assert!(parse_upstream_origin("http://api.gallery.test").is_err());
        assert!(is_canonical_path("/media/image/42"));
        assert!(!is_canonical_path("/x/%2e%2e/api/search_advanced_clip"));
        assert_eq!(
            encode_canonical_cap_path("Demo album/a(1).webp").as_deref(),
            Some("/Demo%20album/a%281%29.webp")
        );
        assert!(build_media_upstream_target(MediaCapKind::Image, "../x.webp", &test_upstreams()).is_err());

        let mut h = HeaderMap::new();
        h.append(
            "cookie",
            "pref=dark; ue_session=s1; le_guest_sid=g1; __Host-ue_admin_view=a1"
                .parse()
                .unwrap(),
        );
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

        let form = form_headers();
        assert_eq!(
            form_field(&Bytes::from_static(b"limit=20&%71=cat+ears"), "q").as_deref(),
            Some("cat ears")
        );
        let mut mixed_dup = form_headers();
        mixed_dup.append(CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(require_form_urlencoded(&mixed_dup).is_err());

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
        assert!(browse_route(&Method::POST, "/api/safety/reveal"));
        assert!(!browse_route(&Method::GET, "/api/safety/reveal"));
        assert!(is_https_request(&"https://gallery.test/api/safety/reveal".parse().unwrap()));
        assert!(is_https_request(&"/api/safety/reveal".parse().unwrap()));
        assert!(!is_https_request(&"http://localhost:8787/api/safety/reveal".parse().unwrap()));
        assert_eq!(checked_media_method(&Method::GET), Some(worker::Method::Get));
        assert_eq!(checked_media_method(&Method::POST), None);
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

    // -----------------------------------------------------------------------
    // 8. GatewayAssertion v3 Caller Age/Terms Flags & Trusted `cf-ipcountry`
    // -----------------------------------------------------------------------

    #[test]
    fn gateway_assertion_populates_caller_age_verified_and_caller_terms_accepted() {
        let do_key = "usr:550e8400-e29b-41d4-a716-446655440000";
        let user_id = "user-age-terms";
        let sid = "sid-age-terms";

        let decode_last_ga = |backend: &MockBackend, cfg: &GatewayConfig| -> GatewayAssertion {
            let up = backend.upstream_calls.borrow();
            let raw = header_value(&up.last().expect("upstream call").headers, GATEWAY_ASSERTION_HEADER)
                .expect("X-Gateway-Assertion header");
            verify_gateway_assertion(
                raw,
                &cfg.gateway_assertion_secret,
                GATEWAY_ASSERTION_AUDIENCE,
                TEST_NOW,
                5,
            )
            .expect("valid GatewayAssertion v3")
        };

        let mut policy = sample_safety_policy();
        policy.age_policy = AgeVerificationPolicy::SelfAttestation;
        policy.refresh_policy_digest();
        let terms_v = policy.legal.terms_version;
        let terms_d = policy.legal.terms_digest.clone();

        let mut backend = MockBackend::with_policy(policy.clone());
        let mut cfg = test_cfg();

        // 1. Unauthenticated anonymous guest -> false / false
        let resp_anon = dispatch(&backend, &cfg, Method::GET, "/", HeaderMap::new(), Bytes::new());
        assert_eq!(resp_anon.status(), StatusCode::OK);
        let ga_anon = decode_last_ga(&backend, &cfg);
        assert_eq!(ga_anon.actor, ActorBinding::Anon);
        assert!(!ga_anon.caller_age_verified);
        assert!(!ga_anon.caller_terms_accepted);

        // 2. Guest session cookie (`le_guest_sid`) -> false / false
        let mut guest_hdrs = HeaderMap::new();
        guest_hdrs.insert(
            "cookie",
            make_guest_cookie(&cfg, "gs_0123456789abcdef0123456789abcdef")
                .parse()
                .unwrap(),
        );
        let resp_guest = dispatch(&backend, &cfg, Method::GET, "/", guest_hdrs, Bytes::new());
        assert_eq!(resp_guest.status(), StatusCode::OK);
        let ga_guest = decode_last_ga(&backend, &cfg);
        assert!(!ga_guest.caller_age_verified);
        assert!(!ga_guest.caller_terms_accepted);

        // 3. Browse pass (`ADMIN_VIEW_COOKIE`) without user session -> false / false
        let mut pass_hdrs = HeaderMap::new();
        pass_hdrs.insert("cookie", make_admin_view_cookie(&cfg).parse().unwrap());
        let resp_pass = dispatch(&backend, &cfg, Method::GET, "/", pass_hdrs, Bytes::new());
        assert_eq!(resp_pass.status(), StatusCode::OK);
        let ga_pass = decode_last_ga(&backend, &cfg);
        assert!(ga_pass.is_billing_waived);
        assert!(!ga_pass.caller_age_verified);
        assert!(!ga_pass.caller_terms_accepted);

        // 4. Live CF Access staff without gallery session -> false / false
        cfg.admin_email = Some("staff@gallery.test".into());
        let resp_staff = dispatch(&backend, &cfg, Method::GET, "/", HeaderMap::new(), Bytes::new());
        assert_eq!(resp_staff.status(), StatusCode::OK);
        let ga_staff = decode_last_ga(&backend, &cfg);
        assert_eq!(
            ga_staff.actor,
            ActorBinding::LiveAdmin {
                email: "staff@gallery.test".into()
            }
        );
        assert!(!ga_staff.caller_age_verified);
        assert!(!ga_staff.caller_terms_accepted);
        cfg.admin_email = None;

        let make_user_hdrs = || {
            let mut h = HeaderMap::new();
            h.insert(
                "cookie",
                make_v2_cookie(&cfg, user_id, do_key, sid).parse().unwrap(),
            );
            h
        };

        // 5. Authenticated user with AssuranceLevel::None and no terms -> false / false
        let base_ctx = SessionContext {
            active: true,
            banned: false,
            suspended: false,
            sid_valid: true,
            assurance_level: AssuranceLevel::None,
            strict_age_ok: false,
            terms_version_accepted: None,
            terms_digest_accepted: None,
            enabled_switchers: vec![],
            pref_version: 1,
        };
        backend.session_contexts.insert(do_key.into(), base_ctx.clone());
        let resp_unattested = dispatch(&backend, &cfg, Method::GET, "/", make_user_hdrs(), Bytes::new());
        assert_eq!(resp_unattested.status(), StatusCode::OK);
        let ga_unattested = decode_last_ga(&backend, &cfg);
        assert!(!ga_unattested.caller_age_verified);
        assert!(!ga_unattested.caller_terms_accepted);

        // 6. SelfAttestation policy: SelfAttestation + current terms -> true / true
        let self_attested_ctx = SessionContext {
            assurance_level: AssuranceLevel::SelfAttestation,
            terms_version_accepted: Some(terms_v),
            terms_digest_accepted: Some(terms_d.clone()),
            ..base_ctx.clone()
        };
        backend
            .session_contexts
            .insert(do_key.into(), self_attested_ctx.clone());
        let resp_self = dispatch(&backend, &cfg, Method::GET, "/", make_user_hdrs(), Bytes::new());
        assert_eq!(resp_self.status(), StatusCode::OK);
        let ga_self = decode_last_ga(&backend, &cfg);
        assert!(ga_self.caller_age_verified);
        assert!(ga_self.caller_terms_accepted);

        // 7. SelfAttestation + stale terms version OR wrong terms digest -> true / false
        for (label, stale_ctx) in [
            (
                "stale terms version",
                SessionContext {
                    terms_version_accepted: Some(terms_v + 1),
                    ..self_attested_ctx.clone()
                },
            ),
            (
                "wrong terms digest",
                SessionContext {
                    terms_digest_accepted: Some("0".repeat(64)),
                    ..self_attested_ctx.clone()
                },
            ),
        ] {
            backend.session_contexts.insert(do_key.into(), stale_ctx);
            let r = dispatch(&backend, &cfg, Method::GET, "/", make_user_hdrs(), Bytes::new());
            assert_eq!(r.status(), StatusCode::OK, "case: {label}");
            let ga = decode_last_ga(&backend, &cfg);
            assert!(ga.caller_age_verified, "case: {label}");
            assert!(!ga.caller_terms_accepted, "case: {label}");
        }

        // 8. StrictProviderVerified18 policy:
        //    - SelfAttestation -> false / true
        //    - Verified18 with strict_age_ok=false -> false / true
        //    - Verified18 with strict_age_ok=true -> true / true
        policy.age_policy = AgeVerificationPolicy::StrictProviderVerified18;
        policy.refresh_policy_digest();
        backend.policy_envelope = Ok(policy_envelope_json(&policy));

        backend
            .session_contexts
            .insert(do_key.into(), self_attested_ctx.clone());
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, "/", make_user_hdrs(), Bytes::new()).status(),
            StatusCode::OK
        );
        let ga_strict_self = decode_last_ga(&backend, &cfg);
        assert!(!ga_strict_self.caller_age_verified);
        assert!(ga_strict_self.caller_terms_accepted);

        backend.session_contexts.insert(
            do_key.into(),
            SessionContext {
                assurance_level: AssuranceLevel::Verified18,
                strict_age_ok: false,
                ..self_attested_ctx.clone()
            },
        );
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, "/", make_user_hdrs(), Bytes::new()).status(),
            StatusCode::OK
        );
        let ga_strict_flag_false = decode_last_ga(&backend, &cfg);
        assert!(!ga_strict_flag_false.caller_age_verified);
        assert!(ga_strict_flag_false.caller_terms_accepted);

        let strict_verified_ctx = SessionContext {
            assurance_level: AssuranceLevel::Verified18,
            strict_age_ok: true,
            enabled_switchers: vec![PolicyRef::new("r18", 1)],
            ..self_attested_ctx.clone()
        };
        backend
            .session_contexts
            .insert(do_key.into(), strict_verified_ctx.clone());
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, "/", make_user_hdrs(), Bytes::new()).status(),
            StatusCode::OK
        );
        let ga_strict_ok = decode_last_ga(&backend, &cfg);
        assert!(ga_strict_ok.caller_age_verified);
        assert!(ga_strict_ok.caller_terms_accepted);

        // 9. Metered POST search carries caller_age_verified & caller_terms_accepted
        let mut post_hdrs = form_headers();
        post_hdrs.insert("origin", "https://gallery.test".parse().unwrap());
        post_hdrs.insert(
            "cookie",
            make_v2_cookie(&cfg, user_id, do_key, sid).parse().unwrap(),
        );
        let post_resp = dispatch(
            &backend,
            &cfg,
            Method::POST,
            "https://gallery.test/api/search_by_desc",
            post_hdrs,
            Bytes::from_static(b"q=nebula"),
        );
        assert_eq!(post_resp.status(), StatusCode::OK);
        let ga_post = decode_last_ga(&backend, &cfg);
        assert!(ga_post.caller_age_verified);
        assert!(ga_post.caller_terms_accepted);

        // 10. Sitemap path stays strictly anonymous safe view (false / false) even for verified user
        let sitemap_resp = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "/sitemap/1.xml",
            make_user_hdrs(),
            Bytes::new(),
        );
        assert_eq!(sitemap_resp.status(), StatusCode::OK);
        let ga_sitemap = decode_last_ga(&backend, &cfg);
        assert_eq!(ga_sitemap.actor, ActorBinding::Anon);
        assert!(!ga_sitemap.caller_age_verified);
        assert!(!ga_sitemap.caller_terms_accepted);

        // 11. Media `/internal/facts-rev/*` assertion also carries caller_age_verified & caller_terms_accepted
        backend.upstream_calls.borrow_mut().clear();
        let cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            aud: MEDIA_CAP_AUDIENCE.into(),
            kind: MediaCapKind::Image,
            asset_id: 77,
            immutable_locator: "2026/01/pic_77.webp".into(),
            facts_rev: 7,
            policy_rev: policy.revision,
            actor_binding: ActorBinding::User {
                sub: user_id.into(),
                sid: sid.into(),
            },
            matched_blocks: vec![PolicyRef::new("r18", 1)],
            matched_blurs: vec![],
            revealed_refs: vec![],
            exp: TEST_NOW + 300,
        };
        let cap_tok = sign_media_capability(&cap, &cfg.media_cap_secret).unwrap();
        let media_resp = dispatch(
            &backend,
            &cfg,
            Method::GET,
            &format!("/media/image/77?cap={cap_tok}"),
            make_user_hdrs(),
            Bytes::new(),
        );
        assert_eq!(media_resp.status(), StatusCode::OK);
        {
            let up = backend.upstream_calls.borrow();
            let facts_call = up
                .iter()
                .find(|c| c.url.contains("/internal/facts-rev/"))
                .expect("facts-rev upstream call");
            let ga_facts = verify_gateway_assertion(
                header_value(&facts_call.headers, GATEWAY_ASSERTION_HEADER).unwrap(),
                &cfg.gateway_assertion_secret,
                GATEWAY_ASSERTION_AUDIENCE,
                TEST_NOW,
                5,
            )
            .unwrap();
            assert!(ga_facts.caller_age_verified);
            assert!(ga_facts.caller_terms_accepted);
        }

        // 12. AgeVerificationPolicy::Off -> caller_age_verified MUST be false even for Verified18!
        for rule in &mut policy.policies {
            rule.bypass.require_age_18 = false;
        }
        policy.age_policy = AgeVerificationPolicy::Off;
        policy.age_gate_trigger = AgeGateTrigger::Off;
        policy.refresh_policy_digest();
        backend.policy_envelope = Ok(policy_envelope_json(&policy));
        assert_eq!(
            dispatch(&backend, &cfg, Method::GET, "/", make_user_hdrs(), Bytes::new()).status(),
            StatusCode::OK
        );
        let ga_off = decode_last_ga(&backend, &cfg);
        assert!(!ga_off.caller_age_verified);
        assert!(ga_off.caller_terms_accepted);

        // 13. Revoked session -> false / false
        backend.session_contexts.insert(
            do_key.into(),
            SessionContext {
                sid_valid: false,
                ..strict_verified_ctx
            },
        );
        let revoked_resp = dispatch(&backend, &cfg, Method::GET, "/", make_user_hdrs(), Bytes::new());
        assert_eq!(revoked_resp.status(), StatusCode::OK);
        let ga_revoked = decode_last_ga(&backend, &cfg);
        assert_eq!(ga_revoked.actor, ActorBinding::Anon);
        assert!(!ga_revoked.caller_age_verified);
        assert!(!ga_revoked.caller_terms_accepted);
    }

    #[test]
    fn user_worker_forwarding_strips_spoofed_cf_ipcountry_and_sets_trusted_cf_country() {
        let backend = MockBackend::with_policy(sample_safety_policy());
        let mut cfg = test_cfg();
        cfg.visitor_country = Some("GB".into());

        // Spoofed (including duplicate) client cf-ipcountry headers are stripped and replaced
        // with the single authoritative Cloudflare runtime `cf.country` value on `/user/*`.
        let mut spoofed = HeaderMap::new();
        spoofed.append("cf-ipcountry", "FR".parse().unwrap());
        spoofed.append("cf-ipcountry", "JP".parse().unwrap());
        let resp = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "/user/account",
            spoofed.clone(),
            Bytes::new(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        {
            let calls = backend.service_calls.borrow();
            let last = calls.last().expect("USER_WORKER service call");
            assert_eq!(last.target, ServiceTarget::UserWorker);
            let country_headers: Vec<&str> = last
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("cf-ipcountry"))
                .map(|(_, v)| v.as_str())
                .collect();
            assert_eq!(country_headers, vec!["GB"]);
        }

        // Absent or blank `cf.country` -> spoofed client header stripped and NO `cf-ipcountry` set.
        for absent in [None, Some(""), Some("   ")] {
            cfg.visitor_country = absent.map(str::to_string);
            let r = dispatch(
                &backend,
                &cfg,
                Method::GET,
                "/user/account",
                spoofed.clone(),
                Bytes::new(),
            );
            assert_eq!(r.status(), StatusCode::OK);
            let calls = backend.service_calls.borrow();
            let last = calls.last().expect("USER_WORKER service call");
            assert_eq!(
                header_value(&last.headers, "cf-ipcountry"),
                None,
                "absent/blank cf.country must not forward cf-ipcountry"
            );
        }

        // Non-USER_WORKER targets (`/admin` and `API_UPSTREAM`) still NEVER receive `cf-ipcountry`.
        cfg.visitor_country = Some("US".into());
        cfg.admin_email = Some("ops@gallery.test".into());
        let admin_resp = dispatch(
            &backend,
            &cfg,
            Method::GET,
            "/admin",
            spoofed.clone(),
            Bytes::new(),
        );
        assert_eq!(admin_resp.status(), StatusCode::OK);
        assert_eq!(
            header_value(
                &backend.service_calls.borrow().last().unwrap().headers,
                "cf-ipcountry"
            ),
            None
        );

        let gallery_resp = dispatch(&backend, &cfg, Method::GET, "/", spoofed, Bytes::new());
        assert_eq!(gallery_resp.status(), StatusCode::OK);
        assert_eq!(
            header_value(
                &backend.upstream_calls.borrow().last().unwrap().headers,
                "cf-ipcountry"
            ),
            None
        );
    }
}
