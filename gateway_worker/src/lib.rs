use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{FromRef, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
};
use tower_cookies::{CookieManagerLayer, Cookies};
use tower_service::Service;
use worker::{
    Context, Env, Error, Fetch, HttpRequest, RequestInit, Result, event, js_sys::Uint8Array,
};

async fn router(env: Env, ctx: Context) -> Result<Router> {
    let client_id_store = env.secret_store("lets-embed-client-id")?;
    let client_id = client_id_store.get().await?.ok_or(Error::BindingError(
        "`lets-embed-client-id` not provided".to_string(),
    ))?;
    let client_secret_store = env.secret_store("lets-embed-client-secret")?;
    let client_secret = client_secret_store.get().await?.ok_or(Error::BindingError(
        "`lets-embed-client-secret` not provided".to_string(),
    ))?;

    Ok(Router::new()
        .route("/admin", any(bypass)) // Protected by Zero Trust policies
        .route("/apply", any(bypass)) // Everyone can bypass
        .fallback(any(verify_jwt).layer(CookieManagerLayer::new()))
        .with_state(MyState {
            env,
            ctx: Arc::new(ctx),
            client_id_secret: (client_id, client_secret),
        }))
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, ctx: Context) -> Result<Response> {
    Ok(router(env, ctx).await?.call(req).await?)
}

#[derive(Debug, Clone, FromRef)]
struct MyState {
    env: Env,
    ctx: Arc<Context>,
    client_id_secret: (String, String),
}

#[cfg_attr(debug_assertions, axum::debug_handler)]
#[worker::send]
pub async fn bypass(
    State((client_id, client_secret)): State<(String, String)>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut target = "https://lets-embed-api.louisfly.icu".to_string();
    if let Some(pq) = uri.path_and_query() {
        target += pq.as_str();
    }

    let mut req_init = RequestInit::new();
    req_init.with_method(method.to_string().into());
    if !matches!(method, Method::GET | Method::HEAD) && !body.is_empty() {
        req_init.with_body(Some(Uint8Array::from(&body[..]).into()));
    }
    for (k, v) in headers {
        if let Some(k) = k
            && let Ok(v) = str::from_utf8(v.as_bytes())
            && let Err(e) = req_init.headers.set(k.as_str(), v)
        {
            return (
                StatusCode::BAD_REQUEST,
                format!("build request failed: {e}"),
            )
                .into_response();
        }
    }
    req_init
        .headers
        .set("CF-Access-Client-Id", &client_id)
        .unwrap();
    req_init
        .headers
        .set("CF-Access-Client-Secret", &client_secret)
        .unwrap();

    let request = match worker::Request::new_with_init(&target, &req_init) {
        Ok(req) => req,
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

#[cfg_attr(debug_assertions, axum::debug_handler)]
#[worker::send]
pub async fn verify_jwt(
    State((client_id, client_secret)): State<(String, String)>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    cookies: Cookies,
    body: Bytes,
) -> impl IntoResponse {
    (StatusCode::SERVICE_UNAVAILABLE, "Not implement yet").into_response()
    // bypass(uri, method, headers, body).await
}
