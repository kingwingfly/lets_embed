use leptos::{prelude::*, task::spawn_local};

/// Result of one round-trip to the like API on the user worker.
// On non-hydrate targets only the stub `call_like_api` exists, which never
// constructs these variants.
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
enum ApiResult {
    /// 200 `{"liked": bool}`
    Liked(bool),
    /// 401 — no valid `ue_session`
    Unauthorized,
}

/// Same-origin fetch against the user worker (browser only).
///
/// GET uses query params, POST/DELETE send a JSON body, per the worker contract.
#[cfg(feature = "hydrate")]
async fn call_like_api(
    method: &'static str,
    kind: &'static str,
    target_id: i64,
) -> Result<ApiResult, String> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Headers, RequestInit, Response};

    let window = web_sys::window().ok_or("no window")?;
    let opts = RequestInit::new();
    opts.set_method(method);

    let url = if method == "GET" {
        format!("/user/api/like?kind={kind}&target_id={target_id}")
    } else {
        let headers = Headers::new().map_err(|e| format!("{e:?}"))?;
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| format!("{e:?}"))?;
        opts.set_headers(&headers);
        let body = serde_json::json!({ "kind": kind, "target_id": target_id }).to_string();
        opts.set_body(&JsValue::from_str(&body));
        "/user/api/like".to_string()
    };

    let resp = JsFuture::from(window.fetch_with_str_and_init(&url, &opts))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let resp: Response = resp
        .dyn_into()
        .map_err(|_| "fetch result is not a Response".to_string())?;

    if resp.status() == 401 {
        return Ok(ApiResult::Unauthorized);
    }
    if !resp.ok() {
        return Err(format!("unexpected status {}", resp.status()));
    }

    let text = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("{e:?}"))?
        .as_string()
        .unwrap_or_default();
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    json.get("liked")
        .and_then(|v| v.as_bool())
        .map(ApiResult::Liked)
        .ok_or_else(|| "malformed like response".to_string())
}

/// Server / non-browser stub: never called (effects only run in the browser),
/// but keeps the ssr target compiling without browser APIs.
#[cfg(not(feature = "hydrate"))]
async fn call_like_api(
    _method: &'static str,
    _kind: &'static str,
    _target_id: i64,
) -> Result<ApiResult, String> {
    Err("like API is only available in the browser".to_string())
}

#[derive(Clone, Copy, PartialEq)]
enum LikeState {
    Liked,
    NotLiked,
    SignedOut,
}

/// A heart toggle for favoriting a post/image/video via the user worker.
///
/// SSR renders a neutral placeholder; the browser then resolves the real state
/// (liked / not liked / signed out) and toggles optimistically on click.
#[component]
pub fn LikeButton(kind: &'static str, target_id: i64) -> impl IntoView {
    // None = SSR placeholder / still loading
    let state: RwSignal<Option<LikeState>> = RwSignal::new(None);
    let pending = RwSignal::new(false);

    // Initial state; effects only run in the browser, so this never fires on the server.
    Effect::new(move |_| {
        spawn_local(async move {
            let next = match call_like_api("GET", kind, target_id).await {
                Ok(ApiResult::Liked(true)) => LikeState::Liked,
                Ok(ApiResult::Liked(false)) => LikeState::NotLiked,
                Ok(ApiResult::Unauthorized) => LikeState::SignedOut,
                Err(e) => {
                    leptos::logging::error!("like status fetch failed: {e}");
                    LikeState::SignedOut
                }
            };
            // try_set: the component may have been disposed while the fetch
            // was in flight (e.g. user navigated away); .set() would panic.
            let _ = state.try_set(Some(next));
        });
    });

    let toggle = move || {
        if pending.get_untracked() {
            return;
        }
        let prev = match state.get_untracked() {
            Some(s @ (LikeState::Liked | LikeState::NotLiked)) => s,
            _ => return,
        };
        let (method, optimistic) = match prev {
            LikeState::Liked => ("DELETE", LikeState::NotLiked),
            _ => ("POST", LikeState::Liked),
        };
        pending.set(true);
        state.set(Some(optimistic));
        spawn_local(async move {
            let next = match call_like_api(method, kind, target_id).await {
                Ok(ApiResult::Liked(true)) => LikeState::Liked,
                Ok(ApiResult::Liked(false)) => LikeState::NotLiked,
                Ok(ApiResult::Unauthorized) => LikeState::SignedOut,
                Err(e) => {
                    leptos::logging::error!("like toggle ({method} {kind} {target_id}) failed: {e}");
                    prev // revert the optimistic toggle
                }
            };
            // try_set: the component may have been disposed mid-flight.
            let _ = state.try_set(Some(next));
            let _ = pending.try_set(false);
        });
    };

    let base = "text-xl md:text-2xl leading-none select-none transition-transform";
    view! {
        {move || match state.get() {
            Some(LikeState::Liked) => view! {
                <button
                    class=format!("{base} text-rose-500 hover:scale-110 cursor-pointer")
                    title=format!("unfavorite this {kind}")
                    on:click=move |_| toggle()
                >
                    "\u{2665}"
                </button>
            }.into_any(),
            Some(LikeState::NotLiked) => view! {
                <button
                    class=format!("{base} text-sky-400 hover:text-rose-400 hover:scale-110 cursor-pointer")
                    title=format!("favorite this {kind}")
                    on:click=move |_| toggle()
                >
                    "\u{2661}"
                </button>
            }.into_any(),
            Some(LikeState::SignedOut) => view! {
                <a
                    href="/user/login"
                    class=format!("{base} text-sky-300 hover:text-sky-500 hover:scale-110")
                    title="sign in to favorite"
                >
                    "\u{2661}"
                </a>
            }.into_any(),
            None => view! {
                <span class=format!("{base} text-sky-200") title="favorite">
                    "\u{2661}"
                </span>
            }.into_any(),
        }}
    }
}
