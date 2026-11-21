use std::collections::{HashMap, HashSet};

use leptos::prelude::*;
#[cfg(feature = "hydrate")]
use leptos::task::spawn_local;

/// Visual style of a [`LikeButton`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LikeVariant {
    /// Light pill button for pages like `ImageDetails`.
    #[default]
    Inline,
    /// Translucent dark pill for floating over gallery/lightbox image & post cards.
    /// Always visible when liked; revealed on hover/focus/touch otherwise.
    Card,
    /// Translucent dark pill for dark toolbars (`Lightbox` / `Viewer` headers).
    Overlay,
}

#[cfg(feature = "hydrate")]
#[derive(Clone)]
struct FallbackCache {
    liked: HashSet<(&'static str, i64)>,
    /// True when the single `/user/api/likes?limit=100` page had `next_cursor == None`,
    /// meaning the set contains every favorite the account has.
    exhaustive: bool,
}

/// Shared client-side favorite store provided at the `<App/>` root.
///
/// Coalesces per-card status lookups into a single batched
/// `GET /user/api/likes/status?items=...` request, serializes mutations per
/// `(kind, target_id)` across duplicate mounted buttons, and resets whenever
/// the authenticated wallet principal changes.
#[derive(Clone, Copy)]
pub struct LikeStore {
    items: RwSignal<HashMap<(&'static str, i64), bool>>,
    pending: RwSignal<HashSet<(&'static str, i64)>>,
    failed: RwSignal<HashSet<(&'static str, i64)>>,
    signed_out: RwSignal<bool>,
    /// Reactive epoch bumped on wallet switch / sign-in / sign-out so mounted
    /// `LikeButton` effects re-fetch cleanly for the new session.
    epoch_sig: RwSignal<u64>,
    #[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
    principal: StoredValue<Option<Option<String>>>,
    #[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
    queued: StoredValue<Vec<(&'static str, i64)>>,
    #[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
    in_flight: StoredValue<HashSet<(&'static str, i64)>>,
    #[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
    flush_scheduled: StoredValue<bool>,
    #[cfg(feature = "hydrate")]
    fallback_cache: StoredValue<Option<FallbackCache>>,
    #[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
    batch_fallback: StoredValue<bool>,
}

impl Default for LikeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LikeStore {
    pub fn new() -> Self {
        Self {
            items: RwSignal::new(HashMap::new()),
            pending: RwSignal::new(HashSet::new()),
            failed: RwSignal::new(HashSet::new()),
            signed_out: RwSignal::new(false),
            epoch_sig: RwSignal::new(0),
            principal: StoredValue::new(None),
            queued: StoredValue::new(Vec::new()),
            in_flight: StoredValue::new(HashSet::new()),
            flush_scheduled: StoredValue::new(false),
            #[cfg(feature = "hydrate")]
            fallback_cache: StoredValue::new(None),
            batch_fallback: StoredValue::new(false),
        }
    }

    /// Synchronize the store with the current session principal reported by
    /// `GET /user/api/me`. Resets cached favorite state whenever the account
    /// switches wallets, signs in from another tab, or signs out.
    pub fn sync_principal(&self, next: Option<String>) {
        #[cfg(feature = "hydrate")]
        {
            let changed = self
                .principal
                .with_value(|cur| cur.as_ref().is_some_and(|prev| prev != &next));
            let first_signed_in_after_401 = self.principal.with_value(|c| c.is_none())
                && next.is_some()
                && self.signed_out.get_untracked();
            self.principal.set_value(Some(next.clone()));

            if changed || first_signed_in_after_401 {
                let next_epoch = self.epoch_sig.get_untracked().wrapping_add(1);
                let _ = self.items.try_update(HashMap::clear);
                let _ = self.pending.try_update(HashSet::clear);
                let _ = self.failed.try_update(HashSet::clear);
                let _ = self.queued.try_update_value(Vec::clear);
                let _ = self.in_flight.try_update_value(HashSet::clear);
                let _ = self.fallback_cache.try_set_value(None);
                let _ = self.signed_out.try_set(next.is_none());
                let _ = self.epoch_sig.try_set(next_epoch);
            } else if next.is_none() {
                let _ = self.signed_out.try_set(true);
            }
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = next;
        }
    }

    #[cfg(feature = "hydrate")]
    fn ensure_loaded(&self, kind: &'static str, target_id: i64) {
        if self.signed_out.get_untracked() {
            return;
        }
        let key = (kind, target_id);
        if self.items.with_untracked(|m| m.contains_key(&key)) {
            return;
        }
        if self.failed.with_untracked(|s| s.contains(&key)) {
            return;
        }
        if self.in_flight.with_value(|s| s.contains(&key)) {
            return;
        }
        self.enqueue(key);
    }

    #[cfg(feature = "hydrate")]
    fn retry_key(&self, kind: &'static str, target_id: i64) {
        let key = (kind, target_id);
        let _ = self.failed.try_update(|s| {
            s.remove(&key);
        });
        if !self.in_flight.with_value(|s| s.contains(&key)) {
            self.enqueue(key);
        }
    }

    #[cfg(feature = "hydrate")]
    fn enqueue(&self, key: (&'static str, i64)) {
        self.in_flight.update_value(|s| {
            s.insert(key);
        });
        self.queued.update_value(|q| q.push(key));

        if !self.flush_scheduled.get_value() {
            self.flush_scheduled.set_value(true);
            let store = *self;
            let scheduled_epoch = store.epoch_sig.get_untracked();
            set_timeout(
                move || {
                    let _ = store.flush_scheduled.try_set_value(false);
                    if store.epoch_sig.try_get_untracked() != Some(scheduled_epoch) {
                        return;
                    }
                    let batch = store.queued.try_update_value(std::mem::take);
                    if let Some(keys) = batch
                        && !keys.is_empty()
                    {
                        store.run_batch(keys, scheduled_epoch);
                    }
                },
                std::time::Duration::from_millis(20),
            );
        }
    }

    #[cfg(feature = "hydrate")]
    fn is_current_epoch(&self, epoch: u64) -> bool {
        self.epoch_sig.try_get_untracked() == Some(epoch)
    }

    #[cfg(feature = "hydrate")]
    fn run_batch(self, keys: Vec<(&'static str, i64)>, epoch: u64) {
        if !self.is_current_epoch(epoch) || self.signed_out.get_untracked() {
            let _ = self.in_flight.try_update_value(|s| {
                for k in &keys {
                    s.remove(k);
                }
            });
            return;
        }
        for chunk in keys.chunks(80) {
            let chunk = chunk.to_vec();
            spawn_local(async move {
                if self.batch_fallback.get_value() {
                    self.fetch_legacy_fallback(&chunk, epoch).await;
                    return;
                }
                let outcome = call_batch_status(&chunk).await;
                if !self.is_current_epoch(epoch) {
                    return;
                }
                match outcome {
                    Ok(BatchOutcome::Liked(liked_set)) => {
                        let _ = self.items.try_update(|map| {
                            for &k in &chunk {
                                map.entry(k).or_insert_with(|| liked_set.contains(&k));
                            }
                        });
                    }
                    Ok(BatchOutcome::Unauthorized) => {
                        let _ = self.signed_out.try_set(true);
                    }
                    Ok(BatchOutcome::NotFound) => {
                        let _ = self.batch_fallback.try_set_value(true);
                        self.fetch_legacy_fallback(&chunk, epoch).await;
                        return;
                    }
                    Err(e) => {
                        leptos::logging::error!("batch like status failed: {e}");
                        let _ = self.failed.try_update(|s| {
                            for &k in &chunk {
                                s.insert(k);
                            }
                        });
                    }
                }
                let _ = self.in_flight.try_update_value(|s| {
                    for k in &chunk {
                        s.remove(k);
                    }
                });
            });
        }
    }

    /// Graceful fallback if an older `user_worker` without `/user/api/likes/status`
    /// is deployed. Uses `/user/api/likes?limit=100` once: if `next_cursor` is None
    /// (<= 100 total likes), absence is exhaustive; otherwise resolves unknown keys
    /// individually via `/user/api/like` so older favorites are never marked unliked.
    #[cfg(feature = "hydrate")]
    async fn fetch_legacy_fallback(self, chunk: &[(&'static str, i64)], epoch: u64) {
        let mut cache = self.fallback_cache.with_value(|c| c.clone());
        if cache.is_none() {
            match call_recent_likes().await {
                Ok(RecentOutcome::Page(page)) => {
                    if !self.is_current_epoch(epoch) {
                        return;
                    }
                    let _ = self.fallback_cache.try_set_value(Some(page.clone()));
                    cache = Some(page);
                }
                Ok(RecentOutcome::Unauthorized) => {
                    if self.is_current_epoch(epoch) {
                        let _ = self.signed_out.try_set(true);
                    }
                    let _ = self.in_flight.try_update_value(|s| {
                        for k in chunk {
                            s.remove(k);
                        }
                    });
                    return;
                }
                Err(e) => {
                    leptos::logging::error!("fallback like list failed: {e}");
                    if self.is_current_epoch(epoch) {
                        let _ = self.failed.try_update(|s| {
                            for &k in chunk {
                                s.insert(k);
                            }
                        });
                        let _ = self.in_flight.try_update_value(|s| {
                            for k in chunk {
                                s.remove(k);
                            }
                        });
                    }
                    return;
                }
            }
        }

        if let Some(page) = cache {
            let mut unresolved = Vec::new();
            let _ = self.items.try_update(|map| {
                for &k in chunk {
                    if page.liked.contains(&k) {
                        map.entry(k).or_insert(true);
                    } else if page.exhaustive {
                        map.entry(k).or_insert(false);
                    } else {
                        unresolved.push(k);
                    }
                }
            });
            for k in unresolved {
                if !self.is_current_epoch(epoch) {
                    return;
                }
                match call_single_status(k.0, k.1).await {
                    Ok(ApiResult::Liked(v)) if self.is_current_epoch(epoch) => {
                        let _ = self.items.try_update(|map| {
                            map.entry(k).or_insert(v);
                        });
                    }
                    Ok(ApiResult::Unauthorized) if self.is_current_epoch(epoch) => {
                        let _ = self.signed_out.try_set(true);
                        break;
                    }
                    Err(_) if self.is_current_epoch(epoch) => {
                        let _ = self.failed.try_update(|s| {
                            s.insert(k);
                        });
                    }
                    _ => {}
                }
            }
        }

        if self.is_current_epoch(epoch) {
            let _ = self.in_flight.try_update_value(|s| {
                for k in chunk {
                    s.remove(k);
                }
            });
        }
    }
}

#[cfg(feature = "hydrate")]
enum BatchOutcome {
    Liked(HashSet<(&'static str, i64)>),
    Unauthorized,
    NotFound,
}

#[cfg(feature = "hydrate")]
enum RecentOutcome {
    Page(FallbackCache),
    Unauthorized,
}

#[cfg(feature = "hydrate")]
fn parse_key_pair(s: &str) -> Option<(&'static str, i64)> {
    let (k, id) = s.split_once(':')?;
    let kind = match k {
        "post" => "post",
        "image" => "image",
        "video" => "video",
        _ => return None,
    };
    Some((kind, id.parse().ok()?))
}

#[cfg(feature = "hydrate")]
async fn call_batch_status(keys: &[(&'static str, i64)]) -> Result<BatchOutcome, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestInit, Response};

    let window = web_sys::window().ok_or("no window")?;
    let opts = RequestInit::new();
    opts.set_method("GET");

    let items: String = keys
        .iter()
        .map(|(k, id)| format!("{k}:{id}"))
        .collect::<Vec<_>>()
        .join(",");
    let url = format!("/user/api/likes/status?items={items}");
    let resp = JsFuture::from(window.fetch_with_str_and_init(&url, &opts))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let resp: Response = resp
        .dyn_into()
        .map_err(|_| "fetch result is not a Response".to_string())?;

    if resp.status() == 401 {
        return Ok(BatchOutcome::Unauthorized);
    }
    if resp.status() == 404 {
        return Ok(BatchOutcome::NotFound);
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
    let set = json
        .get("liked")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().and_then(parse_key_pair))
                .collect()
        })
        .unwrap_or_default();
    Ok(BatchOutcome::Liked(set))
}

#[cfg(feature = "hydrate")]
async fn call_recent_likes() -> Result<RecentOutcome, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestInit, Response};

    let window = web_sys::window().ok_or("no window")?;
    let opts = RequestInit::new();
    opts.set_method("GET");
    let resp = JsFuture::from(window.fetch_with_str_and_init("/user/api/likes?limit=100", &opts))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let resp: Response = resp
        .dyn_into()
        .map_err(|_| "fetch result is not a Response".to_string())?;
    if resp.status() == 401 {
        return Ok(RecentOutcome::Unauthorized);
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
    let mut set = HashSet::new();
    if let Some(arr) = json.get("items").and_then(|v| v.as_array()) {
        for item in arr {
            let kind = match item.get("kind").and_then(|v| v.as_str()) {
                Some("post") => "post",
                Some("image") => "image",
                Some("video") => "video",
                _ => continue,
            };
            if let Some(id) = item.get("target_id").and_then(|v| v.as_i64()) {
                set.insert((kind, id));
            }
        }
    }
    let exhaustive = json.get("next_cursor").is_none_or(|v| v.is_null());
    Ok(RecentOutcome::Page(FallbackCache {
        liked: set,
        exhaustive,
    }))
}

#[cfg(feature = "hydrate")]
async fn call_single_status(kind: &'static str, target_id: i64) -> Result<ApiResult, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestInit, Response};

    let window = web_sys::window().ok_or("no window")?;
    let opts = RequestInit::new();
    opts.set_method("GET");
    let url = format!("/user/api/like?kind={kind}&target_id={target_id}");
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

/// Result of toggling a like via `POST`/`DELETE /user/api/like`.
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
enum ApiResult {
    Liked(bool),
    Unauthorized,
}

#[cfg(feature = "hydrate")]
async fn call_like_mutate(
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

    let headers = Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| format!("{e:?}"))?;
    opts.set_headers(&headers);
    let body = serde_json::json!({ "kind": kind, "target_id": target_id }).to_string();
    opts.set_body(&JsValue::from_str(&body));

    let resp = JsFuture::from(window.fetch_with_str_and_init("/user/api/like", &opts))
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

#[derive(Clone, Copy, PartialEq)]
enum LikeState {
    Liked,
    NotLiked,
    SignedOut,
    Failed,
}

/// A favorite toggle for a post, image, or video backed by the shared [`LikeStore`].
#[component]
pub fn LikeButton(
    kind: &'static str,
    target_id: i64,
    #[prop(default = LikeVariant::Inline)] variant: LikeVariant,
    #[prop(default = false)] show_label: bool,
    #[prop(default = false)] hide_label_mobile: bool,
) -> impl IntoView {
    let store = use_context::<LikeStore>().unwrap_or_default();
    let key = (kind, target_id);

    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        // Re-run whenever the session epoch changes (wallet switch / sign-in).
        let _ = store.epoch_sig.get();
        store.ensure_loaded(kind, target_id);
    });

    let state = Memo::new(move |_| {
        if store.signed_out.get() {
            return Some(LikeState::SignedOut);
        }
        if let Some(liked) = store.items.with(|m| m.get(&key).copied()) {
            return Some(if liked {
                LikeState::Liked
            } else {
                LikeState::NotLiked
            });
        }
        if store.failed.with(|s| s.contains(&key)) {
            return Some(LikeState::Failed);
        }
        None
    });

    let toggle = move |ev: leptos::ev::MouseEvent| {
        ev.stop_propagation();
        ev.prevent_default();
        if store.pending.with_untracked(|s| s.contains(&key)) {
            return;
        }
        let prev_liked = match state.get_untracked() {
            Some(LikeState::Liked) => true,
            Some(LikeState::NotLiked) => false,
            _ => return,
        };
        let next_liked = !prev_liked;
        let method = if prev_liked { "DELETE" } else { "POST" };
        let req_epoch = store.epoch_sig.get_untracked();
        store.pending.update(|s| {
            s.insert(key);
        });
        store.items.update(|m| {
            m.insert(key, next_liked);
        });
        #[cfg(feature = "hydrate")]
        spawn_local(async move {
            let outcome = call_like_mutate(method, kind, target_id).await;
            if store.is_current_epoch(req_epoch) {
                match outcome {
                    Ok(ApiResult::Liked(confirmed)) => {
                        let _ = store.items.try_update(|m| {
                            m.insert(key, confirmed);
                        });
                    }
                    Ok(ApiResult::Unauthorized) => {
                        let _ = store.signed_out.try_set(true);
                        let _ = store.items.try_update(|m| {
                            m.remove(&key);
                        });
                    }
                    Err(e) => {
                        leptos::logging::error!(
                            "like toggle ({method} {kind} {target_id}) failed: {e}"
                        );
                        let _ = store.items.try_update(|m| {
                            m.insert(key, prev_liked);
                        });
                    }
                }
                let _ = store.pending.try_update(|s| {
                    s.remove(&key);
                });
            }
        });
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = (method, req_epoch);
            store.pending.update(|s| {
                s.remove(&key);
            });
        }
    };

    let retry = move |ev: leptos::ev::MouseEvent| {
        ev.stop_propagation();
        ev.prevent_default();
        #[cfg(feature = "hydrate")]
        store.retry_key(kind, target_id);
    };

    let (filled, outline, label_text, liked_accent, idle_accent) = match kind {
        "post" => (
            "\u{2605}",
            "\u{2606}",
            "Post",
            "text-amber-400",
            "hover:text-amber-300",
        ),
        "video" => (
            "\u{2665}",
            "\u{2661}",
            "Video",
            "text-rose-400",
            "hover:text-rose-300",
        ),
        _ => (
            "\u{2665}",
            "\u{2661}",
            "Image",
            "text-rose-400",
            "hover:text-rose-300",
        ),
    };
    let inline_liked = if kind == "post" {
        "text-amber-500 bg-amber-50 ring-amber-200 hover:bg-amber-100"
    } else {
        "text-rose-500 bg-rose-50 ring-rose-200 hover:bg-rose-100"
    };
    let label_cls = if hide_label_mobile {
        "hidden sm:inline"
    } else {
        ""
    };

    let btn_class = move |s: Option<LikeState>| match variant {
        LikeVariant::Card => {
            let vis = if s == Some(LikeState::Liked) {
                "opacity-100"
            } else {
                "opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 touch-visible"
            };
            let color = match s {
                Some(LikeState::Liked) => format!("{liked_accent} bg-slate-900/80 ring-white/30"),
                _ => format!(
                    "text-white/95 {idle_accent} bg-slate-900/60 hover:bg-slate-900/85 ring-white/25"
                ),
            };
            format!(
                "inline-flex items-center justify-center gap-1 h-8 min-w-8 px-2 rounded-full \
                 ring-1 backdrop-blur-xs shadow-sm text-base leading-none select-none \
                 cursor-pointer transition-all hover:scale-105 active:scale-95 {vis} {color}"
            )
        }
        LikeVariant::Overlay => {
            let color = match s {
                Some(LikeState::Liked) => format!("{liked_accent} bg-white/15 border-white/30"),
                _ => format!(
                    "text-white/95 {idle_accent} bg-white/10 hover:bg-white/20 border-white/20"
                ),
            };
            format!(
                "inline-flex items-center justify-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-full \
                 border text-xs sm:text-sm font-semibold leading-none select-none \
                 cursor-pointer transition-colors {color}"
            )
        }
        LikeVariant::Inline => {
            let color = match s {
                Some(LikeState::Liked) => inline_liked,
                _ => "text-sky-600 bg-sky-50/90 ring-sky-200 hover:bg-sky-100",
            };
            format!(
                "inline-flex items-center justify-center gap-1.5 px-3 py-1 rounded-full \
                 ring-1 text-sm md:text-base font-medium leading-none select-none \
                 cursor-pointer transition-all hover:scale-105 active:scale-95 {color}"
            )
        }
    };

    let stop_only = |ev: leptos::ev::MouseEvent| ev.stop_propagation();

    view! {
        {move || {
            let cur = state.get();
            let cls = btn_class(cur);
            match cur {
                Some(LikeState::Liked) => view! {
                    <button
                        type="button"
                        class=cls
                        aria-pressed="true"
                        aria-label=format!("Remove {kind} from favorites")
                        title=format!("Remove {kind} from favorites")
                        on:click=toggle
                    >
                        <span class="text-base leading-none">{filled}</span>
                        {show_label.then(|| view! { <span class=label_cls>{label_text}</span> })}
                    </button>
                }.into_any(),
                Some(LikeState::NotLiked) => view! {
                    <button
                        type="button"
                        class=cls
                        aria-pressed="false"
                        aria-label=format!("Favorite this {kind}")
                        title=format!("Favorite this {kind}")
                        on:click=toggle
                    >
                        <span class="text-base leading-none">{outline}</span>
                        {show_label.then(|| view! { <span class=label_cls>{label_text}</span> })}
                    </button>
                }.into_any(),
                Some(LikeState::SignedOut) => view! {
                    <a
                        href="/user/login"
                        rel="external"
                        class=cls
                        aria-label=format!("Sign in to favorite this {kind}")
                        title=format!("Sign in to favorite this {kind}")
                        on:click=stop_only
                    >
                        <span class="text-base leading-none">{outline}</span>
                        {show_label.then(|| view! { <span class=label_cls>{label_text}</span> })}
                    </a>
                }.into_any(),
                Some(LikeState::Failed) => view! {
                    <button
                        type="button"
                        class=cls
                        aria-label=format!("Retry loading favorite status for this {kind}")
                        title="Could not load favorite status — click to retry"
                        on:click=retry
                    >
                        <span class="text-base leading-none opacity-75">"\u{21BB}"</span>
                        {show_label.then(|| view! { <span class=label_cls>"Retry"</span> })}
                    </button>
                }.into_any(),
                None => view! {
                    <span
                        class=cls
                        aria-hidden="true"
                        title="Loading favorite status"
                        on:click=stop_only
                    >
                        <span class="text-base leading-none opacity-60">{outline}</span>
                        {show_label.then(|| view! { <span class=format!("opacity-60 {label_cls}")>{label_text}</span> })}
                    </span>
                }.into_any(),
            }
        }}
    }
}
