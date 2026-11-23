//! Browser helpers cleanly gated for client (`csr` / `hydrate`) targets with
//! safe no-op fallbacks during `ssr`.

use leptos::{ev, html, prelude::*};

use crate::models::Density;

pub const GALLERY_DENSITY_KEY: &str = "lets-embed:gallery-density";
pub const FAV_DENSITY_KEY: &str = "lets-embed:fav-density";
pub const SAFETY_CHANNEL_NAME: &str = "lets_embed_safety";
pub const NOTICE_DISMISS_PREFIX: &str = "lets-embed:notice:";

#[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
struct LocalCleanup(Option<Box<dyn FnOnce()>>);

#[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
impl Drop for LocalCleanup {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// Register a `!Send` cleanup hook bound to the current Leptos reactive owner.
#[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
fn on_local_cleanup(f: impl FnOnce() + 'static) {
    let _ = StoredValue::new_local(LocalCleanup(Some(Box::new(f))));
}

/// Load persisted gallery density from `localStorage`.
pub fn load_density() -> Option<Density> {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        let storage = web_sys::window()?.local_storage().ok()??;
        storage
            .get_item(GALLERY_DENSITY_KEY)
            .ok()
            .flatten()
            .and_then(|s| Density::parse(&s))
            .or_else(|| {
                storage
                    .get_item(FAV_DENSITY_KEY)
                    .ok()
                    .flatten()
                    .and_then(|s| Density::parse(&s))
            })
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        None
    }
}

/// Persist gallery density across both shared keys so `/` and `/user/favorites`
/// stay synchronized.
pub fn save_density(density: Density) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            let val = density.as_str();
            let _ = storage.set_item(GALLERY_DENSITY_KEY, val);
            let _ = storage.set_item(FAV_DENSITY_KEY, val);
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = density;
    }
}

/// Sync a [`Density`] signal with `localStorage` on client mount and listen for
/// cross-tab `storage` events.
pub fn use_density_storage_sync(density: RwSignal<Density>) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        Effect::new(move |_| {
            if let Some(saved) = load_density()
                && density.get_untracked() != saved
            {
                density.set(saved);
            }
        });

        if let Some(win) = web_sys::window() {
            let cb = Closure::<dyn Fn(web_sys::StorageEvent)>::new(move |ev: web_sys::StorageEvent| {
                let key = ev.key();
                if matches!(
                    key.as_deref(),
                    Some(GALLERY_DENSITY_KEY) | Some(FAV_DENSITY_KEY)
                ) && let Some(next) = ev.new_value().and_then(|v| Density::parse(&v))
                {
                    let _ = density.try_set(next);
                }
            });
            let _ = win.add_event_listener_with_callback("storage", cb.as_ref().unchecked_ref());
            let win_clean = win.clone();
            on_local_cleanup(move || {
                let _ = win_clean
                    .remove_event_listener_with_callback("storage", cb.as_ref().unchecked_ref());
                drop(cb);
            });
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = density;
    }
}

/// Read whether a dismissible notice key has already been dismissed in `localStorage`.
pub fn load_notice_dismissed(dismiss_key: &str) -> bool {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) else {
            return false;
        };
        let key = format!("{NOTICE_DISMISS_PREFIX}{dismiss_key}");
        storage
            .get_item(&key)
            .ok()
            .flatten()
            .is_some_and(|v| v == "1")
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = dismiss_key;
        false
    }
}

/// Persist notice dismissal in `localStorage`.
pub fn save_notice_dismissed(dismiss_key: &str) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            let key = format!("{NOTICE_DISMISS_PREFIX}{dismiss_key}");
            let _ = storage.set_item(&key, "1");
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = dismiss_key;
    }
}

/// Broadcast a Safe Mode state change across all open tabs on
/// `BroadcastChannel("lets_embed_safety")`.
pub fn broadcast_safe_mode(enabled: bool) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::JsValue;

        if let Ok(ch) = web_sys::BroadcastChannel::new(SAFETY_CHANNEL_NAME) {
            let payload = js_sys::Object::new();
            let _ = js_sys::Reflect::set(
                &payload,
                &JsValue::from_str("type"),
                &JsValue::from_str("safe_mode"),
            );
            let _ = js_sys::Reflect::set(
                &payload,
                &JsValue::from_str("enabled"),
                &JsValue::from_bool(enabled),
            );
            let _ = ch.post_message(&payload);
            ch.close();
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = enabled;
    }
}

/// Subscribe to cross-tab Safe Mode updates on `BroadcastChannel("lets_embed_safety")`.
pub fn use_safe_mode_channel(on_remote: impl Fn(bool) + 'static) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::{JsCast, JsValue, closure::Closure};

        if let Ok(ch) = web_sys::BroadcastChannel::new(SAFETY_CHANNEL_NAME) {
            let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |ev: web_sys::MessageEvent| {
                let data = ev.data();
                if let Some(enabled) = data.as_bool() {
                    on_remote(enabled);
                    return;
                }
                if data.is_object() {
                    let kind = js_sys::Reflect::get(&data, &JsValue::from_str("type"))
                        .ok()
                        .and_then(|v| v.as_string());
                    if kind.as_deref() == Some("safe_mode")
                        && let Some(enabled) =
                            js_sys::Reflect::get(&data, &JsValue::from_str("enabled"))
                                .ok()
                                .and_then(|v| v.as_bool())
                    {
                        on_remote(enabled);
                    }
                }
            });
            ch.set_onmessage(Some(cb.as_ref().unchecked_ref()));
            on_local_cleanup(move || {
                ch.set_onmessage(None);
                ch.close();
                drop(cb);
            });
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = on_remote;
    }
}

/// Observe a container div's width using `ResizeObserver` (with `window` resize fallback)
/// and keep `width_sig` updated. Cleans up automatically on unmount.
pub fn observe_element_width(el_ref: NodeRef<html::Div>, width_sig: RwSignal<f64>) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use std::cell::RefCell;
        use std::rc::Rc;
        use wasm_bindgen::{JsCast, closure::Closure};

        type ResizeObserverHandle = (web_sys::ResizeObserver, Closure<dyn Fn(js_sys::Array)>);

        let observer_slot: Rc<RefCell<Option<ResizeObserverHandle>>> =
            Rc::new(RefCell::new(None));
        let observer_for_effect = observer_slot.clone();

        Effect::new(move |_| {
            let Some(el) = el_ref.get() else {
                return;
            };
            let initial = el.client_width() as f64;
            if initial > 0.0 {
                width_sig.set(initial);
            }

            let mut slot = observer_for_effect.borrow_mut();
            if let Some((prev, _)) = slot.take() {
                prev.disconnect();
            }

            let cb = Closure::<dyn Fn(js_sys::Array)>::new(move |entries: js_sys::Array| {
                for i in 0..entries.length() {
                    if let Ok(entry) = entries.get(i).dyn_into::<web_sys::ResizeObserverEntry>() {
                        let w = entry.content_rect().width();
                        if w > 0.0 {
                            let _ = width_sig.try_set(w);
                        }
                    }
                }
            });
            if let Ok(obs) = web_sys::ResizeObserver::new(cb.as_ref().unchecked_ref()) {
                obs.observe(el.as_ref());
                *slot = Some((obs, cb));
            }
        });

        on_local_cleanup(move || {
            if let Some((obs, cb)) = observer_slot.borrow_mut().take() {
                obs.disconnect();
                drop(cb);
            }
        });
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = (el_ref, width_sig);
    }
}

/// Register a `keydown` listener on `window` that is removed automatically on cleanup.
pub fn use_window_keydown(capture: bool, handler: impl Fn(ev::KeyboardEvent) + 'static) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        if let Some(win) = web_sys::window() {
            let cb = Closure::<dyn Fn(ev::KeyboardEvent)>::new(handler);
            let _ = win.add_event_listener_with_callback_and_bool(
                "keydown",
                cb.as_ref().unchecked_ref(),
                capture,
            );
            let win_clean = win.clone();
            on_local_cleanup(move || {
                let _ = win_clean.remove_event_listener_with_callback_and_bool(
                    "keydown",
                    cb.as_ref().unchecked_ref(),
                    capture,
                );
                drop(cb);
            });
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = (capture, handler);
    }
}

/// Register a `pointerdown` listener on `window` that is removed automatically on cleanup.
pub fn use_window_pointerdown(handler: impl Fn(ev::PointerEvent) + 'static) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        if let Some(win) = web_sys::window() {
            let cb = Closure::<dyn Fn(ev::PointerEvent)>::new(handler);
            let _ =
                win.add_event_listener_with_callback("pointerdown", cb.as_ref().unchecked_ref());
            let win_clean = win.clone();
            on_local_cleanup(move || {
                let _ = win_clean.remove_event_listener_with_callback(
                    "pointerdown",
                    cb.as_ref().unchecked_ref(),
                );
                drop(cb);
            });
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = handler;
    }
}

/// Register a `resize` listener on `window` that is removed automatically on cleanup.
pub fn use_window_resize(handler: impl Fn(ev::Event) + 'static) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        if let Some(win) = web_sys::window() {
            let cb = Closure::<dyn Fn(ev::Event)>::new(handler);
            let _ = win.add_event_listener_with_callback("resize", cb.as_ref().unchecked_ref());
            let win_clean = win.clone();
            on_local_cleanup(move || {
                let _ = win_clean
                    .remove_event_listener_with_callback("resize", cb.as_ref().unchecked_ref());
                drop(cb);
            });
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = handler;
    }
}

/// Register a capture-phase `scroll` listener on `document` that is removed automatically on cleanup.
pub fn use_document_scroll_capture(handler: impl Fn(ev::Event) + 'static) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            let cb = Closure::<dyn Fn(ev::Event)>::new(handler);
            let _ = doc.add_event_listener_with_callback_and_bool(
                "scroll",
                cb.as_ref().unchecked_ref(),
                true,
            );
            let doc_clean = doc.clone();
            on_local_cleanup(move || {
                let _ = doc_clean.remove_event_listener_with_callback_and_bool(
                    "scroll",
                    cb.as_ref().unchecked_ref(),
                    true,
                );
                drop(cb);
            });
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = handler;
    }
}

/// Reference-counted `<body>` scroll lock using `.modal-open` class.
pub fn lock_body_scroll() {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use std::cell::Cell;

        thread_local! {
            static LOCK_COUNT: Cell<usize> = const { Cell::new(0) };
        }

        fn toggle_class(add: bool) {
            if let Some(body) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.body())
            {
                let list = body.class_list();
                let _ = if add {
                    list.add_1("modal-open")
                } else {
                    list.remove_1("modal-open")
                };
            }
        }

        LOCK_COUNT.with(|c| {
            let n = c.get();
            if n == 0 {
                toggle_class(true);
            }
            c.set(n + 1);
        });

        on_cleanup(move || {
            LOCK_COUNT.with(|c| {
                let next = c.get().saturating_sub(1);
                c.set(next);
                if next == 0 {
                    toggle_class(false);
                }
            });
        });
    }
}

/// True when `target` is inside an editable form field (`input`, `textarea`, `select`, `contenteditable`).
pub fn is_editable_target(target: Option<web_sys::EventTarget>) -> bool {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::JsCast;

        let Some(el) = target.and_then(|t| t.dyn_into::<web_sys::Element>().ok()) else {
            return false;
        };
        el.closest("input, textarea, select, [contenteditable='true'], [contenteditable='']")
            .ok()
            .flatten()
            .is_some()
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = target;
        false
    }
}

/// Trap `Tab` / `Shift+Tab` keyboard focus inside an open modal dialog.
pub fn trap_dialog_tab(ev: &ev::KeyboardEvent, dialog: Option<web_sys::HtmlDivElement>) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::JsCast;

        if ev.key() != "Tab" || ev.alt_key() || ev.ctrl_key() || ev.meta_key() {
            return;
        }
        let Some(dlg) = dialog else {
            return;
        };
        let Ok(nodes) = dlg.query_selector_all(
            "a[href]:not([tabindex='-1']):not([inert]), button:not([disabled]):not([tabindex='-1']):not([inert]), \
             input:not([disabled]):not([tabindex='-1']), select:not([disabled]), textarea:not([disabled]), \
             video[controls], [tabindex]:not([tabindex='-1'])",
        ) else {
            return;
        };
        let mut focusables: Vec<web_sys::HtmlElement> = Vec::new();
        for i in 0..nodes.length() {
            if let Some(el) = nodes
                .item(i)
                .and_then(|n| n.dyn_into::<web_sys::HtmlElement>().ok())
                && el.closest("[inert]").ok().flatten().is_none()
            {
                focusables.push(el);
            }
        }
        if focusables.is_empty() {
            ev.prevent_default();
            let _ = dlg.focus();
            return;
        }
        let active = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.active_element());
        let first = &focusables[0];
        let last = &focusables[focusables.len() - 1];
        let inside = active
            .as_ref()
            .is_some_and(|a| dlg.contains(Some(a.as_ref())));
        let is_dlg = active
            .as_ref()
            .is_some_and(|a| a.as_ref() as &web_sys::Node == dlg.as_ref() as &web_sys::Node);
        let is_first = active
            .as_ref()
            .is_some_and(|a| a.as_ref() as &web_sys::Node == first.as_ref() as &web_sys::Node);
        let is_last = active
            .as_ref()
            .is_some_and(|a| a.as_ref() as &web_sys::Node == last.as_ref() as &web_sys::Node);
        if ev.shift_key() && (!inside || is_first || is_dlg) {
            ev.prevent_default();
            let _ = last.focus();
        } else if !ev.shift_key() && (!inside || is_last) {
            ev.prevent_default();
            let _ = first.focus();
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = (ev, dialog);
    }
}

/// Immediately pause all `<video>` elements and clear `src` on all `<video>` and `<img>`
/// elements within `container` (or the whole document if `None`).
///
/// Used when Safe Mode / Panic triggers so restricted frames and media buffers
/// are immediately evicted from active modals and viewers (security finding L1).
pub fn wipe_media_elements_in(container: Option<&web_sys::Element>) {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use wasm_bindgen::JsCast;

        let videos = match container {
            Some(el) => el.query_selector_all("video").ok(),
            None => web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.query_selector_all("video").ok()),
        };
        if let Some(list) = videos {
            for i in 0..list.length() {
                if let Some(v) = list
                    .item(i)
                    .and_then(|n| n.dyn_into::<web_sys::HtmlVideoElement>().ok())
                {
                    let _ = v.pause();
                    let _ = v.remove_attribute("src");
                    v.set_src("");
                    v.load();
                }
            }
        }

        let imgs = match container {
            Some(el) => el.query_selector_all("img").ok(),
            None => web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.query_selector_all("img").ok()),
        };
        if let Some(list) = imgs {
            for i in 0..list.length() {
                if let Some(img) = list
                    .item(i)
                    .and_then(|n| n.dyn_into::<web_sys::HtmlImageElement>().ok())
                {
                    let _ = img.remove_attribute("src");
                    img.set_src("");
                }
            }
        }
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = container;
    }
}

/// Read current viewport width in CSS pixels (returns `0.0` during SSR).
pub fn read_window_width() -> f64 {
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        web_sys::window()
            .and_then(|w| w.inner_width().ok())
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
    }
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        0.0
    }
}
