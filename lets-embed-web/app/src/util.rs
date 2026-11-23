pub fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|seg| urlencoding::encode(seg).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Validate and normalize an `http://` or `https://` origin (no trailing slash,
/// path, query, fragment, or userinfo).
pub fn normalize_public_origin(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let (scheme, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https", r)
    } else {
        ("http", trimmed.strip_prefix("http://")?)
    };
    let host = valid_host_authority(rest)?;
    Some(format!("{scheme}://{host}"))
}

fn valid_host_authority(raw: &str) -> Option<&str> {
    let host = raw.trim();
    if host.is_empty()
        || host.len() > 255
        || host.bytes().any(|b| {
            b <= 0x20
                || b == 0x7f
                || matches!(
                    b,
                    b'/' | b'\\' | b'@' | b'?' | b'#' | b'<' | b'>' | b'"' | b'\''
                )
        })
    {
        return None;
    }
    Some(host)
}

#[cfg(feature = "ssr")]
fn single_header<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    let mut all = headers.get_all(name).iter();
    let first = all.next()?.to_str().ok()?;
    if all.next().is_some() {
        return None;
    }
    Some(first)
}

/// Resolve the public origin (`https://host` or `http://localhost:port`) from
/// reverse-proxy forwarding headers (`X-Forwarded-Host` / `X-Forwarded-Proto`)
/// or the direct `Host` header.
#[cfg(feature = "ssr")]
pub fn origin_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(xfh) = single_header(headers, "x-forwarded-host")
        .and_then(|v| v.split(',').next())
        .and_then(valid_host_authority)
    {
        let proto = single_header(headers, "x-forwarded-proto")
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|p| p.eq_ignore_ascii_case("http") || p.eq_ignore_ascii_case("https"))
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| "https".to_string());
        return Some(format!("{proto}://{xfh}"));
    }
    let host = single_header(headers, "host").and_then(valid_host_authority)?;
    let bare = host.split(':').next().unwrap_or(host);
    let proto = if bare.eq_ignore_ascii_case("localhost") || bare == "127.0.0.1" {
        "http"
    } else {
        "https"
    };
    Some(format!("{proto}://{host}"))
}

/// Resolve the canonical public origin for `<link rel="canonical">` and OpenGraph
/// URLs on both SSR and client hydration.
pub fn public_origin() -> Option<String> {
    #[cfg(feature = "ssr")]
    {
        use leptos::prelude::use_context;
        if let Some(origin) = use_context::<crate::state::AppState>()
            .and_then(|st| st.public_url.as_deref().and_then(normalize_public_origin))
        {
            return Some(origin);
        }
        use_context::<axum::http::request::Parts>().and_then(|p| origin_from_headers(&p.headers))
    }
    #[cfg(all(feature = "hydrate", not(feature = "ssr")))]
    {
        web_sys::window()
            .and_then(|w| w.location().origin().ok())
            .and_then(|o| normalize_public_origin(&o))
    }
    #[cfg(not(any(feature = "ssr", feature = "hydrate")))]
    {
        None
    }
}

/// Format a video duration in seconds as `M:SS` or `H:MM:SS`.
pub fn format_duration(seconds: i32) -> String {
    let s = seconds.max(0) as u64;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let rem = s % 60;
    if h > 0 {
        format!("{h}:{m:02}:{rem:02}")
    } else {
        format!("{m}:{rem:02}")
    }
}

/// Update `document.title` strictly on the client so untrusted search/DB text
/// is never interpolated raw into the SSR `<title>` tag and never leaks
/// `leptos_meta`'s title stack across navigations.
pub fn set_document_title(text: &str) {
    #[cfg(feature = "hydrate")]
    {
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            let full = if text.trim().is_empty() {
                "Let's Embed".to_string()
            } else {
                format!("{text} - Let's Embed")
            };
            doc.set_title(&full);
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = text;
    }
}

/// Reference-counted `<body>` scroll lock for stacked modals (`Lightbox` + `Viewer`).
/// Toggles a dedicated `.modal-open` class so any pre-existing inline `overflow`
/// style on `<body>` is preserved when the outermost modal closes.
pub fn lock_body_scroll() {
    #[cfg(feature = "hydrate")]
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

        leptos::prelude::on_cleanup(move || {
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

/// Push a synthetic same-URL browser history entry while a modal (`Lightbox` or
/// `Viewer`) is mounted so pressing Back on mobile closes the topmost modal
/// instead of navigating away from the page.
///
/// Supports stacked modals (e.g. `Lightbox` -> `Viewer`), multi-step Back
/// (`history.go(-k)`), rapid close+reopen serialization, and restoring focus
/// to the previously focused trigger element when the modal closes.
pub fn push_modal_history(on_back: impl Fn() + 'static) {
    #[cfg(feature = "hydrate")]
    {
        modal_history::push(on_back);
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = on_back;
    }
}

/// Navigate away from inside a modal without leaving synthetic modal history
/// entries behind or racing with queued `history.back()` pops.
///
/// - If `dest` equals the current `pathname + search + hash`, simply runs
///   `close_modals()` without navigating (preventing duplicate history entries).
/// - Otherwise drains the modal history stack, unwinds any extra stacked entries
///   (`k > 1`) via `history.go(-(k-1))`, closes modals, and invokes `do_nav`
///   with `replace = true` so the destination cleanly replaces the modal entry.
pub fn navigate_from_modal(
    dest: String,
    close_modals: impl FnOnce(),
    do_nav: impl FnOnce(&str, bool) + 'static,
) {
    #[cfg(feature = "hydrate")]
    {
        modal_history::navigate(dest, close_modals, do_nav);
    }
    #[cfg(not(feature = "hydrate"))]
    {
        close_modals();
        do_nav(&dest, false);
    }
}

/// Keep `Tab` / `Shift+Tab` keyboard focus trapped inside an open modal dialog
/// so users cannot accidentally tab into background controls (e.g. `<SearchBar>`).
pub fn trap_dialog_tab(ev: &leptos::ev::KeyboardEvent, dialog: Option<web_sys::HtmlDivElement>) {
    #[cfg(feature = "hydrate")]
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
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (ev, dialog);
    }
}

#[cfg(feature = "hydrate")]
mod modal_history {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};

    const STATE_KEY: &str = "__le_modal";
    type DeferredAction = Box<dyn FnOnce()>;

    struct ModalEntry {
        token: u64,
        pushed: bool,
        close_fn: Rc<dyn Fn()>,
        prev_focus: Option<web_sys::HtmlElement>,
    }

    thread_local! {
        static NEXT_TOKEN: Cell<u64> = const { Cell::new(1) };
        static STACK: RefCell<Vec<ModalEntry>> = const { RefCell::new(Vec::new()) };
        static PENDING_BACKS: Cell<usize> = const { Cell::new(0) };
        static DEFERRED: RefCell<Vec<DeferredAction>> = const { RefCell::new(Vec::new()) };
        static INSTALLED: Cell<bool> = const { Cell::new(false) };
    }

    fn state_token(state: &JsValue) -> Option<u64> {
        if state.is_null() || state.is_undefined() || !state.is_object() {
            return None;
        }
        js_sys::Reflect::get(state, &JsValue::from_str(STATE_KEY))
            .ok()
            .and_then(|v| v.as_f64())
            .filter(|f| f.is_finite() && *f >= 1.0)
            .map(|f| f as u64)
    }

    fn current_relative_url() -> Option<String> {
        let loc = web_sys::window()?.location();
        let path = loc.pathname().ok()?;
        let search = loc.search().ok().unwrap_or_default();
        let hash = loc.hash().ok().unwrap_or_default();
        Some(format!("{path}{search}{hash}"))
    }

    fn restore_focus(prev: Option<web_sys::HtmlElement>) {
        if let Some(el) = prev
            && el.is_connected()
        {
            let _ = el.focus();
        }
    }

    fn flush_deferred() {
        while PENDING_BACKS.with(|c| c.get() == 0) {
            let next = DEFERRED.with(|q| {
                let mut q = q.borrow_mut();
                if q.is_empty() {
                    None
                } else {
                    Some(q.remove(0))
                }
            });
            match next {
                Some(action) => action(),
                None => break,
            }
        }
    }

    fn push_state_for_token(token: u64) {
        let should_push = STACK.with(|s| {
            let mut stack = s.borrow_mut();
            if let Some(entry) = stack.iter_mut().find(|e| e.token == token) {
                if entry.pushed {
                    return false;
                }
                entry.pushed = true;
                true
            } else {
                false
            }
        });
        if !should_push {
            return;
        }
        let Some(win) = web_sys::window() else {
            return;
        };
        let Ok(history) = win.history() else {
            return;
        };
        let Ok(href) = win.location().href() else {
            return;
        };
        let state = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &state,
            &JsValue::from_str(STATE_KEY),
            &JsValue::from_f64(token as f64),
        );
        if history
            .push_state_with_url(&state, "", Some(&href))
            .is_err()
        {
            STACK.with(|s| {
                if let Some(e) = s.borrow_mut().iter_mut().find(|e| e.token == token) {
                    e.pushed = false;
                }
            });
        }
    }

    fn ensure_listener() {
        INSTALLED.with(|installed| {
            if installed.get() {
                return;
            }
            let Some(win) = web_sys::window() else {
                return;
            };
            let cb = Closure::<dyn Fn(web_sys::PopStateEvent)>::new(
                move |ev: web_sys::PopStateEvent| {
                    let suppressed = PENDING_BACKS.with(|c| {
                        let n = c.get();
                        if n > 0 {
                            c.set(n - 1);
                            true
                        } else {
                            false
                        }
                    });
                    if suppressed {
                        flush_deferred();
                        return;
                    }
                    // Synchronize `STACK` with the history state we actually landed on
                    // (handles single Back, multi-step `history.go(-k)`, and route exits).
                    let landed = state_token(&ev.state());
                    let to_close: Vec<ModalEntry> = STACK.with(|s| {
                        let mut stack = s.borrow_mut();
                        if stack.is_empty() {
                            return Vec::new();
                        }
                        match landed.and_then(|t| stack.iter().position(|e| e.token == t)) {
                            Some(idx) => stack.drain((idx + 1)..).rev().collect(),
                            None => stack.drain(..).rev().collect(),
                        }
                    });
                    let mut restore = None;
                    for entry in to_close {
                        (entry.close_fn)();
                        restore = entry.prev_focus;
                    }
                    restore_focus(restore);
                },
            );
            if win
                .add_event_listener_with_callback("popstate", cb.as_ref().unchecked_ref())
                .is_ok()
            {
                cb.forget();
                installed.set(true);
            }
        });
    }

    pub fn push(on_back: impl Fn() + 'static) {
        ensure_listener();
        let prev_focus = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.active_element())
            .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok());

        let token = NEXT_TOKEN.with(|n| {
            let t = n.get();
            n.set(t.wrapping_add(1).max(1));
            t
        });
        STACK.with(|s| {
            s.borrow_mut().push(ModalEntry {
                token,
                pushed: false,
                close_fn: Rc::new(on_back),
                prev_focus,
            });
        });

        if PENDING_BACKS.with(|c| c.get() > 0) {
            DEFERRED.with(|q| {
                q.borrow_mut()
                    .push(Box::new(move || push_state_for_token(token)));
            });
        } else {
            push_state_for_token(token);
        }

        leptos::prelude::on_cleanup(move || {
            let removed = STACK.with(|s| {
                let mut stack = s.borrow_mut();
                stack
                    .iter()
                    .position(|e| e.token == token)
                    .map(|pos| stack.remove(pos))
            });
            let Some(entry) = removed else {
                return;
            };
            restore_focus(entry.prev_focus);
            if entry.pushed
                && let Some(hist) = web_sys::window().and_then(|w| w.history().ok())
                && state_token(&hist.state().unwrap_or(JsValue::NULL)) == Some(token)
            {
                PENDING_BACKS.with(|c| c.set(c.get().saturating_add(1)));
                let _ = hist.back();
            }
        });
    }

    pub fn navigate(
        dest: String,
        close_modals: impl FnOnce(),
        do_nav: impl FnOnce(&str, bool) + 'static,
    ) {
        // Navigating to the exact current URL (e.g. clicking Details while already
        // on that same `/details/:id` page) simply closes the modal cleanly so
        // `on_cleanup` pops the synthetic entry without creating duplicates.
        if current_relative_url().as_deref() == Some(dest.as_str()) {
            close_modals();
            return;
        }

        let pushed_count = STACK.with(|s| s.borrow_mut().drain(..).filter(|e| e.pushed).count());
        close_modals();

        if pushed_count == 0 {
            if PENDING_BACKS.with(|c| c.get() > 0) {
                DEFERRED.with(|q| {
                    q.borrow_mut().push(Box::new(move || do_nav(&dest, false)));
                });
            } else {
                do_nav(&dest, false);
            }
            return;
        }

        if pushed_count == 1 {
            if PENDING_BACKS.with(|c| c.get() > 0) {
                DEFERRED.with(|q| {
                    q.borrow_mut().push(Box::new(move || do_nav(&dest, true)));
                });
            } else {
                do_nav(&dest, true);
            }
            return;
        }

        // Stacked modals (`k > 1`, e.g. Lightbox -> Viewer): unwind `k - 1`
        // entries via a single `history.go(-(k - 1))`, then replace the bottom
        // modal entry with `dest` so ZERO orphan entries remain in history.
        let unwind = -((pushed_count - 1) as i32);
        let run_unwind = move || {
            if let Some(hist) = web_sys::window().and_then(|w| w.history().ok()) {
                PENDING_BACKS.with(|c| c.set(c.get().saturating_add(1)));
                DEFERRED.with(|q| {
                    q.borrow_mut().push(Box::new(move || do_nav(&dest, true)));
                });
                let _ = hist.go_with_delta(unwind);
            } else {
                do_nav(&dest, true);
            }
        };
        if PENDING_BACKS.with(|c| c.get() > 0) {
            DEFERRED.with(|q| q.borrow_mut().push(Box::new(run_unwind)));
        } else {
            run_unwind();
        }
    }
}

/// Best-effort async client-side clipboard copy via `navigator.clipboard.writeText`,
/// returning `true` only once the returned `Promise` actually fulfills.
#[cfg(feature = "hydrate")]
pub async fn copy_to_clipboard(text: &str) -> bool {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let Some(window) = web_sys::window() else {
        return false;
    };
    let Ok(navigator) = js_sys::Reflect::get(&window, &JsValue::from_str("navigator")) else {
        return false;
    };
    let Ok(clipboard) = js_sys::Reflect::get(&navigator, &JsValue::from_str("clipboard")) else {
        return false;
    };
    let Ok(write_fn) = js_sys::Reflect::get(&clipboard, &JsValue::from_str("writeText")) else {
        return false;
    };
    let Ok(func) = write_fn.dyn_into::<js_sys::Function>() else {
        return false;
    };
    let Ok(ret) = func.call1(&clipboard, &JsValue::from_str(text)) else {
        return false;
    };
    let Ok(promise) = ret.dyn_into::<js_sys::Promise>() else {
        return false;
    };
    JsFuture::from(promise).await.is_ok()
}

/// Distribute images into `col_count` masonry columns by picking the shortest
/// running column height (using each image's natural `height / width` ratio),
/// preserving each image's original index for `<Viewer>` navigation.
pub fn layout_image_masonry(
    images: &[search_types::Image],
    col_count: usize,
) -> Vec<Vec<(usize, search_types::Image)>> {
    let n = col_count.max(1);
    let mut cols: Vec<Vec<(usize, search_types::Image)>> = (0..n).map(|_| Vec::new()).collect();
    let mut heights = vec![0.0f64; n];
    for (idx, im) in images.iter().enumerate() {
        let shortest = heights
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.total_cmp(b))
            .map(|(i, _)| i)
            .unwrap_or(0);
        let ratio = if im.width > 0 && im.height > 0 {
            f64::from(im.height) / f64::from(im.width)
        } else {
            0.75
        };
        heights[shortest] += ratio + 0.05;
        cols[shortest].push((idx, im.clone()));
    }
    cols
}

#[cfg(test)]
mod tests {
    use super::{format_duration, layout_image_masonry, normalize_public_origin};
    use search_types::Image;

    #[test]
    fn normalizes_valid_public_origins_and_rejects_malformed_values() {
        assert_eq!(
            normalize_public_origin("https://lets-embed.louisfly.icu/").as_deref(),
            Some("https://lets-embed.louisfly.icu")
        );
        assert_eq!(
            normalize_public_origin("http://127.0.0.1:3000").as_deref(),
            Some("http://127.0.0.1:3000")
        );
        assert_eq!(normalize_public_origin("https://example.com/path"), None);
        assert_eq!(normalize_public_origin("javascript:alert(1)"), None);
        assert_eq!(normalize_public_origin("https://user@example.com"), None);
        assert_eq!(normalize_public_origin(""), None);
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn resolves_origin_from_forwarded_or_host_headers() {
        use super::origin_from_headers;
        use axum::http::HeaderMap;

        let mut h = HeaderMap::new();
        h.insert("host", "lets-embed-web.louisfly.icu".parse().unwrap());
        h.insert(
            "x-forwarded-host",
            "lets-embed.louisfly.icu".parse().unwrap(),
        );
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(
            origin_from_headers(&h).as_deref(),
            Some("https://lets-embed.louisfly.icu")
        );

        let mut local = HeaderMap::new();
        local.insert("host", "127.0.0.1:3000".parse().unwrap());
        assert_eq!(
            origin_from_headers(&local).as_deref(),
            Some("http://127.0.0.1:3000")
        );
    }

    #[test]
    fn formats_seconds_minutes_and_hours() {
        assert_eq!(format_duration(0), "0:00");
        assert_eq!(format_duration(9), "0:09");
        assert_eq!(format_duration(84), "1:24");
        assert_eq!(format_duration(3665), "1:01:05");
        assert_eq!(format_duration(-5), "0:00");
    }

    #[test]
    fn layout_image_masonry_balances_column_heights_and_preserves_indices() {
        let imgs = vec![
            Image {
                id: 1,
                name: "tall".into(),
                width: 500,
                height: 1500,
            },
            Image {
                id: 2,
                name: "wide1".into(),
                width: 1000,
                height: 500,
            },
            Image {
                id: 3,
                name: "wide2".into(),
                width: 1000,
                height: 500,
            },
            Image {
                id: 4,
                name: "sq".into(),
                width: 800,
                height: 800,
            },
        ];
        let cols = layout_image_masonry(&imgs, 2);
        assert_eq!(cols.len(), 2);
        // Col 0 gets tall (ratio 3.0); Col 1 gets wide1 (0.5), wide2 (0.5), sq (1.0) -> balanced!
        assert_eq!(cols[0].iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0]);
        assert_eq!(
            cols[1].iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }
}
