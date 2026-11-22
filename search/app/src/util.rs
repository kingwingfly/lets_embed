pub fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|seg| urlencoding::encode(seg).into_owned())
        .collect::<Vec<_>>()
        .join("/")
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
/// Supports stacked modals (e.g. `Lightbox` -> `Viewer`): Back pops only the top
/// layer first, then the lower layer on the next Back press. Manual dismissal
/// (Close button / Esc / backdrop) cleans up its own synthetic entry via
/// `history.back()`. Call [`prepare_modal_navigation`] before navigating from
/// inside a modal so the route transition replaces the modal entry cleanly.
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

/// Detach any active modal history entries right before navigating to another
/// route from inside a modal. Returns `true` when the caller should pass
/// `NavigateOptions { replace: true, .. }` so the route navigation overwrites
/// the top modal's synthetic history entry instead of leaving a dead Back step.
pub fn prepare_modal_navigation() -> bool {
    #[cfg(feature = "hydrate")]
    {
        modal_history::prepare_navigation()
    }
    #[cfg(not(feature = "hydrate"))]
    {
        false
    }
}

#[cfg(feature = "hydrate")]
mod modal_history {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};

    const STATE_KEY: &str = "__le_modal";
    type ModalEntry = (u64, Rc<dyn Fn()>);

    thread_local! {
        static NEXT_TOKEN: Cell<u64> = const { Cell::new(1) };
        static STACK: RefCell<Vec<ModalEntry>> = const { RefCell::new(Vec::new()) };
        static SUPPRESS_POPS: Cell<usize> = const { Cell::new(0) };
        static ORPHAN_TOKENS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
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
                    let suppressed = SUPPRESS_POPS.with(|c| {
                        let n = c.get();
                        if n > 0 {
                            c.set(n - 1);
                            true
                        } else {
                            false
                        }
                    });
                    if suppressed {
                        return;
                    }
                    let top = STACK.with(|s| s.borrow_mut().pop());
                    if let Some((_, close_fn)) = top {
                        close_fn();
                        return;
                    }
                    if let Some(tok) = state_token(&ev.state()) {
                        let is_orphan = ORPHAN_TOKENS.with(|o| {
                            let mut list = o.borrow_mut();
                            if list.last().copied() == Some(tok) {
                                list.pop();
                                true
                            } else {
                                false
                            }
                        });
                        if is_orphan
                            && let Some(hist) = web_sys::window().and_then(|w| w.history().ok())
                        {
                            let _ = hist.back();
                        }
                    }
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
        let Some(win) = web_sys::window() else {
            return;
        };
        let Ok(history) = win.history() else {
            return;
        };
        let Ok(href) = win.location().href() else {
            return;
        };

        let token = NEXT_TOKEN.with(|n| {
            let t = n.get();
            n.set(t.wrapping_add(1).max(1));
            t
        });
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
            return;
        }

        STACK.with(|s| s.borrow_mut().push((token, Rc::new(on_back))));

        leptos::prelude::on_cleanup(move || {
            let still_active = STACK.with(|s| {
                let mut stack = s.borrow_mut();
                if let Some(pos) = stack.iter().position(|(t, _)| *t == token) {
                    stack.remove(pos);
                    true
                } else {
                    false
                }
            });
            if still_active && let Some(hist) = web_sys::window().and_then(|w| w.history().ok()) {
                SUPPRESS_POPS.with(|c| c.set(c.get().saturating_add(1)));
                let _ = hist.back();
            }
        });
    }

    pub fn prepare_navigation() -> bool {
        let tokens: Vec<u64> = STACK.with(|s| s.borrow_mut().drain(..).map(|(t, _)| t).collect());
        if tokens.is_empty() {
            return false;
        }
        // The topmost entry is replaced by the upcoming `replace: true` navigation;
        // any lower stacked entries (e.g. Lightbox beneath Viewer) are recorded so
        // pressing Back from the destination skips straight over them.
        if tokens.len() > 1 {
            ORPHAN_TOKENS.with(|o| {
                o.borrow_mut()
                    .extend_from_slice(&tokens[..tokens.len() - 1])
            });
        }
        true
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

#[cfg(test)]
mod tests {
    use super::format_duration;

    #[test]
    fn formats_seconds_minutes_and_hours() {
        assert_eq!(format_duration(0), "0:00");
        assert_eq!(format_duration(9), "0:09");
        assert_eq!(format_duration(84), "1:24");
        assert_eq!(format_duration(3665), "1:01:05");
        assert_eq!(format_duration(-5), "0:00");
    }
}
