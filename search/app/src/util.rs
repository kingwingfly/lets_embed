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
