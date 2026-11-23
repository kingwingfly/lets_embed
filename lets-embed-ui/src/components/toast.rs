use std::sync::atomic::{AtomicU64, Ordering};

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

static NEXT_TOAST_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum number of concurrent floating toasts displayed in [`ToastHost`].
pub const MAX_VISIBLE_TOASTS: usize = 5;

/// Semantic severity/style of a floating notification in [`ToastHost`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToastKind {
    Success,
    Error,
    Warning,
    #[default]
    Info,
}

impl ToastKind {
    pub const ALL: [Self; 4] = [Self::Success, Self::Error, Self::Warning, Self::Info];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }

    /// Default auto-dismiss timeout in milliseconds (paused while hovered or focused).
    pub const fn default_duration_ms(self) -> u64 {
        match self {
            Self::Success | Self::Info => 5_000,
            Self::Warning => 8_000,
            Self::Error => 10_000,
        }
    }

    pub const fn aria_role(self) -> &'static str {
        match self {
            Self::Error => "alert",
            Self::Success | Self::Warning | Self::Info => "status",
        }
    }

    pub const fn aria_live(self) -> &'static str {
        match self {
            Self::Error => "assertive",
            Self::Success | Self::Warning | Self::Info => "polite",
        }
    }
}

/// Single notification entry rendered inside [`ToastHost`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToastItem {
    pub id: u64,
    pub kind: ToastKind,
    pub title: String,
    #[serde(default)]
    pub detail: Option<String>,
}

/// Cloneable, `Copy`, context-providable store managing floating top-right toasts.
#[derive(Clone, Copy, Debug)]
pub struct ToastStore {
    items: RwSignal<Vec<ToastItem>>,
}

impl Default for ToastStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ToastStore {
    pub fn new() -> Self {
        Self {
            items: RwSignal::new(Vec::new()),
        }
    }

    /// Reactive signal containing the active toasts (oldest first, newest at bottom).
    pub fn signal(self) -> RwSignal<Vec<ToastItem>> {
        self.items
    }

    /// Snapshot of currently queued toasts.
    pub fn items(self) -> Vec<ToastItem> {
        self.items.get_untracked()
    }

    /// Push a toast of any [`ToastKind`] and return its unique ID.
    pub fn push(self, kind: ToastKind, title: impl Into<String>, detail: Option<String>) -> u64 {
        let id = NEXT_TOAST_ID.fetch_add(1, Ordering::Relaxed);
        let detail = detail
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty());
        let item = ToastItem {
            id,
            kind,
            title: title.into(),
            detail,
        };
        let _ = self.items.try_update(|list| {
            list.push(item);
            if list.len() > MAX_VISIBLE_TOASTS {
                let drop_count = list.len() - MAX_VISIBLE_TOASTS;
                list.drain(0..drop_count);
            }
        });
        id
    }

    pub fn success(self, title: impl Into<String>, detail: Option<String>) -> u64 {
        self.push(ToastKind::Success, title, detail)
    }

    pub fn error(self, title: impl Into<String>, detail: Option<String>) -> u64 {
        self.push(ToastKind::Error, title, detail)
    }

    pub fn warning(self, title: impl Into<String>, detail: Option<String>) -> u64 {
        self.push(ToastKind::Warning, title, detail)
    }

    pub fn info(self, title: impl Into<String>, detail: Option<String>) -> u64 {
        self.push(ToastKind::Info, title, detail)
    }

    /// Dismiss a single toast by ID.
    pub fn dismiss(self, id: u64) {
        let _ = self.items.try_update(|list| {
            list.retain(|item| item.id != id);
        });
    }

    /// Dismiss all active toasts.
    pub fn clear(self) {
        let _ = self.items.try_update(Vec::clear);
    }
}

/// Provide a [`ToastStore`] in the current Leptos reactive context and return its handle.
///
/// If a [`ToastStore`] was already provided in this context scope, returns the existing handle.
pub fn provide_toast_store() -> ToastStore {
    if let Some(existing) = use_context::<ToastStore>() {
        return existing;
    }
    let store = ToastStore::new();
    provide_context(store);
    store
}

/// Retrieve the active [`ToastStore`] from context (creating and providing one if absent).
pub fn use_toast_store() -> ToastStore {
    use_context::<ToastStore>().unwrap_or_else(provide_toast_store)
}

#[component]
fn ToastIcon(kind: ToastKind) -> impl IntoView {
    match kind {
        ToastKind::Success => view! {
            <svg class="le-toast-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                <circle cx="10" cy="10" r="8" />
                <path stroke-linecap="round" stroke-linejoin="round" d="M6.5 10.2l2.3 2.3 4.7-4.8" />
            </svg>
        }
        .into_any(),
        ToastKind::Error => view! {
            <svg class="le-toast-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                <circle cx="10" cy="10" r="8" />
                <path stroke-linecap="round" d="M10 6.2v4.3" />
                <circle cx="10" cy="13.8" r="0.9" fill="currentColor" stroke="none" />
            </svg>
        }
        .into_any(),
        ToastKind::Warning => view! {
            <svg class="le-toast-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.9" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" d="M10 2.8L18 16.5H2L10 2.8z" />
                <path stroke-linecap="round" d="M10 8v3.6" />
                <circle cx="10" cy="14.2" r="0.85" fill="currentColor" stroke="none" />
            </svg>
        }
        .into_any(),
        ToastKind::Info => view! {
            <svg class="le-toast-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                <circle cx="10" cy="10" r="8" />
                <path stroke-linecap="round" d="M10 9.2v4.6" />
                <circle cx="10" cy="6.4" r="0.9" fill="currentColor" stroke="none" />
            </svg>
        }
        .into_any(),
    }
}

#[component]
fn ToastCard(item: ToastItem, store: ToastStore) -> impl IntoView {
    let id = item.id;
    let kind = item.kind;
    let duration_ms = kind.default_duration_ms();
    let paused = RwSignal::new(false);

    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    {
        use std::time::Duration;

        let remaining_ms = StoredValue::new(duration_ms);
        let started_at = StoredValue::new(Option::<f64>::None);
        let handle = StoredValue::new_local(Option::<TimeoutHandle>::None);

        Effect::new(move |_| {
            let is_paused = paused.get();
            if is_paused {
                if let Some(h) = handle.try_update_value(|slot| slot.take()).flatten() {
                    h.clear();
                }
                if let Some(started) = started_at.get_value() {
                    let elapsed = (js_sys::Date::now() - started).max(0.0) as u64;
                    let next_rem = remaining_ms.get_value().saturating_sub(elapsed).max(800);
                    remaining_ms.set_value(next_rem);
                    started_at.set_value(None);
                }
            } else {
                if let Some(h) = handle.try_update_value(|slot| slot.take()).flatten() {
                    h.clear();
                }
                let rem = remaining_ms.get_value();
                started_at.set_value(Some(js_sys::Date::now()));
                if let Ok(next_handle) = set_timeout_with_handle(
                    move || {
                        store.dismiss(id);
                    },
                    Duration::from_millis(rem),
                ) {
                    let _ = handle.try_set_value(Some(next_handle));
                }
            }
        });

        on_cleanup(move || {
            if let Some(h) = handle.try_update_value(|slot| slot.take()).flatten() {
                h.clear();
            }
        });
    }

    let kind_slug = kind.as_str();
    let progress_style = format!("--le-toast-duration: {duration_ms}ms;");

    view! {
        <div
            class=move || {
                if paused.get() {
                    format!("le-toast le-toast--{kind_slug} is-paused")
                } else {
                    format!("le-toast le-toast--{kind_slug}")
                }
            }
            role=kind.aria_role()
            aria-live=kind.aria_live()
            aria-atomic="true"
            style=progress_style
            on:mouseenter=move |_| paused.set(true)
            on:mouseleave=move |_| paused.set(false)
            on:focusin=move |_| paused.set(true)
            on:focusout=move |_| paused.set(false)
        >
            <span class="le-toast-accent" aria-hidden="true"></span>
            <div class="le-toast-icon-wrap">
                <ToastIcon kind=kind />
            </div>
            <div class="le-toast-body">
                <div class="le-toast-title">{item.title}</div>
                {item.detail.map(|detail| view! {
                    <div class="le-toast-detail">{detail}</div>
                })}
            </div>
            <button
                type="button"
                class="le-toast-close"
                aria-label="Dismiss notification"
                title="Dismiss"
                on:click=move |_| store.dismiss(id)
            >
                "\u{00D7}"
            </button>
            <span class="le-toast-progress" aria-hidden="true"></span>
        </div>
    }
}

/// Google Cloud Console-style fixed top-right floating toast host.
///
/// Mount once near the root of an app (`/`, `/admin`, `/user/*`) after calling
/// [`provide_toast_store`]. Always stays visible regardless of scroll position.
#[component]
pub fn ToastHost(#[prop(optional)] store: Option<ToastStore>) -> impl IntoView {
    let store = store.unwrap_or_else(use_toast_store);
    let items_sig = store.signal();

    view! {
        <div
            class="le-toast-host"
            role="region"
            aria-label="Notifications"
            aria-live="polite"
        >
            <For
                each=move || items_sig.get()
                key=|item| item.id
                let(item)
            >
                <ToastCard item=item store=store />
            </For>
        </div>
    }
}
