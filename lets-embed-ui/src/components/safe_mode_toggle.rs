use leptos::{ev, prelude::*};

use crate::browser::{
    broadcast_safe_mode, is_editable_target, use_safe_mode_channel, use_window_keydown,
};

/// Programmatically toggle Safe Mode, bump `panic_epoch` when activating Safe Mode,
/// optionally broadcast across tabs via `BroadcastChannel("lets_embed_safety")`,
/// and invoke `on_toggle`.
pub fn apply_safe_mode_change(
    safe_mode: RwSignal<bool>,
    panic_epoch: Option<RwSignal<u64>>,
    next: bool,
    broadcast: bool,
    on_toggle: Option<Callback<bool>>,
) {
    safe_mode.set(next);
    if next && let Some(epoch) = panic_epoch {
        epoch.update(|e| *e = e.wrapping_add(1));
    }
    if broadcast {
        broadcast_safe_mode(next);
    }
    if let Some(cb) = on_toggle {
        cb.run(next);
    }
}

/// 1-click Safe Mode / Panic button with:
/// - Global `Shift+S` hotkey listener (ignored inside text inputs/textareas/selects)
/// - `BroadcastChannel("lets_embed_safety")` cross-tab synchronization
/// - Automatic `panic_epoch` increment whenever Safe Mode activates so open
///   [`Lightbox`](crate::components::Lightbox), [`Viewer`](crate::components::Viewer),
///   and [`SpoilerOverlay`](crate::components::SpoilerOverlay) components immediately
///   close/re-blur and wipe media sources.
#[component]
pub fn SafeModeToggle(
    safe_mode: RwSignal<bool>,
    #[prop(optional)] panic_epoch: Option<RwSignal<u64>>,
    #[prop(default = true)] enable_hotkey: bool,
    #[prop(default = true)] sync_tabs: bool,
    #[prop(default = false)] compact: bool,
    #[prop(optional)] on_toggle: Option<Callback<bool>>,
) -> impl IntoView {
    if sync_tabs {
        use_safe_mode_channel(move |remote_enabled| {
            let changed = safe_mode.get_untracked() != remote_enabled;
            if changed {
                safe_mode.set(remote_enabled);
            }
            if remote_enabled && let Some(epoch) = panic_epoch {
                epoch.update(|e| *e = e.wrapping_add(1));
            }
            if changed && let Some(cb) = on_toggle {
                cb.run(remote_enabled);
            }
        });
    }

    if enable_hotkey {
        use_window_keydown(false, move |ev: ev::KeyboardEvent| {
            if ev.default_prevented()
                || ev.is_composing()
                || ev.key_code() == 229
                || ev.ctrl_key()
                || ev.alt_key()
                || ev.meta_key()
                || !ev.shift_key()
            {
                return;
            }
            if is_editable_target(ev.target()) {
                return;
            }
            let key = ev.key();
            if key == "S" || key == "s" {
                ev.prevent_default();
                let next = !safe_mode.get_untracked();
                apply_safe_mode_change(safe_mode, panic_epoch, next, sync_tabs, on_toggle);
            }
        });
    }

    let toggle_click = move |_| {
        let next = !safe_mode.get_untracked();
        apply_safe_mode_change(safe_mode, panic_epoch, next, sync_tabs, on_toggle);
    };

    view! {
        <button
            type="button"
            class=move || {
                let mut cls = String::from("le-safe-toggle");
                if safe_mode.get() {
                    cls.push_str(" is-active");
                }
                if compact {
                    cls.push_str(" le-safe-toggle--compact");
                }
                cls
            }
            aria-pressed=move || safe_mode.get().to_string()
            aria-label=move || {
                if safe_mode.get() {
                    "Safe Mode active — click or press Shift+S to turn off"
                } else {
                    "Enable Safe Mode immediately (Shift+S)"
                }
            }
            title="Toggle Safe Mode (Shift+S)"
            on:click=toggle_click
        >
            <svg
                class="le-safe-toggle-icon"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                aria-hidden="true"
            >
                <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    d="M12 3l7 3v5c0 5-3.2 8.8-7 10-3.8-1.2-7-5-7-10V6l7-3z"
                />
                {move || safe_mode.get().then(|| view! {
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4" />
                })}
            </svg>
            <span class="le-safe-toggle-label">
                {move || if safe_mode.get() { "Safe Mode ON" } else { "Safe Mode" }}
            </span>
            {(!compact).then(|| view! {
                <kbd class="le-safe-toggle-kbd" aria-hidden="true">"Shift+S"</kbd>
            })}
        </button>
    }
}
