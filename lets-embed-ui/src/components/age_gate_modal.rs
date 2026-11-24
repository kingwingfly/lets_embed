use std::sync::atomic::{AtomicUsize, Ordering};

use leptos::{ev, html, prelude::*};

use crate::browser::{
    is_top_modal, lock_body_scroll, push_modal_layer, trap_dialog_tab, use_window_keydown,
};

static NEXT_AGE_GATE_ID: AtomicUsize = AtomicUsize::new(1);

/// Default legal notice displayed inside [`AgeGateModal`].
pub const AGE_GATE_LEGAL_COPY: &str =
    "You must be 18 years or older to view restricted content on this site.";

/// Shared 18+ age verification modal supporting both dismissible just-in-time
/// unlock gates (`on_close = Some(...)`) and mandatory first-visit gates
/// (`on_close = None`).
///
/// Features:
/// - Prominent yellow/amber `18+` warning badge & backdrop blur
/// - Clear legal copy + contextual account/session subtitle
/// - Accessible `role="dialog"`, `aria-modal="true"`, `Tab` focus trap, body scroll lock,
///   and `Escape` dismissal when `on_close` is provided
/// - 100% SSR / hydrate / CSR safe
#[component]
pub fn AgeGateModal(
    #[prop(into)] open: Signal<bool>,
    #[prop(optional, into)] title: Option<Signal<String>>,
    #[prop(optional, into)] subtitle: Option<Signal<String>>,
    #[prop(optional, into)] is_authenticated: Option<Signal<bool>>,
    #[prop(optional, into)] submitting: Option<Signal<bool>>,
    #[prop(optional, into)] error: Option<Signal<Option<String>>>,
    on_confirm: Callback<()>,
    #[prop(optional)] on_leave: Option<Callback<()>>,
    #[prop(optional)] on_close: Option<Callback<()>>,
) -> impl IntoView {
    view! {
        {move || {
            open.get().then(|| view! {
                <AgeGateModalInner
                    title=title
                    subtitle=subtitle
                    is_authenticated=is_authenticated
                    submitting=submitting
                    error=error
                    on_confirm=on_confirm
                    on_leave=on_leave
                    on_close=on_close
                />
            })
        }}
    }
}

#[component]
fn AgeGateModalInner(
    title: Option<Signal<String>>,
    subtitle: Option<Signal<String>>,
    is_authenticated: Option<Signal<bool>>,
    submitting: Option<Signal<bool>>,
    error: Option<Signal<Option<String>>>,
    on_confirm: Callback<()>,
    on_leave: Option<Callback<()>>,
    on_close: Option<Callback<()>>,
) -> impl IntoView {
    lock_body_scroll();
    let modal_layer = push_modal_layer();

    let modal_id = NEXT_AGE_GATE_ID.fetch_add(1, Ordering::Relaxed);
    let title_id = format!("le-age-gate-title-{modal_id}");
    let desc_id = format!("le-age-gate-desc-{modal_id}");
    let dialog_ref = NodeRef::<html::Div>::new();

    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    Effect::new(move |_| {
        if let Some(el) = dialog_ref.get() {
            let _ = el.focus();
        }
    });

    use_window_keydown(false, move |e: ev::KeyboardEvent| {
        if !is_top_modal(modal_layer) {
            return;
        }
        if e.key() == "Tab" {
            trap_dialog_tab(&e, dialog_ref.get_untracked());
            return;
        }
        if e.key() == "Escape"
            && !e.default_prevented()
            && !e.is_composing()
            && e.key_code() != 229
            && !e.alt_key()
            && !e.ctrl_key()
            && !e.meta_key()
            && let Some(close_cb) = on_close
        {
            e.prevent_default();
            close_cb.run(());
        }
    });

    let is_busy = move || submitting.is_some_and(|s| s.get());

    let resolved_title = move || {
        title
            .map(|t| t.get())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Age Verification Required".to_string())
    };

    let resolved_subtitle = move || {
        if let Some(sub) = subtitle {
            let s = sub.get();
            if !s.trim().is_empty() {
                return Some(s);
            }
        }
        is_authenticated.map(|auth| {
            if auth.get() {
                "Your 18+ confirmation will be saved to your account preferences.".to_string()
            } else {
                "Confirm for this browsing session, or sign in to save your preference across devices.".to_string()
            }
        })
    };

    let handle_backdrop_click = move |_| {
        if let Some(close_cb) = on_close
            && !is_busy()
        {
            close_cb.run(());
        }
    };

    let handle_leave = move |_| {
        if is_busy() {
            return;
        }
        if let Some(leave_cb) = on_leave {
            leave_cb.run(());
        } else if let Some(close_cb) = on_close {
            close_cb.run(());
        }
    };

    let handle_confirm = move |_| {
        if is_busy() {
            return;
        }
        on_confirm.run(());
    };

    let dismissible = on_close.is_some();
    let title_id_attr = title_id.clone();
    let desc_id_attr = desc_id.clone();

    view! {
        <div
            class="le-modal-backdrop le-age-gate-backdrop"
            data-dismissible=dismissible.to_string()
            on:click=handle_backdrop_click
        >
            <div
                node_ref=dialog_ref
                role="dialog"
                aria-modal="true"
                aria-labelledby=title_id_attr
                aria-describedby=desc_id_attr
                tabindex="-1"
                class="le-age-gate-dialog"
                on:click=|ev: ev::MouseEvent| ev.stop_propagation()
            >
                {on_close.map(|close_cb| view! {
                    <button
                        type="button"
                        class="le-icon-close le-age-gate-close"
                        aria-label="Close age verification dialog"
                        disabled=is_busy
                        on:click=move |_| {
                            if !is_busy() {
                                close_cb.run(());
                            }
                        }
                    >
                        "\u{00D7}"
                    </button>
                })}

                <div class="le-age-gate-badge-wrap">
                    <span class="le-age-gate-badge" aria-hidden="true">
                        <svg
                            class="le-age-gate-badge-svg"
                            viewBox="0 0 64 64"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                        >
                            <circle cx="32" cy="32" r="28" fill="#fef9c3" stroke="#eab308" stroke-width="3.5" />
                            <circle cx="32" cy="32" r="22" fill="#fef3c7" stroke="#fde047" stroke-width="1.5" stroke-dasharray="3 3" />
                            <text
                                x="32"
                                y="38"
                                text-anchor="middle"
                                font-family="system-ui, -apple-system, sans-serif"
                                font-size="18"
                                font-weight="800"
                                letter-spacing="-0.4"
                                fill="#854d0e"
                            >
                                "18+"
                            </text>
                        </svg>
                    </span>
                    <span class="le-age-gate-pill">"18+ Adults Only"</span>
                </div>

                <h2 id=title_id class="le-age-gate-title">{resolved_title}</h2>

                <p id=desc_id class="le-age-gate-copy">{AGE_GATE_LEGAL_COPY}</p>

                {move || resolved_subtitle().map(|sub| view! {
                    <p class="le-age-gate-subtitle">{sub}</p>
                })}

                {move || error.and_then(|e| e.get()).filter(|s| !s.trim().is_empty()).map(|err| view! {
                    <div class="le-age-gate-error" role="alert">{err}</div>
                })}

                <div class="le-age-gate-actions">
                    <button
                        type="button"
                        class="le-btn le-age-gate-confirm"
                        disabled=is_busy
                        on:click=handle_confirm
                    >
                        {move || if is_busy() {
                            "Confirming\u{2026}"
                        } else {
                            "I am 18 or older \u{2014} Confirm"
                        }}
                    </button>

                    <button
                        type="button"
                        class="le-btn le-btn--secondary le-age-gate-leave"
                        disabled=is_busy
                        on:click=handle_leave
                    >
                        "Leave / Cancel"
                    </button>
                </div>
            </div>
        </div>
    }
}
