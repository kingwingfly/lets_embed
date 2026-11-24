use leptos::{ev, html, prelude::*};

use crate::browser::{lock_body_scroll, trap_dialog_tab, use_window_keydown};
use crate::components::SkySelect;
use crate::models::{
    MAX_REPORT_NOTE_CHARS, ReportReason, ReportSubmission, ReportTargetKind, SelectVariant,
};

/// Truncate text to at most `max_chars` Unicode scalar values.
pub(crate) fn clamp_chars(raw: &str, max_chars: usize) -> String {
    raw.chars().take(max_chars).collect()
}

/// Modal form allowing users to flag content with an allowlisted [`ReportReason`]
/// dropdown and an optional note strictly capped at 500 Unicode characters with a
/// live character counter.
#[component]
pub fn ReportDialog(
    open: Signal<bool>,
    target_kind: Signal<ReportTargetKind>,
    target_id: Signal<i64>,
    #[prop(optional)] target_label: Option<Signal<String>>,
    #[prop(optional)] submitting: Option<Signal<bool>>,
    #[prop(optional)] error: Option<Signal<Option<String>>>,
    #[prop(optional)] success_message: Option<Signal<Option<String>>>,
    on_submit: Callback<ReportSubmission>,
    on_close: Callback<()>,
) -> impl IntoView {
    view! {
        {move || {
            open.get().then(|| view! {
                <ReportDialogModal
                    target_kind=target_kind
                    target_id=target_id
                    target_label=target_label
                    submitting=submitting
                    error=error
                    success_message=success_message
                    on_submit=on_submit
                    on_close=on_close
                />
            })
        }}
    }
}

#[component]
fn ReportDialogModal(
    target_kind: Signal<ReportTargetKind>,
    target_id: Signal<i64>,
    target_label: Option<Signal<String>>,
    submitting: Option<Signal<bool>>,
    error: Option<Signal<Option<String>>>,
    success_message: Option<Signal<Option<String>>>,
    on_submit: Callback<ReportSubmission>,
    on_close: Callback<()>,
) -> impl IntoView {
    lock_body_scroll();

    let dialog_ref = NodeRef::<html::Div>::new();
    let reason = RwSignal::new(ReportReason::MisclassifiedSafety);
    let note = RwSignal::new(String::new());
    let reason_options = Signal::derive(ReportReason::select_options);

    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    Effect::new(move |_| {
        if let Some(el) = dialog_ref.get() {
            let _ = el.focus();
        }
    });

    use_window_keydown(false, move |e: ev::KeyboardEvent| {
        if e.key() == "Tab" {
            trap_dialog_tab(&e, dialog_ref.get_untracked());
            return;
        }
        if e.key() == "Escape"
            && !e.default_prevented()
            && !e.alt_key()
            && !e.ctrl_key()
            && !e.meta_key()
        {
            e.prevent_default();
            on_close.run(());
        }
    });

    let char_count = Memo::new(move |_| note.with(|s| s.chars().count()));
    let is_busy = move || submitting.is_some_and(|s| s.get());

    let handle_submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        if is_busy() {
            return;
        }
        let cleaned = clamp_chars(note.get_untracked().trim(), MAX_REPORT_NOTE_CHARS);
        on_submit.run(ReportSubmission {
            target_kind: target_kind.get_untracked(),
            target_id: target_id.get_untracked(),
            reason: reason.get_untracked(),
            note: cleaned,
        });
    };

    view! {
        <div
            class="le-modal-backdrop"
            on:click=move |_| on_close.run(())
        >
            <div
                node_ref=dialog_ref
                role="dialog"
                aria-modal="true"
                aria-labelledby="le-report-dialog-title"
                tabindex="-1"
                class="le-report-dialog"
                on:click=|ev: ev::MouseEvent| ev.stop_propagation()
            >
                <div class="le-report-header">
                    <div>
                        <h2 id="le-report-dialog-title" class="le-report-title">"Report Content"</h2>
                        <p class="le-report-subtitle">
                            {move || {
                                if let Some(lbl) = target_label {
                                    let s = lbl.get();
                                    if !s.trim().is_empty() {
                                        return s;
                                    }
                                }
                                format!("{} #{}", target_kind.get().as_str(), target_id.get())
                            }}
                        </p>
                    </div>
                    <button
                        type="button"
                        class="le-icon-close"
                        aria-label="Close report dialog"
                        on:click=move |_| on_close.run(())
                    >
                        "\u{00D7}"
                    </button>
                </div>

                {move || success_message.and_then(|s| s.get()).map(|msg| view! {
                    <div class="le-report-banner le-report-banner--ok" role="status">{msg}</div>
                })}

                {move || error.and_then(|e| e.get()).map(|err| view! {
                    <div class="le-report-banner le-report-banner--err" role="alert">{err}</div>
                })}

                <form class="le-report-form" on:submit=handle_submit>
                    <div class="le-field">
                        <span class="le-field-label">"Reason"</span>
                        <SkySelect
                            aria_label="Report reason"
                            variant=SelectVariant::SkyBox
                            trigger_class="le-report-select"
                            value=Signal::derive(move || reason.get().as_str().to_string())
                            options=reason_options
                            on_change=Callback::new(move |val: String| {
                                if let Some(parsed) = ReportReason::parse(&val) {
                                    reason.set(parsed);
                                }
                            })
                        />
                    </div>

                    <div class="le-field">
                        <div class="le-field-label-row">
                            <label for="le-report-note" class="le-field-label">
                                "Additional details (optional)"
                            </label>
                            <span
                                class=move || {
                                    let n = char_count.get();
                                    if n >= MAX_REPORT_NOTE_CHARS {
                                        "le-char-count is-limit"
                                    } else if n >= 420 {
                                        "le-char-count is-warn"
                                    } else {
                                        "le-char-count"
                                    }
                                }
                                aria-live="polite"
                            >
                                {move || format!("{} / {MAX_REPORT_NOTE_CHARS}", char_count.get())}
                            </span>
                        </div>
                        <textarea
                            id="le-report-note"
                            class="le-report-textarea"
                            rows="4"
                            maxlength=MAX_REPORT_NOTE_CHARS
                            placeholder="Share context for reviewers (plain text, up to 500 characters)…"
                            prop:value=move || note.get()
                            on:input=move |ev| {
                                let raw = event_target_value(&ev);
                                note.set(clamp_chars(&raw, MAX_REPORT_NOTE_CHARS));
                            }
                        >{move || note.get()}</textarea>
                    </div>

                    <div class="le-report-footer">
                        <button
                            type="button"
                            class="le-btn le-btn--secondary"
                            on:click=move |_| on_close.run(())
                        >
                            "Cancel"
                        </button>
                        <button
                            type="submit"
                            class="le-btn le-btn--danger"
                            disabled=is_busy
                        >
                            {move || if is_busy() { "Submitting\u{2026}" } else { "Submit report" }}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    }
}
