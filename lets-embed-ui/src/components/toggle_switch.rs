use std::sync::atomic::{AtomicU64, Ordering};

use leptos::prelude::*;

static NEXT_TOGGLE_ID: AtomicU64 = AtomicU64::new(1);

/// Clean, accessible pill toggle switch with left-aligned label/description and
/// an animated right-aligned sliding switch control.
///
/// Replaces raw checkboxes and centered-text toggle cards across `/admin` and
/// `/user/*` surfaces.
#[component]
pub fn ToggleSwitch(
    /// Reactive boolean value of the switch.
    #[prop(into)]
    checked: Signal<bool>,
    /// Callback invoked with the next boolean state when toggled.
    on_change: Callback<bool>,
    /// Primary left-aligned label text.
    #[prop(into)]
    label: String,
    /// Optional muted description text rendered underneath the label.
    #[prop(optional, into)]
    description: Option<String>,
    /// Optional reactive disabled flag.
    #[prop(optional, into)]
    disabled: Option<Signal<bool>>,
    /// Renders a compact pill variant suitable for inline flag strips.
    #[prop(default = false)]
    compact: bool,
    /// Optional additional CSS class on the outer switch button.
    #[prop(optional, into)]
    class: String,
) -> impl IntoView {
    let uid = NEXT_TOGGLE_ID.fetch_add(1, Ordering::Relaxed);
    let label_id = format!("le-toggle-label-{uid}");
    let label_id_attr = label_id.clone();
    let desc_id = description.as_ref().map(|_| format!("le-toggle-desc-{uid}"));
    let desc_id_attr = desc_id.clone();
    let has_desc = description.is_some();

    let is_disabled = move || disabled.is_some_and(|d| d.get());

    let handle_click = move |_| {
        if disabled.is_some_and(|d| d.get_untracked()) {
            return;
        }
        on_change.run(!checked.get_untracked());
    };

    let extra_class = class.trim().to_string();

    view! {
        <button
            type="button"
            role="switch"
            aria-checked=move || if checked.get() { "true" } else { "false" }
            aria-labelledby=label_id_attr
            aria-describedby=desc_id_attr
            disabled=is_disabled
            class=move || {
                let mut cls = String::from("le-toggle-row");
                if compact {
                    cls.push_str(" le-toggle-row--compact");
                }
                if !has_desc {
                    cls.push_str(" le-toggle-row--single");
                }
                if checked.get() {
                    cls.push_str(" is-checked");
                }
                if is_disabled() {
                    cls.push_str(" is-disabled");
                }
                if !extra_class.is_empty() {
                    cls.push(' ');
                    cls.push_str(&extra_class);
                }
                cls
            }
            on:click=handle_click
        >
            <span class="le-toggle-copy">
                <span id=label_id class="le-toggle-label">{label}</span>
                {description.map(|desc| {
                    let did = desc_id.clone().unwrap_or_default();
                    view! {
                        <span id=did class="le-toggle-desc">{desc}</span>
                    }
                })}
            </span>
            <span class="le-toggle-track" aria-hidden="true">
                <span class="le-toggle-thumb"></span>
            </span>
        </button>
    }
}
