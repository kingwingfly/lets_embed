use std::sync::atomic::{AtomicUsize, Ordering};

use leptos::{ev, html, prelude::*};

use crate::browser::{
    use_document_scroll_capture, use_window_keydown, use_window_pointerdown, use_window_resize,
};
use crate::models::{SelectOption, SelectVariant};

static NEXT_SELECT_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MenuPlacement {
    pub open_above: bool,
    pub align_right: bool,
    pub max_height_px: u32,
}

impl Default for MenuPlacement {
    fn default() -> Self {
        Self {
            open_above: false,
            align_right: false,
            max_height_px: 256,
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(any(feature = "csr", feature = "hydrate", test)), allow(dead_code))]
pub(crate) fn compute_menu_placement_from_metrics(
    rect_top: f64,
    rect_bottom: f64,
    rect_left: f64,
    rect_right: f64,
    vw: f64,
    vh: f64,
    option_count: usize,
    variant: SelectVariant,
) -> MenuPlacement {
    let gap = match variant {
        SelectVariant::SearchPill => 8.0,
        SelectVariant::SkyBox | SelectVariant::IndigoBox => 6.0,
    };
    let est_height = (option_count as f64 * 36.0 + 16.0).min(256.0);
    let space_below = (vh - rect_bottom - gap).max(0.0);
    let space_above = (rect_top - gap).max(0.0);
    let open_above = space_below < est_height && space_above > space_below;
    let avail = if open_above { space_above } else { space_below };
    let max_height_px = (avail - 12.0).clamp(88.0, 256.0).round() as u32;

    let trigger_w = (rect_right - rect_left).max(0.0);
    let est_width = match variant {
        SelectVariant::SearchPill => 176.0_f64.max(trigger_w),
        SelectVariant::SkyBox | SelectVariant::IndigoBox => 220.0_f64.max(trigger_w),
    }
    .min((vw - 24.0).max(120.0));
    let space_from_left = vw - rect_left - 12.0;
    let space_from_right = rect_right - 12.0;
    let align_right = space_from_left < est_width && space_from_right > space_from_left;

    MenuPlacement {
        open_above,
        align_right,
        max_height_px,
    }
}

#[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
fn compute_menu_placement(
    trigger: &web_sys::Element,
    option_count: usize,
    variant: SelectVariant,
) -> MenuPlacement {
    let rect = trigger.get_bounding_client_rect();
    let win = web_sys::window();
    let vw = win
        .as_ref()
        .and_then(|w| w.inner_width().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(1024.0);
    let vh = win
        .as_ref()
        .and_then(|w| w.inner_height().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(768.0);
    compute_menu_placement_from_metrics(
        rect.top(),
        rect.bottom(),
        rect.left(),
        rect.right(),
        vw,
        vh,
        option_count,
        variant,
    )
}

pub(crate) fn next_enabled_index(
    options: &[SelectOption],
    current: Option<usize>,
    delta: isize,
) -> Option<usize> {
    if options.is_empty() {
        return None;
    }
    let len = options.len();
    let start = match current {
        Some(i) => i,
        None => {
            return if delta >= 0 {
                options.iter().position(|o| !o.disabled)
            } else {
                options.iter().rposition(|o| !o.disabled)
            };
        }
    };
    for step in 1..=len {
        let idx = if delta >= 0 {
            (start + step) % len
        } else {
            (start + len - (step % len)) % len
        };
        if !options[idx].disabled {
            return Some(idx);
        }
    }
    None
}

/// Custom sky/indigo themed dropdown select replacing native `<select>` popups.
/// Styled purely via `ui.css` `.le-select-*` classes so it works cleanly in both
/// standalone CSR workers and Tailwind-enabled SSR apps.
#[component]
pub fn SkySelect(
    aria_label: &'static str,
    value: Signal<String>,
    options: Signal<Vec<SelectOption>>,
    on_change: Callback<String>,
    #[prop(default = SelectVariant::SkyBox)] variant: SelectVariant,
    #[prop(default = "")] trigger_class: &'static str,
) -> impl IntoView {
    let select_id = NEXT_SELECT_ID.fetch_add(1, Ordering::Relaxed);
    let list_id = format!("le-select-list-{select_id}");
    let open = RwSignal::new(false);
    let placement = RwSignal::new(MenuPlacement::default());
    let active_idx: RwSignal<Option<usize>> = RwSignal::new(None);
    let wrapper_ref = NodeRef::<html::Div>::new();
    let trigger_ref = NodeRef::<html::Button>::new();
    let menu_ref = NodeRef::<html::Div>::new();

    let close = move || {
        open.set(false);
        placement.set(MenuPlacement::default());
        active_idx.set(None);
    };

    let focus_trigger = move || {
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        if let Some(btn) = trigger_ref.get_untracked() {
            let _ = btn.focus();
        }
    };

    let scroll_option_into_view = move |idx: usize| {
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            use wasm_bindgen::{JsCast, JsValue};

            if let Some(el) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.get_element_by_id(&format!("le-select-opt-{select_id}-{idx}")))
            {
                let _ = js_sys::Reflect::get(&el, &JsValue::from_str("scrollIntoView"))
                    .ok()
                    .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
                    .and_then(|f| {
                        let opts = js_sys::Object::new();
                        let _ = js_sys::Reflect::set(
                            &opts,
                            &JsValue::from_str("block"),
                            &JsValue::from_str("nearest"),
                        );
                        f.call1(&el, &opts).ok()
                    });
            }
        }
        #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
        {
            let _ = idx;
        }
    };

    let open_menu = move || {
        let cur = value.get_untracked();
        let (count, sel_idx) = options.with_untracked(|opts| {
            let idx = opts
                .iter()
                .position(|o| o.value == cur && !o.disabled)
                .or_else(|| opts.iter().position(|o| !o.disabled));
            (opts.len(), idx)
        });
        active_idx.set(sel_idx);
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            if let Some(btn) = trigger_ref.get_untracked() {
                let _ = btn.focus();
                let el: &web_sys::Element = btn.as_ref();
                placement.set(compute_menu_placement(el, count, variant));
            }
        }
        #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
        {
            let _ = count;
        }
        open.set(true);
    };

    let toggle = move |_| {
        if open.get_untracked() {
            close();
        } else {
            open_menu();
        }
    };

    use_window_pointerdown(move |e: ev::PointerEvent| {
        if !open.get_untracked() {
            return;
        }
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            use wasm_bindgen::JsCast;
            let target_node = e.target().and_then(|t| t.dyn_into::<web_sys::Node>().ok());
            let inside = wrapper_ref
                .get_untracked()
                .is_some_and(|el| target_node.as_ref().is_some_and(|n| el.contains(Some(n))));
            if !inside {
                close();
            }
        }
        #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
        {
            let _ = e;
        }
    });

    use_window_resize(move |_| {
        if open.get_untracked() {
            close();
        }
    });

    use_document_scroll_capture(move |e: ev::Event| {
        if !open.get_untracked() {
            return;
        }
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            use wasm_bindgen::JsCast;
            let target_node = e.target().and_then(|t| t.dyn_into::<web_sys::Node>().ok());
            let inside_menu = menu_ref
                .get_untracked()
                .is_some_and(|el| target_node.as_ref().is_some_and(|n| el.contains(Some(n))));
            if !inside_menu {
                close();
            }
        }
        #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
        {
            let _ = e;
        }
    });

    use_window_keydown(true, move |e: ev::KeyboardEvent| {
        if !open.get_untracked() {
            return;
        }
        if e.key() == "Escape"
            && !e.is_composing()
            && e.key_code() != 229
            && !e.alt_key()
            && !e.ctrl_key()
            && !e.meta_key()
        {
            e.prevent_default();
            e.stop_propagation();
            close();
            focus_trigger();
        }
    });

    let selected_label = move || {
        let cur = value.get();
        options.with(|opts| {
            opts.iter()
                .find(|o| o.value == cur)
                .or_else(|| opts.first())
                .map(|o| o.label.clone())
                .unwrap_or_default()
        })
    };

    let variant_slug = match variant {
        SelectVariant::SearchPill => "search-pill",
        SelectVariant::SkyBox => "sky-box",
        SelectVariant::IndigoBox => "indigo-box",
    };

    let on_keydown = move |ev: ev::KeyboardEvent| {
        if ev.is_composing() || ev.key_code() == 229 {
            return;
        }
        match ev.key().as_str() {
            "Enter" | " " => {
                ev.prevent_default();
                if !open.get_untracked() {
                    open_menu();
                } else if let Some(idx) = active_idx.get_untracked()
                    && let Some(val) = options.with_untracked(|opts| {
                        opts.get(idx)
                            .filter(|o| !o.disabled)
                            .map(|o| o.value.clone())
                    })
                {
                    on_change.run(val);
                    close();
                } else {
                    close();
                }
            }
            "ArrowDown" => {
                ev.prevent_default();
                if !open.get_untracked() {
                    open_menu();
                } else {
                    let next = options.with_untracked(|opts| {
                        next_enabled_index(opts, active_idx.get_untracked(), 1)
                    });
                    active_idx.set(next);
                    if let Some(idx) = next {
                        scroll_option_into_view(idx);
                    }
                }
            }
            "ArrowUp" => {
                ev.prevent_default();
                if !open.get_untracked() {
                    open_menu();
                } else {
                    let next = options.with_untracked(|opts| {
                        next_enabled_index(opts, active_idx.get_untracked(), -1)
                    });
                    active_idx.set(next);
                    if let Some(idx) = next {
                        scroll_option_into_view(idx);
                    }
                }
            }
            "Escape" if open.get_untracked() => {
                ev.prevent_default();
                ev.stop_propagation();
                close();
            }
            "Tab" if open.get_untracked() => {
                close();
            }
            _ => {}
        }
    };

    let on_focusout = move |ev: ev::FocusEvent| {
        #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
        {
            use wasm_bindgen::JsCast;
            if !open.get_untracked() {
                return;
            }
            let related = ev
                .related_target()
                .and_then(|t| t.dyn_into::<web_sys::Node>().ok());
            let stays_inside = wrapper_ref
                .get_untracked()
                .is_some_and(|w| related.as_ref().is_some_and(|n| w.contains(Some(n))));
            if !stays_inside {
                close();
            }
        }
        #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
        {
            let _ = ev;
        }
    };

    let list_id_aria = list_id.clone();

    view! {
        <div
            node_ref=wrapper_ref
            class=format!("le-select le-select--{variant_slug}")
            on:focusout=on_focusout
        >
            <button
                node_ref=trigger_ref
                type="button"
                role="combobox"
                aria-label=aria_label
                aria-haspopup="listbox"
                aria-expanded=move || open.get().to_string()
                aria-controls=move || open.get().then(|| list_id_aria.clone())
                aria-activedescendant=move || {
                    open.get()
                        .then(|| {
                            active_idx
                                .get()
                                .map(|i| format!("le-select-opt-{select_id}-{i}"))
                        })
                        .flatten()
                }
                class=move || {
                    let is_open = if open.get() { " is-open" } else { "" };
                    if trigger_class.is_empty() {
                        format!("le-select-trigger le-select-trigger--{variant_slug}{is_open}")
                    } else {
                        format!(
                            "le-select-trigger le-select-trigger--{variant_slug}{is_open} {trigger_class}"
                        )
                    }
                }
                on:click=toggle
                on:keydown=on_keydown
            >
                <span class="le-select-value">{selected_label}</span>
                <svg
                    class=move || {
                        if open.get() {
                            "le-select-chevron is-open"
                        } else {
                            "le-select-chevron"
                        }
                    }
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    stroke-width="2.2"
                    aria-hidden="true"
                >
                    <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
            </button>

            {move || {
                let list_id_menu = list_id.clone();
                open.get().then(move || {
                    let opts = options.get();
                    let cur_val = value.get();
                    let pl = placement.get();
                    let pos_cls = match (pl.open_above, pl.align_right) {
                        (false, false) => "le-select-menu--below le-select-menu--left",
                        (false, true) => "le-select-menu--below le-select-menu--right",
                        (true, false) => "le-select-menu--above le-select-menu--left",
                        (true, true) => "le-select-menu--above le-select-menu--right",
                    };
                    let max_h_style = format!("max-height:{}px;", pl.max_height_px);

                    view! {
                        <div
                            node_ref=menu_ref
                            id=list_id_menu
                            role="listbox"
                            aria-label=aria_label
                            style=max_h_style
                            on:mousedown=|ev| ev.prevent_default()
                            class=format!("le-select-menu le-select-menu--{variant_slug} {pos_cls}")
                        >
                            {opts.into_iter().enumerate().map(|(i, opt)| {
                                let is_selected = opt.value == cur_val;
                                let is_disabled = opt.disabled;
                                let val = opt.value.clone();
                                let label = opt.label.clone();
                                let opt_id = format!("le-select-opt-{select_id}-{i}");
                                view! {
                                    <button
                                        id=opt_id
                                        type="button"
                                        role="option"
                                        tabindex="-1"
                                        aria-selected=is_selected.to_string()
                                        aria-disabled=is_disabled.to_string()
                                        disabled=is_disabled
                                        class=move || {
                                            let mut cls = String::from("le-select-option");
                                            if is_disabled {
                                                cls.push_str(" is-disabled");
                                            } else if is_selected {
                                                cls.push_str(" is-selected");
                                            } else if active_idx.get() == Some(i) {
                                                cls.push_str(" is-active");
                                            }
                                            cls
                                        }
                                        on:mousedown=|ev| ev.prevent_default()
                                        on:mouseenter=move |_| {
                                            if !is_disabled {
                                                active_idx.set(Some(i));
                                            }
                                        }
                                        on:click=move |_| {
                                            if !is_disabled {
                                                on_change.run(val.clone());
                                                close();
                                                focus_trigger();
                                            }
                                        }
                                    >
                                        <span class="le-select-option-label">{label}</span>
                                        {is_selected.then(|| view! {
                                            <svg
                                                class="le-select-check"
                                                fill="none"
                                                viewBox="0 0 24 24"
                                                stroke="currentColor"
                                                stroke-width="2.5"
                                                aria-hidden="true"
                                            >
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                                            </svg>
                                        })}
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                    }
                })
            }}
        </div>
    }
}
