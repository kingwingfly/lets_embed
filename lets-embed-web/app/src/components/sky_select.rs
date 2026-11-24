use std::sync::atomic::{AtomicUsize, Ordering};

use leptos::{ev, html, prelude::*};
#[cfg(feature = "hydrate")]
use leptos_use_event_listener::{
    UseEventListenerOptions, use_event_listener, use_event_listener_with_options,
};
#[cfg(feature = "hydrate")]
use wasm_bindgen::{JsCast as _, JsValue};

static NEXT_SELECT_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectOption {
    pub value: String,
    pub label: String,
    /// Optional concise label shown inside the trigger on narrow mobile viewports (`<sm`).
    pub short_label: Option<String>,
    pub disabled: bool,
}

impl SelectOption {
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            short_label: None,
            disabled: false,
        }
    }

    pub fn short_label(mut self, short: impl Into<String>) -> Self {
        self.short_label = Some(short.into());
        self
    }

    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SelectVariant {
    /// Left-anchored pill segment inside the WoS search bar (`rounded-l-full`).
    SearchPill,
    /// Sky-tinted `rounded-xl` box inside Advanced Search condition rows.
    #[default]
    SkyBox,
    /// Indigo-tinted `rounded-xl` box inside Advanced Search boolean groups.
    IndigoBox,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MenuPlacement {
    open_above: bool,
    align_right: bool,
    max_height_px: u32,
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
#[cfg_attr(not(any(feature = "hydrate", test)), allow(dead_code))]
fn compute_menu_placement_from_metrics(
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
        SelectVariant::SkyBox | SelectVariant::IndigoBox => 240.0_f64.max(trigger_w),
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

#[cfg(feature = "hydrate")]
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

fn next_enabled_index(
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

/// Custom sky-blue themed dropdown menu replacing native `<select>` popups so expanded
/// option menus match the rounded blue-white aesthetic and never clash with rounded corners
/// or get clipped by scrollable modal containers.
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
    let list_id = format!("sky-select-list-{select_id}");
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
        #[cfg(feature = "hydrate")]
        if let Some(btn) = trigger_ref.get_untracked() {
            let _ = btn.focus();
        }
    };

    let scroll_option_into_view = move |idx: usize| {
        #[cfg(feature = "hydrate")]
        {
            if let Some(el) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.get_element_by_id(&format!("sky-select-opt-{select_id}-{idx}")))
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
        #[cfg(not(feature = "hydrate"))]
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
        #[cfg(feature = "hydrate")]
        {
            if let Some(btn) = trigger_ref.get_untracked() {
                let _ = btn.focus();
                let el: &web_sys::Element = btn.as_ref();
                placement.set(compute_menu_placement(el, count, variant));
            }
        }
        #[cfg(not(feature = "hydrate"))]
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

    #[cfg(feature = "hydrate")]
    {
        let _ = use_event_listener(window(), ev::pointerdown, move |e: ev::PointerEvent| {
            if !open.get_untracked() {
                return;
            }
            let target_node = e.target().and_then(|t| t.dyn_into::<web_sys::Node>().ok());
            let inside_wrapper = wrapper_ref
                .get_untracked()
                .is_some_and(|el| target_node.as_ref().is_some_and(|n| el.contains(Some(n))));
            if !inside_wrapper {
                close();
            }
        });

        let _ = use_event_listener(window(), ev::resize, move |_| {
            if open.get_untracked() {
                close();
            }
        });

        // Capture-phase scroll on document catches modal overlay scrolling (e.g. `#advanced-search-panel`)
        // while still allowing internal listbox scrolling inside `menu_ref`.
        let _ = use_event_listener_with_options(
            document(),
            ev::scroll,
            move |e: ev::Event| {
                if !open.get_untracked() {
                    return;
                }
                let target_node = e.target().and_then(|t| t.dyn_into::<web_sys::Node>().ok());
                let inside_menu = menu_ref
                    .get_untracked()
                    .is_some_and(|el| target_node.as_ref().is_some_and(|n| el.contains(Some(n))));
                if !inside_menu {
                    close();
                }
            },
            UseEventListenerOptions::default()
                .capture(true)
                .passive(true),
        );

        // Capture-phase Escape listener on window ensures Escape closes SkySelect
        // without closing an enclosing modal (e.g. AdvancedSearchPanel), even on
        // browsers where button click doesn't move focus before the key press.
        let _ = use_event_listener_with_options(
            window(),
            ev::keydown,
            move |e: ev::KeyboardEvent| {
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
            },
            UseEventListenerOptions::default().capture(true),
        );
    }

    let selected_labels = move || {
        let cur = value.get();
        options.with(|opts| {
            opts.iter()
                .find(|o| o.value == cur)
                .or_else(|| opts.first())
                .map(|o| (o.label.clone(), o.short_label.clone()))
                .unwrap_or_default()
        })
    };

    let trigger_base = match variant {
        SelectVariant::SearchPill => {
            "self-stretch inline-flex items-center justify-between gap-1 sm:gap-1.5 rounded-l-full bg-sky-50/90 \
             hover:bg-sky-100/80 text-sky-800 text-xs sm:text-sm font-medium \
             pl-2.5 sm:pl-3.5 pr-2 sm:pr-3 py-1.5 sm:py-2 border-r border-sky-200/80 \
             outline-none cursor-pointer transition-colors whitespace-nowrap"
        }
        SelectVariant::SkyBox => {
            "inline-flex items-center justify-between gap-1.5 rounded-xl bg-white \
             border border-sky-200 hover:border-sky-300 hover:bg-sky-50/40 px-2.5 py-1.5 \
             text-xs outline-none cursor-pointer transition-all whitespace-nowrap"
        }
        SelectVariant::IndigoBox => {
            "inline-flex items-center justify-between gap-1.5 rounded-xl bg-white \
             border border-indigo-200 hover:border-indigo-300 hover:bg-indigo-50/40 px-2.5 py-1.5 \
             text-xs outline-none cursor-pointer transition-all whitespace-nowrap"
        }
    };

    let open_ring = match variant {
        SelectVariant::SearchPill => "bg-sky-100/90 text-sky-900",
        SelectVariant::SkyBox => "border-sky-400 ring-2 ring-sky-200/75",
        SelectVariant::IndigoBox => "border-indigo-400 ring-2 ring-indigo-200/75",
    };

    let chevron_color = match variant {
        SelectVariant::IndigoBox => "text-indigo-500",
        _ => "text-sky-500",
    };

    let menu_ring = match variant {
        SelectVariant::IndigoBox => "ring-indigo-200/90 shadow-indigo-200/50",
        _ => "ring-sky-200/90 shadow-sky-200/55",
    };

    let opt_selected_cls = match variant {
        SelectVariant::IndigoBox => {
            "bg-gradient-to-r from-indigo-50 to-indigo-100/85 text-indigo-800 font-semibold"
        }
        _ => "bg-gradient-to-r from-sky-50 to-sky-100/90 text-sky-800 font-semibold",
    };

    let opt_hover_cls = match variant {
        SelectVariant::IndigoBox => "bg-indigo-50/90 text-indigo-900",
        _ => "bg-sky-50 text-sky-900",
    };

    let check_color = match variant {
        SelectVariant::IndigoBox => "text-indigo-500",
        _ => "text-sky-500",
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
        #[cfg(feature = "hydrate")]
        {
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
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = ev;
        }
    };

    let wrapper_cls = match variant {
        SelectVariant::SearchPill => "web-sky-select web-sky-select--search-pill relative shrink-0 self-stretch inline-flex items-stretch",
        _ => "web-sky-select relative shrink-0 inline-flex items-center",
    };

    let list_id_aria = list_id.clone();

    view! {
        <div node_ref=wrapper_ref class=wrapper_cls on:focusout=on_focusout>
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
                                .map(|i| format!("sky-select-opt-{select_id}-{i}"))
                        })
                        .flatten()
                }
                class=move || {
                    if open.get() {
                        format!("web-sky-select-trigger is-open {trigger_base} {trigger_class} {open_ring}")
                    } else {
                        format!("web-sky-select-trigger {trigger_base} {trigger_class}")
                    }
                }
                on:click=toggle
                on:keydown=on_keydown
            >
                {move || {
                    let (full, short) = selected_labels();
                    match short {
                        Some(s) => view! {
                            <span class="truncate sm:hidden">{s}</span>
                            <span class="truncate hidden sm:inline">{full}</span>
                        }
                        .into_any(),
                        None => view! {
                            <span class="truncate">{full}</span>
                        }
                        .into_any(),
                    }
                }}
                <svg
                    class=move || {
                        let rot = if open.get() { "rotate-180" } else { "" };
                        format!("shrink-0 w-3.5 h-3.5 {chevron_color} transition-transform duration-150 {rot}")
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
                    let h_align = if pl.align_right { "right-0" } else { "left-0" };
                    let placement_cls = match (variant, pl.open_above) {
                        (SelectVariant::SearchPill, false) => {
                            "top-full mt-2 min-w-[11rem] max-w-[min(15rem,calc(100vw-1.5rem))]"
                        }
                        (SelectVariant::SearchPill, true) => {
                            "bottom-full mb-2 min-w-[11rem] max-w-[min(15rem,calc(100vw-1.5rem))]"
                        }
                        (_, false) => {
                            "top-full mt-1.5 min-w-full w-max max-w-[min(15rem,calc(100vw-1.5rem))]"
                        }
                        (_, true) => {
                            "bottom-full mb-1.5 min-w-full w-max max-w-[min(15rem,calc(100vw-1.5rem))]"
                        }
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
                            class=format!(
                                "web-sky-select-menu absolute {h_align} {placement_cls} z-[80] overflow-y-auto overscroll-contain \
                                 rounded-2xl bg-white/95 backdrop-blur-md ring-1 {menu_ring} \
                                 shadow-xl p-1.5 flex flex-col gap-0.5"
                            )
                        >
                            {opts.into_iter().enumerate().map(|(i, opt)| {
                                let is_selected = opt.value == cur_val;
                                let is_disabled = opt.disabled;
                                let val = opt.value.clone();
                                let label = opt.label.clone();
                                let opt_id = format!("sky-select-opt-{select_id}-{i}");
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
                                            let base = "web-sky-select-option w-full text-left px-3 py-1.5 rounded-xl text-xs sm:text-[13px] \
                                                        flex items-center justify-between gap-2.5 transition-colors whitespace-nowrap";
                                            if is_disabled {
                                                format!("{base} opacity-40 cursor-not-allowed text-slate-400")
                                            } else if is_selected {
                                                format!("{base} {opt_selected_cls} cursor-pointer")
                                            } else if active_idx.get() == Some(i) {
                                                format!("{base} {opt_hover_cls} cursor-pointer")
                                            } else {
                                                format!("{base} text-slate-700 hover:bg-sky-50/80 hover:text-sky-900 cursor-pointer")
                                            }
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
                                        <span class="truncate">{label}</span>
                                        {is_selected.then(|| view! {
                                            <svg
                                                class=format!("w-3.5 h-3.5 shrink-0 {check_color}")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyboard_navigation_skips_disabled_options() {
        let opts = vec![
            SelectOption::new("and", "AND"),
            SelectOption::new("or", "OR").disabled(true),
            SelectOption::new("not", "NOT"),
        ];
        assert_eq!(next_enabled_index(&opts, Some(0), 1), Some(2));
        assert_eq!(next_enabled_index(&opts, Some(2), 1), Some(0));
        assert_eq!(next_enabled_index(&opts, Some(2), -1), Some(0));
        assert_eq!(next_enabled_index(&opts, Some(0), -1), Some(2));
    }

    #[test]
    fn menu_placement_flips_and_caps_height_within_viewport() {
        // Near bottom-right corner on a 375x600 viewport -> opens above and aligns right.
        let pl = compute_menu_placement_from_metrics(
            520.0,
            552.0,
            260.0,
            360.0,
            375.0,
            600.0,
            7,
            SelectVariant::SkyBox,
        );
        assert!(pl.open_above);
        assert!(pl.align_right);
        assert_eq!(pl.max_height_px, 256);

        // Tight vertical space (only 130px available below and 90px above) -> capped dynamically.
        let tight = compute_menu_placement_from_metrics(
            96.0,
            128.0,
            20.0,
            140.0,
            375.0,
            264.0,
            7,
            SelectVariant::SkyBox,
        );
        assert!(!tight.open_above);
        assert!(!tight.align_right);
        assert_eq!(tight.max_height_px, 118);

        // Extremely short viewport floors at 88px.
        let tiny = compute_menu_placement_from_metrics(
            40.0,
            72.0,
            20.0,
            140.0,
            375.0,
            120.0,
            7,
            SelectVariant::SkyBox,
        );
        assert_eq!(tiny.max_height_px, 88);
    }
}
