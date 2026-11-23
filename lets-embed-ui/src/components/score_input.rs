use leptos::{ev, prelude::*};

/// Number of decimal places to display for a given numeric step (e.g. `0.01` -> `2`).
pub fn decimal_places_for_step(step: f32) -> usize {
    if !step.is_finite() || step <= 0.0 {
        return 2;
    }
    let s = format!("{step:.4}");
    let trimmed = s.trim_end_matches('0');
    match trimmed.split_once('.') {
        Some((_, frac)) => frac.len().clamp(0, 4),
        None => 0,
    }
}

/// Clamp `value` to `[min, max]` and quantize cleanly to multiples of `step`.
pub fn quantize_score(value: f32, min: f32, max: f32, step: f32) -> f32 {
    let lo = if min.is_finite() { min } else { 0.01 };
    let hi = if max.is_finite() { max.max(lo) } else { 1.0 };
    let st = if step.is_finite() && step > 0.0 {
        step
    } else {
        0.01
    };
    let clamped = if value.is_finite() {
        value.clamp(lo, hi)
    } else {
        lo
    };
    if (st - 0.01).abs() < 1e-6 {
        let min_h = (lo * 100.0).round();
        let max_h = (hi * 100.0).round();
        let h = (clamped * 100.0).round().clamp(min_h, max_h);
        return h / 100.0;
    }
    let snapped = (clamped / st).round() * st;
    snapped.clamp(lo, hi)
}

/// Format a numeric score quantized to `step` with fixed decimal precision matching `step`
/// (e.g. `step = 0.01` formats `0.5` as `"0.50"`, `0.45` as `"0.45"`, `1.0` as `"1.00"`).
pub fn format_score_for_step(value: f32, min: f32, max: f32, step: f32) -> String {
    let q = quantize_score(value, min, max, step);
    let decimals = decimal_places_for_step(step);
    format!("{q:.decimals$}")
}

/// Parse an in-progress keyboard string while the user is typing.
///
/// Returns `Some(quantized)` ONLY when the raw text parses to a finite number already
/// within `[min, max]`, so intermediate states like `""`, `"0"`, `"0."`, `"-"` do not
/// prematurely snap or fight the user's cursor.
pub fn parse_live_score(raw: &str, min: f32, max: f32, step: f32) -> Option<f32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == "-" || trimmed == "+" {
        return None;
    }
    let parsed = trimmed.parse::<f32>().ok()?;
    if !parsed.is_finite() {
        return None;
    }
    let lo = min.min(max);
    let hi = max.max(min);
    if parsed < lo || parsed > hi {
        return None;
    }
    Some(quantize_score(parsed, lo, hi, step))
}

/// Parse a committed string on blur/Enter: clamps and quantizes any valid finite number
/// into `[min, max]` (returning `None` for empty or non-numeric strings).
pub fn parse_committed_score(raw: &str, min: f32, max: f32, step: f32) -> Option<f32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = trimmed.parse::<f32>().ok()?;
    if !parsed.is_finite() {
        return None;
    }
    let lo = min.min(max);
    let hi = max.max(min);
    Some(quantize_score(parsed, lo, hi, step))
}

/// Keyboard-friendly decimal score input using an internal `focused` + raw-text draft state.
///
/// Never snaps back mid-typing (`""`, `"0"`, `"0."`, `".4"`, Backspace, Select-All + type),
/// never triggers broken native HTML5 `type="number"` step validation popups, supports
/// `ArrowUp` / `ArrowDown` stepping by `step`, and formats cleanly to fixed precision on blur.
#[component]
pub fn ScoreInput(
    /// Current numeric value.
    #[prop(into)]
    value: Signal<f32>,
    /// Invoked with the clamped, step-quantized value on valid input or blur.
    on_change: Callback<f32>,
    #[prop(default = 0.01)] min: f32,
    #[prop(default = 1.00)] max: f32,
    #[prop(default = 0.01)] step: f32,
    #[prop(optional, into)] placeholder: Option<String>,
    #[prop(optional, into)] aria_label: Option<String>,
    #[prop(optional, into)] id: Option<String>,
    #[prop(optional, into)] class: String,
    #[prop(optional, into)] disabled: Option<Signal<bool>>,
) -> impl IntoView {
    let initial = format_score_for_step(value.get_untracked(), min, max, step);
    let raw_text = RwSignal::new(initial);
    let focused = RwSignal::new(false);

    // Sync external signal updates ONLY when this input does not have keyboard focus.
    Effect::new(move |_| {
        let external = value.get();
        if !focused.get_untracked() {
            raw_text.set(format_score_for_step(external, min, max, step));
        }
    });

    let commit_current = move || {
        let cur_raw = raw_text.get_untracked();
        let next = parse_committed_score(&cur_raw, min, max, step)
            .unwrap_or_else(|| quantize_score(value.get_untracked(), min, max, step));
        raw_text.set(format_score_for_step(next, min, max, step));
        on_change.run(next);
    };

    let is_disabled = move || disabled.is_some_and(|d| d.get());
    let full_class = if class.trim().is_empty() {
        "le-score-field".to_string()
    } else {
        format!("le-score-field {}", class.trim())
    };
    let min_str = format_score_for_step(min, min, max, step);
    let max_str = format_score_for_step(max, min, max, step);
    let step_decimals = decimal_places_for_step(step);
    let step_str = format!("{step:.step_decimals$}");
    let placeholder_str = placeholder.unwrap_or_else(|| min_str.clone());

    view! {
        <input
            id=id
            type="text"
            inputmode="decimal"
            autocomplete="off"
            spellcheck="false"
            class=full_class
            aria-label=aria_label
            placeholder=placeholder_str
            data-min=min_str
            data-max=max_str
            data-step=step_str
            disabled=is_disabled
            value=move || raw_text.get()
            prop:value=move || raw_text.get()
            on:focus=move |_| focused.set(true)
            on:input=move |ev| {
                let next_raw = event_target_value(&ev);
                raw_text.set(next_raw.clone());
                if let Some(valid) = parse_live_score(&next_raw, min, max, step) {
                    on_change.run(valid);
                }
            }
            on:keydown=move |ev: ev::KeyboardEvent| {
                match ev.key().as_str() {
                    "ArrowUp" => {
                        ev.prevent_default();
                        let base = parse_committed_score(&raw_text.get_untracked(), min, max, step)
                            .unwrap_or_else(|| value.get_untracked());
                        let next = quantize_score(base + step, min, max, step);
                        raw_text.set(format_score_for_step(next, min, max, step));
                        on_change.run(next);
                    }
                    "ArrowDown" => {
                        ev.prevent_default();
                        let base = parse_committed_score(&raw_text.get_untracked(), min, max, step)
                            .unwrap_or_else(|| value.get_untracked());
                        let next = quantize_score(base - step, min, max, step);
                        raw_text.set(format_score_for_step(next, min, max, step));
                        on_change.run(next);
                    }
                    "Enter" => {
                        commit_current();
                    }
                    _ => {}
                }
            }
            on:blur=move |_| {
                focused.set(false);
                commit_current();
            }
        />
    }
}

/// Optional-value companion to [`ScoreInput`] where an empty input represents `None`
/// (fall back to site/policy default threshold).
#[component]
pub fn OptionalScoreInput(
    /// Current optional numeric threshold (`None` = use default).
    #[prop(into)]
    value: Signal<Option<f32>>,
    /// Invoked with `Some(quantized)` or `None` when cleared.
    on_change: Callback<Option<f32>>,
    #[prop(default = 0.01)] min: f32,
    #[prop(default = 1.00)] max: f32,
    #[prop(default = 0.01)] step: f32,
    #[prop(optional)] placeholder: Option<Signal<String>>,
    #[prop(optional, into)] aria_label: Option<String>,
    #[prop(optional, into)] id: Option<String>,
    #[prop(optional, into)] class: String,
    #[prop(optional, into)] disabled: Option<Signal<bool>>,
) -> impl IntoView {
    let initial = value
        .get_untracked()
        .map(|v| format_score_for_step(v, min, max, step))
        .unwrap_or_default();
    let raw_text = RwSignal::new(initial);
    let focused = RwSignal::new(false);

    // Sync external signal updates ONLY when this input does not have keyboard focus.
    Effect::new(move |_| {
        let external = value.get();
        if !focused.get_untracked() {
            raw_text.set(
                external
                    .map(|v| format_score_for_step(v, min, max, step))
                    .unwrap_or_default(),
            );
        }
    });

    let commit_current = move || {
        let cur_raw = raw_text.get_untracked();
        if cur_raw.trim().is_empty() {
            raw_text.set(String::new());
            on_change.run(None);
            return;
        }
        match parse_committed_score(&cur_raw, min, max, step) {
            Some(valid) => {
                raw_text.set(format_score_for_step(valid, min, max, step));
                on_change.run(Some(valid));
            }
            None => {
                raw_text.set(String::new());
                on_change.run(None);
            }
        }
    };

    let is_disabled = move || disabled.is_some_and(|d| d.get());
    let full_class = if class.trim().is_empty() {
        "le-score-field".to_string()
    } else {
        class.trim().to_string()
    };
    let min_str = format_score_for_step(min, min, max, step);
    let max_str = format_score_for_step(max, min, max, step);
    let step_decimals = decimal_places_for_step(step);
    let step_str = format!("{step:.step_decimals$}");

    view! {
        <input
            id=id
            type="text"
            inputmode="decimal"
            autocomplete="off"
            spellcheck="false"
            class=full_class
            aria-label=aria_label
            placeholder=move || placeholder.map(|p| p.get()).unwrap_or_default()
            data-min=min_str
            data-max=max_str
            data-step=step_str
            disabled=is_disabled
            value=move || raw_text.get()
            prop:value=move || raw_text.get()
            on:focus=move |_| focused.set(true)
            on:input=move |ev| {
                let next_raw = event_target_value(&ev);
                raw_text.set(next_raw.clone());
                if next_raw.trim().is_empty() {
                    on_change.run(None);
                } else if let Some(valid) = parse_live_score(&next_raw, min, max, step) {
                    on_change.run(Some(valid));
                }
            }
            on:keydown=move |ev: ev::KeyboardEvent| {
                match ev.key().as_str() {
                    "ArrowUp" => {
                        ev.prevent_default();
                        let base = parse_committed_score(&raw_text.get_untracked(), min, max, step)
                            .or_else(|| value.get_untracked())
                            .unwrap_or(min - step);
                        let next = quantize_score(base + step, min, max, step);
                        raw_text.set(format_score_for_step(next, min, max, step));
                        on_change.run(Some(next));
                    }
                    "ArrowDown" => {
                        ev.prevent_default();
                        let base = parse_committed_score(&raw_text.get_untracked(), min, max, step)
                            .or_else(|| value.get_untracked())
                            .unwrap_or(min + step);
                        let next = quantize_score(base - step, min, max, step);
                        raw_text.set(format_score_for_step(next, min, max, step));
                        on_change.run(Some(next));
                    }
                    "Enter" => {
                        commit_current();
                    }
                    _ => {}
                }
            }
            on:blur=move |_| {
                focused.set(false);
                commit_current();
            }
        />
    }
}
