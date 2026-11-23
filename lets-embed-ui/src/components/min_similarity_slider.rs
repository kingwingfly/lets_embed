use leptos::prelude::*;

/// Compact reusable DINOv3 / SigLIP2 cosine similarity cutoff slider (`0.00`–`1.00`).
#[component]
pub fn MinSimilaritySlider(
    value: RwSignal<f32>,
    #[prop(default = "Min similarity")] label: &'static str,
    #[prop(optional)] model_badge: Option<&'static str>,
    #[prop(default = 0.0)] min: f32,
    #[prop(default = 1.0)] max: f32,
    #[prop(default = 0.01)] step: f32,
    #[prop(default = false)] compact: bool,
    #[prop(optional)] on_change: Option<Callback<f32>>,
) -> impl IntoView {
    let min_clamped = min.clamp(0.0, 1.0);
    let max_clamped = max.clamp(min_clamped, 1.0);
    let step_safe = if step > 0.0 && step.is_finite() {
        step
    } else {
        0.01
    };

    let readout = move || {
        let v = value.get().clamp(min_clamped, max_clamped);
        if v <= min_clamped + 0.0005 && min_clamped <= 0.0005 {
            "Off".to_string()
        } else {
            format!("{v:.2}")
        }
    };

    let root_cls = if compact {
        "le-sim-slider le-sim-slider--compact"
    } else {
        "le-sim-slider"
    };

    view! {
        <div class=root_cls>
            <div class="le-sim-slider-head">
                <span class="le-sim-slider-label">{label}</span>
                {model_badge.map(|badge| view! {
                    <span class="le-sim-slider-badge">{badge}</span>
                })}
                <span class="le-sim-slider-value" aria-live="polite">{readout}</span>
            </div>
            <div class="le-sim-slider-track">
                <input
                    type="range"
                    class="le-sim-slider-input"
                    aria-label=label
                    min=format!("{min_clamped:.2}")
                    max=format!("{max_clamped:.2}")
                    step=format!("{step_safe:.2}")
                    value=move || format!("{:.2}", value.get().clamp(min_clamped, max_clamped))
                    prop:value=move || format!("{:.2}", value.get().clamp(min_clamped, max_clamped))
                    on:input=move |ev| {
                        if let Ok(parsed) = event_target_value(&ev).parse::<f32>()
                            && parsed.is_finite()
                        {
                            let clamped = parsed.clamp(min_clamped, max_clamped);
                            value.set(clamped);
                            if let Some(cb) = on_change {
                                cb.run(clamped);
                            }
                        }
                    }
                />
                {move || (value.get() > min_clamped + 0.0005).then(|| view! {
                    <button
                        type="button"
                        class="le-sim-slider-reset"
                        title="Reset similarity filter"
                        aria-label="Reset similarity filter"
                        on:click=move |_| {
                            value.set(min_clamped);
                            if let Some(cb) = on_change {
                                cb.run(min_clamped);
                            }
                        }
                    >
                        "\u{00D7}"
                    </button>
                })}
            </div>
        </div>
    }
}
