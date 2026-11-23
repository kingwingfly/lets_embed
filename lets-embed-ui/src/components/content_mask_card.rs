use leptos::prelude::*;

use crate::models::{GalleryMask, GalleryMaskPreset};

/// Bundled inline SVG illustration for each safety preset.
/// Never references any external image URL or media asset.
fn preset_illustration(preset: GalleryMaskPreset) -> AnyView {
    match preset {
        GalleryMaskPreset::R18 => view! {
            <svg
                class="le-mask-svg"
                viewBox="0 0 88 88"
                fill="none"
                aria-hidden="true"
                xmlns="http://www.w3.org/2000/svg"
            >
                <defs>
                    <linearGradient id="le-r18-ring" x1="12" y1="10" x2="76" y2="78" gradientUnits="userSpaceOnUse">
                        <stop offset="0%" stop-color="#fb7185" />
                        <stop offset="100%" stop-color="#e11d48" />
                    </linearGradient>
                </defs>
                <circle cx="44" cy="44" r="36" fill="#fff1f2" stroke="url(#le-r18-ring)" stroke-width="4" />
                <circle cx="44" cy="44" r="28" fill="#ffe4e6" stroke="#fda4af" stroke-width="1.5" stroke-dasharray="4 3" />
                <text
                    x="44"
                    y="51"
                    text-anchor="middle"
                    font-family="system-ui, -apple-system, sans-serif"
                    font-size="23"
                    font-weight="800"
                    letter-spacing="-0.5"
                    fill="#be123c"
                >
                    "18+"
                </text>
            </svg>
        }
        .into_any(),
        GalleryMaskPreset::Blood => view! {
            <svg
                class="le-mask-svg"
                viewBox="0 0 88 88"
                fill="none"
                aria-hidden="true"
                xmlns="http://www.w3.org/2000/svg"
            >
                <path
                    d="M44 12L77 70C78.5 72.7 76.6 76 73.5 76H14.5C11.4 76 9.5 72.7 11 70L44 12Z"
                    fill="#fef2f2"
                    stroke="#dc2626"
                    stroke-width="4"
                    stroke-linejoin="round"
                />
                <path
                    d="M44 31V51"
                    stroke="#b91c1c"
                    stroke-width="5.5"
                    stroke-linecap="round"
                />
                <circle cx="44" cy="62" r="3.6" fill="#b91c1c" />
            </svg>
        }
        .into_any(),
        GalleryMaskPreset::Sensitive => view! {
            <svg
                class="le-mask-svg"
                viewBox="0 0 88 88"
                fill="none"
                aria-hidden="true"
                xmlns="http://www.w3.org/2000/svg"
            >
                <rect x="10" y="10" width="68" height="68" rx="22" fill="#eef2ff" stroke="#818cf8" stroke-width="3.5" />
                <path
                    d="M21 44C26.5 34.5 34.8 30 44 30C53.2 30 61.5 34.5 67 44C61.5 53.5 53.2 58 44 58C34.8 58 26.5 53.5 21 44Z"
                    fill="#ffffff"
                    stroke="#4f46e5"
                    stroke-width="3.2"
                    stroke-linejoin="round"
                />
                <circle cx="44" cy="44" r="7.5" fill="#c7d2fe" stroke="#4f46e5" stroke-width="3" />
                <path d="M24 64L64 24" stroke="#4338ca" stroke-width="4" stroke-linecap="round" />
            </svg>
        }
        .into_any(),
        GalleryMaskPreset::Custom => view! {
            <svg
                class="le-mask-svg"
                viewBox="0 0 88 88"
                fill="none"
                aria-hidden="true"
                xmlns="http://www.w3.org/2000/svg"
            >
                <path
                    d="M44 10L72 21V42C72 59.5 59.8 73.5 44 78C28.2 73.5 16 59.5 16 42V21L44 10Z"
                    fill="#f0f9ff"
                    stroke="#0284c7"
                    stroke-width="3.8"
                    stroke-linejoin="round"
                />
                <rect x="33" y="42" width="22" height="17" rx="4" fill="#bae6fd" stroke="#0369a1" stroke-width="3" />
                <path
                    d="M37.5 42V36.5C37.5 32.9 40.4 30 44 30C47.6 30 50.5 32.9 50.5 36.5V42"
                    stroke="#0369a1"
                    stroke-width="3"
                    stroke-linecap="round"
                />
                <circle cx="44" cy="50.5" r="2.4" fill="#0369a1" />
            </svg>
        }
        .into_any(),
    }
}

/// Locked placeholder card rendered for [`GalleryMedia::Locked`](crate::models::GalleryMedia::Locked)
/// items.
///
/// Preserves the media's aspect ratio (`dimensions`) with zero layout shift, displays
/// a bundled inline SVG preset illustration + descriptive lock reason + unlock CTA
/// callback, and **never renders any media URL, `<img>`, or `<video>` element**.
#[component]
pub fn ContentMaskCard(
    mask: GalleryMask,
    #[prop(default = (4, 3))] dimensions: (i32, i32),
    #[prop(default = false)] compact: bool,
    #[prop(optional)] on_unlock_click: Option<Callback<GalleryMask>>,
) -> impl IntoView {
    let (w, h) = if dimensions.0 > 0 && dimensions.1 > 0 {
        dimensions
    } else {
        (4, 3)
    };
    let aspect_style = format!("aspect-ratio: {w} / {h};");
    let preset = mask.preset;
    let preset_slug = preset.as_str();
    let label = if mask.label.trim().is_empty() {
        preset.label().to_string()
    } else {
        mask.label.clone()
    };
    let badge = preset.short_badge();
    let reason = mask.resolved_reason();
    let cta_text = mask.resolved_cta();
    let rule_id = mask.rule_id.clone();

    let card_cls = if compact {
        format!("le-mask-card le-mask-card--{preset_slug} le-mask-card--compact")
    } else {
        format!("le-mask-card le-mask-card--{preset_slug}")
    };
    let aria_label = format!("Locked content: {label}");

    view! {
        <div
            class=card_cls
            style=aspect_style
            data-mask-preset=preset_slug
            data-rule-id=rule_id
            role="region"
            aria-label=aria_label
        >
            <div class="le-mask-card-inner">
                <div class="le-mask-art">
                    {preset_illustration(preset)}
                </div>
                <span class="le-mask-badge">{badge}</span>
                <div class="le-mask-title">{label}</div>
                <p class="le-mask-reason">{reason}</p>
                {on_unlock_click.map(|cb| {
                    let mask_for_cb = mask.clone();
                    view! {
                        <button
                            type="button"
                            class="le-mask-cta"
                            on:click=move |ev: leptos::ev::MouseEvent| {
                                ev.stop_propagation();
                                cb.run(mask_for_cb.clone());
                            }
                        >
                            {cta_text}
                        </button>
                    }
                })}
            </div>
        </div>
    }
}
