use leptos::prelude::*;

use crate::browser::{save_density, use_density_storage_sync};
use crate::models::Density;

/// `Compact` / `Medium` / `Large` masonry density controller with `localStorage`
/// persistence and cross-tab `storage`-event synchronization.
///
/// Guarantees distinct mobile column counts (`Compact = 3`, `Medium = 2`, `Large = 1`).
#[component]
pub fn DensityPicker(
    density: RwSignal<Density>,
    #[prop(default = false)] dark: bool,
    #[prop(default = true)] persist: bool,
    #[prop(optional)] on_change: Option<Callback<Density>>,
    #[prop(default = "Grid size")] aria_label: &'static str,
) -> impl IntoView {
    if persist {
        use_density_storage_sync(density);
    }

    let group_cls = if dark {
        "gallery-density gallery-density-dark le-density-picker"
    } else {
        "gallery-density le-density-picker"
    };

    view! {
        <div class=group_cls role="group" aria-label=aria_label>
            {Density::ALL.into_iter().map(|d| {
                let label = d.label();
                let data_size = d.as_str();
                view! {
                    <button
                        type="button"
                        class="gallery-density-btn le-density-btn"
                        data-density=data_size
                        aria-pressed=move || (density.get() == d).to_string()
                        on:click=move |_| {
                            density.set(d);
                            if persist {
                                save_density(d);
                            }
                            if let Some(cb) = on_change {
                                cb.run(d);
                            }
                        }
                    >
                        {label}
                    </button>
                }
            }).collect_view()}
        </div>
    }
}
