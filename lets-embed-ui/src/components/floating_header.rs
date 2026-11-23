use leptos::prelude::*;

use crate::models::HeaderVariant;

/// Sticky/floating frosted-glass header bar matching the sky-blue glass aesthetic
/// across `/` (`floating-nav-card`), `/details/:id` (`gallery-floating-bar`),
/// `/user/favorites`, and `/admin`.
#[component]
pub fn FloatingHeader(
    #[prop(default = HeaderVariant::Nav)] variant: HeaderVariant,
    #[prop(default = true)] sticky: bool,
    #[prop(optional, into)] class: String,
    #[prop(optional, into)] aria_label: Option<String>,
    #[prop(optional, into)] left: Option<ViewFn>,
    #[prop(optional, into)] center: Option<ViewFn>,
    #[prop(optional, into)] right: Option<ViewFn>,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    let variant_cls = match variant {
        HeaderVariant::Nav => "le-floating-header le-floating-header--nav floating-nav-card",
        HeaderVariant::Toolbar => {
            "le-floating-header le-floating-header--toolbar gallery-floating-bar"
        }
    };
    let sticky_cls = if sticky {
        "le-floating-header--sticky"
    } else {
        "le-floating-header--static"
    };
    let full_cls = if class.trim().is_empty() {
        format!("{variant_cls} {sticky_cls}")
    } else {
        format!("{variant_cls} {sticky_cls} {class}")
    };

    let has_slots = left.is_some() || center.is_some() || right.is_some();

    view! {
        <header class=full_cls aria-label=aria_label>
            {has_slots.then(move || {
                view! {
                    <div class="le-floating-header-row">
                        {left.map(|slot| view! {
                            <div class="le-floating-header-left">{slot.run()}</div>
                        })}
                        {center.map(|slot| view! {
                            <div class="le-floating-header-center">{slot.run()}</div>
                        })}
                        {right.map(|slot| view! {
                            <div class="le-floating-header-right">{slot.run()}</div>
                        })}
                    </div>
                }
            })}
            {children.map(|c| c())}
        </header>
    }
}
