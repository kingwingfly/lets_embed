use leptos::{ev, prelude::*};

use crate::models::{LikeTargetKind, LikeVariant};

/// Pure prop/callback-driven favorite toggle button (`♥`/`♡` for images & videos,
/// `★`/`☆` for posts) supporting optimistic UI updates.
#[component]
pub fn LikeButton(
    kind: LikeTargetKind,
    target_id: i64,
    liked: Signal<bool>,
    #[prop(optional)] pending: Option<Signal<bool>>,
    #[prop(optional, into)] signed_out_href: Option<String>,
    #[prop(default = LikeVariant::Inline)] variant: LikeVariant,
    #[prop(default = false)] show_label: bool,
    #[prop(default = false)] hide_label_mobile: bool,
    #[prop(default = true)] optimistic: bool,
    #[prop(optional)] on_toggle: Option<Callback<bool>>,
) -> impl IntoView {
    let optimistic_override: RwSignal<Option<bool>> = RwSignal::new(None);

    // Clear optimistic override whenever the authoritative `liked` prop updates.
    Effect::new(move |_| {
        let _ = liked.get();
        optimistic_override.set(None);
    });

    let effective_liked = Memo::new(move |_| {
        if optimistic {
            optimistic_override.get().unwrap_or_else(|| liked.get())
        } else {
            liked.get()
        }
    });

    let is_pending = move || pending.is_some_and(|p| p.get());
    let kind_slug = kind.as_str();
    let label_text = kind.label();
    let filled = kind.filled_icon();
    let outline = kind.outline_icon();

    let variant_cls = match variant {
        LikeVariant::Inline => "le-like-btn--inline",
        LikeVariant::Card => "le-like-btn--card",
        LikeVariant::Overlay => "le-like-btn--overlay",
    };
    let label_cls = if hide_label_mobile {
        "le-like-label le-hide-mobile"
    } else {
        "le-like-label"
    };

    if let Some(href) = signed_out_href {
        let cls = format!("le-like-btn {variant_cls} le-like-btn--{kind_slug}");
        return view! {
            <a
                href=href
                rel="external"
                class=cls
                aria-label=format!("Sign in to favorite this {kind_slug}")
                title=format!("Sign in to favorite this {kind_slug}")
                on:click=|ev: ev::MouseEvent| ev.stop_propagation()
            >
                <span class="le-like-icon" aria-hidden="true">{outline}</span>
                {show_label.then(|| view! { <span class=label_cls>{label_text}</span> })}
            </a>
        }
        .into_any();
    }

    let on_click = move |ev: ev::MouseEvent| {
        ev.stop_propagation();
        ev.prevent_default();
        if is_pending() {
            return;
        }
        let next = !effective_liked.get_untracked();
        if optimistic {
            optimistic_override.set(Some(next));
        }
        if let Some(cb) = on_toggle {
            cb.run(next);
        }
    };

    view! {
        <button
            type="button"
            class=move || {
                let state = if effective_liked.get() { " is-liked" } else { "" };
                let busy = if is_pending() { " is-pending" } else { "" };
                format!("le-like-btn {variant_cls} le-like-btn--{kind_slug}{state}{busy}")
            }
            data-target-kind=kind_slug
            data-target-id=target_id
            aria-pressed=move || effective_liked.get().to_string()
            aria-label=move || {
                if effective_liked.get() {
                    format!("Remove {kind_slug} #{target_id} from favorites")
                } else {
                    format!("Favorite {kind_slug} #{target_id}")
                }
            }
            title=move || {
                if effective_liked.get() {
                    format!("Remove {kind_slug} from favorites")
                } else {
                    format!("Favorite this {kind_slug}")
                }
            }
            disabled=is_pending
            on:click=on_click
        >
            <span class="le-like-icon" aria-hidden="true">
                {move || if effective_liked.get() { filled } else { outline }}
            </span>
            {show_label.then(|| view! { <span class=label_cls>{label_text}</span> })}
        </button>
    }
    .into_any()
}
