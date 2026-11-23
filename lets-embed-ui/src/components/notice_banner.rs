use leptos::prelude::*;

use crate::browser::{load_notice_dismissed, save_notice_dismissed};
use crate::models::{NoticeContent, NoticeTone};

/// Dismissible site announcement / cookie / safety notice banner.
///
/// Renders [`NoticeContent::Text`] as escaped plain text by default.
///
/// # Security
/// Only pass [`NoticeContent::PreSanitizedHtml`] when the HTML string has been
/// sanitized server-side through a strict HTML allowlist (e.g. `ammonia`).
/// Never pass unsanitized Markdown or user-controlled HTML.
#[component]
pub fn NoticeBanner(
    content: NoticeContent,
    #[prop(default = NoticeTone::Info)] tone: NoticeTone,
    #[prop(optional, into)] title: Option<String>,
    #[prop(optional, into)] dismiss_key: Option<String>,
    #[prop(default = true)] dismissible: bool,
    #[prop(optional)] on_dismiss: Option<Callback<()>>,
) -> impl IntoView {
    let dismissed = RwSignal::new(false);
    let key_stored = StoredValue::new(dismiss_key);

    // Check localStorage strictly after mount so SSR and initial hydration markup match.
    #[cfg(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr")))]
    Effect::new(move |_| {
        if let Some(k) = key_stored.get_value()
            && load_notice_dismissed(&k)
        {
            dismissed.set(true);
        }
    });
    #[cfg(not(all(any(feature = "csr", feature = "hydrate"), not(feature = "ssr"))))]
    {
        let _ = load_notice_dismissed;
    }

    let tone_slug = tone.as_str();
    let content_stored = StoredValue::new(content);
    let title_stored = StoredValue::new(title);

    let handle_dismiss = move |_| {
        dismissed.set(true);
        if let Some(k) = key_stored.get_value() {
            save_notice_dismissed(&k);
        }
        if let Some(cb) = on_dismiss {
            cb.run(());
        }
    };

    view! {
        {move || {
            (!dismissed.get()).then(|| {
                let body = match content_stored.get_value() {
                    NoticeContent::Text(text) => view! {
                        <span class="le-notice-text">{text}</span>
                    }
                    .into_any(),
                    NoticeContent::PreSanitizedHtml(html) => view! {
                        <span class="le-notice-html" inner_html=html />
                    }
                    .into_any(),
                };
                let heading = title_stored.get_value();
                view! {
                    <aside
                        class=format!("le-notice le-notice--{tone_slug}")
                        role="status"
                        aria-live="polite"
                    >
                        <div class="le-notice-body">
                            {heading.map(|t| view! {
                                <strong class="le-notice-title">{t}</strong>
                            })}
                            {body}
                        </div>
                        {dismissible.then(|| view! {
                            <button
                                type="button"
                                class="le-notice-dismiss"
                                aria-label="Dismiss notice"
                                title="Dismiss"
                                on:click=handle_dismiss
                            >
                                "\u{00D7}"
                            </button>
                        })}
                    </aside>
                }
            })
        }}
    }
}
