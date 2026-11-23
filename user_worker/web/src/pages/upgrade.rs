//! `/user/upgrade` — Pricing summary & sign-in prompt redirecting signed-in users to `/user/account#topup`.

use leptos::prelude::*;
use leptos::task::spawn_local;
use lets_embed_ui::{NoticeBanner, NoticeContent, NoticeTone};

use crate::{
    api::{self, BootstrapResp},
    pages::login::LoginView,
};

#[component]
pub fn UpgradePage() -> impl IntoView {
    let boot = RwSignal::new(None::<BootstrapResp>);

    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(b) = api::get_json::<BootstrapResp>("/user/api/bootstrap").await {
                if b.signed_in {
                    api::navigate_hard("/user/account#topup");
                    return;
                }
                boot.set(Some(b));
            }
        });
    });

    let banner = move || {
        let b = boot.get()?;
        if !b.deposit_open {
            return Some(
                view! {
                    <NoticeBanner
                        content=NoticeContent::Text("New crypto deposits are currently closed. You can still sign in to use existing points.".into())
                        tone=NoticeTone::Warning
                        dismissible=false
                    />
                }
                .into_any(),
            );
        }
        Some(
            view! {
                <section class="u-card">
                    <h2>"Continue exploring"</h2>
                    <p class="u-sub">
                        "This item is outside your free allowance. Sign in to use points or unlock full access."
                    </p>
                    <div class="u-stats">
                        <div class="u-stat">
                            <div class="u-stat-label">"Points per USD"</div>
                            <div class="u-stat-val">{b.points_per_usd}</div>
                        </div>
                        <div class="u-stat">
                            <div class="u-stat-label">"Minimum top-up"</div>
                            <div class="u-stat-val">{api::format_points(b.minimum_topup)}</div>
                        </div>
                    </div>
                </section>
            }
            .into_any(),
        )
    };

    view! {
        <LoginView
            heading="Continue exploring"
            intro="Sign in to view your balance, subscribe, or top up points."
            default_next="/user/account#topup"
            extra_header=ViewFn::from(banner)
        />
    }
}
