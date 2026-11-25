//! `/user/upgrade` — Free-limit & pricing explanation with sign-in prompt; redirects
//! signed-in users to `/user/account?reason=quota#topup`.

use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::{
    api::{self, BootstrapResp},
    pages::login::LoginView,
};

#[component]
pub fn UpgradePage() -> impl IntoView {
    let boot = RwSignal::new(None::<BootstrapResp>);
    let reason = StoredValue::new(api::current_search_param("reason"));

    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(b) = api::get_json::<BootstrapResp>("/user/api/bootstrap").await {
                if b.signed_in {
                    api::navigate_hard("/user/account?reason=quota#topup");
                    return;
                }
                boot.set(Some(b));
            }
        });
    });

    let is_quota_reason = reason.get_value().as_deref() == Some("quota");
    let callout_title = if is_quota_reason {
        "Quota or points limit reached"
    } else {
        "Daily free allowance reached"
    };
    let callout_body = if is_quota_reason {
        "Your current viewing or search quota has run out. Sign in to check your balance, subscribe to a plan, or top up points."
    } else {
        "You\u{2019}ve reached today\u{2019}s free viewing or search limit, or this item isn\u{2019}t covered by anonymous free access. Free daily limits reset at 00:00 UTC."
    };

    let banner = move || {
        let maybe_boot = boot.get();
        view! {
            <aside class="u-login-callout u-login-callout--warn" role="status" aria-live="polite">
                <span class="u-login-callout-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                </span>
                <div class="u-login-callout-body">
                    <strong class="u-login-callout-title">{callout_title}</strong>
                    <p class="u-login-callout-text">{callout_body}</p>
                    {maybe_boot.map(|b| {
                        let show_signup = b.signup_points > 0;
                        let show_pricing = b.deposit_open;
                        view! {
                            <div class="u-login-callout-meta">
                                {show_signup.then(|| view! {
                                    <span class="u-login-callout-pill u-login-callout-pill--ok">
                                        {format!("New accounts get {} free", api::format_points(b.signup_points))}
                                    </span>
                                })}
                                {show_pricing.then(|| view! {
                                    <span class="u-login-callout-pill">
                                        {format!("{} pts / USD", api::format_number(b.points_per_usd))}
                                    </span>
                                    <span class="u-login-callout-pill">
                                        {format!("Min top-up: {} pts", api::format_number(b.minimum_topup))}
                                    </span>
                                })}
                            </div>
                            {(!b.deposit_open).then(|| view! {
                                <p class="u-login-callout-note">
                                    "New crypto deposits are currently closed. You can still sign in to use existing points or free signup points."
                                </p>
                            })}
                        }
                    })}
                </div>
            </aside>
        }
        .into_any()
    };

    view! {
        <LoginView
            heading="Sign in to continue"
            intro="Use your account\u{2019}s points balance or a subscription plan to keep exploring, or come back after 00:00 UTC."
            default_next="/user/account#topup"
            extra_header=ViewFn::from(banner)
        />
    }
}
