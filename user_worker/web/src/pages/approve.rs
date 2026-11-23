//! `/user/login/approve` — Cross-device QR handoff approval page (ETH & Solana wallets).

use leptos::prelude::*;
use leptos::task::spawn_local;
use lets_embed_ui::{FloatingHeader, HeaderVariant, NoticeBanner, NoticeContent, NoticeTone};
use serde_json::json;

use crate::{
    api::{self, BootstrapResp, HandoffInfoResp},
    wallet,
};

#[component]
pub fn ApprovePage() -> impl IntoView {
    let session_id = StoredValue::new(api::current_search_param("s").unwrap_or_default());

    let bootstrap = RwSignal::new(None::<BootstrapResp>);
    let info = RwSignal::new(None::<HandoffInfoResp>);
    let busy = RwSignal::new(false);
    let error_msg = RwSignal::new(None::<String>);
    let success_msg = RwSignal::new(None::<String>);

    Effect::new(move |_| {
        let sid = session_id.get_value();
        spawn_local(async move {
            if let Ok(b) = api::get_json::<BootstrapResp>("/user/api/bootstrap").await {
                bootstrap.set(Some(b));
            }
            if sid.is_empty() {
                error_msg.set(Some("Missing handoff session parameter (?s=...).".into()));
                return;
            }
            let url = format!("/user/api/handoff/info?s={}", urlencoding::encode(&sid));
            match api::get_json::<HandoffInfoResp>(&url).await {
                Ok(h) => info.set(Some(h)),
                Err(e) => error_msg.set(Some(e.display())),
            }
        });
    });

    let approve_eth = move |_| {
        let Some(boot) = bootstrap.get_untracked() else {
            return;
        };
        let Some(h) = info.get_untracked() else {
            return;
        };
        let sid = session_id.get_value();
        busy.set(true);
        error_msg.set(None);
        spawn_local(async move {
            let statement = format!(
                "Approve sign-in for another browser on lets_embed (Code: {}, Session: {})",
                h.verify_code, sid
            );
            let uri = format!("{}/user/login/approve", api::current_origin());
            let signed = wallet::connect_and_sign_siwe(
                "",
                &boot.siwe_domain,
                boot.chain_id,
                &h.approve_nonce,
                &statement,
                Some(&uri),
            )
            .await;
            match signed {
                Ok(sig) => {
                    match api::post_json_empty(
                        "/user/api/handoff/approve_eth",
                        &json!({
                            "session_id": sid,
                            "message": sig.message,
                            "signature": sig.signature,
                        }),
                    )
                    .await
                    {
                        Ok(()) => {
                            success_msg.set(Some(
                                "Sign-in approved! You can return to your other browser now."
                                    .into(),
                            ));
                        }
                        Err(e) => error_msg.set(Some(e.display())),
                    }
                }
                Err(msg) => error_msg.set(Some(msg)),
            }
            busy.set(false);
        });
    };

    let approve_sol = move |_| {
        let Some(boot) = bootstrap.get_untracked() else {
            return;
        };
        let Some(h) = info.get_untracked() else {
            return;
        };
        let sid = session_id.get_value();
        busy.set(true);
        error_msg.set(None);
        spawn_local(async move {
            let challenge = format!(
                "Approve sign-in for another browser on lets_embed with Solana\nDomain: {}\nSession: {}\nCode: {}\nNonce: {}",
                boot.siwe_domain, sid, h.verify_code, h.approve_nonce
            );
            match wallet::connect_and_sign_sol_message("", &challenge).await {
                Ok(sig) => {
                    match api::post_json_empty(
                        "/user/api/handoff/approve_sol",
                        &json!({
                            "session_id": sid,
                            "solana_address": sig.address,
                            "signature": sig.signature,
                            "nonce": h.approve_nonce,
                            "signed_message": sig.signed_message,
                        }),
                    )
                    .await
                    {
                        Ok(()) => {
                            success_msg.set(Some(
                                "Sign-in approved! You can return to your other browser now."
                                    .into(),
                            ));
                        }
                        Err(e) => error_msg.set(Some(e.display())),
                    }
                }
                Err(msg) => error_msg.set(Some(msg)),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="u-shell u-shell--narrow">
            <FloatingHeader
                variant=HeaderVariant::Nav
                left=move || view! {
                    <nav class="u-nav-links">
                        <a class="u-nav-link" href="/">"Gallery"</a>
                        <a class="u-nav-link is-active" href="/user/login/approve">"Approve sign-in"</a>
                    </nav>
                }.into_any()
            />
            <div class="u-stack">
                {move || error_msg.get().map(|msg| view! {
                    <NoticeBanner
                        content=NoticeContent::Text(msg)
                        tone=NoticeTone::Danger
                        dismissible=false
                    />
                })}
                {move || success_msg.get().map(|msg| view! {
                    <NoticeBanner
                        content=NoticeContent::Text(msg)
                        tone=NoticeTone::Success
                        dismissible=false
                    />
                })}

                <section class="u-card">
                    <h1>"Approve cross-device sign-in"</h1>
                    <p class="u-sub">
                        "Confirm that the 4-digit verification code below matches the screen you are signing in on."
                    </p>
                    {move || match info.get() {
                        None => view! { <p class="u-sub">"Loading handoff details..."</p> }.into_any(),
                        Some(h) if h.status != "pending" => view! {
                            <NoticeBanner
                                content=NoticeContent::Text(format!("This handoff session is already {}.", h.status))
                                tone=NoticeTone::Warning
                                dismissible=false
                            />
                        }.into_any(),
                        Some(h) => view! {
                            <div class="u-stack">
                                <div class="u-qr-box">
                                    <span class="u-sub">"Verification Code"</span>
                                    <div class="u-verify-code">{h.verify_code}</div>
                                </div>
                                <div class="u-row">
                                    <button
                                        type="button"
                                        class="u-btn u-btn--full"
                                        disabled=move || busy.get() || success_msg.get().is_some()
                                        on:click=approve_eth
                                    >
                                        "Approve with Ethereum Wallet"
                                    </button>
                                    <button
                                        type="button"
                                        class="u-btn u-btn--secondary u-btn--full"
                                        disabled=move || busy.get() || success_msg.get().is_some()
                                        on:click=approve_sol
                                    >
                                        "Approve with Solana Wallet"
                                    </button>
                                </div>
                            </div>
                        }.into_any(),
                    }}
                </section>
            </div>
        </div>
    }
}
