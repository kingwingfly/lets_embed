//! Access & Pricing tab: login wall, free media folders, per-item pricing/quotas,
//! 30-day subscription plans, exchange rate, and crypto deposit treasury addresses.
//!
//! Uses root `AdminDraftStore` so unsaved edits persist across tab switches,
//! clean left-aligned radio cards, and GCP top-right toasts via `use_toast_store()`.

use leptos::prelude::*;
use lets_embed_ui::use_toast_store;
use site_access::ChargeKind;
use wasm_bindgen_futures::spawn_local;

use crate::{
    api::{
        AccessPolicy, ActivationResult, OverviewResp, SaveAccessReq, SaveAccessResp,
        post_json_activatable,
    },
    drafts::use_admin_drafts,
};

#[component]
pub fn AccessTab(
    overview: RwSignal<Option<OverviewResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let toasts = use_toast_store();
    let draft = use_admin_drafts().access;

    let saving = RwSignal::new(false);

    let on_discard = move |_| {
        if let Some(ov) = overview.get_untracked() {
            draft.hydrate(&ov);
            draft.dirty.set(false);
            toasts.info("Discarded unsaved Access & Pricing changes", None);
        }
    };

    let save_action = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if saving.get_untracked() {
            return;
        }
        saving.set(true);

        let pr = draft.items_prices.get_untracked();
        let fr = draft.items_free.get_untracked();
        let pp = draft.plan_prices.get_untracked();
        let pv = draft.plan_views.get_untracked();
        let ps = draft.plan_searches.get_untracked();

        let folders: Vec<String> = draft
            .free_folders_text
            .get_untracked()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();

        let current_rev = overview
            .get_untracked()
            .map(|o| o.revision)
            .unwrap_or_else(|| draft.revision.get_untracked());

        let req = SaveAccessReq {
            revision: current_rev,
            access: AccessPolicy {
                login_required: draft.login_required.get_untracked(),
                free_media_folders: folders,
                items: std::array::from_fn(|i| crate::api::ItemPricing {
                    price: pr[i],
                    daily_free: fr[i],
                }),
                plans: std::array::from_fn(|i| crate::api::PlanTerms {
                    price: pp[i],
                    views: (pv[i] >= 0).then_some(pv[i]),
                    searches: ps[i],
                }),
                signup_points: draft.signup_points.get_untracked(),
                points_per_usd: draft.points_per_usd.get_untracked(),
                minimum_topup: draft.minimum_topup.get_untracked(),
                eth_deposit: draft.eth_deposit.get_untracked(),
                sol_deposit: draft.sol_deposit.get_untracked(),
            },
        };

        spawn_local(async move {
            match post_json_activatable::<_, SaveAccessResp>("/admin/api/settings/access", &req)
                .await
            {
                Ok(ActivationResult::Active(resp)) => {
                    draft.revision.set(resp.revision);
                    draft.dirty.set(false);
                    if resp.unchanged {
                        toasts.info(format!("No changes to save (rev #{})", resp.revision), None);
                    } else {
                        toasts.success(
                            format!("Saved Access & Pricing rev #{}", resp.revision),
                            Some(format!(
                                "min_enforce_rev #{} · activated on SitePolicyDO",
                                resp.min_enforce_rev
                            )),
                        );
                        on_saved.run(());
                    }
                }
                Ok(ActivationResult::PendingActivation(pending)) => {
                    draft.revision.set(pending.revision);
                    draft.dirty.set(false);
                    toasts.warning(
                        format!(
                            "Saved rev #{} to D1 — awaiting SitePolicyDO activation",
                            pending.revision
                        ),
                        Some(pending.error),
                    );
                    on_saved.run(());
                }
                Err(err) => {
                    toasts.error("Failed to save Access & Pricing", Some(err.message));
                }
            }
            saving.set(false);
        });
    };

    view! {
        <form class="adm-stack" on:submit=save_action>
            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Browsing Access & Free Folders"</h2>
                        <p class="adm-sub">"Control login requirements and which folders qualify for daily free allowances."</p>
                    </div>
                    <span class="adm-pill">
                        {move || if draft.login_required.get() { "Login required" } else { "Public browsing" }}
                    </span>
                </div>

                <div class="adm-grid-2">
                    <label class="adm-radio-card">
                        <input
                            type="radio"
                            name="login_required"
                            prop:checked=move || draft.login_required.get()
                            on:change=move |_| {
                                draft.login_required.set(true);
                                draft.dirty.set(true);
                            }
                        />
                        <span class="adm-radio-copy">
                            <strong>"Require sign-in"</strong>
                            <small>"Visitors must sign in before opening the gallery."</small>
                        </span>
                    </label>
                    <label class="adm-radio-card">
                        <input
                            type="radio"
                            name="login_required"
                            prop:checked=move || !draft.login_required.get()
                            on:change=move |_| {
                                draft.login_required.set(false);
                                draft.dirty.set(true);
                            }
                        />
                        <span class="adm-radio-copy">
                            <strong>"Public browsing"</strong>
                            <small>"Guests can browse using daily free quotas below."</small>
                        </span>
                    </label>
                </div>

                <label class="adm-field">
                    <span>"Free media folders (one path per line under /images or /videos; empty = all)"</span>
                    <textarea
                        rows="3"
                        placeholder="/images/Sample album"
                        prop:value=move || draft.free_folders_text.get()
                        on:input=move |ev| {
                            draft.free_folders_text.set(event_target_value(&ev));
                            draft.dirty.set(true);
                        }
                    />
                </label>
            </section>

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Prices & Daily Free Allowances"</h2>
                        <p class="adm-sub">"0 closes an item to guests; -1 grants unlimited free daily access."</p>
                    </div>
                </div>
                <div class="adm-table-wrap">
                    <table class="adm-table">
                        <thead>
                            <tr>
                                <th>"Item"</th>
                                <th>"Points / item"</th>
                                <th>"Free / day (-1 = unlimited)"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {ChargeKind::ALL.into_iter().map(|kind| {
                                let idx = kind as usize;
                                view! {
                                    <tr>
                                        <td><strong>{kind.label()}</strong></td>
                                        <td>
                                            <input
                                                type="number"
                                                min="0"
                                                prop:value=move || draft.items_prices.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        draft.items_prices.update(|arr| arr[idx] = v);
                                                        draft.dirty.set(true);
                                                    }
                                                }
                                            />
                                        </td>
                                        <td>
                                            <input
                                                type="number"
                                                min="-1"
                                                prop:value=move || draft.items_free.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        draft.items_free.update(|arr| arr[idx] = v);
                                                        draft.dirty.set(true);
                                                    }
                                                }
                                            />
                                        </td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Subscription Plans (30-Day)"</h2>
                        <p class="adm-sub">"Rolling 5-hour quotas; use -1 view units for unlimited views."</p>
                    </div>
                </div>
                <div class="adm-table-wrap">
                    <table class="adm-table">
                        <thead>
                            <tr>
                                <th>"Plan"</th>
                                <th>"Price (points)"</th>
                                <th>"View units / 5h"</th>
                                <th>"Searches / 5h"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {[(0usize, "Basic"), (1usize, "Pro")].into_iter().map(|(idx, label)| {
                                view! {
                                    <tr>
                                        <td><strong>{label}</strong></td>
                                        <td>
                                            <input
                                                type="number"
                                                min="0"
                                                prop:value=move || draft.plan_prices.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        draft.plan_prices.update(|a| a[idx] = v);
                                                        draft.dirty.set(true);
                                                    }
                                                }
                                            />
                                        </td>
                                        <td>
                                            <input
                                                type="number"
                                                min="-1"
                                                prop:value=move || draft.plan_views.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        draft.plan_views.update(|a| a[idx] = v);
                                                        draft.dirty.set(true);
                                                    }
                                                }
                                            />
                                        </td>
                                        <td>
                                            <input
                                                type="number"
                                                min="0"
                                                prop:value=move || draft.plan_searches.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        draft.plan_searches.update(|a| a[idx] = v);
                                                        draft.dirty.set(true);
                                                    }
                                                }
                                            />
                                        </td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Credits & Treasury Deposit Addresses"</h2>
                        <p class="adm-sub">"Leave a chain's address blank to close that chain to new top-ups."</p>
                    </div>
                </div>
                <div class="adm-grid-3">
                    <label class="adm-field">
                        <span>"Points per USD"</span>
                        <input
                            type="number"
                            min="1"
                            prop:value=move || draft.points_per_usd.get().to_string()
                            on:input=move |ev| {
                                if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                    draft.points_per_usd.set(v);
                                    draft.dirty.set(true);
                                }
                            }
                        />
                    </label>
                    <label class="adm-field">
                        <span>"Minimum top-up (points)"</span>
                        <input
                            type="number"
                            min="1"
                            prop:value=move || draft.minimum_topup.get().to_string()
                            on:input=move |ev| {
                                if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                    draft.minimum_topup.set(v);
                                    draft.dirty.set(true);
                                }
                            }
                        />
                    </label>
                    <label class="adm-field">
                        <span>"New account grant (points)"</span>
                        <input
                            type="number"
                            min="0"
                            prop:value=move || draft.signup_points.get().to_string()
                            on:input=move |ev| {
                                if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                    draft.signup_points.set(v);
                                    draft.dirty.set(true);
                                }
                            }
                        />
                    </label>
                </div>
                <div class="adm-grid-2">
                    <label class="adm-field">
                        <span>"Ethereum deposit address (0x…)"</span>
                        <input
                            type="text"
                            maxlength="42"
                            placeholder="0x…"
                            prop:value=move || draft.eth_deposit.get()
                            on:input=move |ev| {
                                draft.eth_deposit.set(event_target_value(&ev));
                                draft.dirty.set(true);
                            }
                        />
                    </label>
                    <label class="adm-field">
                        <span>"Solana deposit address (base58 Ed25519)"</span>
                        <input
                            type="text"
                            maxlength="44"
                            placeholder="Base58 public key"
                            prop:value=move || draft.sol_deposit.get()
                            on:input=move |ev| {
                                draft.sol_deposit.set(event_target_value(&ev));
                                draft.dirty.set(true);
                            }
                        />
                    </label>
                </div>
            </section>

            <div class="adm-save-bar">
                <span class="adm-sub">
                    {move || format!("Editing revision #{}", draft.revision.get())}
                </span>
                <div class="adm-save-bar-actions">
                    {move || draft.dirty.get().then(|| view! {
                        <button
                            type="button"
                            class="adm-btn"
                            disabled=move || saving.get()
                            on:click=on_discard
                        >
                            "Discard changes"
                        </button>
                    })}
                    <button class="adm-btn adm-btn--primary" type="submit" disabled=move || saving.get()>
                        {move || if saving.get() { "Saving…" } else { "Save Access & Pricing" }}
                    </button>
                </div>
            </div>
        </form>
    }
}
