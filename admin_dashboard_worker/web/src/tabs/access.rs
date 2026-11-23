//! Access & Pricing tab: login wall, free media folders, per-item pricing/quotas,
//! 30-day subscription plans, exchange rate, and crypto deposit treasury addresses.

use leptos::prelude::*;
use site_access::ChargeKind;
use wasm_bindgen_futures::spawn_local;

use crate::api::{AccessPolicy, OverviewResp, SaveAccessReq, SaveAccessResp, post_json};

#[component]
pub fn AccessTab(
    overview: RwSignal<Option<OverviewResp>>,
    on_saved: Callback<()>,
) -> impl IntoView {
    let login_required = RwSignal::new(true);
    let free_folders_text = RwSignal::new(String::new());
    let items_prices = RwSignal::new([1i64, 5, 100, 10, 100]);
    let items_free = RwSignal::new([0i64; 5]);
    let plan_prices = RwSignal::new([20_000i64, 50_000]);
    let plan_views = RwSignal::new([2_000i64, -1]);
    let plan_searches = RwSignal::new([10i64, 50]);
    let signup_points = RwSignal::new(3_000i64);
    let points_per_usd = RwSignal::new(10_000i64);
    let minimum_topup = RwSignal::new(1_000i64);
    let eth_deposit = RwSignal::new(String::new());
    let sol_deposit = RwSignal::new(String::new());
    let revision = RwSignal::new(0u32);

    let saving = RwSignal::new(false);
    let status_msg = RwSignal::new(Option::<(bool, String)>::None);

    // Sync local editable signals whenever overview loads/refreshes.
    Effect::new(move |_| {
        if let Some(ov) = overview.get() {
            let a = &ov.access;
            revision.set(ov.revision);
            login_required.set(a.login_required);
            free_folders_text.set(a.free_media_folders.join("\n"));
            let mut pr = [0i64; 5];
            let mut fr = [0i64; 5];
            for i in 0..5 {
                pr[i] = a.items[i].price;
                fr[i] = a.items[i].daily_free;
            }
            items_prices.set(pr);
            items_free.set(fr);
            plan_prices.set([a.plans[0].price, a.plans[1].price]);
            plan_views.set([
                a.plans[0].views.unwrap_or(-1),
                a.plans[1].views.unwrap_or(-1),
            ]);
            plan_searches.set([a.plans[0].searches, a.plans[1].searches]);
            signup_points.set(a.signup_points);
            points_per_usd.set(a.points_per_usd);
            minimum_topup.set(a.minimum_topup);
            eth_deposit.set(a.eth_deposit.clone());
            sol_deposit.set(a.sol_deposit.clone());
        }
    });

    let save_action = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if saving.get_untracked() {
            return;
        }
        saving.set(true);
        status_msg.set(None);

        let pr = items_prices.get_untracked();
        let fr = items_free.get_untracked();
        let pp = plan_prices.get_untracked();
        let pv = plan_views.get_untracked();
        let ps = plan_searches.get_untracked();

        let folders: Vec<String> = free_folders_text
            .get_untracked()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();

        let req = SaveAccessReq {
            revision: revision.get_untracked(),
            access: AccessPolicy {
                login_required: login_required.get_untracked(),
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
                signup_points: signup_points.get_untracked(),
                points_per_usd: points_per_usd.get_untracked(),
                minimum_topup: minimum_topup.get_untracked(),
                eth_deposit: eth_deposit.get_untracked(),
                sol_deposit: sol_deposit.get_untracked(),
            },
        };

        spawn_local(async move {
            match post_json::<_, SaveAccessResp>("/admin/api/settings/access", &req).await {
                Ok(resp) => {
                    revision.set(resp.revision);
                    status_msg.set(Some((
                        true,
                        format!(
                            "Published revision #{} (min_enforce_rev={}) to D1 and SitePolicyDO.",
                            resp.revision, resp.min_enforce_rev
                        ),
                    )));
                    on_saved.run(());
                }
                Err(err) => {
                    status_msg.set(Some((false, err)));
                }
            }
            saving.set(false);
        });
    };

    view! {
        <form class="adm-stack" on:submit=save_action>
            {move || status_msg.get().map(|(ok, msg)| view! {
                <div class=if ok { "adm-alert adm-alert--ok" } else { "adm-alert adm-alert--err" } role="status">
                    {msg}
                </div>
            })}

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Browsing Access & Free Folders"</h2>
                        <p class="adm-sub">"Control login requirements and which folders qualify for daily free allowances."</p>
                    </div>
                    <span class="adm-pill">
                        {move || if login_required.get() { "Login required" } else { "Public browsing" }}
                    </span>
                </div>

                <div class="adm-grid-2">
                    <label class="adm-radio-card">
                        <input
                            type="radio"
                            name="login_required"
                            prop:checked=move || login_required.get()
                            on:change=move |_| login_required.set(true)
                        />
                        <span>
                            <strong>"Require sign-in"</strong>
                            <small>"Visitors must sign in before opening the gallery."</small>
                        </span>
                    </label>
                    <label class="adm-radio-card">
                        <input
                            type="radio"
                            name="login_required"
                            prop:checked=move || !login_required.get()
                            on:change=move |_| login_required.set(false)
                        />
                        <span>
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
                        prop:value=move || free_folders_text.get()
                        on:input=move |ev| free_folders_text.set(event_target_value(&ev))
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
                                                prop:value=move || items_prices.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        items_prices.update(|arr| arr[idx] = v);
                                                    }
                                                }
                                            />
                                        </td>
                                        <td>
                                            <input
                                                type="number"
                                                min="-1"
                                                prop:value=move || items_free.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        items_free.update(|arr| arr[idx] = v);
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
                                                prop:value=move || plan_prices.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        plan_prices.update(|a| a[idx] = v);
                                                    }
                                                }
                                            />
                                        </td>
                                        <td>
                                            <input
                                                type="number"
                                                min="-1"
                                                prop:value=move || plan_views.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        plan_views.update(|a| a[idx] = v);
                                                    }
                                                }
                                            />
                                        </td>
                                        <td>
                                            <input
                                                type="number"
                                                min="0"
                                                prop:value=move || plan_searches.get()[idx].to_string()
                                                on:input=move |ev| {
                                                    if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                        plan_searches.update(|a| a[idx] = v);
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
                            prop:value=move || points_per_usd.get().to_string()
                            on:input=move |ev| {
                                if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                    points_per_usd.set(v);
                                }
                            }
                        />
                    </label>
                    <label class="adm-field">
                        <span>"Minimum top-up (points)"</span>
                        <input
                            type="number"
                            min="1"
                            prop:value=move || minimum_topup.get().to_string()
                            on:input=move |ev| {
                                if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                    minimum_topup.set(v);
                                }
                            }
                        />
                    </label>
                    <label class="adm-field">
                        <span>"New account grant (points)"</span>
                        <input
                            type="number"
                            min="0"
                            prop:value=move || signup_points.get().to_string()
                            on:input=move |ev| {
                                if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                    signup_points.set(v);
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
                            prop:value=move || eth_deposit.get()
                            on:input=move |ev| eth_deposit.set(event_target_value(&ev))
                        />
                    </label>
                    <label class="adm-field">
                        <span>"Solana deposit address (base58 Ed25519)"</span>
                        <input
                            type="text"
                            maxlength="44"
                            placeholder="Base58 public key"
                            prop:value=move || sol_deposit.get()
                            on:input=move |ev| sol_deposit.set(event_target_value(&ev))
                        />
                    </label>
                </div>
            </section>

            <div class="adm-save-bar">
                <span class="adm-sub">
                    {move || format!("Editing revision #{}", revision.get())}
                </span>
                <button class="adm-btn adm-btn--primary" type="submit" disabled=move || saving.get()>
                    {move || if saving.get() { "Saving…" } else { "Save Access & Pricing" }}
                </button>
            </div>
        </form>
    }
}
