//! Accounts & Payments tab: filterable `users_v2` list, linked identities & age
//! assurance badges, live `UserAccount` DO balance/plan/ban controls, and payments ledger.
//!
//! Uses GCP top-right toasts via `use_toast_store()` for all mutations and errors.

use leptos::prelude::*;
use lets_embed_ui::use_toast_store;
use site_access::AuthProviderId;
use wasm_bindgen_futures::spawn_local;

use crate::api::{
    AccountEntryResp, AccountsListResp, AdminBanMutationReq, AdminBanMutationResp,
    AdminCreditMutationReq, AdminCreditMutationResp, AdminPlanMutationReq, AdminPlanMutationResp,
    PaymentsListResp, format_ts_utc, get_json, post_json, url_encode_component,
};

fn assurance_badge_cls(level: &str) -> &'static str {
    match level {
        "verified_18" => "adm-badge adm-badge--ok",
        "provider_self_reported_dob" | "self_attestation" => "adm-badge adm-badge--warn",
        _ => "adm-badge",
    }
}

#[component]
pub fn AccountsTab(on_mutated: Callback<()>) -> impl IntoView {
    let toasts = use_toast_store();

    let search_q = RwSignal::new(String::new());
    let plan_filter = RwSignal::new("all".to_string());
    let status_filter = RwSignal::new("all".to_string());
    let provider_filter = RwSignal::new("all".to_string());
    let sort_by = RwSignal::new("login_desc".to_string());
    let page = RwSignal::new(1usize);

    let accounts_data = RwSignal::new(Option::<AccountsListResp>::None);
    let selected_account = RwSignal::new(Option::<AccountEntryResp>::None);
    let payments_data = RwSignal::new(Option::<PaymentsListResp>::None);
    let payments_status = RwSignal::new("all".to_string());
    let loading = RwSignal::new(false);

    // Inspector form signals
    let credit_points = RwSignal::new(1_000i64);
    let credit_reason = RwSignal::new(String::new());
    let plan_choice = RwSignal::new("pro".to_string());
    let plan_days = RwSignal::new(30u32);
    let busy = RwSignal::new(false);

    let load_accounts = move || {
        loading.set(true);
        let q = search_q.get_untracked();
        let pl = plan_filter.get_untracked();
        let st = status_filter.get_untracked();
        let pv = provider_filter.get_untracked();
        let so = sort_by.get_untracked();
        let pg = page.get_untracked();
        let sel_id = selected_account.get_untracked().map(|a| a.id);

        let mut url = format!(
            "/admin/api/accounts?plan={pl}&status={st}&sort={so}&page={pg}"
        );
        if !q.trim().is_empty() {
            url.push_str("&q=");
            url.push_str(&url_encode_component(q.trim()));
        }
        if pv != "all" {
            url.push_str("&provider=");
            url.push_str(&url_encode_component(&pv));
        }
        if let Some(uid) = sel_id {
            url.push_str("&user_id=");
            url.push_str(&url_encode_component(&uid));
        }

        spawn_local(async move {
            match get_json::<AccountsListResp>(&url).await {
                Ok(resp) => {
                    if let Some(sel) = resp.selected.clone() {
                        selected_account.set(Some(sel));
                    }
                    accounts_data.set(Some(resp));
                }
                Err(err) => {
                    toasts.error("Failed to load accounts", Some(err));
                }
            }
            loading.set(false);
        });
    };

    let load_payments = move || {
        let st = payments_status.get_untracked();
        let url = format!("/admin/api/payments?status={st}&limit=50");
        spawn_local(async move {
            match get_json::<PaymentsListResp>(&url).await {
                Ok(resp) => payments_data.set(Some(resp)),
                Err(err) => {
                    toasts.error("Failed to load payments", Some(err));
                }
            }
        });
    };

    Effect::new(move |_| {
        load_accounts();
        load_payments();
    });

    let on_apply_credit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let Some(acc) = selected_account.get_untracked() else {
            return;
        };
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let req = AdminCreditMutationReq {
            user_id: acc.id,
            points: credit_points.get_untracked(),
            reason: credit_reason.get_untracked(),
            token: None,
        };
        spawn_local(async move {
            match post_json::<_, AdminCreditMutationResp>("/admin/api/accounts/credit", &req).await
            {
                Ok(resp) => {
                    toasts.success(
                        format!("Updated {} balance", resp.user_id),
                        Some(format!(
                            "New balance: {} pts (applied={})",
                            resp.balance, resp.applied
                        )),
                    );
                    credit_reason.set(String::new());
                    load_accounts();
                    on_mutated.run(());
                }
                Err(err) => {
                    toasts.error("Credit adjustment failed", Some(err));
                }
            }
            busy.set(false);
        });
    };

    let on_apply_plan = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let Some(acc) = selected_account.get_untracked() else {
            return;
        };
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let pl = plan_choice.get_untracked();
        let req = AdminPlanMutationReq {
            user_id: acc.id,
            days: if pl == "none" {
                None
            } else {
                Some(plan_days.get_untracked())
            },
            plan: pl,
            token: None,
        };
        spawn_local(async move {
            match post_json::<_, AdminPlanMutationResp>("/admin/api/accounts/plan", &req).await {
                Ok(resp) => {
                    toasts.success(
                        format!("Updated plan for {}", resp.user_id),
                        Some(format!(
                            "Plan: {} · period_end: {}",
                            resp.plan.as_deref().unwrap_or("none"),
                            format_ts_utc(resp.period_end as i64)
                        )),
                    );
                    load_accounts();
                    on_mutated.run(());
                }
                Err(err) => {
                    toasts.error("Plan update failed", Some(err));
                }
            }
            busy.set(false);
        });
    };

    let on_toggle_ban = move |user_id: String, next_banned: bool| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let req = AdminBanMutationReq {
            user_id,
            banned: next_banned,
        };
        spawn_local(async move {
            match post_json::<_, AdminBanMutationResp>("/admin/api/accounts/ban", &req).await {
                Ok(resp) => {
                    let title = if resp.banned {
                        format!("Banned {}", resp.user_id)
                    } else {
                        format!("Unbanned {}", resp.user_id)
                    };
                    let detail = if resp.sessions_revoked {
                        "All active v2 sessions were immediately revoked.".to_string()
                    } else {
                        "Account access restored.".to_string()
                    };
                    toasts.success(title, Some(detail));
                    load_accounts();
                    on_mutated.run(());
                }
                Err(err) => {
                    toasts.error("Ban status update failed", Some(err));
                }
            }
            busy.set(false);
        });
    };

    view! {
        <div class="adm-stack">
            {move || accounts_data.get().map(|d| view! {
                <div class="adm-kpi-row">
                    <div class="adm-kpi"><span>"Total Accounts"</span><strong>{d.summary.total}</strong></div>
                    <div class="adm-kpi"><span>"Active"</span><strong>{d.summary.active}</strong></div>
                    <div class="adm-kpi"><span>"Banned"</span><strong>{d.summary.banned}</strong></div>
                    <div class="adm-kpi"><span>"Basic / Pro"</span><strong>{format!("{} / {}", d.summary.basic, d.summary.pro)}</strong></div>
                    <div class="adm-kpi"><span>"Multi-Auth / ETH / SOL"</span><strong>{format!("{} / {} / {}", d.summary.multi_auth, d.summary.eth, d.summary.sol)}</strong></div>
                </div>
            })}

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Accounts (`users_v2`)"</h2>
                        <p class="adm-sub">"Inspect linked auth identities, age assurance provenance, live DO balances, and ban/session revocation."</p>
                    </div>
                    <button type="button" class="adm-btn" on:click=move |_| load_accounts()>
                        {move || if loading.get() { "Loading…" } else { "Refresh" }}
                    </button>
                </div>

                <div class="adm-filter-bar">
                    <input
                        type="search"
                        placeholder="Search user ID, DO key, email, identity…"
                        prop:value=move || search_q.get()
                        on:input=move |ev| search_q.set(event_target_value(&ev))
                    />
                    <select
                        prop:value=move || plan_filter.get()
                        on:change=move |ev| {
                            plan_filter.set(event_target_value(&ev));
                            page.set(1);
                            load_accounts();
                        }
                    >
                        <option value="all">"All plans"</option>
                        <option value="paid">"Paid only"</option>
                        <option value="pro">"Pro"</option>
                        <option value="basic">"Basic"</option>
                        <option value="none">"PAYG"</option>
                    </select>
                    <select
                        prop:value=move || status_filter.get()
                        on:change=move |ev| {
                            status_filter.set(event_target_value(&ev));
                            page.set(1);
                            load_accounts();
                        }
                    >
                        <option value="all">"All statuses"</option>
                        <option value="active">"Active"</option>
                        <option value="banned">"Banned"</option>
                    </select>
                    <select
                        prop:value=move || provider_filter.get()
                        on:change=move |ev| {
                            provider_filter.set(event_target_value(&ev));
                            page.set(1);
                            load_accounts();
                        }
                    >
                        <option value="all">"All providers"</option>
                        {AuthProviderId::ALL.into_iter().map(|id| view! {
                            <option value=id.as_str()>{id.display_name()}</option>
                        }).collect_view()}
                    </select>
                    <select
                        prop:value=move || sort_by.get()
                        on:change=move |ev| {
                            sort_by.set(event_target_value(&ev));
                            load_accounts();
                        }
                    >
                        <option value="login_desc">"Recent login"</option>
                        <option value="created_desc">"Newest created"</option>
                        <option value="credits_desc">"Credits (high)"</option>
                        <option value="credits_asc">"Credits (low)"</option>
                        <option value="views_desc">"Total views"</option>
                    </select>
                    <button
                        type="button"
                        class="adm-btn adm-btn--primary"
                        on:click=move |_| {
                            page.set(1);
                            load_accounts();
                        }
                    >
                        "Filter"
                    </button>
                </div>

                <div class="adm-table-wrap">
                    <table class="adm-table">
                        <thead>
                            <tr>
                                <th>"Account"</th>
                                <th>"Identities & Age"</th>
                                <th>"Plan"</th>
                                <th>"Balance"</th>
                                <th>"Status"</th>
                                <th>"Last Login"</th>
                                <th>"Action"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || accounts_data.get().map(|data| {
                                if data.accounts.is_empty() {
                                    view! {
                                        <tr><td colspan="7" class="adm-empty">"No accounts match the current filters."</td></tr>
                                    }.into_any()
                                } else {
                                    data.accounts.into_iter().map(|acc| {
                                        let acc_select = acc.clone();
                                        let balance_str = acc
                                            .live_status
                                            .as_ref()
                                            .map(|s| format!("{} pts", s.balance))
                                            .unwrap_or_else(|| "—".to_string());
                                        let plan_str = acc.plan.clone().unwrap_or_else(|| "PAYG".to_string());
                                        view! {
                                            <tr>
                                                <td>
                                                    <div class="adm-mono">{acc.id.clone()}</div>
                                                    {acc.email.clone().map(|em| view! { <div class="adm-sub">{em}</div> })}
                                                </td>
                                                <td>
                                                    <div class="adm-chips">
                                                        {acc.identities.iter().map(|id| view! {
                                                            <span class=assurance_badge_cls(&id.assurance_level)>
                                                                {format!("{} ({})", id.provider_id, id.assurance_level)}
                                                            </span>
                                                        }).collect_view()}
                                                    </div>
                                                </td>
                                                <td><span class="adm-badge">{plan_str}</span></td>
                                                <td class="adm-mono">{balance_str}</td>
                                                <td>
                                                    <span class=if acc.banned { "adm-badge adm-badge--err" } else { "adm-badge adm-badge--ok" }>
                                                        {if acc.banned { "Banned" } else { "Active" }}
                                                    </span>
                                                </td>
                                                <td>{format_ts_utc(acc.last_login)}</td>
                                                <td>
                                                    <button
                                                        type="button"
                                                        class="adm-btn adm-btn--sm"
                                                        on:click=move |_| selected_account.set(Some(acc_select.clone()))
                                                    >
                                                        "Manage"
                                                    </button>
                                                </td>
                                            </tr>
                                        }
                                    }).collect_view().into_any()
                                }
                            })}
                        </tbody>
                    </table>
                </div>
            </section>

            // Selected Account Inspector
            {move || selected_account.get().map(|acc| {
                let uid_for_ban = acc.id.clone();
                let next_ban = !acc.banned;
                view! {
                    <section class="adm-card adm-card--highlight">
                        <div class="adm-card-head">
                            <div>
                                <h2>"Account Inspector"</h2>
                                <p class="adm-mono adm-sub">{format!("id: {} · do_key: {}", acc.id, acc.account_do_key)}</p>
                            </div>
                            <button type="button" class="adm-btn" on:click=move |_| selected_account.set(None)>
                                "Close"
                            </button>
                        </div>

                        <div class="adm-grid-2">
                            <div class="adm-subcard">
                                <h3>"Linked Identities & Provenance"</h3>
                                <ul class="adm-id-list">
                                    {acc.identities.iter().map(|id| view! {
                                        <li>
                                            <strong>{id.provider_id.clone()}</strong>
                                            " · "
                                            <span class="adm-badge">{id.purpose.clone()}</span>
                                            " · "
                                            <span class=assurance_badge_cls(&id.assurance_level)>
                                                {id.assurance_level.clone()}
                                            </span>
                                            <div class="adm-mono adm-sub">{format!("{} / {}", id.issuer, id.subject)}</div>
                                        </li>
                                    }).collect_view()}
                                </ul>
                                <p class="adm-sub">
                                    {format!(
                                        "Terms accepted: {} · Likes: {} · Top-ups: {} ({} pts)",
                                        acc.terms_version_accepted.map(|v| format!("v{v}")).unwrap_or_else(|| "Never".into()),
                                        acc.like_count,
                                        acc.topup_count,
                                        acc.topup_points
                                    )}
                                </p>
                            </div>

                            <div class="adm-subcard">
                                <h3>"Live Durable Object Controls"</h3>
                                <form class="adm-inline-form" on:submit=on_apply_credit>
                                    <label class="adm-field">
                                        <span>"Adjust points (negative deducts)"</span>
                                        <input
                                            type="number"
                                            prop:value=move || credit_points.get().to_string()
                                            on:input=move |ev| {
                                                if let Ok(v) = event_target_value(&ev).parse::<i64>() {
                                                    credit_points.set(v);
                                                }
                                            }
                                        />
                                    </label>
                                    <label class="adm-field">
                                        <span>"Reason"</span>
                                        <input
                                            type="text"
                                            maxlength="300"
                                            placeholder="Support adjustment…"
                                            prop:value=move || credit_reason.get()
                                            on:input=move |ev| credit_reason.set(event_target_value(&ev))
                                        />
                                    </label>
                                    <button type="submit" class="adm-btn adm-btn--primary" disabled=move || busy.get()>
                                        "Apply Credit"
                                    </button>
                                </form>

                                <form class="adm-inline-form" on:submit=on_apply_plan>
                                    <label class="adm-field">
                                        <span>"Plan"</span>
                                        <select
                                            prop:value=move || plan_choice.get()
                                            on:change=move |ev| plan_choice.set(event_target_value(&ev))
                                        >
                                            <option value="basic">"Basic"</option>
                                            <option value="pro">"Pro"</option>
                                            <option value="none">"Revoke plan (PAYG)"</option>
                                        </select>
                                    </label>
                                    <label class="adm-field">
                                        <span>"Days"</span>
                                        <input
                                            type="number"
                                            min="1"
                                            max="3650"
                                            prop:value=move || plan_days.get().to_string()
                                            on:input=move |ev| {
                                                if let Ok(v) = event_target_value(&ev).parse::<u32>() {
                                                    plan_days.set(v);
                                                }
                                            }
                                        />
                                    </label>
                                    <button type="submit" class="adm-btn" disabled=move || busy.get()>
                                        "Update Plan"
                                    </button>
                                </form>

                                <div class="adm-danger-row">
                                    <p class="adm-sub">
                                        "Banning immediately sets banned=true in UserAccount DO and calls /session-revoke-all to invalidate every active v2 session."
                                    </p>
                                    <button
                                        type="button"
                                        class=if acc.banned { "adm-btn" } else { "adm-btn adm-btn--danger" }
                                        disabled=move || busy.get()
                                        on:click=move |_| on_toggle_ban(uid_for_ban.clone(), next_ban)
                                    >
                                        {if acc.banned { "Unban Account" } else { "Ban & Revoke Sessions" }}
                                    </button>
                                </div>
                            </div>
                        </div>
                    </section>
                }
            })}

            // Recent Payments Table
            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Recent Payments"</h2>
                        <p class="adm-sub">"On-chain top-up ledger (`payments` table with global tx_hash replay guard)."</p>
                    </div>
                    <select
                        class="adm-select-inline"
                        prop:value=move || payments_status.get()
                        on:change=move |ev| {
                            payments_status.set(event_target_value(&ev));
                            load_payments();
                        }
                    >
                        <option value="all">"All statuses"</option>
                        <option value="credited">"Credited"</option>
                        <option value="pending">"Pending"</option>
                        <option value="rejected">"Rejected"</option>
                    </select>
                </div>
                <div class="adm-table-wrap">
                    <table class="adm-table">
                        <thead>
                            <tr>
                                <th>"Tx Hash"</th>
                                <th>"Account"</th>
                                <th>"Asset"</th>
                                <th>"Points"</th>
                                <th>"Status"</th>
                                <th>"Time"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || payments_data.get().map(|p| {
                                if p.payments.is_empty() {
                                    view! {
                                        <tr><td colspan="6" class="adm-empty">"No payments recorded yet."</td></tr>
                                    }.into_any()
                                } else {
                                    p.payments.into_iter().map(|row| view! {
                                        <tr>
                                            <td class="adm-mono">{row.tx_hash}</td>
                                            <td class="adm-mono">{row.address}</td>
                                            <td>{format!("{} / {}", row.chain, row.token.to_uppercase())}</td>
                                            <td class="adm-mono">{row.points}</td>
                                            <td><span class="adm-badge">{row.status}</span></td>
                                            <td>{format_ts_utc(row.created_at)}</td>
                                        </tr>
                                    }).collect_view().into_any()
                                }
                            })}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    }
}
