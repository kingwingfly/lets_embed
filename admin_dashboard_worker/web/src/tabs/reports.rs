//! Content Reports Moderation Queue tab (H13).
//!
//! Security: user-submitted `note` is rendered STRICTLY as escaped plain text
//! (`<p class="adm-report-note">{note}</p>` — NEVER `inner_html`) to prevent stored XSS.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api::{
    ReportsListResp, ResolveReportReq, ResolveReportResp, format_ts_utc, get_json, post_json,
    url_encode_component,
};

#[component]
pub fn ReportsTab(on_resolved: Callback<()>) -> impl IntoView {
    let status_filter = RwSignal::new("open".to_string());
    let data = RwSignal::new(Option::<ReportsListResp>::None);
    let loading = RwSignal::new(false);
    let busy_id = RwSignal::new(Option::<String>::None);
    let feedback = RwSignal::new(Option::<(bool, String)>::None);

    let load_reports = move || {
        loading.set(true);
        let st = status_filter.get_untracked();
        let url = format!("/admin/api/reports?status={st}&limit=100");
        spawn_local(async move {
            match get_json::<ReportsListResp>(&url).await {
                Ok(resp) => data.set(Some(resp)),
                Err(err) => feedback.set(Some((false, err))),
            }
            loading.set(false);
        });
    };

    Effect::new(move |_| {
        load_reports();
    });

    let resolve_action = move |report_id: String, next_status: &'static str| {
        if busy_id.get_untracked().is_some() {
            return;
        }
        busy_id.set(Some(report_id.clone()));
        feedback.set(None);
        let url = format!(
            "/admin/api/reports/{}/resolve",
            url_encode_component(&report_id)
        );
        let req = ResolveReportReq {
            status: next_status.to_string(),
        };
        spawn_local(async move {
            match post_json::<_, ResolveReportResp>(&url, &req).await {
                Ok(resp) => {
                    feedback.set(Some((
                        true,
                        format!(
                            "Report {} marked as '{}' by {}.",
                            resp.id, resp.status, resp.resolved_by
                        ),
                    )));
                    load_reports();
                    on_resolved.run(());
                }
                Err(err) => feedback.set(Some((false, err))),
            }
            busy_id.set(None);
        });
    };

    view! {
        <div class="adm-stack">
            {move || feedback.get().map(|(ok, msg)| view! {
                <div class=if ok { "adm-alert adm-alert--ok" } else { "adm-alert adm-alert--err" } role="status">
                    {msg}
                </div>
            })}

            <section class="adm-card">
                <div class="adm-card-head">
                    <div>
                        <h2>"Content Reports Queue"</h2>
                        <p class="adm-sub">"User-submitted flags from `/user/api/reports`. Notes are rendered strictly as escaped plain text."</p>
                    </div>
                    <button type="button" class="adm-btn" on:click=move |_| load_reports()>
                        {move || if loading.get() { "Loading…" } else { "Refresh" }}
                    </button>
                </div>

                <div class="adm-status-pills" role="tablist">
                    {["open", "reviewing", "resolved", "dismissed", "all"].into_iter().map(|st| {
                        let st_str = st.to_string();
                        let st_click = st_str.clone();
                        view! {
                            <button
                                type="button"
                                class=move || if status_filter.get() == st_str {
                                    "adm-pill-btn is-active"
                                } else {
                                    "adm-pill-btn"
                                }
                                on:click=move |_| {
                                    status_filter.set(st_click.clone());
                                    load_reports();
                                }
                            >
                                <span>{st}</span>
                                {move || data.get().and_then(|d| match st {
                                    "open" => Some(d.counts.open),
                                    "reviewing" => Some(d.counts.reviewing),
                                    "resolved" => Some(d.counts.resolved),
                                    "dismissed" => Some(d.counts.dismissed),
                                    _ => None,
                                }).map(|n| view! { <span class="adm-count">{n}</span> })}
                            </button>
                        }
                    }).collect_view()}
                </div>

                <div class="adm-stack">
                    {move || data.get().map(|resp| {
                        if resp.reports.is_empty() {
                            view! {
                                <div class="adm-empty-card">"No content reports in this queue."</div>
                            }.into_any()
                        } else {
                            resp.reports.into_iter().map(|rep| {
                                let id_resolve = rep.id.clone();
                                let id_dismiss = rep.id.clone();
                                let id_review = rep.id.clone();
                                let id_busy_check = rep.id.clone();
                                let is_closed = matches!(rep.status.as_str(), "resolved" | "dismissed");
                                let target_href = match rep.target_kind.as_str() {
                                    "image" => Some(format!("/details/{}", rep.target_id)),
                                    _ => None,
                                };
                                view! {
                                    <article class="adm-report-card">
                                        <div class="adm-report-head">
                                            <div class="adm-chips">
                                                <span class="adm-badge adm-badge--warn">{rep.reason.clone()}</span>
                                                <span class="adm-badge">
                                                    {format!("{}: #{}", rep.target_kind, rep.target_id)}
                                                </span>
                                                <span class=match rep.status.as_str() {
                                                    "open" => "adm-badge adm-badge--err",
                                                    "resolved" => "adm-badge adm-badge--ok",
                                                    _ => "adm-badge",
                                                }>
                                                    {rep.status.clone()}
                                                </span>
                                                {target_href.map(|href| view! {
                                                    <a class="adm-link" href=href target="_blank" rel="noopener noreferrer">
                                                        "Open item ↗"
                                                    </a>
                                                })}
                                            </div>
                                            <span class="adm-sub">{format_ts_utc(rep.created_at)}</span>
                                        </div>

                                        // Plain-text rendering ONLY — NEVER inner_html!
                                        <p class="adm-report-note">
                                            {rep.note.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| "(No note provided)".to_string())}
                                        </p>

                                        <div class="adm-report-foot">
                                            <span class="adm-sub adm-mono">
                                                {format!(
                                                    "id={} · reporter={}",
                                                    rep.id,
                                                    rep.reporter_user_id.as_deref().unwrap_or(&rep.reporter_key)
                                                )}
                                            </span>
                                            {rep.resolved_by.clone().map(|by| view! {
                                                <span class="adm-sub">
                                                    {format!(
                                                        "Handled by {} at {}",
                                                        by,
                                                        rep.resolved_at.map(format_ts_utc).unwrap_or_else(|| "—".into())
                                                    )}
                                                </span>
                                            })}
                                            <div class="adm-btn-group">
                                                {(!is_closed && rep.status != "reviewing").then(|| view! {
                                                    <button
                                                        type="button"
                                                        class="adm-btn adm-btn--sm"
                                                        disabled=move || busy_id.get().as_deref() == Some(id_busy_check.as_str())
                                                        on:click=move |_| resolve_action(id_review.clone(), "reviewing")
                                                    >
                                                        "Reviewing"
                                                    </button>
                                                })}
                                                {(!is_closed).then(|| view! {
                                                    <>
                                                        <button
                                                            type="button"
                                                            class="adm-btn adm-btn--primary adm-btn--sm"
                                                            on:click=move |_| resolve_action(id_resolve.clone(), "resolved")
                                                        >
                                                            "Resolve"
                                                        </button>
                                                        <button
                                                            type="button"
                                                            class="adm-btn adm-btn--sm"
                                                            on:click=move |_| resolve_action(id_dismiss.clone(), "dismissed")
                                                        >
                                                            "Dismiss"
                                                        </button>
                                                    </>
                                                })}
                                            </div>
                                        </div>
                                    </article>
                                }
                            }).collect_view().into_any()
                        }
                    })}
                </div>
            </section>
        </div>
    }
}
