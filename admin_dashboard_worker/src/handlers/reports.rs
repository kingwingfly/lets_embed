//! Content Reports Moderation Queue endpoints (H13).
//!
//! - `GET  /admin/api/reports?status=open|reviewing|resolved|dismissed|all`
//! - `POST /admin/api/reports/{id}/resolve` (`status = resolved|dismissed|reviewing`)

use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;

use crate::{
    AppState, D1_BINDING,
    api::{
        ContentReportItem, ReportCounts, ReportsListResp, ResolveReportReq, ResolveReportResp,
    },
    handlers::{bad_request, guard_mutation, guard_read, internal_error, not_found},
};

#[derive(Debug, Default, Deserialize)]
pub struct ReportsQuery {
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Deserialize)]
struct StatusCountRow {
    status: String,
    n: i64,
}

#[worker::send]
pub async fn list_reports(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReportsQuery>,
) -> Response {
    if let Err(resp) = guard_read(&st, &headers) {
        return resp;
    }

    let status_param = match q.status.as_deref().unwrap_or("open") {
        "open" | "reviewing" | "resolved" | "dismissed" | "all" => {
            q.status.as_deref().unwrap_or("open")
        }
        _ => return bad_request("Invalid status filter (expected open|reviewing|resolved|dismissed|all)"),
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let db = match st.env.d1(D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };

    let count_rows = match db
        .prepare("SELECT status, COUNT(*) AS n FROM content_reports GROUP BY status")
        .all()
        .await
        .and_then(|r| r.results::<StatusCountRow>())
    {
        Ok(rows) => rows,
        Err(e) => {
            worker::console_error!("reports status counts failed: {e:?}");
            return internal_error();
        }
    };

    let mut counts = ReportCounts::default();
    for row in count_rows {
        match row.status.as_str() {
            "open" => counts.open = row.n,
            "reviewing" => counts.reviewing = row.n,
            "resolved" => counts.resolved = row.n,
            "dismissed" => counts.dismissed = row.n,
            _ => {}
        }
    }

    let reports = if status_param == "all" {
        match db
            .prepare(
                "SELECT id, reporter_key, reporter_user_id, target_kind, target_id, \
                        reason, note, status, created_at, resolved_at, resolved_by \
                 FROM content_reports \
                 ORDER BY created_at DESC LIMIT ? OFFSET ?",
            )
            .bind(&[(limit as f64).into(), (offset as f64).into()])
        {
            Ok(stmt) => match stmt.all().await.and_then(|r| r.results::<ContentReportItem>()) {
                Ok(rows) => rows,
                Err(e) => {
                    worker::console_error!("list all reports failed: {e:?}");
                    return internal_error();
                }
            },
            Err(e) => {
                worker::console_error!("bind list all reports failed: {e:?}");
                return internal_error();
            }
        }
    } else {
        match db
            .prepare(
                "SELECT id, reporter_key, reporter_user_id, target_kind, target_id, \
                        reason, note, status, created_at, resolved_at, resolved_by \
                 FROM content_reports \
                 WHERE status = ? \
                 ORDER BY created_at DESC LIMIT ? OFFSET ?",
            )
            .bind(&[
                status_param.into(),
                (limit as f64).into(),
                (offset as f64).into(),
            ])
        {
            Ok(stmt) => match stmt.all().await.and_then(|r| r.results::<ContentReportItem>()) {
                Ok(rows) => rows,
                Err(e) => {
                    worker::console_error!("list filtered reports failed: {e:?}");
                    return internal_error();
                }
            },
            Err(e) => {
                worker::console_error!("bind list filtered reports failed: {e:?}");
                return internal_error();
            }
        }
    };

    Json(ReportsListResp {
        status: status_param.to_string(),
        counts,
        reports,
    })
    .into_response()
}

#[worker::send]
pub async fn resolve_report(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(report_id): Path<String>,
    Json(req): Json<ResolveReportReq>,
) -> Response {
    let admin = match guard_mutation(&st, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let id = report_id.trim();
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return bad_request("Invalid report id");
    }

    let next_status = match req.status.trim() {
        "resolved" => "resolved",
        "dismissed" => "dismissed",
        "reviewing" => "reviewing",
        _ => return bad_request("Invalid resolution status (expected 'resolved', 'dismissed', or 'reviewing')"),
    };

    let db = match st.env.d1(D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };

    let now = (worker::Date::now().as_millis() / 1000) as i64;
    let resolved_at_val: JsValue = if next_status == "reviewing" {
        JsValue::NULL
    } else {
        (now as f64).into()
    };
    let resolved_by_val: JsValue = if next_status == "reviewing" {
        JsValue::NULL
    } else {
        admin.into()
    };

    let updated = match db
        .prepare(
            "UPDATE content_reports \
             SET status = ?, resolved_at = ?, resolved_by = ? \
             WHERE id = ?",
        )
        .bind(&[
            next_status.into(),
            resolved_at_val,
            resolved_by_val,
            id.into(),
        ])
    {
        Ok(stmt) => match stmt.run().await {
            Ok(out) => out.meta().ok().flatten().and_then(|m| m.changes) == Some(1),
            Err(e) => {
                worker::console_error!("resolve report update failed: {e:?}");
                return internal_error();
            }
        },
        Err(e) => {
            worker::console_error!("resolve report bind failed: {e:?}");
            return internal_error();
        }
    };

    if !updated {
        return not_found("Report not found");
    }

    worker::console_log!("Admin {admin} marked content_report {id} as {next_status}");

    Json(ResolveReportResp {
        id: id.to_string(),
        status: next_status.to_string(),
        resolved_at: now,
        resolved_by: admin.to_string(),
    })
    .into_response()
}
