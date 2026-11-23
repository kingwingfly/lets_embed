//! `GET /admin/api/overview` and `POST /admin/api/settings/access`.

use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use site_access::{RuleMode, compute_policy_digest};

use crate::{
    AppState, D1_BINDING,
    api::{
        AccountsSummary, OverviewResp, PaymentsSummary, SafetyOverview, SaveAccessReq,
        SaveAccessResp,
    },
    handlers::{bad_request, conflict, guard_mutation, guard_read, internal_error},
    settings::{LEGACY_UNCLASSIFIED_NOTE, LoadedSettings},
};

#[derive(Default, Deserialize)]
struct PaymentsAggRow {
    total_count: i64,
    credited_count: i64,
    total_points: String,
}

#[derive(Default, Deserialize)]
struct OpenCountRow {
    n: i64,
}

pub(crate) async fn load_accounts_summary(env: &worker::Env) -> worker::Result<AccountsSummary> {
    let db = env.d1(D1_BINDING)?;
    let row = db
        .prepare(
            "SELECT \
               COUNT(*) AS total, \
               COALESCE(SUM(CASE WHEN banned = 0 THEN 1 ELSE 0 END), 0) AS active, \
               COALESCE(SUM(CASE WHEN banned != 0 THEN 1 ELSE 0 END), 0) AS banned, \
               COALESCE(SUM(CASE WHEN plan = 'basic' THEN 1 ELSE 0 END), 0) AS basic, \
               COALESCE(SUM(CASE WHEN plan = 'pro' THEN 1 ELSE 0 END), 0) AS pro, \
               COALESCE(SUM(CASE WHEN account_do_key LIKE '0x%' THEN 1 ELSE 0 END), 0) AS eth, \
               COALESCE(SUM(CASE WHEN account_do_key NOT LIKE '0x%' AND account_do_key NOT LIKE 'usr:%' THEN 1 ELSE 0 END), 0) AS sol, \
               COALESCE(SUM(CASE WHEN account_do_key LIKE 'usr:%' THEN 1 ELSE 0 END), 0) AS multi_auth \
             FROM users_v2",
        )
        .first::<AccountsSummary>(None)
        .await?;
    Ok(row.unwrap_or_default())
}

#[worker::send]
pub async fn get_overview(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let admin_email = match guard_read(&st, &headers) {
        Ok(email) => email.to_string(),
        Err(resp) => return resp,
    };

    let loaded = match LoadedSettings::load(&st.env).await {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("load site_settings failed: {e:?}");
            return internal_error();
        }
    };

    let accounts_summary = match load_accounts_summary(&st.env).await {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("accounts summary failed: {e:?}");
            return internal_error();
        }
    };

    let db = match st.env.d1(D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };

    let pay_row = match db
        .prepare(
            "SELECT \
               COUNT(*) AS total_count, \
               COALESCE(SUM(CASE WHEN status = 'credited' THEN 1 ELSE 0 END), 0) AS credited_count, \
               CAST(COALESCE(SUM(CASE WHEN status = 'credited' THEN points ELSE 0 END), 0) AS TEXT) AS total_points \
             FROM payments",
        )
        .first::<PaymentsAggRow>(None)
        .await
    {
        Ok(row) => row.unwrap_or_default(),
        Err(e) => {
            worker::console_error!("payments summary failed: {e:?}");
            return internal_error();
        }
    };

    let open_report_count = match db
        .prepare("SELECT COUNT(*) AS n FROM content_reports WHERE status = 'open'")
        .first::<OpenCountRow>(None)
        .await
    {
        Ok(row) => row.map_or(0, |r| r.n),
        Err(e) => {
            worker::console_error!("open reports count failed: {e:?}");
            return internal_error();
        }
    };

    let public = &loaded.doc.public;
    let active_switcher_count = public
        .rules
        .iter()
        .filter(|r| r.enabled && r.mode == RuleMode::Switcher)
        .count();

    Json(OverviewResp {
        admin_email,
        revision: loaded.revision,
        min_enforce_rev: public.min_enforce_rev,
        policy_digest: compute_policy_digest(public),
        access: loaded.doc.access,
        safety: SafetyOverview {
            safety_enabled: public.safety_enabled,
            rule_count: public.rules.len(),
            active_switcher_count,
            age_policy: public.age_policy,
            age_gate_trigger: public.age_gate_trigger,
            blocked_country_count: public.geo.blocked_countries.len(),
            cloudflare_images_blur: public.cloudflare_images_blur,
        },
        accounts_summary,
        payments_summary: PaymentsSummary {
            total_count: pay_row.total_count,
            credited_count: pay_row.credited_count,
            total_points: if pay_row.total_points.is_empty() {
                "0".to_string()
            } else {
                pay_row.total_points
            },
        },
        open_report_count,
        legacy_unclassified_note: LEGACY_UNCLASSIFIED_NOTE.to_string(),
    })
    .into_response()
}

#[worker::send]
pub async fn save_access_settings(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SaveAccessReq>,
) -> Response {
    let admin = match guard_mutation(&st, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let normalized_access = match req.access.validate_and_normalize() {
        Ok(a) => a,
        Err(msg) => return bad_request(msg),
    };

    let mut loaded = match LoadedSettings::load(&st.env).await {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("load site_settings failed: {e:?}");
            return internal_error();
        }
    };
    if loaded.revision != req.revision {
        return conflict(
            "Settings were updated in another session. Reload the dashboard and reapply your changes.",
        );
    }

    loaded.doc.access = normalized_access.clone();
    match LoadedSettings::save_and_publish(&st.env, req.revision, &loaded.doc, admin).await {
        Ok(Some((new_rev, digest))) => Json(SaveAccessResp {
            revision: new_rev,
            min_enforce_rev: loaded.doc.public.min_enforce_rev,
            digest,
            access: normalized_access,
        })
        .into_response(),
        Ok(None) => conflict(
            "Settings were updated concurrently. Reload the dashboard and reapply your changes.",
        ),
        Err(e) => {
            worker::console_error!("save access settings failed: {e:?}");
            internal_error()
        }
    }
}
