//! `GET /admin/api/overview` and `POST /admin/api/settings/access`.

use axum::{
    Extension, Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use site_access::{PolicyAction, compute_policy_digest};

use crate::{
    AppState, D1_BINDING,
    api::{
        AccountsSummary, ActivationStatus, OverviewResp, PaymentsSummary, SafetyOverview,
        SaveAccessReq, SaveAccessResp,
    },
    handlers::{
        bad_request, conflict, guard_mutation, guard_read, internal_error,
        pending_activation_response,
    },
    security::AdminIdentity,
    settings::{
        ActivationOutcome, LEGACY_UNCLASSIFIED_NOTE, LoadedSettings,
        ensure_v3_ready_for_non_safety_mutation,
    },
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
pub async fn get_overview(
    State(st): State<AppState>,
    Extension(admin): Extension<AdminIdentity>,
) -> Response {
    let admin_email = match guard_read(&st, &admin) {
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
        .policies
        .iter()
        .filter(|p| p.enabled && p.bypass.include_switcher)
        .count();
    let active_blur_count = public
        .policies
        .iter()
        .filter(|p| p.enabled && p.action == PolicyAction::Blur)
        .count();

    Json(OverviewResp {
        admin_email,
        schema_version: public.schema_version,
        revision: loaded.revision,
        min_enforce_rev: public.min_enforce_rev,
        policy_digest: compute_policy_digest(public),
        vocab_digest: public.vocab_digest.clone(),
        activation_status: loaded.activation_status.as_str().to_string(),
        access: loaded.doc.access,
        safety: SafetyOverview {
            safety_enabled: public.safety_enabled,
            policy_count: public.policies.len(),
            active_switcher_count,
            active_blur_count,
            age_policy: public.age_policy,
            age_gate_trigger: public.age_gate_trigger,
            blocked_country_count: public.geo.blocked_countries.len(),
            fixed_blur_enabled: public.fixed_blur_enabled,
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
        legacy_upgrade_notice: loaded.legacy_upgrade_notice,
    })
    .into_response()
}

#[worker::send]
pub async fn save_access_settings(
    State(st): State<AppState>,
    Extension(admin): Extension<AdminIdentity>,
    headers: HeaderMap,
    Json(req): Json<SaveAccessReq>,
) -> Response {
    let editor = match guard_mutation(&st, &admin, &headers) {
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
    if let Err(msg) =
        ensure_v3_ready_for_non_safety_mutation(loaded.legacy_upgrade_notice.as_deref())
    {
        return conflict(msg);
    }

    if loaded.revision != req.revision {
        return conflict(
            "Settings were updated in another session. Reload the dashboard and reapply your changes.",
        );
    }

    loaded.doc.access = normalized_access.clone();
    match LoadedSettings::save_and_activate(&st.env, req.revision, &loaded.doc, editor).await {
        Ok(Some(ActivationOutcome::Active {
            ack,
            min_enforce_rev,
        })) => {
            worker::console_log!(
                "Admin {editor} saved & activated access settings rev={} digest={}",
                ack.revision,
                ack.policy_digest
            );
            Json(SaveAccessResp {
                ok: true,
                pending_activation: false,
                activation_status: ActivationStatus::Active.as_str().to_string(),
                revision: ack.revision,
                min_enforce_rev,
                digest: ack.policy_digest.clone(),
                policy_digest: ack.policy_digest,
                access: normalized_access,
            })
            .into_response()
        }
        Ok(Some(ActivationOutcome::PendingDoAck {
            revision,
            min_enforce_rev,
            policy_digest,
            error,
        })) => pending_activation_response(revision, min_enforce_rev, policy_digest, error),
        Ok(None) => conflict(
            "Settings were updated concurrently. Reload the dashboard and reapply your changes.",
        ),
        Err(e) => {
            worker::console_error!("save access settings failed: {e:?}");
            internal_error()
        }
    }
}
