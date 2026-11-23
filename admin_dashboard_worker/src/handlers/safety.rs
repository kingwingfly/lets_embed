//! Policy v3 Content Safety endpoints:
//! - `GET  /admin/api/safety`
//! - `POST /admin/api/safety`
//! - `POST /admin/api/policy/retry-activation`
//!
//! Validates Policy v3 via `site_access::validate_policy_set_with_mode`, validates
//! `post_tag:` / `author:` references against `APP_ORIGIN/internal/validate-safety-catalog`
//! when configured, computes conservative `grant_generation` & `min_enforce_rev`, and
//! executes two-phase activation (`pending_do_ack` -> exact `SitePolicyDO` ACK -> `active`).

use axum::{
    Extension, Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use site_access::{builtin_safety_presets, compute_policy_digest};

use crate::{
    AppState,
    api::{
        ActivationStatus, RetryActivationResp, SafetyConfigResp, SaveSafetyReq, SaveSafetyResp,
    },
    do_client,
    handlers::{
        bad_gateway, bad_request, bad_request_fields, conflict, guard_mutation, guard_read,
        internal_error, pending_activation_response,
    },
    security::AdminIdentity,
    settings::{
        ActivationOutcome, LEGACY_UNCLASSIFIED_NOTE, LoadedSettings, build_catalog_field_errors,
        prepare_safety_update,
    },
};

#[worker::send]
pub async fn get_safety(
    State(st): State<AppState>,
    Extension(admin): Extension<AdminIdentity>,
) -> Response {
    if let Err(resp) = guard_read(&st, &admin) {
        return resp;
    }

    let loaded = match LoadedSettings::load(&st.env).await {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("load site_settings failed: {e:?}");
            return internal_error();
        }
    };

    let p = loaded.doc.public;
    let policy_digest = compute_policy_digest(&p);

    Json(SafetyConfigResp {
        schema_version: p.schema_version,
        revision: loaded.revision,
        min_enforce_rev: p.min_enforce_rev,
        policy_digest,
        vocab_digest: p.vocab_digest,
        activation_status: loaded.activation_status.as_str().to_string(),
        safety_enabled: p.safety_enabled,
        policies: p.policies,
        presets: builtin_safety_presets(),
        unclassified_mode: p.unclassified_mode,
        fixed_blur_enabled: p.fixed_blur_enabled,
        age_policy: p.age_policy,
        age_gate_trigger: p.age_gate_trigger,
        similarity: p.similarity,
        geo: p.geo,
        legal: p.legal,
        legacy_unclassified_note: LEGACY_UNCLASSIFIED_NOTE.to_string(),
        legacy_upgrade_notice: loaded.legacy_upgrade_notice,
    })
    .into_response()
}

#[worker::send]
pub async fn save_safety(
    State(st): State<AppState>,
    Extension(admin): Extension<AdminIdentity>,
    headers: HeaderMap,
    Json(req): Json<SaveSafetyReq>,
) -> Response {
    let editor = match guard_mutation(&st, &admin, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
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

    let next_rev = req.revision.saturating_add(1);
    let prepared = match prepare_safety_update(&loaded.doc.public, &req, next_rev) {
        Ok(u) => u,
        Err(msg) => return bad_request(msg),
    };

    // Optional origin catalog validation (`POST {APP_ORIGIN}/internal/validate-safety-catalog`)
    // for all `post_tag:` and `author:` references across `match_expr` and `except_expr`.
    if !prepared.all_post_tags.is_empty() || !prepared.all_authors.is_empty() {
        match do_client::validate_safety_catalog_remote(
            &st.env,
            &prepared.all_post_tags,
            &prepared.all_authors,
        )
        .await
        {
            Ok(Some(cat))
                if !cat.unknown_post_tags.is_empty() || !cat.unknown_authors.is_empty() =>
            {
                let field_errors = build_catalog_field_errors(
                    &prepared.field_refs,
                    &cat.unknown_post_tags,
                    &cat.unknown_authors,
                );
                let summary = field_errors
                    .iter()
                    .map(|e| e.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                return bad_request_fields(summary, field_errors);
            }
            Ok(_) => {}
            Err(e) => {
                worker::console_error!("origin catalog validation failed: {e:?}");
                return bad_gateway(format!(
                    "Origin catalog validation failed (policy not published): {e}"
                ));
            }
        }
    }

    loaded.doc.public = prepared.next_policy.clone();

    match LoadedSettings::save_and_activate(&st.env, req.revision, &loaded.doc, editor).await {
        Ok(Some(ActivationOutcome::Active {
            ack,
            min_enforce_rev,
        })) => {
            worker::console_log!(
                "Admin {editor} published & activated Policy v3 rev={} min_enforce_rev={} tightened={} terms_bumped={} auto_disabled={}",
                ack.revision,
                min_enforce_rev,
                prepared.tightened,
                prepared.terms_bumped,
                prepared.auto_disabled_providers.len()
            );
            Json(SaveSafetyResp {
                ok: true,
                pending_activation: false,
                activation_status: ActivationStatus::Active.as_str().to_string(),
                revision: ack.revision,
                min_enforce_rev,
                tightened: prepared.tightened,
                terms_bumped: prepared.terms_bumped,
                auto_disabled_providers: prepared.auto_disabled_providers,
                policy_digest: ack.policy_digest,
                vocab_digest: prepared.next_policy.vocab_digest,
                policies: prepared.next_policy.policies,
                legal: prepared.next_policy.legal,
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
            worker::console_error!("save safety policy failed: {e:?}");
            internal_error()
        }
    }
}

/// Idempotent retry endpoint for activating a `pending_do_ack` revision on `SitePolicyDO`.
#[worker::send]
pub async fn retry_policy_activation(
    State(st): State<AppState>,
    Extension(admin): Extension<AdminIdentity>,
    headers: HeaderMap,
) -> Response {
    let editor = match guard_mutation(&st, &admin, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    match LoadedSettings::retry_latest_activation(&st.env).await {
        Ok(ActivationOutcome::Active {
            ack,
            min_enforce_rev,
        }) => {
            worker::console_log!(
                "Admin {editor} retried & activated Policy v3 rev={} digest={}",
                ack.revision,
                ack.policy_digest
            );
            Json(RetryActivationResp {
                ok: true,
                pending_activation: false,
                activation_status: ActivationStatus::Active.as_str().to_string(),
                revision: ack.revision,
                min_enforce_rev,
                policy_digest: ack.policy_digest,
            })
            .into_response()
        }
        Ok(ActivationOutcome::PendingDoAck {
            revision,
            min_enforce_rev,
            policy_digest,
            error,
        }) => pending_activation_response(revision, min_enforce_rev, policy_digest, error),
        Err(e) => {
            worker::console_error!("retry policy activation failed: {e:?}");
            bad_request(e.to_string())
        }
    }
}
