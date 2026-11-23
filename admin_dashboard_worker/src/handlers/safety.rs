//! `GET /admin/api/safety` and `POST /admin/api/safety`.
//!
//! Validates metadata-only safety rules (`search_types::safety::validate_policy_rules`),
//! similarity thresholds (`search_types::validate_min_similarity`), ISO-3166 geo codes,
//! Terms digest/version bumping, Strict 18+ provider auto-disablement, monotonic
//! `min_enforce_rev` tightening detection, D1 CAS publication, and immediate
//! `SitePolicyDO` `/publish` synchronization.

use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use site_access::{builtin_safety_presets, compute_policy_digest};

use crate::{
    AppState,
    api::{SafetyConfigResp, SaveSafetyReq, SaveSafetyResp},
    handlers::{bad_request, conflict, guard_mutation, guard_read, internal_error},
    settings::{LEGACY_UNCLASSIFIED_NOTE, LoadedSettings, prepare_safety_update},
};

#[worker::send]
pub async fn get_safety(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = guard_read(&st, &headers) {
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
    let digest = compute_policy_digest(&p);

    Json(SafetyConfigResp {
        revision: loaded.revision,
        min_enforce_rev: p.min_enforce_rev,
        digest,
        safety_enabled: p.safety_enabled,
        rules: p.rules,
        presets: builtin_safety_presets(),
        unclassified_mode: p.unclassified_mode,
        cloudflare_images_blur: p.cloudflare_images_blur,
        age_policy: p.age_policy,
        age_gate_trigger: p.age_gate_trigger,
        similarity: p.similarity,
        geo: p.geo,
        legal: p.legal,
        panic_shortcut: p.panic_shortcut,
        legacy_unclassified_note: LEGACY_UNCLASSIFIED_NOTE.to_string(),
    })
    .into_response()
}

#[worker::send]
pub async fn save_safety(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SaveSafetyReq>,
) -> Response {
    let admin = match guard_mutation(&st, &headers) {
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

    loaded.doc.public = prepared.next_policy.clone();

    match LoadedSettings::save_and_publish(&st.env, req.revision, &loaded.doc, admin).await {
        Ok(Some((new_rev, digest))) => {
            worker::console_log!(
                "Admin {admin} published safety policy rev={new_rev} min_enforce_rev={} tightened={} terms_bumped={} auto_disabled={}",
                prepared.next_policy.min_enforce_rev,
                prepared.tightened,
                prepared.terms_bumped,
                prepared.auto_disabled_providers.len()
            );
            Json(SaveSafetyResp {
                revision: new_rev,
                min_enforce_rev: prepared.next_policy.min_enforce_rev,
                tightened: prepared.tightened,
                terms_bumped: prepared.terms_bumped,
                auto_disabled_providers: prepared.auto_disabled_providers,
                digest,
                legal: prepared.next_policy.legal,
            })
            .into_response()
        }
        Ok(None) => conflict(
            "Settings were updated concurrently. Reload the dashboard and reapply your changes.",
        ),
        Err(e) => {
            worker::console_error!("save safety policy failed: {e:?}");
            internal_error()
        }
    }
}
