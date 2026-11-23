//! Auth provider configuration (`GET/POST /admin/api/providers`) and encrypted
//! secret key rotation (`POST /admin/api/secrets/rotate`).
//!
//! Security guarantees:
//! - Enforces `AgeVerificationPolicy::StrictProviderVerified18` (H7): rejects enabling
//!   any provider where `!id.supports_strict_age_verification()`.
//! - Enforces OIDC SSRF URL validation (H11) on all issuer URLs.
//! - Stores secrets ONLY in D1 `provider_secrets` encrypted via AES-256-GCM using
//!   dedicated `SETTINGS_ENCRYPTION_KEY`, fresh 96-bit CSPRNG nonce, explicit `kid`,
//!   and AAD = `"{deployment_id}|{provider_id}|{field_name}"`.
//! - NEVER returns plaintext secrets and NEVER logs secret material.

use std::collections::HashMap;

use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use site_access::{AuthProviderId, AuthProviderPublicConfig, compute_policy_digest};
use worker::wasm_bindgen::JsValue;

use crate::{
    AppState, D1_BINDING,
    api::{ProviderView, ProvidersResp, RotateSecretsResp, SaveProvidersReq},
    handlers::{bad_request, conflict, guard_mutation, guard_read, internal_error},
    settings::{LoadedSettings, secret_field_for_provider, validate_provider_updates},
};

#[derive(Deserialize)]
struct SecretMetaRow {
    provider_id: String,
    field_name: String,
    kid: String,
    updated_at: i64,
    updated_by: Option<String>,
}

#[derive(Deserialize)]
struct SecretRotateRow {
    provider_id: String,
    field_name: String,
    kid: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

async fn load_secret_metadata(
    env: &worker::Env,
) -> worker::Result<HashMap<(String, String), SecretMetaRow>> {
    let db = env.d1(D1_BINDING)?;
    let rows = db
        .prepare(
            "SELECT provider_id, field_name, kid, updated_at, updated_by \
             FROM provider_secrets",
        )
        .all()
        .await?
        .results::<SecretMetaRow>()?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
        map.insert((row.provider_id.clone(), row.field_name.clone()), row);
    }
    Ok(map)
}

fn build_provider_views(
    age_policy: site_access::AgeVerificationPolicy,
    configured: &[AuthProviderPublicConfig],
    secret_meta: &HashMap<(String, String), SecretMetaRow>,
) -> Vec<ProviderView> {
    AuthProviderId::ALL
        .iter()
        .map(|&id| {
            let config = configured
                .iter()
                .find(|c| c.id == id)
                .cloned()
                .unwrap_or(AuthProviderPublicConfig {
                    id,
                    enabled: false,
                    display_name: None,
                    issuer: None,
                    public_client_id: None,
                    soft_birthday_check: false,
                });
            let secret_field = secret_field_for_provider(id);
            let meta = secret_field
                .and_then(|field| secret_meta.get(&(id.as_str().to_string(), field.to_string())));

            ProviderView {
                config,
                supports_strict_age_verification: id.supports_strict_age_verification(),
                allowed_under_age_policy: id.is_allowed_under(age_policy),
                secret_field_name: secret_field.map(str::to_string),
                has_client_secret: meta.is_some(),
                kid: meta.map(|m| m.kid.clone()),
                updated_at: meta.map(|m| m.updated_at),
                updated_by: meta.and_then(|m| m.updated_by.clone()),
            }
        })
        .collect()
}

#[worker::send]
pub async fn get_providers(State(st): State<AppState>, headers: HeaderMap) -> Response {
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

    let secret_meta = match load_secret_metadata(&st.env).await {
        Ok(m) => m,
        Err(e) => {
            worker::console_error!("load provider_secrets metadata failed: {e:?}");
            return internal_error();
        }
    };

    let public = &loaded.doc.public;
    let providers = build_provider_views(public.age_policy, &public.enabled_providers, &secret_meta);

    Json(ProvidersResp {
        revision: loaded.revision,
        min_enforce_rev: public.min_enforce_rev,
        digest: compute_policy_digest(public),
        age_policy: public.age_policy,
        current_kid: st.keyring.current.kid().to_string(),
        has_prev_key: st.keyring.has_previous(),
        providers,
    })
    .into_response()
}

#[worker::send]
pub async fn save_providers(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SaveProvidersReq>,
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

    let age_policy = loaded.doc.public.age_policy;
    let public_configs = match validate_provider_updates(age_policy, &req.providers) {
        Ok(cfgs) => cfgs,
        Err(msg) => return bad_request(msg),
    };

    // Pre-encrypt all submitted secrets BEFORE publishing a new settings revision
    // so any crypto/AAD failure rejects cleanly before mutating `site_settings`.
    enum PendingSecretOp {
        Delete {
            provider: &'static str,
            field: &'static str,
        },
        Upsert {
            provider: &'static str,
            field: &'static str,
            enc: crate::crypto::EncryptedSecret,
        },
    }
    let mut pending_ops = Vec::new();
    for item in &req.providers {
        let Some(field_name) = secret_field_for_provider(item.id) else {
            continue;
        };
        let provider_str = item.id.as_str();
        if item.clear_secret {
            pending_ops.push(PendingSecretOp::Delete {
                provider: provider_str,
                field: field_name,
            });
            continue;
        }
        if let Some(raw_secret) = item.secret_value.as_deref() {
            let trimmed = raw_secret.trim();
            if trimmed.is_empty() {
                continue;
            }
            let enc = match st.keyring.encrypt(
                &st.deployment_id,
                provider_str,
                field_name,
                trimmed.as_bytes(),
            ) {
                Ok(e) => e,
                Err(e) => {
                    worker::console_error!("encrypt provider secret failed for {provider_str}: {e}");
                    return internal_error();
                }
            };
            pending_ops.push(PendingSecretOp::Upsert {
                provider: provider_str,
                field: field_name,
                enc,
            });
        }
    }

    // Step 1: Commit strictly non-secret provider config via D1 CAS (do NOT publish
    // to SitePolicyDO yet until encrypted `provider_secrets` writes succeed).
    loaded.doc.public.enabled_providers = public_configs.clone();
    let (new_rev, stored_public, digest) =
        match LoadedSettings::save_d1_cas(&st.env, req.revision, &loaded.doc, admin).await {
            Ok(Some(res)) => res,
            Ok(None) => {
                return conflict(
                    "Settings were updated concurrently. Reload the dashboard and reapply your changes.",
                );
            }
            Err(e) => {
                worker::console_error!("save provider config failed: {e:?}");
                return internal_error();
            }
        };

    // Step 2: Persist any submitted write-only secrets ONLY in encrypted `provider_secrets` table.
    let db = match st.env.d1(D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };

    let mut secret_writes = Vec::new();
    let mut updated_secret_count = 0usize;
    let mut cleared_secret_count = 0usize;

    for op in pending_ops {
        match op {
            PendingSecretOp::Delete { provider, field } => match db
                .prepare("DELETE FROM provider_secrets WHERE provider_id = ? AND field_name = ?")
                .bind(&[provider.into(), field.into()])
            {
                Ok(stmt) => {
                    secret_writes.push(stmt);
                    cleared_secret_count += 1;
                }
                Err(e) => {
                    worker::console_error!("bind delete provider_secret failed: {e:?}");
                    return internal_error();
                }
            },
            PendingSecretOp::Upsert {
                provider,
                field,
                enc,
            } => {
                let nonce_val: JsValue = js_sys::Uint8Array::from(&enc.nonce[..]).into();
                let ct_val: JsValue = js_sys::Uint8Array::from(enc.ciphertext.as_slice()).into();

                match db
                    .prepare(
                        "INSERT INTO provider_secrets \
                           (provider_id, field_name, kid, nonce, ciphertext, updated_at, updated_by) \
                         VALUES (?, ?, ?, ?, ?, unixepoch(), ?) \
                         ON CONFLICT(provider_id, field_name) DO UPDATE SET \
                           kid = excluded.kid, \
                           nonce = excluded.nonce, \
                           ciphertext = excluded.ciphertext, \
                           updated_at = excluded.updated_at, \
                           updated_by = excluded.updated_by",
                    )
                    .bind(&[
                        provider.into(),
                        field.into(),
                        enc.kid.as_str().into(),
                        nonce_val,
                        ct_val,
                        admin.into(),
                    ])
                {
                    Ok(stmt) => {
                        secret_writes.push(stmt);
                        updated_secret_count += 1;
                    }
                    Err(e) => {
                        worker::console_error!("bind upsert provider_secret failed: {e:?}");
                        return internal_error();
                    }
                }
            }
        }
    }

    if !secret_writes.is_empty()
        && let Err(e) = db.batch(secret_writes).await
    {
        worker::console_error!("write provider_secrets batch failed: {e:?}");
        return internal_error();
    }

    // Step 3: Publish to SitePolicyDO ONLY AFTER both D1 CAS and `provider_secrets` succeed.
    if let Err(e) = crate::do_client::publish_site_policy(&st.env, &stored_public, &digest).await {
        worker::console_error!("SitePolicyDO publish after provider save failed: {e:?}");
        return internal_error();
    }

    worker::console_log!(
        "Admin {admin} saved providers rev={new_rev} secrets_updated={updated_secret_count} secrets_cleared={cleared_secret_count}"
    );

    let secret_meta = match load_secret_metadata(&st.env).await {
        Ok(m) => m,
        Err(e) => {
            worker::console_error!("reload provider_secrets metadata failed: {e:?}");
            return internal_error();
        }
    };
    let providers = build_provider_views(age_policy, &public_configs, &secret_meta);

    Json(ProvidersResp {
        revision: new_rev,
        min_enforce_rev: loaded.doc.public.min_enforce_rev,
        digest,
        age_policy,
        current_kid: st.keyring.current.kid().to_string(),
        has_prev_key: st.keyring.has_previous(),
        providers,
    })
    .into_response()
}

/// Re-encrypts rows in `provider_secrets` from `SETTINGS_ENCRYPTION_KEY_PREV` (or any
/// older `kid`) to the active `SETTINGS_ENCRYPTION_KEY` with fresh 96-bit CSPRNG nonces.
///
/// Uses per-row optimistic CAS (`WHERE provider_id = ? AND field_name = ? AND kid = ?`)
/// so rotation is safe and resumable across retries.
#[worker::send]
pub async fn rotate_secrets(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match guard_mutation(&st, &headers) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let db = match st.env.d1(D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };

    let rows = match db
        .prepare(
            "SELECT provider_id, field_name, kid, hex(nonce) AS nonce_hex, hex(ciphertext) AS ciphertext_hex \
             FROM provider_secrets",
        )
        .all()
        .await
        .and_then(|r| r.results::<SecretRotateRow>())
    {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("query provider_secrets for rotation failed: {e:?}");
            return internal_error();
        }
    };

    let current_kid = st.keyring.current.kid().to_string();
    let total_rows = rows.len();
    let mut rotated = 0usize;
    let mut skipped_current = 0usize;
    let mut failed = 0usize;

    for row in rows {
        if row.kid == current_kid {
            skipped_current += 1;
            continue;
        }
        let (Ok(old_nonce), Ok(old_ct)) = (
            hex::decode(&row.nonce_hex),
            hex::decode(&row.ciphertext_hex),
        ) else {
            worker::console_error!(
                "corrupt hex blob in provider_secrets for {}/{}",
                row.provider_id,
                row.field_name
            );
            failed += 1;
            continue;
        };

        let reenc = match st.keyring.reencrypt(
            &st.deployment_id,
            &row.provider_id,
            &row.field_name,
            &row.kid,
            &old_nonce,
            &old_ct,
        ) {
            Ok(e) => e,
            Err(e) => {
                worker::console_error!(
                    "re-encrypt failed for {}/{} (kid={}): {e}",
                    row.provider_id,
                    row.field_name,
                    row.kid
                );
                failed += 1;
                continue;
            }
        };

        let nonce_val: JsValue = js_sys::Uint8Array::from(&reenc.nonce[..]).into();
        let ct_val: JsValue = js_sys::Uint8Array::from(reenc.ciphertext.as_slice()).into();

        // Resumable CAS update: only updates if `kid` has not already changed concurrently.
        let res = db
            .prepare(
                "UPDATE provider_secrets \
                 SET kid = ?, nonce = ?, ciphertext = ?, updated_at = unixepoch(), updated_by = ? \
                 WHERE provider_id = ? AND field_name = ? AND kid = ?",
            )
            .bind(&[
                reenc.kid.as_str().into(),
                nonce_val,
                ct_val,
                admin.into(),
                row.provider_id.as_str().into(),
                row.field_name.as_str().into(),
                row.kid.as_str().into(),
            ]);

        match res {
            Ok(stmt) => match stmt.run().await {
                Ok(out) if out.meta().ok().flatten().and_then(|m| m.changes) == Some(1) => {
                    rotated += 1;
                }
                Ok(_) => {
                    skipped_current += 1;
                }
                Err(e) => {
                    worker::console_error!(
                        "persist rotated secret failed for {}/{}: {e:?}",
                        row.provider_id,
                        row.field_name
                    );
                    failed += 1;
                }
            },
            Err(e) => {
                worker::console_error!("bind rotate update failed: {e:?}");
                failed += 1;
            }
        }
    }

    worker::console_log!(
        "Admin {admin} rotated provider_secrets: total={total_rows} rotated={rotated} skipped={skipped_current} failed={failed} target_kid={current_kid}"
    );

    Json(RotateSecretsResp {
        current_kid,
        total_rows,
        rotated,
        skipped_current,
        failed,
    })
    .into_response()
}
