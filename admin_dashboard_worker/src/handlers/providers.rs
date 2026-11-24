//! Auth provider configuration (`GET/POST /admin/api/providers`) and encrypted
//! secret key rotation (`POST /admin/api/secrets/rotate`).
//!
//! Security guarantees:
//! - Enforces `AgeVerificationPolicy::StrictProviderVerified18` (H7): rejects enabling
//!   any provider where `!id.supports_strict_age_verification()`.
//! - Enforces OIDC SSRF URL validation (H11) on all issuer URLs.
//! - Stores secrets ONLY in D1 `provider_secrets` encrypted via AES-256-GCM using
//!   `PROVIDER_SECRETS_KEY` / `SETTINGS_ENCRYPTION_KEY` / HKDF(`SITE_SECRET`),
//!   fresh 96-bit CSPRNG nonce, explicit `kid`, and AAD = `"{deployment_id}|{provider_id}|{field_name}"`.
//! - NEVER returns plaintext secrets and NEVER logs secret material.

use std::collections::HashMap;

use axum::{
    Extension, Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use site_access::{AuthProviderId, AuthProviderPublicConfig, compute_policy_digest};
use worker::wasm_bindgen::JsValue;

use crate::{
    AppState, D1_BINDING,
    api::{
        ActivationStatus, ProviderView, ProvidersResp, RotateSecretsResp, SaveProvidersReq,
        SaveProvidersResp,
    },
    handlers::{
        bad_request, conflict, guard_mutation, guard_read, internal_error,
        pending_activation_response,
    },
    security::AdminIdentity,
    settings::{
        ActivationOutcome, LoadedSettings, are_providers_unchanged,
        ensure_v3_ready_for_non_safety_mutation, secret_field_for_provider,
        validate_provider_updates,
    },
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
struct VersionedSecretMetaRow {
    provider_id: String,
    field_name: String,
    kid: String,
    deleted: i64,
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

#[derive(Deserialize)]
struct VersionedSecretRotateRow {
    policy_rev: i64,
    provider_id: String,
    field_name: String,
    kid: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

/// Load effective masked secret metadata up to `up_to_rev`: overlays versioned rows
/// from `provider_secret_versions` (`policy_rev <= up_to_rev`, ordered ascending so
/// the newest version wins) on top of legacy `provider_secrets` (F11).
async fn load_secret_metadata(
    env: &worker::Env,
    up_to_rev: u64,
) -> worker::Result<HashMap<(String, String), SecretMetaRow>> {
    let db = env.d1(D1_BINDING)?;
    let legacy_rows = db
        .prepare(
            "SELECT provider_id, field_name, kid, updated_at, updated_by \
             FROM provider_secrets",
        )
        .all()
        .await?
        .results::<SecretMetaRow>()?;
    let mut map = HashMap::with_capacity(legacy_rows.len());
    for row in legacy_rows {
        map.insert((row.provider_id.clone(), row.field_name.clone()), row);
    }

    let ver_rows = db
        .prepare(
            "SELECT provider_id, field_name, kid, deleted, updated_at, updated_by \
             FROM provider_secret_versions \
             WHERE policy_rev <= ?1 \
             ORDER BY policy_rev ASC",
        )
        .bind(&[(up_to_rev as f64).into()])?
        .all()
        .await?
        .results::<VersionedSecretMetaRow>()?;
    for row in ver_rows {
        let key = (row.provider_id.clone(), row.field_name.clone());
        if row.deleted != 0 {
            map.remove(&key);
        } else {
            map.insert(
                key,
                SecretMetaRow {
                    provider_id: row.provider_id,
                    field_name: row.field_name,
                    kid: row.kid,
                    updated_at: row.updated_at,
                    updated_by: row.updated_by,
                },
            );
        }
    }
    Ok(map)
}

fn build_provider_views(
    age_policy: site_access::AgeVerificationPolicy,
    configured: &[AuthProviderPublicConfig],
    secret_meta: &HashMap<(String, String), SecretMetaRow>,
) -> Vec<ProviderView> {
    // Match runtime effective defaults (F28): when `enabled_providers` is empty and
    // `age_policy != StrictProviderVerified18`, SIWE and SIWS are active by default in `user_worker`.
    let empty_defaults_wallets = configured.is_empty()
        && age_policy != site_access::AgeVerificationPolicy::StrictProviderVerified18;
    AuthProviderId::ALL
        .iter()
        .map(|&id| {
            let config = configured
                .iter()
                .find(|c| c.id == id)
                .cloned()
                .unwrap_or(AuthProviderPublicConfig {
                    id,
                    enabled: empty_defaults_wallets
                        && matches!(id, AuthProviderId::Siwe | AuthProviderId::Siws),
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
pub async fn get_providers(
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

    let secret_meta = match load_secret_metadata(&st.env, loaded.revision).await {
        Ok(m) => m,
        Err(e) => {
            worker::console_error!("load provider_secrets metadata failed: {e:?}");
            return internal_error();
        }
    };

    let public = &loaded.doc.public;
    let providers = build_provider_views(public.age_policy, &public.enabled_providers, &secret_meta);
    let policy_digest = compute_policy_digest(public);

    Json(ProvidersResp {
        ok: !loaded.activation_status.is_pending(),
        unchanged: false,
        pending_activation: loaded.activation_status.is_pending(),
        activation_status: loaded.activation_status.as_str().to_string(),
        revision: loaded.revision,
        min_enforce_rev: public.min_enforce_rev,
        digest: policy_digest.clone(),
        policy_digest,
        age_policy: public.age_policy,
        current_kid: st.keyring.current.kid().to_string(),
        has_prev_key: st.keyring.has_previous(),
        public_origin: st.public_origin(),
        providers,
    })
    .into_response()
}

#[worker::send]
pub async fn save_providers(
    State(st): State<AppState>,
    Extension(admin): Extension<AdminIdentity>,
    headers: HeaderMap,
    Json(req): Json<SaveProvidersReq>,
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

    if are_providers_unchanged(
        age_policy,
        &loaded.doc.public.enabled_providers,
        &public_configs,
        !pending_ops.is_empty(),
    ) {
        let secret_meta = match load_secret_metadata(&st.env, loaded.revision).await {
            Ok(m) => m,
            Err(e) => {
                worker::console_error!("load provider_secrets metadata failed: {e:?}");
                return internal_error();
            }
        };
        let public = &loaded.doc.public;
        let providers = build_provider_views(age_policy, &public.enabled_providers, &secret_meta);
        let policy_digest = compute_policy_digest(public);
        return Json(SaveProvidersResp {
            ok: true,
            unchanged: true,
            pending_activation: loaded.activation_status.is_pending(),
            activation_status: loaded.activation_status.as_str().to_string(),
            revision: loaded.revision,
            min_enforce_rev: public.min_enforce_rev,
            digest: policy_digest.clone(),
            policy_digest,
            age_policy,
            current_kid: st.keyring.current.kid().to_string(),
            has_prev_key: st.keyring.has_previous(),
            public_origin: st.public_origin(),
            providers,
        })
        .into_response();
    }

    // Phase 1: Stage write-only encrypted secrets in revision-scoped `provider_secret_versions`
    // at `policy_rev = target_rev` AND commit `site_settings` inside ONE single atomic D1 batch
    // transaction BEFORE Phase-2 activation (F11 + Cycle 2 C-1).
    let target_rev = req.revision.saturating_add(1);
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
                .prepare(
                    "INSERT INTO provider_secret_versions \
                       (policy_rev, provider_id, field_name, kid, nonce, ciphertext, deleted, updated_at, updated_by) \
                     VALUES (?, ?, ?, '', X'', X'', 1, unixepoch(), ?)",
                )
                .bind(&[
                    (target_rev as f64).into(),
                    provider.into(),
                    field.into(),
                    editor.into(),
                ]) {
                Ok(stmt) => {
                    secret_writes.push(stmt);
                    cleared_secret_count += 1;
                }
                Err(e) => {
                    worker::console_error!("bind delete provider_secret_versions failed: {e:?}");
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
                        "INSERT INTO provider_secret_versions \
                           (policy_rev, provider_id, field_name, kid, nonce, ciphertext, deleted, updated_at, updated_by) \
                         VALUES (?, ?, ?, ?, ?, ?, 0, unixepoch(), ?)",
                    )
                    .bind(&[
                        (target_rev as f64).into(),
                        provider.into(),
                        field.into(),
                        enc.kid.as_str().into(),
                        nonce_val,
                        ct_val,
                        editor.into(),
                    ])
                {
                    Ok(stmt) => {
                        secret_writes.push(stmt);
                        updated_secret_count += 1;
                    }
                    Err(e) => {
                        worker::console_error!("bind upsert provider_secret_versions failed: {e:?}");
                        return internal_error();
                    }
                }
            }
        }
    }

    loaded.doc.public.enabled_providers = public_configs.clone();
    let (new_rev, stored_public, digest) = match LoadedSettings::save_d1_cas_pending_with_writes(
        &st.env,
        req.revision,
        &loaded.doc,
        editor,
        secret_writes,
    )
    .await
    {
        Ok(Some(res)) => res,
        Ok(None) => {
            return conflict(
                "Settings were updated concurrently. Reload the dashboard and reapply your changes.",
            );
        }
        Err(e) => {
            worker::console_error!("atomic save provider config + secrets failed: {e:?}");
            return internal_error();
        }
    };

    // Phase 2: Activate on SitePolicyDO ONLY AFTER both D1 CAS and staged secrets succeed.
    match LoadedSettings::activate_saved_revision(&st.env, &stored_public, &digest).await {
        Ok(ActivationOutcome::Active {
            ack,
            min_enforce_rev,
        }) => {
            worker::console_log!(
                "Admin {editor} saved & activated providers rev={} secrets_updated={updated_secret_count} secrets_cleared={cleared_secret_count}",
                ack.revision
            );

            let secret_meta = match load_secret_metadata(&st.env, ack.revision).await {
                Ok(m) => m,
                Err(e) => {
                    worker::console_error!("reload provider_secrets metadata failed: {e:?}");
                    return internal_error();
                }
            };
            let providers = build_provider_views(age_policy, &public_configs, &secret_meta);

            Json(SaveProvidersResp {
                ok: true,
                unchanged: false,
                pending_activation: false,
                activation_status: ActivationStatus::Active.as_str().to_string(),
                revision: ack.revision,
                min_enforce_rev,
                digest: ack.policy_digest.clone(),
                policy_digest: ack.policy_digest,
                age_policy,
                current_kid: st.keyring.current.kid().to_string(),
                has_prev_key: st.keyring.has_previous(),
                public_origin: st.public_origin(),
                providers,
            })
            .into_response()
        }
        Ok(ActivationOutcome::PendingDoAck {
            revision,
            min_enforce_rev,
            policy_digest,
            error,
        }) => {
            worker::console_warn!(
                "Admin {editor} saved providers rev={new_rev} (pending_do_ack): {error}"
            );
            pending_activation_response(revision, min_enforce_rev, policy_digest, error)
        }
        Err(e) => {
            worker::console_error!("activate providers policy failed: {e:?}");
            internal_error()
        }
    }
}

/// Re-encrypts rows in `provider_secrets` from the previous key (or any older `kid`)
/// to the active provider encryption key with fresh 96-bit CSPRNG nonces.
#[worker::send]
pub async fn rotate_secrets(
    State(st): State<AppState>,
    Extension(admin): Extension<AdminIdentity>,
    headers: HeaderMap,
) -> Response {
    let editor = match guard_mutation(&st, &admin, &headers) {
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

    // Prune aged superseded/tombstoned historical rows BEFORE re-encrypting so retired keys
    // and cleared secrets never cause permanent rotation failures or remain in D1 indefinitely (Cycle 2 C-2).
    #[derive(Deserialize)]
    struct ActiveRevRow {
        rev: i64,
    }
    let active_rev = match db
        .prepare(
            "SELECT COALESCE(MAX(revision), 0) AS rev \
             FROM site_settings WHERE activation_status = 'active'",
        )
        .first::<ActiveRevRow>(None)
        .await
    {
        Ok(r) => r.map_or(0, |row| row.rev.max(0) as u64),
        Err(e) => {
            worker::console_error!("query active policy rev for rotation failed: {e:?}");
            return internal_error();
        }
    };

    if let (Ok(prune_ver), Ok(prune_legacy)) = (
        db.prepare(
            "DELETE FROM provider_secret_versions \
             WHERE policy_rev < ( \
               SELECT MAX(v2.policy_rev) \
               FROM provider_secret_versions v2 \
               WHERE v2.provider_id = provider_secret_versions.provider_id \
                 AND v2.field_name = provider_secret_versions.field_name \
                 AND v2.policy_rev <= ?1 \
                 AND v2.updated_at <= unixepoch() - 120 \
             )",
        )
        .bind(&[(active_rev as f64).into()]),
        db.prepare(
            "DELETE FROM provider_secrets \
             WHERE EXISTS ( \
               SELECT 1 FROM provider_secret_versions v \
               WHERE v.provider_id = provider_secrets.provider_id \
                 AND v.field_name = provider_secrets.field_name \
                 AND v.policy_rev <= ?1 \
                 AND v.updated_at <= unixepoch() - 120 \
             )",
        )
        .bind(&[(active_rev as f64).into()]),
    ) && let Err(e) = db.batch(vec![prune_ver, prune_legacy]).await
    {
        worker::console_warn!("prune superseded secret rows warning: {e:?}");
    }

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

    let versioned_rows = match db
        .prepare(
            "SELECT policy_rev, provider_id, field_name, kid, hex(nonce) AS nonce_hex, hex(ciphertext) AS ciphertext_hex \
             FROM provider_secret_versions WHERE deleted = 0",
        )
        .all()
        .await
        .and_then(|r| r.results::<VersionedSecretRotateRow>())
    {
        Ok(r) => r,
        Err(e) => {
            worker::console_error!("query provider_secret_versions for rotation failed: {e:?}");
            return internal_error();
        }
    };

    let current_kid = st.keyring.current.kid().to_string();
    let total_rows = rows.len() + versioned_rows.len();
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
                editor.into(),
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

    for row in versioned_rows {
        if row.kid == current_kid {
            skipped_current += 1;
            continue;
        }
        let (Ok(old_nonce), Ok(old_ct)) = (
            hex::decode(&row.nonce_hex),
            hex::decode(&row.ciphertext_hex),
        ) else {
            worker::console_error!(
                "corrupt hex blob in provider_secret_versions for rev={}/{}/{}",
                row.policy_rev,
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
                    "re-encrypt failed for versioned rev={}/{}/{} (kid={}): {e}",
                    row.policy_rev,
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
        let res = db
            .prepare(
                "UPDATE provider_secret_versions \
                 SET kid = ?, nonce = ?, ciphertext = ?, updated_at = unixepoch(), updated_by = ? \
                 WHERE policy_rev = ? AND provider_id = ? AND field_name = ? AND kid = ?",
            )
            .bind(&[
                reenc.kid.as_str().into(),
                nonce_val,
                ct_val,
                editor.into(),
                (row.policy_rev as f64).into(),
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
                        "persist rotated versioned secret failed for rev={}/{}/{}: {e:?}",
                        row.policy_rev,
                        row.provider_id,
                        row.field_name
                    );
                    failed += 1;
                }
            },
            Err(e) => {
                worker::console_error!("bind rotate versioned update failed: {e:?}");
                failed += 1;
            }
        }
    }

    worker::console_log!(
        "Admin {editor} rotated provider_secrets: total={total_rows} rotated={rotated} skipped={skipped_current} failed={failed} target_kid={current_kid}"
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
