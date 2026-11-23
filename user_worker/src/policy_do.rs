//! Authoritative singleton `SitePolicyDO` (fixes H3 & matches wire contract #56).
//!
//! Singleton instance `"global"` stores the latest allowlisted [`PublicSitePolicy`],
//! deterministic SHA-256 `digest`, and monotonic `min_enforce_rev`.
//!
//! Routes:
//! - `GET  /policy`  -> `200` JSON `{ "policy": PublicSitePolicy, "digest": "<hex-sha256>" }`
//! - `POST /publish` -> called by `admin_dashboard_worker` after D1 CAS publish

use std::cell::Cell;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use site_access::{
    AgeGateTrigger, AgeVerificationPolicy, AuthProviderPublicConfig, GeoPolicy, LegalDocConfig,
    PublicSitePolicy, SafetyRuleConfig, SimilarityDefaults, UnclassifiedMode,
    canonical_policy_json, compute_policy_digest, compute_terms_digest,
};
use worker::{DurableObject, Env, Method, Request, RequestInit, Response, Result, State, durable_object};

pub const SITE_POLICY_BINDING: &str = "SITE_POLICY";
pub const SITE_POLICY_SINGLETON: &str = "global";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SitePolicyEnvelope {
    pub policy: PublicSitePolicy,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum PublishPayload {
    Envelope {
        policy: PublicSitePolicy,
        #[serde(default)]
        digest: Option<String>,
    },
    Bare(PublicSitePolicy),
}

// ---------------------------------------------------------------------------
// Strict Allowlist D1 Extraction (ZERO secrets ever leak)
// ---------------------------------------------------------------------------

/// Extract ONLY the allowlisted fields of [`PublicSitePolicy`] from a D1
/// `site_settings.document` JSON blob. Supports both nested `public_policy`
/// objects and top-level merged documents while silently discarding all pricing
/// fields and any unknown/secret fields.
pub fn extract_public_policy_from_document(revision: u32, document: &str) -> PublicSitePolicy {
    let raw: Value = serde_json::from_str(document).unwrap_or(Value::Null);
    let src = raw
        .get("public_policy")
        .filter(|v| v.is_object())
        .unwrap_or(&raw);

    let mut policy = PublicSitePolicy::default();

    if let Some(obj) = src.as_object() {
        if let Some(v) = obj.get("min_enforce_rev").and_then(Value::as_u64) {
            policy.min_enforce_rev = u32::try_from(v).unwrap_or(revision);
        }
        if let Some(v) = obj.get("safety_enabled").and_then(Value::as_bool) {
            policy.safety_enabled = v;
        }
        if let Some(v) = obj.get("rules")
            && let Ok(rules) = serde_json::from_value::<Vec<SafetyRuleConfig>>(v.clone())
        {
            policy.rules = rules;
        }
        if let Some(v) = obj.get("unclassified_mode")
            && let Ok(mode) = serde_json::from_value::<UnclassifiedMode>(v.clone())
        {
            policy.unclassified_mode = mode;
        }
        if let Some(v) = obj.get("cloudflare_images_blur").and_then(Value::as_bool) {
            policy.cloudflare_images_blur = v;
        }
        if let Some(v) = obj.get("age_policy")
            && let Ok(ap) = serde_json::from_value::<AgeVerificationPolicy>(v.clone())
        {
            policy.age_policy = ap;
        }
        if let Some(v) = obj.get("age_gate_trigger")
            && let Ok(trigger) = serde_json::from_value::<AgeGateTrigger>(v.clone())
        {
            policy.age_gate_trigger = trigger;
        }
        if let Some(v) = obj.get("similarity")
            && let Ok(sim) = serde_json::from_value::<SimilarityDefaults>(v.clone())
            && sim.is_valid()
        {
            policy.similarity = sim;
        }
        if let Some(v) = obj.get("legal")
            && let Ok(mut legal) = serde_json::from_value::<LegalDocConfig>(v.clone())
        {
            if legal.terms_digest.trim().is_empty() {
                legal.terms_digest = compute_terms_digest(&legal.terms_md);
            }
            policy.legal = legal;
        }
        if let Some(v) = obj.get("geo")
            && let Ok(geo) = serde_json::from_value::<GeoPolicy>(v.clone())
        {
            policy.geo = geo;
        }
        if let Some(arr) = obj.get("enabled_providers").and_then(Value::as_array) {
            // Explicitly strip any unknown/secret fields from each provider entry
            // before deserializing into `AuthProviderPublicConfig` (`deny_unknown_fields`).
            let mut providers = Vec::with_capacity(arr.len());
            for item in arr {
                if let Some(pobj) = item.as_object() {
                    let mut filtered = serde_json::Map::new();
                    for key in [
                        "id",
                        "enabled",
                        "display_name",
                        "issuer",
                        "public_client_id",
                        "soft_birthday_check",
                    ] {
                        if let Some(val) = pobj.get(key) {
                            filtered.insert(key.to_string(), val.clone());
                        }
                    }
                    if let Ok(cfg) =
                        serde_json::from_value::<AuthProviderPublicConfig>(Value::Object(filtered))
                    {
                        providers.push(cfg);
                    }
                }
            }
            policy.enabled_providers = providers;
        }
        if let Some(s) = obj
            .get("panic_shortcut")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 32)
        {
            policy.panic_shortcut = s.to_string();
        }
    }

    policy.revision = revision;
    policy.min_enforce_rev = policy.min_enforce_rev.min(revision);
    if policy.legal.terms_digest.trim().is_empty() {
        policy.legal.terms_digest = compute_terms_digest(&policy.legal.terms_md);
    }
    policy
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishValidationError {
    DigestMismatch,
    StaleRevision { incoming: u32, current: u32 },
    NonMonotonicMinEnforceRev { incoming: u32, current: u32 },
    InvalidMinEnforceRev,
}

/// Pure validation for `SitePolicyDO` publish transitions.
pub fn validate_publish_transition(
    current: Option<(u32, u32, &str)>,
    incoming: &PublicSitePolicy,
    supplied_digest: Option<&str>,
) -> std::result::Result<(String, String), PublishValidationError> {
    if incoming.min_enforce_rev > incoming.revision {
        return Err(PublishValidationError::InvalidMinEnforceRev);
    }
    let canonical = canonical_policy_json(incoming);
    let digest = compute_policy_digest(incoming);
    if let Some(supplied) = supplied_digest
        && !supplied.eq_ignore_ascii_case(&digest)
    {
        return Err(PublishValidationError::DigestMismatch);
    }

    if let Some((cur_rev, cur_min, cur_digest)) = current {
        if incoming.revision < cur_rev {
            return Err(PublishValidationError::StaleRevision {
                incoming: incoming.revision,
                current: cur_rev,
            });
        }
        if incoming.revision == cur_rev && cur_digest != digest {
            return Err(PublishValidationError::StaleRevision {
                incoming: incoming.revision,
                current: cur_rev,
            });
        }
        if incoming.min_enforce_rev < cur_min {
            return Err(PublishValidationError::NonMonotonicMinEnforceRev {
                incoming: incoming.min_enforce_rev,
                current: cur_min,
            });
        }
    }
    Ok((canonical, digest))
}

// ---------------------------------------------------------------------------
// Durable Object
// ---------------------------------------------------------------------------

#[durable_object]
pub struct SitePolicyDO {
    state: State,
    env: Env,
    schema_ready: Cell<bool>,
}

impl DurableObject for SitePolicyDO {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            schema_ready: Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        match (req.method(), req.path().as_str()) {
            (Method::Get, "/policy") => self.get_policy().await,
            (Method::Post, "/publish") => self.publish(req.json().await?).await,
            _ => Response::error("not found", 404),
        }
    }
}

#[derive(Deserialize)]
struct StoredPolicyRow {
    revision: i64,
    min_enforce_rev: i64,
    digest: String,
    policy_json: String,
}

impl SitePolicyDO {
    fn ensure_schema(&self) -> Result<worker::SqlStorage> {
        let db = self.state.storage().sql();
        if !self.schema_ready.get() {
            db.exec(
                "CREATE TABLE IF NOT EXISTS site_policy_state (\
                    id INTEGER PRIMARY KEY CHECK (id = 1),\
                    revision INTEGER NOT NULL,\
                    min_enforce_rev INTEGER NOT NULL,\
                    digest TEXT NOT NULL,\
                    policy_json TEXT NOT NULL\
                )",
                None,
            )?;
            self.schema_ready.set(true);
        }
        Ok(db)
    }

    fn read_stored(&self) -> Result<Option<StoredPolicyRow>> {
        let db = self.ensure_schema()?;
        let rows: Vec<StoredPolicyRow> = db
            .exec(
                "SELECT revision, min_enforce_rev, digest, policy_json FROM site_policy_state WHERE id = 1",
                None,
            )?
            .to_array()?;
        Ok(rows.into_iter().next())
    }

    fn write_stored(
        &self,
        revision: u32,
        min_enforce_rev: u32,
        digest: &str,
        policy_json: &str,
    ) -> Result<()> {
        let db = self.ensure_schema()?;
        db.exec(
            "INSERT OR REPLACE INTO site_policy_state (id, revision, min_enforce_rev, digest, policy_json) \
             VALUES (1, ?1, ?2, ?3, ?4)",
            vec![
                i64::from(revision).into(),
                i64::from(min_enforce_rev).into(),
                digest.into(),
                policy_json.into(),
            ],
        )?;
        Ok(())
    }

    async fn bootstrap_from_d1(&self) -> Result<(String, String)> {
        #[derive(Deserialize)]
        struct D1Row {
            revision: u32,
            document: String,
        }
        let d1 = self.env.d1(crate::D1_BINDING)?;
        let row: Option<D1Row> = d1
            .prepare("SELECT revision, document FROM site_settings ORDER BY revision DESC LIMIT 1")
            .first(None)
            .await?;

        let policy = match row {
            Some(r) => extract_public_policy_from_document(r.revision, &r.document),
            None => PublicSitePolicy::default(),
        };
        let canonical = canonical_policy_json(&policy);
        let digest = compute_policy_digest(&policy);
        self.write_stored(policy.revision, policy.min_enforce_rev, &digest, &canonical)?;
        Ok((canonical, digest))
    }

    fn envelope_response(canonical_policy_json: &str, digest: &str) -> Result<Response> {
        // Embed canonical policy bytes verbatim inside the envelope JSON.
        let body = format!(
            r#"{{"policy":{canonical_policy_json},"digest":{}}}"#,
            serde_json::to_string(digest)
                .map_err(|e| worker::Error::RustError(e.to_string()))?
        );
        let mut resp = Response::ok(body)?;
        resp.headers_mut()
            .set("content-type", "application/json; charset=utf-8")?;
        resp.headers_mut()
            .set("cache-control", "private, no-store")?;
        resp.headers_mut().set("x-policy-digest", digest)?;
        Ok(resp)
    }

    async fn get_policy(&self) -> Result<Response> {
        let (policy_json, digest) = match self.read_stored()? {
            Some(row) => (row.policy_json, row.digest),
            None => self.bootstrap_from_d1().await?,
        };
        Self::envelope_response(&policy_json, &digest)
    }

    async fn publish(&self, payload: PublishPayload) -> Result<Response> {
        let (mut policy, supplied_digest) = match payload {
            PublishPayload::Envelope { policy, digest } => (policy, digest),
            PublishPayload::Bare(policy) => (policy, None),
        };
        if policy.legal.terms_digest.trim().is_empty() {
            policy.legal.terms_digest = compute_terms_digest(&policy.legal.terms_md);
        }

        let stored = self.read_stored()?;
        let current = stored.as_ref().map(|r| {
            (
                r.revision.max(0) as u32,
                r.min_enforce_rev.max(0) as u32,
                r.digest.as_str(),
            )
        });

        let (canonical, digest) =
            match validate_publish_transition(current, &policy, supplied_digest.as_deref()) {
                Ok(pair) => pair,
                Err(PublishValidationError::DigestMismatch) => {
                    return Response::error("policy digest mismatch", 400);
                }
                Err(PublishValidationError::InvalidMinEnforceRev) => {
                    return Response::error("min_enforce_rev cannot exceed revision", 400);
                }
                Err(PublishValidationError::StaleRevision { .. }) => {
                    return Response::error("stale policy revision", 409);
                }
                Err(PublishValidationError::NonMonotonicMinEnforceRev { .. }) => {
                    return Response::error("min_enforce_rev must be monotonic", 409);
                }
            };

        self.write_stored(policy.revision, policy.min_enforce_rev, &digest, &canonical)?;
        Self::envelope_response(&canonical, &digest)
    }
}

// ---------------------------------------------------------------------------
// Client Helper
// ---------------------------------------------------------------------------

pub async fn load_site_policy(env: &Env) -> Result<SitePolicyEnvelope> {
    let stub = env
        .durable_object(SITE_POLICY_BINDING)?
        .id_from_name(SITE_POLICY_SINGLETON)?
        .get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let req = Request::new_with_init("https://do/policy", &init)?;
    let mut resp = stub.fetch_with_request(req).await?;
    if resp.status_code() != 200 {
        return Err(worker::Error::RustError(format!(
            "SitePolicyDO GET /policy failed: {}",
            resp.status_code()
        )));
    }
    resp.json::<SitePolicyEnvelope>().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use site_access::AuthProviderId;

    #[test]
    fn bootstrap_extracts_allowlist_and_strips_all_secret_fields() {
        let doc = r#"{
            "login_required": true,
            "eth_deposit": "0x2222222222222222222222222222222222222222",
            "safety_enabled": true,
            "min_enforce_rev": 3,
            "age_policy": "self_attestation",
            "enabled_providers": [
                {
                    "id": "google",
                    "enabled": true,
                    "public_client_id": "cid-123",
                    "client_secret": "MUST-NEVER-LEAK",
                    "bot_token": "ALSO-SECRET"
                }
            ],
            "secret_blob": "top-secret"
        }"#;

        let extracted = extract_public_policy_from_document(5, doc);
        assert_eq!(extracted.revision, 5);
        assert_eq!(extracted.min_enforce_rev, 3);
        assert!(extracted.safety_enabled);
        assert_eq!(extracted.age_policy, AgeVerificationPolicy::SelfAttestation);
        assert_eq!(extracted.enabled_providers.len(), 1);
        assert_eq!(extracted.enabled_providers[0].id, AuthProviderId::Google);
        assert_eq!(
            extracted.enabled_providers[0].public_client_id.as_deref(),
            Some("cid-123")
        );

        let serialized = canonical_policy_json(&extracted);
        assert!(!serialized.contains("MUST-NEVER-LEAK"));
        assert!(!serialized.contains("ALSO-SECRET"));
        assert!(!serialized.contains("top-secret"));
        assert!(!serialized.contains("eth_deposit"));
    }

    #[test]
    fn publish_transition_enforces_monotonicity_and_digest() {
        let mut p1 = PublicSitePolicy {
            revision: 2,
            min_enforce_rev: 2,
            safety_enabled: true,
            ..PublicSitePolicy::default()
        };
        let (_, d1) = validate_publish_transition(None, &p1, None).expect("initial publish");

        // Wrong digest rejected
        assert_eq!(
            validate_publish_transition(Some((2, 2, &d1)), &p1, Some("deadbeef")),
            Err(PublishValidationError::DigestMismatch)
        );

        // Idempotent same revision + same digest succeeds
        assert!(validate_publish_transition(Some((2, 2, &d1)), &p1, Some(&d1)).is_ok());

        // Older revision rejected
        p1.revision = 1;
        p1.min_enforce_rev = 1;
        assert!(matches!(
            validate_publish_transition(Some((2, 2, &d1)), &p1, None),
            Err(PublishValidationError::StaleRevision { .. })
        ));

        // Lower min_enforce_rev rejected even on newer revision
        let p2 = PublicSitePolicy {
            revision: 3,
            min_enforce_rev: 1,
            safety_enabled: true,
            ..PublicSitePolicy::default()
        };
        assert!(matches!(
            validate_publish_transition(Some((2, 2, &d1)), &p2, None),
            Err(PublishValidationError::NonMonotonicMinEnforceRev { .. })
        ));
    }
}
