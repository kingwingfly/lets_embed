//! Authoritative singleton `SitePolicyDO` for Policy v3.
//!
//! Singleton instance `"global"` stores the active Policy v3 [`PublicSitePolicy`],
//! deterministic SHA-256 `policy_digest`, and monotonic `min_enforce_rev`.
//!
//! Security invariants (Policy v3):
//! - Strict schema v3 decoding via [`site_access::decode_active_policy_v3`] on
//!   every read, D1 bootstrap, and activation request.
//! - Disabled bootstrap (`PublicSitePolicy::fresh_bootstrap()`) is permitted ONLY
//!   for a known fresh installation (no stored DO row AND D1 has no active row
//!   with `revision > 0`). Malformed active policies, unsupported schemas,
//!   legacy `"rules"` payloads, digest mismatches, and D1 failures ALWAYS fail
//!   closed!
//! - Two-phase activation endpoints (`POST /internal/policy/activate`,
//!   `POST /internal/policy/refresh`, `POST /publish`, `POST /activate`,
//!   `POST /refresh`) validate and persist idempotently and return an explicit
//!   `{ "ok": true, "revision": u64, "policy_digest": String, "digest": String, "policy": ... }`
//!   ACK so `admin_dashboard_worker` can verify exact `(revision, policy_digest)`
//!   activation before marking D1 `activation_status = 'active'`.

use std::cell::Cell;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use site_access::{
    PolicyValidationError, PublicSitePolicy, canonical_policy_json, compute_policy_digest,
    decode_active_policy_v3, validate_policy_set_with_mode,
};
use worker::{
    DurableObject, Env, Method, Request, RequestInit, Response, Result, State, durable_object,
};

pub const SITE_POLICY_BINDING: &str = "SITE_POLICY";
pub const SITE_POLICY_SINGLETON: &str = "global";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SitePolicyEnvelope {
    pub policy: PublicSitePolicy,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SitePolicyActivationAck {
    pub ok: bool,
    pub revision: u64,
    pub policy_digest: String,
    pub digest: String,
    pub policy: PublicSitePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyLoadError {
    MalformedJson(String),
    Validation(PolicyValidationError),
    RevisionMismatch { expected: u64, actual: u64 },
    DigestMismatch,
}

impl fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedJson(msg) => write!(f, "malformed policy JSON: {msg}"),
            Self::Validation(e) => write!(f, "strict v3 policy validation failed: {e}"),
            Self::RevisionMismatch { expected, actual } => {
                write!(f, "policy revision mismatch (row={expected}, doc={actual})")
            }
            Self::DigestMismatch => write!(f, "stored policy digest mismatch"),
        }
    }
}

impl std::error::Error for PolicyLoadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishValidationError {
    MalformedJson(String),
    Validation(PolicyValidationError),
    DigestMismatch,
    StaleRevision { incoming: u64, current: u64 },
    NonMonotonicMinEnforceRev { incoming: u64, current: u64 },
    InvalidMinEnforceRev,
}

impl fmt::Display for PublishValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedJson(msg) => write!(f, "malformed activation payload: {msg}"),
            Self::Validation(e) => write!(f, "invalid Policy v3: {e}"),
            Self::DigestMismatch => write!(f, "policy_digest mismatch"),
            Self::StaleRevision { incoming, current } => {
                write!(f, "stale policy revision {incoming} (current {current})")
            }
            Self::NonMonotonicMinEnforceRev { incoming, current } => {
                write!(
                    f,
                    "min_enforce_rev {incoming} cannot decrease below {current}"
                )
            }
            Self::InvalidMinEnforceRev => write!(f, "min_enforce_rev cannot exceed revision"),
        }
    }
}

impl std::error::Error for PublishValidationError {}

// ---------------------------------------------------------------------------
// Strict Policy v3 Decoding & Validation (host-testable)
// ---------------------------------------------------------------------------

/// Strictly decode a persisted DO SQLite row as Policy v3, verifying revision,
/// `min_enforce_rev`, and `policy_digest` integrity. Fails closed on any mismatch.
pub fn decode_stored_policy_strict(
    stored_rev: u64,
    stored_min_enforce_rev: u64,
    stored_digest: &str,
    raw_json: &str,
) -> std::result::Result<PublicSitePolicy, PolicyLoadError> {
    let policy = decode_active_policy_v3(raw_json).map_err(PolicyLoadError::Validation)?;
    if policy.revision != stored_rev {
        return Err(PolicyLoadError::RevisionMismatch {
            expected: stored_rev,
            actual: policy.revision,
        });
    }
    if policy.min_enforce_rev != stored_min_enforce_rev {
        return Err(PolicyLoadError::Validation(
            PolicyValidationError::InvalidField(format!(
                "stored min_enforce_rev mismatch (row={stored_min_enforce_rev}, doc={})",
                policy.min_enforce_rev
            )),
        ));
    }
    if !policy.verify_policy_digest() || !policy.policy_digest.eq_ignore_ascii_case(stored_digest) {
        return Err(PolicyLoadError::DigestMismatch);
    }
    Ok(policy)
}

/// Strictly decode a D1 `site_settings` row during cold-start bootstrap or refresh.
///
/// Bootstraps a disabled v3 policy (`PublicSitePolicy::fresh_bootstrap()`) ONLY
/// for a known fresh installation:
/// - `row == None` (no active row in D1), OR
/// - `row == Some((0, doc))` where `doc` is a valid JSON object containing no
///   safety/policy keys (e.g. `0002_site_settings.sql` seed `'{}'` or initial
///   pricing-only rev 0).
///
/// Any row with `revision > 0`, any malformed JSON, any legacy `"rules"` /
/// non-v3 `schema_version`, or any digest/revision mismatch ALWAYS fails closed!
pub fn decode_d1_policy_row_strict(
    row: Option<(u64, &str)>,
) -> std::result::Result<PublicSitePolicy, PolicyLoadError> {
    let Some((revision, document)) = row else {
        return Ok(PublicSitePolicy::fresh_bootstrap());
    };

    let raw: Value = serde_json::from_str(document)
        .map_err(|e| PolicyLoadError::MalformedJson(e.to_string()))?;
    let obj = raw
        .as_object()
        .ok_or_else(|| PolicyLoadError::MalformedJson("site_settings.document must be a JSON object".into()))?;

    if revision == 0 {
        let has_policy_fields = obj.contains_key("public_policy")
            || obj.contains_key("schema_version")
            || obj.contains_key("rules")
            || obj.contains_key("policies")
            || obj.contains_key("safety_enabled");
        if !has_policy_fields {
            return Ok(PublicSitePolicy::fresh_bootstrap());
        }
    }

    let policy_val = match obj.get("public_policy") {
        Some(sub) if sub.is_object() => sub,
        Some(_) => {
            return Err(PolicyLoadError::MalformedJson(
                "public_policy field must be a JSON object".into(),
            ));
        }
        None => &raw,
    };

    let policy_json = serde_json::to_string(policy_val)
        .map_err(|e| PolicyLoadError::MalformedJson(e.to_string()))?;
    let policy = decode_active_policy_v3(&policy_json).map_err(PolicyLoadError::Validation)?;
    if policy.revision != revision {
        return Err(PolicyLoadError::RevisionMismatch {
            expected: revision,
            actual: policy.revision,
        });
    }
    if !policy.verify_policy_digest() {
        return Err(PolicyLoadError::DigestMismatch);
    }
    Ok(policy)
}

/// Strictly decode an activation / publish request body (`{ "policy": ..., "policy_digest"?: ..., "digest"?: ... }`
/// or bare `PublicSitePolicy` JSON) using [`decode_active_policy_v3`].
pub fn decode_activation_payload(
    raw_body: &str,
) -> std::result::Result<(PublicSitePolicy, Option<String>), PublishValidationError> {
    let root: Value = serde_json::from_str(raw_body)
        .map_err(|e| PublishValidationError::MalformedJson(e.to_string()))?;
    let obj = root
        .as_object()
        .ok_or_else(|| PublishValidationError::MalformedJson("payload must be a JSON object".into()))?;

    let (policy_val, supplied_digest) = if let Some(inner) = obj.get("policy") {
        if !inner.is_object() {
            return Err(PublishValidationError::MalformedJson(
                "'policy' field must be a JSON object".into(),
            ));
        }
        let pd = obj
            .get("policy_digest")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let d = obj
            .get("digest")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let (Some(a), Some(b)) = (pd, d)
            && !a.eq_ignore_ascii_case(b)
        {
            return Err(PublishValidationError::DigestMismatch);
        }
        (inner, pd.or(d).map(str::to_string))
    } else {
        (&root, None)
    };

    let policy_str = serde_json::to_string(policy_val)
        .map_err(|e| PublishValidationError::MalformedJson(e.to_string()))?;
    let policy =
        decode_active_policy_v3(&policy_str).map_err(PublishValidationError::Validation)?;
    if !policy.verify_policy_digest() {
        return Err(PublishValidationError::DigestMismatch);
    }
    if let Some(ref supplied) = supplied_digest
        && !supplied.eq_ignore_ascii_case(&policy.policy_digest)
    {
        return Err(PublishValidationError::DigestMismatch);
    }
    Ok((policy, supplied_digest))
}

/// Pure validation for `SitePolicyDO` publish / activation transitions.
///
/// Validates Policy v3 invariants, digest integrity, monotonic `revision`
/// (allowing idempotent re-activation of the exact same `(revision, digest)`),
/// and monotonic `min_enforce_rev`.
pub fn validate_publish_transition(
    current: Option<(u64, u64, &str)>,
    incoming: &PublicSitePolicy,
    supplied_digest: Option<&str>,
) -> std::result::Result<(String, String), PublishValidationError> {
    if incoming.min_enforce_rev > incoming.revision {
        return Err(PublishValidationError::InvalidMinEnforceRev);
    }
    validate_policy_set_with_mode(incoming, false).map_err(PublishValidationError::Validation)?;
    if !incoming.verify_policy_digest() {
        return Err(PublishValidationError::DigestMismatch);
    }

    let canonical = canonical_policy_json(incoming);
    let digest = compute_policy_digest(incoming);
    if !incoming.policy_digest.eq_ignore_ascii_case(&digest) {
        return Err(PublishValidationError::DigestMismatch);
    }
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
        if incoming.revision == cur_rev && !cur_digest.eq_ignore_ascii_case(&digest) {
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

/// Builds the canonical activation ACK JSON body containing BOTH two-phase ACK
/// fields (`ok`, `revision`, `policy_digest`) AND `SitePolicyEnvelope` fields
/// (`policy`, `digest`).
pub fn format_activation_ack_json(revision: u64, digest: &str, canonical_policy_json: &str) -> String {
    let digest_json = serde_json::to_string(digest).expect("digest string serializes");
    format!(
        r#"{{"ok":true,"revision":{revision},"policy_digest":{digest_json},"digest":{digest_json},"policy":{canonical_policy_json}}}"#
    )
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
            (Method::Post, "/publish" | "/activate" | "/internal/policy/activate") => {
                let raw = req.text().await?;
                self.activate_from_body(&raw).await
            }
            (Method::Post, "/refresh" | "/internal/policy/refresh") => {
                let raw = req.text().await.unwrap_or_default();
                self.refresh(&raw).await
            }
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

#[derive(Deserialize)]
struct D1PolicyRow {
    revision: i64,
    document: String,
}

#[derive(Deserialize)]
struct RefreshHint {
    #[serde(default)]
    revision: Option<u64>,
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
        revision: u64,
        min_enforce_rev: u64,
        digest: &str,
        policy_json: &str,
    ) -> Result<()> {
        let db = self.ensure_schema()?;
        let rev_i64 = i64::try_from(revision)
            .map_err(|_| worker::Error::RustError("revision overflows i64".into()))?;
        let min_i64 = i64::try_from(min_enforce_rev)
            .map_err(|_| worker::Error::RustError("min_enforce_rev overflows i64".into()))?;
        db.exec(
            "INSERT OR REPLACE INTO site_policy_state (id, revision, min_enforce_rev, digest, policy_json) \
             VALUES (1, ?1, ?2, ?3, ?4)",
            vec![rev_i64.into(), min_i64.into(), digest.into(), policy_json.into()],
        )?;
        Ok(())
    }

    async fn bootstrap_from_d1(&self) -> std::result::Result<(String, String), Response> {
        let d1 = self.env.d1(crate::D1_BINDING).map_err(|e| {
            worker::console_error!("SitePolicyDO D1 binding failed: {e:?}");
            Response::error("site policy storage unavailable", 503).expect("503 response")
        })?;
        let row: Option<D1PolicyRow> = d1
            .prepare(
                "SELECT revision, document FROM site_settings \
                 WHERE activation_status = 'active' \
                 ORDER BY revision DESC LIMIT 1",
            )
            .first(None)
            .await
            .map_err(|e| {
                worker::console_error!("SitePolicyDO D1 bootstrap query failed: {e:?}");
                Response::error("site policy D1 read failed", 503).expect("503 response")
            })?;

        let pair = match &row {
            Some(r) if r.revision >= 0 => Some((r.revision as u64, r.document.as_str())),
            Some(_) => {
                worker::console_error!("SitePolicyDO D1 row has negative revision");
                return Err(
                    Response::error("malformed site policy revision", 503).expect("503 response")
                );
            }
            None => None,
        };

        let policy = decode_d1_policy_row_strict(pair).map_err(|e| {
            worker::console_error!("SitePolicyDO strict v3 D1 bootstrap rejected: {e}");
            Response::error(format!("site policy fail-closed: {e}"), 503).expect("503 response")
        })?;

        let canonical = canonical_policy_json(&policy);
        let digest = policy.policy_digest.clone();
        self.write_stored(policy.revision, policy.min_enforce_rev, &digest, &canonical)
            .map_err(|e| {
                worker::console_error!("SitePolicyDO SQLite persist failed: {e:?}");
                Response::error("site policy persistence failed", 503).expect("503 response")
            })?;
        Ok((canonical, digest))
    }

    fn envelope_response(canonical_policy_json: &str, digest: &str) -> Result<Response> {
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

    fn activation_ack_response(
        revision: u64,
        digest: &str,
        canonical_policy_json: &str,
    ) -> Result<Response> {
        let body = format_activation_ack_json(revision, digest, canonical_policy_json);
        let mut resp = Response::ok(body)?;
        resp.headers_mut()
            .set("content-type", "application/json; charset=utf-8")?;
        resp.headers_mut()
            .set("cache-control", "private, no-store")?;
        resp.headers_mut().set("x-policy-digest", digest)?;
        Ok(resp)
    }

    async fn get_policy(&self) -> Result<Response> {
        match self.read_stored()? {
            Some(row) => {
                if row.revision < 0 || row.min_enforce_rev < 0 {
                    worker::console_error!("SitePolicyDO stored row has negative revision");
                    return Response::error("corrupt stored site policy", 503);
                }
                match decode_stored_policy_strict(
                    row.revision as u64,
                    row.min_enforce_rev as u64,
                    &row.digest,
                    &row.policy_json,
                ) {
                    Ok(policy) => {
                        let canonical = canonical_policy_json(&policy);
                        Self::envelope_response(&canonical, &policy.policy_digest)
                    }
                    Err(e) => {
                        worker::console_error!(
                            "SitePolicyDO stored policy failed strict v3 decode: {e}"
                        );
                        Response::error(format!("site policy fail-closed: {e}"), 503)
                    }
                }
            }
            None => match self.bootstrap_from_d1().await {
                Ok((policy_json, digest)) => Self::envelope_response(&policy_json, &digest),
                Err(fail_closed_resp) => Ok(fail_closed_resp),
            },
        }
    }

    fn apply_validated_policy(
        &self,
        policy: &PublicSitePolicy,
        supplied_digest: Option<&str>,
    ) -> Result<Response> {
        let stored = self.read_stored()?;
        let current = stored.as_ref().map(|r| {
            (
                r.revision.max(0) as u64,
                r.min_enforce_rev.max(0) as u64,
                r.digest.as_str(),
            )
        });

        let (canonical, digest) =
            match validate_publish_transition(current, policy, supplied_digest) {
                Ok(pair) => pair,
                Err(
                    e @ (PublishValidationError::MalformedJson(_)
                    | PublishValidationError::Validation(_)
                    | PublishValidationError::DigestMismatch
                    | PublishValidationError::InvalidMinEnforceRev),
                ) => {
                    return Response::error(e.to_string(), 400);
                }
                Err(
                    e @ (PublishValidationError::StaleRevision { .. }
                    | PublishValidationError::NonMonotonicMinEnforceRev { .. }),
                ) => {
                    return Response::error(e.to_string(), 409);
                }
            };

        self.write_stored(policy.revision, policy.min_enforce_rev, &digest, &canonical)?;
        Self::activation_ack_response(policy.revision, &digest, &canonical)
    }

    async fn activate_from_body(&self, raw_body: &str) -> Result<Response> {
        let (policy, supplied_digest) = match decode_activation_payload(raw_body) {
            Ok(pair) => pair,
            Err(e) => return Response::error(e.to_string(), 400),
        };
        self.apply_validated_policy(&policy, supplied_digest.as_deref())
    }

    async fn refresh(&self, raw_body: &str) -> Result<Response> {
        let trimmed = raw_body.trim();
        if !trimmed.is_empty()
            && let Ok(val) = serde_json::from_str::<Value>(trimmed)
            && val.as_object().is_some_and(|obj| {
                obj.contains_key("policy") || obj.contains_key("schema_version")
            })
        {
            return self.activate_from_body(trimmed).await;
        }

        let target_rev = if trimmed.is_empty() {
            None
        } else {
            serde_json::from_str::<RefreshHint>(trimmed)
                .ok()
                .and_then(|h| h.revision)
        };

        let d1 = match self.env.d1(crate::D1_BINDING) {
            Ok(db) => db,
            Err(e) => {
                worker::console_error!("SitePolicyDO refresh D1 binding failed: {e:?}");
                return Response::error("site policy storage unavailable", 503);
            }
        };

        let row: Option<D1PolicyRow> = match target_rev {
            Some(rev) => match d1
                .prepare("SELECT revision, document FROM site_settings WHERE revision = ?1")
                .bind(&[(rev as f64).into()])
            {
                Ok(stmt) => match stmt.first(None).await {
                    Ok(r) => r,
                    Err(e) => {
                        worker::console_error!("SitePolicyDO refresh D1 query failed: {e:?}");
                        return Response::error("site policy D1 read failed", 503);
                    }
                },
                Err(e) => {
                    worker::console_error!("SitePolicyDO refresh D1 bind failed: {e:?}");
                    return Response::error("site policy D1 bind failed", 503);
                }
            },
            None => match d1
                .prepare(
                    "SELECT revision, document FROM site_settings \
                     WHERE activation_status IN ('pending_do_ack', 'active') \
                     ORDER BY revision DESC LIMIT 1",
                )
                .first(None)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    worker::console_error!("SitePolicyDO refresh D1 query failed: {e:?}");
                    return Response::error("site policy D1 read failed", 503);
                }
            },
        };

        if target_rev.is_some() && row.is_none() {
            return Response::error("requested policy revision not found in D1", 404);
        }

        let pair = match &row {
            Some(r) if r.revision >= 0 => Some((r.revision as u64, r.document.as_str())),
            Some(_) => return Response::error("corrupt policy revision in D1", 503),
            None => None,
        };

        let policy = match decode_d1_policy_row_strict(pair) {
            Ok(p) => p,
            Err(e) => {
                worker::console_error!("SitePolicyDO refresh strict v3 decode failed: {e}");
                return Response::error(format!("site policy fail-closed: {e}"), 400);
            }
        };

        self.apply_validated_policy(&policy, None)
    }
}

// ---------------------------------------------------------------------------
// Client Helpers
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
    let text = resp.text().await?;
    let val: Value =
        serde_json::from_str(&text).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let policy_val = val
        .get("policy")
        .ok_or_else(|| worker::Error::RustError("SitePolicyDO envelope missing policy".into()))?;
    let digest = val
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| worker::Error::RustError("SitePolicyDO envelope missing digest".into()))?
        .to_string();
    let policy_json =
        serde_json::to_string(policy_val).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let policy = decode_active_policy_v3(&policy_json)
        .map_err(|e| worker::Error::RustError(format!("strict v3 policy decode failed: {e}")))?;
    if !policy.verify_policy_digest() || !policy.policy_digest.eq_ignore_ascii_case(&digest) {
        return Err(worker::Error::RustError(
            "SitePolicyDO envelope digest mismatch".into(),
        ));
    }
    Ok(SitePolicyEnvelope { policy, digest })
}

/// Forward a raw JSON activation/refresh request directly to singleton `SitePolicyDO`.
pub async fn forward_policy_activation(
    env: &Env,
    do_path: &str,
    raw_body: String,
) -> Result<(u16, String)> {
    let stub = env
        .durable_object(SITE_POLICY_BINDING)?
        .id_from_name(SITE_POLICY_SINGLETON)?
        .get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.headers.set("content-type", "application/json")?;
    init.with_body(Some(raw_body.into()));
    let req = Request::new_with_init(&format!("https://do{do_path}"), &init)?;
    let mut resp = stub.fetch_with_request(req).await?;
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use site_access::{AgeVerificationPolicy, builtin_safety_presets};

    fn sample_v3_policy(revision: u64, min_enforce_rev: u64) -> PublicSitePolicy {
        let mut policy = PublicSitePolicy {
            revision,
            min_enforce_rev,
            safety_enabled: true,
            fixed_blur_enabled: true,
            policies: builtin_safety_presets(),
            age_policy: AgeVerificationPolicy::SelfAttestation,
            ..PublicSitePolicy::fresh_bootstrap()
        };
        policy.refresh_policy_digest();
        policy
    }

    #[test]
    fn fresh_bootstrap_allowed_only_for_empty_or_rev0_non_policy_d1_rows() {
        // No row -> disabled v3 bootstrap
        let boot_none = decode_d1_policy_row_strict(None).expect("empty D1 bootstraps v3");
        assert_eq!(boot_none.schema_version, 3);
        assert_eq!(boot_none.revision, 0);
        assert!(!boot_none.safety_enabled);
        assert!(boot_none.verify_policy_digest());

        // Seed row `(0, '{}')` -> disabled v3 bootstrap
        let boot_seed =
            decode_d1_policy_row_strict(Some((0, "{}"))).expect("rev 0 seed bootstraps v3");
        assert_eq!(boot_seed.schema_version, 3);
        assert_eq!(boot_seed.revision, 0);
        assert!(!boot_seed.safety_enabled);

        // Rev 0 with pricing-only fields -> disabled v3 bootstrap
        let boot_pricing = decode_d1_policy_row_strict(Some((
            0,
            r#"{"login_required":true,"signup_points":3000}"#,
        )))
        .expect("pricing-only rev 0 bootstraps v3");
        assert_eq!(boot_pricing.revision, 0);
        assert!(!boot_pricing.safety_enabled);

        // Rev 0 with malformed JSON MUST fail closed!
        assert!(decode_d1_policy_row_strict(Some((0, "{broken"))).is_err());

        // Rev 0 containing legacy v2 "rules" MUST fail closed!
        assert!(
            decode_d1_policy_row_strict(Some((0, r#"{"safety_enabled":false,"rules":[]}"#)))
                .is_err()
        );
    }

    #[test]
    fn active_d1_rows_require_strict_v3_and_fail_closed_on_v2_or_tamper() {
        let p = sample_v3_policy(5, 3);
        let wrapped = serde_json::json!({
            "login_required": true,
            "eth_deposit": "0x2222222222222222222222222222222222222222",
            "public_policy": p,
        })
        .to_string();

        let decoded = decode_d1_policy_row_strict(Some((5, &wrapped))).expect("valid v3 row");
        assert_eq!(decoded, p);

        // Revision mismatch between D1 column and policy document fails closed!
        assert!(matches!(
            decode_d1_policy_row_strict(Some((6, &wrapped))),
            Err(PolicyLoadError::RevisionMismatch {
                expected: 6,
                actual: 5
            })
        ));

        // Legacy v2 row (missing schema_version / containing "rules") fails closed!
        let legacy_v2 = r#"{"revision":2,"safety_enabled":true,"rules":[]}"#;
        assert!(matches!(
            decode_d1_policy_row_strict(Some((2, legacy_v2))),
            Err(PolicyLoadError::Validation(
                PolicyValidationError::UnsupportedSchemaVersion(None)
            ))
        ));

        // Wrong schema_version (v2) fails closed!
        let wrong_ver = r#"{"schema_version":2,"revision":2,"safety_enabled":true}"#;
        assert!(matches!(
            decode_d1_policy_row_strict(Some((2, wrong_ver))),
            Err(PolicyLoadError::Validation(
                PolicyValidationError::UnsupportedSchemaVersion(Some(2))
            ))
        ));

        // Digest mismatch fails closed!
        let mut tampered = p.clone();
        tampered.policy_digest = "0".repeat(64);
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        assert!(matches!(
            decode_d1_policy_row_strict(Some((5, &tampered_json))),
            Err(PolicyLoadError::Validation(
                PolicyValidationError::DigestMismatch
            ))
        ));
    }

    #[test]
    fn stored_do_row_strict_decode_rejects_v2_and_digest_mismatch() {
        let p = sample_v3_policy(4, 2);
        let canonical = canonical_policy_json(&p);
        assert_eq!(
            decode_stored_policy_strict(4, 2, &p.policy_digest, &canonical).unwrap(),
            p
        );
        assert!(decode_stored_policy_strict(4, 2, &"a".repeat(64), &canonical).is_err());
        assert!(decode_stored_policy_strict(5, 2, &p.policy_digest, &canonical).is_err());
        assert!(decode_stored_policy_strict(4, 1, &p.policy_digest, &canonical).is_err());
        assert!(
            decode_stored_policy_strict(
                4,
                2,
                &p.policy_digest,
                r#"{"revision":4,"rules":[]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn activation_payload_decode_monotonic_transition_and_ack_json() {
        let p1 = sample_v3_policy(2, 2);
        let body = serde_json::json!({
            "policy": p1,
            "policy_digest": p1.policy_digest,
        })
        .to_string();

        let (decoded, supplied) = decode_activation_payload(&body).expect("valid activation");
        assert_eq!(decoded, p1);
        assert_eq!(supplied.as_deref(), Some(p1.policy_digest.as_str()));

        let (canonical, digest) =
            validate_publish_transition(None, &decoded, supplied.as_deref())
                .expect("initial activate");
        assert_eq!(digest, p1.policy_digest);

        // ACK JSON carries exact `{ ok: true, revision, policy_digest }` AND envelope fields
        let ack_json = format_activation_ack_json(decoded.revision, &digest, &canonical);
        let ack: SitePolicyActivationAck = serde_json::from_str(&ack_json).expect("decode ack");
        assert!(ack.ok);
        assert_eq!(ack.revision, 2);
        assert_eq!(ack.policy_digest, digest);
        assert_eq!(ack.digest, digest);
        assert_eq!(ack.policy, p1);

        // Idempotent retry of same (rev, digest) succeeds!
        assert!(
            validate_publish_transition(Some((2, 2, &digest)), &p1, Some(&digest)).is_ok()
        );

        // Wrong digest rejected
        assert_eq!(
            validate_publish_transition(Some((2, 2, &digest)), &p1, Some(&"f".repeat(64))),
            Err(PublishValidationError::DigestMismatch)
        );

        // Older revision rejected (409)
        let p_old = sample_v3_policy(1, 1);
        assert!(matches!(
            validate_publish_transition(Some((2, 2, &digest)), &p_old, None),
            Err(PublishValidationError::StaleRevision {
                incoming: 1,
                current: 2
            })
        ));

        // Same revision with different digest rejected (409)
        let mut p_same_rev_diff = p1.clone();
        p_same_rev_diff.fixed_blur_enabled = false;
        p_same_rev_diff.refresh_policy_digest();
        assert!(matches!(
            validate_publish_transition(Some((2, 2, &digest)), &p_same_rev_diff, None),
            Err(PublishValidationError::StaleRevision {
                incoming: 2,
                current: 2
            })
        ));

        // Non-monotonic min_enforce_rev rejected (409)
        let p_lower_min = sample_v3_policy(3, 1);
        assert!(matches!(
            validate_publish_transition(Some((2, 2, &digest)), &p_lower_min, None),
            Err(PublishValidationError::NonMonotonicMinEnforceRev {
                incoming: 1,
                current: 2
            })
        ));

        // Legacy v2 payload rejected at decode_activation_payload
        let v2_body = r#"{"policy":{"revision":3,"safety_enabled":true,"rules":[]}}"#;
        assert!(decode_activation_payload(v2_body).is_err());
    }
}
