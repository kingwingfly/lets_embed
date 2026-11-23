//! Immutable digest-verified Policy v3 sync & `ArcSwap` compilation for Managed Mode
//! (and zero-network static holder for Standalone Mode).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow, bail};
use arc_swap::ArcSwap;
use search_engine::{CompiledPolicy, Engine};
use site_access::{
    GatewayAssertion, PublicSitePolicy, compute_policy_digest, decode_active_policy_v3,
};

/// Maximum acceptable policy payload size returned by `POLICY_URL` (2 MiB).
const MAX_POLICY_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Maximum HTTP timeout for fetching `POLICY_URL`.
const POLICY_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Default staleness window before re-verifying against `POLICY_URL`.
pub const DEFAULT_MAX_POLICY_STALENESS: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub initialized: bool,
    pub compiled: Arc<CompiledPolicy>,
    pub fetched_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct PolicySyncConfig {
    pub policy_url: String,
    pub cf_access_client_id: Option<String>,
    pub cf_access_client_secret: Option<String>,
    pub max_staleness: Duration,
}

#[derive(Debug)]
struct PolicySyncClient {
    config: PolicySyncConfig,
    http: reqwest::Client,
}

#[derive(Debug)]
pub struct PolicyStore {
    snapshot: ArcSwap<PolicySnapshot>,
    sync: Option<PolicySyncClient>,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl PolicyStore {
    /// Standalone Mode store: immediately initialized, zero network calls.
    pub fn standalone(compiled: CompiledPolicy) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(PolicySnapshot {
                initialized: true,
                compiled: Arc::new(compiled),
                fetched_at: Some(Instant::now()),
            }),
            sync: None,
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Managed Mode store: starts uninitialized and MUST fetch, strictly decode (schema v3),
    /// digest-verify, and compile from `POLICY_URL` before serving any protected request
    /// (fails closed on error).
    pub fn managed(config: PolicySyncConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(POLICY_FETCH_TIMEOUT)
            .build()
            .context("failed to build policy HTTP client")?;
        Ok(Self {
            snapshot: ArcSwap::from_pointee(PolicySnapshot {
                initialized: false,
                compiled: Arc::new(CompiledPolicy::disabled()),
                fetched_at: None,
            }),
            sync: Some(PolicySyncClient { config, http }),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Current pinned snapshot in Standalone Mode.
    pub fn current_standalone(&self) -> Arc<CompiledPolicy> {
        self.snapshot.load().compiled.clone()
    }

    /// Pin ONE immutable `Arc<CompiledPolicy>` snapshot for an incoming Managed Mode
    /// request verified with `assertion`, enforcing exact `(rev, digest)` alignment
    /// and performing a bounded single-flight refresh whenever uninitialized, stale,
    /// or mismatched.
    ///
    /// Fails closed (returns `Err`) on any fetch, schema v3 validation, digest mismatch,
    /// revision mismatch, out-of-order downgrade, or compilation failure — NEVER falls
    /// back to `CompiledPolicy::disabled()`.
    pub async fn resolve_for_assertion(
        &self,
        assertion: &GatewayAssertion,
        engine: &Engine,
    ) -> anyhow::Result<Arc<CompiledPolicy>> {
        self.resolve_for_assertion_with(assertion, |policy| engine.compile_policy(policy))
            .await
    }

    /// Generic variant accepting a custom compiler closure (used for unit testing
    /// digest checks, exact revision alignment, single-flight swaps, and fail-closed errors).
    pub async fn resolve_for_assertion_with<F>(
        &self,
        assertion: &GatewayAssertion,
        compiler: F,
    ) -> anyhow::Result<Arc<CompiledPolicy>>
    where
        F: FnOnce(PublicSitePolicy) -> anyhow::Result<CompiledPolicy>,
    {
        let Some(sync) = self.sync.as_ref() else {
            return Ok(self.snapshot.load().compiled.clone());
        };

        if let Some(pinned) =
            snapshot_satisfies(&self.snapshot.load(), assertion, sync.config.max_staleness)
        {
            return Ok(pinned);
        }

        // Single-flight refresh: serialize concurrent refreshes and re-check after acquiring lock.
        let _guard = self.refresh_lock.lock().await;
        let current = self.snapshot.load();
        if let Some(pinned) = snapshot_satisfies(&current, assertion, sync.config.max_staleness) {
            return Ok(pinned);
        }

        let fetched = fetch_policy_from_url(sync).await?;
        let computed_digest = compute_policy_digest(&fetched);

        // Reject out-of-order older revisions relative to any previously verified snapshot.
        if current.initialized && fetched.revision < current.compiled.policy.revision {
            bail!(
                "fetched policy revision {} is older than active revision {}",
                fetched.revision,
                current.compiled.policy.revision
            );
        }

        // Enforce monotonic min_enforce_rev AND exact `(rev, digest)` match against the signed gateway assertion.
        if fetched.revision < assertion.min_enforce_rev {
            bail!(
                "fetched policy revision {} is below assertion min_enforce_rev {}",
                fetched.revision,
                assertion.min_enforce_rev
            );
        }
        if fetched.revision != assertion.rev {
            bail!(
                "fetched policy revision {} does not match assertion revision {}",
                fetched.revision,
                assertion.rev
            );
        }
        if computed_digest != assertion.digest {
            bail!(
                "fetched policy digest {} does not match assertion digest {}",
                computed_digest,
                assertion.digest
            );
        }

        let compiled =
            Arc::new(compiler(fetched).context("failed compiling Policy v3 safety rules")?);
        self.snapshot.store(Arc::new(PolicySnapshot {
            initialized: true,
            compiled: compiled.clone(),
            fetched_at: Some(Instant::now()),
        }));
        Ok(compiled)
    }
}

/// Exact Policy v3 snapshot alignment: NEVER accept a newer or older revision when
/// `assertion.rev` or `assertion.digest` differs from the pinned snapshot.
fn snapshot_satisfies(
    snap: &PolicySnapshot,
    assertion: &GatewayAssertion,
    max_staleness: Duration,
) -> Option<Arc<CompiledPolicy>> {
    if !snap.initialized {
        return None;
    }
    let fresh = snap
        .fetched_at
        .is_some_and(|t| t.elapsed() < max_staleness);
    if !fresh {
        return None;
    }
    let rev = snap.compiled.policy.revision;
    if rev < assertion.min_enforce_rev {
        return None;
    }
    if rev == assertion.rev && snap.compiled.digest == assertion.digest {
        return Some(snap.compiled.clone());
    }
    None
}

async fn fetch_policy_from_url(sync: &PolicySyncClient) -> anyhow::Result<PublicSitePolicy> {
    let mut req = sync
        .http
        .get(&sync.config.policy_url)
        .header("accept", "application/json");
    if let Some(id) = sync.config.cf_access_client_id.as_deref()
        && !id.is_empty()
    {
        req = req.header("CF-Access-Client-Id", id);
    }
    if let Some(sec) = sync.config.cf_access_client_secret.as_deref()
        && !sec.is_empty()
    {
        req = req.header("CF-Access-Client-Secret", sec);
    }

    let mut resp = req.send().await.context("policy upstream request failed")?;
    if resp.status() != reqwest::StatusCode::OK {
        bail!("policy upstream returned HTTP {}", resp.status());
    }

    let header_digest = resp
        .headers()
        .get("x-policy-digest")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    if let Some(len) = resp.content_length()
        && len as usize > MAX_POLICY_BODY_BYTES
    {
        bail!("policy response exceeds maximum size ({len} bytes)");
    }

    // Stream chunks incrementally with a hard MAX_POLICY_BODY_BYTES cap so chunked
    // responses without Content-Length can never cause unbounded memory buffering.
    let mut bytes = Vec::with_capacity(
        resp.content_length()
            .map(|l| (l as usize).min(MAX_POLICY_BODY_BYTES))
            .unwrap_or(4096),
    );
    while let Some(chunk) = resp
        .chunk()
        .await
        .context("failed reading policy response body chunk")?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_POLICY_BODY_BYTES {
            bail!(
                "policy response exceeds maximum size ({MAX_POLICY_BODY_BYTES} bytes)"
            );
        }
        bytes.extend_from_slice(&chunk);
    }

    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("invalid JSON from policy endpoint")?;

    let (policy_json, envelope_digest): (String, Option<String>) =
        if let Some(inner) = value.get("policy") {
            let raw = serde_json::to_string(inner)
                .context("failed serializing 'policy' object from envelope")?;
            let dig = value
                .get("digest")
                .or_else(|| value.get("policy_digest"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned);
            (raw, dig)
        } else {
            let raw = String::from_utf8(bytes).context("policy body is not valid UTF-8")?;
            (raw, None)
        };

    // Strictly enforce Policy v3 schema decoding (rejects missing/non-3 schema_version,
    // legacy "rules" field, internal digest mismatch, or invalid expressions/policies).
    let policy = decode_active_policy_v3(&policy_json)
        .map_err(|e| anyhow!("invalid Policy v3 document from POLICY_URL: {e}"))?;

    let computed = compute_policy_digest(&policy);
    if let Some(expected) = envelope_digest
        && expected != computed
    {
        return Err(anyhow!(
            "policy envelope digest mismatch: declared {expected}, computed {computed}"
        ));
    }
    if let Some(expected) = header_digest
        && expected != computed
    {
        return Err(anyhow!(
            "policy header X-Policy-Digest mismatch: declared {expected}, computed {computed}"
        ));
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use site_access::{ActorBinding, GATEWAY_ASSERTION_AUDIENCE, GATEWAY_ASSERTION_VERSION};

    fn make_v3_policy(revision: u64, min_enforce_rev: u64, safety_enabled: bool) -> PublicSitePolicy {
        let mut p = PublicSitePolicy {
            revision,
            min_enforce_rev,
            safety_enabled,
            ..PublicSitePolicy::default()
        };
        p.refresh_policy_digest();
        p
    }

    fn make_assertion(policy: &PublicSitePolicy) -> GatewayAssertion {
        GatewayAssertion {
            v: GATEWAY_ASSERTION_VERSION,
            aud: GATEWAY_ASSERTION_AUDIENCE.to_string(),
            actor: ActorBinding::Anon,
            rev: policy.revision,
            min_enforce_rev: policy.min_enforce_rev,
            digest: compute_policy_digest(policy),
            direct_grants: vec![],
            click_eligible: vec![],
            is_billing_waived: false,
            caller_age_verified: false,
            caller_terms_accepted: false,
            exp: 2_000_000_000,
        }
    }

    async fn spawn_policy_mock(body: String) -> String {
        let app = Router::new().route(
            "/policy",
            get(move || {
                let body = body.clone();
                async move { ([("content-type", "application/json")], body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}/policy")
    }

    #[tokio::test]
    async fn managed_policy_sync_verifies_digest_and_fails_closed_on_mismatch_or_compile_error() {
        let p1 = make_v3_policy(3, 2, false);
        let envelope = serde_json::json!({
            "policy": p1,
            "digest": compute_policy_digest(&p1),
        })
        .to_string();
        let url = spawn_policy_mock(envelope).await;

        let store = PolicyStore::managed(PolicySyncConfig {
            policy_url: url,
            cf_access_client_id: None,
            cf_access_client_secret: None,
            max_staleness: Duration::from_secs(60),
        })
        .unwrap();

        // 1. Mismatched assertion digest MUST fail closed (and leave store uninitialized).
        let mut bad_assertion = make_assertion(&p1);
        bad_assertion.digest = "a".repeat(64);
        assert!(
            store
                .resolve_for_assertion_with(&bad_assertion, CompiledPolicy::compile)
                .await
                .is_err()
        );
        assert!(!store.snapshot.load().initialized);

        // 2. Compile failure MUST fail closed (never falling back to disabled).
        let good_assertion = make_assertion(&p1);
        assert!(
            store
                .resolve_for_assertion_with(&good_assertion, |_| {
                    Err(anyhow!("simulated compile error"))
                })
                .await
                .is_err()
        );
        assert!(!store.snapshot.load().initialized);

        // 3. Valid fetch + digest + compile swaps atomically.
        let compiled = store
            .resolve_for_assertion_with(&good_assertion, CompiledPolicy::compile)
            .await
            .expect("valid sync");
        assert_eq!(compiled.policy.revision, 3);
        assert!(store.snapshot.load().initialized);

        // 4. Subsequent request with different revision against stale mock fails closed!
        let mut tightened = good_assertion.clone();
        tightened.rev = 4;
        tightened.min_enforce_rev = 4;
        assert!(
            store
                .resolve_for_assertion_with(&tightened, CompiledPolicy::compile)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn managed_policy_sync_rejects_pre_v3_schema_and_legacy_rules_field() {
        let legacy_json = serde_json::json!({
            "schema_version": 2,
            "revision": 1,
            "min_enforce_rev": 1,
            "safety_enabled": false,
            "rules": []
        })
        .to_string();
        let url = spawn_policy_mock(legacy_json).await;

        let store = PolicyStore::managed(PolicySyncConfig {
            policy_url: url,
            cf_access_client_id: None,
            cf_access_client_secret: None,
            max_staleness: Duration::from_secs(60),
        })
        .unwrap();

        let p = make_v3_policy(1, 1, false);
        let assertion = make_assertion(&p);
        let err = store
            .resolve_for_assertion_with(&assertion, CompiledPolicy::compile)
            .await
            .expect_err("schema_version 2 must be rejected strictly");
        assert!(
            err.to_string().contains("Policy v3"),
            "unexpected err: {err}"
        );
    }

    #[test]
    fn snapshot_satisfies_requires_exact_revision_and_digest_and_freshness() {
        let p5 = make_v3_policy(5, 4, false);
        let compiled = Arc::new(CompiledPolicy::compile(p5.clone()).unwrap());

        let exact_assertion = make_assertion(&p5);
        let mut older_assertion = make_assertion(&p5);
        older_assertion.rev = 4;
        let mut wrong_digest_assertion = make_assertion(&p5);
        wrong_digest_assertion.digest = "b".repeat(64);

        let fresh_snap = PolicySnapshot {
            initialized: true,
            compiled: compiled.clone(),
            fetched_at: Some(Instant::now()),
        };
        // Exact match succeeds when fresh.
        assert!(
            snapshot_satisfies(&fresh_snap, &exact_assertion, Duration::from_secs(60)).is_some()
        );
        // Policy v3 NEVER accepts revision skew (rev 5 snapshot MUST NOT satisfy rev 4 assertion).
        assert!(
            snapshot_satisfies(&fresh_snap, &older_assertion, Duration::from_secs(60)).is_none()
        );
        // Digest mismatch rejected even when revision matches.
        assert!(
            snapshot_satisfies(&fresh_snap, &wrong_digest_assertion, Duration::from_secs(60))
                .is_none()
        );

        let stale_snap = PolicySnapshot {
            initialized: true,
            compiled,
            fetched_at: Instant::now().checked_sub(Duration::from_secs(120)),
        };
        assert!(
            snapshot_satisfies(&stale_snap, &exact_assertion, Duration::from_secs(60)).is_none()
        );
    }

    #[tokio::test]
    async fn chunked_oversized_policy_body_fails_closed_incrementally() {
        use axum::body::Body;
        use futures::stream;

        let app = Router::new().route(
            "/big-policy",
            get(|| async {
                // Stream >2 MiB without setting Content-Length (chunked transfer encoding).
                let chunk = vec![b' '; 256 * 1024];
                let chunks = (0..10).map(move |_| Ok::<_, std::io::Error>(chunk.clone()));
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from_stream(stream::iter(chunks)))
                    .unwrap()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let store = PolicyStore::managed(PolicySyncConfig {
            policy_url: format!("http://{addr}/big-policy"),
            cf_access_client_id: None,
            cf_access_client_secret: None,
            max_staleness: Duration::from_secs(60),
        })
        .unwrap();

        let p = PublicSitePolicy::default();
        let assertion = make_assertion(&p);
        let err = store
            .resolve_for_assertion_with(&assertion, CompiledPolicy::compile)
            .await
            .expect_err("oversized chunked body must fail closed");
        assert!(err.to_string().contains("exceeds maximum size"), "err: {err}");
    }
}
