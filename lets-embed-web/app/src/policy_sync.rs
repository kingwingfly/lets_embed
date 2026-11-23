//! Immutable digest-verified policy sync & `ArcSwap` compilation for Managed Mode
//! (and zero-network static holder for Standalone Mode).

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow, bail};
use arc_swap::ArcSwap;
use search_engine::{CompiledPolicy, Engine};
use site_access::{GatewayAssertion, PublicSitePolicy, compute_policy_digest};

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

    /// Managed Mode store: starts uninitialized and MUST fetch, digest-verify, and compile
    /// from `POLICY_URL` before serving any protected request (fails closed on error).
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
    /// request verified with `assertion`, performing a bounded single-flight refresh
    /// whenever uninitialized, stale, or below `assertion.min_enforce_rev` / `assertion.rev`.
    ///
    /// Fails closed (returns `Err`) on any fetch, digest mismatch, out-of-order downgrade,
    /// or Postgres rule compilation failure — NEVER falls back to `CompiledPolicy::disabled()`.
    pub async fn resolve_for_assertion(
        &self,
        assertion: &GatewayAssertion,
        engine: &Engine,
    ) -> anyhow::Result<Arc<CompiledPolicy>> {
        self.resolve_for_assertion_with(assertion, |policy| engine.compile_policy(policy))
            .await
    }

    /// Generic variant accepting a custom compiler closure (used for unit testing
    /// digest checks, single-flight swaps, and fail-closed compilation errors).
    pub async fn resolve_for_assertion_with<F, Fut>(
        &self,
        assertion: &GatewayAssertion,
        compiler: F,
    ) -> anyhow::Result<Arc<CompiledPolicy>>
    where
        F: FnOnce(PublicSitePolicy) -> Fut,
        Fut: Future<Output = anyhow::Result<CompiledPolicy>>,
    {
        let Some(sync) = self.sync.as_ref() else {
            return Ok(self.snapshot.load().compiled.clone());
        };

        if let Some(pinned) = snapshot_satisfies(&self.snapshot.load(), assertion, sync.config.max_staleness) {
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

        // Enforce monotonic min_enforce_rev and exact digest match against the signed gateway assertion.
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
        if computed_digest != assertion.policy_digest {
            bail!(
                "fetched policy digest {} does not match assertion digest {}",
                computed_digest,
                assertion.policy_digest
            );
        }

        let compiled = Arc::new(
            compiler(fetched)
                .await
                .context("failed compiling safety policy rules")?,
        );
        self.snapshot.store(Arc::new(PolicySnapshot {
            initialized: true,
            compiled: compiled.clone(),
            fetched_at: Some(Instant::now()),
        }));
        Ok(compiled)
    }
}

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
    // Never downgrade if we already hold a strictly newer fresh verified revision.
    if rev > assertion.rev {
        return Some(snap.compiled.clone());
    }
    // Same revision must match digest exactly.
    if rev == assertion.rev && snap.compiled.digest == assertion.policy_digest {
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

    let (policy, envelope_digest): (PublicSitePolicy, Option<String>) =
        if let Some(inner) = value.get("policy") {
            let pol: PublicSitePolicy = serde_json::from_value(inner.clone())
                .context("invalid 'policy' object in policy envelope")?;
            let dig = value
                .get("digest")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned);
            (pol, dig)
        } else {
            let pol: PublicSitePolicy = serde_json::from_value(value)
                .context("invalid PublicSitePolicy JSON")?;
            (pol, None)
        };

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
    use site_access::{GATEWAY_ASSERTION_AUDIENCE, GATEWAY_ASSERTION_VERSION};

    fn make_assertion(policy: &PublicSitePolicy) -> GatewayAssertion {
        GatewayAssertion {
            v: GATEWAY_ASSERTION_VERSION,
            aud: GATEWAY_ASSERTION_AUDIENCE.to_string(),
            rev: policy.revision,
            min_enforce_rev: policy.min_enforce_rev,
            policy_digest: compute_policy_digest(policy),
            sub: None,
            sid: None,
            switchers: vec![],
            safe_mode: false,
            is_admin_view: false,
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
        let p1 = PublicSitePolicy {
            revision: 3,
            min_enforce_rev: 2,
            safety_enabled: false,
            ..PublicSitePolicy::default()
        };
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
        bad_assertion.policy_digest = "a".repeat(64);
        assert!(
            store
                .resolve_for_assertion_with(&bad_assertion, |pol| async move {
                    CompiledPolicy::compile_with_resolver(
                        pol,
                        &Default::default(),
                        &Default::default(),
                        &Default::default(),
                    )
                })
                .await
                .is_err()
        );
        assert!(!store.snapshot.load().initialized);

        // 2. Compile failure MUST fail closed (never falling back to disabled).
        let good_assertion = make_assertion(&p1);
        assert!(
            store
                .resolve_for_assertion_with(&good_assertion, |_| async move {
                    Err(anyhow!("simulated db compile error"))
                })
                .await
                .is_err()
        );
        assert!(!store.snapshot.load().initialized);

        // 3. Valid fetch + digest + compile swaps atomically.
        let compiled = store
            .resolve_for_assertion_with(&good_assertion, |pol| async move {
                CompiledPolicy::compile_with_resolver(
                    pol,
                    &Default::default(),
                    &Default::default(),
                    &Default::default(),
                )
            })
            .await
            .expect("valid sync");
        assert_eq!(compiled.policy.revision, 3);
        assert!(store.snapshot.load().initialized);

        // 4. Subsequent request with higher min_enforce_rev against stale mock fails closed!
        let mut tightened = good_assertion.clone();
        tightened.rev = 4;
        tightened.min_enforce_rev = 4;
        assert!(
            store
                .resolve_for_assertion_with(&tightened, |pol| async move {
                    CompiledPolicy::compile_with_resolver(
                        pol,
                        &Default::default(),
                        &Default::default(),
                        &Default::default(),
                    )
                })
                .await
                .is_err()
        );
    }

    #[test]
    fn snapshot_satisfies_enforces_staleness_even_when_rev_exceeds_assertion() {
        let p5 = PublicSitePolicy {
            revision: 5,
            min_enforce_rev: 4,
            ..PublicSitePolicy::default()
        };
        let compiled = Arc::new(
            CompiledPolicy::compile_with_resolver(
                p5.clone(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
            )
            .unwrap(),
        );
        let mut older_assertion = make_assertion(&p5);
        older_assertion.rev = 4;

        let fresh_snap = PolicySnapshot {
            initialized: true,
            compiled: compiled.clone(),
            fetched_at: Some(Instant::now()),
        };
        assert!(snapshot_satisfies(&fresh_snap, &older_assertion, Duration::from_secs(60)).is_some());

        let stale_snap = PolicySnapshot {
            initialized: true,
            compiled,
            fetched_at: Instant::now().checked_sub(Duration::from_secs(120)),
        };
        assert!(snapshot_satisfies(&stale_snap, &older_assertion, Duration::from_secs(60)).is_none());
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
            .resolve_for_assertion_with(&assertion, |pol| async move {
                CompiledPolicy::compile_with_resolver(
                    pol,
                    &Default::default(),
                    &Default::default(),
                    &Default::default(),
                )
            })
            .await
            .expect_err("oversized chunked body must fail closed");
        assert!(err.to_string().contains("exceeds maximum size"), "err: {err}");
    }
}
