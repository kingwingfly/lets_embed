//! Atomic single-use challenge Durable Object (`AuthChallengeDO` — fixes H12).
//!
//! Eliminates eventually-consistent KV `get` + `delete` races by performing all
//! single-use nonce, OAuth/OIDC transaction, Email OTP/Magic-Link, Telegram
//! replay guard, content report rate-limit, and bounded JWKS cache operations
//! inside synchronous single-threaded DO SQLite storage.

use std::cell::Cell;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use worker::{
    Date, DurableObject, Env, Method, Request, RequestInit, Response, Result, State,
    durable_object,
};

pub const AUTH_CHALLENGE_BINDING: &str = "AUTH_CHALLENGE";
const MAX_JWKS_CACHE_ENTRIES: i64 = 32;
const MAX_JWKS_CACHE_TTL_SECS: u64 = 900;

fn now_secs() -> u64 {
    Date::now().as_millis() / 1000
}

fn json_resp<T: Serialize>(val: &T, status: u16) -> Result<Response> {
    Ok(Response::from_json(val)?.with_status(status))
}

pub fn ct_eq_str(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

// ---------------------------------------------------------------------------
// Wire Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceIssueReq {
    pub nonce: String,
    pub purpose: String,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceConsumeReq {
    pub nonce: String,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTxStartReq {
    pub tx_id: String,
    pub tx_cookie_hash: String,
    pub provider_id: String,
    /// `"login"` or `"link"`
    pub action: String,
    pub initiator_user_id: Option<String>,
    pub redirect_uri: String,
    pub state: String,
    pub pkce_verifier: String,
    pub nonce: String,
    pub next_url: String,
    pub expires_at: u64,
    #[serde(default)]
    pub ip_bucket: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTxConsumeReq {
    pub tx_id: String,
    pub tx_cookie_hash: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthTxRecord {
    pub tx_id: String,
    pub provider_id: String,
    pub action: String,
    pub initiator_user_id: Option<String>,
    pub redirect_uri: String,
    pub pkce_verifier: String,
    pub nonce: String,
    pub next_url: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailOtpIssueReq {
    pub email_hash: String,
    pub code_mac: String,
    pub link_mac: String,
    pub action: String,
    pub initiator_user_id: Option<String>,
    pub next_url: String,
    pub expires_at: u64,
    pub max_attempts: u32,
    pub email_rate_max: u32,
    pub email_rate_window_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailOtpVerifyReq {
    pub email_hash: String,
    pub code_mac: Option<String>,
    pub link_mac: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailOtpVerifyResp {
    pub action: String,
    pub initiator_user_id: Option<String>,
    pub next_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConsumeReq {
    pub digest: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitHitReq {
    pub bucket: String,
    pub window_secs: u64,
    pub max_hits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitResp {
    pub allowed: bool,
    pub count: u32,
    pub remaining: u32,
    pub retry_after_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksCacheGetReq {
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksCachePutReq {
    pub issuer: String,
    pub discovery_json: String,
    pub jwks_json: String,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwksCacheEntry {
    pub issuer: String,
    pub discovery_json: String,
    pub jwks_json: String,
    pub fetched_at: u64,
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// Pure Helpers (host-testable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpCheckOutcome {
    Matched,
    WrongRetryable { attempts_after: u32 },
    Exhausted,
    Expired,
}

/// Pure OTP verification decision enforcing expiry, constant-time MAC check,
/// and strict `max_attempts` lockout.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_otp_attempt(
    stored_code_mac: &str,
    stored_link_mac: &str,
    supplied_code_mac: Option<&str>,
    supplied_link_mac: Option<&str>,
    attempts: u32,
    max_attempts: u32,
    expires_at: u64,
    now: u64,
) -> OtpCheckOutcome {
    if now >= expires_at {
        return OtpCheckOutcome::Expired;
    }
    if attempts >= max_attempts {
        return OtpCheckOutcome::Exhausted;
    }
    let code_ok = supplied_code_mac.is_some_and(|m| ct_eq_str(stored_code_mac, m));
    let link_ok = supplied_link_mac.is_some_and(|m| ct_eq_str(stored_link_mac, m));
    if code_ok || link_ok {
        return OtpCheckOutcome::Matched;
    }
    let next = attempts.saturating_add(1);
    if next >= max_attempts {
        OtpCheckOutcome::Exhausted
    } else {
        OtpCheckOutcome::WrongRetryable {
            attempts_after: next,
        }
    }
}

// ---------------------------------------------------------------------------
// Durable Object
// ---------------------------------------------------------------------------

#[durable_object]
pub struct AuthChallengeDO {
    state: State,
    #[allow(dead_code)]
    env: Env,
    schema_ready: Cell<bool>,
    last_purge: Cell<i64>,
}

impl DurableObject for AuthChallengeDO {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            schema_ready: Cell::new(false),
            last_purge: Cell::new(0),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        match (req.method(), path.as_str()) {
            (Method::Post, "/nonce/issue") => self.nonce_issue(req.json().await?),
            (Method::Post, "/nonce/consume") => self.nonce_consume(req.json().await?),
            (Method::Post, "/oauth/start") => self.oauth_start(req.json().await?),
            (Method::Post, "/oauth/consume") => self.oauth_consume(req.json().await?),
            (Method::Post, "/email-otp/issue") => self.email_otp_issue(req.json().await?),
            (Method::Post, "/email-otp/verify") => self.email_otp_verify(req.json().await?),
            (Method::Post, "/telegram/consume") => self.telegram_consume(req.json().await?),
            (Method::Post, "/rate-limit/hit") => self.rate_limit_hit_endpoint(req.json().await?),
            (Method::Post, "/jwks/get") => self.jwks_get(req.json().await?),
            (Method::Post, "/jwks/put") => self.jwks_put(req.json().await?),
            _ => Response::error("not found", 404),
        }
    }
}

impl AuthChallengeDO {
    fn ensure_schema(&self, now: i64) -> Result<worker::SqlStorage> {
        let db = self.state.storage().sql();
        if !self.schema_ready.get() {
            db.exec(
                "CREATE TABLE IF NOT EXISTS nonces (\
                    nonce TEXT PRIMARY KEY,\
                    purpose TEXT NOT NULL,\
                    expires_at INTEGER NOT NULL\
                )",
                None,
            )?;
            db.exec(
                "CREATE TABLE IF NOT EXISTS oauth_tx (\
                    tx_id TEXT PRIMARY KEY,\
                    tx_cookie_hash TEXT NOT NULL,\
                    provider_id TEXT NOT NULL,\
                    action TEXT NOT NULL,\
                    initiator_user_id TEXT,\
                    redirect_uri TEXT NOT NULL,\
                    state TEXT NOT NULL,\
                    pkce_verifier TEXT NOT NULL,\
                    nonce TEXT NOT NULL,\
                    next_url TEXT NOT NULL,\
                    expires_at INTEGER NOT NULL\
                )",
                None,
            )?;
            db.exec(
                "CREATE TABLE IF NOT EXISTS email_otp (\
                    email_hash TEXT PRIMARY KEY,\
                    code_mac TEXT NOT NULL,\
                    link_mac TEXT NOT NULL,\
                    attempts INTEGER NOT NULL DEFAULT 0,\
                    max_attempts INTEGER NOT NULL DEFAULT 5,\
                    action TEXT NOT NULL DEFAULT 'login',\
                    initiator_user_id TEXT,\
                    next_url TEXT NOT NULL,\
                    expires_at INTEGER NOT NULL\
                )",
                None,
            )?;
            db.exec(
                "CREATE TABLE IF NOT EXISTS telegram_digests (\
                    digest TEXT PRIMARY KEY,\
                    expires_at INTEGER NOT NULL\
                )",
                None,
            )?;
            db.exec(
                "CREATE TABLE IF NOT EXISTS rate_limits (\
                    bucket TEXT PRIMARY KEY,\
                    count INTEGER NOT NULL,\
                    window_end INTEGER NOT NULL\
                )",
                None,
            )?;
            db.exec(
                "CREATE TABLE IF NOT EXISTS jwks_cache (\
                    issuer TEXT PRIMARY KEY,\
                    discovery_json TEXT NOT NULL,\
                    jwks_json TEXT NOT NULL,\
                    fetched_at INTEGER NOT NULL,\
                    expires_at INTEGER NOT NULL\
                )",
                None,
            )?;
            self.schema_ready.set(true);
        }

        if now.saturating_sub(self.last_purge.get()) >= 60 {
            let _ = db.exec("DELETE FROM nonces WHERE expires_at <= ?1", vec![now.into()]);
            let _ = db.exec("DELETE FROM oauth_tx WHERE expires_at <= ?1", vec![now.into()]);
            let _ = db.exec("DELETE FROM email_otp WHERE expires_at <= ?1", vec![now.into()]);
            let _ = db.exec(
                "DELETE FROM telegram_digests WHERE expires_at <= ?1",
                vec![now.into()],
            );
            let _ = db.exec(
                "DELETE FROM rate_limits WHERE window_end <= ?1",
                vec![now.into()],
            );
            let _ = db.exec(
                "DELETE FROM jwks_cache WHERE expires_at <= ?1",
                vec![now.into()],
            );
            self.last_purge.set(now);
        }

        Ok(db)
    }

    fn hit_bucket(
        db: &worker::SqlStorage,
        bucket: &str,
        now: i64,
        window_secs: u64,
        max_hits: u32,
    ) -> Result<RateLimitResp> {
        #[derive(Deserialize)]
        struct Row {
            count: i64,
            window_end: i64,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT count, window_end FROM rate_limits WHERE bucket = ?1 AND window_end > ?2",
                vec![bucket.into(), now.into()],
            )?
            .to_array()?;
        if let Some(row) = rows.into_iter().next() {
            let cur = row.count.max(0) as u32;
            let retry_after = (row.window_end - now).max(1) as u64;
            if cur >= max_hits {
                return Ok(RateLimitResp {
                    allowed: false,
                    count: cur,
                    remaining: 0,
                    retry_after_secs: retry_after,
                });
            }
            let next = cur + 1;
            db.exec(
                "UPDATE rate_limits SET count = ?1 WHERE bucket = ?2",
                vec![(next as i64).into(), bucket.into()],
            )?;
            return Ok(RateLimitResp {
                allowed: true,
                count: next,
                remaining: max_hits.saturating_sub(next),
                retry_after_secs: retry_after,
            });
        }

        let window_end = now.saturating_add(window_secs.max(1) as i64);
        db.exec(
            "INSERT OR REPLACE INTO rate_limits (bucket, count, window_end) VALUES (?1, 1, ?2)",
            vec![bucket.into(), window_end.into()],
        )?;
        Ok(RateLimitResp {
            allowed: true,
            count: 1,
            remaining: max_hits.saturating_sub(1),
            retry_after_secs: window_secs.max(1),
        })
    }

    fn nonce_issue(&self, req: NonceIssueReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_schema(now)?;
        let ttl = req.ttl_secs.clamp(30, 900) as i64;
        db.exec(
            "INSERT OR REPLACE INTO nonces (nonce, purpose, expires_at) VALUES (?1, ?2, ?3)",
            vec![req.nonce.into(), req.purpose.into(), (now + ttl).into()],
        )?;
        Response::ok("")
    }

    fn nonce_consume(&self, req: NonceConsumeReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_schema(now)?;
        #[derive(Deserialize)]
        struct Row {
            purpose: String,
            expires_at: i64,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT purpose, expires_at FROM nonces WHERE nonce = ?1",
                vec![req.nonce.clone().into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Response::error("unknown or expired nonce", 401);
        };
        // Always delete immediately so the nonce is strictly single-use.
        db.exec(
            "DELETE FROM nonces WHERE nonce = ?1",
            vec![req.nonce.into()],
        )?;
        if row.expires_at <= now || row.purpose != req.purpose {
            return Response::error("unknown or expired nonce", 401);
        }
        Response::ok("")
    }

    fn oauth_start(&self, req: OAuthTxStartReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_schema(now)?;
        if let Some(ip_bucket) = req.ip_bucket.as_deref() {
            let rl = Self::hit_bucket(&db, ip_bucket, now, 600, 40)?;
            if !rl.allowed {
                return Response::error("too many sign-in attempts", 429);
            }
        }
        db.exec(
            "INSERT OR REPLACE INTO oauth_tx \
             (tx_id, tx_cookie_hash, provider_id, action, initiator_user_id, redirect_uri, state, pkce_verifier, nonce, next_url, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            vec![
                req.tx_id.into(),
                req.tx_cookie_hash.into(),
                req.provider_id.into(),
                req.action.into(),
                req.initiator_user_id.into(),
                req.redirect_uri.into(),
                req.state.into(),
                req.pkce_verifier.into(),
                req.nonce.into(),
                req.next_url.into(),
                (req.expires_at as i64).into(),
            ],
        )?;
        Response::ok("")
    }

    fn oauth_consume(&self, req: OAuthTxConsumeReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_schema(now)?;
        #[derive(Deserialize)]
        struct Row {
            tx_id: String,
            tx_cookie_hash: String,
            provider_id: String,
            action: String,
            initiator_user_id: Option<String>,
            redirect_uri: String,
            state: String,
            pkce_verifier: String,
            nonce: String,
            next_url: String,
            expires_at: i64,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT tx_id, tx_cookie_hash, provider_id, action, initiator_user_id, redirect_uri, state, pkce_verifier, nonce, next_url, expires_at \
                 FROM oauth_tx WHERE tx_id = ?1",
                vec![req.tx_id.clone().into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Response::error("invalid or expired auth transaction", 401);
        };
        // Consume atomically before returning so replay is impossible.
        db.exec(
            "DELETE FROM oauth_tx WHERE tx_id = ?1",
            vec![req.tx_id.into()],
        )?;
        if row.expires_at <= now
            || !ct_eq_str(&row.tx_cookie_hash, &req.tx_cookie_hash)
            || !ct_eq_str(&row.state, &req.state)
        {
            return Response::error("invalid or expired auth transaction", 401);
        }
        json_resp(
            &OAuthTxRecord {
                tx_id: row.tx_id,
                provider_id: row.provider_id,
                action: row.action,
                initiator_user_id: row.initiator_user_id,
                redirect_uri: row.redirect_uri,
                pkce_verifier: row.pkce_verifier,
                nonce: row.nonce,
                next_url: row.next_url,
                expires_at: row.expires_at.max(0) as u64,
            },
            200,
        )
    }

    fn email_otp_issue(&self, req: EmailOtpIssueReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_schema(now)?;
        let rl_bucket = format!("email-send:{}", req.email_hash);
        let rl = Self::hit_bucket(
            &db,
            &rl_bucket,
            now,
            req.email_rate_window_secs.max(60),
            req.email_rate_max.max(1),
        )?;
        if !rl.allowed {
            return Response::error("rate limit exceeded", 429);
        }
        db.exec(
            "INSERT OR REPLACE INTO email_otp \
             (email_hash, code_mac, link_mac, attempts, max_attempts, action, initiator_user_id, next_url, expires_at) \
             VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8)",
            vec![
                req.email_hash.into(),
                req.code_mac.into(),
                req.link_mac.into(),
                (req.max_attempts.clamp(1, 10) as i64).into(),
                req.action.into(),
                req.initiator_user_id.into(),
                req.next_url.into(),
                (req.expires_at as i64).into(),
            ],
        )?;
        Response::ok("")
    }

    fn email_otp_verify(&self, req: EmailOtpVerifyReq) -> Result<Response> {
        let now = now_secs();
        let db = self.ensure_schema(now as i64)?;
        #[derive(Deserialize)]
        struct Row {
            code_mac: String,
            link_mac: String,
            attempts: i64,
            max_attempts: i64,
            action: String,
            initiator_user_id: Option<String>,
            next_url: String,
            expires_at: i64,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT code_mac, link_mac, attempts, max_attempts, action, initiator_user_id, next_url, expires_at \
                 FROM email_otp WHERE email_hash = ?1",
                vec![req.email_hash.clone().into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Response::error("invalid or expired code", 401);
        };

        let outcome = evaluate_otp_attempt(
            &row.code_mac,
            &row.link_mac,
            req.code_mac.as_deref(),
            req.link_mac.as_deref(),
            row.attempts.max(0) as u32,
            row.max_attempts.max(1) as u32,
            row.expires_at.max(0) as u64,
            now,
        );

        match outcome {
            OtpCheckOutcome::Matched => {
                db.exec(
                    "DELETE FROM email_otp WHERE email_hash = ?1",
                    vec![req.email_hash.into()],
                )?;
                json_resp(
                    &EmailOtpVerifyResp {
                        action: row.action,
                        initiator_user_id: row.initiator_user_id,
                        next_url: row.next_url,
                    },
                    200,
                )
            }
            OtpCheckOutcome::WrongRetryable { attempts_after } => {
                db.exec(
                    "UPDATE email_otp SET attempts = ?1 WHERE email_hash = ?2",
                    vec![(attempts_after as i64).into(), req.email_hash.into()],
                )?;
                Response::error("invalid or expired code", 401)
            }
            OtpCheckOutcome::Exhausted => {
                db.exec(
                    "DELETE FROM email_otp WHERE email_hash = ?1",
                    vec![req.email_hash.into()],
                )?;
                Response::error("too many failed attempts — request a new code", 429)
            }
            OtpCheckOutcome::Expired => {
                db.exec(
                    "DELETE FROM email_otp WHERE email_hash = ?1",
                    vec![req.email_hash.into()],
                )?;
                Response::error("invalid or expired code", 401)
            }
        }
    }

    fn telegram_consume(&self, req: TelegramConsumeReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_schema(now)?;
        #[derive(Deserialize)]
        struct Row {
            expires_at: i64,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT expires_at FROM telegram_digests WHERE digest = ?1",
                vec![req.digest.clone().into()],
            )?
            .to_array()?;
        if rows.into_iter().any(|r| r.expires_at > now) {
            return Response::error("telegram login assertion already consumed", 409);
        }
        db.exec(
            "INSERT OR REPLACE INTO telegram_digests (digest, expires_at) VALUES (?1, ?2)",
            vec![req.digest.into(), (req.expires_at as i64).into()],
        )?;
        Response::ok("")
    }

    fn rate_limit_hit_endpoint(&self, req: RateLimitHitReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_schema(now)?;
        let resp = Self::hit_bucket(&db, &req.bucket, now, req.window_secs, req.max_hits)?;
        let status = if resp.allowed { 200 } else { 429 };
        json_resp(&resp, status)
    }

    fn jwks_get(&self, req: JwksCacheGetReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_schema(now)?;
        #[derive(Deserialize)]
        struct Row {
            issuer: String,
            discovery_json: String,
            jwks_json: String,
            fetched_at: i64,
            expires_at: i64,
        }
        let rows: Vec<Row> = db
            .exec(
                "SELECT issuer, discovery_json, jwks_json, fetched_at, expires_at \
                 FROM jwks_cache WHERE issuer = ?1 AND expires_at > ?2",
                vec![req.issuer.into(), now.into()],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Response::error("cache miss", 404);
        };
        json_resp(
            &JwksCacheEntry {
                issuer: row.issuer,
                discovery_json: row.discovery_json,
                jwks_json: row.jwks_json,
                fetched_at: row.fetched_at.max(0) as u64,
                expires_at: row.expires_at.max(0) as u64,
            },
            200,
        )
    }

    fn jwks_put(&self, req: JwksCachePutReq) -> Result<Response> {
        let now = now_secs() as i64;
        let db = self.ensure_schema(now)?;
        let ttl = req.ttl_secs.clamp(60, MAX_JWKS_CACHE_TTL_SECS) as i64;
        db.exec(
            "INSERT OR REPLACE INTO jwks_cache (issuer, discovery_json, jwks_json, fetched_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![
                req.issuer.into(),
                req.discovery_json.into(),
                req.jwks_json.into(),
                now.into(),
                (now + ttl).into(),
            ],
        )?;
        // Enforce bounded cache size (evict oldest entries beyond MAX_JWKS_CACHE_ENTRIES).
        db.exec(
            "DELETE FROM jwks_cache WHERE issuer NOT IN (\
                SELECT issuer FROM jwks_cache ORDER BY fetched_at DESC LIMIT ?1\
            )",
            vec![MAX_JWKS_CACHE_ENTRIES.into()],
        )?;
        Response::ok("")
    }
}

// ---------------------------------------------------------------------------
// Client Helpers
// ---------------------------------------------------------------------------

async fn call_challenge_do<B: Serialize>(
    env: &Env,
    do_name: &str,
    path: &str,
    body: &B,
) -> Result<(u16, String)> {
    let stub = env
        .durable_object(AUTH_CHALLENGE_BINDING)?
        .id_from_name(do_name)?
        .get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.headers.set("content-type", "application/json")?;
    let json = serde_json::to_string(body).map_err(|e| worker::Error::RustError(e.to_string()))?;
    init.with_body(Some(json.into()));
    let req = Request::new_with_init(&format!("https://do{path}"), &init)?;
    let mut resp = stub.fetch_with_request(req).await?;
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}

pub async fn issue_nonce(env: &Env, nonce: &str, purpose: &str, ttl_secs: u64) -> Result<()> {
    let (status, msg) = call_challenge_do(
        env,
        &format!("nonce:{nonce}"),
        "/nonce/issue",
        &NonceIssueReq {
            nonce: nonce.to_string(),
            purpose: purpose.to_string(),
            ttl_secs,
        },
    )
    .await?;
    if status == 200 {
        Ok(())
    } else {
        Err(worker::Error::RustError(format!(
            "nonce issue failed ({status}): {msg}"
        )))
    }
}

/// Atomically consume a single-use nonce. Returns `Ok(true)` if valid & consumed,
/// `Ok(false)` if missing, expired, wrong purpose, or already used.
pub async fn consume_nonce(env: &Env, nonce: &str, purpose: &str) -> Result<bool> {
    let (status, msg) = call_challenge_do(
        env,
        &format!("nonce:{nonce}"),
        "/nonce/consume",
        &NonceConsumeReq {
            nonce: nonce.to_string(),
            purpose: purpose.to_string(),
        },
    )
    .await?;
    match status {
        200 => Ok(true),
        401 => Ok(false),
        _ => Err(worker::Error::RustError(format!(
            "nonce consume failed ({status}): {msg}"
        ))),
    }
}

pub async fn start_oauth_tx(env: &Env, req: &OAuthTxStartReq) -> Result<(u16, String)> {
    call_challenge_do(env, &format!("oauth:{}", req.tx_id), "/oauth/start", req).await
}

pub async fn consume_oauth_tx(
    env: &Env,
    req: &OAuthTxConsumeReq,
) -> Result<Option<OAuthTxRecord>> {
    let (status, text) = call_challenge_do(
        env,
        &format!("oauth:{}", req.tx_id),
        "/oauth/consume",
        req,
    )
    .await?;
    match status {
        200 => serde_json::from_str::<OAuthTxRecord>(&text)
            .map(Some)
            .map_err(|e| worker::Error::RustError(e.to_string())),
        401 => Ok(None),
        _ => Err(worker::Error::RustError(format!(
            "oauth consume failed ({status}): {text}"
        ))),
    }
}

pub async fn issue_email_otp(env: &Env, req: &EmailOtpIssueReq) -> Result<u16> {
    let (status, _) = call_challenge_do(
        env,
        &format!("email:{}", req.email_hash),
        "/email-otp/issue",
        req,
    )
    .await?;
    Ok(status)
}

pub async fn verify_email_otp(
    env: &Env,
    req: &EmailOtpVerifyReq,
) -> Result<(u16, Option<EmailOtpVerifyResp>)> {
    let (status, text) = call_challenge_do(
        env,
        &format!("email:{}", req.email_hash),
        "/email-otp/verify",
        req,
    )
    .await?;
    if status == 200 {
        let parsed = serde_json::from_str::<EmailOtpVerifyResp>(&text)
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        Ok((200, Some(parsed)))
    } else {
        Ok((status, None))
    }
}

/// Atomically consume a Telegram login assertion digest (`SHA256(hash)`).
/// Returns `Ok(true)` if fresh & recorded, `Ok(false)` on replay (`409`).
pub async fn consume_telegram_digest(env: &Env, digest: &str, expires_at: u64) -> Result<bool> {
    let (status, msg) = call_challenge_do(
        env,
        &format!("tg:{digest}"),
        "/telegram/consume",
        &TelegramConsumeReq {
            digest: digest.to_string(),
            expires_at,
        },
    )
    .await?;
    match status {
        200 => Ok(true),
        409 => Ok(false),
        _ => Err(worker::Error::RustError(format!(
            "telegram consume failed ({status}): {msg}"
        ))),
    }
}

pub async fn hit_rate_limit(
    env: &Env,
    bucket: &str,
    window_secs: u64,
    max_hits: u32,
) -> Result<RateLimitResp> {
    let (status, text) = call_challenge_do(
        env,
        &format!("rl:{bucket}"),
        "/rate-limit/hit",
        &RateLimitHitReq {
            bucket: bucket.to_string(),
            window_secs,
            max_hits,
        },
    )
    .await?;
    if status == 200 || status == 429 {
        serde_json::from_str::<RateLimitResp>(&text)
            .map_err(|e| worker::Error::RustError(e.to_string()))
    } else {
        Err(worker::Error::RustError(format!(
            "rate limit DO failed ({status}): {text}"
        )))
    }
}

pub async fn get_cached_jwks(env: &Env, issuer: &str) -> Result<Option<JwksCacheEntry>> {
    let (status, text) = call_challenge_do(
        env,
        "jwks:global",
        "/jwks/get",
        &JwksCacheGetReq {
            issuer: issuer.to_string(),
        },
    )
    .await?;
    match status {
        200 => serde_json::from_str::<JwksCacheEntry>(&text)
            .map(Some)
            .map_err(|e| worker::Error::RustError(e.to_string())),
        404 => Ok(None),
        _ => Err(worker::Error::RustError(format!(
            "jwks get failed ({status}): {text}"
        ))),
    }
}

pub async fn put_cached_jwks(env: &Env, req: &JwksCachePutReq) -> Result<()> {
    let (status, text) = call_challenge_do(env, "jwks:global", "/jwks/put", req).await?;
    if status == 200 {
        Ok(())
    } else {
        Err(worker::Error::RustError(format!(
            "jwks put failed ({status}): {text}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otp_attempt_enforces_max_5_and_expiry() {
        assert_eq!(
            evaluate_otp_attempt("code-mac", "link-mac", Some("code-mac"), None, 0, 5, 1000, 900),
            OtpCheckOutcome::Matched
        );
        assert_eq!(
            evaluate_otp_attempt("code-mac", "link-mac", None, Some("link-mac"), 4, 5, 1000, 900),
            OtpCheckOutcome::Matched
        );
        assert_eq!(
            evaluate_otp_attempt("code-mac", "link-mac", Some("wrong"), None, 3, 5, 1000, 900),
            OtpCheckOutcome::WrongRetryable { attempts_after: 4 }
        );
        // 5th failed attempt exhausts the challenge.
        assert_eq!(
            evaluate_otp_attempt("code-mac", "link-mac", Some("wrong"), None, 4, 5, 1000, 900),
            OtpCheckOutcome::Exhausted
        );
        // Expired challenge rejects even the right MAC.
        assert_eq!(
            evaluate_otp_attempt("code-mac", "link-mac", Some("code-mac"), None, 0, 5, 1000, 1000),
            OtpCheckOutcome::Expired
        );
    }
}
