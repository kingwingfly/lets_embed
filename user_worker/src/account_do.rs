//! UNIT 3: the per-user `UserAccount` Durable Object.
//!
//! STUB: implement the fetch dispatch + alarm. Contracts (see types.rs for
//! the exact wire protocol; gateway_worker duplicates those structs):
//!
//! Routes: POST /charge, POST /credit, GET /status, POST /init,
//!         POST /subscribe, POST /unsubscribe, POST /ban.
//!
//! Storage keys:
//!   init: bool, address: String, banned: bool, balance: i64, plan: String?,
//!   quota: i64, period_end: u64, total_views: i64,
//!   seen:{epoch_day}: HashMap<String, u64> (path -> first_seen secs),
//!   credit:{key}: bool (idempotency markers).
//!
//! Charge algorithm: lazy ensure_init (FREE_GRANT_POINTS on first touch);
//! banned -> 403; dedupe: path present in seen:{day} or seen:{day-1} with
//! first_seen > now - DEDUPE_WINDOW_SECS -> 200 charged:false; else cost by
//! kind; active plan (period_end > now) quota first, then balance; neither ->
//! 402; on success record seen, bump total_views. On first write into a new
//! day's map, delete seen:{day-2} (bounded storage). Alarm = subscription
//! renewal: deduct price from balance and reset quota + period_end + re-arm,
//! or lapse to PAYG (delete plan, quota = 0).
//!
//! Keep pure decision logic (dedupe predicate, charge math) in plain
//! host-testable fns with #[cfg(test)] tests.

use worker::{DurableObject, Env, Request, Response, Result, State, durable_object};

#[durable_object]
pub struct UserAccount {
    state: State,
    env: Env,
}

impl DurableObject for UserAccount {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, _req: Request) -> Result<Response> {
        let _ = (&self.state, &self.env);
        Response::error("not implemented", 501)
    }

    async fn alarm(&self) -> Result<Response> {
        Response::error("not implemented", 501)
    }
}
