//! UNIT 1: the per-user `UserAccount` Durable Object.
//!
//! One instance per user (id = lowercase 0x address). Tracks PAYG balance,
//! subscription plan + rolling usage window, view/search dedupe and ban state.
//! See `types.rs` for the wire protocol (duplicated in gateway_worker) and
//! `config.rs` for pricing.
//!
//! SCAFFOLD STATE: a working PAYG-only base (dedupe + balance charging,
//! subscribe deducts from balance, alarm lapses the plan). UNIT 1 layers in the
//! 5-hour usage window (`views_per_window` / `searches_per_window`), the
//! quota-then-PAYG fallback order, and search metering, then reports the
//! `views_remaining` / `searches_remaining` / `window_reset` fields.

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use worker::{
    Date, DurableObject, Env, Method, Request, Response, Result, State, durable_object,
};

use crate::config;
use crate::types::{
    BalanceResp, BanReq, ChargeKind, ChargeReq, ChargeResp, CreditReq, InitReq, StatusResp,
    SubscribeReq,
};

// ---------------------------------------------------------------------------
// Pure decision logic (host-testable)
// ---------------------------------------------------------------------------

fn view_cost(kind: ChargeKind) -> i64 {
    match kind {
        ChargeKind::Image => config::COST_IMAGE_VIEW,
        ChargeKind::Video => config::COST_VIDEO_VIEW,
        ChargeKind::Search => config::COST_SIM_SEARCH,
    }
}

/// A repeat charge is free if the key was first seen within the dedupe window.
fn is_recent_view(path: &str, now: u64, maps: [&HashMap<String, u64>; 2]) -> bool {
    let cutoff = now.saturating_sub(config::DEDUPE_WINDOW_SECS);
    maps.iter()
        .any(|m| m.get(path).is_some_and(|&first_seen| first_seen > cutoff))
}

fn now_secs() -> u64 {
    Date::now().as_millis() / 1000
}

fn json<T: serde::Serialize>(v: &T, status: u16) -> Result<Response> {
    Ok(Response::from_json(v)?.with_status(status))
}

// ---------------------------------------------------------------------------
// Durable Object
// ---------------------------------------------------------------------------

#[durable_object]
pub struct UserAccount {
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for UserAccount {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        match (req.method(), path.as_str()) {
            (Method::Post, "/init") => self.init(req.json().await?).await,
            (Method::Post, "/charge") => self.charge(req.json().await?).await,
            (Method::Post, "/credit") => self.credit(req.json().await?).await,
            (Method::Get, "/status") => json(&self.status_resp().await?, 200),
            (Method::Post, "/subscribe") => self.subscribe(req.json().await?).await,
            (Method::Post, "/ban") => self.ban(req.json().await?).await,
            _ => Response::error("not found", 404),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        let storage = self.state.storage();
        let now = now_secs();
        if storage.get::<String>("plan").await?.is_none() {
            return Response::ok("");
        }
        let period_end: u64 = self.get_or("period_end", 0).await?;
        if period_end > now {
            // fired early — re-arm at the real period end
            storage
                .set_alarm(((period_end - now) * 1000) as i64)
                .await?;
            return Response::ok("");
        }
        // period elapsed: no auto-renew — lapse to PAYG
        storage.delete("plan").await?;
        Response::ok("")
    }
}

impl UserAccount {
    async fn get_or<T: DeserializeOwned>(&self, key: &str, default: T) -> Result<T> {
        Ok(self.state.storage().get(key).await?.unwrap_or(default))
    }

    /// First touch of a brand-new account: grant the free points.
    async fn ensure_init(&self) -> Result<()> {
        let storage = self.state.storage();
        if storage.get::<bool>("init").await?.is_none() {
            storage.put("balance", config::FREE_GRANT_POINTS).await?;
            storage.put("init", true).await?;
        }
        Ok(())
    }

    /// Whether a subscription period is currently active.
    async fn plan_active(&self, now: u64) -> Result<bool> {
        let period_end: u64 = self.get_or("period_end", 0).await?;
        Ok(self.state.storage().get::<String>("plan").await?.is_some() && period_end > now)
    }

    async fn status_resp(&self) -> Result<StatusResp> {
        let now = now_secs();
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active = self.plan_active(now).await?;
        Ok(StatusResp {
            address: self.get_or("address", String::new()).await?,
            balance: self.get_or("balance", 0).await?,
            plan: self.state.storage().get("plan").await?,
            period_end: if active { period_end } else { 0 },
            // SCAFFOLD: window accounting is UNIT 1's job.
            views_remaining: None,
            searches_remaining: None,
            window_reset: 0,
            banned: self.get_or("banned", false).await?,
            total_views: self.get_or("total_views", 0).await?,
        })
    }

    async fn init(&self, req: InitReq) -> Result<Response> {
        self.ensure_init().await?;
        self.state.storage().put("address", &req.address).await?;
        json(&self.status_resp().await?, 200)
    }

    async fn charge(&self, req: ChargeReq) -> Result<Response> {
        self.ensure_init().await?;
        if self.get_or("banned", false).await? {
            return Response::error("banned", 403);
        }
        let storage = self.state.storage();
        let now = now_secs();
        let day = now / 86_400;
        let today_key = format!("seen:{day}");
        let today: Option<HashMap<String, u64>> = storage.get(&today_key).await?;
        let yesterday: HashMap<String, u64> = self
            .get_or(&format!("seen:{}", day - 1), HashMap::new())
            .await?;

        let cost = view_cost(req.kind);
        let mut balance: i64 = self.get_or("balance", 0).await?;

        let new_day = today.is_none();
        let mut today_map = today.unwrap_or_default();
        let resp = |charged: bool, balance: i64| ChargeResp {
            charged,
            cost,
            balance,
            views_remaining: None,
            searches_remaining: None,
            window_reset: 0,
        };

        if is_recent_view(&req.path, now, [&today_map, &yesterday]) {
            return json(&resp(false, balance), 200);
        }

        // SCAFFOLD: PAYG only. UNIT 1 consults the active plan's window first.
        if balance < cost {
            return json(&resp(false, balance), 402);
        }
        balance -= cost;
        if new_day {
            // drop the map that fell out of the dedupe horizon (bounded storage)
            storage.delete(&format!("seen:{}", day - 2)).await?;
        }
        today_map.insert(req.path, now);
        let total_views: i64 = self.get_or("total_views", 0).await? + 1;
        storage.put(&today_key, &today_map).await?;
        storage.put("balance", balance).await?;
        storage.put("total_views", total_views).await?;
        json(&resp(true, balance), 200)
    }

    async fn credit(&self, req: CreditReq) -> Result<Response> {
        let storage = self.state.storage();
        let marker = format!("credit:{}", req.key);
        let balance: i64 = self.get_or("balance", 0).await?;
        if storage.get::<bool>(&marker).await?.is_some() {
            return json(&BalanceResp { balance, applied: false }, 200);
        }
        let balance = (balance + req.points).max(0);
        storage.put("balance", balance).await?;
        storage.put(&marker, true).await?;
        json(&BalanceResp { balance, applied: true }, 200)
    }

    async fn subscribe(&self, req: SubscribeReq) -> Result<Response> {
        let Some(plan) = config::plan(&req.plan) else {
            return Response::error("unknown plan", 400);
        };
        let storage = self.state.storage();
        let now = now_secs();
        let current: Option<String> = storage.get("plan").await?;
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active = current.is_some() && period_end > now;
        // Renew (same plan, active) extends; a different active plan is a 409.
        if active && current.as_deref() != Some(plan.id) {
            return Response::error("another plan is active", 409);
        }
        let balance: i64 = self.get_or("balance", 0).await?;
        if balance < plan.price_points {
            return Response::error("insufficient balance", 402);
        }
        let new_end = if active {
            period_end + plan.period_secs
        } else {
            now + plan.period_secs
        };
        storage.put("balance", balance - plan.price_points).await?;
        storage.put("plan", plan.id).await?;
        storage.put("period_end", new_end).await?;
        storage
            .set_alarm((new_end.saturating_sub(now) * 1000) as i64)
            .await?;
        json(&self.status_resp().await?, 200)
    }

    async fn ban(&self, req: BanReq) -> Result<Response> {
        self.state.storage().put("banned", req.banned).await?;
        json(&self.status_resp().await?, 200)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_750_000_000;

    fn map(entries: &[(&str, u64)]) -> HashMap<String, u64> {
        entries.iter().map(|&(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn dedupe_hits_today_and_yesterday_within_window() {
        let today = map(&[("/images/a.webp", NOW - 10)]);
        let yesterday = map(&[("/images/b.webp", NOW - config::DEDUPE_WINDOW_SECS + 1)]);
        let empty = HashMap::new();
        assert!(is_recent_view("/images/a.webp", NOW, [&today, &empty]));
        assert!(is_recent_view("/images/b.webp", NOW, [&empty, &yesterday]));
    }

    #[test]
    fn dedupe_misses_unknown_path_and_expired_entry() {
        let yesterday = map(&[("/images/old.webp", NOW - config::DEDUPE_WINDOW_SECS)]);
        let empty = HashMap::new();
        assert!(!is_recent_view("/images/new.webp", NOW, [&empty, &yesterday]));
        // first_seen exactly at the cutoff is no longer free
        assert!(!is_recent_view("/images/old.webp", NOW, [&empty, &yesterday]));
    }

    #[test]
    fn view_costs_match_config() {
        assert_eq!(view_cost(ChargeKind::Image), config::COST_IMAGE_VIEW);
        assert_eq!(view_cost(ChargeKind::Video), config::COST_VIDEO_VIEW);
        assert_eq!(view_cost(ChargeKind::Search), config::COST_SIM_SEARCH);
    }
}
