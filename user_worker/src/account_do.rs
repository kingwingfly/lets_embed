//! UNIT 3: the per-user `UserAccount` Durable Object.
//!
//! One instance per user (id = lowercase 0x address). Tracks PAYG balance,
//! subscription quota, view dedupe and ban state. See `types.rs` for the wire
//! protocol (duplicated in gateway_worker) and `config.rs` for pricing.

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use worker::{
    Date, DurableObject, Env, Method, Request, Response, Result, State, durable_object,
};

use crate::config;
use crate::types::{
    BalanceResp, BanReq, ChargeReq, ChargeResp, CreditReq, InitReq, MediaKind, StatusResp,
    SubscribeReq,
};

// ---------------------------------------------------------------------------
// Pure decision logic (host-testable)
// ---------------------------------------------------------------------------

fn view_cost(kind: MediaKind) -> i64 {
    match kind {
        MediaKind::Image => config::COST_IMAGE_VIEW,
        MediaKind::Video => config::COST_VIDEO_VIEW,
    }
}

/// A repeat view is free if the path was first seen within the dedupe window.
fn is_recent_view(path: &str, now: u64, maps: [&HashMap<String, u64>; 2]) -> bool {
    let cutoff = now.saturating_sub(config::DEDUPE_WINDOW_SECS);
    maps.iter()
        .any(|m| m.get(path).is_some_and(|&first_seen| first_seen > cutoff))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChargeSource {
    Quota,
    Balance,
}

/// Subscription quota first (only while the period is active), then PAYG.
fn charge_source(plan_active: bool, quota: i64, balance: i64, cost: i64) -> Option<ChargeSource> {
    if plan_active && quota >= cost {
        Some(ChargeSource::Quota)
    } else if balance >= cost {
        Some(ChargeSource::Balance)
    } else {
        None
    }
}

/// Renewal succeeds iff the balance covers the plan price; returns the new balance.
fn renewal_deduct(balance: i64, price: i64) -> Option<i64> {
    (balance >= price).then(|| balance - price)
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
            (Method::Post, "/unsubscribe") => self.unsubscribe().await,
            (Method::Post, "/ban") => self.ban(req.json().await?).await,
            _ => Response::error("not found", 404),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        let storage = self.state.storage();
        let now = now_secs();
        let Some(plan_id) = storage.get::<String>("plan").await? else {
            return Response::ok("");
        };
        let period_end: u64 = self.get_or("period_end", 0).await?;
        if period_end > now {
            // fired early — re-arm at the real period end
            storage
                .set_alarm(((period_end - now) * 1000) as i64)
                .await?;
            return Response::ok("");
        }
        let balance: i64 = self.get_or("balance", 0).await?;
        let renewed = config::plan(&plan_id)
            .and_then(|p| renewal_deduct(balance, p.price_points).map(|b| (p, b)));
        match renewed {
            Some((plan, new_balance)) => {
                let new_end = period_end + plan.period_secs;
                storage.put("balance", new_balance).await?;
                storage.put("quota", plan.quota_points).await?;
                storage.put("period_end", new_end).await?;
                storage
                    .set_alarm((new_end.saturating_sub(now) * 1000) as i64)
                    .await?;
            }
            None => {
                // unknown plan or insufficient balance: lapse to PAYG
                storage.delete("plan").await?;
                storage.put("quota", 0i64).await?;
            }
        }
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

    async fn status_resp(&self) -> Result<StatusResp> {
        let now = now_secs();
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active = period_end > now;
        Ok(StatusResp {
            address: self.get_or("address", String::new()).await?,
            balance: self.get_or("balance", 0).await?,
            plan: self.state.storage().get("plan").await?,
            quota_remaining: if active {
                self.get_or("quota", 0).await?
            } else {
                0
            },
            period_end: if active { period_end } else { 0 },
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
        let mut quota: i64 = self.get_or("quota", 0).await?;
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active = period_end > now;
        let quota_remaining = |quota: i64| if active { quota } else { 0 };

        let new_day = today.is_none();
        let mut today_map = today.unwrap_or_default();
        if is_recent_view(&req.path, now, [&today_map, &yesterday]) {
            return json(
                &ChargeResp {
                    charged: false,
                    cost,
                    balance,
                    quota_remaining: quota_remaining(quota),
                },
                200,
            );
        }

        let Some(source) = charge_source(active, quota, balance, cost) else {
            return json(
                &ChargeResp {
                    charged: false,
                    cost,
                    balance,
                    quota_remaining: quota_remaining(quota),
                },
                402,
            );
        };
        match source {
            ChargeSource::Quota => quota -= cost,
            ChargeSource::Balance => balance -= cost,
        }
        if new_day {
            // first write into a new day's map: drop the map that fell out of
            // the dedupe horizon, keeping storage bounded
            storage.delete(&format!("seen:{}", day - 2)).await?;
        }
        today_map.insert(req.path, now);
        let total_views: i64 = self.get_or("total_views", 0).await? + 1;
        storage.put(&today_key, &today_map).await?;
        storage.put("balance", balance).await?;
        storage.put("quota", quota).await?;
        storage.put("total_views", total_views).await?;
        json(
            &ChargeResp {
                charged: true,
                cost,
                balance,
                quota_remaining: quota_remaining(quota),
            },
            200,
        )
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
        if current.as_deref() == Some(plan.id) && period_end > now {
            return Response::error("plan already active", 409);
        }
        let balance: i64 = self.get_or("balance", 0).await?;
        if balance < plan.price_points {
            return Response::error("insufficient balance", 402);
        }
        storage.put("balance", balance - plan.price_points).await?;
        storage.put("plan", plan.id).await?;
        storage.put("quota", plan.quota_points).await?;
        storage.put("period_end", now + plan.period_secs).await?;
        storage.set_alarm((plan.period_secs * 1000) as i64).await?;
        json(&self.status_resp().await?, 200)
    }

    async fn unsubscribe(&self) -> Result<Response> {
        // remaining quota / period_end are left to expire on their own
        self.state.storage().delete("plan").await?;
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
    fn charge_prefers_active_quota_then_balance() {
        assert_eq!(charge_source(true, 5, 100, 5), Some(ChargeSource::Quota));
        // quota too small: fall back to balance even with an active plan
        assert_eq!(charge_source(true, 4, 100, 5), Some(ChargeSource::Balance));
        // inactive plan never uses quota
        assert_eq!(charge_source(false, 100, 5, 5), Some(ChargeSource::Balance));
        assert_eq!(charge_source(false, 100, 4, 5), None);
        assert_eq!(charge_source(true, 0, 0, 1), None);
    }

    #[test]
    fn charge_source_exact_amounts() {
        assert_eq!(charge_source(true, 1, 0, 1), Some(ChargeSource::Quota));
        assert_eq!(charge_source(false, 0, 1, 1), Some(ChargeSource::Balance));
    }

    #[test]
    fn renewal_deducts_or_lapses() {
        assert_eq!(renewal_deduct(1_000, 1_000), Some(0));
        assert_eq!(renewal_deduct(1_500, 1_000), Some(500));
        assert_eq!(renewal_deduct(999, 1_000), None);
    }

    #[test]
    fn view_costs_match_config() {
        assert_eq!(view_cost(MediaKind::Image), config::COST_IMAGE_VIEW);
        assert_eq!(view_cost(MediaKind::Video), config::COST_VIDEO_VIEW);
    }
}
