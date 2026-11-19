//! Wallet and guest metering in the account Durable Object. Wallet instances own
//! balances, subscriptions and usage. Guest instances enforce the published
//! daily free allowances for a pseudonymous client IP.

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use worker::{Date, DurableObject, Env, Method, Request, Response, Result, State, durable_object};

use crate::types::{
    BalanceResp, BanReq, ChargeKind, ChargeReq, ChargeResp, CreditReq, InitReq, StatusResp,
    SubscribeReq,
};
use crate::{
    config,
    settings::{self, Policy},
};
use site_access::GuestReq;

// ---------------------------------------------------------------------------
// Pure decision logic (host-testable)
// ---------------------------------------------------------------------------

#[cfg(test)]
fn view_cost(kind: ChargeKind) -> i64 {
    Policy::default().item(kind).price
}

/// A repeat charge is free if the key was first seen within the dedupe window.
fn is_recent_view(path: &str, now: u64, maps: [&HashMap<String, u64>; 2]) -> bool {
    let cutoff = now.saturating_sub(config::DEDUPE_WINDOW_SECS);
    maps.iter()
        .any(|m| m.get(path).is_some_and(|&first_seen| first_seen > cutoff))
}

/// Whether a new usage window should be opened: none yet, or the current one has
/// elapsed (`now` reached `win_start + WINDOW_SECS`).
fn should_roll(win_start: Option<u64>, now: u64) -> bool {
    match win_start {
        None => true,
        Some(start) => now >= start + config::WINDOW_SECS,
    }
}

/// Where a (non-deduped) charge draws from once the plan + window are consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChargeSource {
    /// Pro plan media view — unlimited; deduct nothing, just record the view.
    FreeUnlimited,
    /// Draw from the subscription window quota (no balance change).
    Window,
    /// Pay-as-you-go: deduct `cost` from the points balance.
    Balance,
    /// No quota and the balance is too low — refuse (402).
    Refuse,
}

/// Decide how one charge is satisfied given plan, window usage and balance.
/// Pure (plain values + caller-provided window counters) so it is host-testable.
/// `win_views` / `win_search` are the counters for the *current* (already rolled)
/// window.
fn decide_charge(
    plan: Option<&config::Plan>,
    active: bool,
    kind: ChargeKind,
    win_views: i64,
    win_search: i64,
    balance: i64,
    cost: i64,
) -> ChargeSource {
    if active && let Some(plan) = plan {
        match kind {
            // View-class kinds (incl. the cheap by-id embed search) draw from the
            // media view budget; pro's unlimited views cover them for free.
            ChargeKind::Image | ChargeKind::Video | ChargeKind::EmbedSearch => {
                match plan.views_per_window {
                    None => return ChargeSource::FreeUnlimited,
                    Some(limit) => {
                        if win_views + cost <= limit {
                            return ChargeSource::Window;
                        }
                    }
                }
            }
            // The expensive upload-image search draws from the scarce search quota.
            ChargeKind::Search | ChargeKind::Description => {
                if win_search < plan.searches_per_window {
                    return ChargeSource::Window;
                }
            }
        }
    }
    // No plan, or the window quota is exhausted: fall back to PAYG.
    if balance >= cost {
        ChargeSource::Balance
    } else {
        ChargeSource::Refuse
    }
}

/// Remaining media view-units this window; `None` = no active plan or unlimited
/// (pro). `win_views` is the current window's consumed count.
fn views_remaining(plan: Option<&config::Plan>, active: bool, win_views: i64) -> Option<i64> {
    if !active {
        return None;
    }
    plan?
        .views_per_window
        .map(|limit| (limit - win_views).max(0))
}

/// Remaining searches this window; `None` = no active plan.
fn searches_remaining(plan: Option<&config::Plan>, active: bool, win_search: i64) -> Option<i64> {
    if !active {
        return None;
    }
    Some((plan?.searches_per_window - win_search).max(0))
}

/// Points refunded for the unused remainder of a subscription period. The
/// refund is the plan price prorated by the fraction of the period still
/// unspent (floored): `price * remaining / period`. `remaining_secs` is clamped
/// to the period length so it can never over-refund. Pure (host-testable).
fn prorated_refund(price_points: i64, period_secs: u64, remaining_secs: u64) -> i64 {
    if period_secs == 0 {
        return 0;
    }
    let remaining = remaining_secs.min(period_secs);
    ((price_points as i128 * remaining as i128) / period_secs as i128) as i64
}

/// Epoch secs when the current window resets; 0 = no active/open window.
fn window_reset(active: bool, win_start: Option<u64>, now: u64) -> u64 {
    match win_start {
        Some(start) if active && now < start + config::WINDOW_SECS => start + config::WINDOW_SECS,
        _ => 0,
    }
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
    env: Env,
}

impl DurableObject for UserAccount {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        let policy = settings::load(&self.env).await?;
        match (req.method(), path.as_str()) {
            (Method::Post, "/init") => self.init(req.json().await?, &policy).await,
            (Method::Post, "/charge") => self.charge(req.json().await?, &policy, false).await,
            (Method::Post, "/can-charge") => self.charge(req.json().await?, &policy, true).await,
            (Method::Post, "/credit") => self.credit(req.json().await?).await,
            (Method::Get, "/status") => json(&self.status_resp(&policy).await?, 200),
            (Method::Post, "/subscribe") => self.subscribe(req.json().await?, &policy).await,
            (Method::Post, "/unsubscribe") => self.unsubscribe(&policy).await,
            (Method::Post, "/ban") => self.ban(req.json().await?, &policy).await,
            (Method::Post, "/guest") => self.guest(req.json().await?, &policy),
            (Method::Post, "/admin-plan") => self.admin_plan(req.json().await?, &policy).await,
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
        // period elapsed: no auto-renew — lapse to PAYG and close the window so a
        // lapsed account reports `None` for views/searches.
        storage.delete("plan").await?;
        storage.delete("win_start").await?;
        storage.delete("win_views").await?;
        storage.delete("win_search").await?;
        Response::ok("")
    }
}

impl UserAccount {
    async fn write_fields(&self, fields: serde_json::Value) -> Result<()> {
        // DO multi-put takes a plain JS object. BigInt preserves exact i64 balances.
        let serializer = serde_wasm_bindgen::Serializer::new()
            .serialize_maps_as_objects(true)
            .serialize_large_number_types_as_bigints(true);
        let object = serde::Serialize::serialize(&fields, &serializer)?;
        self.state.storage().put_multiple_raw(object.into()).await
    }

    // Refund the historical price actually paid. Legacy subscriptions were
    // sold at the compile-time price. Admin-granted periods have zero basis.
    async fn refund(&self, id: Option<&str>, end: u64, now: u64) -> Result<i64> {
        let Some(plan) = id.and_then(config::plan).filter(|_| end > now) else {
            return Ok(0);
        };
        let paid = self.get_or("plan_paid", plan.price_points).await?;
        Ok(prorated_refund(paid, plan.period_secs, end - now))
    }

    fn free_item(&self, req: &ChargeReq, limit: i64, day: u64, check_only: bool) -> Result<bool> {
        if limit == 0 {
            return Ok(false);
        }
        if limit < 0 {
            return Ok(true);
        }
        // Synchronous DO SQLite calls complete before another request can enter.
        // Store single resource hashes rather than an ever-growing KV value.
        use sha2::{Digest, Sha256};
        #[derive(serde::Deserialize)]
        struct Usage {
            seen: i64,
            used: i64,
        }
        let db = self.state.storage().sql();
        db.exec("CREATE TABLE IF NOT EXISTS free_usage (day INTEGER,kind TEXT,resource BLOB, PRIMARY KEY(day,kind,resource)) WITHOUT ROWID",None)?;
        if !check_only {
            db.exec(
                "DELETE FROM free_usage WHERE day < ?",
                vec![(day as i64).into()],
            )?;
        }
        let hash = Sha256::digest(req.path.as_bytes()).to_vec();
        let kind = req.kind.name();
        let used:Usage=db.exec("SELECT EXISTS(SELECT 1 FROM free_usage WHERE day=?1 AND kind=?2 AND resource=?3) AS seen, COUNT(*) AS used FROM free_usage WHERE day=?1 AND kind=?2",
            vec![(day as i64).into(),kind.into(),hash.clone().into()])?.one()?;
        if used.seen != 0 {
            return Ok(true);
        }
        if used.used >= limit {
            return Ok(false);
        }
        if !check_only {
            db.exec(
                "INSERT INTO free_usage VALUES(?,?,?)",
                vec![(day as i64).into(), kind.into(), hash.into()],
            )?;
        }
        Ok(true)
    }

    fn guest(&self, req: GuestReq, policy: &Policy) -> Result<Response> {
        if policy.login_required {
            return Response::error("Login required", 401);
        }
        if let Some(item) = req.item {
            let limit = policy.item(item.kind).daily_free;
            if !policy.free_media_in_scope(&item)
                || !self.free_item(&item, limit, now_secs() / 86_400, req.head)?
            {
                return Response::error(
                    "Sign in to access this item or continue beyond the daily free allowance",
                    402,
                );
            }
        }
        Response::ok("")
    }

    async fn admin_plan(
        &self,
        req: crate::types::AdminPlanReq,
        policy: &Policy,
    ) -> Result<Response> {
        let storage = self.state.storage();
        let marker = format!("admin-plan:{}", req.token);
        if storage.get::<bool>(&marker).await?.is_some() {
            return json(&self.status_resp(policy).await?, 200);
        }
        let now = now_secs();
        let (id, end) = match req.plan.as_str() {
            "none" => ("", 0),
            id => match policy.plan(id) {
                Some(p) if (1..=3650).contains(&req.days) => {
                    (p.id, now + u64::from(req.days) * 86_400)
                }
                _ => return Response::error("Unknown plan", 400),
            },
        };
        let current: Option<String> = storage.get("plan").await?;
        let previous_end = self.get_or("period_end", 0).await?;
        let refund = self.refund(current.as_deref(), previous_end, now).await?;
        let balance: i64 = self.get_or("balance", 0).await?;
        self.write_fields(
            serde_json::json!({"plan":id,"period_end":end,"plan_paid":0,"win_start":now,
            "win_views":0,"win_search":0,"balance":balance.saturating_add(refund),(marker):true}),
        )
        .await?;
        if end > now {
            storage.set_alarm(((end - now) * 1000) as i64).await?;
        } else {
            storage.delete("plan").await?;
            storage.delete_alarm().await?;
        }
        json(&self.status_resp(policy).await?, 200)
    }

    async fn get_or<T: DeserializeOwned>(&self, key: &str, default: T) -> Result<T> {
        Ok(self.state.storage().get(key).await?.unwrap_or(default))
    }

    /// First touch of a brand-new account: grant the free points.
    async fn ensure_init(&self, policy: &Policy) -> Result<()> {
        let storage = self.state.storage();
        if storage.get::<bool>("init").await?.is_none() {
            self.write_fields(serde_json::json!({"init":true, "balance": policy.signup_points}))
                .await?;
        }
        Ok(())
    }

    /// Whether a subscription period is currently active.
    async fn plan_active(&self, now: u64) -> Result<bool> {
        let period_end: u64 = self.get_or("period_end", 0).await?;
        Ok(self.state.storage().get::<String>("plan").await?.is_some() && period_end > now)
    }

    /// Report the current window's remaining view/search quota and reset time
    /// from stored state, WITHOUT rolling/persisting. An elapsed (or never
    /// opened) window reports a fresh window: full quota, `window_reset == 0`.
    async fn window_fields(
        &self,
        active: bool,
        plan: Option<&config::Plan>,
        now: u64,
    ) -> Result<(Option<i64>, Option<i64>, u64)> {
        let win_start: Option<u64> = self.state.storage().get("win_start").await?;
        let open = active && !should_roll(win_start, now);
        let (win_views, win_search) = if open {
            (
                self.get_or("win_views", 0).await?,
                self.get_or("win_search", 0).await?,
            )
        } else {
            (0, 0)
        };
        Ok((
            views_remaining(plan, active, win_views),
            searches_remaining(plan, active, win_search),
            window_reset(active, win_start, now),
        ))
    }

    async fn status_resp(&self, policy: &Policy) -> Result<StatusResp> {
        let now = now_secs();
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active = self.plan_active(now).await?;
        let plan_id: Option<String> = self.state.storage().get("plan").await?;
        let plan_cfg = plan_id.as_deref().and_then(|id| policy.plan(id));
        let (views_remaining, searches_remaining, window_reset) =
            self.window_fields(active, plan_cfg.as_ref(), now).await?;
        Ok(StatusResp {
            address: self.get_or("address", String::new()).await?,
            balance: self.get_or("balance", 0).await?,
            plan: plan_id.filter(|_| active),
            period_end: if active { period_end } else { 0 },
            views_remaining,
            searches_remaining,
            window_reset,
            banned: self.get_or("banned", false).await?,
            total_views: self.get_or("total_views", 0).await?,
        })
    }

    async fn init(&self, req: InitReq, policy: &Policy) -> Result<Response> {
        self.ensure_init(policy).await?;
        self.state.storage().put("address", &req.address).await?;
        json(&self.status_resp(policy).await?, 200)
    }

    async fn charge(&self, req: ChargeReq, policy: &Policy, check_only: bool) -> Result<Response> {
        if !check_only {
            self.ensure_init(policy).await?;
        }
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

        let rule = policy.item(req.kind);
        let cost = rule.price;
        // A first GET receives the signup grant. A HEAD can evaluate it without creating a wallet.
        let mut balance: i64 = match storage.get("balance").await? {
            Some(balance) => balance,
            None if check_only && storage.get::<bool>("init").await?.is_none() => {
                policy.signup_points
            }
            None => 0,
        };

        let active = self.plan_active(now).await?;
        let plan_cfg = if active {
            storage
                .get::<String>("plan")
                .await?
                .as_deref()
                .and_then(|id| policy.plan(id))
        } else {
            None
        };

        let new_day = today.is_none();
        let mut today_map = today.unwrap_or_default();

        // Deduped repeats within the window cost nothing and touch no state; they
        // still report the current window figures.
        if is_recent_view(&req.path, now, [&today_map, &yesterday]) {
            let (views_remaining, searches_remaining, window_reset) =
                self.window_fields(active, plan_cfg.as_ref(), now).await?;
            return json(
                &ChargeResp {
                    charged: false,
                    cost,
                    balance,
                    views_remaining,
                    searches_remaining,
                    window_reset,
                },
                200,
            );
        }

        // Roll the usage window if the plan is active and the current one elapsed
        // (or was never opened).
        let mut win_start: Option<u64> = storage.get("win_start").await?;
        let mut win_views: i64 = self.get_or("win_views", 0).await?;
        let mut win_search: i64 = self.get_or("win_search", 0).await?;
        let mut window_dirty = false;
        if active && should_roll(win_start, now) {
            win_start = Some(now);
            win_views = 0;
            win_search = 0;
            window_dirty = true;
        }

        let included = cost == 0
            || (policy.free_media_in_scope(&req)
                && self.free_item(&req, rule.daily_free, day, check_only)?);
        let source = if included {
            ChargeSource::FreeUnlimited
        } else {
            decide_charge(
                plan_cfg.as_ref(),
                active,
                req.kind,
                win_views,
                win_search,
                balance,
                cost,
            )
        };
        if source == ChargeSource::Refuse {
            let views_remaining = views_remaining(plan_cfg.as_ref(), active, win_views);
            let searches_remaining = searches_remaining(plan_cfg.as_ref(), active, win_search);
            let window_reset = window_reset(active, win_start, now);
            return json(
                &ChargeResp {
                    charged: false,
                    cost,
                    balance,
                    views_remaining,
                    searches_remaining,
                    window_reset,
                },
                402,
            );
        }
        if check_only {
            return Response::ok("");
        }
        match source {
            ChargeSource::FreeUnlimited => {} // pro media view: deduct nothing
            ChargeSource::Window => {
                match req.kind {
                    ChargeKind::Search | ChargeKind::Description => win_search += 1,
                    ChargeKind::Image | ChargeKind::Video | ChargeKind::EmbedSearch => {
                        win_views += cost
                    }
                }
                window_dirty = true;
            }
            ChargeSource::Balance => balance -= cost,
            ChargeSource::Refuse => unreachable!("handled above"),
        }

        if new_day {
            // drop the map that fell out of the dedupe horizon (bounded storage)
            storage.delete(&format!("seen:{}", day - 2)).await?;
        }
        today_map.insert(req.path, now);
        let total_views: i64 = self.get_or("total_views", 0).await? + 1;
        let mut fields = serde_json::json!({(today_key): today_map, "balance":balance, "total_views":total_views});
        if window_dirty {
            fields["win_start"] = win_start.expect("active window has a start").into();
            fields["win_views"] = win_views.into();
            fields["win_search"] = win_search.into();
        }
        self.write_fields(fields).await?;

        let views_remaining = views_remaining(plan_cfg.as_ref(), active, win_views);
        let searches_remaining = searches_remaining(plan_cfg.as_ref(), active, win_search);
        let window_reset = window_reset(active, win_start, now);
        json(
            &ChargeResp {
                charged: !included,
                cost: if included { 0 } else { cost },
                balance,
                views_remaining,
                searches_remaining,
                window_reset,
            },
            200,
        )
    }

    async fn credit(&self, req: CreditReq) -> Result<Response> {
        let storage = self.state.storage();
        let marker = format!("credit:{}", req.key);
        let balance: i64 = self.get_or("balance", 0).await?;
        if storage.get::<bool>(&marker).await?.is_some() {
            return json(
                &BalanceResp {
                    balance,
                    applied: false,
                },
                200,
            );
        }
        let balance = balance.saturating_add(req.points).max(0);
        self.write_fields(serde_json::json!({"balance":balance, (marker):true}))
            .await?;
        json(
            &BalanceResp {
                balance,
                applied: true,
            },
            200,
        )
    }

    /// Subscribe to / renew / switch plans. Any currently active plan is
    /// prorated: its unused remainder is refunded, and the target plan is then
    /// bought for a fresh full period. So the active period is always *at most*
    /// one plan period (30d) — clicking Subscribe repeatedly no longer stacks
    /// days — and switching (upgrade/downgrade/renew) only charges the
    /// difference net of the refund. A pure renew (same plan) costs ~0 net.
    async fn subscribe(&self, req: SubscribeReq, policy: &Policy) -> Result<Response> {
        let Some(target) = policy.plan(&req.plan) else {
            return Response::error("unknown plan", 400);
        };
        if req
            .expected_price
            .is_some_and(|price| price != target.price_points)
        {
            return Response::error(
                "Plan price changed. Reload your account to review the current price.",
                409,
            );
        }
        let storage = self.state.storage();
        let now = now_secs();
        let current: Option<String> = storage.get("plan").await?;
        let period_end: u64 = self.get_or("period_end", 0).await?;

        let refund = self.refund(current.as_deref(), period_end, now).await?;

        let balance: i64 = self.get_or("balance", 0).await?;
        // Net cost of the switch: full target price offset by the refund. May be
        // negative when downgrading (the user is credited the difference).
        let net_cost = target.price_points - refund;
        if net_cost > 0 && balance < net_cost {
            return Response::error("insufficient balance", 402);
        }
        let new_balance = balance.saturating_sub(net_cost).max(0);
        // Always a fresh full period from now — never stacks past one period.
        let new_end = now + target.period_secs;

        self.write_fields(serde_json::json!({"balance":new_balance, "plan":target.id,
            "period_end":new_end, "plan_paid":target.price_points, "win_start":now, "win_views":0,"win_search":0})).await?;
        storage
            .set_alarm((new_end.saturating_sub(now) * 1000) as i64)
            .await?;
        json(&self.status_resp(policy).await?, 200)
    }

    /// Cancel the active plan, refunding the unused (prorated) remainder to the
    /// PAYG balance and lapsing to pay-as-you-go immediately. Idempotent: with
    /// no active plan it just clears any stale state and returns 200.
    async fn unsubscribe(&self, policy: &Policy) -> Result<Response> {
        let storage = self.state.storage();
        let now = now_secs();
        let current: Option<String> = storage.get("plan").await?;
        let period_end: u64 = self.get_or("period_end", 0).await?;

        let refund = self.refund(current.as_deref(), period_end, now).await?;
        let balance: i64 = self.get_or("balance", 0).await?;
        self.write_fields(
            serde_json::json!({"balance":balance.saturating_add(refund), "period_end":0,
            "plan_paid":0,"win_start":0,"win_views":0,"win_search":0}),
        )
        .await?;
        storage.delete("plan").await?;
        let _ = storage.delete_alarm().await;
        json(&self.status_resp(policy).await?, 200)
    }

    async fn ban(&self, req: BanReq, policy: &Policy) -> Result<Response> {
        self.state.storage().put("banned", req.banned).await?;
        json(&self.status_resp(policy).await?, 200)
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
        assert!(!is_recent_view(
            "/images/new.webp",
            NOW,
            [&empty, &yesterday]
        ));
        // first_seen exactly at the cutoff is no longer free
        assert!(!is_recent_view(
            "/images/old.webp",
            NOW,
            [&empty, &yesterday]
        ));
    }

    #[test]
    fn view_costs_match_config() {
        assert_eq!(view_cost(ChargeKind::Image), config::COST_IMAGE_VIEW);
        assert_eq!(view_cost(ChargeKind::Video), config::COST_VIDEO_VIEW);
        assert_eq!(view_cost(ChargeKind::Search), config::COST_SEARCH);
        assert_eq!(
            view_cost(ChargeKind::EmbedSearch),
            config::COST_EMBED_SEARCH
        );
    }

    fn basic() -> &'static config::Plan {
        config::plan("basic").expect("basic plan")
    }
    fn pro() -> &'static config::Plan {
        config::plan("pro").expect("pro plan")
    }

    #[test]
    fn prorated_refund_matches_examples() {
        let day = 86_400u64;
        let basic_price = basic().price_points; // 20_000 over 30d
        let pro_price = pro().price_points; // 50_000 over 30d
        let period = basic().period_secs; // 30d (same for both)

        // Used 15 of 30 days of basic → 10_000 unused refund (the "off" on an upgrade).
        assert_eq!(prorated_refund(basic_price, period, 15 * day), 10_000);
        // Used 15 of 30 days of pro → 25_000 back on unsubscribe.
        assert_eq!(prorated_refund(pro_price, period, 15 * day), 25_000);
        // Boundaries: brand-new period refunds ~full; fully-spent refunds 0.
        assert_eq!(prorated_refund(pro_price, period, period), pro_price);
        assert_eq!(prorated_refund(pro_price, period, 0), 0);
        // Over-long remaining is clamped to the period (never over-refunds).
        assert_eq!(
            prorated_refund(pro_price, period, period + 999 * day),
            pro_price
        );
        // Degenerate period never divides by zero.
        assert_eq!(prorated_refund(pro_price, 0, day), 0);
    }

    #[test]
    fn should_roll_unset_or_elapsed() {
        assert!(should_roll(None, NOW));
        assert!(should_roll(Some(NOW), NOW + config::WINDOW_SECS));
        assert!(should_roll(Some(NOW), NOW + config::WINDOW_SECS + 1));
        assert!(!should_roll(Some(NOW), NOW));
        assert!(!should_roll(Some(NOW), NOW + config::WINDOW_SECS - 1));
    }

    #[test]
    fn pro_media_views_are_free_unlimited() {
        let c = view_cost(ChargeKind::Image);
        assert_eq!(
            decide_charge(Some(pro()), true, ChargeKind::Image, 0, 0, 0, c),
            ChargeSource::FreeUnlimited
        );
        // still free with a huge accumulated count and zero balance
        assert_eq!(
            decide_charge(Some(pro()), true, ChargeKind::Video, 1_000_000, 0, 0, c),
            ChargeSource::FreeUnlimited
        );
    }

    #[test]
    fn basic_media_within_window_consumes_quota() {
        let c = view_cost(ChargeKind::Image);
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Image, 0, 0, 0, c),
            ChargeSource::Window
        );
        // exactly at the limit boundary (limit - cost) still fits
        let limit = basic().views_per_window.unwrap();
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Image, limit - c, 0, 0, c),
            ChargeSource::Window
        );
    }

    #[test]
    fn basic_media_exhausted_falls_back_to_balance_then_refuses() {
        let c = view_cost(ChargeKind::Video);
        let limit = basic().views_per_window.unwrap();
        // window full: fall back to PAYG when the balance covers it
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Video, limit, 0, 100, c),
            ChargeSource::Balance
        );
        // window full AND broke: refuse
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Video, limit, 0, c - 1, c),
            ChargeSource::Refuse
        );
    }

    #[test]
    fn search_uses_window_then_payg() {
        let c = view_cost(ChargeKind::Search);
        let limit = basic().searches_per_window;
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Search, 0, 0, 0, c),
            ChargeSource::Window
        );
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Search, 0, limit - 1, 0, c),
            ChargeSource::Window
        );
        // window searches exhausted: PAYG if funded, else refuse
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Search, 0, limit, c, c),
            ChargeSource::Balance
        );
        assert_eq!(
            decide_charge(Some(basic()), true, ChargeKind::Search, 0, limit, c - 1, c),
            ChargeSource::Refuse
        );
    }

    #[test]
    fn embed_search_is_view_class_not_search_quota() {
        let c = view_cost(ChargeKind::EmbedSearch);
        assert_eq!(c, config::COST_EMBED_SEARCH);
        // cheaper than the inference search
        assert!(c < view_cost(ChargeKind::Search));
        // pro's unlimited views cover it for free (does not touch search quota)
        assert_eq!(
            decide_charge(
                Some(pro()),
                true,
                ChargeKind::EmbedSearch,
                0,
                pro().searches_per_window,
                0,
                c
            ),
            ChargeSource::FreeUnlimited
        );
        // basic draws it from the VIEW window (win_views), regardless of search usage
        let vlimit = basic().views_per_window.unwrap();
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::EmbedSearch,
                vlimit - c,
                basic().searches_per_window,
                0,
                c
            ),
            ChargeSource::Window
        );
        // view window exhausted → PAYG, even though search slots remain
        assert_eq!(
            decide_charge(
                Some(basic()),
                true,
                ChargeKind::EmbedSearch,
                vlimit,
                0,
                c,
                c
            ),
            ChargeSource::Balance
        );
    }

    #[test]
    fn no_plan_is_payg_for_all_kinds() {
        for kind in [
            ChargeKind::Image,
            ChargeKind::Video,
            ChargeKind::Search,
            ChargeKind::EmbedSearch,
        ] {
            let c = view_cost(kind);
            assert_eq!(
                decide_charge(None, false, kind, 0, 0, c, c),
                ChargeSource::Balance
            );
            assert_eq!(
                decide_charge(None, false, kind, 0, 0, c - 1, c),
                ChargeSource::Refuse
            );
        }
        // an inactive plan behaves like no plan
        assert_eq!(
            decide_charge(Some(basic()), false, ChargeKind::Image, 0, 0, 1, 1),
            ChargeSource::Balance
        );
    }

    #[test]
    fn remaining_reflects_plan_and_usage() {
        // no active plan → None
        assert_eq!(views_remaining(None, false, 0), None);
        assert_eq!(searches_remaining(None, false, 0), None);
        // pro views unlimited → None; searches still counted
        assert_eq!(views_remaining(Some(pro()), true, 5), None);
        assert_eq!(
            searches_remaining(Some(pro()), true, 3),
            Some(pro().searches_per_window - 3)
        );
        // basic clamps at zero, never negative
        let vlimit = basic().views_per_window.unwrap();
        assert_eq!(
            views_remaining(Some(basic()), true, 100),
            Some(vlimit - 100)
        );
        assert_eq!(views_remaining(Some(basic()), true, vlimit + 50), Some(0));
        assert_eq!(
            searches_remaining(Some(basic()), true, basic().searches_per_window + 5),
            Some(0)
        );
    }

    #[test]
    fn window_reset_zero_unless_active_and_open() {
        assert_eq!(window_reset(false, Some(NOW), NOW), 0);
        assert_eq!(window_reset(true, None, NOW), 0);
        assert_eq!(
            window_reset(true, Some(NOW), NOW),
            NOW + config::WINDOW_SECS
        );
        // elapsed window is no longer open
        assert_eq!(window_reset(true, Some(NOW), NOW + config::WINDOW_SECS), 0);
    }
}
