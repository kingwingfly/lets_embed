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
use worker::{Date, DurableObject, Env, Method, Request, Response, Result, State, durable_object};

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
        ChargeKind::Search => config::COST_SEARCH,
        ChargeKind::EmbedSearch => config::COST_EMBED_SEARCH,
    }
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
            ChargeKind::Search => {
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

    async fn status_resp(&self) -> Result<StatusResp> {
        let now = now_secs();
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active = self.plan_active(now).await?;
        let plan_id: Option<String> = self.state.storage().get("plan").await?;
        let plan_cfg = plan_id.as_deref().and_then(config::plan);
        let (views_remaining, searches_remaining, window_reset) =
            self.window_fields(active, plan_cfg, now).await?;
        Ok(StatusResp {
            address: self.get_or("address", String::new()).await?,
            balance: self.get_or("balance", 0).await?,
            plan: plan_id,
            period_end: if active { period_end } else { 0 },
            views_remaining,
            searches_remaining,
            window_reset,
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

        let active = self.plan_active(now).await?;
        let plan_cfg = if active {
            storage
                .get::<String>("plan")
                .await?
                .as_deref()
                .and_then(config::plan)
        } else {
            None
        };

        let new_day = today.is_none();
        let mut today_map = today.unwrap_or_default();

        // Deduped repeats within the window cost nothing and touch no state; they
        // still report the current window figures.
        if is_recent_view(&req.path, now, [&today_map, &yesterday]) {
            let (views_remaining, searches_remaining, window_reset) =
                self.window_fields(active, plan_cfg, now).await?;
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

        let source = decide_charge(
            plan_cfg, active, req.kind, win_views, win_search, balance, cost,
        );
        if source == ChargeSource::Refuse {
            let views_remaining = views_remaining(plan_cfg, active, win_views);
            let searches_remaining = searches_remaining(plan_cfg, active, win_search);
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
        match source {
            ChargeSource::FreeUnlimited => {} // pro media view: deduct nothing
            ChargeSource::Window => {
                match req.kind {
                    ChargeKind::Search => win_search += 1,
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
        storage.put(&today_key, &today_map).await?;
        storage.put("balance", balance).await?;
        storage.put("total_views", total_views).await?;
        if window_dirty {
            storage
                .put(
                    "win_start",
                    win_start.expect("rolled/active window has a start"),
                )
                .await?;
            storage.put("win_views", win_views).await?;
            storage.put("win_search", win_search).await?;
        }

        let views_remaining = views_remaining(plan_cfg, active, win_views);
        let searches_remaining = searches_remaining(plan_cfg, active, win_search);
        let window_reset = window_reset(active, win_start, now);
        json(
            &ChargeResp {
                charged: true,
                cost,
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
        let balance = (balance + req.points).max(0);
        storage.put("balance", balance).await?;
        storage.put(&marker, true).await?;
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
    async fn subscribe(&self, req: SubscribeReq) -> Result<Response> {
        let Some(target) = config::plan(&req.plan) else {
            return Response::error("unknown plan", 400);
        };
        let storage = self.state.storage();
        let now = now_secs();
        let current: Option<String> = storage.get("plan").await?;
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active = current.is_some() && period_end > now;

        // Refund the unused remainder of the currently active plan (if any).
        let refund = if active {
            current
                .as_deref()
                .and_then(config::plan)
                .map(|cur| prorated_refund(cur.price_points, cur.period_secs, period_end - now))
                .unwrap_or(0)
        } else {
            0
        };

        let balance: i64 = self.get_or("balance", 0).await?;
        // Net cost of the switch: full target price offset by the refund. May be
        // negative when downgrading (the user is credited the difference).
        let net_cost = target.price_points - refund;
        if net_cost > 0 && balance < net_cost {
            return Response::error("insufficient balance", 402);
        }
        let new_balance = (balance - net_cost).max(0);
        // Always a fresh full period from now — never stacks past one period.
        let new_end = now + target.period_secs;

        storage.put("balance", new_balance).await?;
        storage.put("plan", target.id).await?;
        storage.put("period_end", new_end).await?;
        // Reset the usage window on any successful subscribe (new / renew / switch).
        storage.put("win_start", now).await?;
        storage.put("win_views", 0i64).await?;
        storage.put("win_search", 0i64).await?;
        storage
            .set_alarm((new_end.saturating_sub(now) * 1000) as i64)
            .await?;
        json(&self.status_resp().await?, 200)
    }

    /// Cancel the active plan, refunding the unused (prorated) remainder to the
    /// PAYG balance and lapsing to pay-as-you-go immediately. Idempotent: with
    /// no active plan it just clears any stale state and returns 200.
    async fn unsubscribe(&self) -> Result<Response> {
        let storage = self.state.storage();
        let now = now_secs();
        let current: Option<String> = storage.get("plan").await?;
        let period_end: u64 = self.get_or("period_end", 0).await?;
        let active = current.is_some() && period_end > now;

        if active {
            let refund = current
                .as_deref()
                .and_then(config::plan)
                .map(|cur| prorated_refund(cur.price_points, cur.period_secs, period_end - now))
                .unwrap_or(0);
            let balance: i64 = self.get_or("balance", 0).await?;
            storage.put("balance", balance + refund).await?;
        }
        // Lapse to PAYG and close the window (mirrors the alarm's lapse path).
        storage.delete("plan").await?;
        storage.delete("period_end").await?;
        storage.delete("win_start").await?;
        storage.delete("win_views").await?;
        storage.delete("win_search").await?;
        let _ = storage.delete_alarm().await;
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
