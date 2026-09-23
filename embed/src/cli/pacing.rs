//! Admission pacing: shared counters, interval sampling, and the in-flight limit policy.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use tokio::{sync::Semaphore, time::MissedTickBehavior};

/// Counters sampled by `pace_in_flight`
pub(super) struct Pace {
    /// images `record` marked completed, i.e. useful pipeline throughput
    completed: AtomicU64,
    /// time `infer` spent waiting for input (i.e. the device starving), and when its current
    /// wait began; one lock so a reading never counts a wait twice or goes backwards
    infer_idle: Mutex<(Duration, Option<Instant>)>,
    /// permits still to retire for a shrink the pacer couldn't apply to idle permits
    retiring: AtomicUsize,
}

impl Pace {
    pub(super) fn new() -> Self {
        Self {
            completed: AtomicU64::default(),
            infer_idle: Mutex::new((Duration::ZERO, None)),
            retiring: AtomicUsize::default(),
        }
    }

    pub(super) fn add_completed(&self, images: usize) {
        self.completed.fetch_add(images as u64, Relaxed);
    }

    /// Put `n` permits (back) into circulation, first retiring any the pacer asked to drop
    pub(super) fn release(&self, in_flight: &Semaphore, n: usize) {
        let retired = self
            .retiring
            .try_update(Relaxed, Relaxed, |r| Some(r - r.min(n)))
            .map_or(0, |r| r.min(n));
        in_flight.add_permits(n - retired);
    }

    /// Resize the eventual limit; permits still held by images retire as they return.
    fn resize(&self, in_flight: &Semaphore, current: usize, target: usize) {
        if target > current {
            // Cancel pending retirements before adding permits.
            self.release(in_flight, target - current);
        } else if target < current {
            // A waiting fetcher can take returned permits before they ever become idle.
            let shrink = current - target;
            let forgotten = in_flight.forget_permits(shrink);
            self.retiring.fetch_add(shrink - forgotten, Relaxed);
        }
    }

    pub(super) fn infer_idle_start(&self) {
        self.infer_idle.lock().1 = Some(Instant::now());
    }

    pub(super) fn infer_idle_end(&self) {
        let (total, since) = &mut *self.infer_idle.lock();
        if let Some(since) = since.take() {
            *total += since.elapsed();
        }
    }

    /// Total time `infer` has spent waiting for input, including a wait still in progress
    fn infer_idle(&self) -> Duration {
        let (total, since) = *self.infer_idle.lock();
        total + since.map_or(Duration::ZERO, |since| since.elapsed())
    }
}

/// The in-flight limit to start from, and the lowest `pace_in_flight` shrinks it to; the
/// semaphore must start with exactly this many permits.
pub(super) fn min_in_flight(batch_size: usize) -> usize {
    2 * batch_size
}

/// Sample, decide, and apply the in-flight limit once per tick.
#[tracing::instrument(skip_all)]
pub(super) async fn pace_in_flight(
    in_flight: Arc<Semaphore>,
    pace: Arc<Pace>,
    batch_size: usize,
    max_drain: Duration,
) {
    let now = Instant::now();
    let mut sampler = PaceSampler::new(now);
    let mut controller = InFlightController::new(batch_size, max_drain, now);
    let mut limit = controller.floor;
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    // After a stall, don't fire catch-up ticks with near-zero elapsed time.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let sample = sampler.sample(&pace, &in_flight, limit, Instant::now());
        let target = controller.decide(limit, &sample);
        pace.resize(&in_flight, limit, target);
        limit = target;
    }
}

/// Counter deltas and admission occupancy for one sampling interval.
struct PaceSample {
    at: Instant,
    elapsed: Duration,
    completed: u64,
    infer_idle: Duration,
    used: usize,
}

struct PaceSampler {
    last: Instant,
    completed: u64,
    infer_idle: Duration,
}

impl PaceSampler {
    fn new(now: Instant) -> Self {
        Self {
            last: now,
            completed: 0,
            infer_idle: Duration::ZERO,
        }
    }

    fn sample(
        &mut self,
        pace: &Pace,
        in_flight: &Semaphore,
        limit: usize,
        now: Instant,
    ) -> PaceSample {
        let completed = pace.completed.load(Relaxed);
        let infer_idle = pace.infer_idle();
        // Pending retirements still circulate until their images finish.
        let used =
            (limit + pace.retiring.load(Relaxed)).saturating_sub(in_flight.available_permits());
        let sample = PaceSample {
            at: now,
            elapsed: now.duration_since(self.last),
            completed: completed - self.completed,
            infer_idle: infer_idle.saturating_sub(self.infer_idle),
            used,
        };

        self.last = now;
        self.completed = completed;
        self.infer_idle = infer_idle;
        sample
    }
}

/// Size the in-flight limit (images claimed but not yet recorded) from two direct signals,
/// rather than from modeled service times, so waits no stage accounts for can't trap it:
///
/// - growth: while the device waits for input and admission uses the whole limit, the limit
///   isn't enough to cover storage latency, so it doubles;
/// - drain bound: by Little's law an image stays `in flight / throughput` in the pipeline, which
///   is also about how long a SIGINT drain takes. While downloads are the bottleneck that time
///   stays flat as the limit grows; once something saturates, it rises. The limit therefore
///   stops growing, and shrinks, where that time would pass `max(max_drain, 1.5 × the fastest
///   observed)`.
///
/// This policy uses only samples and an explicit clock, so it can be exercised without
/// running the pipeline or changing semaphore permits.
struct InFlightController {
    floor: usize,
    max_drain: Duration,
    /// Completed images/s, exponentially smoothed.
    throughput: f64,
    /// Lowest observed residence in seconds, slowly decayed to follow lasting slowdowns.
    fastest: f64,
    /// Hold decisions until newly admitted images have had time to complete.
    settle_until: Instant,
}

impl InFlightController {
    const HEADROOM: f64 = 1.5;
    /// limit multiplier per growth step
    const GROWTH: f64 = 2.0;
    const SMOOTHING: f64 = 0.5;
    /// share of the tick the device may wait for input before the limit grows
    const STARVING: f64 = 0.1;
    /// the fastest residence decays upward by this per tick, to follow a lasting slowdown
    const FASTEST_DECAY: f64 = 1.05;
    /// sanity bound on claimed rows and buffered downloads
    const MAX_IN_FLIGHT: usize = 1024;
    const MAX_SETTLE: Duration = Duration::from_secs(30);

    fn new(batch_size: usize, max_drain: Duration, now: Instant) -> Self {
        Self {
            floor: min_in_flight(batch_size),
            max_drain,
            throughput: 0.0,
            fastest: f64::INFINITY,
            settle_until: now,
        }
    }

    fn decide(&mut self, limit: usize, sample: &PaceSample) -> usize {
        let elapsed = sample.elapsed.as_secs_f64();
        let throughput = sample.completed as f64 / elapsed;
        self.throughput += Self::SMOOTHING * (throughput - self.throughput);
        let starving = sample.infer_idle.as_secs_f64() / elapsed > Self::STARVING;
        let residence = match self.throughput > 0.0 {
            true => sample.used as f64 / self.throughput,
            false => f64::INFINITY,
        };
        let saturated = sample.used * 10 >= limit * 9;
        // sample only while admission uses the whole limit: a near-empty pipeline (idle table,
        // tail of a run) shows a short residence that says nothing about per-image latency
        if saturated && residence.is_finite() {
            self.fastest = (self.fastest * Self::FASTEST_DECAY).min(residence);
        }
        let drain_bound = self
            .max_drain
            .as_secs_f64()
            .max(self.fastest * Self::HEADROOM);

        let target = if sample.at < self.settle_until {
            limit
        } else if residence > drain_bound {
            // draining would take too long (or nothing completes): keep what finishes in time
            (self.throughput * drain_bound) as usize
        } else if starving && saturated && self.throughput > 0.0 {
            // the device waits while admission uses the whole limit; growth also needs images
            // to be completing, or a storage outage (or startup) would grow it while every
            // claimed image fails and burns one of its attempts
            (limit as f64 * Self::GROWTH).ceil() as usize
        } else {
            limit
        }
        // `clamp` panics if min > max, i.e. with a floor above the cap (batch size > 512)
        .clamp(self.floor, Self::MAX_IN_FLIGHT.max(self.floor));
        if target != limit {
            self.settle_until = sample.at
                + Duration::from_secs_f64(self.fastest.min(Self::MAX_SETTLE.as_secs_f64()));
        }
        tracing::debug!(
            throughput = self.throughput,
            residence,
            starving,
            used = sample.used,
            limit,
            target,
            "in-flight limit"
        );

        target
    }
}
