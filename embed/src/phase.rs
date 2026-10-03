//! Where images are in the pipeline: how many are in each phase, and how long they stay.
//!
//! A [`Tracker`] travels with each image next to its `Ticket`, from the claim to the end of
//! `record`'s write. The phases cover all of that time, so the images in them add up to the
//! gate's `in_flight`, and during a stall the phase holding the images stands out: its count
//! grows while few leave it.

use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

use opentelemetry::{
    KeyValue, global,
    metrics::{Histogram, UpDownCounter},
};

/// A part of an image's way through the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// claimed by `fetch_batch`: the claim query, then the hand-off to `convert_image`
    Claim,
    /// read from storage, retries included
    Download,
    /// downloaded, waiting for a decoding slot
    DecodeQueue,
    /// decoded and resized for the three models
    Decode,
    /// decoded, waiting for the device
    InferQueue,
    /// in a batch on the device
    Infer,
    /// inferred, waiting for `record` to start a write
    RecordQueue,
    /// in a write to the database
    Write,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Claim => "claim",
            Phase::Download => "download",
            Phase::DecodeQueue => "decode_queue",
            Phase::Decode => "decode",
            Phase::InferQueue => "infer_queue",
            Phase::Infer => "infer",
            Phase::RecordQueue => "record_queue",
            Phase::Write => "write",
        }
    }

    fn attributes(self) -> [KeyValue; 1] {
        [KeyValue::new("phase", self.name())]
    }
}

struct Meters {
    items: UpDownCounter<i64>,
    duration: Histogram<f64>,
}

static METERS: LazyLock<Meters> = LazyLock::new(|| {
    let meter = global::meter("embed");
    Meters {
        items: meter
            .i64_up_down_counter("embed.items")
            .with_description("images in each phase of the pipeline")
            .build(),
        duration: meter
            .f64_histogram("embed.phase.duration")
            .with_description("time an image spent in a phase")
            .with_unit("s")
            // from a batch on the device to a download retried for minutes
            .with_boundaries(vec![
                0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0,
                300.0,
            ])
            .build(),
    }
});

/// One image's place in the [`Phase`]s.
///
/// Dropping it takes the image out of its phase, so an image lost to an error or a panic stops
/// counting, as its dropped ticket returns its permits.
#[derive(Debug)]
pub struct Tracker {
    phase: Phase,
    since: Instant,
}

impl Tracker {
    /// Start counting an image in `phase`.
    pub fn new(phase: Phase) -> Self {
        METERS.items.add(1, &phase.attributes());
        Self {
            phase,
            since: Instant::now(),
        }
    }

    /// Move the image on to `next`.
    pub fn enter(&mut self, next: Phase) {
        let now = Instant::now();
        self.leave(now.duration_since(self.since));
        METERS.items.add(1, &next.attributes());
        self.phase = next;
        self.since = now;
    }

    /// Record the time spent in the current phase, and stop counting the image in it.
    fn leave(&self, stay: Duration) {
        let attributes = self.phase.attributes();
        METERS.duration.record(stay.as_secs_f64(), &attributes);
        METERS.items.add(-1, &attributes);
    }
}

impl Drop for Tracker {
    fn drop(&mut self) {
        self.leave(self.since.elapsed());
    }
}
