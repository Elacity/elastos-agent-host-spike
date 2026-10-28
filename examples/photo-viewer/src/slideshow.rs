// Built-by: deepseek-v4.1-flash-1017-ultrafast
//! Slideshow scheduling (slice P11).
//!
//! A `Slideshow` walks a caller-supplied `order` of `Cid`s, dwelling on each
//! for `interval_ms`, and wrapping back to the first item after the last. The
//! clock is injected (`Clock`), so the schedule is deterministic and the guest
//! never reads wall time itself. `tick(now)` advances the current index by the
//! number of whole intervals that elapsed since the last tick, `pause` and
//! `resume` stop and restart the dwell timer without losing position.
//!
//! Two states are refused at construction, never silently accepted:
//! `empty-album` (nothing to show) and `interval-too-short` (dwell under
//! `MIN_INTERVAL_MS`). Both carry a stable reason string for the playlist
//! surface to report verbatim.
//!
//! SEAM: `Cid`, `Clock` and `SlideshowError` are new lab types defined here;
//! no such seam was shown, and no existing enum is extended.

use std::fmt;

/// Smallest dwell the slideshow accepts. Below this the person cannot see the
/// frame, so construction is refused with `interval-too-short`.
pub const MIN_INTERVAL_MS: u64 = 500;
/// Default dwell when the caller does not choose one.
pub const DEFAULT_INTERVAL_MS: u64 = 5_000;

/// A content id, the identity Runtime uses to name bytes without reading
/// them. Kept as an opaque wrapper so ordering and equality are unambiguous.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cid(pub String);

impl Cid {
    pub fn new(value: impl Into<String>) -> Self {
        Cid(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Injected time source. The guest supplies a fake in tests and the host
/// supplies a real one in production; the module never calls `Instant::now`.
pub trait Clock {
    /// Milliseconds since an arbitrary origin. Monotonic.
    fn now_ms(&self) -> u64;
}

/// Why a slideshow could not be built or advanced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlideshowError {
    /// The album named no images.
    EmptyAlbum,
    /// The dwell was under `MIN_INTERVAL_MS`.
    IntervalTooShort { interval_ms: u64 },
}

impl SlideshowError {
    /// Stable reason string reported to the playlist surface.
    pub fn reason(&self) -> &'static str {
        match self {
            SlideshowError::EmptyAlbum => "empty-album",
            SlideshowError::IntervalTooShort { .. } => "interval-too-short",
        }
    }
}

impl fmt::Display for SlideshowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlideshowError::EmptyAlbum => f.write_str("empty-album"),
            SlideshowError::IntervalTooShort { interval_ms } => {
                write!(f, "interval-too-short: {interval_ms} < {MIN_INTERVAL_MS}")
            }
        }
    }
}

impl std::error::Error for SlideshowError {}

/// A deterministic slideshow over a fixed order of content ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slideshow {
    order: Vec<Cid>,
    interval_ms: u64,
    current: usize,
    /// The clock value (ms) at which the dwell on `current` began, or, when
    /// paused, the values are frozen and `paused_remaining_ms` holds the
    /// remaining dwell. While paused, `started_at_ms` is ignored.
    started_at_ms: u64,
    /// Remaining dwell in ms while paused; ignored when not paused.
    paused_remaining_ms: u64,
    paused: bool,
}

impl Slideshow {
    /// Build a slideshow over `order` dwelling `interval_ms` on each item.
    /// Refuses `empty-album` and `interval-too-short`.
    pub fn new(
        order: Vec<Cid>,
        interval_ms: u64,
        clock: &dyn Clock,
    ) -> Result<Self, SlideshowError> {
        if order.is_empty() {
            return Err(SlideshowError::EmptyAlbum);
        }
        if interval_ms < MIN_INTERVAL_MS {
            return Err(SlideshowError::IntervalTooShort { interval_ms });
        }
        Ok(Slideshow {
            order,
            interval_ms,
            current: 0,
            started_at_ms: clock.now_ms(),
            paused_remaining_ms: interval_ms,
            paused: false,
        })
    }

    /// The item shown now.
    pub fn current_cid(&self) -> &Cid {
        &self.order[self.current]
    }

    /// The wrapped index shown now.
    pub fn current_index(&self) -> usize {
        self.current
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Advance to the item that should be shown at `now`. Returns the number
    /// of intervals that moved the index (wrapping). While paused, no advance.
    pub fn tick(&mut self, clock: &dyn Clock) -> usize {
        if self.paused {
            return 0;
        }
        let now = clock.now_ms();
        let elapsed = now.saturating_sub(self.started_at_ms);
        let steps = (elapsed / self.interval_ms) as usize;
        if steps == 0 {
            return 0;
        }
        let n = self.order.len();
        let advanced = steps % n;
        self.current = (self.current + advanced) % n;
        // Re-anchor to the start of the current dwell so partial time is not
        // double-counted on the next tick.
        self.started_at_ms = self.started_at_ms.saturating_add(steps as u64 * self.interval_ms);
        advanced
    }

    /// Stop the dwell timer. Position is kept and remaining time is frozen.
    pub fn pause(&mut self, clock: &dyn Clock) {
        if !self.paused {
            self.paused_remaining_ms = self.remaining_ms(clock);
            self.paused = true;
        }
    }

    /// Restart the dwell timer from now, resuming the remaining dwell.
    pub fn resume(&mut self, clock: &dyn Clock) {
        if self.paused {
            let remaining = self.paused_remaining_ms.min(self.interval_ms);
            self.paused = false;
            self.started_at_ms = clock.now_ms().saturating_sub(self.interval_ms - remaining);
        }
    }

    /// Milliseconds left in the current dwell (for the not-paused case).
    fn remaining_ms(&self, clock: &dyn Clock) -> u64 {
        if self.paused {
            self.paused_remaining_ms
        } else {
            let elapsed = clock.now_ms().saturating_sub(self.started_at_ms);
            self.interval_ms - (elapsed % self.interval_ms)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A fake clock the test advances by hand.
    struct FakeClock {
        now: Cell<u64>,
    }
    impl FakeClock {
        fn new() -> Self {
            FakeClock { now: Cell::new(0) }
        }
        fn advance(&self, ms: u64) {
            self.now.set(self.now.get() + ms);
        }
    }
    impl Clock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.now.get()
        }
    }

    fn cids(n: usize) -> Vec<Cid> {
        (0..n).map(|i| Cid::new(format!("cid-{i}"))).collect()
    }

    // P11: an empty order is refused with the exact reason, never shown.
    #[test]
    fn empty_album_is_refused() {
        let clock = FakeClock::new();
        let err = Slideshow::new(Vec::new(), 1_000, &clock).unwrap_err();
        assert_eq!(err.reason(), "empty-album");
        assert_eq!(err, SlideshowError::EmptyAlbum);
    }

    // P11: a dwell under the floor is refused with the exact reason.
    #[test]
    fn interval_too_short_is_refused() {
        let clock = FakeClock::new();
        let err = Slideshow::new(cids(3), MIN_INTERVAL_MS - 1, &clock).unwrap_err();
        assert_eq!(err.reason(), "interval-too-short");
        assert_eq!(
            err,
            SlideshowError::IntervalTooShort {
                interval_ms: MIN_INTERVAL_MS - 1
            }
        );
        // Falsifier: exactly MIN_INTERVAL_MS is accepted.
        assert!(Slideshow::new(cids(3), MIN_INTERVAL_MS, &clock).is_ok());
    }

    // P11: tick advances one item per elapsed interval.
    #[test]
    fn tick_advances_on_interval() {
        let clock = FakeClock::new();
        let mut show = Slideshow::new(cids(3), 1_000, &clock).unwrap();
        assert_eq!(show.current_index(), 0);
        clock.advance(1_000);
        assert_eq!(show.tick(&clock), 1);
        assert_eq!(show.current_cid().as_str(), "cid-1");
        clock.advance(999);
        assert_eq!(show.tick(&clock), 0);
        clock.advance(1);
        assert_eq!(show.tick(&clock), 1);
        assert_eq!(show.current_index(), 2);
    }

    // P11: past the last item the index wraps to the first.
    #[test]
    fn tick_wraps_around() {
        let clock = FakeClock::new();
        let mut show = Slideshow::new(cids(2), 1_000, &clock).unwrap();
        clock.advance(2_000);
        assert_eq!(show.tick(&clock), 0);
        assert_eq!(show.current_index(), 0);
        clock.advance(1_000);
        assert_eq!(show.tick(&clock), 1);
        assert_eq!(show.current_index(), 1);
        // A whole wrap lands back on item 0: two intervals on 2 items.
        clock.advance(2_000);
        assert_eq!(show.tick(&clock), 0);
        assert_eq!(show.current_index(), 1);
    }

    // P11: pause freezes the dwell; resume continues from the same point.
    #[test]
    fn pause_and_resume_hold_position() {
        let clock = FakeClock::new();
        let mut show = Slideshow::new(cids(3), 1_000, &clock).unwrap();
        clock.advance(600);
        show.pause(&clock);
        assert!(show.is_paused());
        // While paused, time passing does not advance.
        clock.advance(5_000);
        assert_eq!(show.tick(&clock), 0);
        assert_eq!(show.current_index(), 0);
        // Resume; the remaining 400 ms then completes the dwell.
        show.resume(&clock);
        assert!(!show.is_paused());
        clock.advance(400);
        assert_eq!(show.tick(&clock), 1);
        assert_eq!(show.current_index(), 1);
    }
}
