//! One token bucket per v2 guest. The store's fuel is the loan this bucket
//! has lent. Wasmtime's component host-call fuel (`DEFAULT_HOSTCALL_FUEL`,
//! 128 MiB of guest bytes copied into the host) is a separate budget: this
//! bucket does not bound host allocation.

use std::time::{Duration, Instant};

use wasmtime::{ResourceLimiter, Result};

/// Capacity. On this Mac the debug build of the shipped busy loop burned
/// 1_900_589_658 fuel per second, so this is about two seconds of that burn.
/// The property test uses the constant. It does not read the machine.
pub(crate) const V2_BUCKET_CAPACITY: u64 = 3_800_000_000;
/// Refill per second of monotonic time. A resident that spends a few dozen
/// fuel every two seconds needs on the order of 32 fuel per second. This is
/// far above that and about 0.2% of the measured full burn, so a busy loop
/// still empties the bucket in about two seconds.
pub(crate) const V2_BUCKET_REFILL_PER_SEC: u64 = 4_000_000;

/// One v2 guest's linear memories and tables, summed. A dropped memory is
/// not returned: Wasmtime 48 has no drop callback, so the count only grows.
pub(crate) const V2_GUEST_MEMORY: usize = 128 * 1024 * 1024;
const V2_INSTANCES: usize = 16;
const V2_MEMORIES: usize = 4;
const V2_TABLES: usize = 32;

pub(crate) struct FuelBucket {
    capacity: u64,
    balance: u64,
    pub(crate) lent: u64,
    at: Instant,
    /// This suspension was already charged. A spurious poll must not read fuel again.
    pub(crate) open: bool,
    /// Sleep. The guest cannot run, so ticks do not count. An events read
    /// that is only pending does not set this: the guest may still run.
    pub(crate) parked: bool,
    /// Ticks in the current execution window. A wait longer than one tick
    /// refills it. It is not a lifetime sum.
    pub(crate) window_ticks: u64,
    /// When the events read last went pending, if it is still pending.
    pub(crate) wait_since: Option<Instant>,
    /// Refill below one fuel unit, kept across wakes.
    remainder: u64,
    /// `get_fuel` or `set_fuel` failed. The run ends with this name.
    pub(crate) fault: Option<&'static str>,
    clock_ms: u64,
}

impl FuelBucket {
    pub(crate) fn full(capacity: u64, now: Instant) -> Self {
        Self {
            capacity,
            balance: capacity,
            lent: capacity,
            at: now,
            open: false,
            parked: false,
            window_ticks: 0,
            wait_since: None,
            remainder: 0,
            fault: None,
            clock_ms: 0,
        }
    }

    /// Charge `lent - remaining`, refill, and lend again. `None` means the
    /// loan is gone and the run is execution-bound. A parked bucket returns
    /// the loan it already wrote.
    pub(crate) fn settle(&mut self, remaining: u64, now: Instant) -> Option<u64> {
        if self.open {
            return Some(self.lent);
        }
        let burned = self.lent.saturating_sub(remaining);
        self.balance = self.balance.saturating_sub(burned);
        let add =
            refill(now.saturating_duration_since(self.at), &mut self.remainder).min(self.capacity);
        self.at = now;
        self.balance = self.balance.saturating_add(add).min(self.capacity);
        self.open = true;
        if self.balance == 0 {
            self.lent = 0;
            return None;
        }
        self.lent = self.balance;
        Some(self.lent)
    }

    pub(crate) fn resume(&mut self) {
        self.open = false;
        self.parked = false;
    }

    pub(crate) fn park(&mut self) {
        self.parked = true;
    }

    /// The store-level burn sets the gap to zero so the assertion is the
    /// loan, not the scheduler.
    #[cfg(test)]
    pub(crate) fn close_the_gap(&mut self) {
        self.at = Instant::now() + Duration::from_secs(1);
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.clock_ms
    }

    /// How long a `sleep-until` blocks. The wait is the gap on this guest's
    /// clock. That parked time is outside the run deadline.
    pub(crate) fn sleep_for(&mut self, deadline_ms: u64) -> Duration {
        let wait = deadline_ms.saturating_sub(self.clock_ms);
        self.clock_ms = self.clock_ms.max(deadline_ms);
        Duration::from_millis(wait)
    }
}

/// Whole fuel units in `elapsed`, plus any fraction still held in `remainder`.
/// A 0.9 ms gap is 900 µs and is not dropped.
pub(crate) fn refill(elapsed: Duration, remainder: &mut u64) -> u64 {
    let us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let acc = remainder.saturating_add(V2_BUCKET_REFILL_PER_SEC.saturating_mul(us));
    *remainder = acc % 1_000_000;
    acc / 1_000_000
}

#[derive(Default)]
pub(crate) struct GuestMemory {
    used: usize,
}

impl ResourceLimiter for GuestMemory {
    fn memory_growing(&mut self, current: usize, desired: usize, _: Option<usize>) -> Result<bool> {
        self.grow(desired.saturating_sub(current))
    }

    fn table_growing(&mut self, current: usize, desired: usize, _: Option<usize>) -> Result<bool> {
        let bytes = desired
            .saturating_sub(current)
            .saturating_mul(std::mem::size_of::<usize>());
        self.grow(bytes)
    }

    fn instances(&self) -> usize {
        V2_INSTANCES
    }

    fn memories(&self) -> usize {
        V2_MEMORIES
    }

    fn tables(&self) -> usize {
        V2_TABLES
    }
}

impl GuestMemory {
    fn grow(&mut self, bytes: usize) -> Result<bool> {
        let Some(next) = self.used.checked_add(bytes) else {
            return Ok(false);
        };
        if next > V2_GUEST_MEMORY {
            return Ok(false);
        }
        self.used = next;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(steps: &[(u64, u64)]) -> (u64, bool, u64) {
        let mut balance = V2_BUCKET_CAPACITY;
        let mut lent = V2_BUCKET_CAPACITY;
        let mut spent = 0u64;
        let mut alive = true;
        let mut remainder = 0u64;
        for &(burn, ms) in steps {
            if !alive {
                break;
            }
            let burn = burn.min(lent);
            spent += burn;
            balance = balance.saturating_sub(burn);
            let add = refill(Duration::from_millis(ms), &mut remainder);
            balance = balance.saturating_add(add).min(V2_BUCKET_CAPACITY);
            if balance == 0 {
                alive = false;
                lent = 0;
            } else {
                lent = balance;
            }
        }
        (spent, alive, lent)
    }

    fn drive(steps: &[(u64, u64)]) -> (u64, bool, u64) {
        let mut now = Instant::now();
        let mut bucket = FuelBucket::full(V2_BUCKET_CAPACITY, now);
        let mut spent = 0u64;
        let mut alive = true;
        for &(burn, ms) in steps {
            if !alive {
                break;
            }
            now += Duration::from_millis(ms);
            bucket.resume();
            let burn = burn.min(bucket.lent);
            let remaining = bucket.lent - burn;
            spent += burn;
            if bucket.settle(remaining, now).is_none() {
                alive = false;
            }
        }
        (spent, alive, bucket.lent)
    }

    fn assert_bound(steps: &[(u64, u64)]) {
        let (spent, alive, lent) = drive(steps);
        let (model_spent, model_alive, model_lent) = model(steps);
        assert_eq!((spent, alive, lent), (model_spent, model_alive, model_lent));
        let window: u64 = steps.iter().map(|(_, ms)| *ms).sum();
        let cap = V2_BUCKET_CAPACITY
            .saturating_add(V2_BUCKET_REFILL_PER_SEC.saturating_mul(window) / 1_000);
        assert!(spent <= cap, "spent {spent} over {window} ms, bound {cap}");
    }

    #[test]
    fn spend_stays_inside_the_bucket_for_every_listed_shape() {
        let b = V2_BUCKET_CAPACITY;
        assert_bound(&[(1_000, 10); 40]);
        assert_bound(
            &[(400, 5), (700, 5)]
                .into_iter()
                .cycle()
                .take(40)
                .collect::<Vec<_>>(),
        );
        assert_bound(&(1..=80).map(|i| (i * 1_000, 2)).collect::<Vec<_>>());
        assert_bound(&[(u64::MAX, 0); 4]);
        let exact = V2_BUCKET_REFILL_PER_SEC / 10;
        assert_bound(&[(exact, 100); 20]);
        assert_bound(&[(u64::MAX, 0)]);
        assert_bound(&[(32, 0); 200]);
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut random = Vec::new();
        for _ in 0..48 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let burn = state % (b / 8 + 1);
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let ms = state % 40;
            random.push((burn, ms));
        }
        assert_bound(&random);
    }

    #[test]
    fn an_idle_resident_survives_ten_thousand_wakes() {
        let steps = vec![(64, 0); 10_000];
        let (spent, alive, _) = drive(&steps);
        assert!(alive, "10,000 wakes of 64 fuel spent {spent}");
        assert_eq!(spent, 64 * 10_000);
    }

    #[test]
    fn a_sub_millisecond_gap_keeps_its_fraction() {
        let mut now = Instant::now();
        let mut bucket = FuelBucket::full(100_000, now);
        now += Duration::from_micros(900);
        let lend = bucket.settle(10_000, now).unwrap();
        assert_eq!(lend, 13_600, "0.9 ms must credit refill, not zero");
    }

    #[test]
    fn a_parked_bucket_does_not_lend_twice() {
        let now = Instant::now();
        let mut bucket = FuelBucket::full(V2_BUCKET_CAPACITY, now);
        let first = bucket.settle(V2_BUCKET_CAPACITY / 2, now).unwrap();
        let second = bucket.settle(V2_BUCKET_CAPACITY / 2, now).unwrap();
        assert_eq!(first, V2_BUCKET_CAPACITY / 2);
        assert_eq!(
            second, first,
            "a second read while parked must keep the same loan"
        );
    }

    #[test]
    fn dropped_memory_stays_counted_and_four_memories_share_the_total() {
        let mut memory = GuestMemory::default();
        let page = 64 * 1024;
        for _ in 0..4 {
            assert!(memory.memory_growing(0, page, None).unwrap());
        }
        assert!(!memory.memory_growing(0, V2_GUEST_MEMORY, None).unwrap());
        let mut filled = GuestMemory::default();
        assert!(filled.memory_growing(0, V2_GUEST_MEMORY, None).unwrap());
        assert!(
            !filled.memory_growing(0, page, None).unwrap(),
            "a drop is not returned"
        );
        assert_eq!(memory.memories(), 4);
        assert_eq!(memory.instances(), 16);
    }
}
