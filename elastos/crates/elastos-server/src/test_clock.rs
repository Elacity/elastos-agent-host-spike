//! Test-only wall-clock seam for production sites that must read the clock
//! once per operation.
//!
//! A test arms a script with two readings: the first read of the seamed
//! production function observes `first`, every later read observes `rest`.
//! That models a wall clock that steps between the two reads the old code
//! performed. Post-fix the operation reads once, so `rest` is never observed
//! and [`reads`] stays at 1.
//!
//! The script lives in a thread-local, so a test that arms it cannot leak the
//! value into a concurrently running test on another thread.

use std::cell::Cell;

#[derive(Clone, Copy)]
struct Script {
    first: u64,
    rest: u64,
    reads: u64,
}

thread_local! {
    static SCRIPT: Cell<Option<Script>> = const { Cell::new(None) };
}

/// Disarms the script when dropped.
pub(crate) struct ClockGuard(());

impl Drop for ClockGuard {
    fn drop(&mut self) {
        SCRIPT.with(|slot| slot.set(None));
    }
}

/// Script `first` for the operation's first clock read and `rest` for every
/// later read.
pub(crate) fn arm(first: u64, rest: u64) -> ClockGuard {
    SCRIPT.with(|slot| {
        slot.set(Some(Script {
            first,
            rest,
            reads: 0,
        }));
    });
    ClockGuard(())
}

/// The next scripted reading, or `None` when no test armed the seam.
pub(crate) fn next() -> Option<u64> {
    SCRIPT.with(|slot| {
        let mut script = slot.get()?;
        script.reads += 1;
        let value = if script.reads == 1 {
            script.first
        } else {
            script.rest
        };
        slot.set(Some(script));
        Some(value)
    })
}

/// Number of clock reads served by the armed script.
pub(crate) fn reads() -> u64 {
    SCRIPT.with(|slot| slot.get().map_or(0, |script| script.reads))
}
