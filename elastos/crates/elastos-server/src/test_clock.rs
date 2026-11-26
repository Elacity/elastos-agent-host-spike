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
    /// Readings in order. The last one repeats for every later read.
    steps: [u64; 4],
    len: u8,
    reads: u64,
}

thread_local! {
    static SCRIPT: Cell<Option<Script>> = const { Cell::new(None) };
}

/// Disarms the script when dropped.
///
/// The script lives in a thread-local, so the guard is deliberately `!Send`:
/// dropping it on another worker thread would clear that thread's slot and
/// leave the arming thread's script armed.
pub(crate) struct ClockGuard(std::marker::PhantomData<std::rc::Rc<()>>);

impl Drop for ClockGuard {
    fn drop(&mut self) {
        SCRIPT.with(|slot| slot.set(None));
    }
}

/// Script `first` for the operation's first clock read and `rest` for every
/// later read.
pub(crate) fn arm(first: u64, rest: u64) -> ClockGuard {
    arm_steps(&[first, rest])
}

/// Script up to four readings. The last one repeats after the list is used.
pub(crate) fn arm_steps(steps: &[u64]) -> ClockGuard {
    assert!(!steps.is_empty() && steps.len() <= 4);
    let mut stored = [0; 4];
    stored[..steps.len()].copy_from_slice(steps);
    SCRIPT.with(|slot| {
        slot.set(Some(Script {
            steps: stored,
            len: u8::try_from(steps.len()).expect("step count fits"),
            reads: 0,
        }));
    });
    ClockGuard(std::marker::PhantomData)
}

fn step_index(script: &Script) -> usize {
    usize::try_from(script.reads.min(u64::from(script.len - 1))).expect("step index")
}

/// The next scripted reading, or `None` when no test armed the seam.
pub(crate) fn next() -> Option<u64> {
    SCRIPT.with(|slot| {
        let mut script = slot.get()?;
        let value = script.steps[step_index(&script)];
        script.reads += 1;
        slot.set(Some(script));
        Some(value)
    })
}

/// Replace the next unserved reading without changing the served count.
///
/// A test uses this to advance the script while an operation is queued, so
/// the operation's read happens after the test's chosen step.
pub(crate) fn set_next(value: u64) {
    SCRIPT.with(|slot| {
        let Some(mut script) = slot.get() else {
            return;
        };
        let index = step_index(&script);
        script.steps[index] = value;
        slot.set(Some(script));
    });
}

/// Number of clock reads served by the armed script.
pub(crate) fn reads() -> u64 {
    SCRIPT.with(|slot| slot.get().map_or(0, |script| script.reads))
}
