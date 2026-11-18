//! The one wall-clock reading a service-grant operation takes.
//!
//! A grant's five-part validity predicate (revision/expiry/TTL) must be
//! judged against one instant per operation: two readings inside one check
//! let a wall-clock step between them reject a grant that was valid at the
//! operation's reading. Production has a single owner for that reading; under
//! test the reading can be scripted and the reads of the operation are
//! counted, including a reading a `spawn_blocking` closure takes on another
//! thread, so a row can prove an operation takes exactly one.

#[cfg(not(test))]
pub(crate) fn now_ts() -> u64 {
    crate::auth::now_ts()
}

#[cfg(test)]
pub(crate) use scripted::{arm, now_ts, reads};

/// Wraps work handed to another thread with the calling thread's scripted
/// readings, so a read inside `spawn_blocking` is still the one operation's
/// read. Production builds return the work unchanged.
#[cfg(test)]
pub(crate) fn inherit_readings<T>(f: impl FnOnce() -> T + Send) -> impl FnOnce() -> T + Send {
    scripted::inherit(f)
}

#[cfg(not(test))]
pub(crate) fn inherit_readings<T>(f: impl FnOnce() -> T + Send) -> impl FnOnce() -> T + Send {
    f
}

#[cfg(test)]
mod scripted {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Clone)]
    struct Script {
        /// Readings still to serve, first to last; the last one repeats.
        readings: VecDeque<u64>,
        /// Readings served under this script on any thread that inherited it.
        served: Arc<AtomicUsize>,
    }

    thread_local! {
        static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
        /// The counter of the arm made on this thread; an inherited thread
        /// shares the same counter through its script.
        static COUNTER: RefCell<Option<Arc<AtomicUsize>>> = const { RefCell::new(None) };
    }

    /// Serves `first` to the next reading on this thread and `rest` to every
    /// reading after it until the guard drops. Reads are counted meanwhile.
    pub(crate) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            SCRIPT.with(|script| *script.borrow_mut() = None);
            COUNTER.with(|counter| *counter.borrow_mut() = None);
        }
    }

    pub(crate) fn arm(first: u64, rest: u64) -> Armed {
        let served = Arc::new(AtomicUsize::new(0));
        SCRIPT.with(|script| {
            *script.borrow_mut() = Some(Script {
                readings: VecDeque::from([first, rest]),
                served: served.clone(),
            });
        });
        COUNTER.with(|counter| *counter.borrow_mut() = Some(served));
        Armed
    }

    /// Readings served under the arm made on this thread, on this thread or
    /// on a thread that inherited its script.
    pub(crate) fn reads() -> usize {
        COUNTER.with(|counter| {
            counter
                .borrow()
                .as_ref()
                .map_or(0, |counter| counter.load(Ordering::SeqCst))
        })
    }

    /// Captures this thread's readings now and installs them around the work
    /// when the returned closure runs on another thread.
    pub(super) fn inherit<T>(f: impl FnOnce() -> T + Send) -> impl FnOnce() -> T + Send {
        let readings = SCRIPT.with(|script| script.borrow().clone());
        move || {
            let previous = SCRIPT.with(|script| script.replace(readings));
            let result = f();
            SCRIPT.with(|script| *script.borrow_mut() = previous);
            result
        }
    }

    pub(crate) fn now_ts() -> u64 {
        let scripted = SCRIPT.with(|script| {
            let mut script = script.borrow_mut();
            let script = script.as_mut()?;
            script.served.fetch_add(1, Ordering::SeqCst);
            if script.readings.len() > 1 {
                script.readings.pop_front()
            } else {
                script.readings.front().copied()
            }
        });
        scripted.unwrap_or_else(crate::auth::now_ts)
    }
}
