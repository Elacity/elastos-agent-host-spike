//! The one wall-clock reading a service-grant operation takes.
//!
//! A grant's five-part validity predicate (revision/expiry/TTL) must be
//! judged against one instant per operation: two readings inside one check
//! let a wall-clock step between them reject a grant that was valid at the
//! operation's reading. Production has a single owner for that reading; under
//! test the reading can be scripted and the reads of the calling thread are
//! counted, so a row can prove an operation takes exactly one.

#[cfg(not(test))]
pub(crate) fn now_ts() -> u64 {
    crate::auth::now_ts()
}

#[cfg(test)]
pub(crate) use scripted::{arm, now_ts, reads};

#[cfg(test)]
mod scripted {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct Script {
        /// Readings still to serve, first to last; the last one repeats.
        readings: VecDeque<u64>,
        served: usize,
    }

    thread_local! {
        static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
    }

    /// Serves `first` to the next reading on this thread and `rest` to every
    /// reading after it until the guard drops. Reads are counted meanwhile.
    pub(crate) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            SCRIPT.with(|script| *script.borrow_mut() = None);
        }
    }

    pub(crate) fn arm(first: u64, rest: u64) -> Armed {
        SCRIPT.with(|script| {
            *script.borrow_mut() = Some(Script {
                readings: VecDeque::from([first, rest]),
                served: 0,
            });
        });
        Armed
    }

    /// Scripted readings served on this thread since the arming guard was made.
    pub(crate) fn reads() -> usize {
        SCRIPT.with(|script| script.borrow().as_ref().map_or(0, |script| script.served))
    }

    pub(crate) fn now_ts() -> u64 {
        let scripted = SCRIPT.with(|script| {
            let mut script = script.borrow_mut();
            let script = script.as_mut()?;
            script.served += 1;
            if script.readings.len() > 1 {
                script.readings.pop_front()
            } else {
                script.readings.front().copied()
            }
        });
        scripted.unwrap_or_else(crate::auth::now_ts)
    }
}
