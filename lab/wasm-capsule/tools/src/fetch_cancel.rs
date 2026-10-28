//! M3 P2-6 (P10): cancelling a fetch releases its reserved bandwidth budget
//! exactly once. A second cancel of the same fetch is refused with
//! `fetch_not_active`.
//!
//! This module is a lab ledger only: nothing here is on any Runtime
//! admission, launch or network path. It models the accounting rule that a
//! reservation made when a fetch starts is given back when the fetch is
//! cancelled, and that giving it back twice is an error, not a silent no-op.
//!
//! Presets chosen here and not given by the task (small and conservative):
//! - a fresh [`Budget`] starts with `capacity = 0` and `reserved = 0`; callers
//!   set a positive capacity with [`Budget::new`];
//! - a fetch reservation is exactly one plain `u64` amount passed to
//!   [`start_fetch`], never a fraction or a default size;
//! - a cancelled fetch id is remembered in a tombstone set so that a later
//!   cancel of the same id is `fetch_not_active` rather than `fetch_not_found`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The one error enum for this module. Each variant has exactly one arm in
/// [`FetchError::code`], and `Display` renders `<code>: <explanation>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// Cancelling a fetch that is not active (already cancelled).
    FetchNotActive,
    /// Cancelling a fetch id that this ledger does not know at all.
    FetchNotFound,
    /// The requested reservation does not fit in the remaining capacity.
    BudgetExhausted,
    /// A fetch id was started twice without cancelling the first one.
    FetchAlreadyActive,
    /// A reservation amount of zero is not a fetch.
    ZeroReservation,
}

impl FetchError {
    /// Stable snake_case code for each refusal; the task's backticked names
    /// are these codes in snake_case.
    pub fn code(&self) -> &'static str {
        match self {
            FetchError::FetchNotActive => "fetch_not_active",
            FetchError::FetchNotFound => "fetch_not_found",
            FetchError::BudgetExhausted => "budget_exhausted",
            FetchError::FetchAlreadyActive => "fetch_already_active",
            FetchError::ZeroReservation => "zero_reservation",
        }
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            FetchError::FetchNotActive => "fetch is not active, its budget was already released",
            FetchError::FetchNotFound => "no fetch with this id is known",
            FetchError::BudgetExhausted => "reservation does not fit in remaining budget",
            FetchError::FetchAlreadyActive => "fetch id is already active",
            FetchError::ZeroReservation => "reservation amount must be greater than zero",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for FetchError {}

/// A bandwidth budget ledger: a fixed capacity, the amount currently
/// reserved by active fetches, the per-fetch reservations that make up
/// `reserved`, and the set of ids already cancelled.
#[derive(Debug, Clone)]
pub struct Budget {
    capacity: u64,
    reserved: u64,
    active: BTreeMap<u64, u64>,
    cancelled: BTreeSet<u64>,
}

impl Budget {
    /// A budget with the given total capacity and nothing reserved.
    pub fn new(capacity: u64) -> Budget {
        Budget {
            capacity,
            reserved: 0,
            active: BTreeMap::new(),
            cancelled: BTreeSet::new(),
        }
    }

    /// Total capacity of this budget.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Amount currently held by active fetches.
    pub fn reserved(&self) -> u64 {
        self.reserved
    }

    /// Amount still free to reserve.
    pub fn available(&self) -> u64 {
        self.capacity - self.reserved
    }

    /// Whether a fetch id is currently active.
    pub fn is_active(&self, id: u64) -> bool {
        self.active.contains_key(&id)
    }
}

/// Start a fetch of `amount` units against `budget`, reserving that amount.
/// The reservation is recorded under `id` so that [`cancel_fetch`] can give it
/// back. Unknown-to-task shapes are plain functions over owned, plain inputs.
pub fn start_fetch(budget: &mut Budget, id: u64, amount: u64) -> Result<(), FetchError> {
    if amount == 0 {
        return Err(FetchError::ZeroReservation);
    }
    if budget.active.contains_key(&id) {
        return Err(FetchError::FetchAlreadyActive);
    }
    if amount > budget.available() {
        return Err(FetchError::BudgetExhausted);
    }
    budget.active.insert(id, amount);
    budget.reserved += amount;
    Ok(())
}

/// Cancel a fetch, releasing its reserved budget exactly once.
///
/// - If `id` is active, its reservation is returned, the fetch removed and the
///   id remembered as cancelled; the result is `Ok(amount)`.
/// - If `id` was cancelled before, the result is
///   `Err(FetchError::FetchNotActive)` and the ledger is unchanged, so the
///   budget cannot be released twice.
/// - If `id` was never started, the result is `Err(FetchError::FetchNotFound)`.
pub fn cancel_fetch(budget: &mut Budget, id: u64) -> Result<u64, FetchError> {
    match budget.active.remove(&id) {
        Some(amount) => {
            budget.reserved -= amount;
            budget.cancelled.insert(id);
            Ok(amount)
        }
        None => {
            if budget.cancelled.contains(&id) {
                Err(FetchError::FetchNotActive)
            } else {
                Err(FetchError::FetchNotFound)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P10: a start reserves, and a single cancel releases the reservation
    // exactly once.
    #[test]
    fn cancel_releases_reserved_budget_exactly_once() {
        let mut budget = Budget::new(100);
        start_fetch(&mut budget, 7, 30).expect("start fits");
        assert_eq!(budget.reserved(), 30);
        assert_eq!(budget.available(), 70);

        let released = cancel_fetch(&mut budget, 7).expect("first cancel succeeds");
        assert_eq!(released, 30);
        assert_eq!(budget.reserved(), 0, "reservation returned to the budget");
        assert_eq!(budget.available(), 100);
        assert!(!budget.is_active(7));
    }

    // P10: the refusal path named in the task is the test. A second cancel of
    // the same fetch is refused with `fetch_not_active` and releases nothing.
    #[test]
    fn double_cancel_is_refused_fetch_not_active() {
        let mut budget = Budget::new(50);
        start_fetch(&mut budget, 1, 20).expect("start fits");
        cancel_fetch(&mut budget, 1).expect("first cancel succeeds");
        let after_first = budget.reserved();

        let err = cancel_fetch(&mut budget, 1).expect_err("second cancel must be refused");
        assert_eq!(err.code(), "fetch_not_active");
        assert_eq!(budget.reserved(), after_first, "double cancel released nothing");
        assert_eq!(budget.reserved(), 0);
    }

    // P10: an id that was never started is refused as `fetch_not_found`, a
    // different code from a double cancel.
    #[test]
    fn unknown_id_is_refused_fetch_not_found() {
        let mut budget = Budget::new(10);
        let err = cancel_fetch(&mut budget, 99).expect_err("unknown id refused");
        assert_eq!(err.code(), "fetch_not_found");
        assert_eq!(budget.reserved(), 0);
    }

    // P10: a limits type with every limit at zero. Capacity zero reserves
    // nothing, no fetch can start, and available stays zero.
    #[test]
    fn zero_capacity_budget_has_every_limit_at_zero() {
        let mut budget = Budget::new(0);
        assert_eq!(budget.capacity(), 0);
        assert_eq!(budget.reserved(), 0);
        assert_eq!(budget.available(), 0);

        let err = start_fetch(&mut budget, 1, 1).expect_err("no capacity to reserve");
        assert_eq!(err.code(), "budget_exhausted");
        assert_eq!(budget.reserved(), 0);
    }

    // P10: reservations beyond capacity are refused and leave the ledger
    // unchanged, so available never underflows.
    #[test]
    fn over_reservation_is_refused_without_change() {
        let mut budget = Budget::new(10);
        start_fetch(&mut budget, 1, 6).expect("fits");
        let err = start_fetch(&mut budget, 2, 6).expect_err("does not fit");
        assert_eq!(err.code(), "budget_exhausted");
        assert_eq!(budget.reserved(), 6);
        assert_eq!(budget.available(), 4);
        assert!(!budget.is_active(2));
    }

    // P10: a zero reservation is not a fetch and is refused.
    #[test]
    fn zero_reservation_is_refused() {
        let mut budget = Budget::new(10);
        let err = start_fetch(&mut budget, 1, 0).expect_err("zero refused");
        assert_eq!(err.code(), "zero_reservation");
        assert_eq!(budget.reserved(), 0);
    }

    // P10: starting the same id twice is refused as `fetch_already_active`.
    #[test]
    fn duplicate_start_is_refused_fetch_already_active() {
        let mut budget = Budget::new(10);
        start_fetch(&mut budget, 1, 3).expect("fits");
        let err = start_fetch(&mut budget, 1, 3).expect_err("duplicate refused");
        assert_eq!(err.code(), "fetch_already_active");
        assert_eq!(budget.reserved(), 3, "duplicate did not reserve twice");
    }

    // P10: returning capacity after cancel lets a later fetch reserve it.
    #[test]
    fn released_capacity_can_be_reserved_again() {
        let mut budget = Budget::new(10);
        start_fetch(&mut budget, 1, 10).expect("full reservation fits");
        assert_eq!(budget.available(), 0);
        cancel_fetch(&mut budget, 1).expect("release");
        start_fetch(&mut budget, 2, 10).expect("freed capacity now fits");
        assert_eq!(budget.reserved(), 10);
        assert_eq!(budget.available(), 0);
    }
}
