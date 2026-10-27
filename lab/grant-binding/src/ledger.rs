//! The one ledger the verifier owns: the ceiling, the outstanding holds, the
//! reservations recorded so far and the total charged by settled holds.
//!
//! `admit` sets the allowance ceiling and leaves outstanding holds alone.
//! `reserve` first takes the binding decision from `Verifier::resolve`, then
//! records the hold on this ledger. `settle` and `release` are the only ways a
//! hold ends, and both take that same binding decision first. The guest's
//! `reported_usage` claim is not read: a known settle charges the figure the
//! verifier passes in when it stays at or under the stored hold, refuses a
//! larger one, and an unknown outcome keeps the hold. The ledger value
//! sits behind one mutex, and admit, reserve, settle, and release lock it for
//! the check and the write.

use std::collections::HashMap;

use crate::{Call, GuestRequest, Handle, Refuse, Verifier};

#[derive(Debug, Clone, Copy)]
struct OpenHold {
    handle: Handle,
    amount: u64,
}

fn handles_match(bound: Handle, presented: Handle) -> bool {
    bound == presented
}

/// The one ledger the verifier owns.
#[derive(Debug)]
pub(crate) struct Ledger {
    ceiling: u64,
    held: u64,
    next_reservation: u64,
    charged: u64,
    open: HashMap<u64, OpenHold>,
}

impl Ledger {
    /// An empty ledger: no ceiling, nothing held and nothing charged.
    pub(crate) fn new() -> Self {
        Self {
            ceiling: 0,
            held: 0,
            next_reservation: 0,
            charged: 0,
            open: HashMap::new(),
        }
    }
}

/// A hold on the ledger. Its id is the ledger's own record of the hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    id: u64,
}

/// A refused reserve with one clear reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveRefuse {
    OverCeiling { ceiling: u64, held: u64, asked: u64 },
    Binding(Refuse),
}

impl std::fmt::Display for ReserveRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReserveRefuse::OverCeiling { .. } => {
                formatter.write_str("reservation exceeds the ceiling")
            }
            ReserveRefuse::Binding(refusal) => refusal.fmt(formatter),
        }
    }
}

/// The measured outcome of a settle: the figure the host can prove, or a
/// result it cannot state yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleOutcome {
    Known(u64),
    Unknown,
}

/// A refused settle with one clear reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleRefuse {
    UnknownOutcome,
    NotOutstanding,
    AboveReservation,
    ChargeOverflow,
    OtherHandle,
    Binding(Refuse),
}

impl std::fmt::Display for SettleRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettleRefuse::UnknownOutcome => formatter.write_str("unknown outcome keeps the hold"),
            SettleRefuse::NotOutstanding => formatter.write_str("reservation is not outstanding"),
            SettleRefuse::AboveReservation => {
                formatter.write_str("measured figure exceeds the reservation")
            }
            SettleRefuse::ChargeOverflow => {
                formatter.write_str("settled charge does not fit in u64")
            }
            SettleRefuse::OtherHandle => {
                formatter.write_str("reservation is bound to another handle")
            }
            SettleRefuse::Binding(refusal) => refusal.fmt(formatter),
        }
    }
}

/// A refused release with one clear reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRefuse {
    NotOutstanding,
    OtherHandle,
    Binding(Refuse),
}

impl std::fmt::Display for ReleaseRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseRefuse::NotOutstanding => formatter.write_str("reservation is not outstanding"),
            ReleaseRefuse::OtherHandle => {
                formatter.write_str("reservation is bound to another handle")
            }
            ReleaseRefuse::Binding(refusal) => refusal.fmt(formatter),
        }
    }
}

impl Verifier {
    /// Sets the allowance ceiling. Outstanding holds stay as they are.
    pub fn admit(&self, ceiling: u64) {
        self.ledger.lock().expect("ledger lock").ceiling = ceiling;
    }

    /// Holds `amount` on the ledger when the outstanding total plus `amount`
    /// stays at or under the ceiling. A binding refusal records nothing, a sum
    /// that does not fit in `u64` is over the ceiling, and the request's
    /// reported usage does not lower the hold.
    pub fn reserve(
        &self,
        call: &Call,
        request: &GuestRequest,
        amount: u64,
    ) -> Result<Reservation, ReserveRefuse> {
        self.resolve(*call, request.handle)
            .map_err(ReserveRefuse::Binding)?;
        let mut ledger = self.ledger.lock().expect("ledger lock");
        let held = ledger.held;
        let ledger: &mut Ledger = &mut ledger;
        let total = match held.checked_add(amount) {
            Some(total) if total <= ledger.ceiling => total,
            _ => {
                return Err(ReserveRefuse::OverCeiling {
                    ceiling: ledger.ceiling,
                    held,
                    asked: amount,
                })
            }
        };
        ledger.held = total;
        ledger.next_reservation += 1;
        ledger.open.insert(
            ledger.next_reservation,
            OpenHold {
                handle: request.handle,
                amount,
            },
        );
        Ok(Reservation {
            id: ledger.next_reservation,
        })
    }

    /// Ends one hold with the figure the host measured. A binding refusal
    /// records nothing, an unknown outcome keeps the hold as it is, and a
    /// reservation that is not outstanding is refused. A known outcome
    /// charges the measured figure when it stays at or under the stored hold,
    /// gives back the stored hold and returns the charge; a larger figure is
    /// refused and records nothing. The request's reported usage does not
    /// lower it.
    pub fn settle(
        &self,
        call: &Call,
        request: &GuestRequest,
        reservation: Reservation,
        outcome: SettleOutcome,
    ) -> Result<u64, SettleRefuse> {
        self.resolve(*call, request.handle)
            .map_err(SettleRefuse::Binding)?;
        let measured = match outcome {
            SettleOutcome::Known(measured) => measured,
            SettleOutcome::Unknown => {
                return Err(SettleRefuse::UnknownOutcome);
            }
        };
        let mut ledger = self.ledger.lock().expect("ledger lock");
        let ledger: &mut Ledger = &mut ledger;
        let (bound, stored) = match ledger.open.get(&reservation.id) {
            Some(open) => (open.handle, open.amount),
            None => return Err(SettleRefuse::NotOutstanding),
        };
        if !handles_match(bound, request.handle) {
            return Err(SettleRefuse::OtherHandle);
        }
        if measured > stored {
            return Err(SettleRefuse::AboveReservation);
        }
        let charge = measured;
        let charged = match ledger.charged.checked_add(charge) {
            Some(charged) => charged,
            None => return Err(SettleRefuse::ChargeOverflow),
        };
        ledger.charged = charged;
        ledger.held -= stored;
        ledger.open.remove(&reservation.id);
        Ok(charge)
    }

    /// Ends one hold without charging anything. A binding refusal records
    /// nothing and a reservation that is not outstanding is refused.
    pub fn release(
        &self,
        call: &Call,
        request: &GuestRequest,
        reservation: Reservation,
    ) -> Result<(), ReleaseRefuse> {
        self.resolve(*call, request.handle)
            .map_err(ReleaseRefuse::Binding)?;
        let mut ledger = self.ledger.lock().expect("ledger lock");
        let (bound, amount) = match ledger.open.get(&reservation.id) {
            Some(open) => (open.handle, open.amount),
            None => return Err(ReleaseRefuse::NotOutstanding),
        };
        if !handles_match(bound, request.handle) {
            return Err(ReleaseRefuse::OtherHandle);
        }
        ledger.open.remove(&reservation.id);
        ledger.held -= amount;
        Ok(())
    }
}

#[cfg(test)]
use crate::{guest, rights, InstanceId};

/// Registers one instance with a fresh grant and returns both.
#[cfg(test)]
fn bound(verifier: &mut Verifier) -> (InstanceId, Handle) {
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    (instance, handle)
}

#[cfg(test)]
struct Books {
    held: u64,
    charged: u64,
    open: HashMap<u64, u64>,
}

#[cfg(test)]
fn books(verifier: &Verifier) -> Books {
    let ledger = verifier.ledger.lock().expect("ledger lock");
    Books {
        held: ledger.held,
        charged: ledger.charged,
        open: ledger
            .open
            .iter()
            .map(|(id, open)| (*id, open.amount))
            .collect(),
    }
}

#[test]
fn model_reserve_at_the_ceiling_is_allowed() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(5);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    verifier.reserve(&call, &request, 5).expect("reserve");
    assert_eq!(books(&verifier).held, 5);
}

#[test]
fn model_reserve_over_the_ceiling_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(5);
    let call = verifier.open_call(instance);
    let refusal = verifier
        .reserve(&call, &guest(handle), 6)
        .expect_err("over the ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 5,
            held: 0,
            asked: 6,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    assert_eq!(books(&verifier).held, 0);
}

#[test]
fn model_reserve_past_the_u64_total_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(u64::MAX);
    let call = verifier.open_call(instance);
    verifier
        .reserve(&call, &guest(handle), u64::MAX)
        .expect("at the ceiling");
    assert_eq!(books(&verifier).held, u64::MAX);
    let refusal = verifier
        .reserve(&call, &guest(handle), 1)
        .expect_err("sum past u64::MAX");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: u64::MAX,
            held: u64::MAX,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    assert_eq!(books(&verifier).held, u64::MAX);
    let again = verifier
        .reserve(&call, &guest(handle), u64::MAX)
        .expect_err("still over the ceiling");
    assert_eq!(again.to_string(), "reservation exceeds the ceiling");
    assert_eq!(books(&verifier).held, u64::MAX);
}

#[test]
fn model_outstanding_hold_counts_toward_the_ceiling() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(5);
    let call = verifier.open_call(instance);
    verifier
        .reserve(&call, &guest(handle), 3)
        .expect("first reserve");
    // The second admission sets the ceiling again and keeps the hold.
    verifier.admit(5);
    let refusal = verifier
        .reserve(&call, &guest(handle), 3)
        .expect_err("over the ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 5,
            held: 3,
            asked: 3,
        }
    );
    assert_eq!(books(&verifier).held, 3);
}

#[test]
fn model_reported_usage_does_not_lower_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    verifier.reserve(&call, &request, 10).expect("reserve");
    assert_eq!(books(&verifier).held, 10);
}

#[test]
fn model_reserve_on_a_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier.admit(5);
    let call = verifier.open_call(sibling);
    let refusal = verifier
        .reserve(&call, &guest(handle), 1)
        .expect_err("sibling instance");
    assert_eq!(refusal, ReserveRefuse::Binding(Refuse::Instance));
    assert_eq!(refusal.to_string(), "instance does not match the grant");
    assert_eq!(books(&verifier).held, 0);
}

#[test]
fn model_settle_known_outcome_charges_the_measured_figure() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let reservation = verifier
        .reserve(&call, &guest(handle), 10)
        .expect("reserve");
    let charge = verifier
        .settle(&call, &guest(handle), reservation, SettleOutcome::Known(10))
        .expect("settle");
    assert_eq!(charge, 10);
    assert_eq!(books(&verifier).charged, 10);
    assert_eq!(books(&verifier).held, 0);
    assert!(!books(&verifier).open.contains_key(&reservation.id));
}

#[test]
fn model_reported_usage_does_not_lower_the_settled_charge() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    let reservation = verifier.reserve(&call, &request, 10).expect("reserve");
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(10))
        .expect("settle");
    assert_eq!(charge, 10);
    assert_eq!(books(&verifier).charged, 10);
    assert_eq!(books(&verifier).held, 0);
}

#[test]
fn model_settle_twice_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 0,
        ..guest(handle)
    };
    let reservation = verifier.reserve(&call, &request, 10).expect("reserve");
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(10))
        .expect("settle");
    assert_eq!(charge, 10);
    assert_eq!(books(&verifier).charged, 10);
    assert_eq!(books(&verifier).held, 0);
    let refusal = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(10))
        .expect_err("second settle");
    assert_eq!(refusal, SettleRefuse::NotOutstanding);
    assert_eq!(refusal.to_string(), "reservation is not outstanding");
    assert_eq!(books(&verifier).charged, 10);
    assert_eq!(books(&verifier).held, 0);
}

#[test]
fn model_unknown_outcome_keeps_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 10).expect("reserve");
    let refusal = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(refusal, SettleRefuse::UnknownOutcome);
    assert_eq!(refusal.to_string(), "unknown outcome keeps the hold");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(books(&verifier).charged, 0);
    assert!(books(&verifier).open.contains_key(&reservation.id));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(10))
        .expect("settle after unknown");
    assert_eq!(charge, 10);
}

#[test]
fn model_release_returns_the_unused_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let reservation = verifier
        .reserve(&call, &guest(handle), 10)
        .expect("reserve");
    let released = verifier.release(&call, &guest(handle), reservation);
    assert_eq!(released, Ok(()));
    assert_eq!(books(&verifier).held, 0);
    assert_eq!(books(&verifier).charged, 0);
    assert!(!books(&verifier).open.contains_key(&reservation.id));
}

#[test]
fn model_settle_on_a_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier.admit(10);
    let call = verifier.open_call(first);
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 10).expect("reserve");
    let sibling_call = verifier.open_call(sibling);
    let refusal = verifier
        .settle(
            &sibling_call,
            &request,
            reservation,
            SettleOutcome::Known(10),
        )
        .expect_err("sibling instance");
    assert_eq!(refusal, SettleRefuse::Binding(Refuse::Instance));
    assert_eq!(refusal.to_string(), "instance does not match the grant");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(books(&verifier).charged, 0);
}

#[test]
fn model_release_on_a_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier.admit(10);
    let call = verifier.open_call(first);
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 10).expect("reserve");
    let sibling_call = verifier.open_call(sibling);
    let refusal = verifier
        .release(&sibling_call, &request, reservation)
        .expect_err("sibling instance");
    assert_eq!(refusal, ReleaseRefuse::Binding(Refuse::Instance));
    assert_eq!(refusal.to_string(), "instance does not match the grant");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(books(&verifier).charged, 0);
    assert!(books(&verifier).open.contains_key(&reservation.id));
}

#[test]
fn model_settle_below_the_hold_returns_the_rest() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 9,
        ..guest(handle)
    };
    let reservation = verifier.reserve(&call, &request, 10).expect("reserve");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(
        verifier.settle(&call, &request, reservation, SettleOutcome::Known(4)),
        Ok(4)
    );
    assert_eq!(books(&verifier).charged, 4);
    assert_eq!(books(&verifier).held, 0);
    assert!(!books(&verifier).open.contains_key(&reservation.id));
    verifier
        .reserve(&call, &request, 10)
        .expect("reserve after settle");
    assert_eq!(books(&verifier).held, 10);
}

#[test]
fn model_release_twice_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let reservation = verifier
        .reserve(&call, &guest(handle), 10)
        .expect("reserve");
    let released = verifier.release(&call, &guest(handle), reservation);
    assert_eq!(released, Ok(()));
    assert_eq!(books(&verifier).held, 0);
    assert_eq!(books(&verifier).charged, 0);
    let refusal = verifier
        .release(&call, &guest(handle), reservation)
        .expect_err("second release");
    assert_eq!(refusal, ReleaseRefuse::NotOutstanding);
    assert_eq!(refusal.to_string(), "reservation is not outstanding");
    assert_eq!(books(&verifier).held, 0);
    assert_eq!(books(&verifier).charged, 0);
    assert!(!books(&verifier).open.contains_key(&reservation.id));
}

#[test]
fn model_concurrent_reserves_keep_one_ceiling() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(5);
    let call = verifier.open_call(instance);
    let request = guest(handle);
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| verifier.reserve(&call, &request, 3));
        let second = scope.spawn(|| verifier.reserve(&call, &request, 3));
        (first.join().expect("first"), second.join().expect("second"))
    });
    let allowed = [first, second]
        .iter()
        .filter(|result| result.is_ok())
        .count();
    assert_eq!(allowed, 1);
    let refusal = match (first, second) {
        (Ok(_), Err(refusal)) | (Err(refusal), Ok(_)) => refusal,
        _ => panic!("exactly one reserve must be allowed"),
    };
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 5,
            held: 3,
            asked: 3,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let books = books(&verifier);
    assert_eq!(books.held, 3);
    assert_eq!(books.charged, 0);
    assert_eq!(books.open.len(), 1);
}

#[test]
fn model_settle_above_the_reservation_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 100,
        ..guest(handle)
    };
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    let refusal = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(9))
        .expect_err("above the reservation");
    assert_eq!(refusal, SettleRefuse::AboveReservation);
    assert_eq!(
        refusal.to_string(),
        "measured figure exceeds the reservation"
    );
    let after_refusal = books(&verifier);
    assert_eq!(after_refusal.held, 4);
    assert_eq!(after_refusal.charged, 0);
    assert_eq!(after_refusal.open.get(&reservation.id), Some(&4));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("settle at the reservation");
    assert_eq!(charge, 4);
    let after_settle = books(&verifier);
    assert_eq!(after_settle.charged, 4);
    assert_eq!(after_settle.held, 0);
    assert!(!after_settle.open.contains_key(&reservation.id));
}

#[test]
fn model_settle_past_the_u64_charge_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(u64::MAX);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    let first = verifier
        .reserve(&call, &request, u64::MAX - 3)
        .expect("reserve");
    assert_eq!(
        verifier.settle(&call, &request, first, SettleOutcome::Known(u64::MAX - 3)),
        Ok(u64::MAX - 3)
    );
    let after_first = books(&verifier);
    assert_eq!(after_first.charged, u64::MAX - 3);
    assert_eq!(after_first.held, 0);
    let second = verifier.reserve(&call, &request, 10).expect("reserve");
    let refusal = verifier
        .settle(&call, &request, second, SettleOutcome::Known(4))
        .expect_err("past the u64 charge");
    assert_eq!(refusal, SettleRefuse::ChargeOverflow);
    assert_eq!(refusal.to_string(), "settled charge does not fit in u64");
    let after_refusal = books(&verifier);
    assert_eq!(after_refusal.held, 10);
    assert_eq!(after_refusal.charged, u64::MAX - 3);
    assert_eq!(after_refusal.open.get(&second.id), Some(&10));
    assert_eq!(
        verifier.settle(&call, &request, second, SettleOutcome::Known(3)),
        Ok(3)
    );
    let after_second = books(&verifier);
    assert_eq!(after_second.charged, u64::MAX);
    assert_eq!(after_second.held, 0);
    assert!(!after_second.open.contains_key(&second.id));
}

#[test]
fn model_settle_on_another_handle_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-1", "session-a");
    let holder = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let other = verifier
        .bind_grant(second, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    assert_ne!(holder, other);
    verifier.admit(10);
    let call = verifier.open_call(first);
    let request = guest(holder);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    let refusal = verifier
        .settle(
            &verifier.open_call(second),
            &guest(other),
            reservation,
            SettleOutcome::Known(4),
        )
        .expect_err("another handle");
    assert_eq!(refusal, SettleRefuse::OtherHandle);
    assert_eq!(
        refusal.to_string(),
        "reservation is bound to another handle"
    );
    let after_refusal = books(&verifier);
    assert_eq!(after_refusal.held, 4);
    assert_eq!(after_refusal.charged, 0);
    assert_eq!(after_refusal.open.get(&reservation.id), Some(&4));
    assert_eq!(
        verifier.settle(&call, &request, reservation, SettleOutcome::Known(4)),
        Ok(4)
    );
    let after_settle = books(&verifier);
    assert_eq!(after_settle.charged, 4);
    assert_eq!(after_settle.held, 0);
    assert!(!after_settle.open.contains_key(&reservation.id));
}

#[test]
fn model_release_on_another_handle_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-1", "session-a");
    let holder = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let other = verifier
        .bind_grant(second, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    assert_ne!(holder, other);
    verifier.admit(10);
    let call = verifier.open_call(first);
    let request = guest(holder);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    let refusal = verifier
        .release(&verifier.open_call(second), &guest(other), reservation)
        .expect_err("another handle");
    assert_eq!(refusal, ReleaseRefuse::OtherHandle);
    assert_eq!(
        refusal.to_string(),
        "reservation is bound to another handle"
    );
    let after_refusal = books(&verifier);
    assert_eq!(after_refusal.held, 4);
    assert_eq!(after_refusal.charged, 0);
    assert_eq!(after_refusal.open.get(&reservation.id), Some(&4));
    assert_eq!(verifier.release(&call, &request, reservation), Ok(()));
    let after_release = books(&verifier);
    assert_eq!(after_release.charged, 0);
    assert_eq!(after_release.held, 0);
    assert!(!after_release.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_ceiling_does_not_raise_the_ceiling() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(5);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_ceiling: 100,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 5);
    let refusal = verifier
        .reserve(&call, &request, 6)
        .expect_err("forged ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 5,
            held: 0,
            asked: 6,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after_refusal = books(&verifier);
    assert_eq!(after_refusal.held, 0);
    assert_eq!(after_refusal.charged, 0);
    assert!(after_refusal.open.is_empty());
    verifier
        .reserve(&call, &request, 5)
        .expect("at the stored ceiling");
    assert_eq!(books(&verifier).held, 5);
}

#[test]
fn model_lower_ceiling_leaves_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let reservation = verifier.reserve(&call, &guest(handle), 8).expect("reserve");
    verifier.admit(4);
    let after = books(&verifier);
    assert_eq!(after.held, 8);
    assert_eq!(after.charged, 0);
    assert_eq!(after.open.get(&reservation.id), Some(&8));
    let refusal = verifier
        .reserve(&call, &guest(handle), 1)
        .expect_err("lower ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 8,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let still = books(&verifier);
    assert_eq!(still.held, 8);
    assert_eq!(still.charged, 0);
    assert_eq!(still.open.get(&reservation.id), Some(&8));
}

#[test]
fn model_known_zero_settle_frees_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 7,
        ..guest(handle)
    };
    let reservation = verifier.reserve(&call, &request, 8).expect("reserve");
    assert_eq!(books(&verifier).held, 8);
    assert_eq!(
        verifier.settle(&call, &request, reservation, SettleOutcome::Known(0)),
        Ok(0)
    );
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
    verifier.reserve(&call, &request, 10).expect("freed hold");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(books(&verifier).charged, 0);
}

#[test]
fn model_one_release_returns_only_that_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = guest(handle);
    let first = verifier.reserve(&call, &request, 6).expect("reserve");
    let second = verifier.reserve(&call, &request, 4).expect("reserve");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(verifier.release(&call, &request, first), Ok(()));
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert!(!after.open.contains_key(&first.id));
    assert_eq!(after.open.get(&second.id), Some(&4));
}

#[test]
fn model_one_settle_drops_only_that_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = guest(handle);
    let first = verifier.reserve(&call, &request, 6).expect("reserve");
    let second = verifier.reserve(&call, &request, 4).expect("reserve");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(
        verifier.settle(&call, &request, first, SettleOutcome::Known(6)),
        Ok(6)
    );
    let after = books(&verifier);
    assert_eq!(after.charged, 6);
    assert_eq!(after.held, 4);
    assert!(!after.open.contains_key(&first.id));
    assert_eq!(after.open.get(&second.id), Some(&4));
}

#[test]
fn model_settled_reservation_id_is_not_reused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = guest(handle);
    let first = verifier.reserve(&call, &request, 6).expect("reserve");
    let measured = 6;
    assert_eq!(
        verifier.settle(&call, &request, first, SettleOutcome::Known(measured)),
        Ok(6)
    );
    let second = verifier.reserve(&call, &request, 4).expect("reserve");
    let stale = verifier
        .settle(&call, &request, first, SettleOutcome::Known(4))
        .expect_err("settled id is not reused");
    assert_eq!(stale, SettleRefuse::NotOutstanding);
    assert_eq!(stale.to_string(), "reservation is not outstanding");
    assert_ne!(second.id, first.id);
    let after = books(&verifier);
    assert_eq!(after.charged, 6);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&second.id), Some(&4));
    assert!(!after.open.contains_key(&first.id));
}

#[test]
fn model_reserve_before_admit_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    let refusal = verifier
        .reserve(&call, &guest(handle), 1)
        .expect_err("reserve before admit");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 0,
            held: 0,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after_refusal = books(&verifier);
    assert_eq!(after_refusal.held, 0);
    assert_eq!(after_refusal.charged, 0);
    assert!(after_refusal.open.is_empty());
    verifier.admit(1);
    verifier
        .reserve(&call, &guest(handle), 1)
        .expect("admit opens the ceiling");
    assert_eq!(books(&verifier).held, 1);
}

#[test]
fn model_reported_usage_does_not_open_ceiling_room() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(5);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    let refusal = verifier
        .reserve(&call, &request, 6)
        .expect_err("reported usage does not open room");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 5,
            held: 0,
            asked: 6,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after_refusal = books(&verifier);
    assert_eq!(after_refusal.held, 0);
    assert_eq!(after_refusal.charged, 0);
    assert!(after_refusal.open.is_empty());
    verifier
        .reserve(&call, &request, 5)
        .expect("at the stored ceiling");
    assert_eq!(books(&verifier).held, 5);
}

#[test]
fn model_released_reservation_id_is_not_reused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = guest(handle);
    let released = verifier.reserve(&call, &request, 6).expect("reserve");
    assert_eq!(verifier.release(&call, &request, released), Ok(()));
    let second = verifier.reserve(&call, &request, 4).expect("reserve");
    let stale = verifier
        .settle(&call, &request, released, SettleOutcome::Known(4))
        .expect_err("released id is not reused");
    assert_eq!(stale, SettleRefuse::NotOutstanding);
    assert_eq!(stale.to_string(), "reservation is not outstanding");
    assert_ne!(second.id, released.id);
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&second.id), Some(&4));
    assert!(!after.open.contains_key(&released.id));
}

#[test]
fn model_reported_usage_does_not_keep_the_released_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    let reservation = verifier.reserve(&call, &request, 10).expect("reserve");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(verifier.release(&call, &request, reservation), Ok(()));
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
    verifier
        .reserve(&call, &request, 10)
        .expect("the released hold is free");
    let freed = books(&verifier);
    assert_eq!(freed.held, 10);
    assert_eq!(freed.charged, 0);
}

#[test]
fn model_lower_ceiling_does_not_refuse_the_settle() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 8).expect("reserve");
    verifier.admit(4);
    assert_eq!(books(&verifier).held, 8);
    assert_eq!(books(&verifier).charged, 0);
    assert_eq!(
        verifier.settle(&call, &request, reservation, SettleOutcome::Known(8)),
        Ok(8)
    );
    let after = books(&verifier);
    assert_eq!(after.charged, 8);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
    let refusal = verifier
        .reserve(&call, &request, 5)
        .expect_err("lowered ceiling still bounds a new reserve");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 5,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    verifier
        .reserve(&call, &request, 4)
        .expect("room under the lowered ceiling");
    let freed = books(&verifier);
    assert_eq!(freed.held, 4);
    assert_eq!(freed.charged, 8);
}

#[test]
fn model_forged_ceiling_does_not_replace_the_settled_charge() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(10);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_ceiling: 9,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 0);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("settle");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}
