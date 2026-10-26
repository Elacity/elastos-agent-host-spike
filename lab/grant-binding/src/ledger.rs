//! The one ledger the verifier owns: the ceiling, the outstanding holds, the
//! reservations recorded so far and the total charged by settled holds.
//!
//! `admit` sets the allowance ceiling and leaves outstanding holds alone.
//! `reserve` first takes the binding decision from `Verifier::resolve`, then
//! records the hold on this ledger. `settle` and `release` are the only ways a
//! hold ends, and both take that same binding decision first. The guest's
//! `reported_usage` claim is not read: a known settle charges the figure the
//! verifier passes in, and an unknown outcome keeps the hold.

use std::collections::HashMap;

use crate::{Call, GuestRequest, Refuse, Verifier};

/// The one ledger the verifier owns.
#[derive(Debug)]
pub(crate) struct Ledger {
    ceiling: u64,
    held: u64,
    next_reservation: u64,
    charged: u64,
    open: HashMap<u64, u64>,
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
    Binding(Refuse),
}

impl std::fmt::Display for SettleRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettleRefuse::UnknownOutcome => formatter.write_str("unknown outcome keeps the hold"),
            SettleRefuse::NotOutstanding => formatter.write_str("reservation is not outstanding"),
            SettleRefuse::Binding(refusal) => refusal.fmt(formatter),
        }
    }
}

/// A refused release with one clear reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRefuse {
    NotOutstanding,
    Binding(Refuse),
}

impl std::fmt::Display for ReleaseRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseRefuse::NotOutstanding => formatter.write_str("reservation is not outstanding"),
            ReleaseRefuse::Binding(refusal) => refusal.fmt(formatter),
        }
    }
}

impl Verifier {
    /// Sets the allowance ceiling. Outstanding holds stay as they are.
    pub fn admit(&mut self, ceiling: u64) {
        self.ledger.ceiling = ceiling;
    }

    /// Holds `amount` on the ledger when the outstanding total plus `amount`
    /// stays at or under the ceiling. A binding refusal records nothing, a sum
    /// that does not fit in `u64` is over the ceiling, and the request's
    /// reported usage does not lower the hold.
    pub fn reserve(
        &mut self,
        call: &Call,
        request: &GuestRequest,
        amount: u64,
    ) -> Result<Reservation, ReserveRefuse> {
        self.resolve(*call, request.handle)
            .map_err(ReserveRefuse::Binding)?;
        let held = self.ledger.held;
        let total = match held.checked_add(amount) {
            Some(total) if total <= self.ledger.ceiling => total,
            _ => {
                return Err(ReserveRefuse::OverCeiling {
                    ceiling: self.ledger.ceiling,
                    held,
                    asked: amount,
                })
            }
        };
        self.ledger.held = total;
        self.ledger.next_reservation += 1;
        self.ledger
            .open
            .insert(self.ledger.next_reservation, amount);
        Ok(Reservation {
            id: self.ledger.next_reservation,
        })
    }

    /// Ends one hold with the figure the host measured. A binding refusal
    /// records nothing, an unknown outcome keeps the hold as it is, and a
    /// reservation that is not outstanding is refused. A known outcome charges
    /// the measured figure, gives back the stored hold and returns the charge;
    /// the request's reported usage does not lower it.
    pub fn settle(
        &mut self,
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
        let stored = match self.ledger.open.get(&reservation.id) {
            Some(stored) => *stored,
            None => return Err(SettleRefuse::NotOutstanding),
        };
        let charge = measured;
        self.ledger.charged += charge;
        self.ledger.held -= stored;
        self.ledger.open.remove(&reservation.id);
        Ok(charge)
    }

    /// Ends one hold without charging anything. A binding refusal records
    /// nothing and a reservation that is not outstanding is refused.
    pub fn release(
        &mut self,
        call: &Call,
        request: &GuestRequest,
        reservation: Reservation,
    ) -> Result<(), ReleaseRefuse> {
        self.resolve(*call, request.handle)
            .map_err(ReleaseRefuse::Binding)?;
        let amount = match self.ledger.open.get(&reservation.id) {
            Some(amount) => *amount,
            None => return Err(ReleaseRefuse::NotOutstanding),
        };
        self.ledger.open.remove(&reservation.id);
        self.ledger.held -= amount;
        Ok(())
    }
}

#[cfg(test)]
use crate::{guest, rights, Handle, InstanceId};

/// Registers one instance with a fresh grant and returns both.
#[cfg(test)]
fn bound(verifier: &mut Verifier) -> (InstanceId, Handle) {
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    (instance, handle)
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
    assert_eq!(verifier.ledger.held, 5);
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
    assert_eq!(verifier.ledger.held, 0);
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
    assert_eq!(verifier.ledger.held, u64::MAX);
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
    assert_eq!(verifier.ledger.held, u64::MAX);
    let again = verifier
        .reserve(&call, &guest(handle), u64::MAX)
        .expect_err("still over the ceiling");
    assert_eq!(again.to_string(), "reservation exceeds the ceiling");
    assert_eq!(verifier.ledger.held, u64::MAX);
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
    assert_eq!(verifier.ledger.held, 3);
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
    assert_eq!(verifier.ledger.held, 10);
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
    assert_eq!(verifier.ledger.held, 0);
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
    assert_eq!(verifier.ledger.charged, 10);
    assert_eq!(verifier.ledger.held, 0);
    assert!(!verifier.ledger.open.contains_key(&reservation.id));
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
    assert_eq!(verifier.ledger.charged, 10);
    assert_eq!(verifier.ledger.held, 0);
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
    assert_eq!(verifier.ledger.charged, 10);
    assert_eq!(verifier.ledger.held, 0);
    let refusal = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(10))
        .expect_err("second settle");
    assert_eq!(refusal, SettleRefuse::NotOutstanding);
    assert_eq!(refusal.to_string(), "reservation is not outstanding");
    assert_eq!(verifier.ledger.charged, 10);
    assert_eq!(verifier.ledger.held, 0);
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
    assert_eq!(verifier.ledger.held, 10);
    assert_eq!(verifier.ledger.charged, 0);
    assert!(verifier.ledger.open.contains_key(&reservation.id));
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
    assert_eq!(verifier.ledger.held, 0);
    assert_eq!(verifier.ledger.charged, 0);
    assert!(!verifier.ledger.open.contains_key(&reservation.id));
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
    assert_eq!(verifier.ledger.held, 10);
    assert_eq!(verifier.ledger.charged, 0);
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
    assert_eq!(verifier.ledger.held, 10);
    assert_eq!(verifier.ledger.charged, 0);
    assert!(verifier.ledger.open.contains_key(&reservation.id));
}
