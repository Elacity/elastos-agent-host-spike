//! The one ledger the verifier owns: the ceiling, the outstanding holds and
//! the reservations recorded so far.
//!
//! `admit` sets the allowance ceiling and leaves outstanding holds alone.
//! `reserve` first takes the binding decision from `Verifier::resolve`, then
//! records the hold on this ledger. The guest's `reported_usage` claim is not
//! read.

use crate::{Call, GuestRequest, Refuse, Verifier};

/// The one ledger the verifier owns.
#[derive(Debug)]
pub(crate) struct Ledger {
    ceiling: u64,
    held: u64,
    next_reservation: u64,
}

impl Ledger {
    /// An empty ledger: no ceiling and nothing held.
    pub(crate) fn new() -> Self {
        Self {
            ceiling: 0,
            held: 0,
            next_reservation: 0,
        }
    }
}

/// A hold on the ledger. Its id is the ledger's own record of the hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    #[allow(dead_code)] // later slices settle and release by this id
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

impl Verifier {
    /// Sets the allowance ceiling. Outstanding holds stay as they are.
    pub fn admit(&mut self, ceiling: u64) {
        self.ledger.ceiling = ceiling;
    }

    /// Holds `amount` on the ledger when the outstanding total plus `amount`
    /// stays at or under the ceiling. A binding refusal records nothing, and
    /// the request's reported usage does not lower the hold.
    pub fn reserve(
        &mut self,
        call: &Call,
        request: &GuestRequest,
        amount: u64,
    ) -> Result<Reservation, ReserveRefuse> {
        self.resolve(*call, request.handle)
            .map_err(ReserveRefuse::Binding)?;
        let held = self.ledger.held;
        let over_ceiling = held.saturating_add(amount) > self.ledger.ceiling;
        if over_ceiling {
            return Err(ReserveRefuse::OverCeiling {
                ceiling: self.ledger.ceiling,
                held,
                asked: amount,
            });
        }
        self.ledger.held = held + amount;
        self.ledger.next_reservation += 1;
        Ok(Reservation {
            id: self.ledger.next_reservation,
        })
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
