//! The one ledger the verifier owns: the ceiling, the outstanding holds, the
//! reservations recorded so far and the total charged by settled holds.
//!
//! `admit` sets the allowance ceiling and leaves outstanding holds alone.
//! `reserve` first takes the binding decision from `Verifier::resolve`, then
//! records the hold on this ledger. `settle` and `release` end a hold.
//! `timeout_hold` records an uncertain hold and does not end it. Each takes
//! the binding decision first.
//! The guest's
//! `reported_usage` claim is not read: a known settle charges the figure the
//! verifier passes in when it stays at or under the stored hold, refuses a
//! larger one, and an unknown outcome marks that hold uncertain when its bound
//! handle is presented and keeps it, release of an uncertain hold is refused,
//! a timeout before the verifier deadline is refused, a timeout when the
//! verifier never set a deadline is refused, and a timeout at a deadline the
//! verifier set records timed out, outcome unknown and keeps the hold. The
//! ledger value sits behind one mutex, and admit, reserve, settle, release,
//! and timeout_hold lock it for the check and the write.

use std::collections::HashMap;

use crate::{Call, EndedGrant, GuestRequest, Handle, HeldGrant, Refuse, Verifier};

/// Copies the binding a hold keeps once its grant ends.
fn held_binding(grant: &EndedGrant) -> HeldGrant {
    HeldGrant {
        record: grant.record.clone(),
    }
}

#[derive(Debug, Clone, Copy)]
struct OpenHold {
    handle: Handle,
    amount: u64,
    uncertain: bool,
    timed_out: bool,
    deadline: u64,
    deadline_set: bool,
}

fn handles_match(bound: Handle, presented: Handle) -> bool {
    bound == presented
}

fn held_for_identity(
    open: &HashMap<u64, OpenHold>,
    grants: &HashMap<Handle, crate::EndedGrant>,
    identity: &str,
) -> u64 {
    let mut sum: u64 = 0;
    for open_hold in open.values() {
        let Some(grant) = grants.get(&open_hold.handle) else {
            continue;
        };
        if grant.record.identity != identity {
            continue;
        }
        sum = sum.saturating_add(open_hold.amount);
    }
    sum
}

/// The one ledger the verifier owns.
#[derive(Debug)]
pub(crate) struct Ledger {
    ceiling: u64,
    admitted: u64,
    ceilings: HashMap<String, u64>,
    held: u64,
    next_reservation: u64,
    charged: u64,
    verifier_deadline: u64,
    deadline_set: bool,
    open: HashMap<u64, OpenHold>,
    /// The ended bindings a hold keeps, by handle.
    pub(crate) ended: HashMap<Handle, HeldGrant>,
}

impl Ledger {
    /// An empty ledger: no ceiling, nothing held and nothing charged.
    pub(crate) fn new() -> Self {
        Self {
            ceiling: 0,
            admitted: 0,
            ceilings: HashMap::new(),
            held: 0,
            next_reservation: 0,
            charged: 0,
            verifier_deadline: 0,
            deadline_set: false,
            open: HashMap::new(),
            ended: HashMap::new(),
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
    SumOverflow { held: u64, asked: u64 },
    NoCeiling,
    Binding(Refuse),
}

impl std::fmt::Display for ReserveRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReserveRefuse::OverCeiling { .. } => {
                formatter.write_str("reservation exceeds the ceiling")
            }
            ReserveRefuse::SumOverflow { .. } => {
                formatter.write_str("reservation sum does not fit in u64")
            }
            ReserveRefuse::NoCeiling => formatter.write_str("identity has no ceiling"),
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
    Uncertain,
    Binding(Refuse),
}

impl std::fmt::Display for ReleaseRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseRefuse::NotOutstanding => formatter.write_str("reservation is not outstanding"),
            ReleaseRefuse::OtherHandle => {
                formatter.write_str("reservation is bound to another handle")
            }
            ReleaseRefuse::Uncertain => formatter.write_str("uncertain hold is not released"),
            ReleaseRefuse::Binding(refusal) => refusal.fmt(formatter),
        }
    }
}

/// A refused timeout with one clear reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutRefuse {
    NotUncertain,
    NotOutstanding,
    OtherHandle,
    Early,
    NoDeadline,
    Binding(Refuse),
}

impl std::fmt::Display for TimeoutRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeoutRefuse::NotUncertain => formatter.write_str("hold is not uncertain"),
            TimeoutRefuse::NotOutstanding => formatter.write_str("reservation is not outstanding"),
            TimeoutRefuse::OtherHandle => {
                formatter.write_str("reservation is bound to another handle")
            }
            TimeoutRefuse::Early => formatter.write_str("timeout is before the verifier deadline"),
            TimeoutRefuse::NoDeadline => formatter.write_str("verifier deadline is not set"),
            TimeoutRefuse::Binding(refusal) => refusal.fmt(formatter),
        }
    }
}

/// The record a due timeout leaves on an uncertain hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutRecord;

impl std::fmt::Display for TimeoutRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("timed out, outcome unknown")
    }
}

impl Verifier {
    /// Records `ceiling`, the last admitted ceiling, in one ledger lock. An
    /// identity updates records the ceiling for that identity alone. None
    /// lowers every identity ceiling above `ceiling` and leaves no identity
    /// above it. `ceiling` is stored in the same lock.
    pub(super) fn store_admitted_ceiling(&self, identity: Option<&str>, ceiling: u64) {
        let mut ledger = self.ledger.lock().expect("ledger lock");
        ledger.admitted = ceiling;
        match identity {
            Some(identity) => {
                ledger.ceilings.insert(identity.to_owned(), ceiling);
            }
            None => {
                for stored in ledger.ceilings.values_mut() {
                    *stored = (*stored).min(ceiling);
                }
            }
        }
        ledger.ceiling = ceiling;
    }

    /// Sets the allowance ceiling. Outstanding holds stay as they are.
    /// Every identity ceiling above `ceiling` is lowered to it, and an
    /// identity with no ceiling keeps none until an ask names it.
    pub fn admit(&self, ceiling: u64) {
        self.store_admitted_ceiling(None, ceiling);
    }

    /// Holds `amount` on the ledger when the total this identity compares plus
    /// `amount` stays at or under the ceiling. A binding refusal records nothing,
    /// an identity with no stored ceiling is refused with no ceiling, a total
    /// that does not fit in `u64` is over the ceiling, a stored sum of every
    /// open hold plus `amount` that does not fit in `u64` is a sum overflow,
    /// and the request's reported usage does not lower the hold.
    pub fn reserve(
        &self,
        call: &Call,
        request: &GuestRequest,
        amount: u64,
    ) -> Result<Reservation, ReserveRefuse> {
        self.resolve(*call, request.handle)
            .map_err(ReserveRefuse::Binding)?;
        let identity = self
            .grants
            .get(&request.handle)
            .expect("resolved grant")
            .record
            .identity
            .clone();
        let mut ledger = self.ledger.lock().expect("ledger lock");
        let held = ledger.held;
        let shared = held;
        let own = held_for_identity(&ledger.open, &self.grants, &identity);
        let held = if ledger.ceilings.contains_key(&identity) {
            own
        } else {
            shared
        };
        if !ledger.ceilings.contains_key(&identity) {
            return Err(ReserveRefuse::NoCeiling);
        }
        ledger.ceiling = ledger.admitted;
        if let Some(agent_ceiling) = ledger.ceilings.get(&identity).copied() {
            ledger.ceiling = agent_ceiling;
        }
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
        let put_back = if ledger.ceilings.contains_key(&identity) {
            match shared.checked_add(amount) {
                Some(shared_total) => Some(shared_total),
                None => {
                    return Err(ReserveRefuse::SumOverflow {
                        held: shared,
                        asked: amount,
                    })
                }
            }
        } else {
            None
        };
        ledger.held = total;
        if let Some(shared_total) = put_back {
            ledger.held = shared_total;
        }
        ledger.next_reservation += 1;
        ledger.open.insert(
            ledger.next_reservation,
            OpenHold {
                handle: request.handle,
                amount,
                uncertain: false,
                timed_out: false,
                deadline: 0,
                deadline_set: false,
            },
        );
        Ok(Reservation {
            id: ledger.next_reservation,
        })
    }

    /// Ends one hold with the figure the host measured. A binding refusal
    /// records nothing, an unknown outcome marks that hold uncertain when the
    /// presented handle is the one bound to it and keeps it, and a reservation
    /// that is not outstanding is refused. A known outcome charges the
    /// measured figure when it stays at or under the stored hold, gives back
    /// the stored hold and returns the charge; a larger figure is refused and
    /// records nothing. The request's reported usage does not lower it.
    pub fn settle(
        &self,
        call: &Call,
        request: &GuestRequest,
        reservation: Reservation,
        outcome: SettleOutcome,
    ) -> Result<u64, SettleRefuse> {
        // A hold that opened before its grant ended resolves through the kept
        // binding; every other refusal stands as `resolve` made it.
        self.resolve_for_hold(*call, request.handle)
            .map_err(SettleRefuse::Binding)?;
        let measured = match outcome {
            SettleOutcome::Known(measured) => measured,
            SettleOutcome::Unknown => {
                {
                    let mut ledger = self.ledger.lock().expect("ledger lock");
                    let ledger: &mut Ledger = &mut ledger;
                    if let Some(open) = ledger.open.get_mut(&reservation.id) {
                        if handles_match(open.handle, request.handle) {
                            open.uncertain = true;
                            open.deadline = ledger.verifier_deadline;
                            open.deadline_set = ledger.deadline_set;
                        }
                    }
                }
                return Err(SettleRefuse::UnknownOutcome);
            }
        };
        let mut ledger = self.ledger.lock().expect("ledger lock");
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
        // The ended binding left with its last hold.
        Self::clear_gone(&mut ledger, bound);
        Ok(charge)
    }

    /// Stores the deadline the next unknown settle copies onto its hold
    /// and marks that deadline as set. The guest does not pass this value.
    pub fn set_verifier_deadline(&self, deadline: u64) {
        let mut ledger = self.ledger.lock().expect("ledger lock");
        ledger.verifier_deadline = deadline;
        ledger.deadline_set = true;
    }

    /// Records a due timeout on an uncertain hold. A binding refusal records
    /// nothing, a reservation that is not outstanding is refused, a hold that
    /// is not uncertain stays open, a hold whose deadline was never set is
    /// refused, and a timeout that arrives before the verifier deadline is
    /// refused. A due timeout records timed out, outcome unknown and keeps
    /// the hold, so a second timeout records it again.
    pub fn timeout_hold(
        &self,
        call: &Call,
        request: &GuestRequest,
        reservation: Reservation,
        now: u64,
    ) -> Result<TimeoutRecord, TimeoutRefuse> {
        // A hold that opened before its grant ended resolves through the kept
        // binding; every other refusal stands as `resolve` made it.
        self.resolve_for_hold(*call, request.handle)
            .map_err(TimeoutRefuse::Binding)?;
        let mut ledger = self.ledger.lock().expect("ledger lock");
        let open = match ledger.open.get(&reservation.id) {
            Some(open) => (
                open.handle,
                open.amount,
                open.uncertain,
                open.deadline,
                open.deadline_set,
            ),
            None => return Err(TimeoutRefuse::NotOutstanding),
        };
        let (bound, amount, uncertain, deadline, deadline_set) = open;
        if !handles_match(bound, request.handle) {
            return Err(TimeoutRefuse::OtherHandle);
        }
        if !uncertain {
            return Err(TimeoutRefuse::NotUncertain);
        }
        if !deadline_set {
            return Err(TimeoutRefuse::NoDeadline);
        }
        if now < deadline {
            return Err(TimeoutRefuse::Early);
        }
        let _kept = amount;
        if let Some(open) = ledger.open.get_mut(&reservation.id) {
            open.timed_out = true;
        }
        Ok(TimeoutRecord)
    }

    /// Drops the ended binding once no open hold uses it, so an ended handle
    /// leaves the ledger with its last hold. While a hold uses it the binding
    /// stays, because `settle` and `release` still resolve it.
    fn clear_gone(ledger: &mut Ledger, handle: Handle) {
        if ledger.open.values().any(|open| open.handle == handle) {
            return;
        }
        ledger.ended.remove(&handle);
    }

    /// Ends one handle's binding (M1 check A7, condition c). The store keeps
    /// the record, marked ended, so every later use of that handle is refused
    /// with `unknown handle`, the same refusal an unbound handle gets. A
    /// handle that already ended is not an error. A stop or revoke path is its
    /// only caller and passes the handle the grant route stored.
    ///
    /// The record also goes to the ledger, so a hold the handle opened before
    /// the end still resolves through `settle`, `release` and `timeout_hold`
    /// and gives back its amount. `held_for_identity` counts it until then,
    /// and the ledger forgets the record with that last hold. A grant ended
    /// with no open hold leaves the ledger at once.
    pub fn end_grant(&mut self, handle: Handle) {
        if let Some(grant) = self.grants.get_mut(&handle) {
            grant.ended = true;
            let mut ledger = self.ledger.lock().expect("ledger lock");
            ledger
                .ended
                .entry(handle)
                .or_insert_with(|| held_binding(grant));
            Self::clear_gone(&mut ledger, handle);
        }
    }

    /// Returns one hold's amount to the ceiling and drops the hold.
    #[allow(unused_variables)]
    fn return_unused_hold(
        ledger: &mut Ledger,
        reservation: Reservation,
        amount: u64,
        request: &GuestRequest,
    ) {
        ledger.open.remove(&reservation.id);
        ledger.held -= amount;
    }

    /// Ends one hold without charging anything. A binding refusal records
    /// nothing and a reservation that is not outstanding is refused. Only the
    /// bound handle's unknown settle makes a hold uncertain; an uncertain hold
    /// is refused and stays open with its amount still held.
    pub fn release(
        &self,
        call: &Call,
        request: &GuestRequest,
        reservation: Reservation,
    ) -> Result<(), ReleaseRefuse> {
        // A hold that opened before its grant ended resolves through the kept
        // binding; every other refusal stands as `resolve` made it.
        self.resolve_for_hold(*call, request.handle)
            .map_err(ReleaseRefuse::Binding)?;
        let mut ledger = self.ledger.lock().expect("ledger lock");
        let (bound, amount, uncertain) = match ledger.open.get(&reservation.id) {
            Some(open) => (open.handle, open.amount, open.uncertain),
            None => return Err(ReleaseRefuse::NotOutstanding),
        };
        if !handles_match(bound, request.handle) {
            return Err(ReleaseRefuse::OtherHandle);
        }
        if uncertain {
            return Err(ReleaseRefuse::Uncertain);
        }
        Self::return_unused_hold(&mut ledger, reservation, amount, request);
        // The ended binding left with its last hold.
        Self::clear_gone(&mut ledger, bound);
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
    timed_out: HashMap<u64, bool>,
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
        timed_out: ledger
            .open
            .iter()
            .filter(|(_, open)| open.timed_out)
            .map(|(id, open)| (*id, open.timed_out))
            .collect(),
    }
}

#[test]
fn model_end_grant_refuses_the_ended_handle() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .use_grant(call, &guest(handle))
        .expect("bound handle");
    verifier.end_grant(handle);
    let refusal = verifier
        .use_grant(call, &guest(handle))
        .expect_err("the ended handle no longer resolves");
    assert_eq!(refusal, Refuse::UnknownHandle);
    assert_eq!(refusal.to_string(), "unknown handle");
    assert_eq!(books(&verifier).held, 0, "ending a binding holds nothing");
}

/// Sets a ceiling of 5 for the bound identity and opens one hold of 5.
#[cfg(test)]
fn reserve_five(verifier: &mut Verifier, call: &Call, handle: Handle) -> Reservation {
    verifier
        .admit_ask(call, &guest(handle), crate::ask::BudgetAsk { amount: 5 }, 5)
        .expect("ask");
    verifier.reserve(call, &guest(handle), 5).expect("reserve")
}

#[test]
fn model_ended_grant_refuses_a_new_reserve() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 5 },
            5,
        )
        .expect("ask");
    verifier.end_grant(handle);
    let refusal = verifier
        .reserve(&call, &guest(handle), 1)
        .expect_err("the ended handle opens no hold");
    assert_eq!(refusal, ReserveRefuse::Binding(Refuse::UnknownHandle));
    assert_eq!(refusal.to_string(), "unknown handle");
    assert!(
        verifier
            .admit_ask(
                &call,
                &guest(handle),
                crate::ask::BudgetAsk { amount: 5 },
                5
            )
            .is_err(),
        "the ended handle admits no ask"
    );
    assert_eq!(books(&verifier).held, 0, "a refused reserve holds nothing");
}

#[test]
fn model_ended_grant_release_clears_the_hold_it_opened() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    let reservation = reserve_five(&mut verifier, &call, handle);
    assert_eq!(books(&verifier).held, 5);
    verifier.end_grant(handle);
    assert_eq!(
        verifier.release(&call, &guest(handle), reservation),
        Ok(()),
        "a hold opened before the end still releases"
    );
    assert_eq!(
        books(&verifier).held,
        0,
        "the released hold gives its amount back"
    );
    assert!(books(&verifier).open.is_empty(), "no hold stays open");
}

#[test]
fn model_ended_grant_settle_clears_the_hold_it_opened() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    let reservation = reserve_five(&mut verifier, &call, handle);
    verifier.end_grant(handle);
    assert_eq!(
        verifier.settle(&call, &guest(handle), reservation, SettleOutcome::Known(0)),
        Ok(0),
        "a hold opened before the end still settles"
    );
    assert_eq!(
        books(&verifier).held,
        0,
        "the settled hold gives its amount back"
    );
    assert!(books(&verifier).open.is_empty(), "no hold stays open");
}

#[test]
fn model_ended_grant_timeout_hold_reaches_the_hold_it_opened() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    let reservation = reserve_five(&mut verifier, &call, handle);
    verifier.set_verifier_deadline(10);
    assert_eq!(
        verifier.settle(&call, &guest(handle), reservation, SettleOutcome::Unknown),
        Err(SettleRefuse::UnknownOutcome)
    );
    verifier.end_grant(handle);
    assert_eq!(
        verifier.timeout_hold(&call, &guest(handle), reservation, 10),
        Ok(TimeoutRecord),
        "a hold opened before the end still times out at its deadline"
    );
    assert_eq!(
        books(&verifier).timed_out.get(&reservation.id),
        Some(&true),
        "the kept uncertain hold records its timeout"
    );
    assert_eq!(
        books(&verifier).held,
        5,
        "the uncertain hold stays counted while it is open"
    );
}

#[test]
fn model_reserve_at_the_ceiling_is_allowed() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 5 },
            5,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 5 },
            5,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: u64::MAX },
            u64::MAX,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 5 },
            5,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        reported_usage: 11,
        ..guest(handle)
    };
    assert!(request.reported_usage > 10);
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
fn model_forged_instance_does_not_move_the_reserve() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    let reservation = verifier
        .reserve(&call, &request, 4)
        .expect("forged instance does not move the reserve");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_append_does_not_move_the_reserve() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let reservation = verifier
        .reserve(&call, &request, 4)
        .expect("forged append does not move the reserve");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_overwrite_does_not_move_the_reserve() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    let reservation = verifier
        .reserve(&call, &request, 4)
        .expect("forged overwrite does not move the reserve");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_child_journal_does_not_move_the_reserve() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let reservation = verifier
        .reserve(&call, &request, 4)
        .expect("forged child journal does not move the reserve");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_identity_does_not_move_the_reserve() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let reservation = verifier
        .reserve(&call, &request, 4)
        .expect("forged identity does not move the reserve");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_session_does_not_move_the_reserve() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let reservation = verifier
        .reserve(&call, &request, 4)
        .expect("forged session does not move the reserve");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_ceiling_does_not_move_the_reserve() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_ceiling: 1,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 0);
    let reservation = verifier
        .reserve(&call, &request, 4)
        .expect("forged ceiling does not move the reserve");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_reported_usage_does_not_move_the_reserve() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    let reservation = verifier
        .reserve(&call, &request, 4)
        .expect("reported usage does not move the reserve");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_settle_known_outcome_charges_the_measured_figure() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
fn model_forged_instance_does_not_move_the_release() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    verifier
        .release(&call, &request, reservation)
        .expect("forged instance does not move the release");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_append_does_not_move_the_release() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    verifier
        .release(&call, &request, reservation)
        .expect("forged append does not move the release");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_overwrite_does_not_move_the_release() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    verifier
        .release(&call, &request, reservation)
        .expect("forged overwrite does not move the release");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_child_journal_does_not_move_the_release() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    verifier
        .release(&call, &request, reservation)
        .expect("forged child journal does not move the release");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_identity_does_not_move_the_release() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    verifier
        .release(&call, &request, reservation)
        .expect("forged identity does not move the release");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_session_does_not_move_the_release() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    verifier
        .release(&call, &request, reservation)
        .expect("forged session does not move the release");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_ceiling_does_not_move_the_release() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_ceiling: 1,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 0);
    verifier
        .release(&call, &request, reservation)
        .expect("forged ceiling does not move the release");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_reported_usage_does_not_move_the_release() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    verifier
        .release(&call, &request, reservation)
        .expect("reported usage does not move the release");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_settle_below_the_hold_returns_the_rest() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 5 },
            5,
        )
        .expect("ask");
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
    let after = books(&verifier);
    assert_eq!(after.held, 3);
    assert_eq!(after.charged, 0);
    assert_eq!(after.open.len(), 1);
    let (third, fourth) = std::thread::scope(|scope| {
        let third = scope.spawn(|| verifier.reserve(&call, &request, 1));
        let fourth = scope.spawn(|| verifier.reserve(&call, &request, 1));
        (third.join().expect("third"), fourth.join().expect("fourth"))
    });
    third.expect("both later reserves fit the ceiling");
    fourth.expect("both later reserves fit the ceiling");
    let filled = books(&verifier);
    assert_eq!(filled.held, 5);
    assert_eq!(filled.charged, 0);
    assert_eq!(filled.open.len(), 3);
}

#[test]
fn model_settle_above_the_reservation_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: u64::MAX },
            u64::MAX,
        )
        .expect("ask");
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 5 },
            5,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    assert_eq!(refusal, ReserveRefuse::NoCeiling);
    assert_eq!(refusal.to_string(), "identity has no ceiling");
    let after_refusal = books(&verifier);
    assert_eq!(after_refusal.held, 0);
    assert_eq!(after_refusal.charged, 0);
    assert!(after_refusal.open.is_empty());
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 0 },
            0,
        )
        .expect("zero ceiling");
    let zero = verifier
        .reserve(&call, &guest(handle), 1)
        .expect_err("a zero ceiling still refuses");
    assert_eq!(
        zero,
        ReserveRefuse::OverCeiling {
            ceiling: 0,
            held: 0,
            asked: 1,
        }
    );
    assert_eq!(zero.to_string(), "reservation exceeds the ceiling");
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 1 },
            1,
        )
        .expect("ask");
    verifier
        .reserve(&call, &guest(handle), 1)
        .expect("admit opens the ceiling");
    assert_eq!(books(&verifier).held, 1);
}

#[test]
fn model_reported_usage_does_not_open_ceiling_room() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 5 },
            5,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
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

#[test]
fn model_forged_append_does_not_retarget_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    assert_eq!(books(&verifier).held, 4);
    assert_eq!(books(&verifier).open.get(&reservation.id), Some(&4));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged append does not retarget the hold");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_overwrite_does_not_retarget_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    assert_eq!(books(&verifier).held, 4);
    assert_eq!(books(&verifier).open.get(&reservation.id), Some(&4));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged overwrite does not retarget the hold");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_child_journal_does_not_retarget_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    assert_eq!(books(&verifier).held, 4);
    assert_eq!(books(&verifier).open.get(&reservation.id), Some(&4));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged child journal does not retarget the hold");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_identity_does_not_retarget_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    assert_eq!(books(&verifier).held, 4);
    assert_eq!(books(&verifier).open.get(&reservation.id), Some(&4));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged identity does not retarget the hold");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_session_does_not_retarget_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    assert_eq!(books(&verifier).held, 4);
    assert_eq!(books(&verifier).open.get(&reservation.id), Some(&4));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged session does not retarget the hold");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_instance_does_not_retarget_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    assert_eq!(books(&verifier).held, 4);
    assert_eq!(books(&verifier).open.get(&reservation.id), Some(&4));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged instance does not retarget the hold");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_release_after_unknown_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    let refusal = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(refusal, SettleRefuse::UnknownOutcome);
    assert_eq!(refusal.to_string(), "unknown outcome keeps the hold");
    let blocked = verifier
        .release(&call, &request, reservation)
        .expect_err("uncertain hold is not released");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("measured settle ends the uncertain hold");
    assert_eq!(charge, 4);
    let settled = books(&verifier);
    assert_eq!(settled.charged, 4);
    assert_eq!(settled.held, 0);
    assert!(!settled.open.contains_key(&reservation.id));
}

#[test]
fn model_reported_usage_does_not_release_an_uncertain_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    let unknown = verifier
        .settle(&call, &reserved, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    let blocked = verifier
        .release(&call, &request, reservation)
        .expect_err("uncertain hold is not released");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_timeout_ends_an_uncertain_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(handle);
    let first = verifier.reserve(&call, &request, 4).expect("reserve");
    let second = verifier.reserve(&call, &request, 3).expect("reserve");
    let fresh = verifier
        .timeout_hold(&call, &request, first, 0)
        .expect_err("a fresh hold is not timed out");
    assert_eq!(fresh, TimeoutRefuse::NotUncertain);
    assert_eq!(fresh.to_string(), "hold is not uncertain");
    let before = books(&verifier);
    assert_eq!(before.charged, 0);
    assert_eq!(before.held, 7);
    assert_eq!(before.open.get(&first.id), Some(&4));
    assert_eq!(before.open.get(&second.id), Some(&3));
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &request, first, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    let blocked = verifier
        .release(&call, &request, first)
        .expect_err("release of an uncertain hold stays refused");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
    assert_eq!(books(&verifier).held, 7);
    assert_eq!(books(&verifier).charged, 0);
    let record = verifier
        .timeout_hold(&call, &request, first, 0)
        .expect("a due timeout records the uncertain hold");
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 7);
    assert_eq!(after.open.get(&first.id), Some(&4));
    assert_eq!(after.open.get(&second.id), Some(&3));
    assert!(after.timed_out.contains_key(&first.id));
    assert!(!after.timed_out.contains_key(&second.id));
    let blocked = verifier
        .release(&call, &request, first)
        .expect_err("release of a recorded hold stays refused");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
}

#[test]
fn model_known_settle_after_timeout_still_charges() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("a due timeout records the uncertain hold");
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let recorded = books(&verifier);
    assert_eq!(recorded.charged, 0);
    assert_eq!(recorded.held, 4);
    assert_eq!(recorded.open.get(&reservation.id), Some(&4));
    assert!(recorded.timed_out.contains_key(&reservation.id));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("measured settle charges the recorded hold");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
    assert!(!after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_early_timeout_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    verifier.set_verifier_deadline(5);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 4)
        .expect_err("timeout is before the verifier deadline");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    let record = verifier
        .timeout_hold(&call, &request, reservation, 5)
        .expect("deadline reached");
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    assert!(after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_unset_deadline_timeout_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let refusal = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect_err("unset deadline is not due");
    assert_eq!(refusal, TimeoutRefuse::NoDeadline);
    assert_eq!(refusal.to_string(), "verifier deadline is not set");
    let later = verifier
        .timeout_hold(&call, &request, reservation, 100)
        .expect_err("a later instant is still unset");
    assert_eq!(later, TimeoutRefuse::NoDeadline);
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_ceiling_does_not_set_the_timeout_deadline() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    verifier.set_verifier_deadline(100);
    let request = GuestRequest {
        forged_ceiling: 1,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 0);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 50)
        .expect_err("guest ceiling does not set the deadline");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_reported_usage_does_not_set_the_timeout_deadline() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    verifier.set_verifier_deadline(100);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 50)
        .expect_err("reported usage does not set the deadline");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_later_deadline_does_not_move_the_hold() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    verifier.set_verifier_deadline(100);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    verifier.set_verifier_deadline(0);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 50)
        .expect_err("a later deadline does not move this hold");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_append_does_not_set_the_timeout_deadline() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    verifier.set_verifier_deadline(100);
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 50)
        .expect_err("forged append does not set the deadline");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_overwrite_does_not_set_the_timeout_deadline() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    verifier.set_verifier_deadline(100);
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 50)
        .expect_err("forged overwrite does not set the deadline");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_child_journal_does_not_set_the_timeout_deadline() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    verifier.set_verifier_deadline(100);
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 50)
        .expect_err("forged child journal does not set the deadline");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_identity_does_not_set_the_timeout_deadline() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    verifier.set_verifier_deadline(100);
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 50)
        .expect_err("forged identity does not set the deadline");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_session_does_not_set_the_timeout_deadline() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    verifier.set_verifier_deadline(100);
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 50)
        .expect_err("forged session does not set the deadline");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_instance_does_not_set_the_timeout_deadline() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    verifier.set_verifier_deadline(100);
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let early = verifier
        .timeout_hold(&call, &request, reservation, 50)
        .expect_err("forged instance does not set the deadline");
    assert_eq!(early, TimeoutRefuse::Early);
    assert_eq!(early.to_string(), "timeout is before the verifier deadline");
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert!(!stayed.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_append_does_not_skip_the_uncertain_mark() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    let blocked = verifier
        .release(&call, &request, reservation)
        .expect_err("forged append does not skip the uncertain mark");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_overwrite_does_not_skip_the_uncertain_mark() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    let blocked = verifier
        .release(&call, &request, reservation)
        .expect_err("forged overwrite does not skip the uncertain mark");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_child_journal_does_not_skip_the_uncertain_mark() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    let blocked = verifier
        .release(&call, &request, reservation)
        .expect_err("forged child journal does not skip the uncertain mark");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_identity_does_not_skip_the_uncertain_mark() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    let blocked = verifier
        .release(&call, &request, reservation)
        .expect_err("forged identity does not skip the uncertain mark");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_session_does_not_skip_the_uncertain_mark() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    let blocked = verifier
        .release(&call, &request, reservation)
        .expect_err("forged session does not skip the uncertain mark");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_instance_does_not_skip_the_uncertain_mark() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reserved = guest(handle);
    let reservation = verifier.reserve(&call, &reserved, 4).expect("reserve");
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    let blocked = verifier
        .release(&call, &request, reservation)
        .expect_err("forged instance does not skip the uncertain mark");
    assert_eq!(blocked, ReleaseRefuse::Uncertain);
    assert_eq!(blocked.to_string(), "uncertain hold is not released");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
}

#[test]
fn model_forged_instance_does_not_move_the_settle() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged instance does not move the settle");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_append_does_not_move_the_settle() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged append does not move the settle");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_overwrite_does_not_move_the_settle() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged overwrite does not move the settle");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_child_journal_does_not_move_the_settle() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged child journal does not move the settle");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_identity_does_not_move_the_settle() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged identity does not move the settle");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_session_does_not_move_the_settle() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged session does not move the settle");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_forged_ceiling_does_not_move_the_settle() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        forged_ceiling: 1,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 0);
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("forged ceiling does not move the settle");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_reported_usage_does_not_move_the_settle() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    let charge = verifier
        .settle(&call, &request, reservation, SettleOutcome::Known(4))
        .expect("reported usage does not move the settle");
    assert_eq!(charge, 4);
    let after = books(&verifier);
    assert_eq!(after.charged, 4);
    assert_eq!(after.held, 0);
    assert!(!after.open.contains_key(&reservation.id));
}

#[test]
fn model_timeout_twice_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 10).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(
        verifier.timeout_hold(&call, &request, reservation, 0),
        Ok(TimeoutRecord)
    );
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(books(&verifier).charged, 0);
    assert_eq!(books(&verifier).open.get(&reservation.id), Some(&10));
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("a second timeout records it again");
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(books(&verifier).charged, 0);
    assert_eq!(books(&verifier).open.get(&reservation.id), Some(&10));
    let refusal = verifier
        .timeout_hold(&call, &request, Reservation { id: 0 }, 0)
        .expect_err("missing reservation");
    assert_eq!(refusal, TimeoutRefuse::NotOutstanding);
    assert_eq!(refusal.to_string(), "reservation is not outstanding");
    assert_eq!(books(&verifier).held, 10);
    assert!(books(&verifier).open.contains_key(&reservation.id));
}

#[test]
fn model_timeout_on_another_handle_is_refused() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(holder);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let refusal = verifier
        .timeout_hold(&verifier.open_call(second), &guest(other), reservation, 0)
        .expect_err("another handle");
    assert_eq!(refusal, TimeoutRefuse::OtherHandle);
    assert_eq!(
        refusal.to_string(),
        "reservation is bound to another handle"
    );
    let after_refusal = books(&verifier);
    assert_eq!(after_refusal.held, 4);
    assert_eq!(after_refusal.charged, 0);
    assert_eq!(after_refusal.open.get(&reservation.id), Some(&4));
    assert_eq!(
        verifier.timeout_hold(&call, &request, reservation, 0),
        Ok(TimeoutRecord)
    );
    let after_timeout = books(&verifier);
    assert_eq!(after_timeout.charged, 0);
    assert_eq!(after_timeout.held, 4);
    assert_eq!(after_timeout.open.get(&reservation.id), Some(&4));
    assert!(after_timeout.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_timeout_on_a_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(handle);
    let reservation = verifier.reserve(&call, &request, 10).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let sibling_call = verifier.open_call(sibling);
    let refusal = verifier
        .timeout_hold(&sibling_call, &request, reservation, 0)
        .expect_err("sibling instance");
    assert_eq!(refusal, TimeoutRefuse::Binding(Refuse::Instance));
    assert_eq!(refusal.to_string(), "instance does not match the grant");
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(books(&verifier).charged, 0);
    assert!(books(&verifier).open.contains_key(&reservation.id));
    assert_eq!(
        verifier.timeout_hold(&call, &request, reservation, 0),
        Ok(TimeoutRecord)
    );
    assert_eq!(books(&verifier).held, 10);
    assert_eq!(books(&verifier).charged, 0);
    assert!(books(&verifier).open.contains_key(&reservation.id));
}

#[test]
fn model_forged_instance_does_not_move_the_timeout() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &guest(handle), reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("forged instance does not move the timeout");
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    assert!(after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_append_does_not_move_the_timeout() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &guest(handle), reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("forged append does not move the timeout");
    assert_eq!(record, TimeoutRecord);
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    assert!(after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_overwrite_does_not_move_the_timeout() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &guest(handle), reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("forged overwrite does not move the timeout");
    assert_eq!(record, TimeoutRecord);
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    assert!(after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_child_journal_does_not_move_the_timeout() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &guest(handle), reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("forged child journal does not move the timeout");
    assert_eq!(record, TimeoutRecord);
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    assert!(after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_identity_does_not_move_the_timeout() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &guest(handle), reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("forged identity does not move the timeout");
    assert_eq!(record, TimeoutRecord);
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    assert!(after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_session_does_not_move_the_timeout() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &guest(handle), reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("forged session does not move the timeout");
    assert_eq!(record, TimeoutRecord);
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    assert!(after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_forged_ceiling_does_not_move_the_timeout() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &guest(handle), reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let request = GuestRequest {
        forged_ceiling: 1,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 0);
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("forged ceiling does not move the timeout");
    assert_eq!(record, TimeoutRecord);
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    assert!(after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_reported_usage_does_not_move_the_timeout() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    verifier
        .admit_ask(
            &call,
            &guest(handle),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(handle), 4).expect("reserve");
    verifier.set_verifier_deadline(0);
    let unknown = verifier
        .settle(&call, &guest(handle), reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    let record = verifier
        .timeout_hold(&call, &request, reservation, 0)
        .expect("reported usage does not move the timeout");
    assert_eq!(record, TimeoutRecord);
    assert_eq!(record.to_string(), "timed out, outcome unknown");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
    assert_eq!(after.open.get(&reservation.id), Some(&4));
    assert!(after.timed_out.contains_key(&reservation.id));
}

#[test]
fn model_unknown_from_another_handle_does_not_mark_the_hold() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let request = guest(holder);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    let refusal = verifier
        .settle(
            &verifier.open_call(second),
            &guest(other),
            reservation,
            SettleOutcome::Unknown,
        )
        .expect_err("unknown outcome");
    assert_eq!(refusal, SettleRefuse::UnknownOutcome);
    assert_eq!(refusal.to_string(), "unknown outcome keeps the hold");
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
fn model_forged_append_does_not_mark_another_handle() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(holder), 4).expect("reserve");
    let request = GuestRequest {
        forged_append: true,
        ..guest(other)
    };
    assert!(request.forged_append);
    let unknown = verifier
        .settle(
            &verifier.open_call(second),
            &request,
            reservation,
            SettleOutcome::Unknown,
        )
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert_eq!(verifier.release(&call, &guest(holder), reservation), Ok(()));
}

#[test]
fn model_forged_overwrite_does_not_mark_another_handle() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(holder), 4).expect("reserve");
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(other)
    };
    assert!(request.forged_overwrite);
    let unknown = verifier
        .settle(
            &verifier.open_call(second),
            &request,
            reservation,
            SettleOutcome::Unknown,
        )
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert_eq!(verifier.release(&call, &guest(holder), reservation), Ok(()));
}

#[test]
fn model_forged_child_journal_does_not_mark_another_handle() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(holder), 4).expect("reserve");
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(other)
    };
    assert!(request.forged_child_journal);
    let unknown = verifier
        .settle(
            &verifier.open_call(second),
            &request,
            reservation,
            SettleOutcome::Unknown,
        )
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert_eq!(verifier.release(&call, &guest(holder), reservation), Ok(()));
}

#[test]
fn model_forged_identity_does_not_mark_another_handle() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(holder), 4).expect("reserve");
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(other)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let unknown = verifier
        .settle(
            &verifier.open_call(second),
            &request,
            reservation,
            SettleOutcome::Unknown,
        )
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert_eq!(verifier.release(&call, &guest(holder), reservation), Ok(()));
}

#[test]
fn model_forged_session_does_not_mark_another_handle() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(holder), 4).expect("reserve");
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(other)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let unknown = verifier
        .settle(
            &verifier.open_call(second),
            &request,
            reservation,
            SettleOutcome::Unknown,
        )
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert_eq!(verifier.release(&call, &guest(holder), reservation), Ok(()));
}

#[test]
fn model_forged_instance_does_not_mark_another_handle() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(holder), 4).expect("reserve");
    let request = GuestRequest {
        forged_instance: Some(second),
        ..guest(other)
    };
    assert_eq!(request.forged_instance, Some(second));
    let unknown = verifier
        .settle(
            &verifier.open_call(second),
            &request,
            reservation,
            SettleOutcome::Unknown,
        )
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert_eq!(verifier.release(&call, &guest(holder), reservation), Ok(()));
}

#[test]
fn model_forged_ceiling_does_not_mark_another_handle() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(holder), 4).expect("reserve");
    let request = GuestRequest {
        forged_ceiling: 1,
        ..guest(other)
    };
    assert!(request.forged_ceiling > 0);
    let unknown = verifier
        .settle(
            &verifier.open_call(second),
            &request,
            reservation,
            SettleOutcome::Unknown,
        )
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert_eq!(verifier.release(&call, &guest(holder), reservation), Ok(()));
}

#[test]
fn model_reported_usage_does_not_mark_another_handle() {
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
    let call = verifier.open_call(first);
    verifier
        .admit_ask(
            &call,
            &guest(holder),
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("ask");
    let reservation = verifier.reserve(&call, &guest(holder), 4).expect("reserve");
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(other)
    };
    assert!(request.reported_usage > 0);
    let unknown = verifier
        .settle(
            &verifier.open_call(second),
            &request,
            reservation,
            SettleOutcome::Unknown,
        )
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    let stayed = books(&verifier);
    assert_eq!(stayed.charged, 0);
    assert_eq!(stayed.held, 4);
    assert_eq!(stayed.open.get(&reservation.id), Some(&4));
    assert_eq!(verifier.release(&call, &guest(holder), reservation), Ok(()));
}

#[test]
fn model_second_agent_does_not_raise_the_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_request = guest(first_handle);
    let second_request = guest(second_handle);
    let granted = verifier
        .admit_ask(
            &first_call,
            &first_request,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("first ask");
    assert_eq!(granted, 4);
    let granted = verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("second ask");
    assert_eq!(granted, 50);
    let refusal = verifier
        .reserve(&first_call, &first_request, 5)
        .expect_err("second ask does not raise the first ceiling");
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
        .reserve(&second_call, &second_request, 50)
        .expect("second agent keeps its own ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 50);
}

#[test]
fn model_lower_admit_binds_an_asked_agent() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = guest(handle);
    let granted = verifier
        .admit_ask(&call, &request, crate::ask::BudgetAsk { amount: 10 }, 10)
        .expect("ask");
    assert_eq!(granted, 10);
    verifier.admit(4);
    let refusal = verifier
        .reserve(&call, &request, 8)
        .expect_err("a lower admit binds the asked agent");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 8,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    verifier
        .reserve(&call, &request, 4)
        .expect("inside the lower ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
}

#[test]
fn model_admit_at_the_round_is_honoured_by_the_reserve() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = guest(handle);
    let granted = verifier
        .admit_ask(&call, &request, crate::ask::BudgetAsk { amount: 4 }, 4)
        .expect("ask");
    assert_eq!(granted, 4);
    verifier.admit(10);
    let refusal = verifier
        .reserve(&call, &request, 5)
        .expect_err("the round admit lowers the asked ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 5,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    assert_eq!(books(&verifier).held, 0);
    verifier
        .reserve(&call, &request, 4)
        .expect("reserve at the lowered ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 4);
}

#[test]
fn model_unasked_agent_does_not_inherit_the_last_admit() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    let third = verifier.register_instance("agent-3", "session-a");
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    let third_handle = verifier
        .bind_grant(third, "UsersAI/agent-3/notes", rights())
        .expect("bind");
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let third_call = verifier.open_call(third);
    let first_request = guest(first_handle);
    let second_request = guest(second_handle);
    let third_request = guest(third_handle);
    verifier
        .admit_ask(
            &first_call,
            &first_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("first ask");
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("second ask");
    verifier
        .reserve(&first_call, &first_request, 1)
        .expect("first agent inside its own ceiling");
    let refusal = verifier
        .reserve(&third_call, &third_request, 40)
        .expect_err("an unasked agent has no ceiling");
    assert_eq!(refusal, ReserveRefuse::NoCeiling);
    assert_eq!(refusal.to_string(), "identity has no ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 1);
}

#[test]
fn model_empty_ceilings_map_has_no_ceiling() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.admit(5);
    let call = verifier.open_call(instance);
    let refusal = verifier
        .reserve(&call, &guest(handle), 1)
        .expect_err("an empty ceilings map has no ceiling");
    assert_eq!(refusal, ReserveRefuse::NoCeiling);
    assert_eq!(refusal.to_string(), "identity has no ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
}

#[test]
fn model_other_agent_hold_does_not_fill_the_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_request = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &first_call,
            &first_request,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("first ask");
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("second ask");
    verifier
        .reserve(&first_call, &first_request, 4)
        .expect("first agent uses its own ceiling");
    assert_eq!(books(&verifier).held, 4);
    verifier
        .reserve(&second_call, &second_request, 50)
        .expect("first hold does not fill the second ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 54);
    let refusal = verifier
        .reserve(&second_call, &second_request, 1)
        .expect_err("second agent is at its own ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 50,
            held: 50,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    assert_eq!(books(&verifier).held, 54);
}

#[test]
fn model_second_agent_hold_past_the_shared_u64_total_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_request = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &first_call,
            &first_request,
            crate::ask::BudgetAsk { amount: u64::MAX },
            u64::MAX,
        )
        .expect("first ask");
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 1 },
            1,
        )
        .expect("second ask");
    verifier
        .reserve(&first_call, &first_request, u64::MAX)
        .expect("first agent fills its own ceiling");
    assert_eq!(books(&verifier).held, u64::MAX);
    let refusal = verifier
        .reserve(&second_call, &second_request, 1)
        .expect_err("the stored sum does not fit in u64");
    assert_eq!(
        refusal,
        ReserveRefuse::SumOverflow {
            held: u64::MAX,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation sum does not fit in u64");
    let after = books(&verifier);
    assert_eq!(after.held, u64::MAX);
    assert_eq!(after.open.len(), 1);
    assert_eq!(after.charged, 0);
}

#[test]
fn model_same_identity_shares_one_ceiling() {
    let mut verifier = Verifier::new();
    let asked = verifier.register_instance("agent-1", "session-a");
    let other = verifier.register_instance("agent-1", "session-b");
    assert_ne!(other, asked);
    let asked_handle = verifier
        .bind_grant(asked, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let other_handle = verifier
        .bind_grant(other, "UsersAI/agent-1/other", rights())
        .expect("bind");
    assert_ne!(other_handle, asked_handle);
    let asked_call = verifier.open_call(asked);
    let other_call = verifier.open_call(other);
    let asked_request = guest(asked_handle);
    let other_request = guest(other_handle);
    verifier
        .admit_ask(
            &asked_call,
            &asked_request,
            crate::ask::BudgetAsk { amount: 10 },
            10,
        )
        .expect("one ask for the identity");
    verifier
        .reserve(&other_call, &other_request, 6)
        .expect("other session holds inside the shared ceiling");
    let refusal = verifier
        .reserve(&asked_call, &asked_request, 6)
        .expect_err("the other session's hold fills this identity");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 10,
            held: 6,
            asked: 6,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 6);
}

#[test]
fn model_forged_identity_does_not_pick_the_reserve_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_honest = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("agent-2 ceiling is 50");
    verifier
        .admit_ask(
            &first_call,
            &first_honest,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("agent-1 ceiling is 4");
    let forged = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(first_handle)
    };
    assert_eq!(forged.forged_identity.as_deref(), Some("agent-2"));
    let refusal = verifier
        .reserve(&first_call, &forged, 40)
        .expect_err("forged identity does not use agent-2's ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 40,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
}

#[test]
fn model_forged_session_does_not_pick_the_reserve_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_honest = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("agent-2 ceiling is 50");
    verifier
        .admit_ask(
            &first_call,
            &first_honest,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("agent-1 ceiling is 4");
    let forged = GuestRequest {
        forged_session: Some("agent-2".to_owned()),
        ..guest(first_handle)
    };
    assert_eq!(forged.forged_session.as_deref(), Some("agent-2"));
    let refusal = verifier
        .reserve(&first_call, &forged, 40)
        .expect_err("forged session does not use agent-2's ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 40,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
}

#[test]
fn model_forged_instance_does_not_pick_the_reserve_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_honest = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("agent-2 ceiling is 50");
    verifier
        .admit_ask(
            &first_call,
            &first_honest,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("agent-1 ceiling is 4");
    let forged = GuestRequest {
        forged_instance: Some(second),
        ..guest(first_handle)
    };
    assert_eq!(forged.forged_instance, Some(second));
    let refusal = verifier
        .reserve(&first_call, &forged, 40)
        .expect_err("forged instance does not use agent-2's ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 40,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
}

#[test]
fn model_forged_append_does_not_pick_the_reserve_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_honest = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("agent-2 ceiling is 50");
    verifier
        .admit_ask(
            &first_call,
            &first_honest,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("agent-1 ceiling is 4");
    let forged = GuestRequest {
        forged_append: true,
        ..guest(first_handle)
    };
    assert!(forged.forged_append);
    let refusal = verifier
        .reserve(&first_call, &forged, 40)
        .expect_err("forged append does not use agent-2's ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 40,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
}

#[test]
fn model_forged_overwrite_does_not_pick_the_reserve_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_honest = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("agent-2 ceiling is 50");
    verifier
        .admit_ask(
            &first_call,
            &first_honest,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("agent-1 ceiling is 4");
    let forged = GuestRequest {
        forged_overwrite: true,
        ..guest(first_handle)
    };
    assert!(forged.forged_overwrite);
    let refusal = verifier
        .reserve(&first_call, &forged, 40)
        .expect_err("forged overwrite does not use agent-2's ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 40,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
}

#[test]
fn model_forged_child_journal_does_not_pick_the_reserve_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_honest = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("agent-2 ceiling is 50");
    verifier
        .admit_ask(
            &first_call,
            &first_honest,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("agent-1 ceiling is 4");
    let forged = GuestRequest {
        forged_child_journal: true,
        ..guest(first_handle)
    };
    assert!(forged.forged_child_journal);
    let refusal = verifier
        .reserve(&first_call, &forged, 40)
        .expect_err("forged child journal does not use agent-2's ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 40,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
}

#[test]
fn model_forged_ceiling_does_not_pick_the_reserve_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_honest = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("agent-2 ceiling is 50");
    verifier
        .admit_ask(
            &first_call,
            &first_honest,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("agent-1 ceiling is 4");
    let forged = GuestRequest {
        forged_ceiling: 100,
        ..guest(first_handle)
    };
    assert!(forged.forged_ceiling > 0);
    let refusal = verifier
        .reserve(&first_call, &forged, 40)
        .expect_err("forged ceiling does not use agent-2's ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 40,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
}

#[test]
fn model_reported_usage_does_not_pick_the_reserve_ceiling() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-a");
    assert_ne!(second, first);
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .expect("bind");
    assert_ne!(second_handle, first_handle);
    let first_call = verifier.open_call(first);
    let second_call = verifier.open_call(second);
    let first_honest = guest(first_handle);
    let second_request = guest(second_handle);
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            crate::ask::BudgetAsk { amount: 50 },
            80,
        )
        .expect("agent-2 ceiling is 50");
    verifier
        .admit_ask(
            &first_call,
            &first_honest,
            crate::ask::BudgetAsk { amount: 4 },
            10,
        )
        .expect("agent-1 ceiling is 4");
    let forged = GuestRequest {
        reported_usage: 1,
        ..guest(first_handle)
    };
    assert!(forged.reported_usage > 0);
    let refusal = verifier
        .reserve(&first_call, &forged, 40)
        .expect_err("reported usage does not use agent-2's ceiling");
    assert_eq!(
        refusal,
        ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 0,
            asked: 40,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
    let after = books(&verifier);
    assert_eq!(after.charged, 0);
    assert_eq!(after.held, 0);
}

#[test]
fn model_ended_grant_hold_still_counts_against_the_identity_ceiling() {
    let mut verifier = Verifier::new();
    let (instance, a) = bound(&mut verifier);
    let call = verifier.open_call(instance);
    let _hold = reserve_five(&mut verifier, &call, a);
    verifier.end_grant(a);
    let b = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("second bind");
    verifier
        .admit_ask(&call, &guest(b), crate::ask::BudgetAsk { amount: 5 }, 5)
        .expect("ask on b");
    assert!(
        verifier.reserve(&call, &guest(b), 1).is_err(),
        "the ended grant's open hold of 5 still fills the identity ceiling of 5"
    );
}

#[test]
fn model_end_grant_with_no_hold_leaves_no_kept_binding() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound(&mut verifier);
    verifier.end_grant(handle);
    let ended_empty = verifier
        .ledger
        .lock()
        .expect("ledger lock")
        .ended
        .is_empty();
    assert!(ended_empty, "a grant ended with no open hold keeps nothing");
    let call = verifier.open_call(instance);
    let refusal = verifier
        .reserve(&call, &guest(handle), 1)
        .expect_err("the ended handle opens no hold");
    assert_eq!(refusal, ReserveRefuse::Binding(Refuse::UnknownHandle));
}
