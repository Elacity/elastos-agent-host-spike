//! One model-token account per admitted agent.
//!
//! N9 fixes each agent's ceiling from its signed manifest at admission; N11
//! spends it before a run is dispatched. This module is only the account. Its
//! key is `AgentKey`, which can only be built from the `AdmissionContext` that
//! `admit_launch` constructs from the stored agent id
//! (`agent_admission.rs:213-217`); that context's `actor` field is private
//! (`agent_admission.rs:66-70`), so no string of the caller's choosing names an
//! agent.
//!
//! **Hold-only.** A reservation is charged once and never returns: no refund and
//! no settle (design §5 "No refund"), so an agent that keeps running drains its
//! ceiling and a cancel or unknown outcome keeps its hold. **Restart retention
//! is out of scope:** the account is in memory, so a restart begins at zero.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use elastos_model_contract::{model_run_id, RuntimeCreateBinding};

use crate::agent_admission::AdmissionContext;

/// The one identity that may hold model tokens: the principal admission minted.
///
/// The field is private, and `from_admission` is the only way to name an agent
/// outside this module. `AdmissionContext` has private fields and is built only
/// by `admit_launch` (`agent_admission.rs:213-217`), so a caller cannot mint a
/// key for an agent admission did not admit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentKey(String);

impl AgentKey {
    /// The principal of a launch admission let through.
    pub(crate) fn from_admission(admission: &AdmissionContext) -> Self {
        Self(admission.actor().to_string())
    }

    pub(crate) fn principal(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(principal: &str) -> Self {
        Self(principal.to_string())
    }
}

/// The run identity a hold is charged to, derived from the production binding.
///
/// `of` hashes the real `RuntimeCreateBinding` through `model_run_id()`
/// (`elastos-model-contract/src/lib.rs:198-208`), so a retry with the same
/// request id under the same principal and capsule repeats the key. It keeps
/// the binding's principal too: a key minted for one agent is refused on
/// another agent's account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunKey {
    id: String,
    principal: String,
    offer_id: String,
    revision: String,
    operation: String,
    input_hash: String,
}

impl RunKey {
    pub(crate) fn of(binding: &RuntimeCreateBinding, revision: &str) -> Self {
        Self {
            id: model_run_id(binding),
            principal: binding.principal_id.clone(),
            offer_id: binding.offer_id.clone(),
            revision: revision.to_string(),
            operation: binding.operation.clone(),
            input_hash: binding.input_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HoldFingerprint {
    offer_id: String,
    revision: String,
    operation: String,
    input_hash: String,
    tokens: u64,
}

impl HoldFingerprint {
    fn of(run: &RunKey, tokens: u64) -> Self {
        Self {
            offer_id: run.offer_id.clone(),
            revision: run.revision.clone(),
            operation: run.operation.clone(),
            input_hash: run.input_hash.clone(),
            tokens,
        }
    }
}

/// Ceiling and spending for one agent.
#[derive(Debug, Default)]
struct Account {
    ceiling: u64,
    /// Tokens held by reservations, refunded by nothing.
    held: u64,
    /// Held tokens and request fingerprints by `model_run_id()`; only an
    /// identical retry reuses a hold without a second charge.
    holds: HashMap<String, HoldFingerprint>,
}

/// One reservation of `tokens` for one run. Nothing happens when it is dropped:
/// the run is charged whether it completes, fails or is never heard from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hold {
    pub(crate) tokens: u64,
}

/// Why `open` or `reserve` refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No ceiling was opened for this agent; admission sets it first (N9).
    UnknownAgent,
    /// The ceiling is already set and this call asked for a different one.
    CeilingAlreadySet { ceiling: u64, asked: u64 },
    /// The run key was minted for a different agent than the account asked for.
    RunForOtherAgent,
    /// The same run id names a different request or reservation.
    ConflictingRetry,
    /// Holding `asked` more would pass `ceiling`. `held` excludes `asked`.
    OverCap { asked: u64, held: u64, ceiling: u64 },
}

/// Every agent's account in this process, behind one mutex.
///
/// One `Mutex` and not a per-agent atomic CAS: a reservation moves the agent's
/// `held` total and its `holds` map together, and `open` inserts into the same
/// map, so one lock makes the whole check-then-add atomic without a retry loop.
#[derive(Debug, Default)]
pub(crate) struct ModelBudget {
    agents: Mutex<HashMap<String, Account>>,
    /// Test-only: a planted check-then-add calls `after_read_gate` between its
    /// read and its write; the concurrency row installs a barrier here so every
    /// racer finishes reading before any racer adds.
    #[cfg(test)]
    after_read: Mutex<Option<std::sync::Arc<std::sync::Barrier>>>,
}

impl ModelBudget {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Sets `agent`'s ceiling once. Re-opening with the same ceiling is
    /// idempotent; any other ceiling is refused, so a caller cannot raise it.
    ///
    /// A panic in an earlier caller does not lock the account out: the account
    /// is inserted whole, so ignoring poisoning cannot expose a torn total.
    pub(crate) fn open(&self, agent: &AgentKey, ceiling: u64) -> Result<(), Refusal> {
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        match agents.get(&agent.0) {
            Some(account) if account.ceiling != ceiling => Err(Refusal::CeilingAlreadySet {
                ceiling: account.ceiling,
                asked: ceiling,
            }),
            Some(_) => Ok(()),
            None => {
                agents.insert(
                    agent.0.clone(),
                    Account {
                        ceiling,
                        ..Account::default()
                    },
                );
                Ok(())
            }
        }
    }

    /// Holds `tokens` for `run` — minted from the production binding through
    /// `model_run_id()` — atomically, so concurrent callers never hold more
    /// than the ceiling together. The same run id and fingerprint on the same
    /// agent return the existing hold without another charge. `checked_add` turns a
    /// would-be overflow into a refusal, not a wrap.
    ///
    /// The run-key entry is written before `held` moves: a panic between them
    /// cannot leave a charge without its run key, which is what makes ignoring
    /// a poisoned mutex safe. A hold of zero is stored as zero; an identical
    /// retry returns that zero hold.
    pub(crate) fn reserve(
        &self,
        agent: &AgentKey,
        run: &RunKey,
        tokens: u64,
    ) -> Result<Hold, Refusal> {
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        let account = agents.get_mut(&agent.0).ok_or(Refusal::UnknownAgent)?;
        if run.principal != agent.0 {
            return Err(Refusal::RunForOtherAgent);
        }
        let fingerprint = HoldFingerprint::of(run, tokens);
        if let Some(held) = account.holds.get(&run.id) {
            return if held == &fingerprint {
                Ok(Hold {
                    tokens: held.tokens,
                })
            } else {
                Err(Refusal::ConflictingRetry)
            };
        }
        let total = account
            .held
            .checked_add(tokens)
            .filter(|total| *total <= account.ceiling)
            .ok_or(Refusal::OverCap {
                asked: tokens,
                held: account.held,
                ceiling: account.ceiling,
            })?;
        account.holds.insert(run.id.clone(), fingerprint);
        account.held = total;
        Ok(Hold { tokens })
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn held_for_test(&self, agent: &AgentKey) -> u64 {
        self.agents
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&agent.0)
            .map(|account| account.held)
            .unwrap_or(0)
    }

    /// Test-only: waits for the concurrency row's racers to finish their reads.
    /// Production never calls this; a planted check-then-add does.
    #[cfg(test)]
    #[allow(dead_code)]
    fn after_read_gate(&self) {
        let gate = self
            .after_read
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(gate) = gate {
            gate.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_model_contract::RuntimeCreateBinding;
    use std::sync::{Arc, Barrier};

    const A: &str = "agent:v2:a";
    const B: &str = "agent:v2:b";

    /// The key admission mints: outside this module only `from_admission` can
    /// build one, from a context only `admit_launch` builds.
    fn key(agent: &str) -> AgentKey {
        AgentKey(agent.to_string())
    }

    /// The key N11 will use: the real `model_run_id()`, so a retried request id
    /// under the same principal and capsule repeats the key.
    fn run_key(agent: &str, request: &str) -> RunKey {
        RunKey::of(
            &RuntimeCreateBinding {
                schema: "elastos.runtime.create/v1".into(),
                principal_id: agent.into(),
                session_id: "instance:1".into(),
                capsule_id: "pkg:agent-host".into(),
                grant_id: "cap:1".into(),
                request_id: request.into(),
                offer_id: "offer:deepseek".into(),
                operation: "runs_create".into(),
                input_hash: "sha256:00".into(),
            },
            "sha256:revision",
        )
    }

    fn over_cap(asked: u64, held: u64, ceiling: u64) -> Refusal {
        Refusal::OverCap {
            asked,
            held,
            ceiling,
        }
    }

    fn opened() -> ModelBudget {
        let budget = ModelBudget::new();
        budget.open(&key(A), 100).unwrap();
        budget
    }

    #[test]
    fn over_cap_refused() {
        let budget = opened();
        budget.reserve(&key(A), &run_key(A, "r1"), 60).unwrap();
        assert_eq!(
            budget.reserve(&key(A), &run_key(A, "r2"), 41),
            Err(over_cap(41, 60, 100))
        );
        assert_eq!(
            budget.reserve(&key(A), &run_key(A, "r2"), 40),
            Ok(Hold { tokens: 40 })
        );
    }

    #[test]
    fn concurrent_reserves_share_cap() {
        let budget = Arc::new(opened());
        let start = Arc::new(Barrier::new(24));
        // A planted check-then-add waits at `after_read_gate` after its read, so
        // every racer has read `held` before any racer writes.
        *budget.after_read.lock().unwrap() = Some(Arc::new(Barrier::new(24)));
        let racers: Vec<_> = (0..24)
            .map(|i| {
                let (budget, start) = (budget.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    budget
                        .reserve(&key(A), &run_key(A, &i.to_string()), 10)
                        .is_ok()
                })
            })
            .collect();
        let won = racers
            .into_iter()
            .map(|r| r.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(won, 10, "ten holds of ten fill the ceiling exactly");
        *budget.after_read.lock().unwrap() = None;
        assert_eq!(
            budget.reserve(&key(A), &run_key(A, "last"), 1),
            Err(over_cap(1, 100, 100))
        );
    }

    #[test]
    fn retry_not_double_charged() {
        let budget = opened();
        let retry = run_key(A, "same-request");
        let first = budget.reserve(&key(A), &retry, 60).unwrap();
        assert_eq!(budget.reserve(&key(A), &retry, 60), Ok(first));
        assert_eq!(
            budget.reserve(&key(A), &run_key(A, "other"), 50),
            Err(over_cap(50, 60, 100))
        );
    }

    #[test]
    fn changed_retry_fingerprint_is_refused() {
        let budget = opened();
        let retry = run_key(A, "same-request");
        budget.reserve(&key(A), &retry, 60).unwrap();
        for changed in [
            RunKey {
                offer_id: "other".into(),
                ..retry.clone()
            },
            RunKey {
                revision: "new".into(),
                ..retry.clone()
            },
            RunKey {
                operation: "other".into(),
                ..retry.clone()
            },
            RunKey {
                input_hash: "sha256:01".into(),
                ..retry.clone()
            },
        ] {
            assert_eq!(
                budget.reserve(&key(A), &changed, 60),
                Err(Refusal::ConflictingRetry)
            );
        }
        assert_eq!(
            budget.reserve(&key(A), &retry, 61),
            Err(Refusal::ConflictingRetry)
        );
        assert_eq!(budget.reserve(&key(A), &retry, 60), Ok(Hold { tokens: 60 }));
    }

    #[test]
    fn b_unaffected_by_a_exhaustion() {
        let budget = opened();
        budget.open(&key(B), 100).unwrap();
        budget.reserve(&key(A), &run_key(A, "a1"), 100).unwrap();
        assert_eq!(
            budget.reserve(&key(A), &run_key(A, "a2"), 1),
            Err(over_cap(1, 100, 100))
        );
        assert_eq!(
            budget.reserve(&key(B), &run_key(B, "b1"), 100),
            Ok(Hold { tokens: 100 })
        );
    }

    #[test]
    fn run_key_cannot_charge_another_agent() {
        let budget = opened();
        budget.open(&key(B), 100).unwrap();
        let a_run = run_key(A, "a-run");
        assert_eq!(
            budget.reserve(&key(B), &a_run, 10),
            Err(Refusal::RunForOtherAgent)
        );
        assert_eq!(budget.reserve(&key(A), &a_run, 10), Ok(Hold { tokens: 10 }));
    }

    #[test]
    fn ceiling_cannot_be_raised() {
        let budget = opened();
        let already = |asked| {
            Err(Refusal::CeilingAlreadySet {
                ceiling: 100,
                asked,
            })
        };
        assert_eq!(budget.open(&key(A), 200), already(200));
        assert_eq!(budget.open(&key(A), 50), already(50));
        assert_eq!(
            budget.reserve(&key(A), &run_key(A, "big"), 150),
            Err(over_cap(150, 0, 100))
        );
    }

    #[test]
    fn unknown_agent_refused() {
        let ghost =
            ModelBudget::new().reserve(&key("agent:v2:ghost"), &run_key("agent:v2:ghost", "g"), 1);
        assert_eq!(ghost, Err(Refusal::UnknownAgent));
    }
}
