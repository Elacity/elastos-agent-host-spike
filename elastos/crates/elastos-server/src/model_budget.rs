//! One model-token account per admitted agent.
//!
//! N9 fixes each agent's ceiling from its signed manifest at admission; N11
//! spends it before a run is dispatched. This module is only the account. Its
//! key is the principal the admission context already carries
//! (`AdmissionContext.actor`, `agent_admission.rs:72-76`), so one agent cannot
//! spend another's tokens.
//!
//! **Hold-only.** A reservation is charged once and never returns: no refund and
//! no settle (design §5 "No refund"), so an agent that keeps running drains its
//! ceiling and a cancel or unknown outcome keeps its hold. **Restart retention
//! is out of scope:** the account is in memory, so a restart begins at zero.

// N11 wires this in; until then nothing in the crate calls it.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Ceiling and spending for one agent.
#[derive(Debug, Default)]
struct Account {
    ceiling: u64,
    /// Tokens held by reservations, refunded by nothing.
    held: u64,
    /// Held tokens by `model_run_id()`, so a retry is not charged twice.
    holds: HashMap<String, u64>,
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
}

impl ModelBudget {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Sets `agent`'s ceiling once. Re-opening with the same ceiling is
    /// idempotent; any other ceiling is refused, so a caller cannot raise it.
    ///
    /// A panic in an earlier caller does not lock the account out: every write
    /// is a single assignment, so ignoring poisoning cannot expose a torn total.
    pub(crate) fn open(&self, agent: &str, ceiling: u64) -> Result<(), Refusal> {
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        match agents.get(agent) {
            Some(account) if account.ceiling != ceiling => Err(Refusal::CeilingAlreadySet {
                ceiling: account.ceiling,
                asked: ceiling,
            }),
            Some(_) => Ok(()),
            None => {
                agents.insert(
                    agent.to_string(),
                    Account {
                        ceiling,
                        ..Account::default()
                    },
                );
                Ok(())
            }
        }
    }

    /// Holds `tokens` for `run_key` — the production `model_run_id()`
    /// (`elastos-model-contract/src/lib.rs:198-208`) — atomically, so concurrent
    /// callers never hold more than the ceiling together. The same `run_key` on
    /// the same agent returns the existing hold and is not charged again.
    /// `checked_add` turns a would-be overflow into a refusal, not a wrap.
    pub(crate) fn reserve(&self, agent: &str, run_key: &str, tokens: u64) -> Result<Hold, Refusal> {
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        let account = agents.get_mut(agent).ok_or(Refusal::UnknownAgent)?;
        if let Some(&held) = account.holds.get(run_key) {
            return Ok(Hold { tokens: held });
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
        account.held = total;
        account.holds.insert(run_key.to_string(), tokens);
        Ok(Hold { tokens })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_model_contract::{model_run_id, RuntimeCreateBinding};
    use std::sync::{Arc, Barrier};

    const A: &str = "agent:v2:a";
    const B: &str = "agent:v2:b";

    /// The key N11 will use: the real `model_run_id()`, so a retried request id
    /// under the same principal and capsule repeats the key.
    fn run_key(agent: &str, request: &str) -> String {
        model_run_id(&RuntimeCreateBinding {
            schema: "elastos.runtime.create/v1".into(),
            principal_id: agent.into(),
            session_id: "instance:1".into(),
            capsule_id: "pkg:agent-host".into(),
            grant_id: "cap:1".into(),
            request_id: request.into(),
            offer_id: "offer:deepseek".into(),
            operation: "runs_create".into(),
            input_hash: "sha256:00".into(),
        })
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
        budget.open(A, 100).unwrap();
        budget
    }

    #[test]
    fn over_cap_refused() {
        let budget = opened();
        budget.reserve(A, &run_key(A, "r1"), 60).unwrap();
        assert_eq!(
            budget.reserve(A, &run_key(A, "r2"), 41),
            Err(over_cap(41, 60, 100))
        );
        assert_eq!(
            budget.reserve(A, &run_key(A, "r2"), 40),
            Ok(Hold { tokens: 40 })
        );
    }

    #[test]
    fn concurrent_reserves_share_cap() {
        let budget = Arc::new(opened());
        let start = Arc::new(Barrier::new(24));
        let racers: Vec<_> = (0..24)
            .map(|i| {
                let (budget, start) = (budget.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    budget.reserve(A, &run_key(A, &i.to_string()), 10).is_ok()
                })
            })
            .collect();
        let won = racers
            .into_iter()
            .map(|r| r.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(won, 10, "ten holds of ten fill the ceiling exactly");
        assert_eq!(
            budget.reserve(A, &run_key(A, "last"), 1),
            Err(over_cap(1, 100, 100))
        );
    }

    #[test]
    fn retry_not_double_charged() {
        let budget = opened();
        let retry = run_key(A, "same-request");
        let first = budget.reserve(A, &retry, 60).unwrap();
        assert_eq!(budget.reserve(A, &retry, 60), Ok(first));
        assert_eq!(
            budget.reserve(A, &run_key(A, "other"), 50),
            Err(over_cap(50, 60, 100))
        );
    }

    #[test]
    fn b_unaffected_by_a_exhaustion() {
        let budget = opened();
        budget.open(B, 100).unwrap();
        budget.reserve(A, &run_key(A, "a1"), 100).unwrap();
        assert_eq!(
            budget.reserve(A, &run_key(A, "a2"), 1),
            Err(over_cap(1, 100, 100))
        );
        assert_eq!(
            budget.reserve(B, &run_key(B, "b1"), 100),
            Ok(Hold { tokens: 100 })
        );
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
        assert_eq!(budget.open(A, 200), already(200));
        assert_eq!(budget.open(A, 50), already(50));
        assert_eq!(
            budget.reserve(A, &run_key(A, "big"), 150),
            Err(over_cap(150, 0, 100))
        );
    }

    #[test]
    fn unknown_agent_refused() {
        let ghost = ModelBudget::new().reserve("agent:v2:ghost", "run:sha256:00", 1);
        assert_eq!(ghost, Err(Refusal::UnknownAgent));
    }
}
