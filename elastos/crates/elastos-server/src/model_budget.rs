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
//! ceiling and a cancel or unknown outcome keeps its hold. A bound Home stores
//! that total on the agent record in blocks: open reads it, and charge writes
//! one block under the agent lock. `held` can lag other Runtimes; the store refuses.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use elastos_model_contract::{model_run_id, RuntimeCreateBinding};

use crate::agent_admission::AdmissionContext;
use crate::agents::{charge_model_spend, model_spend, SpendRefusal, NO_OWNER};

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
    /// Tokens drawn by reservations in this process, refunded by nothing.
    held: u64,
    /// Stored block this process last observed.
    charged: u64,
    owner: Option<String>,
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
    /// The run key was minted for a different agent than the account asked for.
    RunForOtherAgent,
    /// The same run id names a different request or reservation.
    ConflictingRetry,
    /// Holding `asked` more would pass `ceiling`. `held` excludes `asked`.
    OverCap {
        asked: u64,
        held: u64,
        ceiling: u64,
    },
    Record(&'static str),
}

/// Every agent's account in this process, behind one mutex.
///
/// One `Mutex` and not a per-agent atomic CAS: a reservation moves the agent's
/// `held` total and its `holds` map together, and `open` inserts into the same
/// map, so one lock makes the whole check-then-add atomic without a retry loop.
#[derive(Debug, Default)]
pub(crate) struct ModelBudget {
    agents: Mutex<HashMap<String, Account>>,
    home: Mutex<Option<PathBuf>>,
    /// Test-only: a planted check-then-add calls `after_read_gate` between its
    /// read and its write; the concurrency row installs a barrier here so every
    /// racer finishes reading before any racer adds.
    #[cfg(test)]
    after_read: Mutex<Option<std::sync::Arc<std::sync::Barrier>>>,
}

type Block = Result<(u64, u64, Option<u64>), (u64, u64)>;

/// One run against the charged block. The block is
/// `ceil(ceiling / (64 / live agents))`, so eight agents together write about
/// 64 rows and the 512-row chain keeps the owner's earlier rows. A raised
/// ceiling keeps the stored total and does not start a new row budget: each
/// new row costs `ceil(new ceiling / 8)` tokens, and a one-token raise still
/// costs one row. When the stored total is ahead of this process, that block
/// counts as spent, unused part included. A restart does the same.
pub(crate) fn block_charge(memory: (u64, u64), stored: u64, run: u64, ceiling: u64) -> Block {
    let ahead = stored > memory.1;
    let (drawn, charged) = if ahead { (stored, stored) } else { memory };
    let next = drawn.checked_add(run).filter(|n| *n <= ceiling);
    let Some(next) = next else {
        return Err((drawn, charged));
    };
    if next <= charged {
        return Ok((next, charged, None));
    }
    let rows = 64 / crate::agents::MAX_LIVE_AGENTS_PER_OWNER as u64;
    let unit = ceiling.div_ceil(rows);
    let raise = run.max(unit).min(ceiling.saturating_sub(charged));
    let sum = charged.checked_add(raise);
    let total = sum.filter(|n| *n > stored && *n >= next);
    let raised = total.map(|n| (next, n, Some(n)));
    raised.ok_or((drawn, charged))
}

/// The budget mutex comes before the agent file lock. This refuses the
/// reverse: the agent file lock is already held on this thread.
fn refuse_agent_lock_first() -> Result<(), Refusal> {
    if crate::agents::agent_file_lock_held() {
        Err(Refusal::Record(crate::agents::LOCK_ORDER))
    } else {
        Ok(())
    }
}

impl ModelBudget {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn bind_home(&self, data_dir: PathBuf) {
        *self.home.lock().unwrap_or_else(PoisonError::into_inner) = Some(data_dir);
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Sets the ceiling and keeps what is already spent. A failed read opens nothing.
    pub(crate) fn open(&self, agent: &AgentKey, ceiling: u64) -> Result<(), Refusal> {
        refuse_agent_lock_first()?;
        let loaded = self
            .home_dir()
            .map(|dir| model_spend(&dir, agent.principal()).map_err(Refusal::Record))
            .transpose()?;
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        let account = agents.entry(agent.0.clone()).or_default();
        if let Some((owner, spent)) = loaded {
            account.owner = Some(owner);
            // A restart counts the unused part of a charged block as spent (conservative).
            account.held = spent;
            account.charged = spent;
        }
        account.ceiling = ceiling;
        Ok(())
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
        refuse_agent_lock_first()?;
        let home = self.home_dir();
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        let account = agents.get_mut(&agent.0).ok_or(Refusal::UnknownAgent)?;
        if run.principal != agent.0 {
            return Err(Refusal::RunForOtherAgent);
        }
        let fingerprint = HoldFingerprint::of(run, tokens);
        // A retry of the same run id after a restart is charged again: holds do not survive the process.
        if let Some(held) = account.holds.get(&run.id) {
            return if held == &fingerprint {
                Ok(Hold {
                    tokens: held.tokens,
                })
            } else {
                Err(Refusal::ConflictingRetry)
            };
        }
        let total = if let Some(dir) = home {
            let owner = account.owner.clone().ok_or(Refusal::Record(NO_OWNER))?;
            let memory = (account.held, account.charged);
            match charge_model_spend(
                &dir,
                &owner,
                agent.principal(),
                memory,
                tokens,
                account.ceiling,
            ) {
                Ok((drawn, charged)) => {
                    account.charged = charged;
                    drawn
                }
                Err(SpendRefusal::Over(asked, held, charged, ceiling)) => {
                    account.held = held;
                    account.charged = charged;
                    return Err(Refusal::OverCap {
                        asked,
                        held,
                        ceiling,
                    });
                }
                Err(SpendRefusal::Name(name)) => return Err(Refusal::Record(name)),
            }
        } else {
            account
                .held
                .checked_add(tokens)
                .filter(|total| *total <= account.ceiling)
                .ok_or(Refusal::OverCap {
                    asked: tokens,
                    held: account.held,
                    ceiling: account.ceiling,
                })?
        };
        account.holds.insert(run.id.clone(), fingerprint);
        account.held = total;
        Ok(Hold { tokens })
    }

    #[cfg(all(test, unix))]
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
    fn changed_ceiling_keeps_what_is_spent() {
        let budget = opened();
        budget.reserve(&key(A), &run_key(A, "r1"), 60).unwrap();
        budget.open(&key(A), 200).unwrap();
        assert_eq!(
            budget.reserve(&key(A), &run_key(A, "r2"), 140),
            Ok(Hold { tokens: 140 })
        );
        budget.open(&key(A), 100).unwrap();
        assert_eq!(
            budget.reserve(&key(A), &run_key(A, "r3"), 1),
            Err(over_cap(1, 200, 100))
        );
    }

    #[test]
    fn unknown_agent_refused() {
        let ghost =
            ModelBudget::new().reserve(&key("agent:v2:ghost"), &run_key("agent:v2:ghost", "g"), 1);
        assert_eq!(ghost, Err(Refusal::UnknownAgent));
    }

    #[cfg(unix)]
    fn planted_agent() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let owner = "person:local:spend-owner";
        crate::auth::store_test_human_principal(dir.path(), owner);
        let agent = crate::agents::tests::plant_for_dispatch(dir.path(), owner, owner);
        (dir, owner.to_string(), agent)
    }

    #[cfg(unix)]
    fn opened_on(dir: &std::path::Path, agent: &str, ceiling: u64) -> (ModelBudget, AgentKey) {
        let budget = ModelBudget::new();
        budget.bind_home(dir.to_path_buf());
        let key = AgentKey::for_test(agent);
        budget.open(&key, ceiling).unwrap();
        (budget, key)
    }

    /// Spend, drop the account, open a new one on the same folder.
    #[cfg(unix)]
    #[test]
    fn spent_total_survives_a_new_runtime() {
        let (dir, _owner, agent) = planted_agent();
        {
            let (first, key) = opened_on(dir.path(), &agent, 100);
            first.reserve(&key, &run_key(&agent, "r1"), 40).unwrap();
        }
        let (second, key) = opened_on(dir.path(), &agent, 100);
        assert_eq!(second.held_for_test(&key), 40);
        assert_eq!(
            second.reserve(&key, &run_key(&agent, "r2"), 61),
            Err(over_cap(61, 40, 100))
        );
        second.open(&key, 30).unwrap();
        assert_eq!(second.held_for_test(&key), 40);
        assert_eq!(
            second.reserve(&key, &run_key(&agent, "r3"), 1),
            Err(over_cap(1, 40, 30))
        );
        let file =
            std::fs::read_to_string(crate::agents::agent_file_path(dir.path()).unwrap()).unwrap();
        assert!(file.contains("\"model_tokens_spent\": 40"), "{file}");
    }

    /// A record that does not parse refuses by that name, before any hold.
    #[cfg(unix)]
    #[test]
    fn unreadable_agent_record_refuses_by_name() {
        let (dir, _owner, agent) = planted_agent();
        let (budget, key) = opened_on(dir.path(), &agent, 100);
        let path = crate::agents::agent_file_path(dir.path()).unwrap();
        std::fs::write(&path, b"{").unwrap();
        assert_eq!(
            budget.reserve(&key, &run_key(&agent, "r1"), 10),
            Err(Refusal::Record(crate::agents::DOES_NOT_PARSE))
        );
        assert_eq!(budget.held_for_test(&key), 0);
        let again = ModelBudget::new();
        again.bind_home(dir.path().to_path_buf());
        assert_eq!(
            again.open(&key, 100),
            Err(Refusal::Record(crate::agents::DOES_NOT_PARSE))
        );
    }

    /// A failed write leaves the stored total and the in-memory hold unchanged.
    #[cfg(unix)]
    #[test]
    fn failed_write_refuses_by_name_before_the_hold_moves() {
        let (dir, _owner, agent) = planted_agent();
        let (budget, key) = opened_on(dir.path(), &agent, 100);
        budget.reserve(&key, &run_key(&agent, "r1"), 40).unwrap();
        let path = crate::agents::agent_file_path(dir.path()).unwrap();
        let before = std::fs::read(&path).unwrap();
        let parent = path.parent().unwrap();
        let restore = parent.to_path_buf();
        struct Restore(std::path::PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }
        let _restore = Restore(restore);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(
            budget.reserve(&key, &run_key(&agent, "r2"), 10),
            Err(Refusal::Record(crate::agents::CANNOT_WRITE))
        );
        drop(_restore);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(budget.held_for_test(&key), 40);
    }

    /// Two agents keep separate totals. Retiring one leaves its total in place.
    #[cfg(unix)]
    #[test]
    fn two_agents_keep_separate_spent_totals() {
        let (dir, owner, first) = planted_agent();
        let second = crate::agents::tests::plant_another_dispatch(dir.path(), &owner, "request-b");
        let budget = ModelBudget::new();
        budget.bind_home(dir.path().to_path_buf());
        let a = AgentKey::for_test(&first);
        let b = AgentKey::for_test(&second);
        budget.open(&a, 100).unwrap();
        budget.open(&b, 80).unwrap();
        budget.reserve(&a, &run_key(&first, "a1"), 70).unwrap();
        assert_eq!(
            budget.reserve(&b, &run_key(&second, "b1"), 80),
            Ok(Hold { tokens: 80 })
        );
        assert_eq!(
            budget.reserve(&a, &run_key(&first, "a2"), 40),
            Err(over_cap(40, 70, 100))
        );
        crate::agents::tests::retire_for_dispatch(dir.path(), &owner, &first);
        let file =
            std::fs::read_to_string(crate::agents::agent_file_path(dir.path()).unwrap()).unwrap();
        assert!(file.contains("\"model_tokens_spent\": 70"), "{file}");
        assert_eq!(
            budget.reserve(&a, &run_key(&first, "a3"), 1),
            Err(Refusal::Record(crate::agents::ALREADY_RETIRED))
        );
        assert_eq!(budget.held_for_test(&b), 80);
    }

    /// Two opens in two Runtimes share the lock. The stale memory does not admit.
    #[cfg(unix)]
    #[test]
    fn two_opens_in_two_runtimes_use_the_stored_total() {
        let (dir, _owner, agent) = planted_agent();
        let (first, key) = opened_on(dir.path(), &agent, 100);
        let (second, key_b) = opened_on(dir.path(), &agent, 100);
        first.reserve(&key, &run_key(&agent, "r1"), 60).unwrap();
        assert_eq!(
            second.held_for_test(&key_b),
            0,
            "stale by the other runtime's 60"
        );
        assert_eq!(
            second.reserve(&key_b, &run_key(&agent, "r2"), 50),
            Err(over_cap(50, 60, 100))
        );
        assert_eq!(second.held_for_test(&key_b), 60);
        assert_eq!(first.held_for_test(&key), 60);
    }

    #[cfg(unix)]
    fn audit_of(dir: &std::path::Path) -> Vec<elastos_runtime::auth::RuntimeAuditEventV1> {
        crate::auth::load_auth_state(dir).unwrap().audit
    }

    #[cfg(unix)]
    fn stored_spent(dir: &std::path::Path, agent: &str) -> u64 {
        model_spend(dir, agent).unwrap().1
    }

    #[cfg(unix)]
    fn spend_rows(dir: &std::path::Path, agent: &str) -> usize {
        audit_of(dir)
            .iter()
            .filter(|event| {
                event.event_type == "agent.record.spend"
                    && event.principal_id.as_deref() == Some(agent)
            })
            .count()
    }

    /// The spend row is the Runtime's record: the agent is the subject, the
    /// owner's proof is absent, and the owner appears only as owner.
    #[cfg(unix)]
    #[test]
    fn spend_row_records_the_agents_spend_not_the_owners_act() {
        let (dir, owner, agent) = planted_agent();
        let (budget, key) = opened_on(dir.path(), &agent, 100);
        budget.reserve(&key, &run_key(&agent, "row"), 40).unwrap();
        let events = audit_of(dir.path());
        let create = events
            .iter()
            .find(|event| event.event_type == "agent.record.create")
            .unwrap();
        let row = events
            .iter()
            .find(|event| event.event_type == "agent.record.spend")
            .unwrap();
        assert_eq!(row.principal_id.as_deref(), Some(agent.as_str()));
        assert_eq!(row.proof_binding_id, None);
        assert_eq!(row.session_id, None);
        assert!(row.signature.is_some() && row.signer_did.is_some());
        assert!(create.proof_binding_id.is_some());
        assert_ne!(row.proof_binding_id, create.proof_binding_id);
        assert!(create.session_id.is_some());
        assert!(row.reason.starts_with(&format!("owner={owner} ")));
        let proof = create.proof_binding_id.as_deref().unwrap();
        assert!(!row.reason.contains(proof));
        assert_eq!(stored_spent(dir.path(), &agent), 40);
    }

    /// 1,000 one-token runs stay inside one block per 1/8 of the ceiling, so
    /// the owner's earlier rows are still inside the 512-row chain.
    #[cfg(unix)]
    #[test]
    fn a_thousand_small_runs_leave_the_owner_row_in_the_chain() {
        let (dir, _owner, agent) = planted_agent();
        let owner_ids: Vec<_> = audit_of(dir.path())
            .iter()
            .map(|event| event.event_id.clone())
            .collect();
        assert!(!owner_ids.is_empty());
        let (budget, key) = opened_on(dir.path(), &agent, 1_000);
        budget.reserve(&key, &run_key(&agent, "n0"), 1).unwrap();
        assert_eq!(budget.held_for_test(&key), 1);
        assert_eq!(stored_spent(dir.path(), &agent), 125);
        assert_eq!(spend_rows(dir.path(), &agent), 1);
        for i in 1..125 {
            budget
                .reserve(&key, &run_key(&agent, &format!("n{i}")), 1)
                .unwrap();
        }
        assert_eq!(budget.held_for_test(&key), 125);
        assert_eq!(stored_spent(dir.path(), &agent), 125);
        assert_eq!(spend_rows(dir.path(), &agent), 1);
        for i in 125..1_000 {
            budget
                .reserve(&key, &run_key(&agent, &format!("n{i}")), 1)
                .unwrap();
        }
        assert_eq!(budget.held_for_test(&key), 1_000);
        assert_eq!(stored_spent(dir.path(), &agent), 1_000);
        let spends = spend_rows(dir.path(), &agent);
        assert!(spends <= 65, "{spends} spend rows");
        assert_eq!(spends, 8);
        let after = audit_of(dir.path());
        for id in owner_ids {
            assert!(
                after.iter().any(|event| event.event_id == id),
                "owner row left the chain: {id}"
            );
        }
    }

    /// Same process: a run that fits the ceiling draws the unused block and is
    /// not refused. After a restart that unused part counts as spent.
    #[cfg(unix)]
    #[test]
    fn restart_mid_block_counts_the_unused_part_as_spent() {
        let (dir, owner, agent) = planted_agent();
        let other = crate::agents::tests::plant_another_dispatch(dir.path(), &owner, "request-b");
        let (budget, key) = opened_on(dir.path(), &agent, 640);
        budget.reserve(&key, &run_key(&agent, "a1"), 1).unwrap();
        budget.reserve(&key, &run_key(&agent, "a2"), 4).unwrap();
        assert_eq!(budget.held_for_test(&key), 5);
        assert_eq!(stored_spent(dir.path(), &agent), 80);
        assert_eq!(spend_rows(dir.path(), &agent), 1);
        budget.reserve(&key, &run_key(&agent, "a3"), 635).unwrap();
        assert_eq!(budget.held_for_test(&key), 640);
        assert_eq!(stored_spent(dir.path(), &agent), 640);
        assert_eq!(
            budget.reserve(&key, &run_key(&agent, "a4"), 1),
            Err(over_cap(1, 640, 640))
        );
        let (fresh, other_key) = opened_on(dir.path(), &other, 640);
        fresh
            .reserve(&other_key, &run_key(&other, "b1"), 1)
            .unwrap();
        assert_eq!(fresh.held_for_test(&other_key), 1);
        assert_eq!(stored_spent(dir.path(), &other), 80);
        drop(fresh);
        let (restarted, other_key) = opened_on(dir.path(), &other, 640);
        assert_eq!(restarted.held_for_test(&other_key), 80);
        assert_eq!(
            restarted.reserve(&other_key, &run_key(&other, "b2"), 561),
            Err(over_cap(561, 80, 640))
        );
        restarted
            .reserve(&other_key, &run_key(&other, "b3"), 560)
            .unwrap();
        assert_eq!(stored_spent(dir.path(), &other), 640);
    }

    /// The last raise is only what remains under the ceiling.
    #[cfg(unix)]
    #[test]
    fn the_last_partial_block_stops_at_the_ceiling() {
        let (dir, _owner, agent) = planted_agent();
        let (budget, key) = opened_on(dir.path(), &agent, 65);
        for i in 0..63 {
            budget
                .reserve(&key, &run_key(&agent, &format!("p{i}")), 1)
                .unwrap();
        }
        assert_eq!(stored_spent(dir.path(), &agent), 63);
        assert_eq!(budget.held_for_test(&key), 63);
        assert_eq!(spend_rows(dir.path(), &agent), 7);
        budget.reserve(&key, &run_key(&agent, "last"), 1).unwrap();
        assert_eq!(stored_spent(dir.path(), &agent), 65);
        assert_eq!(budget.held_for_test(&key), 64);
        assert_eq!(spend_rows(dir.path(), &agent), 8);
        budget.reserve(&key, &run_key(&agent, "rest"), 1).unwrap();
        assert_eq!(budget.held_for_test(&key), 65);
        assert_eq!(
            budget.reserve(&key, &run_key(&agent, "over"), 1),
            Err(over_cap(1, 65, 65))
        );
        assert_eq!(stored_spent(dir.path(), &agent), 65);
    }

    /// Eight live agents, each drained by small runs, still leave the owner's
    /// earlier rows in the 512-row chain.
    #[cfg(unix)]
    #[test]
    fn eight_agents_small_runs_leave_the_owners_earlier_rows() {
        let (dir, owner, first) = planted_agent();
        let mut agents = vec![first];
        for index in 1..crate::agents::MAX_LIVE_AGENTS_PER_OWNER {
            agents.push(crate::agents::tests::plant_another_dispatch(
                dir.path(),
                &owner,
                &format!("request-{index}"),
            ));
        }
        assert_eq!(agents.len(), 8);
        let owner_ids: Vec<_> = audit_of(dir.path())
            .iter()
            .map(|event| event.event_id.clone())
            .collect();
        let budget = ModelBudget::new();
        budget.bind_home(dir.path().to_path_buf());
        for agent in &agents {
            let key = AgentKey::for_test(agent);
            budget.open(&key, 64).unwrap();
            for step in 0..64 {
                budget
                    .reserve(&key, &run_key(agent, &format!("s{step}")), 1)
                    .unwrap();
            }
            assert_eq!(stored_spent(dir.path(), agent), 64);
            assert_eq!(spend_rows(dir.path(), agent), 8);
        }
        let spends: usize = agents
            .iter()
            .map(|agent| spend_rows(dir.path(), agent))
            .sum();
        assert_eq!(
            spends, 64,
            "eight agents write 64 rows, not the 512-row chain"
        );
        let after = audit_of(dir.path());
        for id in owner_ids {
            assert!(
                after.iter().any(|event| event.event_id == id),
                "owner row left the chain: {id}"
            );
        }
    }

    /// A raised ceiling keeps the stored total. The new rows cost the new
    /// block, not a fresh budget of eight.
    #[cfg(unix)]
    #[test]
    fn a_raised_ceiling_does_not_reset_the_row_bound() {
        let (dir, _owner, agent) = planted_agent();
        let (budget, key) = opened_on(dir.path(), &agent, 80);
        for i in 0..80 {
            budget
                .reserve(&key, &run_key(&agent, &format!("a{i}")), 1)
                .unwrap();
        }
        assert_eq!(stored_spent(dir.path(), &agent), 80);
        assert_eq!(spend_rows(dir.path(), &agent), 8);
        budget.open(&key, 160).unwrap();
        assert_eq!(budget.held_for_test(&key), 80);
        for i in 0..80 {
            budget
                .reserve(&key, &run_key(&agent, &format!("b{i}")), 1)
                .unwrap();
        }
        assert_eq!(stored_spent(dir.path(), &agent), 160);
        assert_eq!(
            spend_rows(dir.path(), &agent),
            12,
            "a raise of 80 tokens costs 4 rows at the new block of 20, not a fresh 8"
        );
    }

    /// The same run id is charged once in this process and again after a restart.
    #[cfg(unix)]
    #[test]
    fn a_retry_of_the_same_run_after_a_restart_is_charged_again() {
        let (dir, _owner, agent) = planted_agent();
        let run = run_key(&agent, "same-request");
        {
            let (budget, key) = opened_on(dir.path(), &agent, 1_000);
            budget.reserve(&key, &run, 1).unwrap();
            assert_eq!(stored_spent(dir.path(), &agent), 125);
            assert_eq!(spend_rows(dir.path(), &agent), 1);
        }
        let (restarted, key) = opened_on(dir.path(), &agent, 1_000);
        restarted.reserve(&key, &run, 1).unwrap();
        assert_eq!(stored_spent(dir.path(), &agent), 250);
        assert_eq!(spend_rows(dir.path(), &agent), 2);
    }

    /// Agent file lock, then the budget mutex, is refused by name. The same
    /// reserve is admitted once that lock is released.
    #[cfg(unix)]
    #[test]
    fn agent_file_lock_before_the_budget_mutex_is_refused() {
        let (dir, _owner, agent) = planted_agent();
        let (budget, key) = opened_on(dir.path(), &agent, 100);
        let held = crate::agents::tests::hold_agent_file_lock_for_test(dir.path()).unwrap();
        assert_eq!(
            budget.open(&key, 100),
            Err(Refusal::Record(crate::agents::LOCK_ORDER))
        );
        assert_eq!(
            budget.reserve(&key, &run_key(&agent, "order"), 1),
            Err(Refusal::Record(crate::agents::LOCK_ORDER))
        );
        drop(held);
        budget.reserve(&key, &run_key(&agent, "order"), 1).unwrap();
    }

    /// Below eight tokens the block is one token, so a one-token run writes a
    /// row and still cannot pass the ceiling.
    #[cfg(unix)]
    #[test]
    fn a_ceiling_under_64_charges_one_token_blocks() {
        let (dir, owner, agent) = planted_agent();
        let other = crate::agents::tests::plant_another_dispatch(dir.path(), &owner, "request-c");
        let (budget, key) = opened_on(dir.path(), &agent, 7);
        for i in 0..7 {
            budget
                .reserve(&key, &run_key(&agent, &format!("c{i}")), 1)
                .unwrap();
        }
        assert_eq!(stored_spent(dir.path(), &agent), 7);
        assert_eq!(spend_rows(dir.path(), &agent), 7);
        assert_eq!(
            budget.reserve(&key, &run_key(&agent, "c7"), 1),
            Err(over_cap(1, 7, 7))
        );
        let (whole, other_key) = opened_on(dir.path(), &other, 7);
        whole
            .reserve(&other_key, &run_key(&other, "all"), 7)
            .unwrap();
        assert_eq!(stored_spent(dir.path(), &other), 7);
        assert_eq!(spend_rows(dir.path(), &other), 1);
        assert_eq!(
            whole.reserve(&other_key, &run_key(&other, "more"), 1),
            Err(over_cap(1, 7, 7))
        );
    }
}
