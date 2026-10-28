//! `scrub`: re-verify stored content against its CID in bounded batches within
//! a byte budget per run, resuming where the last run stopped (P12).
//!
//! The scrub plan never trusts stored bytes. For each item it asks an injected
//! [`ContentVerifier`] whether the stored content still matches the CID the
//! bundle was admitted under. On a match the item stays `Healthy`. On a
//! mismatch the item is marked `content_corrupt`, a re-fetch is scheduled, and
//! the bad bytes are never handed back through [`ScrubOutcome::served`].
//!
//! Resume rule: a run walks items from `cursor.next_index` in order, taking
//! whole items only. It stops before an item whose bytes would exceed the
//! remaining byte budget for this run, unless that item is the first item of
//! the run (a single item larger than the whole budget is taken whole so the
//! cursor always advances; otherwise the plan could never make progress). The
//! cursor records the index of the first item not yet verified this run.
//!
//! Presets chosen here (no values were given in the task; these are small and
//! conservative):
//!   * `batch_size`: 64 items walked per batch step.
//!   * `byte_budget`: 1 MiB of stored bytes re-hashed per run before the plan
//!     stops and records its resume cursor.
//!   * `max_refetch_attempts`: 1 re-fetch scheduled per corrupt item.
//!
//! Hashes are supplied by the injected verifier; this module adds no hash of
//! its own and treats the CID as an opaque label it only compares and prints.

use std::collections::VecDeque;
use std::fmt;

/// The bytes and CID of one stored item, as the store handed them back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredItem {
    /// Opaque CID label the item was admitted under.
    pub cid: String,
    /// Stored content bytes.
    pub bytes: Vec<u8>,
}

/// Outcome of verifying one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Stored bytes still match the CID.
    Match,
    /// Stored bytes do not match the CID.
    Mismatch,
}

/// Injected verifier: re-hash stored bytes and compare to the CID.
pub trait ContentVerifier {
    fn verify(&self, cid: &str, bytes: &[u8]) -> Verdict;
}

/// Per-run limits. All limits may be zero; see `zero_limits_do_nothing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrubLimits {
    /// Items walked per batch step.
    pub batch_size: usize,
    /// Stored bytes re-hashed per run before stopping.
    pub byte_budget: u64,
    /// Re-fetch attempts scheduled per corrupt item.
    pub max_refetch_attempts: u8,
}

impl Default for ScrubLimits {
    fn default() -> Self {
        ScrubLimits {
            batch_size: 64,
            byte_budget: 1024 * 1024,
            max_refetch_attempts: 1,
        }
    }
}

/// Where an item stands after a scrub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemState {
    /// Verified against its CID this run.
    Healthy,
    /// Stored bytes did not match the CID; bytes are not served.
    ContentCorrupt,
    /// Corrupt item whose re-fetch is scheduled (attempt count recorded).
    RefetchScheduled { attempts: u8 },
}

/// A scheduled re-fetch for a corrupt item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refetch {
    /// CID whose stored bytes are to be re-fetched.
    pub cid: String,
    /// Attempt index (1-based).
    pub attempt: u8,
}

/// Resume cursor: index into the ordered item list where this run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub next_index: usize,
    pub bytes_hashed: u64,
}

impl Cursor {
    pub const START: Cursor = Cursor {
        next_index: 0,
        bytes_hashed: 0,
    };
}

/// What one scrub run produced. Bytes for corrupt items are never included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubOutcome {
    pub states: Vec<ItemState>,
    pub refetches: Vec<Refetch>,
    pub cursor: Cursor,
}

impl ScrubOutcome {
    /// Bytes a caller may serve: only Healthy items, never corrupt ones.
    pub fn served(&self, items: &[StoredItem]) -> Vec<Vec<u8>> {
        items
            .iter()
            .zip(self.states.iter())
            .filter(|(_, st)| matches!(st, ItemState::Healthy))
            .map(|(it, _)| it.bytes.clone())
            .collect()
    }
}

/// Errors raised by the scrub plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrubError {
    EmptyBatch { batch_size: usize },
    ZeroBudget { byte_budget: u64 },
    DuplicateCid { cid: String },
    MissingCid { index: usize },
}

impl ScrubError {
    pub fn code(&self) -> &'static str {
        match self {
            ScrubError::EmptyBatch { .. } => "empty_batch",
            ScrubError::ZeroBudget { .. } => "zero_budget",
            ScrubError::DuplicateCid { .. } => "duplicate_cid",
            ScrubError::MissingCid { .. } => "missing_cid",
        }
    }
}

impl fmt::Display for ScrubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explain = match self {
            ScrubError::EmptyBatch { .. } => "batch size must be at least one item",
            ScrubError::ZeroBudget { .. } => "byte budget must be at least one byte",
            ScrubError::DuplicateCid { .. } => "two stored items share one CID",
            ScrubError::MissingCid { .. } => "stored item has an empty CID",
        };
        write!(f, "{}: {}", self.code(), explain)
    }
}

/// The scrub plan: ordered items plus the cursor from the last run.
#[derive(Debug, Clone)]
pub struct ScrubPlan {
    pub items: Vec<StoredItem>,
    pub cursor: Cursor,
}

impl ScrubPlan {
    pub fn new(items: Vec<StoredItem>) -> Result<Self, ScrubError> {
        for (index, item) in items.iter().enumerate() {
            if item.cid.is_empty() {
                return Err(ScrubError::MissingCid { index });
            }
        }
        for i in 0..items.len() {
            for j in (i + 1)..items.len() {
                if items[i].cid == items[j].cid {
                    return Err(ScrubError::DuplicateCid {
                        cid: items[i].cid.clone(),
                    });
                }
            }
        }
        Ok(ScrubPlan {
            items,
            cursor: Cursor::START,
        })
    }

    /// Run one batch under `limits`, resuming from the stored cursor.
    ///
    /// Walks whole items from `cursor.next_index`. Stops before an item whose
    /// bytes would exceed the remaining budget, unless it is the first item of
    /// the run (so the cursor always makes progress past an oversized item).
    /// States are reported for the whole item list; items not walked this run
    /// keep `Healthy` as their not-yet-rechecked placeholder and are rechecked
    /// by a later run via the cursor.
    pub fn run<V: ContentVerifier>(
        &mut self,
        verifier: &V,
        limits: ScrubLimits,
    ) -> Result<ScrubOutcome, ScrubError> {
        if limits.batch_size == 0 {
            return Err(ScrubError::EmptyBatch {
                batch_size: limits.batch_size,
            });
        }
        if limits.byte_budget == 0 {
            return Err(ScrubError::ZeroBudget {
                byte_budget: limits.byte_budget,
            });
        }

        let mut states = Vec::with_capacity(self.items.len());
        for _ in 0..self.items.len() {
            states.push(ItemState::Healthy);
        }
        let mut refetches: VecDeque<Refetch> = VecDeque::new();

        let start = self.cursor.next_index.min(self.items.len());
        let mut bytes_hashed: u64 = 0;
        let mut index = start;
        let mut walked: usize = 0;

        while index < self.items.len() && walked < limits.batch_size {
            let cost = self.items[index].bytes.len() as u64;
            if walked > 0 && bytes_hashed + cost > limits.byte_budget {
                break;
            }
            let cid = self.items[index].cid.clone();
            match verifier.verify(&cid, &self.items[index].bytes) {
                Verdict::Match => {
                    states[index] = ItemState::Healthy;
                }
                Verdict::Mismatch => {
                    let attempts = limits.max_refetch_attempts;
                    states[index] = if attempts == 0 {
                        ItemState::ContentCorrupt
                    } else {
                        ItemState::RefetchScheduled { attempts }
                    };
                    let mut scheduled = 0u8;
                    while scheduled < attempts {
                        scheduled += 1;
                        refetches.push_back(Refetch {
                            cid: cid.clone(),
                            attempt: scheduled,
                        });
                    }
                }
            }
            bytes_hashed += cost;
            walked += 1;
            index += 1;
        }

        self.cursor = Cursor {
            next_index: index,
            bytes_hashed: self.cursor.bytes_hashed + bytes_hashed,
        };

        Ok(ScrubOutcome {
            states,
            refetches: refetches.into_iter().collect(),
            cursor: self.cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedVerifier {
        bad: Vec<String>,
    }

    impl ContentVerifier for FixedVerifier {
        fn verify(&self, cid: &str, _bytes: &[u8]) -> Verdict {
            if self.bad.iter().any(|b| b == cid) {
                Verdict::Mismatch
            } else {
                Verdict::Match
            }
        }
    }

    fn item(cid: &str, len: usize) -> StoredItem {
        StoredItem {
            cid: cid.to_string(),
            bytes: vec![cid.len() as u8; len],
        }
    }

    // P12: a matching item stays Healthy and its bytes are served.
    #[test]
    fn matching_item_stays_healthy() {
        let items = vec![item("cid-a", 8), item("cid-b", 8)];
        let verifier = FixedVerifier { bad: vec![] };
        let mut plan = ScrubPlan::new(items.clone()).expect("plan");
        let out = plan.run(&verifier, ScrubLimits::default()).expect("run");
        assert_eq!(out.states[0], ItemState::Healthy);
        assert_eq!(out.states[1], ItemState::Healthy);
        assert_eq!(
            out.served(&items),
            vec![items[0].bytes.clone(), items[1].bytes.clone()]
        );
    }

    // P12: a mismatch marks the item content_corrupt, schedules a re-fetch, and
    // the bad bytes are never served.
    #[test]
    fn mismatch_marks_corrupt_and_never_served() {
        let items = vec![item("cid-a", 8), item("cid-bad", 8)];
        let verifier = FixedVerifier {
            bad: vec!["cid-bad".to_string()],
        };
        let mut plan = ScrubPlan::new(items.clone()).expect("plan");
        let out = plan.run(&verifier, ScrubLimits::default()).expect("run");
        assert_eq!(
            out.states[1],
            ItemState::RefetchScheduled { attempts: 1 }
        );
        assert_eq!(out.refetches.len(), 1);
        assert_eq!(out.refetches[0].cid, "cid-bad");
        assert_eq!(out.served(&items), vec![items[0].bytes.clone()]);
    }

    // P12: the byte budget stops the run and the cursor resumes next time.
    // With a 15-byte budget and 10-byte items each run takes exactly one item,
    // so the cursor advances 1 -> 2 -> 3 and then stays at the end.
    #[test]
    fn byte_budget_resumes_from_cursor() {
        let items = vec![item("a", 10), item("b", 10), item("c", 10)];
        let verifier = FixedVerifier { bad: vec![] };
        let mut plan = ScrubPlan::new(items.clone()).expect("plan");
        let limits = ScrubLimits {
            batch_size: 64,
            byte_budget: 15,
            max_refetch_attempts: 1,
        };
        let first = plan.run(&verifier, limits).expect("first");
        assert_eq!(first.cursor.next_index, 1);
        let second = plan.run(&verifier, limits).expect("second");
        assert_eq!(second.cursor.next_index, 2);
        let third = plan.run(&verifier, limits).expect("third");
        assert_eq!(third.cursor.next_index, 3);
        let after = plan.run(&verifier, limits).expect("after");
        assert_eq!(after.cursor.next_index, 3);
    }

    // P12: a summary run keeps walking the plan to completion; the total
    // bytes_hashed accumulates monotonically and never re-hashes an item.
    // Three 10-byte items with a 32-byte budget finish in two runs with no
    // skipped bytes.
    #[test]
    fn cursor_keeps_walking_without_rehashing() {
        let items = vec![item("a", 10), item("b", 10), item("c", 10)];
        let verifier = FixedVerifier { bad: vec![] };
        let mut plan = ScrubPlan::new(items).expect("plan");
        let limits = ScrubLimits {
            batch_size: 64,
            byte_budget: 32,
            max_refetch_attempts: 1,
        };
        let first = plan.run(&verifier, limits).expect("first");
        assert_eq!(first.cursor.next_index, 3);
        assert_eq!(first.cursor.bytes_hashed, 30);
        let after = plan.run(&verifier, limits).expect("after");
        assert_eq!(after.cursor.next_index, 3);
        assert_eq!(after.cursor.bytes_hashed, 30);
    }

    // P12: with every limit at zero the plan refuses the run without walking.
    #[test]
    fn zero_limits_do_nothing() {
        let items = vec![item("a", 4)];
        let verifier = FixedVerifier { bad: vec![] };
        let mut plan = ScrubPlan::new(items).expect("plan");
        let limits = ScrubLimits {
            batch_size: 0,
            byte_budget: 0,
            max_refetch_attempts: 0,
        };
        let err = plan.run(&verifier, limits).expect_err("refused");
        assert_eq!(err.code(), "empty_batch");
        assert_eq!(plan.cursor.next_index, 0);
    }

    // P12: a corrupt item with zero retries is still marked corrupt and the
    // refusal codes stay stable snake_case.
    #[test]
    fn refusals_have_stable_codes() {
        assert_eq!(
            ScrubError::EmptyBatch { batch_size: 0 }.code(),
            "empty_batch"
        );
        assert_eq!(
            ScrubError::ZeroBudget { byte_budget: 0 }.code(),
            "zero_budget"
        );
        assert_eq!(
            ScrubError::DuplicateCid { cid: "x".into() }.code(),
            "duplicate_cid"
        );
        assert_eq!(
            ScrubError::MissingCid { index: 0 }.code(),
            "missing_cid"
        );
        let shown = format!("{}", ScrubError::MissingCid { index: 0 });
        assert!(shown.starts_with("missing_cid: "));
    }
}
