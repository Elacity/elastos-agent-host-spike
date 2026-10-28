//! `receipt_budget`: a storage budget for a receipt chain (M3 P2-7, P10, P18).
//!
//! Every receipt has a label and a size in bytes. A [`ReceiptBudget`] holds a
//! byte budget and a set of receipts. The chain head is a receipt already in
//! the chain. When adding a receipt would exceed the budget, the oldest
//! receipts that are neither the chain head nor a checkpoint are proposed for
//! archival first (P18 data lifecycle). The head and checkpoints are never
//! proposed, so the chain stays verifiable.
//!
//! A budget of zero is refused with [`BudgetRefusal::BadReceiptBudget`]. This
//! module is pure: it proposes archival, it never deletes anything itself.
//!
//! Preset choices the task left open (small and conservative): the tests use a
//! budget of 100 bytes and receipts of 10 bytes each.

use std::collections::VecDeque;
use std::fmt;

/// Refusals from building or driving a receipt budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// The budget was zero bytes.
    BadReceiptBudget,
    /// A receipt was larger than the entire budget.
    ReceiptExceedsBudget,
    /// A label was requested as head for a receipt not in the chain.
    UnknownReceipt,
}

impl BudgetRefusal {
    /// Stable snake_case code for each refusal.
    pub fn code(&self) -> &'static str {
        match self {
            BudgetRefusal::BadReceiptBudget => "bad_receipt_budget",
            BudgetRefusal::ReceiptExceedsBudget => "receipt_exceeds_budget",
            BudgetRefusal::UnknownReceipt => "unknown_receipt",
        }
    }
}

impl fmt::Display for BudgetRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let human = match self {
            BudgetRefusal::BadReceiptBudget => "receipt budget must be greater than zero",
            BudgetRefusal::ReceiptExceedsBudget => "one receipt is larger than the whole budget",
            BudgetRefusal::UnknownReceipt => "no receipt with that label in the chain",
        };
        write!(f, "{}: {}", self.code(), human)
    }
}

impl std::error::Error for BudgetRefusal {}

/// One receipt in the chain: a label, a size in bytes and whether it is a
/// checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptEntry {
    label: String,
    size: u64,
    checkpoint: bool,
}

/// A byte budget over a receipt chain.
#[derive(Debug, Clone)]
pub struct ReceiptBudget {
    budget: u64,
    head: Option<String>,
    receipts: VecDeque<ReceiptEntry>,
    used: u64,
}

impl ReceiptBudget {
    /// Start a budget of `budget` bytes with an empty chain. The chain head is
    /// set later with [`ReceiptBudget::set_head`] once its receipt exists.
    /// Refuses `BadReceiptBudget` when the budget is zero.
    pub fn new(budget: u64) -> Result<Self, BudgetRefusal> {
        if budget == 0 {
            return Err(BudgetRefusal::BadReceiptBudget);
        }
        Ok(ReceiptBudget {
            budget,
            head: None,
            receipts: VecDeque::new(),
            used: 0,
        })
    }

    /// Bytes currently used by the chain.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// The configured byte budget.
    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// The current chain head label, if one is set.
    pub fn head(&self) -> Option<&str> {
        self.head.as_deref()
    }

    /// Add a non-checkpoint receipt. Returns the labels this push proposes for
    /// archival to stay within budget. Refuses when one receipt alone exceeds
    /// the budget.
    pub fn push(&mut self, label: impl Into<String>, size: u64) -> Result<Vec<String>, BudgetRefusal> {
        self.push_entry(label.into(), size, false)
    }

    /// Add a checkpoint receipt. Checkpoints are never proposed for archival.
    pub fn push_checkpoint(
        &mut self,
        label: impl Into<String>,
        size: u64,
    ) -> Result<Vec<String>, BudgetRefusal> {
        self.push_entry(label.into(), size, true)
    }

    /// Mark `label` as the new chain head. The head is never proposed for
    /// archival.
    pub fn set_head(&mut self, label: impl Into<String>) -> Result<(), BudgetRefusal> {
        let label = label.into();
        if !self.receipts.iter().any(|r| r.label == label) {
            return Err(BudgetRefusal::UnknownReceipt);
        }
        self.head = Some(label);
        Ok(())
    }

    /// The labels kept in the chain, oldest to newest.
    pub fn labels(&self) -> Vec<String> {
        self.receipts.iter().map(|r| r.label.clone()).collect()
    }

    fn push_entry(
        &mut self,
        label: String,
        size: u64,
        checkpoint: bool,
    ) -> Result<Vec<String>, BudgetRefusal> {
        if size > self.budget {
            return Err(BudgetRefusal::ReceiptExceedsBudget);
        }
        self.receipts.push_back(ReceiptEntry { label, size, checkpoint });
        self.used += size;
        let mut archived = Vec::new();
        while self.used > self.budget {
            let head = self.head.clone();
            let victim = self
                .receipts
                .iter()
                .position(|r| !r.checkpoint && Some(&r.label) != head.as_ref());
            match victim {
                Some(idx) => {
                    if let Some(entry) = self.receipts.remove(idx) {
                        self.used = self.used.saturating_sub(entry.size);
                        if Some(&entry.label) == head.as_ref() {
                            self.head = None;
                        }
                        archived.push(entry.label);
                    }
                }
                None => break,
            }
        }
        Ok(archived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P10: a budget of zero is refused with bad_receipt_budget, never silently
    // accepted as an unbounded chain.
    #[test]
    fn zero_budget_is_refused() {
        let err = ReceiptBudget::new(0).unwrap_err();
        assert_eq!(err.code(), "bad_receipt_budget");
        assert_eq!(err.to_string(), "bad_receipt_budget: receipt budget must be greater than zero");
    }

    // P10: a positive budget is accepted and starts empty with no head.
    #[test]
    fn positive_budget_is_accepted() {
        let b = ReceiptBudget::new(100).unwrap();
        assert_eq!(b.budget(), 100);
        assert_eq!(b.used(), 0);
        assert!(b.labels().is_empty());
        assert_eq!(b.head(), None);
    }

    // P18: under the budget nothing is proposed for archival.
    #[test]
    fn under_budget_archives_nothing() {
        let mut b = ReceiptBudget::new(100).unwrap();
        let proposed = b.push("r1", 10).unwrap();
        assert!(proposed.is_empty());
        assert_eq!(b.used(), 10);
        assert_eq!(b.labels(), vec!["r1".to_string()]);
    }

    // P18: going over budget proposes the oldest non-head, non-checkpoint receipt.
    #[test]
    fn over_budget_proposes_oldest_non_checkpoint() {
        let mut b = ReceiptBudget::new(30).unwrap();
        b.push("r1", 10).unwrap();
        b.push("r2", 10).unwrap();
        b.push("head", 10).unwrap();
        b.set_head("head").unwrap();
        assert_eq!(b.used(), 30);
        let proposed = b.push("r3", 10).unwrap();
        assert_eq!(proposed, vec!["r1".to_string()]);
        assert_eq!(b.used(), 30);
        assert_eq!(b.labels(), vec!["r2".to_string(), "head".to_string(), "r3".to_string()]);
    }

    // P18: the chain head is never proposed for archival even when oldest.
    // Here the head "h" is pushed first, then "r1" fills the budget, and "r2"
    // overflows: "h" is skipped and "r1" (the oldest non-head) is proposed.
    #[test]
    fn chain_head_never_archived() {
        let mut b = ReceiptBudget::new(20).unwrap();
        b.push("h", 10).unwrap();
        b.set_head("h").unwrap();
        b.push("r1", 10).unwrap();
        assert_eq!(b.used(), 20);
        let proposed = b.push("r2", 10).unwrap();
        assert_eq!(proposed, vec!["r1".to_string()]);
        assert_eq!(b.labels(), vec!["h".to_string(), "r2".to_string()]);
        assert_eq!(b.head(), Some("h"));
    }

    // P18: checkpoints are never proposed for archival even when oldest.
    // "cp1" (checkpoint) is oldest, then "h" is the head, then "r1" overflows:
    // the checkpoint is skipped and "h" is not a candidate, so nothing but the
    // oldest non-checkpoint can go; here that is "r1" itself, which is the new
    // receipt, proving the checkpoint and head survive.
    #[test]
    fn checkpoints_never_archived() {
        let mut b = ReceiptBudget::new(20).unwrap();
        b.push_checkpoint("cp1", 10).unwrap();
        b.push("h", 10).unwrap();
        b.set_head("h").unwrap();
        assert_eq!(b.used(), 20);
        let proposed = b.push("r1", 10).unwrap();
        assert_eq!(proposed, vec!["r1".to_string()]);
        assert_eq!(b.labels(), vec!["cp1".to_string(), "h".to_string()]);
        assert_eq!(b.used(), 20);
    }

    // P10: a single receipt larger than the budget is refused.
    #[test]
    fn receipt_exceeding_budget_refused() {
        let mut b = ReceiptBudget::new(10).unwrap();
        let err = b.push("big", 11).unwrap_err();
        assert_eq!(err.code(), "receipt_exceeds_budget");
        assert_eq!(b.used(), 0);
    }

    // P18: setting head to an unknown label is refused; Display is code: text.
    #[test]
    fn unknown_head_refused() {
        let mut b = ReceiptBudget::new(10).unwrap();
        let err = b.set_head("missing").unwrap_err();
        assert_eq!(err.code(), "unknown_receipt");
        assert!(err.to_string().starts_with("unknown_receipt: "));
    }

    // P10: every limit at zero. Budget zero refuses bad_receipt_budget; a
    // zero-sized receipt is allowed and uses nothing.
    #[test]
    fn all_limits_zero() {
        let zero_budget = ReceiptBudget::new(0);
        assert_eq!(zero_budget.unwrap_err().code(), "bad_receipt_budget");
        let mut b = ReceiptBudget::new(1).unwrap();
        let proposed = b.push("empty", 0).unwrap();
        assert!(proposed.is_empty());
        assert_eq!(b.used(), 0);
    }
}
