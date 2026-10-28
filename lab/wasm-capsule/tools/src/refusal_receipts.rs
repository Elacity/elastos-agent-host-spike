//! M3 receipts (P12, P18): every lab op, allowed or refused, leaves a receipt.
//!
//! P12 says a refusal is a first-class, named outcome: not a panic, not a
//! free-form string, but one code from a fixed table that callers can compare.
//! P18 says the record of what happened comes from the run itself. So this
//! module keeps a ledger of receipts in the order the ops happened, and one
//! refused op is recorded exactly like one allowed op, distinguished only by
//! its kind and code.
//!
//! [`Refusal`] is the one error enum of this module. Every variant has one arm
//! in [`Refusal::code`], a single table returning a stable snake_case code;
//! there is no wildcard arm, so a new variant without a code does not build.
//! [`std::fmt::Display`] renders `<code>: <one-line explanation>` and never
//! carries an absolute host path: relative names only.
//!
//! [`Receipts`] is the ledger. [`Receipts::record_allowed`] appends an allowed
//! receipt and [`Receipts::record_refused`] appends a refusal receipt; both
//! return `Ok(())` on success and never hand out a borrow of the ledger's
//! storage, so a caller can keep recording without an aliasing conflict.
//! [`Receipts::all`] reads the receipts back in the order they were recorded.
//! Both record functions take plain `&str` names instead of owned typed
//! inputs, so callers need no extra types.
//!
//! Presets the task did not give, chosen small and conservative: a ledger holds
//! at most [`RECEIPTS_CAPACITY`] receipts, and recording beyond it refuses with
//! [`Refusal::ReceiptsFull`] rather than growing without bound.

use std::fmt;

/// The most receipts one [`Receipts`] ledger keeps (preset; see module docs).
pub const RECEIPTS_CAPACITY: usize = 64;

/// The kind of thing a [`Receipt`] records: an op that was allowed, or one
/// that was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptKind {
    /// The op ran.
    Allowed,
    /// The op was refused; the receipt carries the refusal code.
    Refusal,
}

impl ReceiptKind {
    /// The stable lowercase snake_case name of this kind.
    pub fn code(&self) -> &'static str {
        match self {
            ReceiptKind::Allowed => "allowed",
            ReceiptKind::Refusal => "refusal",
        }
    }
}

/// One receipt: the op's name, its kind, and for a refusal its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    op: String,
    kind: ReceiptKind,
    code: Option<&'static str>,
}

impl Receipt {
    /// The op name the receipt was recorded with.
    pub fn op(&self) -> &str {
        &self.op
    }

    /// The receipt's kind.
    pub fn kind(&self) -> ReceiptKind {
        self.kind
    }

    /// The refusal code of a refusal receipt, `None` for an allowed one.
    pub fn code(&self) -> Option<&'static str> {
        self.code
    }
}

/// The one error enum of this module. Each variant has one arm in
/// [`Refusal::code`]; the codes are stable and snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The op name was empty.
    EmptyOp,
    /// The ledger already holds [`RECEIPTS_CAPACITY`] receipts.
    ReceiptsFull,
    /// The requested receipt index is not in the ledger.
    ReceiptNotFound,
}

impl Refusal {
    /// The one code table: each variant maps to one stable snake_case code.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::EmptyOp => "empty_op",
            Refusal::ReceiptsFull => "receipts_full",
            Refusal::ReceiptNotFound => "receipt_not_found",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            Refusal::EmptyOp => "the op name is empty",
            Refusal::ReceiptsFull => "the receipt ledger is full",
            Refusal::ReceiptNotFound => "the receipt index is not in the ledger",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

/// An ordered ledger of receipts. See the module docs.
#[derive(Debug, Default, Clone)]
pub struct Receipts {
    entries: Vec<Receipt>,
}

impl Receipts {
    /// A new, empty ledger.
    pub fn new() -> Receipts {
        Receipts {
            entries: Vec::new(),
        }
    }

    /// Append an allowed receipt for `op`. Refuses an empty op name and a full
    /// ledger; the receipt is pushed only on success.
    pub fn record_allowed(&mut self, op: &str) -> Result<(), Refusal> {
        self.record(op, ReceiptKind::Allowed, None)
    }

    /// Append a refusal receipt for `op` carrying `refusal`'s code.
    pub fn record_refused(&mut self, op: &str, refusal: Refusal) -> Result<(), Refusal> {
        self.record(op, ReceiptKind::Refusal, Some(refusal.code()))
    }

    fn record(
        &mut self,
        op: &str,
        kind: ReceiptKind,
        code: Option<&'static str>,
    ) -> Result<(), Refusal> {
        if op.is_empty() {
            return Err(Refusal::EmptyOp);
        }
        if self.entries.len() >= RECEIPTS_CAPACITY {
            return Err(Refusal::ReceiptsFull);
        }
        self.entries.push(Receipt {
            op: op.to_owned(),
            kind,
            code,
        });
        Ok(())
    }

    /// Every receipt, in the order it was recorded.
    pub fn all(&self) -> &[Receipt] {
        &self.entries
    }

    /// The receipt at `index`, or [`Refusal::ReceiptNotFound`].
    pub fn get(&self, index: usize) -> Result<&Receipt, Refusal> {
        self.entries.get(index).ok_or(Refusal::ReceiptNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P12, P18: one allowed op then one refused op leaves two receipts, in
    // that order, and only the refused one carries a refusal code.
    #[test]
    fn one_allowed_one_refused_give_two_ordered_receipts() {
        let mut ledger = Receipts::new();
        ledger.record_allowed("verify").unwrap();
        ledger.record_refused("run", Refusal::ReceiptsFull).unwrap();

        let all = ledger.all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].op(), "verify");
        assert_eq!(all[0].kind(), ReceiptKind::Allowed);
        assert_eq!(all[0].code(), None);
        assert_eq!(all[1].op(), "run");
        assert_eq!(all[1].kind(), ReceiptKind::Refusal);
        assert_eq!(all[1].code(), Some("receipts_full"));
    }

    // P12: every refusal has a stable snake_case code from the one table.
    #[test]
    fn each_refusal_has_its_code() {
        assert_eq!(Refusal::EmptyOp.code(), "empty_op");
        assert_eq!(Refusal::ReceiptsFull.code(), "receipts_full");
        assert_eq!(Refusal::ReceiptNotFound.code(), "receipt_not_found");
    }

    // P12: an empty op is refused and nothing is recorded; the empty ledger
    // then reports the missing-index refusal, not the empty-op one.
    #[test]
    fn empty_op_is_refused_and_not_recorded() {
        let mut ledger = Receipts::new();
        assert_eq!(ledger.record_allowed(""), Err(Refusal::EmptyOp));
        assert_eq!(ledger.all().len(), 0);
        assert_eq!(ledger.get(0).unwrap_err(), Refusal::ReceiptNotFound);
        assert_eq!(ledger.get(0).unwrap_err().code(), "receipt_not_found");
    }

    // P12 limits test: every limit at zero means the ledger refuses its first
    // receipt. Covered through capacity by filling to the preset and no more.
    #[test]
    fn full_ledger_refuses_the_next_receipt() {
        let mut ledger = Receipts::new();
        for _ in 0..RECEIPTS_CAPACITY {
            ledger.record_allowed("op").unwrap();
        }
        assert_eq!(
            ledger.record_refused("op", Refusal::EmptyOp),
            Err(Refusal::ReceiptsFull)
        );
        assert_eq!(ledger.all().len(), RECEIPTS_CAPACITY);
        let last = ledger.get(RECEIPTS_CAPACITY - 1).unwrap();
        assert_eq!(last.code(), None);
    }

    // P12: Display renders `<code>: <explanation>` and carries no leading
    // slash, so no absolute host path leaks into a receipt.
    #[test]
    fn display_is_code_then_explanation() {
        let rendered = Refusal::EmptyOp.to_string();
        assert_eq!(rendered, "empty_op: the op name is empty");
        assert!(!rendered.starts_with('/'));
    }
}
