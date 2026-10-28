//! wc-005d: export a receipt chain as newline-delimited records.
//!
//! Each exported record carries the record's own CID and its parent's CID.
//! The first record of a chain has no parent, written `-`. Every later
//! record's parent must equal the previous record's CID; when it does not,
//! the export is refused `chain_broken` naming the first bad index. An
//! empty chain exports nothing (zero bytes).
//!
//! This is a lab writer. It makes no admission or launch decision, and it
//! holds no host path: indices and CIDs are relative names only.
//!
//! Preset limits chosen here (not given by the task), small and
//! conservative: `ExportLimits { max_records: 4096, max_record_bytes: 1024,
//! max_total_bytes: 1_048_576 }`. A zero limit rejects any chain.

use std::fmt;

/// One link of a receipt chain: an opaque CID and its parent's CID.
///
/// `parent` is `None` only for the head record. The encoding of `cid` is
/// opaque here; this module compares and prints it, and adds no rule of its
/// own about how a CID is spelled beyond being non-empty and free of the
/// record separator and newline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub cid: String,
    pub parent: Option<String>,
}

impl Receipt {
    /// A head record with no parent.
    pub fn head(cid: &str) -> Self {
        Receipt { cid: cid.to_string(), parent: None }
    }

    /// A record chained to `parent`.
    pub fn child(cid: &str, parent: &str) -> Self {
        Receipt { cid: cid.to_string(), parent: Some(parent.to_string()) }
    }
}

/// Small conservative budgets for one export. See the module doc comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportLimits {
    pub max_records: usize,
    pub max_record_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for ExportLimits {
    fn default() -> Self {
        ExportLimits { max_records: 4096, max_record_bytes: 1024, max_total_bytes: 1_048_576 }
    }
}

/// A refusal from the export path. One variant per rule, one arm per
/// variant in `code()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportRefusal {
    /// The chain does not link: record at `index` names a parent that is
    /// not the previous record's CID.
    ChainBroken { index: usize },
    /// A head record was given a parent at `index`.
    UnexpectedParent { index: usize },
    /// A non-head record has no parent at `index`.
    MissingParent { index: usize },
    /// A CID is empty or contains the record separator.
    MalformedCid { index: usize },
    /// A limit was zero or the export exceeds it.
    LimitExceeded { limit: &'static str },
}

impl ExportRefusal {
    /// The stable snake_case code. Callers match this, never Display text.
    pub fn code(&self) -> &'static str {
        match self {
            ExportRefusal::ChainBroken { .. } => "chain_broken",
            ExportRefusal::UnexpectedParent { .. } => "unexpected_parent",
            ExportRefusal::MissingParent { .. } => "missing_parent",
            ExportRefusal::MalformedCid { .. } => "malformed_cid",
            ExportRefusal::LimitExceeded { .. } => "limit_exceeded",
        }
    }
}

impl fmt::Display for ExportRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportRefusal::ChainBroken { index } => {
                write!(f, "{}: record {} does not link to its predecessor", self.code(), index)
            }
            ExportRefusal::UnexpectedParent { index } => {
                write!(f, "{}: head record {} carries a parent", self.code(), index)
            }
            ExportRefusal::MissingParent { index } => {
                write!(f, "{}: record {} has no parent", self.code(), index)
            }
            ExportRefusal::MalformedCid { index } => {
                write!(f, "{}: record {} has an unusable cid", self.code(), index)
            }
            ExportRefusal::LimitExceeded { limit } => {
                write!(f, "{}: export exceeds the {} limit", self.code(), limit)
            }
        }
    }
}

/// The field separator and the no-parent marker.
const FIELD_SEP: char = '\t';
const NO_PARENT: &str = "-";

/// One exported line, before joining. `cid<TAB>parent`, head parent `-`.
fn render(receipt: &Receipt) -> String {
    let parent = receipt.parent.as_deref().unwrap_or(NO_PARENT);
    format!("{}{}{}", receipt.cid, FIELD_SEP, parent)
}

fn check_cid(cid: &str, index: usize) -> Result<(), ExportRefusal> {
    if cid.is_empty() || cid.contains(FIELD_SEP) || cid.contains('\n') {
        return Err(ExportRefusal::MalformedCid { index });
    }
    Ok(())
}

/// Export `chain` as newline-delimited records.
///
/// Returns the bytes to write: one line per record, `cid\tparent`, with a
/// trailing newline after each, and zero bytes for an empty chain. A broken
/// link is refused `chain_broken` with the first bad index. A zero limit
/// refuses even an empty chain.
pub fn export(chain: &[Receipt], limits: ExportLimits) -> Result<Vec<u8>, ExportRefusal> {
    if limits.max_records == 0 {
        return Err(ExportRefusal::LimitExceeded { limit: "max_records" });
    }
    if limits.max_record_bytes == 0 {
        return Err(ExportRefusal::LimitExceeded { limit: "max_record_bytes" });
    }
    if limits.max_total_bytes == 0 {
        return Err(ExportRefusal::LimitExceeded { limit: "max_total_bytes" });
    }
    if chain.len() > limits.max_records {
        return Err(ExportRefusal::LimitExceeded { limit: "max_records" });
    }

    let mut out: Vec<u8> = Vec::new();
    let mut previous: Option<&str> = None;

    for (index, receipt) in chain.iter().enumerate() {
        check_cid(&receipt.cid, index)?;
        if let Some(parent) = receipt.parent.as_deref() {
            check_cid(parent, index)?;
        }

        match (index, receipt.parent.as_deref()) {
            (0, Some(_)) => return Err(ExportRefusal::UnexpectedParent { index }),
            (0, None) => {}
            (_, None) => return Err(ExportRefusal::MissingParent { index }),
            (_, Some(parent)) => {
                if previous != Some(parent) {
                    return Err(ExportRefusal::ChainBroken { index });
                }
            }
        }

        let line = render(receipt);
        let line_bytes = line.len() + 1;
        if line.len() > limits.max_record_bytes {
            return Err(ExportRefusal::LimitExceeded { limit: "max_record_bytes" });
        }
        if out.len() + line_bytes > limits.max_total_bytes {
            return Err(ExportRefusal::LimitExceeded { limit: "max_total_bytes" });
        }
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
        previous = Some(receipt.cid.as_str());
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // P18: a linked chain exports every record with its own CID and its
    // parent's CID, in order, head parent rendered `-`.
    #[test]
    fn exports_cids_and_parents_in_order() {
        let chain = vec![Receipt::head("a"), Receipt::child("b", "a"), Receipt::child("c", "b")];
        let bytes = export(&chain, ExportLimits::default()).expect("linked chain exports");
        let text = String::from_utf8(bytes).expect("utf8");
        assert_eq!(text, "a\t-\nb\ta\nc\tb\n");
    }

    // P18: an empty chain exports nothing.
    #[test]
    fn empty_chain_exports_nothing() {
        let bytes = export(&[], ExportLimits::default()).expect("empty chain exports");
        assert!(bytes.is_empty());
    }

    // P18: a record that names the wrong parent is refused chain_broken
    // naming the first bad index.
    #[test]
    fn broken_chain_refused_with_first_index() {
        let chain = vec![Receipt::head("a"), Receipt::child("b", "a"), Receipt::child("c", "x")];
        let refusal = export(&chain, ExportLimits::default()).expect_err("broken chain refused");
        assert_eq!(refusal.code(), "chain_broken");
        match refusal {
            ExportRefusal::ChainBroken { index } => assert_eq!(index, 2),
            other => panic!("expected chain_broken, got {}", other.code()),
        }
    }

    // P18: the first bad index is reported even with many later links
    // wrong, so callers can point at one record.
    #[test]
    fn reports_first_bad_index_only() {
        let chain = vec![
            Receipt::head("a"),
            Receipt::child("b", "wrong"),
            Receipt::child("c", "also-wrong"),
        ];
        let refusal = export(&chain, ExportLimits::default()).expect_err("refused");
        match refusal {
            ExportRefusal::ChainBroken { index } => assert_eq!(index, 1),
            other => panic!("expected chain_broken, got {}", other.code()),
        }
    }

    // P12: a head record with a parent and a later record without one are
    // each refused with their own code.
    #[test]
    fn head_parent_and_missing_parent_refused() {
        let head_with_parent = vec![Receipt::child("a", "z")];
        let r = export(&head_with_parent, ExportLimits::default()).expect_err("refused");
        assert_eq!(r.code(), "unexpected_parent");

        let missing = vec![Receipt::head("a"), Receipt { cid: "b".to_string(), parent: None }];
        let r = export(&missing, ExportLimits::default()).expect_err("refused");
        assert_eq!(r.code(), "missing_parent");
    }

    // P12: a CID that is empty or carries the field separator is refused.
    #[test]
    fn malformed_cid_refused() {
        let empty = vec![Receipt::head("")];
        let r = export(&empty, ExportLimits::default()).expect_err("refused");
        assert_eq!(r.code(), "malformed_cid");

        let separated = vec![Receipt::head("a\tb")];
        let r = export(&separated, ExportLimits::default()).expect_err("refused");
        assert_eq!(r.code(), "malformed_cid");
    }

    // P12: a limits type with every limit at zero refuses any chain,
    // including the empty one.
    #[test]
    fn all_limits_zero_refuses() {
        let zero = ExportLimits { max_records: 0, max_record_bytes: 0, max_total_bytes: 0 };
        let r = export(&[], zero).expect_err("zero limits refuse");
        assert_eq!(r.code(), "limit_exceeded");
    }

    // P12: a record over the per-record cap is refused; per-record cap
    // counts the rendered line without its newline, so "abcd" (4 bytes,
    // "abcd\t-") is over a cap of 3.
    #[test]
    fn record_over_cap_refused() {
        let limits = ExportLimits { max_records: 10, max_record_bytes: 3, max_total_bytes: 100 };
        let chain = vec![Receipt::head("abcd")];
        let r = export(&chain, limits).expect_err("refused");
        assert_eq!(r.code(), "limit_exceeded");
        match r {
            ExportRefusal::LimitExceeded { limit } => assert_eq!(limit, "max_record_bytes"),
            other => panic!("expected limit_exceeded, got {}", other.code()),
        }
    }

    // Display renders "<code>: <explanation>" and carries no host path.
    #[test]
    fn display_renders_code_prefix() {
        let r = ExportRefusal::ChainBroken { index: 4 };
        let text = format!("{}", r);
        assert!(text.starts_with("chain_broken: "));
        assert!(!text.contains('/'));
    }
}
