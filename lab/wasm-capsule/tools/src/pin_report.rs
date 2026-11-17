//! `pin_report`: P12's comparison of the owner's desired pin set with what a
//! device actually holds.
//!
//! The owner states a desired set of CIDs (opaque lab CID strings). The device
//! states what it holds as `(cid, content_hash_ok)` pairs. This module reports
//! the difference:
//!
//! - `missing`: desired CIDs the device does not hold at all;
//! - `extra`: held CIDs the owner did not desire;
//! - `corrupt`: held CIDs whose content hash failed, whether desired or not.
//!
//! A corrupt CID is not counted as missing: the device holds something for it,
//! it is just damaged. Corrupt held CIDs that the owner did not desire appear
//! under both `extra` and `corrupt`; a corrupt desired CID appears only under
//! `corrupt`. Each list is sorted and de-duplicated so the report is stable.
//! The report unpins nothing; it is an observation only, and the caller
//! decides what to do next.
//!
//! An empty desired set therefore lists every healthy held CID as extra;
//! corrupt held CIDs appear under `extra` and `corrupt`.
//!
//! Preset values chosen conservatively: no capacity limits are imposed here
//! (the report is a pure comparison), and CIDs are compared byte-for-byte.

use std::collections::BTreeSet;
use std::fmt;

/// A refusal from building or reading a pin report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinReportError {
    /// A CID string was empty or otherwise not usable as an identity.
    EmptyCid,
}

impl PinReportError {
    /// Stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            PinReportError::EmptyCid => "empty_cid",
        }
    }
}

impl fmt::Display for PinReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            PinReportError::EmptyCid => "a pin CID must not be empty",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for PinReportError {}

/// The owner's desired pin set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredPins {
    cids: BTreeSet<String>,
}

impl DesiredPins {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one desired CID. Rejects an empty CID; duplicates collapse.
    pub fn insert(&mut self, cid: impl Into<String>) -> Result<(), PinReportError> {
        let cid = cid.into();
        if cid.is_empty() {
            return Err(PinReportError::EmptyCid);
        }
        self.cids.insert(cid);
        Ok(())
    }

    pub fn contains(&self, cid: &str) -> bool {
        self.cids.contains(cid)
    }

    pub fn len(&self) -> usize {
        self.cids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cids.is_empty()
    }
}

/// What the device actually holds: a CID plus whether its content hash passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldPin {
    pub cid: String,
    pub content_hash_ok: bool,
}

impl HeldPin {
    pub fn new(cid: impl Into<String>, content_hash_ok: bool) -> Self {
        Self {
            cid: cid.into(),
            content_hash_ok,
        }
    }
}

/// The device's held set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeldPins {
    pins: Vec<HeldPin>,
}

impl HeldPins {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one held pin. An empty CID is rejected.
    pub fn insert(&mut self, pin: HeldPin) -> Result<(), PinReportError> {
        if pin.cid.is_empty() {
            return Err(PinReportError::EmptyCid);
        }
        self.pins.push(pin);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.pins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

/// The difference between desired and held pins. All lists sorted, unique.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinReport {
    pub missing: Vec<String>,
    pub extra: Vec<String>,
    pub corrupt: Vec<String>,
}

impl PinReport {
    /// Compare `desired` with `held`. Read-only: never removes a held pin.
    pub fn compare(desired: &DesiredPins, held: &HeldPins) -> Self {
        let mut healthy: BTreeSet<&str> = BTreeSet::new();
        let mut corrupt: BTreeSet<&str> = BTreeSet::new();
        for pin in &held.pins {
            if pin.content_hash_ok {
                healthy.insert(pin.cid.as_str());
            } else {
                corrupt.insert(pin.cid.as_str());
            }
        }

        let mut missing = Vec::new();
        for cid in &desired.cids {
            if !healthy.contains(cid.as_str()) && !corrupt.contains(cid.as_str()) {
                missing.push(cid.clone());
            }
        }

        let mut extra: Vec<String> = Vec::new();
        for cid in &healthy {
            if !desired.cids.contains(*cid) {
                extra.push((*cid).to_string());
            }
        }
        for cid in &corrupt {
            if !desired.cids.contains(*cid) {
                extra.push((*cid).to_string());
            }
        }
        extra.sort();
        extra.dedup();

        Self {
            missing,
            extra,
            corrupt: corrupt.iter().map(|cid| (*cid).to_string()).collect(),
        }
    }

    /// True when the device matches the owner's intent exactly.
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.extra.is_empty() && self.corrupt.is_empty()
    }

    /// Total count across all three lists. A report with every limit at zero
    /// (no missing, no extra, no corrupt) is clean.
    pub fn total(&self) -> usize {
        self.missing.len() + self.extra.len() + self.corrupt.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a DesiredPins from CIDs. Explicit construction keeps the helper
    // distinct from any method named `desired`.
    fn make_desired(cids: &[&str]) -> DesiredPins {
        let mut d = DesiredPins::new();
        for cid in cids {
            d.insert(*cid).expect("non-empty test cid");
        }
        d
    }

    fn make_held(pins: &[(&str, bool)]) -> HeldPins {
        let mut h = HeldPins::new();
        for (cid, ok) in pins {
            h.insert(HeldPin::new(*cid, *ok))
                .expect("non-empty test cid");
        }
        h
    }

    // P12: the report names what the owner wants but the device lacks.
    #[test]
    fn missing_lists_desired_but_absent() {
        let d = make_desired(&["a", "b", "c"]);
        let h = make_held(&[("a", true)]);
        let r = PinReport::compare(&d, &h);
        assert_eq!(r.missing, vec!["b".to_string(), "c".to_string()]);
        assert!(r.corrupt.is_empty());
    }

    // P12: held pins the owner did not desire are extra, and are listed sorted.
    #[test]
    fn extra_lists_held_but_undesired_sorted() {
        let d = make_desired(&["a"]);
        let h = make_held(&[("z", true), ("a", true), ("m", true)]);
        let r = PinReport::compare(&d, &h);
        assert_eq!(r.extra, vec!["m".to_string(), "z".to_string()]);
        assert_eq!(r.missing, Vec::<String>::new());
    }

    // P12: held CIDs with a failed content hash are corrupt, not missing,
    // and are listed sorted.
    #[test]
    fn corrupt_lists_failed_hashes_sorted() {
        let d = make_desired(&["a", "b"]);
        let h = make_held(&[("b", false), ("a", false)]);
        let r = PinReport::compare(&d, &h);
        assert_eq!(r.corrupt, vec!["a".to_string(), "b".to_string()]);
        assert!(r.missing.is_empty());
        assert!(r.extra.is_empty());
    }

    // P12: an empty desired set lists every held CID as extra; healthy held
    // appear only in extra, corrupt held appear in both extra and corrupt.
    #[test]
    fn empty_desired_lists_all_held_as_extra() {
        let d = make_desired(&[]);
        let h = make_held(&[("x", true), ("y", true), ("bad", false)]);
        let r = PinReport::compare(&d, &h);
        assert_eq!(
            r.extra,
            vec!["bad".to_string(), "x".to_string(), "y".to_string()]
        );
        assert_eq!(r.corrupt, vec!["bad".to_string()]);
        assert!(r.missing.is_empty());
    }

    // P12: a matching device is clean, the report removes nothing, and a
    // clean report with every limit at zero counts zero entries while the
    // held set keeps all its pins.
    #[test]
    fn zero_limits_yield_clean_report_and_hold_all_pins() {
        let d = make_desired(&["a", "b"]);
        let h = make_held(&[("a", true), ("b", true)]);
        let r = PinReport::compare(&d, &h);
        assert!(r.is_clean());
        assert_eq!(r.total(), 0);
        assert!(r.missing.is_empty());
        assert!(r.extra.is_empty());
        assert!(r.corrupt.is_empty());
        assert_eq!(h.len(), 2);
    }

    // P12: a desired-but-corrupt CID is corrupt, not missing, and not extra.
    #[test]
    fn desired_but_corrupt_not_missing() {
        let d = make_desired(&["a", "b"]);
        let h = make_held(&[("a", true), ("b", false)]);
        let r = PinReport::compare(&d, &h);
        assert!(r.missing.is_empty());
        assert!(r.extra.is_empty());
        assert_eq!(r.corrupt, vec!["b".to_string()]);
    }

    // P12: the refusal table returns a stable snake_case code and Display
    // renders `<code>: <explanation>` with no host path.
    #[test]
    fn empty_cid_refused_with_stable_code() {
        let mut d = DesiredPins::new();
        let err = d.insert("").unwrap_err();
        assert_eq!(err.code(), "empty_cid");
        let rendered = format!("{err}");
        assert!(rendered.starts_with("empty_cid: "));
        assert!(!rendered.contains('/'));

        let mut h = HeldPins::new();
        let held_err = h
            .insert(HeldPin::new("", true))
            .expect_err("empty held cid refused");
        assert_eq!(held_err.code(), "empty_cid");
    }
}
