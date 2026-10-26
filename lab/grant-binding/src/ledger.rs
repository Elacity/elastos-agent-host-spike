//! The ledger stub.
//!
//! `Ledger::new()` exists so later slices fill this one store instead of
//! keeping a second record of the same grants.

/// The one ledger the verifier owns.
#[derive(Debug, Default)]
pub struct Ledger {}

impl Ledger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self {}
    }
}
