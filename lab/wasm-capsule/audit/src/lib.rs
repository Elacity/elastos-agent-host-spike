//! Static lab pre-check skeleton. The audit implementation lands in cwa-001.

pub const AUDIT_API: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredImport {
    pub module: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    Undeclared { module: String, name: String },
    Malformed,
    CodeInCustomSection,
}

#[allow(unused_variables)]
pub fn audit(wasm: &[u8], declared: &[DeclaredImport]) -> Result<Vec<DeclaredImport>, Refusal> {
    unimplemented!("audit implementation lands in cwa-001")
}
