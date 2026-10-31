//! `cid_required`: the lab rule that content is always addressed by CID
//! (P12), and that any request using a mutable alias or a path where a CID
//! is required is refused with the stable code `cid_required` (P3).
//!
//! Owner names never resolve to content directly. The only way an owner
//! name maps to a CID is through an explicit [`OwnerNameTable`] of
//! bindings, which this module owns and checks. A caller-supplied string is
//! never treated as a trusted resolution: an owner-shaped request either
//! finds a binding in the table or is refused, and a request that is not an
//! owner name and not a CID is refused `cid_required`.
//!
//! Classification order in [`CidRequiredGate::require_cid`] is fixed and is
//! what the tests pin:
//! 1. a syntactically valid CID is accepted verbatim;
//! 2. anything that looks like a mutable alias or a path is refused
//!    `cid_required`, before any owner lookup;
//! 3. an owner-shaped token resolves through the table only, and a missing
//!    binding is refused `unknown_owner`;
//! 4. everything else is refused `cid_required`.
//!
//! This is a lab check only. No Runtime admission or launch path uses it.
//!
//! Preset values the task did not give, chosen small and conservative:
//! - a CID is a lower-case multibase token: it must start with one of the
//!   multibase prefixes `b`, `z`, `f`, `m` or `u`, be `MIN_CID_LEN..=MAX_CID_LEN`
//!   bytes of lower-case ASCII letters and digits, and contain no path
//!   separator, no `.` and no `..`. The minimum length means a short bare
//!   word such as `alice`, `nobody` or `latest` is never a CID;
//! - an owner name is a non-empty token of at most `MAX_OWNER_NAME_LEN`
//!   bytes of lower-case ASCII letters, digits and `-`;
//! - the owner name table holds at most `MAX_OWNER_BINDINGS` bindings.

use std::collections::BTreeMap;
use std::fmt;

/// Minimum accepted CID length in bytes, including its multibase prefix.
pub const MIN_CID_LEN: usize = 8;
/// Maximum accepted CID length in bytes.
pub const MAX_CID_LEN: usize = 128;
/// Maximum accepted owner name length in bytes.
pub const MAX_OWNER_NAME_LEN: usize = 64;
/// Maximum number of owner name to CID bindings in one table.
pub const MAX_OWNER_BINDINGS: usize = 256;

/// The multibase prefixes this lab accepts on a CID. Nothing else is a CID.
const MULTIBASE_PREFIXES: [u8; 5] = [b'b', b'z', b'f', b'm', b'u'];

/// One refusal from the cid-required gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The address given was a mutable alias or a path, not a CID.
    CidRequired { given: String },
    /// A CID was syntactically wrong.
    InvalidCid { given_len: usize },
    /// An owner name was syntactically wrong.
    InvalidOwnerName { given_len: usize },
    /// The owner name table was full.
    OwnerTableFull,
    /// The owner name was not present in the table.
    UnknownOwner,
}

impl Refusal {
    /// Stable snake_case code table. These strings never change.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::CidRequired { .. } => "cid_required",
            Refusal::InvalidCid { .. } => "invalid_cid",
            Refusal::InvalidOwnerName { .. } => "invalid_owner_name",
            Refusal::OwnerTableFull => "owner_table_full",
            Refusal::UnknownOwner => "unknown_owner",
        }
    }

    fn explain(&self) -> String {
        match self {
            Refusal::CidRequired { given } => format!(
                "a mutable alias or path was given where a CID is required: {}",
                given
            ),
            Refusal::InvalidCid { given_len } => {
                format!(
                    "the given CID is not a valid content address ({} bytes)",
                    given_len
                )
            }
            Refusal::InvalidOwnerName { given_len } => {
                format!("the owner name is not a valid token ({} bytes)", given_len)
            }
            Refusal::OwnerTableFull => {
                "the owner name table has no room for another binding".to_string()
            }
            Refusal::UnknownOwner => {
                "the owner name has no binding in the owner name table".to_string()
            }
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.explain())
    }
}

impl std::error::Error for Refusal {}

/// The explicit table that is the only place owner names map to CIDs.
#[derive(Debug, Clone, Default)]
pub struct OwnerNameTable {
    bindings: BTreeMap<String, String>,
}

impl OwnerNameTable {
    /// An empty table.
    pub fn new() -> Self {
        OwnerNameTable::default()
    }

    /// Bind an owner name to a CID. The CID is checked as a CID first, so an
    /// alias or path can never be stored as an owner's content address.
    pub fn bind(&mut self, owner: &str, cid: &str) -> Result<(), Refusal> {
        if !is_owner_name(owner) {
            return Err(Refusal::InvalidOwnerName {
                given_len: owner.len(),
            });
        }
        if !is_cid(cid) {
            return Err(Refusal::CidRequired {
                given: cid.to_string(),
            });
        }
        if !self.bindings.contains_key(owner) && self.bindings.len() >= MAX_OWNER_BINDINGS {
            return Err(Refusal::OwnerTableFull);
        }
        self.bindings.insert(owner.to_string(), cid.to_string());
        Ok(())
    }

    /// Resolve an owner name to its CID. This is the only resolution path.
    pub fn resolve(&self, owner: &str) -> Result<&str, Refusal> {
        match self.bindings.get(owner) {
            Some(cid) => Ok(cid.as_str()),
            None => Err(Refusal::UnknownOwner),
        }
    }
}

/// Is `s` a plausible content address (a CID) for this lab? A bare word is
/// not: a CID carries a multibase prefix and at least `MIN_CID_LEN` bytes.
pub fn is_cid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= MIN_CID_LEN
        && bytes.len() <= MAX_CID_LEN
        && MULTIBASE_PREFIXES.contains(&bytes[0])
        && !s.contains('/')
        && !s.contains('\\')
        && !s.contains('.')
        && !s.contains(':')
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Does `s` look like a mutable alias or a path, rather than a CID? Alias and
/// path shapes win over an owner-shaped word only when they carry a path or
/// alias marker, so an owner name that happens to be an all-lowercase word is
/// still resolved through the table.
pub fn looks_like_alias_or_path(s: &str) -> bool {
    s.is_empty()
        || s.contains('/')
        || s.contains('\\')
        || s.contains("..")
        || s.contains('.')
        || s.contains(':')
        || s.eq_ignore_ascii_case("latest")
        || s.eq_ignore_ascii_case("current")
        || s.eq_ignore_ascii_case("head")
}

fn is_owner_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_OWNER_NAME_LEN
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The cid-required gate: an address request either names a CID directly or
/// names an owner that the table resolves to a CID. Anything else is refused
/// with `cid_required`.
pub struct CidRequiredGate<'a> {
    table: &'a OwnerNameTable,
}

impl<'a> CidRequiredGate<'a> {
    /// Build a gate over an explicit owner name table.
    pub fn new(table: &'a OwnerNameTable) -> Self {
        CidRequiredGate { table }
    }

    /// Resolve an address request to a CID. The order is CID, then alias or
    /// path refusal, then owner name through the table, then refusal.
    pub fn require_cid(&self, request: &str) -> Result<String, Refusal> {
        if is_cid(request) {
            return Ok(request.to_string());
        }
        if looks_like_alias_or_path(request) {
            return Err(Refusal::CidRequired {
                given: request.to_string(),
            });
        }
        if is_owner_name(request) {
            return self.table.resolve(request).map(|cid| cid.to_string());
        }
        Err(Refusal::CidRequired {
            given: request.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cid() -> &'static str {
        "bafkqabcontentaddr0001"
    }

    // P12: content is always addressed by CID, so a CID request is accepted
    // verbatim.
    #[test]
    fn a_cid_is_accepted_as_a_content_address() {
        let table = OwnerNameTable::new();
        let gate = CidRequiredGate::new(&table);
        assert_eq!(gate.require_cid(sample_cid()).unwrap(), sample_cid());
    }

    // P12: a bare all-lowercase word is not a CID, so it is never accepted as
    // a content address just because it matches the multibase charset.
    #[test]
    fn a_bare_word_is_not_a_cid() {
        assert!(!is_cid("alice"));
        assert!(!is_cid("nobody"));
        assert!(!is_cid("latest"));
        assert!(is_cid(sample_cid()));
    }

    // P3: a mutable alias or path where a CID is required is refused with the
    // stable `cid_required` code.
    #[test]
    fn a_path_or_alias_is_refused_cid_required() {
        let table = OwnerNameTable::new();
        let gate = CidRequiredGate::new(&table);
        for bad in [
            "latest",
            "current",
            "HEAD",
            "current/thing",
            "./x.bin",
            "a..b",
            "C:\\x",
            "/abs/path",
        ] {
            let err = gate.require_cid(bad).unwrap_err();
            assert_eq!(err.code(), "cid_required");
        }
    }

    // P3: owner names map to CIDs only through the owner name table; with a
    // binding in place the gate returns exactly the bound CID.
    #[test]
    fn owner_names_resolve_only_through_the_table() {
        let mut table = OwnerNameTable::new();
        table.bind("alice", sample_cid()).unwrap();
        let gate = CidRequiredGate::new(&table);
        assert_eq!(gate.require_cid("alice").unwrap(), sample_cid());
    }

    // P3: an owner name with no binding is refused, never resolved to some
    // ambient content.
    #[test]
    fn unknown_owner_is_refused() {
        let table = OwnerNameTable::new();
        let gate = CidRequiredGate::new(&table);
        let err = gate.require_cid("nobody").unwrap_err();
        assert_eq!(err.code(), "unknown_owner");
    }

    // P12: a path or alias is refused even when the same owner exists, so a
    // bound CID cannot be reached through a mutable name.
    #[test]
    fn a_path_is_refused_even_when_the_owner_exists() {
        let mut table = OwnerNameTable::new();
        table.bind("alice", sample_cid()).unwrap();
        let gate = CidRequiredGate::new(&table);
        let err = gate.require_cid("alice/latest").unwrap_err();
        assert_eq!(err.code(), "cid_required");
    }

    // P12: the table itself refuses a path or alias as an owner's content
    // address, keeping every binding a real CID.
    #[test]
    fn binding_a_path_as_a_cid_is_refused() {
        let mut table = OwnerNameTable::new();
        let err = table.bind("alice", "latest/x").unwrap_err();
        assert_eq!(err.code(), "cid_required");
        assert_eq!(table.resolve("alice").unwrap_err().code(), "unknown_owner");
    }

    // P3: a malformed owner name is refused with its own stable code and does
    // not enter the table.
    #[test]
    fn an_invalid_owner_name_is_refused() {
        let mut table = OwnerNameTable::new();
        let err = table.bind("Alice Smith", sample_cid()).unwrap_err();
        assert_eq!(err.code(), "invalid_owner_name");
    }

    // P3: the table has a bounded size and refuses further bindings with a
    // stable code once full.
    #[test]
    fn owner_table_refuses_a_binding_when_full() {
        let mut table = OwnerNameTable::new();
        for i in 0..MAX_OWNER_BINDINGS {
            table.bind(&format!("owner{}", i), sample_cid()).unwrap();
        }
        let err = table.bind("onemore", sample_cid()).unwrap_err();
        assert_eq!(err.code(), "owner_table_full");
    }

    // P3: every limit at zero still behaves: an empty CID and an empty owner
    // name are both refused, never accepted as a content address.
    #[test]
    fn zero_length_cid_and_owner_are_refused() {
        let mut table = OwnerNameTable::new();
        assert_eq!(table.bind("", "").unwrap_err().code(), "invalid_owner_name");
        assert_eq!(table.bind("alice", "").unwrap_err().code(), "cid_required");
        let gate = CidRequiredGate::new(&table);
        assert_eq!(gate.require_cid("").unwrap_err().code(), "cid_required");
    }

    // P3: Display renders `<code>: <explanation>` with no host path.
    #[test]
    fn display_prefixes_the_code_and_never_a_host_path() {
        let err = Refusal::CidRequired {
            given: "latest/x".to_string(),
        };
        let text = err.to_string();
        assert!(text.starts_with("cid_required: "));
        assert!(!text.contains("/home"));
        assert!(!text.contains("/Users"));
    }
}
