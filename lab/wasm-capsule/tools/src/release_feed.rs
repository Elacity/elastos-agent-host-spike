// Built-by: deepseek-v4.1-flash-1017-ultrafast
//! The publisher release feed (M3 P2-1, principles P15 and P2).
//!
//! A publisher ships releases under a name. Each release names its version,
//! its bundle CID (as [`crate::bundle_identity`] would print it), its
//! publisher key id, and its `seq`. The feed keeps them in arrival order and
//! refuses any append that would make the feed lie about ordering.
//!
//! P15: a feed entry is the publisher's public claim, so it is written as one
//! canonical line: fixed fields, US (0x1f) separators, no escaping, no
//! trailing newline, so two encoders that agree on the fields produce the
//! same bytes and the line can be signed as-is.
//!
//! P2: the feed holds many names. `append` is monotone per name on `seq` and
//! `version`; `latest` reads the newest release of one name.
//!
//! SEAM: the lab CID check is local to this lab file ([`is_lab_cid`]). The
//! real hash and manifest walk belong to cc-capsule-identity, and this module
//! does not reproduce them. It refuses anything that is not lowercase base32
//! text of a plausible printed length.

use std::collections::BTreeMap;
use std::fmt;

/// Why an entry was refused by [`Feed::append`]. Each rule has its own reason,
/// and the reason string is the exact text refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendRefusal {
    /// `seq` is not greater than the last `seq` of this name.
    SeqNotIncreasing,
    /// `version` is not greater than the last `version` of this name.
    VersionNotIncreasing,
    /// `bundle_cid` is not a lab CID.
    NotALabCid,
}

impl AppendRefusal {
    /// The exact reason string, used by tests and by callers that print.
    pub fn reason(&self) -> &'static str {
        match self {
            AppendRefusal::SeqNotIncreasing => "seq-not-increasing",
            AppendRefusal::VersionNotIncreasing => "version-not-increasing",
            AppendRefusal::NotALabCid => "not-a-lab-cid",
        }
    }
}

impl fmt::Display for AppendRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for AppendRefusal {}

/// The separator between canonical line fields.
pub const FIELD_SEP: u8 = 0x1f;

/// One publisher release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub version: u64,
    pub bundle_cid: String,
    pub publisher_kid: String,
    pub seq: u64,
}

impl Entry {
    /// The canonical line for this entry: `name<V>version<V>bundle_cid<V>
    /// publisher_kid<V>seq`, with `V` = [`FIELD_SEP`]. No trailing newline.
    pub fn canonical_line(&self) -> Vec<u8> {
        let mut line = Vec::new();
        line.extend_from_slice(self.name.as_bytes());
        line.push(FIELD_SEP);
        line.extend_from_slice(self.version.to_string().as_bytes());
        line.push(FIELD_SEP);
        line.extend_from_slice(self.bundle_cid.as_bytes());
        line.push(FIELD_SEP);
        line.extend_from_slice(self.publisher_kid.as_bytes());
        line.push(FIELD_SEP);
        line.extend_from_slice(self.seq.to_string().as_bytes());
        line
    }
}

/// A publisher release feed: entries in arrival order, plus, per name, the
/// last accepted `seq` and `version`.
#[derive(Clone, Debug, Default)]
pub struct Feed {
    entries: Vec<Entry>,
    last: BTreeMap<String, (u64, u64)>,
}

impl Feed {
    /// A new, empty feed.
    pub fn new() -> Feed {
        Feed::default()
    }

    /// Append `entry`, refusing an edit that would break per-name
    /// monotonicity or that names a non-lab CID. On refusal the feed is
    /// unchanged.
    pub fn append(&mut self, entry: Entry) -> Result<(), AppendRefusal> {
        if !is_lab_cid(&entry.bundle_cid) {
            return Err(AppendRefusal::NotALabCid);
        }
        if let Some((last_seq, last_version)) = self.last.get(&entry.name) {
            if entry.seq <= *last_seq {
                return Err(AppendRefusal::SeqNotIncreasing);
            }
            if entry.version <= *last_version {
                return Err(AppendRefusal::VersionNotIncreasing);
            }
        }
        self.last
            .insert(entry.name.clone(), (entry.seq, entry.version));
        self.entries.push(entry);
        Ok(())
    }

    /// The accepted entry with the highest `seq` for `name`, if any.
    pub fn latest(&self, name: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .filter(|entry| entry.name == name)
            .max_by_key(|entry| entry.seq)
    }

    /// Every entry in arrival order, as canonical lines.
    pub fn canonical_lines(&self) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .map(Entry::canonical_line)
            .collect()
    }

    /// The number of accepted entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no entry has been accepted.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// True when `cid` is lab-CID shaped: lowercase base32 letters and digits
/// only, at least 32 bytes and at most 128. SEAM: the real hash is
/// cc-capsule-identity's; this lab file only checks the printed shape it
/// accepts.
pub fn is_lab_cid(cid: &str) -> bool {
    if cid.len() < 32 || cid.len() > 128 {
        return false;
    }
    cid.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(seed: u8) -> String {
        // 52 lowercase base32 characters, shaped like the lane's printed CID.
        let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
        (0..52u8)
            .map(|i| alphabet[(seed.wrapping_add(i) % alphabet.len() as u8) as usize] as char)
            .collect()
    }

    fn entry(name: &str, version: u64, seq: u64, seed: u8) -> Entry {
        Entry {
            name: name.to_string(),
            version,
            bundle_cid: cid(seed),
            publisher_kid: "kid-test".to_string(),
            seq,
        }
    }

    // P15: two names in one feed keep their own order, and the canonical line
    // has exactly the five fields in the documented order.
    #[test]
    fn p15_append_two_names_and_canonical_line() {
        let mut feed = Feed::new();
        feed.append(entry("alpha", 1, 1, 1)).expect("alpha v1");
        feed.append(entry("beta", 1, 1, 2)).expect("beta v1");
        feed.append(entry("alpha", 2, 2, 3)).expect("alpha v2");
        assert_eq!(feed.len(), 3);
        let lines = feed.canonical_lines();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"alpha");
        expected.push(FIELD_SEP);
        expected.extend_from_slice(b"2");
        expected.push(FIELD_SEP);
        expected.extend_from_slice(cid(3).as_bytes());
        expected.push(FIELD_SEP);
        expected.extend_from_slice(b"kid-test");
        expected.push(FIELD_SEP);
        expected.extend_from_slice(b"2");
        assert_eq!(lines[2], expected);
    }

    // P15: `seq` must strictly increase per name; the exact refusal text is
    // "seq-not-increasing", and the feed does not change.
    #[test]
    fn p15_refuses_seq_not_increasing() {
        let mut feed = Feed::new();
        feed.append(entry("alpha", 1, 5, 1)).expect("first");
        let refused = feed.append(entry("alpha", 2, 5, 2));
        assert_eq!(refused, Err(AppendRefusal::SeqNotIncreasing));
        assert_eq!(AppendRefusal::SeqNotIncreasing.to_string(), "seq-not-increasing");
        assert_eq!(feed.len(), 1);
    }

    // P15: `version` must strictly increase per name; the exact refusal text is
    // "version-not-increasing", and the feed does not change.
    #[test]
    fn p15_refuses_version_not_increasing() {
        let mut feed = Feed::new();
        feed.append(entry("alpha", 3, 1, 1)).expect("first");
        let refused = feed.append(entry("alpha", 3, 2, 2));
        assert_eq!(refused, Err(AppendRefusal::VersionNotIncreasing));
        assert_eq!(
            AppendRefusal::VersionNotIncreasing.to_string(),
            "version-not-increasing"
        );
        assert_eq!(feed.len(), 1);
    }

    // P15: a bundle CID that is not lab-CID shaped is refused with the exact
    // text "not-a-lab-cid", and an empty feed stays empty.
    #[test]
    fn p15_refuses_not_a_lab_cid() {
        let mut feed = Feed::new();
        let mut bad = entry("alpha", 1, 1, 1);
        bad.bundle_cid = "NOT-A-CID".to_string();
        let refused = feed.append(bad);
        assert_eq!(refused, Err(AppendRefusal::NotALabCid));
        assert_eq!(AppendRefusal::NotALabCid.to_string(), "not-a-lab-cid");
        assert!(feed.is_empty());
        assert_eq!(feed.len(), 0);
    }

    // P2: `latest` returns the highest-seq entry of one name, ignores other
    // names, and is None for an unknown name.
    #[test]
    fn p2_latest_per_name() {
        let mut feed = Feed::new();
        feed.append(entry("alpha", 1, 1, 1)).expect("alpha v1");
        feed.append(entry("beta", 9, 7, 2)).expect("beta v9");
        feed.append(entry("alpha", 2, 2, 3)).expect("alpha v2");
        assert_eq!(feed.latest("alpha").map(|e| e.version), Some(2));
        assert_eq!(feed.latest("beta").map(|e| e.version), Some(9));
        assert!(feed.latest("gamma").is_none());
    }
}
