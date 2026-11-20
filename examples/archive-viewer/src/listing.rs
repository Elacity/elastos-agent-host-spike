//! The format-independent listing rules: one owner for the name, path, kind,
//! status and duplicate rules every archive format feeds its entries through.
//!
//! A format reader decodes its records into [`Entry`] values and calls
//! [`block_duplicates`] on the result; the entry's name, kind, method,
//! encryption flag and declared sizes carry every input the rules read. ZIP
//! produces its entries from the central directory here; a second format
//! produces the same shape and gets the same ruling, so there is no second
//! copy of a rule to drift.

use std::collections::HashMap;

use crate::{MAX_NAME_BYTES, MAX_SEGMENTS};

/// A whole-archive refusal: the view names it and lists no entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub code: &'static str,
    pub message: String,
}

impl Refused {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Refused {
            code,
            message: message.into(),
        }
    }
}

/// Why one entry is not listed as safe.
pub type Reason = &'static str;

/// What one entry's record says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub index: usize,
    /// The name as text. Only ever drawn with `textContent` by the page.
    pub path: String,
    pub kind: Kind,
    pub method: u16,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub status: Status,
    pub local_offset: u64,
    /// Where the entry's data starts, from its local header (B4a).
    pub data_start: u64,
    /// Where the entry's whole record ends (B4a).
    pub local_end: u64,
    pub(crate) name_len: u16,
    pub(crate) extra_len: u16,
    pub(crate) flags: u16,
    /// The record's CRC-32, where its format carries one. A tar entry has no
    /// checksum, so its stored bytes are checked by their length alone.
    pub(crate) crc: Option<u32>,
    pub(crate) name: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Archive,
    /// A symlink or any other kind P9 blocks.
    Other,
}

impl Kind {
    pub fn code(&self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Directory => "directory",
            Kind::Archive => "archive",
            Kind::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The record passed every rule and is listed.
    Listed,
    /// The entry is listed with this reason and never read.
    Blocked(Reason),
    /// A method other than stored (0) or deflate (8).
    Unsupported,
    /// Encryption flag bit 0 is set.
    Encrypted,
}

impl Status {
    pub fn code(&self) -> &'static str {
        match self {
            Status::Listed => "listed",
            Status::Blocked(_) => "blocked",
            Status::Unsupported => "unsupported",
            Status::Encrypted => "encrypted",
        }
    }

    pub fn reason(&self) -> Option<Reason> {
        match self {
            Status::Blocked(reason) => Some(reason),
            _ => None,
        }
    }
}

/// The listing one archive gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    /// The object's size, or 0 when the archive was refused.
    pub size: u64,
    pub entries: Vec<Entry>,
    pub refused: Option<Refused>,
    /// Why a listing that walks the object stopped before its end marker:
    /// the entries above are the ones the run read. A tar walk marks a spent
    /// read budget here; ZIP's directory gives its whole listing at once.
    pub stopped: Option<Refused>,
}

/// The suffixes that name a nested archive (N1). The entry is listed as
/// `archive` and never opened.
pub(crate) fn archive_name(name: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    [".zip", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".zst"]
        .iter()
        .any(|suffix| lower.ends_with(suffix.as_bytes()))
}

/// P4: a marked name is UTF-8; an unmarked one must be printable ASCII.
pub(crate) fn name_text(name: &[u8], flags: u16) -> Result<String, Reason> {
    if flags & (1 << 11) != 0 {
        std::str::from_utf8(name)
            .map(str::to_string)
            .map_err(|_| "not_utf8")
    } else if name.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        Ok(String::from_utf8_lossy(name).into_owned())
    } else {
        Err("not_ascii")
    }
}

/// The status of one decoded entry: its name rules (P1 to P4, P8), its kind
/// (P9), a directory's declared data (L9), encryption and method.
pub(crate) fn entry_status(
    path: &str,
    kind: Kind,
    flags: u16,
    method: u16,
    uncompressed_size: u64,
    compressed_size: u64,
) -> Status {
    if let Err(reason) = path_rules(path, kind) {
        return Status::Blocked(reason);
    }
    if kind == Kind::Other {
        return Status::Blocked("unsupported_kind");
    }
    if kind == Kind::Directory && (uncompressed_size != 0 || compressed_size != 0) {
        return Status::Blocked("directory_with_data");
    }
    if flags & 1 != 0 {
        return Status::Encrypted;
    }
    if method != 0 && method != 8 {
        return Status::Unsupported;
    }
    Status::Listed
}

/// The name rules P1 to P4 and P8. The name is text for the page; it is never
/// a path here.
fn path_rules(path: &str, kind: Kind) -> Result<(), Reason> {
    let bytes = path.as_bytes();
    if bytes.first() == Some(&b'/') {
        return Err("absolute_name");
    }
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err("absolute_name");
    }
    if path.contains('\\') {
        return Err("backslash");
    }
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
    {
        return Err("control_character");
    }
    if path.len() > MAX_NAME_BYTES {
        return Err("name_too_long");
    }
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    // A directory's permitted trailing slash is not another segment.
    if trimmed.split('/').count() > MAX_SEGMENTS {
        return Err("name_too_long");
    }
    if trimmed.is_empty() && kind == Kind::Directory {
        return Err("dot_segment");
    }
    if trimmed
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("dot_segment");
    }
    if path.ends_with('/') && kind != Kind::Directory {
        return Err("dot_segment");
    }
    Ok(())
}

/// Why a listed entry is not shown, from its own status. Every format that
/// shows an entry reads this one map, so a blocked, unsupported or encrypted
/// entry keeps its reason whichever record decoded it.
pub(crate) fn shown_status(status: Status) -> Result<(), Reason> {
    match status {
        Status::Listed => Ok(()),
        Status::Blocked(reason) => Err(reason),
        Status::Unsupported => Err("unsupported"),
        Status::Encrypted => Err("encrypted"),
    }
}

/// P5: two entries with one name are both blocked, whichever comes first.
pub(crate) fn block_duplicates(entries: &mut [Entry]) {
    let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();
    for entry in entries.iter() {
        *seen.entry(entry.name.clone()).or_insert(0) += 1;
    }
    for entry in entries.iter_mut() {
        if seen.get(&entry.name).copied().unwrap_or(0) > 1
            && matches!(
                entry.status,
                Status::Listed | Status::Unsupported | Status::Encrypted
            )
        {
            entry.status = Status::Blocked("duplicate");
        }
    }
}
