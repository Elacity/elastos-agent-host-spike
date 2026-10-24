//! ZIP structure: the end record, the central directory, and the checks that
//! a directory which lies cannot pass.
//!
//! The guest never reads the whole archive. It finds the object's size with
//! one-byte probes (a read answer carries the size of its slice, not of the
//! object), reads the last 22 + 1,024 bytes, then the directory, then a
//! 30-byte local-header prefix for every entry (B4a). Every byte comes through
//! [`Reader`], which counts each read against the run's budget the moment it
//! returns, and keeps an authority failure apart from a content one.
//!
//! Only what this first slice needs is here: no inflate, no preview and no
//! nested archive opened. Names get the P1 to P9 statuses; the records get L1
//! to L4, B4 and L5.

use std::collections::HashMap;

use capsule_kit_guest::{read_counted, Bus, Refusal};

use crate::{
    MAX_ARCHIVE_BYTES, MAX_COMMENT_BYTES, MAX_DIRECTORY_BYTES, MAX_ENTRIES, MAX_LOCAL_HEADER_BYTES,
    MAX_NAME_BYTES, MAX_SEGMENTS,
};

const END_RECORD_BYTES: u64 = 22;
const END_SIGNATURE: u32 = 0x0605_4b50;
const DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const DIRECTORY_RECORD_BYTES: u64 = 46;
const LOCAL_HEADER_BYTES: u64 = 30;

/// A whole-archive refusal: the view names it and lists no entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub code: &'static str,
    pub message: String,
}

impl Refused {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
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
    name_len: u16,
    extra_len: u16,
    flags: u16,
    crc: u32,
    name: Vec<u8>,
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
}

/// The counted read window over one object.
///
/// A read asks for no more than the run may still read, and takes what came
/// back off the budget at once. An authority failure is returned as
/// [`ReadError::Refusal`] and stops the run; a spent budget is
/// [`ReadError::Budget`], a content failure of the listing.
pub struct Reader<'a> {
    bus: &'a mut dyn Bus,
    uri: &'a str,
    grant: &'a str,
    left: &'a mut u64,
}

#[derive(Debug)]
pub enum ReadError {
    Refusal(Refusal),
    Budget,
}

impl<'a> Reader<'a> {
    pub fn new(bus: &'a mut dyn Bus, uri: &'a str, grant: &'a str, left: &'a mut u64) -> Self {
        Reader {
            bus,
            uri,
            grant,
            left,
        }
    }

    /// Reads at most `length` bytes at `offset`. Never asks for more than is
    /// left: a read past the budget is a content failure, not a trap.
    pub fn read(&mut self, offset: u64, length: u64) -> Result<Vec<u8>, ReadError> {
        // An empty directory is read as no bytes, not as a spent budget.
        if length == 0 {
            return Ok(Vec::new());
        }
        if length > *self.left {
            return Err(ReadError::Budget);
        }
        read_counted(self.bus, self.uri, self.grant, self.left, offset, length)
            .map_err(ReadError::Refusal)
    }
}

/// Reads the listing of one archive. A refusal of the whole archive is
/// returned inside [`Listing::refused`]; an authority failure stops the run
/// with its [`Refusal`].
pub fn listing(reader: &mut Reader<'_>) -> Result<Listing, Refusal> {
    match parse(reader) {
        Ok((size, entries)) => Ok(Listing {
            size,
            entries,
            refused: None,
        }),
        Err(ParseError::Refused(refused)) => Ok(Listing {
            size: 0,
            entries: Vec::new(),
            refused: Some(refused),
        }),
        Err(ParseError::Refusal(refusal)) => Err(refusal),
    }
}

enum ParseError {
    Refused(Refused),
    Refusal(Refusal),
}

impl From<Refused> for ParseError {
    fn from(refused: Refused) -> Self {
        ParseError::Refused(refused)
    }
}

fn read(reader: &mut Reader<'_>, offset: u64, length: u64) -> Result<Vec<u8>, ParseError> {
    match reader.read(offset, length) {
        Ok(bytes) => Ok(bytes),
        Err(ReadError::Refusal(refusal)) => Err(ParseError::Refusal(refusal)),
        Err(ReadError::Budget) => Err(Refused::new(
            "read_budget",
            "the listing would read more bytes than one run may",
        )
        .into()),
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// The object's size, found with one-byte probes.
fn object_size(reader: &mut Reader<'_>) -> Result<u64, ParseError> {
    let mut low = 0u64;
    let mut high = MAX_ARCHIVE_BYTES + 1;
    while low < high {
        let middle = low + (high - low) / 2;
        if read(reader, middle, 1)?.is_empty() {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    // The search stops at 2^32. An object at or past that boundary would be
    // reported as exactly 2^32 bytes, so an end record there would look like
    // the real end of a larger object; refuse instead.
    if low > MAX_ARCHIVE_BYTES {
        return Err(Refused::new(
            "object_too_large",
            format!("the object is larger than {MAX_ARCHIVE_BYTES} bytes"),
        )
        .into());
    }
    Ok(low)
}

/// The end record (L1), its directory bounds (L2), counts (L3), records (L4)
/// and the local-header prefix of every entry (B4a).
fn parse(reader: &mut Reader<'_>) -> Result<(u64, Vec<Entry>), ParseError> {
    let size = object_size(reader)?;
    if size < END_RECORD_BYTES {
        return Err(Refused::new("end_record_missing", "the object is too short").into());
    }
    let tail_start = size.saturating_sub(END_RECORD_BYTES + MAX_COMMENT_BYTES);
    let tail = read(reader, tail_start, size - tail_start)?;
    let mut candidates = Vec::new();
    for at in 0..tail.len().saturating_sub(END_RECORD_BYTES as usize - 1) {
        if u32_at(&tail, at) != Some(END_SIGNATURE) {
            continue;
        }
        let comment = u16_at(&tail, at + 20).unwrap_or(0);
        let end = tail_start + at as u64 + END_RECORD_BYTES + u64::from(comment);
        if end == size {
            candidates.push(at);
        }
    }
    match candidates.len() {
        1 => {}
        0 => {
            return Err(Refused::new(
                "end_record_missing",
                format!(
                    "no end record ends at the object's last byte; a comment longer than \
                     {MAX_COMMENT_BYTES} bytes is refused"
                ),
            )
            .into())
        }
        count => {
            return Err(Refused::new(
                "ambiguous_end",
                format!("{count} end records end at the object's last byte"),
            )
            .into())
        }
    }
    let at = candidates[0];
    let end_offset = tail_start + at as u64;

    let disk = u16_at(&tail, at + 4).unwrap_or(0);
    let directory_disk = u16_at(&tail, at + 6).unwrap_or(0);
    let on_disk = u16_at(&tail, at + 8).unwrap_or(0);
    let count = u16_at(&tail, at + 10).unwrap_or(0);
    let directory_size = u64::from(u32_at(&tail, at + 12).unwrap_or(0));
    let directory_offset = u64::from(u32_at(&tail, at + 16).unwrap_or(0));

    if disk != 0 || directory_disk != 0 {
        return Err(Refused::new("multi_disk", "the archive spans more than one disk").into());
    }
    if count == u16::MAX
        || on_disk == u16::MAX
        || directory_offset == u64::from(u32::MAX)
        || directory_size == u64::from(u32::MAX)
    {
        return Err(Refused::new("zip64", "zip64 archives are not supported").into());
    }
    if directory_offset > end_offset {
        return Err(Refused::new(
            "directory_outside_object",
            "the directory starts past the end record",
        )
        .into());
    }
    if directory_size > MAX_DIRECTORY_BYTES {
        return Err(Refused::new(
            "directory_too_large",
            format!("the directory is {directory_size} bytes, the limit is {MAX_DIRECTORY_BYTES}"),
        )
        .into());
    }
    if directory_offset + directory_size != end_offset {
        return Err(Refused::new(
            "directory_not_at_end_record",
            "the directory does not end where the end record begins",
        )
        .into());
    }
    if on_disk != count {
        return Err(Refused::new(
            "count_mismatch",
            format!("the end record says {count} entries and {on_disk} on this disk"),
        )
        .into());
    }
    if usize::from(count) > MAX_ENTRIES {
        return Err(Refused::new(
            "too_many_entries",
            format!("the archive has {count} entries, the limit is {MAX_ENTRIES}"),
        )
        .into());
    }

    let directory = read(reader, directory_offset, directory_size)?;
    // A provider that answers short must not make the parser index past the
    // bytes it holds. The end record says the directory is `directory_size`
    // bytes and L2 proved that range inside the object, so a short answer is
    // a content failure.
    if directory.len() as u64 != directory_size {
        return Err(Refused::new(
            "directory_truncated",
            format!(
                "the directory answered {} of {directory_size} bytes",
                directory.len()
            ),
        )
        .into());
    }
    let mut entries = parse_directory(&directory, directory_size)?;
    if entries.len() != usize::from(count) {
        return Err(Refused::new(
            "count_mismatch",
            format!(
                "the end record says {count} entries, the directory has {}",
                entries.len()
            ),
        )
        .into());
    }
    block_duplicates(&mut entries);
    check_local_headers(reader, &mut entries, directory_offset)?;
    Ok((size, entries))
}

fn parse_directory(directory: &[u8], directory_size: u64) -> Result<Vec<Entry>, ParseError> {
    let end = directory_size as usize;
    let mut entries = Vec::new();
    let mut at = 0usize;
    while at < end {
        if end - at < DIRECTORY_RECORD_BYTES as usize {
            return Err(
                Refused::new("record_too_long", "a record does not fit the directory").into(),
            );
        }
        if u32_at(directory, at) != Some(DIRECTORY_SIGNATURE) {
            return Err(Refused::new("record_signature", "a record has no signature").into());
        }
        let flags = u16_at(directory, at + 8).unwrap_or(0);
        let method = u16_at(directory, at + 10).unwrap_or(0);
        let crc = u32_at(directory, at + 16).unwrap_or(0);
        let compressed = u64::from(u32_at(directory, at + 20).unwrap_or(0));
        let uncompressed = u64::from(u32_at(directory, at + 24).unwrap_or(0));
        let name_len = u16_at(directory, at + 28).unwrap_or(0);
        let extra_len = u16_at(directory, at + 30).unwrap_or(0);
        let comment_len = u16_at(directory, at + 32).unwrap_or(0);
        let start_disk = u16_at(directory, at + 34).unwrap_or(0);
        let external = u32_at(directory, at + 38).unwrap_or(0);
        let local = u64::from(u32_at(directory, at + 42).unwrap_or(0));
        let record = DIRECTORY_RECORD_BYTES as usize
            + usize::from(name_len)
            + usize::from(extra_len)
            + usize::from(comment_len);
        let Some(next) = at.checked_add(record) else {
            return Err(Refused::new("record_too_long", "a record length overflows").into());
        };
        if next > end {
            return Err(Refused::new("record_too_long", "a record runs past the directory").into());
        }
        if start_disk != 0 {
            return Err(Refused::new("multi_disk", "an entry is on another disk").into());
        }
        if compressed == u64::from(u32::MAX)
            || uncompressed == u64::from(u32::MAX)
            || local == u64::from(u32::MAX)
        {
            return Err(Refused::new("zip64", "zip64 entries are not supported").into());
        }
        let name_start = at + DIRECTORY_RECORD_BYTES as usize;
        let name = directory[name_start..name_start + usize::from(name_len)].to_vec();
        entries.push(make_entry(
            entries.len(),
            name,
            flags,
            method,
            crc,
            compressed,
            uncompressed,
            external,
            local,
            name_len,
            extra_len,
        ));
        at = next;
    }
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn make_entry(
    index: usize,
    name: Vec<u8>,
    flags: u16,
    method: u16,
    crc: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    external: u32,
    local_offset: u64,
    name_len: u16,
    extra_len: u16,
) -> Entry {
    let kind = kind_of(&name, external);
    let empty = Entry {
        index,
        path: String::new(),
        kind,
        method,
        compressed_size,
        uncompressed_size,
        status: Status::Blocked("not_utf8"),
        local_offset,
        data_start: 0,
        local_end: 0,
        name_len,
        extra_len,
        flags,
        crc,
        name: name.clone(),
    };
    let status = match name_text(&name, flags) {
        Err(reason) => Status::Blocked(reason),
        Ok(path) => entry_status(
            &path,
            kind,
            flags,
            method,
            uncompressed_size,
            compressed_size,
        ),
    };
    let path = match name_text(&name, flags) {
        Ok(path) => path,
        Err(_) => format!("<{} bytes, not text>", name.len()),
    };
    Entry {
        path,
        status,
        ..empty
    }
}

fn kind_of(name: &[u8], external: u32) -> Kind {
    let unix = (external >> 16) & 0o170000;
    // P9: only a regular file (or an unset DOS attribute) and a directory are
    // listed as such. A symlink, device, socket or any other kind is not.
    let other = !matches!(unix, 0 | 0o100000 | 0o040000);
    if other {
        return Kind::Other;
    }
    if name.ends_with(b"/") || unix == 0o040000 {
        return Kind::Directory;
    }
    if archive_name(name) {
        return Kind::Archive;
    }
    Kind::File
}

fn archive_name(name: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    [".zip", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".zst"]
        .iter()
        .any(|suffix| lower.ends_with(suffix.as_bytes()))
}

fn name_text(name: &[u8], flags: u16) -> Result<String, Reason> {
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

fn entry_status(
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

/// P5: two entries with one name are both blocked, whichever comes first.
fn block_duplicates(entries: &mut [Entry]) {
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

/// B4a: read the 30-byte local header of every entry, place the entry's whole
/// record `[local_offset, end)`, and refuse an archive whose records overlap.
fn check_local_headers(
    reader: &mut Reader<'_>,
    entries: &mut [Entry],
    directory_offset: u64,
) -> Result<(), ParseError> {
    for entry in entries.iter_mut() {
        let header = read(reader, entry.local_offset, LOCAL_HEADER_BYTES)?;
        if header.len() < LOCAL_HEADER_BYTES as usize {
            return Err(Refused::new(
                "local_header_outside_object",
                "an entry's local header is not inside the object",
            )
            .into());
        }
        if u32_at(&header, 0) != Some(LOCAL_SIGNATURE) {
            return Err(Refused::new(
                "local_header_signature",
                "an entry's local header has no signature",
            )
            .into());
        }
        let name_len = u16_at(&header, 26).unwrap_or(0);
        let extra_len = u16_at(&header, 28).unwrap_or(0);
        let data = entry
            .local_offset
            .checked_add(LOCAL_HEADER_BYTES + u64::from(name_len) + u64::from(extra_len));
        let Some(data) = data else {
            return Err(Refused::new(
                "local_header_outside_object",
                "an entry's data start overflows",
            )
            .into());
        };
        let Some(end) = data.checked_add(entry.compressed_size) else {
            return Err(
                Refused::new("local_header_outside_object", "an entry's end overflows").into(),
            );
        };
        if end > directory_offset {
            return Err(Refused::new(
                "entry_outside_directory",
                "an entry's record runs into or past the directory",
            )
            .into());
        }
        entry.data_start = data;
        entry.name_len = name_len;
        entry.extra_len = extra_len;
        // The record may not need the whole 30 bytes read again: keep what
        // places it, and let L5 read the name separately.
        entry.local_end = end;
    }
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|index| entries[*index].local_offset);
    for pair in order.windows(2) {
        let (first, second) = (&entries[pair[0]], &entries[pair[1]]);
        if second.local_offset < first.local_end {
            return Err(Refused::new(
                "overlapping_entries",
                format!(
                    "entries {} and {} share their records",
                    first.index, second.index
                ),
            )
            .into());
        }
    }
    Ok(())
}

/// L5: before an entry is shown, its local header must agree with the record
/// and with the lengths B4a used. A mismatch skips that entry, never the
/// archive.
pub fn check_shown(reader: &mut Reader<'_>, entry: &Entry) -> Result<Result<(), Reason>, Refusal> {
    // An entry that is not listed keeps its own status as the skip reason, so
    // the page never has to guess why the request named an entry it cannot
    // show.
    match entry.status {
        Status::Listed => {}
        Status::Blocked(reason) => return Ok(Err(reason)),
        Status::Unsupported => return Ok(Err("unsupported")),
        Status::Encrypted => return Ok(Err("encrypted")),
    }
    let length = LOCAL_HEADER_BYTES + u64::from(entry.name_len);
    if length > MAX_LOCAL_HEADER_BYTES {
        return Ok(Err("local_header_too_long"));
    }
    let header = match reader.read(entry.local_offset, length) {
        Ok(header) => header,
        Err(ReadError::Refusal(refusal)) => return Err(refusal),
        Err(ReadError::Budget) => return Ok(Err("read_budget")),
    };
    if header.len() as u64 != length {
        return Ok(Err("local_header_outside_object"));
    }
    Ok(check_local_header(entry, &header))
}

/// The comparison L5 makes, on the bytes read for one entry.
pub fn check_local_header(entry: &Entry, header: &[u8]) -> Result<(), Reason> {
    if u32_at(header, 0) != Some(LOCAL_SIGNATURE) {
        return Err("local_header_signature");
    }
    let name_len = u16_at(header, 26).unwrap_or(0);
    let extra_len = u16_at(header, 28).unwrap_or(0);
    if name_len != entry.name_len || extra_len != entry.extra_len {
        return Err("local_header_lengths");
    }
    let Some(name) = header.get(LOCAL_HEADER_BYTES as usize..) else {
        return Err("local_header_lengths");
    };
    if name != entry.name.as_slice() {
        return Err("local_header_name");
    }
    let flags = u16_at(header, 6).unwrap_or(0);
    if flags & !(1 << 3) != entry.flags & !(1 << 3) {
        return Err("local_header_flags");
    }
    if u16_at(header, 8) != Some(entry.method) {
        return Err("local_header_method");
    }
    if entry.flags & (1 << 3) == 0 {
        if u32_at(header, 14) != Some(entry.crc) {
            return Err("local_header_crc");
        }
        let local_compressed = u64::from(u32_at(header, 18).unwrap_or(0));
        let local_uncompressed = u64::from(u32_at(header, 22).unwrap_or(0));
        if local_compressed != entry.compressed_size
            || local_uncompressed != entry.uncompressed_size
        {
            return Err("local_header_sizes");
        }
    }
    Ok(())
}
