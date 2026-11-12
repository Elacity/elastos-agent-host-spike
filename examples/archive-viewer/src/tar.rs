//! Uncompressed tar (ustar) structure: the 512-byte header walk.
//!
//! tar has no directory: the listing starts at offset 0 and reads one header
//! per entry, then steps over the entry's data by its declared size without
//! reading it. Every byte comes through [`Reader`], so a run stops when the
//! read budget is spent; that stop lists the entries read so far and is
//! marked on the listing, never a trap. The header's checksum, its octal
//! size and the data bound are checked before an entry is listed.
//!
//! Each header is decoded into an [`Entry`] and hands the name, path, kind,
//! status and duplicate rules to [`crate::listing`], the same owner ZIP uses;
//! this module decodes records and defines none of those rules.

use capsule_kit_guest::Refusal;

use crate::listing::{
    archive_name, block_duplicates, entry_status, name_text, Entry, Kind, Listing, Refused, Status,
};
use crate::zip::{object_size, ParseError, ReadError, Reader};
use crate::MAX_ENTRIES;

/// The ustar header and data step.
pub(crate) const BLOCK_BYTES: u64 = 512;
/// The bytes a ustar magic lives in: a detection probe reads no more.
pub(crate) const PROBE_BYTES: u64 = 263;

const NAME: usize = 0;
const NAME_END: usize = 100;
const SIZE: usize = 124;
const SIZE_END: usize = 136;
const CHECKSUM: usize = 148;
const CHECKSUM_END: usize = 156;
const TYPEFLAG: usize = 156;
const MAGIC: usize = 257;
const MAGIC_END: usize = 263;
const PREFIX: usize = 345;
const PREFIX_END: usize = 500;

enum TarError {
    Refused(Refused),
    Refusal(Refusal),
    /// The read budget is spent: the listing stops and is marked.
    Stopped(Refused),
}

impl From<Refused> for TarError {
    fn from(refused: Refused) -> Self {
        TarError::Refused(refused)
    }
}

/// Reads the listing of one tar archive. A refusal of the whole archive is
/// returned inside [`Listing::refused`]; a spent read budget is marked in
/// [`Listing::stopped`]; an authority failure stops the run.
pub fn listing(reader: &mut Reader<'_>) -> Result<Listing, Refusal> {
    match parse(reader) {
        Ok((size, entries, stopped)) => Ok(Listing {
            size,
            entries,
            refused: None,
            stopped,
        }),
        Err(TarError::Refused(refused)) => Ok(Listing {
            size: 0,
            entries: Vec::new(),
            refused: Some(refused),
            stopped: None,
        }),
        Err(TarError::Stopped(reason)) => Ok(Listing {
            size: 0,
            entries: Vec::new(),
            refused: None,
            stopped: Some(reason),
        }),
        Err(TarError::Refusal(refusal)) => Err(refusal),
    }
}

/// Whether these bytes begin with a ustar header. The format dispatch asks
/// this on the object's first block; the checksum is checked in `parse`.
pub(crate) fn is_header(block: &[u8]) -> bool {
    block.len() >= MAGIC_END && &block[MAGIC..MAGIC_END - 1] == b"ustar"
}

/// The bytes of one fixed field, cut at its first NUL.
fn field(block: &[u8], start: usize, end: usize) -> Vec<u8> {
    let bytes = &block[start..end];
    let len = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    bytes[..len].to_vec()
}

/// An octal number: optional leading spaces, octal digits, then NUL or a
/// space ends the field. Any other byte is not a number.
fn octal(bytes: &[u8]) -> Option<u64> {
    let mut value = 0u64;
    let mut digits = false;
    for &byte in bytes {
        match byte {
            b'0'..=b'7' => {
                digits = true;
                value = value.checked_mul(8)?.checked_add(u64::from(byte - b'0'))?;
            }
            b' ' if !digits => continue,
            0 | b' ' => break,
            _ => return None,
        }
    }
    digits.then_some(value)
}

/// The header's checksum, computed with its own field read as spaces.
fn checksum(block: &[u8]) -> u64 {
    block
        .iter()
        .enumerate()
        .map(|(at, &byte)| {
            if (CHECKSUM..CHECKSUM_END).contains(&at) {
                u64::from(b' ')
            } else {
                u64::from(byte)
            }
        })
        .sum()
}

/// A regular file or directory is listable; every other type is P9's
/// non-regular kind. A name that ends like an archive is N1's `archive`.
fn kind_of(typeflag: u8, path: &[u8]) -> Kind {
    match typeflag {
        0 | b'0' => {
            if archive_name(path) {
                Kind::Archive
            } else {
                Kind::File
            }
        }
        b'5' => Kind::Directory,
        _ => Kind::Other,
    }
}

fn make_entry(index: usize, name: Vec<u8>, kind: Kind, size: u64, offset: u64) -> Entry {
    let status = match name_text(&name, 0) {
        Err(reason) => Status::Blocked(reason),
        Ok(path) => entry_status(&path, kind, 0, 0, size, size),
    };
    let path = match name_text(&name, 0) {
        Ok(path) => path,
        Err(_) => format!("<{} bytes, not text>", name.len()),
    };
    Entry {
        index,
        path,
        kind,
        method: 0,
        compressed_size: size,
        uncompressed_size: size,
        status,
        local_offset: offset,
        data_start: offset + BLOCK_BYTES,
        local_end: offset + BLOCK_BYTES + size,
        name_len: 0,
        extra_len: 0,
        flags: 0,
        crc: 0,
        name,
    }
}

/// One block, counted. A spent budget is a marked stop; a short answer is a
/// content failure.
fn read_block(reader: &mut Reader<'_>, offset: u64) -> Result<Vec<u8>, TarError> {
    match reader.read(offset, BLOCK_BYTES) {
        Ok(bytes) => Ok(bytes),
        Err(ReadError::Refusal(refusal)) => Err(TarError::Refusal(refusal)),
        Err(ReadError::Budget) => Err(TarError::Stopped(Refused::new(
            "read_budget",
            "the listing reached the bytes one run may read; entries after the stop are not listed",
        ))),
    }
}

fn size_of(reader: &mut Reader<'_>) -> Result<u64, TarError> {
    match object_size(reader) {
        Ok(size) => Ok(size),
        Err(ParseError::Refused(refused)) => Err(TarError::Refused(refused)),
        Err(ParseError::Refusal(refusal)) => Err(TarError::Refusal(refusal)),
    }
}

/// The entries read so far, ruled by the shared duplicate rule before they are
/// published: a stop is still a listing, and a repeated name in it is a
/// duplicate.
fn stop(size: u64, mut entries: Vec<Entry>, reason: Refused) -> (u64, Vec<Entry>, Option<Refused>) {
    block_duplicates(&mut entries);
    (size, entries, Some(reason))
}

fn parse(reader: &mut Reader<'_>) -> Result<(u64, Vec<Entry>, Option<Refused>), TarError> {
    let size = size_of(reader)?;
    let mut entries = Vec::new();
    let mut offset = 0u64;
    let mut zeros = 0u8;
    while offset < size {
        let block = match read_block(reader, offset) {
            Ok(block) => block,
            Err(TarError::Stopped(reason)) => return Ok(stop(size, entries, reason)),
            Err(error) => return Err(error),
        };
        if block.len() < BLOCK_BYTES as usize {
            return Err(Refused::new(
                "header_truncated",
                format!(
                    "the header at {offset} answers {} of {BLOCK_BYTES} bytes",
                    block.len()
                ),
            )
            .into());
        }
        // The end marker is a pair of zero blocks; any entry after it is not
        // part of the archive.
        if block.iter().all(|&byte| byte == 0) {
            zeros += 1;
            if zeros == 2 {
                break;
            }
            offset += BLOCK_BYTES;
            continue;
        }
        zeros = 0;
        if !is_header(&block) {
            return Err(Refused::new(
                "header_magic",
                format!("the header at {offset} is not ustar"),
            )
            .into());
        }
        let stored = octal(&block[CHECKSUM..CHECKSUM_END]);
        if stored != Some(checksum(&block)) {
            return Err(Refused::new(
                "header_checksum",
                format!("the header at {offset} does not match its checksum"),
            )
            .into());
        }
        let declared = match octal(&block[SIZE..SIZE_END]) {
            Some(size) => size,
            None => {
                return Err(Refused::new(
                    "size_not_octal",
                    format!("the header at {offset} has a size that is not octal"),
                )
                .into())
            }
        };
        let name = field(&block, NAME, NAME_END);
        let prefix = field(&block, PREFIX, PREFIX_END);
        let mut path = Vec::new();
        if !prefix.is_empty() {
            path.extend_from_slice(&prefix);
            path.push(b'/');
        }
        path.extend_from_slice(&name);
        let typeflag = block[TYPEFLAG];
        let end = offset
            .checked_add(BLOCK_BYTES)
            .and_then(|start| start.checked_add(declared));
        let blocks = declared
            .checked_add(BLOCK_BYTES - 1)
            .map(|v| v / BLOCK_BYTES);
        let next = offset.checked_add(BLOCK_BYTES).and_then(|start| {
            blocks
                .and_then(|blocks| blocks.checked_mul(BLOCK_BYTES))
                .and_then(|data| start.checked_add(data))
        });
        let (Some(end), Some(next)) = (end, next) else {
            return Err(Refused::new(
                "entry_outside_object",
                format!("the entry at {offset} declares a size that overflows"),
            )
            .into());
        };
        if end > size || next > size {
            return Err(Refused::new(
                "entry_outside_object",
                format!(
                    "the entry at {offset} declares {declared} bytes, past the object's {size}"
                ),
            )
            .into());
        }
        if entries.len() == MAX_ENTRIES {
            return Err(Refused::new(
                "too_many_entries",
                format!("the archive has more than {MAX_ENTRIES} entries"),
            )
            .into());
        }
        entries.push(make_entry(
            entries.len(),
            path.clone(),
            kind_of(typeflag, &path),
            declared,
            offset,
        ));
        offset = next;
    }
    block_duplicates(&mut entries);
    Ok((size, entries, None))
}
