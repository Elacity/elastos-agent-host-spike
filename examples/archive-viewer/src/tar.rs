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
/// The bytes a ustar magic and its version live in: a detection probe reads
/// no more.
pub(crate) const PROBE_BYTES: u64 = 265;

const NAME: usize = 0;
const NAME_END: usize = 100;
const SIZE: usize = 124;
const SIZE_END: usize = 136;
const CHECKSUM: usize = 148;
const CHECKSUM_END: usize = 156;
const TYPEFLAG: usize = 156;
const MAGIC: usize = 257;
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

/// Whether these bytes begin with a ustar header: the magic is exactly
/// `ustar`, then NUL, then version `00`. Anything else is another format.
/// The format dispatch asks this on the object's first block; the checksum
/// is checked in `parse`.
pub(crate) fn is_header(block: &[u8]) -> bool {
    let magic = block.len() >= PROBE_BYTES as usize
        && &block[MAGIC..MAGIC + 5] == b"ustar"
        && block[MAGIC + 5] == 0;
    let version = block.len() >= PROBE_BYTES as usize && &block[MAGIC + 6..MAGIC + 8] == b"00";
    magic && version
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

/// An octal number: optional leading spaces, one or more octal digits, then
/// only NUL or space padding to the end of the field. Any other byte is not a
/// number, and a field with no digits is not one either.
fn octal(bytes: &[u8]) -> Option<u64> {
    let mut value = 0u64;
    let mut at = 0usize;
    while at < bytes.len() && bytes[at] == b' ' {
        at += 1;
    }
    let first_digit = at;
    while at < bytes.len() && matches!(bytes[at], b'0'..=b'7') {
        value = value
            .checked_mul(8)?
            .checked_add(u64::from(bytes[at] - b'0'))?;
        at += 1;
    }
    if at == first_digit {
        return None;
    }
    while at < bytes.len() {
        if bytes[at] != 0 && bytes[at] != b' ' {
            return None;
        }
        at += 1;
    }
    Some(value)
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

/// The same checksum with each byte read as signed 8-bit, as some writers
/// store it. The checksum field is spaces here too.
fn signed_checksum(block: &[u8]) -> i64 {
    block
        .iter()
        .enumerate()
        .map(|(at, &byte)| {
            if (CHECKSUM..CHECKSUM_END).contains(&at) {
                i64::from(b' ')
            } else {
                i64::from(byte as i8)
            }
        })
        .sum()
}

/// How a refused record type is named in its refusal: the byte in hex and,
/// for printable ASCII, the character too.
fn record_type_text(typeflag: u8) -> String {
    if typeflag.is_ascii_graphic() {
        format!("0x{typeflag:02x} ('{}')", typeflag as char)
    } else {
        format!("0x{typeflag:02x}")
    }
}

/// A regular file or directory is listable; a hard link, symbolic link,
/// character device, block device or FIFO is P9's non-regular kind. A name
/// that ends like an archive is N1's `archive`.
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
        crc: None,
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
        // The archive ends only at two consecutive zero blocks. One alone
        // followed by a header, data or the end of the object is not an end,
        // and never a reason to carry on as though the pair was there.
        if block.iter().all(|&byte| byte == 0) {
            let next_offset = offset + BLOCK_BYTES;
            let lone_end = next_offset >= size;
            if lone_end {
                let refused = Refused::new(
                    "end_marker",
                    format!("the zero block at {offset} ends the object; the archive needs two"),
                );
                return Err(refused.into());
            }
            let second = match read_block(reader, next_offset) {
                Ok(block) => block,
                Err(TarError::Stopped(reason)) => return Ok(stop(size, entries, reason)),
                Err(error) => return Err(error),
            };
            let second_zero =
                second.len() == BLOCK_BYTES as usize && second.iter().all(|&byte| byte == 0);
            if !second_zero {
                return Err(Refused::new(
                    "end_marker",
                    format!("the zero block at {offset} is not followed by a second zero block"),
                )
                .into());
            }
            break;
        }
        if !is_header(&block) {
            return Err(Refused::new(
                "header_magic",
                format!("the header at {offset} is not ustar"),
            )
            .into());
        }
        let stored = octal(&block[CHECKSUM..CHECKSUM_END]);
        // The stored value is the unsigned byte sum or the signed one; the
        // checksum field itself counts as spaces in both.
        let unsigned = checksum(&block);
        let signed = signed_checksum(&block);
        let matches = stored == Some(unsigned) || stored.map(|value| value as i64) == Some(signed);
        if !matches {
            return Err(Refused::new(
                "header_checksum",
                format!("the header at {offset} does not match its checksum"),
            )
            .into());
        }
        // A base-256 size marks the number with its high bit; this reader
        // reads octal sizes only.
        if block[SIZE] & 0x80 != 0 {
            return Err(Refused::new(
                "size_base256",
                format!("the header at {offset} has a base-256 size, which is not supported"),
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
        // A closed list: a file (`0`, NUL), a directory (`5`), or a hard
        // link, symbolic link, character device, block device or FIFO
        // (`1` to `4`, `6`). Those types carry no data that a later record
        // depends on. Every other type can change how the following bytes or
        // entries are read (pax `x`/`g`, a GNU long name or link `L`/`K`,
        // GNU sparse `S`, multi-volume `M`, a volume header `V`, an old GNU
        // long name `N`) or is unknown to this reader, so the whole archive
        // is refused.
        if !matches!(typeflag, 0 | b'0' | b'1' | b'2' | b'3' | b'4' | b'5' | b'6') {
            // A pax header (`x`, `g`) or a GNU long name or link (`L`, `K`)
            // carries the next entry's effective name or size. This reader
            // does not apply that metadata, so listing on would show the
            // wrong record.
            if matches!(typeflag, b'x' | b'g' | b'L' | b'K') {
                return Err(Refused::new(
                    "extension_header",
                    format!(
                        "the header at {offset} is a pax or GNU extension header, which this reader does not support yet"
                    ),
                )
                .into());
            }
            return Err(Refused::new(
                "unsupported_type",
                format!(
                    "the header at {offset} has record type {}, which this reader does not support",
                    record_type_text(typeflag)
                ),
            )
            .into());
        }
        // A link, device or FIFO header carries no data (ustar), so its size
        // field must be zero. With a non-zero size the walk would step over
        // bytes that are not part of this record and lose the next header,
        // so the archive is refused.
        if matches!(typeflag, b'1' | b'2' | b'3' | b'4' | b'6') && declared != 0 {
            return Err(Refused::new(
                "other_type_size",
                format!(
                    "the header at {offset} is type {} and declares {declared} bytes; a link, device or FIFO carries no data",
                    record_type_text(typeflag)
                ),
            )
            .into());
        }
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
