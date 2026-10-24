//! Text previews: bounded inflate under the zip-bomb caps, the per-entry byte
//! checks (L6 to L8), and the capsule kit's text check.
//!
//! The decompressor is the attack surface (DESIGN.md, "Zip bombs"), so every
//! cap here is counted in the loop and taken from the archive, not from what
//! the directory claims:
//!
//! - **B1** (`MAX_PREVIEW_BYTES`): the declared uncompressed size is checked
//!   before any read, and the output window is the cap plus one byte, so the
//!   first byte past the cap stops the entry `oversize`.
//! - **B2** (`MAX_RATIO`): a declared ratio past the cap is not even read; the
//!   inflate loop also checks, after every step of at most
//!   [`INFLATE_STEP_BYTES`] compressed bytes, that the output stays inside 100
//!   times the bytes consumed so far plus the slack (F3).
//! - **B3** (`MAX_INFLATE_BYTES`): every output byte of a run is taken off
//!   one budget, whether the entry is then shown or skipped.
//!
//! L6 to L8 check the bytes, not the declaration: the stream must end at the
//! declared compressed size, produce exactly the declared uncompressed size,
//! match the declared CRC-32, and a stored entry's two sizes must agree.

use capsule_kit_guest::text;
use capsule_kit_guest::Refusal;
use docs_model::{self, ModelError};
use miniz_oxide::inflate::core::{decompress_with_limit, inflate_flags, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;

use crate::zip::{Entry, ReadError, Reader, Reason};

/// B1: an entry is shown only if its declared uncompressed size is at most
/// this.
pub const MAX_PREVIEW_BYTES: u64 = 16 * 1024;
/// B1: the output window is the cap plus one byte: the first byte past the
/// cap stops the entry.
pub const OUTPUT_WINDOW_BYTES: u64 = MAX_PREVIEW_BYTES + 1;
/// B2: a declared ratio over this is not even read.
pub const MAX_RATIO: u64 = 100;
/// B2: the slack the ratio allows for tiny entries.
pub const RATIO_SLACK_BYTES: u64 = 1024;
/// B3: all entries shown in one run inflate at most this much in all.
pub const MAX_INFLATE_BYTES: u64 = 64 * 1024;
/// The compressed bytes of the shown entries one run may read.
pub const MAX_COMPRESSED_BYTES: u64 = 24 * 1024;
/// B2: one inflate step asks for at most this many compressed bytes, so the
/// streaming ratio check runs after every step (F3).
pub const INFLATE_STEP_BYTES: usize = 16;

/// What one run may still inflate and read. Every byte comes off as it comes
/// out, whether the entry is then shown or skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub inflate: u64,
    pub compressed: u64,
}

impl Budget {
    pub const fn new() -> Self {
        Budget {
            inflate: MAX_INFLATE_BYTES,
            compressed: MAX_COMPRESSED_BYTES,
        }
    }

    /// Takes one entry's bytes off the run. A skipped entry counts too: its
    /// inflation already happened (PATTERNS 1, "count before any early
    /// return").
    pub fn take(&mut self, outcome: &Outcome) {
        self.compressed = self.compressed.saturating_sub(outcome.read);
        self.inflate = self.inflate.saturating_sub(outcome.produced);
    }
}

impl Default for Budget {
    fn default() -> Self {
        Budget::new()
    }
}

/// What one entry cost, and the text when it passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Output bytes, counted even when the entry is skipped.
    pub produced: u64,
    /// Compressed bytes read, counted even when the entry is skipped.
    pub read: u64,
    /// The checked text as typed blocks, or why the entry is not shown.
    pub blocks: Result<Vec<u8>, Reason>,
}

fn skipped(reason: Reason) -> Outcome {
    Outcome {
        produced: 0,
        read: 0,
        blocks: Err(reason),
    }
}

fn skipped_after(produced: u64, read: u64, reason: Reason) -> Outcome {
    Outcome {
        produced,
        read,
        blocks: Err(reason),
    }
}

/// Inflates one shown entry under the caps and checks it. An authority
/// failure stops the run; every content failure is the entry's own reason.
pub fn preview(
    reader: &mut Reader<'_>,
    entry: &Entry,
    budget: &Budget,
) -> Result<Outcome, Refusal> {
    // B1: the declared size is checked first, so an entry that claims to be
    // too large is never read.
    if entry.uncompressed_size > MAX_PREVIEW_BYTES {
        return Ok(skipped("oversize"));
    }
    // B2: a declared ratio past the cap is not read either.
    if entry.uncompressed_size
        > entry
            .compressed_size
            .saturating_mul(MAX_RATIO)
            .saturating_add(RATIO_SLACK_BYTES)
    {
        return Ok(skipped("ratio"));
    }
    // L8: a stored entry's two sizes must agree, before its bytes are read.
    if entry.method == 0 && entry.compressed_size != entry.uncompressed_size {
        return Ok(skipped("size_mismatch"));
    }
    if entry.compressed_size > budget.compressed {
        return Ok(skipped("compressed_budget"));
    }
    if budget.inflate == 0 || (entry.method == 0 && entry.compressed_size > budget.inflate) {
        return Ok(skipped("inflate_budget"));
    }

    let data = match reader.read(entry.data_start, entry.compressed_size) {
        Ok(data) => data,
        Err(ReadError::Refusal(refusal)) => return Err(refusal),
        Err(ReadError::Budget) => return Ok(skipped("read_budget")),
    };
    let read = data.len() as u64;
    // A provider that answers short must not be inflated as if the bytes
    // were there (L6: the stream ends at the declared compressed size).
    if read != entry.compressed_size {
        return Ok(Outcome {
            produced: 0,
            read,
            blocks: Err("size_mismatch"),
        });
    }

    let (output, produced, failure) = if entry.method == 0 {
        // L8 and the length check above already proved the stored bytes are
        // the declared bytes, so they are used directly.
        let produced = data.len() as u64;
        (data, produced, None)
    } else {
        match inflate_bounded(&data, entry.uncompressed_size, budget.inflate) {
            Ok((output, produced)) => (output, produced, None),
            Err((produced, reason)) => (Vec::new(), produced, Some(reason)),
        }
    };
    if let Some(reason) = failure {
        return Ok(Outcome {
            produced,
            read,
            blocks: Err(reason),
        });
    }

    // L7: the CRC-32 of the output must be the directory's.
    if crc32(&output) != entry.crc {
        return Ok(Outcome {
            produced,
            read,
            blocks: Err("crc_mismatch"),
        });
    }
    let text = match text::check_whole(&output) {
        Ok(text) => text,
        Err(_) => return Ok(skipped_after(produced, read, "not_text")),
    };
    let blocks = match docs_model::blocks(docs_model::Kind::Text, text) {
        Ok(blocks) => blocks,
        Err(ModelError::TooLong) => return Ok(skipped_after(produced, read, "too_long")),
    };
    // One JSON array, rendered straight into the view's bytes: the same
    // blocks the documents viewer and the page draw.
    let mut rendered = Vec::new();
    rendered.push(b'[');
    for (index, block) in blocks.iter().enumerate() {
        if index > 0 {
            rendered.push(b',');
        }
        docs_model::write_block(&mut rendered, block);
    }
    rendered.push(b']');
    Ok(Outcome {
        produced,
        read,
        blocks: Ok(rendered),
    })
}

/// Inflates `data` to at most the B1 window and the run's remaining output,
/// stepping at most [`INFLATE_STEP_BYTES`] compressed bytes at a time.
///
/// `Ok` is the whole stream, ended exactly at the end of `data` with exactly
/// `declared` bytes out. `Err` carries the bytes produced before the stop.
fn inflate_bounded(
    data: &[u8],
    declared: u64,
    allowance: u64,
) -> Result<(Vec<u8>, u64), (u64, Reason)> {
    // The decompressor's 32 KiB dictionary is also its output buffer, so
    // every inflated byte is written into counted memory at once. The
    // stream wrapper would produce into an internal dictionary and copy only
    // what fits, which would hide the work the caps are meant to bound.
    const DICTIONARY_BYTES: usize = 32 * 1024;
    let mut state = DecompressorOxide::new();
    let mut dictionary = vec![0u8; DICTIONARY_BYTES];
    let mut output = Vec::new();
    let mut produced = 0u64;
    let mut consumed = 0usize;
    let mut out_pos = 0usize;
    loop {
        let room = OUTPUT_WINDOW_BYTES.saturating_sub(produced);
        if room == 0 {
            return Err((produced, "oversize"));
        }
        let left = allowance.saturating_sub(produced);
        // A spent output budget can still finish the stream: the last blocks
        // of a stored or empty stream carry no bytes, so ask for zero output
        // instead of refusing an exact fit before it can end.
        let ask = room.min(left);
        // The decompressor does not wrap: stop at the ring's end and continue
        // from zero next time. The ask stays inside the cap and the budget.
        let ask = ask.min((DICTIONARY_BYTES - out_pos) as u64) as usize;
        let step_end = (consumed + INFLATE_STEP_BYTES).min(data.len());
        let flags = if step_end < data.len() {
            inflate_flags::TINFL_FLAG_HAS_MORE_INPUT
        } else {
            0
        };
        let (status, in_used, out_used) = decompress_with_limit(
            &mut state,
            &data[consumed..step_end],
            &mut dictionary,
            out_pos,
            ask,
            flags,
        );
        output.extend_from_slice(&dictionary[out_pos..out_pos + out_used]);
        consumed += in_used;
        produced += out_used as u64;
        out_pos = (out_pos + out_used) % DICTIONARY_BYTES;
        // B1 first: the byte past the window is oversize, whatever the stream
        // says about itself.
        if produced > MAX_PREVIEW_BYTES {
            return Err((produced, "oversize"));
        }
        // B2 after every step: one step over the whole stream would hide an
        // early burst, so the output is checked against the bytes consumed
        // so far. The declared ratio (F4) checked this before the read; this
        // is the same rule on the bytes that really came out.
        if produced
            > (consumed as u64)
                .saturating_mul(MAX_RATIO)
                .saturating_add(RATIO_SLACK_BYTES)
        {
            return Err((produced, "ratio"));
        }
        match status {
            TINFLStatus::Done => {
                // L6: exactly the declared compressed bytes consumed and
                // exactly the declared uncompressed bytes produced.
                if consumed != data.len() || produced != declared {
                    return Err((produced, "size_mismatch"));
                }
                return Ok((output, produced));
            }
            TINFLStatus::NeedsMoreInput => {}
            TINFLStatus::HasMoreOutput => {
                if ask == 0 {
                    return Err((produced, "inflate_budget"));
                }
            }
            _ => return Err((produced, "size_mismatch")),
        }
        if in_used == 0 && out_used == 0 {
            let reason = if ask == 0 {
                "inflate_budget"
            } else {
                "size_mismatch"
            };
            return Err((produced, reason));
        }
    }
}

/// Why one entry is not shown, with the cap it passed named.
pub fn message(entry: &Entry, reason: Reason) -> String {
    match reason {
        "oversize" => format!(
            "entry {} is larger than {MAX_PREVIEW_BYTES} bytes",
            entry.path
        ),
        "ratio" => format!(
            "entry {} would inflate past {MAX_RATIO} times its compressed bytes",
            entry.path
        ),
        "size_mismatch" => format!("entry {} does not match its declared sizes", entry.path),
        "crc_mismatch" => format!("entry {} does not match its declared CRC", entry.path),
        "not_text" => format!("entry {} is not text", entry.path),
        "too_long" => format!(
            "entry {} has more than {} blocks to show",
            entry.path,
            docs_model::MAX_BLOCKS
        ),
        "compressed_budget" => format!(
            "entry {} would pass the {MAX_COMPRESSED_BYTES} compressed bytes one run may read",
            entry.path
        ),
        "inflate_budget" => format!(
            "entry {} would pass the {MAX_INFLATE_BYTES} bytes one run may inflate",
            entry.path
        ),
        "read_budget" => format!("entry {} would pass what one run may read", entry.path),
        _ => format!("entry {} is not shown: {reason}", entry.path),
    }
}

/// CRC-32 (IEEE 802.3), the checksum ZIP records. Table-driven: one lookup a
/// byte, so the 64 KiB of output one run may check stays cheap.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC_TABLE[index];
    }
    !crc
}

const CRC_TABLE: [u32; 256] = crc_table();

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}
