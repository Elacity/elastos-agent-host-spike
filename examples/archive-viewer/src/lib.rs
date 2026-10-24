//! Archive viewer core, read-only: one ZIP archive, listed but not extracted.
//!
//! Runtime calls `lifecycle.run`. The guest reads a request object naming one
//! archive, asks for a read grant on that one object, and reaches every byte
//! through the offset/length read window. It reads the end record, the
//! central directory and one 30-byte local-header prefix per entry, checks
//! them against each other, and writes one view the render-only page draws.
//! It never reads the whole archive and never writes anything but its view.
//!
//! An authority failure (no grant, a refused or failed call, a request that
//! cannot be read or parsed) stops the run before anything is written, and
//! `run` returns a `bus-error` that names the resource and the reason. A
//! content failure of the whole archive (no end record, a directory that
//! lies, overlapping records, too many entries) writes the view with the
//! reason and no entries.
//!
//! For each entry the request names to show, it checks the local header (L5),
//! then inflates at most one entry into a fixed window under the zip-bomb caps
//! (B1 to B3), checks the output against the declared sizes and CRC (L6 to L8)
//! and the capsule kit's text checks, and writes the text. A nested archive or
//! a directory is listed only. The Bus calls, the refusals, the counted reads,
//! the URI and text checks and the WIT glue are the capsule kit's guest crate
//! (`examples/capsule-kit/guest`).

mod preview;
mod request;
mod zip;

#[cfg(test)]
mod tests;

use capsule_kit_guest::{bus, grant, read_bounded, App};

pub use capsule_kit_guest::{Bus, BusFailure, CallError, InvokeReply, Refusal};
pub use request::{Request, REQUEST_SCHEMA};
pub use zip::{check_local_header, Entry, Kind, Listing, Reason, Refused, Status};

/// The request object: one archive to open, and the entries to show.
pub const REQUEST_URI: &str = "localhost://Users/self/.AppData/App/archive-viewer/open.json";
/// Where the listing is written for the render-only page.
pub const VIEW_URI: &str = "localhost://Users/self/.AppData/App/archive-viewer/view.json";
pub const VIEW_SCHEMA: &str = "elastos.archive-viewer.view/v1";
/// A request names one object under the person's folders; `.AppData/` is
/// refused in `request`, so the app can never list its own view or another
/// app's data.
pub const USERS_PREFIX: &str = "localhost://Users/self/";

/// The request is read whole, so it keeps a small cap.
pub const MAX_REQUEST_BYTES: u64 = 4 * 1024;
/// Entry indexes one request may name to show.
pub const MAX_REQUEST_SHOW: usize = 8;

/// No zip64: offsets and sizes are 32-bit, so this is the largest archive the
/// format can address. The size is found with one-byte probes, never by
/// reading the object.
pub const MAX_ARCHIVE_BYTES: u64 = u32::MAX as u64;
/// The end record is searched for only in the last 22 + 1,024 bytes.
pub const MAX_COMMENT_BYTES: u64 = 1024;
/// The directory cap keeps the listing and its fuel bounded (B4a's prefix
/// reads and the names come out of it).
pub const MAX_DIRECTORY_BYTES: u64 = 16 * 1024;
/// P8: more entries than this refuse the archive.
pub const MAX_ENTRIES: usize = 256;
/// P8: a name longer than this, or with more segments, is blocked.
pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_SEGMENTS: usize = 32;
/// L5 reads a local header of at most 30 + 255 bytes.
pub const MAX_LOCAL_HEADER_BYTES: u64 = 350;
/// All archive bytes one run reads: the probes, the tail, the directory, the
/// 30-byte prefix of every entry and the named entries' local headers. Each
/// read is counted the moment it returns, before anything else happens to it.
pub const MAX_READ_BYTES: u64 = 64 * 1024;
/// The whole view, written once: the archive, every entry, the skipped list
/// and the frame around them.
pub const MAX_VIEW_BYTES: u64 = 64 * 1024;

/// What the archive viewer's refusals say about it.
pub const APP: App = App {
    name: "archive-viewer",
    input: "request",
    max_input_bytes: MAX_REQUEST_BYTES,
};

/// One shown entry's checked text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub index: usize,
    /// The typed blocks of the entry's text, already rendered as one JSON
    /// array (the documents viewer's block kinds).
    pub blocks: Vec<u8>,
}

/// A requested entry that could not be shown, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub index: usize,
    pub reason: &'static str,
    pub message: String,
}

/// Reads the request and the archive, checks a local header for each entry the
/// request names, inflates the listed files within the caps, and writes the
/// view. Returns the view text.
pub fn run(bus: &mut dyn Bus) -> Result<String, Refusal> {
    let request_grant = grant(bus, REQUEST_URI, "read", "read which archive to show")?;
    let request_bytes = read_bounded(
        bus,
        REQUEST_URI,
        &request_grant,
        Vec::new(),
        MAX_REQUEST_BYTES,
    )?
    .ok_or(Refusal::InputTooLarge)?;
    let request = request::parse(&request_bytes).map_err(Refusal::Input)?;

    let archive_grant = grant(bus, &request.uri, "read", "read the archive to list")?;
    let mut left = MAX_READ_BYTES;
    let listing = {
        let mut reader = zip::Reader::new(bus, &request.uri, &archive_grant, &mut left);
        zip::listing(&mut reader)?
    };

    let (previews, skipped, _) = previews_for(
        bus,
        &request.uri,
        &archive_grant,
        &mut left,
        &listing,
        &request.show,
    )?;

    let mut text = view_json(&request.uri, &listing, &previews, &skipped);
    let over = text.len() as u64;
    if over > MAX_VIEW_BYTES {
        // The view is capped as a whole (PATTERNS 1). Never serialize past
        // the cap: write a small refusal that says why, with no entries.
        text = view_json(
            &request.uri,
            &Listing {
                size: 0,
                entries: Vec::new(),
                refused: Some(Refused {
                    code: "view_too_large",
                    message: format!("the listing is {over} bytes, the limit is {MAX_VIEW_BYTES}"),
                }),
            },
            &[],
            &[],
        );
    }
    debug_assert!(text.len() as u64 <= MAX_VIEW_BYTES, "{} bytes", text.len());
    let write_grant = grant(bus, VIEW_URI, "write", "write the checked listing")?;
    bus::write_bytes(bus, VIEW_URI, &write_grant, text.as_bytes()).map_err(|error| {
        Refusal::Call {
            resource: VIEW_URI.to_string(),
            error,
        }
    })?;
    Ok(text)
}

/// The previews and skips of the entries a request names, and the budget they
/// used. `run` writes the view; the tests read the budget to prove the total.
pub fn previews_for(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    left: &mut u64,
    listing: &Listing,
    show: &[usize],
) -> Result<(Vec<Preview>, Vec<Skipped>, preview::Budget), Refusal> {
    let mut previews = Vec::new();
    let mut budget = preview::Budget::new();
    let mut skipped = Vec::new();
    for index in show {
        match listing.entries.get(*index) {
            None => skipped.push(Skipped {
                index: *index,
                reason: "no_such_entry",
                message: format!("the archive has no entry {index}"),
            }),
            Some(entry) => {
                let mut reader = zip::Reader::new(bus, uri, grant, left);
                match zip::check_shown(&mut reader, entry)? {
                    Ok(()) => {
                        // N1: a directory, a nested archive or another kind is
                        // listed only, and its bytes stay unread.
                        if entry.kind != Kind::File {
                            continue;
                        }
                        let outcome = preview::preview(&mut reader, entry, &budget)?;
                        budget.take(&outcome);
                        match outcome.blocks {
                            Ok(blocks) => previews.push(Preview {
                                index: *index,
                                blocks,
                            }),
                            Err(reason) => skipped.push(Skipped {
                                index: *index,
                                reason,
                                message: preview::message(entry, reason),
                            }),
                        }
                    }
                    Err(reason) => skipped.push(Skipped {
                        index: *index,
                        reason,
                        message: format!("entry {} is not shown: {reason}", entry.path),
                    }),
                }
            }
        }
    }
    Ok((previews, skipped, budget))
}

/// The view, keys in sorted order so the text is deterministic.
pub fn view_json(
    uri: &str,
    listing: &Listing,
    previews: &[Preview],
    skipped: &[Skipped],
) -> String {
    let mut out = String::new();
    out.push_str(r#"{"archive":{"size":"#);
    out.push_str(&listing.size.to_string());
    out.push_str(r#","uri":"#);
    push_str(&mut out, uri);
    out.push_str(r#"},"entries":["#);
    for (position, entry) in listing.entries.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        push_entry(&mut out, entry);
    }
    out.push_str(r#"],"previews":["#);
    for (position, preview) in previews.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        out.push_str(r#"{"blocks":"#);
        out.push_str(std::str::from_utf8(&preview.blocks).expect("the blocks are JSON"));
        out.push_str(r#","index":"#);
        out.push_str(&preview.index.to_string());
        out.push('}');
    }
    out.push(']');
    if let Some(refused) = &listing.refused {
        out.push_str(r#","refused":{"code":"#);
        push_str(&mut out, refused.code);
        out.push_str(r#","message":"#);
        push_str(&mut out, &refused.message);
        out.push('}');
    }
    out.push_str(r#","schema":"#);
    push_str(&mut out, VIEW_SCHEMA);
    out.push_str(r#","skipped":["#);
    for (position, skip) in skipped.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        out.push_str(r#"{"index":"#);
        out.push_str(&skip.index.to_string());
        out.push_str(r#","message":"#);
        push_str(&mut out, &skip.message);
        out.push_str(r#","reason":"#);
        push_str(&mut out, skip.reason);
        out.push('}');
    }
    out.push_str("]}");
    out
}

fn push_entry(out: &mut String, entry: &Entry) {
    out.push_str(r#"{"compressed_size":"#);
    out.push_str(&entry.compressed_size.to_string());
    out.push_str(r#","index":"#);
    out.push_str(&entry.index.to_string());
    out.push_str(r#","kind":"#);
    push_str(out, entry.kind.code());
    out.push_str(r#","method":"#);
    out.push_str(&entry.method.to_string());
    out.push_str(r#","path":"#);
    push_str(out, &entry.path);
    if let Some(reason) = entry.status.reason() {
        out.push_str(r#","reason":"#);
        push_str(out, reason);
    }
    out.push_str(r#","status":"#);
    push_str(out, entry.status.code());
    out.push_str(r#","uncompressed_size":"#);
    out.push_str(&entry.uncompressed_size.to_string());
    out.push('}');
}

/// One JSON string, escaped. Names come from the archive, so nothing here
/// trusts them beyond being text.
fn push_str(out: &mut String, text: &str) {
    out.push_str(&serde_json::to_string(text).expect("a string always serializes"));
}

#[cfg(target_arch = "wasm32")]
struct ArchiveViewer;

#[cfg(target_arch = "wasm32")]
impl capsule_kit_guest::wit::exports::elastos::bus::lifecycle::Guest for ArchiveViewer {
    fn run() -> Result<(), capsule_kit_guest::wit::elastos::bus::types::BusError> {
        capsule_kit_guest::component::lifecycle_run(&APP, |bus| run(bus).map(|_| ()))
    }
}

#[cfg(target_arch = "wasm32")]
capsule_kit_guest::wit::export_lifecycle!(ArchiveViewer with_types_in capsule_kit_guest::wit);
