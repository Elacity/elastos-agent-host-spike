//! Documents viewer core guest, read-only.
//!
//! Runtime calls `lifecycle.run`. The guest reads one shelf object, then
//! each document it names, through `providers.invoke` with a grant it
//! requested for that object, using the offset/length read window only. It
//! names the kind from the name (`.md`, `.markdown`, `.txt`), checks the head
//! is text before it reads further, tells an oversize document by one byte
//! past the limit, and only then reads the rest. The text is parsed here, in
//! the sandbox, into typed blocks (`docs-model`), and the surface only draws
//! them.
//!
//! An authority failure (no grant, a refused or failed call, a shelf that
//! cannot be read or parsed) stops the run before anything is written, and
//! `run` returns a `bus-error` that names the resource and the reason. A
//! content failure (wrong kind, empty, not text, oversize, too long) skips
//! that document; the output lists it with its reason.
//!
//! The Component ABI has no input argument and no return value
//! (`elastos/wit/elastos-bus-v1.wit:84-88`), so the shelf and the output are
//! principal-scoped objects at fixed paths. The guest imports only
//! `elastos:bus@v1`. It has no files, sockets, clock or environment.
//!
//! The Bus calls, the refusals, the reads and the WIT glue are the capsule
//! kit's guest crate (`examples/capsule-kit/guest`), shared with the photo
//! viewer.

mod shelf;

#[cfg(test)]
mod tests;

use capsule_kit_guest::text::{self, TextError};
use capsule_kit_guest::{bus, grant, read_bounded, read_counted, App};
use docs_model::{Kind, ModelError};

pub use capsule_kit_guest::{Bus, BusFailure, CallError, InvokeReply, Refusal, READ_CHUNK_BYTES};
pub use shelf::SHELF_SCHEMA;

/// The documents the person asked to read.
pub const SHELF_URI: &str = "localhost://Users/self/.AppData/App/docs-viewer/shelf.json";
/// Where the pages are written for the render-only surface.
pub const PAGES_URI: &str = "localhost://Users/self/.AppData/App/docs-viewer/pages.json";
/// Shelf items must name objects under this folder.
pub const DOCUMENTS_PREFIX: &str = "localhost://Users/self/Documents/";
pub const PAGES_SCHEMA: &str = "elastos.docs-viewer.pages/v1";

/// The shelf is read whole, so it keeps a small cap.
pub const MAX_SHELF_BYTES: u64 = 4 * 1024;
pub const MAX_SHELF_ITEMS: usize = 8;
/// A document is read whole, after its head is checked. Bus v1 bytes cost
/// about 415 fuel each, so this cap and the shelf budget below keep the
/// worst shelf under 80% of the Runtime's fixed fuel (`host-test`).
pub const MAX_DOCUMENT_BYTES: u64 = 16 * 1024;
/// All document bytes one shelf reads: every byte any read of a document
/// returns counts, before anything else happens to it, shown or skipped. A
/// document that would pass it is skipped, found by one byte past what is
/// left, not by reading it.
pub const MAX_SHELF_TEXT_BYTES: u64 = 32 * 1024;
/// The whole pages text one shelf writes: documents, skipped entries and the
/// frame around them. The output is written whole, each byte as a JSON number
/// of up to four characters, so this keeps the write far under the 1 MiB
/// bridge frame, and its fuel bounded: markdown can render to several times
/// its own size.
pub const MAX_PAGES_BYTES: u64 = 64 * 1024;

/// Bytes read before anything else: enough to tell text from a binary file.
pub const HEAD_BYTES: u64 = 512;

/// What the documents viewer's refusals say about it.
pub const APP: App = App {
    name: "docs-viewer",
    input: "shelf",
    max_input_bytes: MAX_SHELF_BYTES,
};

/// Why one document is left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Skip {
    WrongKind,
    Empty,
    NotText(TextError),
    Oversize,
    ShelfFull,
    TooLong,
}

impl Skip {
    pub fn code(&self) -> &'static str {
        match self {
            Skip::WrongKind => "wrong_kind",
            Skip::Empty => "empty",
            Skip::NotText(_) => "not_text",
            Skip::Oversize => "oversize",
            Skip::ShelfFull => "shelf_full",
            Skip::TooLong => "too_long",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Skip::WrongKind => "is not a .md, .markdown or .txt document".to_string(),
            Skip::Empty => "is empty".to_string(),
            Skip::NotText(TextError::OtherEncoding) => "is UTF-16 or UTF-32, not UTF-8".to_string(),
            Skip::NotText(TextError::NotUtf8) => "is not UTF-8 text".to_string(),
            Skip::NotText(TextError::Control) => {
                "has a NUL or control character; it is not text".to_string()
            }
            Skip::Oversize => format!("is larger than {MAX_DOCUMENT_BYTES} bytes"),
            Skip::ShelfFull => format!(
                "would pass what one shelf may read ({MAX_SHELF_TEXT_BYTES} bytes) \
                 or write ({MAX_PAGES_BYTES} bytes of pages)"
            ),
            Skip::TooLong => format!(
                "has more than {} blocks, {} spans in a block or {} list items, \
                 or would take more than {MAX_PAGES_BYTES} bytes to show",
                docs_model::MAX_BLOCKS,
                docs_model::MAX_SPANS,
                docs_model::MAX_LIST_ITEMS
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    pub order: usize,
    pub uri: String,
    pub kind: Kind,
    pub title: String,
    pub bytes: usize,
    /// Its whole entry in the pages, written once.
    pub entry: Vec<u8>,
}

/// What one shelf may still read and write.
struct Budget {
    /// Document bytes: every byte a read returns is taken off at once.
    read: u64,
    /// Pages bytes left for documents. The frame and a worst-case skipped
    /// entry for every item not yet decided are already taken off, so the
    /// whole text can never pass [`MAX_PAGES_BYTES`].
    written: u64,
}

/// Every reason, to find the longest skipped entry.
const ALL_SKIPS: [Skip; 8] = [
    Skip::WrongKind,
    Skip::Empty,
    Skip::NotText(TextError::OtherEncoding),
    Skip::NotText(TextError::NotUtf8),
    Skip::NotText(TextError::Control),
    Skip::Oversize,
    Skip::ShelfFull,
    Skip::TooLong,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub order: usize,
    pub uri: String,
    pub reason: Skip,
}

/// Reads the shelf and its documents, and writes the pages.
/// Returns the text that was written.
pub fn run(bus: &mut dyn Bus) -> Result<String, Refusal> {
    let shelf_grant = grant(bus, SHELF_URI, "read", "read the shelf to show")?;
    let shelf_bytes = read_bounded(bus, SHELF_URI, &shelf_grant, Vec::new(), MAX_SHELF_BYTES)?
        .ok_or(Refusal::InputTooLarge)?;
    let items = shelf::parse(&shelf_bytes).map_err(Refusal::Input)?;

    let mut documents = Vec::with_capacity(items.len());
    let mut skipped = Vec::new();
    // Each item may still end up skipped: hold back room for its entry.
    let longest = ALL_SKIPS
        .iter()
        .max_by_key(|reason| {
            let mut out = Vec::new();
            skip_entry(&mut out, 0, "", reason);
            out.len()
        })
        .expect("there are reasons");
    let held: Vec<u64> = items
        .iter()
        .enumerate()
        .map(|(order, uri)| {
            let mut out = Vec::new();
            skip_entry(&mut out, order, uri, longest);
            out.len() as u64 + 1
        })
        .collect();
    let frame = pages_json(&[], &[]).len() as u64;
    let mut budget = Budget {
        read: MAX_SHELF_TEXT_BYTES,
        written: MAX_PAGES_BYTES.saturating_sub(frame + held.iter().sum::<u64>()),
    };
    for (order, uri) in items.iter().enumerate() {
        // What was held back for this item is its own to use now.
        budget.written += held[order];
        match check_item(bus, order, uri, &mut budget)? {
            Ok(document) => documents.push(document),
            Err(reason) => {
                let mut entry = Vec::new();
                skip_entry(&mut entry, order, uri, &reason);
                budget.written -= entry.len() as u64 + 1;
                skipped.push(Skipped {
                    order,
                    uri: uri.clone(),
                    reason,
                });
            }
        }
    }

    let text = pages_json(&documents, &skipped);
    // The cap is on the whole text written, not only on what is shown.
    debug_assert!(text.len() as u64 <= MAX_PAGES_BYTES, "{}", text.len());
    let write_grant = grant(bus, PAGES_URI, "write", "write the checked pages")?;
    bus::write_bytes(bus, PAGES_URI, &write_grant, text.as_bytes()).map_err(|error| {
        Refusal::Call {
            resource: PAGES_URI.to_string(),
            error,
        }
    })?;
    Ok(text)
}

/// The outer error stops the run; the inner one skips the document.
fn check_item(
    bus: &mut dyn Bus,
    order: usize,
    uri: &str,
    budget: &mut Budget,
) -> Result<Result<Document, Skip>, Refusal> {
    // The kind from the name, before any grant or read.
    let Some(kind) = Kind::from_name(uri) else {
        return Ok(Err(Skip::WrongKind));
    };
    // Nothing more is read once the shelf has read what it may.
    let left = budget.read;
    let ask = HEAD_BYTES.min(left);
    if ask == 0 {
        return Ok(Err(Skip::ShelfFull));
    }
    let item_grant = grant(bus, uri, "read", "read a document on the shelf")?;

    // Text first, from the head alone. Every read is counted the moment it
    // returns (`read_counted`), so a document skipped at any step below has
    // still paid for what was read.
    let head = read_counted(bus, uri, &item_grant, &mut budget.read, 0, ask)?;
    if head.is_empty() {
        return Ok(Err(Skip::Empty));
    }
    let more = head.len() as u64 == ask;
    if more && ask < HEAD_BYTES {
        // It may go on past what the shelf may still read.
        return Ok(Err(Skip::ShelfFull));
    }
    if let Err(err) = text::check_head(&head, more) {
        return Ok(Err(Skip::NotText(err)));
    }

    // Size next: one byte past the limit, then one byte past what the shelf
    // had left. Only then the rest of the document, up to the nearer of the
    // two, which both were just shown to hold no byte.
    let bytes = if more {
        if budget.read == 0 {
            return Ok(Err(Skip::ShelfFull));
        }
        let past = read_counted(
            bus,
            uri,
            &item_grant,
            &mut budget.read,
            MAX_DOCUMENT_BYTES,
            1,
        )?;
        if !past.is_empty() {
            return Ok(Err(Skip::Oversize));
        }
        if left < MAX_DOCUMENT_BYTES {
            let past = read_counted(bus, uri, &item_grant, &mut budget.read, left, 1)?;
            if !past.is_empty() {
                return Ok(Err(Skip::ShelfFull));
            }
        }
        let end = MAX_DOCUMENT_BYTES.min(left);
        let mut bytes = head;
        while (bytes.len() as u64) < end {
            let offset = bytes.len() as u64;
            let ask = READ_CHUNK_BYTES.min(end - offset);
            let chunk = read_counted(bus, uri, &item_grant, &mut budget.read, offset, ask)?;
            let short = (chunk.len() as u64) < ask;
            bytes.extend_from_slice(&chunk);
            if short {
                break;
            }
        }
        bytes
    } else {
        head
    };

    let text = match text::check_whole(&bytes) {
        Ok(text) => text,
        Err(err) => return Ok(Err(Skip::NotText(err))),
    };
    let blocks = match docs_model::blocks(kind, text) {
        Ok(blocks) => blocks,
        Err(ModelError::TooLong) => return Ok(Err(Skip::TooLong)),
    };
    // Rendered once. Stop as soon as it is too long for any pages: what is
    // past the cap is never used.
    let mut rendered = vec![b'['];
    for (index, block) in blocks.iter().enumerate() {
        if index > 0 {
            rendered.push(b',');
        }
        docs_model::write_block(&mut rendered, block);
        if rendered.len() as u64 >= MAX_PAGES_BYTES {
            return Ok(Err(Skip::TooLong));
        }
    }
    rendered.push(b']');
    let name = uri.rsplit('/').next().unwrap_or(uri);
    let title = docs_model::title(&blocks, name);
    let entry = document_entry(&rendered, bytes.len(), kind, order, &title, uri);
    // The whole entry counts against the pages, with its comma.
    let size = entry.len() as u64 + 1;
    if size > budget.written {
        return Ok(Err(Skip::ShelfFull));
    }
    budget.written -= size;
    Ok(Ok(Document {
        order,
        uri: uri.to_string(),
        kind,
        title,
        bytes: bytes.len(),
        entry,
    }))
}

/// One document's entry in the pages, keys in sorted order.
fn document_entry(
    rendered: &[u8],
    bytes: usize,
    kind: Kind,
    order: usize,
    title: &str,
    uri: &str,
) -> Vec<u8> {
    use docs_model::write_str;
    let mut out = Vec::with_capacity(rendered.len() + 256);
    out.extend_from_slice(br#"{"blocks":"#);
    out.extend_from_slice(rendered);
    out.extend_from_slice(format!(r#","bytes":{bytes},"mime":"#).as_bytes());
    write_str(&mut out, kind.mime());
    out.extend_from_slice(format!(r#","order":{order},"title":"#).as_bytes());
    write_str(&mut out, title);
    out.extend_from_slice(br#","uri":"#);
    write_str(&mut out, uri);
    out.push(b'}');
    out
}

/// One skipped entry in the pages, keys in sorted order.
fn skip_entry(out: &mut Vec<u8>, order: usize, uri: &str, reason: &Skip) {
    use docs_model::write_str;
    out.extend_from_slice(br#"{"message":"#);
    write_str(out, &reason.message());
    out.extend_from_slice(format!(r#","order":{order},"reason":"#).as_bytes());
    write_str(out, reason.code());
    out.extend_from_slice(br#","uri":"#);
    write_str(out, uri);
    out.push(b'}');
}

/// The pages, with keys in sorted order so the text is deterministic. Written
/// straight into a string: a `serde_json::Value` per span costs too much fuel
/// on Bus v1 (`docs_model::write_block`).
pub fn pages_json(documents: &[Document], skipped: &[Skipped]) -> String {
    use docs_model::write_str;
    let mut out = Vec::new();
    out.extend_from_slice(br#"{"documents":["#);
    for (index, document) in documents.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&document.entry);
    }
    out.extend_from_slice(br#"],"schema":"#);
    write_str(&mut out, PAGES_SCHEMA);
    out.extend_from_slice(br#","shelf":"#);
    write_str(&mut out, SHELF_URI);
    out.extend_from_slice(br#","skipped":["#);
    for (index, skip) in skipped.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        skip_entry(&mut out, skip.order, &skip.uri, &skip.reason);
    }
    out.extend_from_slice(b"]}");
    String::from_utf8(out).expect("only UTF-8 was written")
}

#[cfg(target_arch = "wasm32")]
struct DocsViewer;

#[cfg(target_arch = "wasm32")]
impl capsule_kit_guest::wit::exports::elastos::bus::lifecycle::Guest for DocsViewer {
    fn run() -> Result<(), capsule_kit_guest::wit::elastos::bus::types::BusError> {
        capsule_kit_guest::component::lifecycle_run(&APP, |bus| run(bus).map(|_| ()))
    }
}

#[cfg(target_arch = "wasm32")]
capsule_kit_guest::wit::export_lifecycle!(DocsViewer with_types_in capsule_kit_guest::wit);
