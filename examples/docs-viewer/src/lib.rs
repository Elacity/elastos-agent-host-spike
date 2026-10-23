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
//! `bus.rs`, `component.rs` and `fake.rs` are links to the capsule kit
//! (`examples/capsule-kit/v1-guest`), shared with the photo viewer.

mod bus;
mod shelf;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use docs_model::text::{self, TextError};
use docs_model::{Kind, ModelError};

pub use bus::{Bus, BusFailure, CallError, InvokeReply};
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

/// Bytes per read. Content travels as a JSON array of numbers, up to four
/// characters a byte, so 8 KiB stays far under the 1 MiB bridge frame
/// (`elastos-server/src/resource_bridge.rs:32`).
pub const READ_CHUNK_BYTES: u64 = 8 * 1024;
/// Bytes read before anything else: enough to tell text from a binary file.
pub const HEAD_BYTES: u64 = 512;

/// Why the run stopped. Each variant names what is missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    NoGrant {
        resource: String,
        failure: BusFailure,
    },
    Call {
        resource: String,
        error: CallError,
    },
    ShelfTooLarge,
    Shelf(String),
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::NoGrant { resource, failure } => {
                format!(
                    "docs-viewer has no grant for {resource}: {}",
                    failure.message()
                )
            }
            Refusal::Call { resource, error } => match error {
                CallError::Bus(failure) => {
                    format!(
                        "docs-viewer call on {resource} failed: {}",
                        failure.message()
                    )
                }
                CallError::Provider { code, message } => {
                    format!("docs-viewer call on {resource} failed: {code}: {message}")
                }
                CallError::Shape(message) => {
                    format!("docs-viewer call on {resource} had an unexpected answer: {message}")
                }
            },
            Refusal::ShelfTooLarge => {
                format!("docs-viewer shelf is larger than {MAX_SHELF_BYTES} bytes")
            }
            Refusal::Shelf(message) => format!("docs-viewer shelf refused: {message}"),
        }
    }

    /// The `bus-error` Runtime receives from `lifecycle.run`.
    pub fn to_bus_failure(&self) -> BusFailure {
        let message = self.message();
        match self {
            Refusal::NoGrant { .. } => BusFailure::Denied(message),
            Refusal::Call { error, .. } => match error {
                CallError::Bus(BusFailure::Denied(_)) => BusFailure::Denied(message),
                CallError::Bus(BusFailure::NotFound(_)) => BusFailure::NotFound(message),
                CallError::Bus(BusFailure::Timeout(_)) => BusFailure::Timeout(message),
                CallError::Bus(BusFailure::Unavailable(_)) | CallError::Provider { .. } => {
                    BusFailure::Unavailable(message)
                }
                CallError::Bus(BusFailure::Invalid(_)) => BusFailure::Invalid(message),
                CallError::Bus(BusFailure::Internal(_)) | CallError::Shape(_) => {
                    BusFailure::Internal(message)
                }
            },
            Refusal::ShelfTooLarge | Refusal::Shelf(_) => BusFailure::Invalid(message),
        }
    }
}

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
        .ok_or(Refusal::ShelfTooLarge)?;
    let items = shelf::parse(&shelf_bytes).map_err(Refusal::Shelf)?;

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

fn grant(bus: &mut dyn Bus, resource: &str, action: &str, reason: &str) -> Result<String, Refusal> {
    bus.request(resource, action, reason)
        .map_err(|failure| Refusal::NoGrant {
            resource: resource.to_string(),
            failure,
        })
}

fn read_at(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, Refusal> {
    bus::read_window(bus, uri, grant, offset, length).map_err(|error| Refusal::Call {
        resource: uri.to_string(),
        error,
    })
}

/// Reads on from the end of `bytes` in chunks, to the end of the object.
/// `None` means it is larger than `limit`.
fn read_bounded(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    mut bytes: Vec<u8>,
    limit: u64,
) -> Result<Option<Vec<u8>>, Refusal> {
    loop {
        let offset = bytes.len() as u64;
        // Ask for one byte past the limit so an exact fit is told apart from more.
        let ask = READ_CHUNK_BYTES.min(limit + 1 - offset);
        let chunk = read_at(bus, uri, grant, offset, ask)?;
        let short = (chunk.len() as u64) < ask;
        bytes.extend_from_slice(&chunk);
        if bytes.len() as u64 > limit {
            return Ok(None);
        }
        if short {
            return Ok(Some(bytes));
        }
    }
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

/// One read of a document, taken off what the shelf may still read before
/// anything else can happen to it. The read window refuses an answer longer
/// than it asked for, so `length` is the most it can take off.
fn read_counted(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    left: &mut u64,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, Refusal> {
    assert!(length <= *left, "a read past what the shelf may read");
    let bytes = read_at(bus, uri, grant, offset, length)?;
    *left -= bytes.len() as u64;
    Ok(bytes)
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
wit_bindgen::generate!({
    path: "../../elastos/wit",
    world: "product-capsule-v1",
});

#[cfg(target_arch = "wasm32")]
const EXPECTED_RUNTIME_ABI: &str = "elastos.component/v1";

#[cfg(target_arch = "wasm32")]
mod component;

#[cfg(target_arch = "wasm32")]
struct DocsViewer;

#[cfg(target_arch = "wasm32")]
impl exports::elastos::bus::lifecycle::Guest for DocsViewer {
    fn run() -> Result<(), elastos::bus::types::BusError> {
        let abi = component::runtime_abi();
        if abi != EXPECTED_RUNTIME_ABI {
            return Err(elastos::bus::types::BusError::Invalid(format!(
                "docs-viewer requires {EXPECTED_RUNTIME_ABI}, received {abi}"
            )));
        }
        run(&mut component::WitBus)
            .map(|_| ())
            .map_err(|refusal| component::to_wit(refusal.to_bus_failure()))
    }
}

#[cfg(target_arch = "wasm32")]
export!(DocsViewer);
