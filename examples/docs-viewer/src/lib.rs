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
/// All document bytes one shelf reads in full, shown or skipped. A document
/// that would pass it is skipped, found by one byte past what is left, not
/// by reading it.
pub const MAX_SHELF_TEXT_BYTES: u64 = 32 * 1024;
/// All rendered blocks one shelf writes. The output is written whole, each
/// byte as a JSON number of up to four characters, so this keeps the write
/// far under the 1 MiB bridge frame, and its fuel bounded: markdown can render
/// to several times its own size.
pub const MAX_SHELF_SHOWN_BYTES: u64 = 64 * 1024;

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
                 or show ({MAX_SHELF_SHOWN_BYTES} bytes)"
            ),
            Skip::TooLong => format!(
                "has more than {} blocks, {} spans in a block or {} list items, \
                 or would take more than {MAX_SHELF_SHOWN_BYTES} bytes to show",
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
    /// The blocks, rendered once as a JSON array.
    pub rendered: Vec<u8>,
}

/// What one shelf may still read and show.
struct Budget {
    read: u64,
    shown: u64,
}

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
    let mut budget = Budget {
        read: MAX_SHELF_TEXT_BYTES,
        shown: MAX_SHELF_SHOWN_BYTES,
    };
    for (order, uri) in items.iter().enumerate() {
        match check_item(bus, order, uri, &mut budget)? {
            Ok(document) => documents.push(document),
            Err(reason) => skipped.push(Skipped {
                order,
                uri: uri.clone(),
                reason,
            }),
        }
    }

    let text = pages_json(&documents, &skipped);
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
    let item_grant = grant(bus, uri, "read", "read a document on the shelf")?;

    // Text first, from the head alone.
    let head = read_at(bus, uri, &item_grant, 0, HEAD_BYTES)?;
    if head.is_empty() {
        return Ok(Err(Skip::Empty));
    }
    let more = head.len() as u64 == HEAD_BYTES;
    if let Err(err) = text::check_head(&head, more) {
        return Ok(Err(Skip::NotText(err)));
    }

    // Size next: one byte past the limit, then one byte past what the shelf
    // has left. Only then the rest of the document.
    let left = budget.read;
    let bytes = if more {
        if !read_at(bus, uri, &item_grant, MAX_DOCUMENT_BYTES, 1)?.is_empty() {
            return Ok(Err(Skip::Oversize));
        }
        if left < MAX_DOCUMENT_BYTES && !read_at(bus, uri, &item_grant, left, 1)?.is_empty() {
            return Ok(Err(Skip::ShelfFull));
        }
        match read_bounded(bus, uri, &item_grant, head, MAX_DOCUMENT_BYTES.min(left))? {
            Some(bytes) => bytes,
            // It grew between the size check and the read.
            None => return Ok(Err(Skip::Oversize)),
        }
    } else if head.len() as u64 > left {
        return Ok(Err(Skip::ShelfFull));
    } else {
        head
    };
    // Read in full: it counts, whatever comes next.
    budget.read -= bytes.len() as u64;

    let text = match text::check_whole(&bytes) {
        Ok(text) => text,
        Err(err) => return Ok(Err(Skip::NotText(err))),
    };
    let blocks = match docs_model::blocks(kind, text) {
        Ok(blocks) => blocks,
        Err(ModelError::TooLong) => return Ok(Err(Skip::TooLong)),
    };
    // Rendered once, and measured before it counts.
    let mut rendered = vec![b'['];
    for (index, block) in blocks.iter().enumerate() {
        if index > 0 {
            rendered.push(b',');
        }
        docs_model::write_block(&mut rendered, block);
        // Stop as soon as it is too long: what is past the cap is never used.
        if rendered.len() as u64 >= MAX_SHELF_SHOWN_BYTES {
            return Ok(Err(Skip::TooLong));
        }
    }
    rendered.push(b']');
    let size = rendered.len() as u64;
    if size > MAX_SHELF_SHOWN_BYTES {
        return Ok(Err(Skip::TooLong));
    }
    if size > budget.shown {
        return Ok(Err(Skip::ShelfFull));
    }
    budget.shown -= size;
    let name = uri.rsplit('/').next().unwrap_or(uri);
    Ok(Ok(Document {
        order,
        uri: uri.to_string(),
        kind,
        title: docs_model::title(&blocks, name),
        bytes: bytes.len(),
        rendered,
    }))
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
        out.extend_from_slice(br#"{"blocks":"#);
        out.extend_from_slice(&document.rendered);
        out.extend_from_slice(format!(r#","bytes":{},"mime":"#, document.bytes).as_bytes());
        write_str(&mut out, document.kind.mime());
        out.extend_from_slice(format!(r#","order":{},"title":"#, document.order).as_bytes());
        write_str(&mut out, &document.title);
        out.extend_from_slice(br#","uri":"#);
        write_str(&mut out, &document.uri);
        out.push(b'}');
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
        out.extend_from_slice(br#"{"message":"#);
        write_str(&mut out, &skip.reason.message());
        out.extend_from_slice(format!(r#","order":{},"reason":"#, skip.order).as_bytes());
        write_str(&mut out, skip.reason.code());
        out.extend_from_slice(br#","uri":"#);
        write_str(&mut out, &skip.uri);
        out.push(b'}');
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
mod component {
    use super::elastos::bus::{capabilities, providers, runtime, types};
    use super::{Bus, BusFailure, InvokeReply};

    pub struct WitBus;

    fn from_wit(err: types::BusError) -> BusFailure {
        match err {
            types::BusError::Denied(message) => BusFailure::Denied(message),
            types::BusError::NotFound(message) => BusFailure::NotFound(message),
            types::BusError::Invalid(message) => BusFailure::Invalid(message),
            types::BusError::Unavailable(message) => BusFailure::Unavailable(message),
            types::BusError::Timeout(message) => BusFailure::Timeout(message),
            types::BusError::Internal(message) => BusFailure::Internal(message),
        }
    }

    pub fn to_wit(failure: BusFailure) -> types::BusError {
        match failure {
            BusFailure::Denied(message) => types::BusError::Denied(message),
            BusFailure::NotFound(message) => types::BusError::NotFound(message),
            BusFailure::Invalid(message) => types::BusError::Invalid(message),
            BusFailure::Unavailable(message) => types::BusError::Unavailable(message),
            BusFailure::Timeout(message) => types::BusError::Timeout(message),
            BusFailure::Internal(message) => types::BusError::Internal(message),
        }
    }

    impl Bus for WitBus {
        fn request(
            &mut self,
            resource: &str,
            action: &str,
            reason: &str,
        ) -> Result<String, BusFailure> {
            capabilities::request(&types::CapabilityRequest {
                resource: resource.to_string(),
                actions: vec![action.to_string()],
                reason: reason.to_string(),
            })
            .map(|grant| grant.id)
            .map_err(from_wit)
        }

        fn invoke(
            &mut self,
            resource: &str,
            operation: &str,
            body: &[u8],
            grant: &str,
        ) -> Result<InvokeReply, BusFailure> {
            providers::invoke(&types::InvokeRequest {
                resource: resource.to_string(),
                operation: operation.to_string(),
                body: body.to_vec(),
                grant: Some(grant.to_string()),
            })
            .map(|reply| InvokeReply {
                status: reply.status,
                body: reply.body,
            })
            .map_err(from_wit)
        }
    }

    pub fn runtime_abi() -> String {
        runtime::info().abi
    }
}

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
