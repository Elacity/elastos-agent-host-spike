//! The documents reader on the DRAFT Bus v2: a resident guest that shows each
//! document it is pointed at, until its events close.
//!
//! The host sends a document's URI as a `message` event. The guest:
//! - names the kind from the name (`.md`, `.markdown`, `.txt`);
//! - asks for a read grant on exactly that URI, and reads it through
//!   `providers.invoke`, asking for at most 16 KiB and refusing more even if
//!   more arrives;
//! - uses the bytes only once the read's trailing future says `ok`;
//! - checks they are text and parses them into blocks (`docs-model`, the same
//!   model as the Bus v1 core);
//! - draws one frame with `ui.present`, a text node per block.
//!
//! A refused grant or a denied read ends the run with its reason (pattern 1:
//! authority stops). A document that is not shown (the wrong kind, not text,
//! too long, a read that fails another way) gets a frame that says so, and
//! the reader goes on (content is skipped). It stops when its events close;
//! it does not look at `stop-requested`.

wit_bindgen::generate!({ path: "../../../../bus2-proof/wit", world: "product-capsule-v2" });

use docs_model::text;
use docs_model::{Block, Kind, ModelError, Span};
use elastos::bus::types::{BusError, Event, InvokeRequest};
use elastos::bus::{capabilities, providers, ui};
use wit_bindgen::StreamResult;

/// The same cap as the Bus v1 core (`examples/docs-viewer/src/lib.rs`).
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
/// Bytes the guest asks for per read of the stream.
const READ_BUFFER: usize = 16 * 1024;
const MEDIA_TYPE: &str = "application/vnd.elastos.ui+json;v=0";
/// What the proof host's `ui.present` takes (`bus2-proof/host/src/ui.rs`).
const MAX_NODES: usize = 32;
const MAX_TEXT_CHARS: usize = 1000;
const MAX_FRAME_BYTES: usize = 16 * 1024;

struct Reader;

/// Why a document is not shown. Authority failures are not here: they end
/// the run.
fn not_shown(uri: &str, why: &str) -> Vec<String> {
    vec![docs_model::cut(
        &format!("Not shown: {uri} {why}"),
        MAX_TEXT_CHARS - 1,
    )]
}

/// The whole object, a refusal that ends the run (`Err`), or one that only
/// means this document is not shown (`Ok(Err)`). Nothing partial is returned.
async fn read_document(uri: &str) -> Result<Result<Vec<u8>, String>, BusError> {
    let grant = capabilities::request(
        uri.to_string(),
        vec!["read".to_string()],
        "show this document".to_string(),
    )
    .await?;
    let request = InvokeRequest {
        resource: uri.to_string(),
        operation: "read".to_string(),
        grant: Some(grant.id),
        params: format!(r#"{{"max_bytes":{MAX_DOCUMENT_BYTES}}}"#).into_bytes(),
    };
    let (_status, mut stream, trailer) = match providers::invoke(request, None).await {
        Ok(read) => read,
        Err(BusError::Denied(why)) => return Err(BusError::Denied(why)),
        Err(other) => return Ok(Err(reason(&other))),
    };
    let mut bytes = Vec::new();
    loop {
        let (result, chunk) = stream.read(Vec::with_capacity(READ_BUFFER)).await;
        if bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            return Ok(Err(format!(
                "sent more than the {MAX_DOCUMENT_BYTES} bytes asked for; none are used"
            )));
        }
        bytes.extend_from_slice(&chunk);
        match result {
            StreamResult::Complete(_) => continue,
            StreamResult::Dropped => break,
            StreamResult::Cancelled => return Ok(Err("could not be read whole".to_string())),
        }
    }
    // Only the trailing future says whether these bytes are the document.
    match trailer.await {
        Ok(()) => Ok(Ok(bytes)),
        Err(BusError::Denied(why)) => Err(BusError::Denied(why)),
        Err(other) => Ok(Err(reason(&other))),
    }
}

fn reason(error: &BusError) -> String {
    match error {
        BusError::Denied(why)
        | BusError::NotFound(why)
        | BusError::Invalid(why)
        | BusError::Unavailable(why)
        | BusError::Timeout(why)
        | BusError::Conflict(why)
        | BusError::Internal(why) => format!("could not be read: {why}"),
    }
}

fn spans_text(spans: &[Span]) -> String {
    spans.iter().map(|span| span.text.as_str()).collect()
}

/// One block as one line of text. The frame has text and image nodes only, so
/// the kind of a block is lost here (a heading is just its text).
fn block_text(block: &Block) -> String {
    match block {
        Block::Heading { spans, .. } | Block::Paragraph { spans } => spans_text(spans),
        Block::Quote { spans } => format!("> {}", spans_text(spans)),
        Block::List { ordered, items } => items
            .iter()
            .enumerate()
            .map(|(at, item)| {
                if *ordered {
                    format!("{}. {}", at + 1, spans_text(item))
                } else {
                    format!("• {}", spans_text(item))
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Block::Code { text } => text.clone(),
        Block::Rule => "—".to_string(),
    }
}

/// The text nodes of one document: a node per block, each cut to what a
/// node may hold, as many as fit in one frame, and a last node that says how
/// many blocks did not fit.
fn document_nodes(blocks: &[Block]) -> Vec<String> {
    // Room kept for the last node and the frame around the nodes.
    const RESERVE: usize = 256;
    let mut nodes = Vec::new();
    let mut size = 0;
    for (at, block) in blocks.iter().enumerate() {
        let node = docs_model::cut(&block_text(block), MAX_TEXT_CHARS - 1);
        let node_size = json_size(&node);
        if nodes.len() == MAX_NODES - 1 || size + node_size + RESERVE > MAX_FRAME_BYTES {
            nodes.push(format!(
                "… {} more blocks are not shown: a frame holds {MAX_NODES} text nodes of \
                 {MAX_TEXT_CHARS} characters, {MAX_FRAME_BYTES} bytes in all",
                blocks.len() - at
            ));
            return nodes;
        }
        size += node_size;
        nodes.push(node);
    }
    if nodes.is_empty() {
        nodes.push("(this document is empty)".to_string());
    }
    nodes
}

fn json_size(text: &str) -> usize {
    let mut out = Vec::new();
    docs_model::write_str(&mut out, text);
    out.len() + r#"{"text":},"#.len()
}

/// `{"frame":[{"text":"..."},...]}`, every text escaped as JSON.
fn frame(nodes: &[String]) -> Vec<u8> {
    let mut out = br#"{"frame":["#.to_vec();
    for (at, node) in nodes.iter().enumerate() {
        if at > 0 {
            out.push(b',');
        }
        out.extend_from_slice(br#"{"text":"#);
        docs_model::write_str(&mut out, node);
        out.push(b'}');
    }
    out.extend_from_slice(b"]}");
    out
}

/// What to show for one message.
async fn nodes_for(uri: &str) -> Result<Vec<String>, BusError> {
    let Some(kind) = Kind::from_name(uri) else {
        return Ok(not_shown(uri, "is not a .md, .markdown or .txt document"));
    };
    let bytes = match read_document(uri).await? {
        Ok(bytes) => bytes,
        Err(why) => return Ok(not_shown(uri, &why)),
    };
    let text = match text::check_whole(&bytes) {
        Ok(text) => text,
        Err(_) => return Ok(not_shown(uri, "is not UTF-8 text")),
    };
    match docs_model::blocks(kind, text) {
        Ok(blocks) => Ok(document_nodes(&blocks)),
        Err(ModelError::TooLong) => Ok(not_shown(uri, "has too many blocks or spans")),
    }
}

impl exports::elastos::bus::lifecycle::Guest for Reader {
    async fn run(mut events: wit_bindgen::StreamReader<Event>) -> Result<(), BusError> {
        while let Some(event) = events.next().await {
            if let Event::Message(uri) = event {
                let uri = String::from_utf8(uri)
                    .map_err(|_| BusError::Invalid("a document URI is UTF-8".to_string()))?;
                let nodes = nodes_for(&uri).await?;
                ui::present(MEDIA_TYPE.to_string(), frame(&nodes)).await?;
            }
        }
        Ok(())
    }
}

export!(Reader);
