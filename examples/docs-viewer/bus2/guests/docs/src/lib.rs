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
//! - draws one frame with `ui.present`, one typed block per model block.
//!
//! A refused grant or a denied read ends the run with its reason (pattern 1:
//! authority stops). A document that is not shown (the wrong kind, not text,
//! too long, a read that fails another way) gets a frame that says so, and
//! the reader goes on (content is skipped). It stops when its events close;
//! it does not look at `stop-requested`.

wit_bindgen::generate!({ path: "../../../../bus2-proof/wit", world: "product-capsule-v2" });

use docs_model::text;
use docs_model::{Block, Kind, ModelError, Span, Style};
use elastos::bus::types::{BusError, Event, InvokeRequest};
use elastos::bus::ui::{Block as UiBlock, Image, Item, Span as UiSpan};
use elastos::bus::{capabilities, providers, ui};
use wit_bindgen::StreamResult;

/// The same cap as the Bus v1 core (`examples/docs-viewer/src/lib.rs`).
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
/// Bytes the guest asks for per read of the stream.
const READ_BUFFER: usize = 16 * 1024;
/// What the proof host's `ui.present` takes (`bus2-proof/host/src/ui.rs`).
const MAX_NODES: usize = 32;
const MAX_TEXT_BYTES: usize = 1000;

struct Reader;

/// Why a document is not shown. Authority failures are not here: they end
/// the run.
fn not_shown(uri: &str, why: &str) -> Vec<UiBlock> {
    vec![paragraph(&format!("Not shown: {uri} {why}"))]
}

/// The whole object, a refusal that ends the run (`Err`), or one that only
/// means this document is not shown (`Ok(Err)`). Nothing partial is returned.
async fn read_document(uri: &str) -> Result<Result<(String, Vec<u8>), String>, BusError> {
    let grant = capabilities::request(
        uri.to_string(),
        vec!["read".to_string()],
        "show this document".to_string(),
    )
    .await?;
    let grant_id = grant.id.clone();
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
        Ok(()) => Ok(Ok((grant_id, bytes))),
        Err(BusError::Denied(why)) => Err(BusError::Denied(why)),
        Err(other) => Ok(Err(reason(&other))),
    }
}

fn reason(error: &BusError) -> String {
    match error {
        // Bus v2 names a conflict; it is not one of the read failures.
        BusError::Conflict(why) => format!("in conflict: {why}"),
        BusError::Denied(why)
        | BusError::NotFound(why)
        | BusError::Invalid(why)
        | BusError::Unavailable(why)
        | BusError::Timeout(why)
        | BusError::Internal(why) => format!("could not be read: {why}"),
    }
}

fn cut_bytes(text: &str) -> String {
    if text.len() <= MAX_TEXT_BYTES {
        return text.to_string();
    }
    let mark = "…";
    let mut end = MAX_TEXT_BYTES - mark.len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{mark}", &text[..end])
}

fn paragraph(text: &str) -> UiBlock {
    UiBlock::Paragraph(vec![UiSpan::Plain(cut_bytes(text))])
}

fn ui_spans(spans: &[Span]) -> Vec<UiSpan> {
    spans
        .iter()
        .map(|span| {
            let text = cut_bytes(&span.text);
            match span.style {
                Style::Plain => UiSpan::Plain(text),
                Style::Strong => UiSpan::Strong(text),
                Style::Em => UiSpan::Emphasis(text),
                Style::Code => UiSpan::Code(text),
            }
        })
        .collect()
}

fn ui_block(block: &Block) -> UiBlock {
    match block {
        Block::Heading { level, spans } => UiBlock::Heading((*level, ui_spans(spans))),
        Block::Paragraph { spans } => UiBlock::Paragraph(ui_spans(spans)),
        Block::Quote { spans } => UiBlock::Quote(vec![ui_spans(spans)]),
        Block::List { ordered, items } => UiBlock::List((
            *ordered,
            items
                .iter()
                .map(|item| Item::Spans(ui_spans(item)))
                .collect(),
        )),
        Block::Code { text } => UiBlock::CodeBlock(cut_bytes(text)),
        Block::Rule => UiBlock::Rule,
    }
}

/// A whole line `![alt](localhost://...)`. An http target stays text.
fn localhost_image(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("![")?;
    let (alt, after) = rest.split_once("](")?;
    let uri = after.strip_suffix(')')?;
    if alt.is_empty() || uri.len() <= "localhost://".len() || !uri.starts_with("localhost://") {
        return None;
    }
    if uri
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | ')'))
    {
        return None;
    }
    Some((alt.to_string(), uri.to_string()))
}

fn is_image(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"\xFF\xD8\xFF")
        || (bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP")
}

fn fit(mut blocks: Vec<UiBlock>) -> Vec<UiBlock> {
    if blocks.is_empty() {
        return vec![paragraph("(this document is empty)")];
    }
    if blocks.len() <= MAX_NODES {
        return blocks;
    }
    let left = blocks.len() - (MAX_NODES - 1);
    blocks.truncate(MAX_NODES - 1);
    blocks.push(paragraph(&format!(
        "… {left} more blocks are not shown: a frame holds {MAX_NODES} blocks"
    )));
    blocks
}

enum Segment {
    Text(String),
    Image { alt: String, uri: String },
}

fn segments(text: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut chunk = String::new();
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\n', '\r']);
        if let Some((alt, uri)) = localhost_image(bare) {
            if !chunk.is_empty() {
                out.push(Segment::Text(std::mem::take(&mut chunk)));
            }
            out.push(Segment::Image { alt, uri });
        } else {
            chunk.push_str(line);
        }
    }
    if !chunk.is_empty() {
        out.push(Segment::Text(chunk));
    }
    out
}

fn parse_chunk(kind: Kind, text: &str) -> Result<Vec<UiBlock>, ModelError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    Ok(docs_model::blocks(kind, text)?
        .iter()
        .map(ui_block)
        .collect())
}

/// What to show for one message.
async fn nodes_for(uri: &str) -> Result<Vec<UiBlock>, BusError> {
    let Some(kind) = Kind::from_name(uri) else {
        return Ok(not_shown(uri, "is not a .md, .markdown or .txt document"));
    };
    let bytes = match read_document(uri).await? {
        Ok((_grant, bytes)) => bytes,
        Err(why) => return Ok(not_shown(uri, &why)),
    };
    let text = match text::check_whole(&bytes) {
        Ok(text) => text,
        Err(_) => return Ok(not_shown(uri, "is not UTF-8 text")),
    };
    let mut blocks = Vec::new();
    for segment in segments(text) {
        match segment {
            Segment::Text(chunk) => match parse_chunk(kind, &chunk) {
                Ok(parsed) => blocks.extend(parsed),
                Err(ModelError::TooLong) => {
                    return Ok(not_shown(uri, "has too many blocks or spans"));
                }
            },
            Segment::Image { alt, uri: image } => match read_document(&image).await? {
                Ok((grant, bytes)) if is_image(&bytes) => {
                    blocks.push(UiBlock::Image(Image { grant, alt }));
                }
                Ok(_) => blocks.extend(not_shown(&image, "is not an image")),
                Err(why) => blocks.extend(not_shown(&image, &why)),
            },
        }
    }
    Ok(fit(blocks))
}

impl exports::elastos::bus::lifecycle::Guest for Reader {
    async fn run(mut events: wit_bindgen::StreamReader<Event>) -> Result<(), BusError> {
        while let Some(event) = events.next().await {
            if let Event::Message(uri) = event {
                let uri = String::from_utf8(uri)
                    .map_err(|_| BusError::Invalid("a document URI is UTF-8".to_string()))?;
                let nodes = nodes_for(&uri).await?;
                ui::present(nodes).await?;
            }
        }
        Ok(())
    }
}

export!(Reader);
