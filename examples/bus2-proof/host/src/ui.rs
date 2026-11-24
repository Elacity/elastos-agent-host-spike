//! `ui.present`: one typed document draws one frame.
//!
//! A string is text. An image is a grant this guest holds, with `read`, on
//! an object that is a PNG, JPEG, or WebP. There is no media type, no URI
//! in the document, no script, and no HTML. A new `present` replaces the
//! frame on screen.
//!
//! Bounds match the Runtime: 32 blocks, 64 spans, 32 list items, depth 2,
//! 1000 text bytes in one string, 16 KiB of text in one document.

use crate::elastos::bus::ui::{Block, Item, Nested, Span};
use crate::{BusError, HostState};

pub const MAX_BLOCKS: usize = 32;
pub const MAX_SPANS: usize = 64;
pub const MAX_ITEMS: usize = 32;
pub const MAX_DEPTH: usize = 2;
pub const MAX_TEXT_BYTES: usize = 1000;
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;

/// A drawn frame. Images name a grant and a resource, never the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub nodes: Vec<Node>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    pub style: String,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListItem {
    Spans(Vec<Piece>),
    Blocks(Vec<Node>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Heading {
        level: u8,
        spans: Vec<Piece>,
    },
    Paragraph {
        spans: Vec<Piece>,
    },
    Code {
        text: String,
    },
    Quote {
        paragraphs: Vec<Vec<Piece>>,
    },
    List {
        ordered: bool,
        items: Vec<ListItem>,
    },
    Rule,
    Image {
        grant: String,
        resource: String,
        alt: String,
    },
}

struct Counts {
    blocks: usize,
    spans: usize,
    items: usize,
    text: usize,
}

pub fn is_image(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"\xFF\xD8\xFF")
        || (bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP")
}

/// Checks a document and returns the frame it draws.
pub fn check_document(state: &HostState, document: &[Block]) -> Result<Frame, BusError> {
    if document.is_empty() || document.len() > MAX_BLOCKS {
        return Err(BusError::Invalid(format!(
            "a document has 1 to {MAX_BLOCKS} blocks"
        )));
    }
    let mut counts = Counts {
        blocks: 0,
        spans: 0,
        items: 0,
        text: 0,
    };
    let mut nodes = Vec::with_capacity(document.len());
    for block in document {
        nodes.push(check_block(state, block, 1, &mut counts)?);
    }
    Ok(Frame { nodes })
}

fn check_block(
    state: &HostState,
    block: &Block,
    depth: usize,
    counts: &mut Counts,
) -> Result<Node, BusError> {
    if depth > MAX_DEPTH {
        return Err(BusError::Invalid(format!("depth cap {MAX_DEPTH}")));
    }
    counts.blocks += 1;
    if counts.blocks > MAX_BLOCKS {
        return Err(BusError::Invalid(format!(
            "a document has at most {MAX_BLOCKS} blocks"
        )));
    }
    match block {
        Block::Heading((level, spans)) => {
            if !(1..=6).contains(level) {
                return Err(BusError::Invalid("a heading level is 1 to 6".into()));
            }
            Ok(Node::Heading {
                level: *level,
                spans: pieces(spans, counts)?,
            })
        }
        Block::Paragraph(spans) => Ok(Node::Paragraph {
            spans: pieces(spans, counts)?,
        }),
        Block::CodeBlock(text) => {
            count_text(text, counts)?;
            Ok(Node::Code { text: text.clone() })
        }
        Block::Quote(paragraphs) => {
            let mut out = Vec::with_capacity(paragraphs.len());
            for paragraph in paragraphs {
                out.push(pieces(paragraph, counts)?);
            }
            Ok(Node::Quote { paragraphs: out })
        }
        Block::List((ordered, items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                counts.items += 1;
                if counts.items > MAX_ITEMS {
                    return Err(BusError::Invalid(format!(
                        "a document has at most {MAX_ITEMS} list items"
                    )));
                }
                out.push(match item {
                    Item::Spans(spans) => ListItem::Spans(pieces(spans, counts)?),
                    Item::Blocks(blocks) => {
                        if depth == MAX_DEPTH {
                            return Err(BusError::Invalid(format!("depth cap {MAX_DEPTH}")));
                        }
                        let mut nested = Vec::with_capacity(blocks.len());
                        for block in blocks {
                            nested.push(check_nested(state, block, counts)?);
                        }
                        ListItem::Blocks(nested)
                    }
                });
            }
            Ok(Node::List {
                ordered: *ordered,
                items: out,
            })
        }
        Block::Rule => Ok(Node::Rule),
        Block::Image(image) => {
            count_text(&image.alt, counts)?;
            let resource = image_grant(state, &image.grant)?;
            Ok(Node::Image {
                grant: image.grant.clone(),
                resource,
                alt: image.alt.clone(),
            })
        }
    }
}

/// A block inside a list. Its own lists hold spans only.
fn check_nested(state: &HostState, block: &Nested, counts: &mut Counts) -> Result<Node, BusError> {
    counts.blocks += 1;
    if counts.blocks > MAX_BLOCKS {
        return Err(BusError::Invalid(format!(
            "a document has at most {MAX_BLOCKS} blocks"
        )));
    }
    match block {
        Nested::Heading((level, spans)) => {
            if !(1..=6).contains(level) {
                return Err(BusError::Invalid("a heading level is 1 to 6".into()));
            }
            Ok(Node::Heading {
                level: *level,
                spans: pieces(spans, counts)?,
            })
        }
        Nested::Paragraph(spans) => Ok(Node::Paragraph {
            spans: pieces(spans, counts)?,
        }),
        Nested::CodeBlock(text) => {
            count_text(text, counts)?;
            Ok(Node::Code { text: text.clone() })
        }
        Nested::Quote(paragraphs) => {
            let mut out = Vec::with_capacity(paragraphs.len());
            for paragraph in paragraphs {
                out.push(pieces(paragraph, counts)?);
            }
            Ok(Node::Quote { paragraphs: out })
        }
        Nested::List((ordered, items)) => {
            let mut out = Vec::with_capacity(items.len());
            for spans in items {
                counts.items += 1;
                if counts.items > MAX_ITEMS {
                    return Err(BusError::Invalid(format!(
                        "a document has at most {MAX_ITEMS} list items"
                    )));
                }
                out.push(ListItem::Spans(pieces(spans, counts)?));
            }
            Ok(Node::List {
                ordered: *ordered,
                items: out,
            })
        }
        Nested::Rule => Ok(Node::Rule),
        Nested::Image(image) => {
            count_text(&image.alt, counts)?;
            let resource = image_grant(state, &image.grant)?;
            Ok(Node::Image {
                grant: image.grant.clone(),
                resource,
                alt: image.alt.clone(),
            })
        }
    }
}

fn pieces(spans: &[Span], counts: &mut Counts) -> Result<Vec<Piece>, BusError> {
    let mut out = Vec::with_capacity(spans.len());
    for span in spans {
        counts.spans += 1;
        if counts.spans > MAX_SPANS {
            return Err(BusError::Invalid(format!(
                "a document has at most {MAX_SPANS} spans"
            )));
        }
        let (style, text) = match span {
            Span::Plain(text) => ("plain", text),
            Span::Strong(text) => ("strong", text),
            Span::Emphasis(text) => ("emphasis", text),
            Span::Code(text) => ("code", text),
        };
        count_text(text, counts)?;
        out.push(Piece {
            style: style.to_string(),
            text: text.clone(),
        });
    }
    Ok(out)
}

fn count_text(text: &str, counts: &mut Counts) -> Result<(), BusError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(BusError::Invalid(format!(
            "a text has at most {MAX_TEXT_BYTES} bytes"
        )));
    }
    counts.text += text.len();
    if counts.text > MAX_DOCUMENT_BYTES {
        return Err(BusError::Invalid(format!("size cap {MAX_DOCUMENT_BYTES}")));
    }
    Ok(())
}

fn image_grant(state: &HostState, id: &str) -> Result<String, BusError> {
    if id.is_empty() {
        return Err(BusError::Invalid("an image names a grant".into()));
    }
    if state.revoked.iter().any(|kept| kept == id) {
        return Err(BusError::Denied(format!("{id} was revoked")));
    }
    let grant = state
        .grants
        .iter()
        .find(|grant| grant.id == id)
        .ok_or_else(|| BusError::Denied(format!("{id} is not a grant this guest holds")))?;
    if !grant.actions.iter().any(|action| action == "read") {
        return Err(BusError::Denied(format!("{id} does not allow read")));
    }
    let object = state
        .objects
        .get(&grant.resource)
        .ok_or_else(|| BusError::NotFound(format!("no object {}", grant.resource)))?;
    if !is_image(&object.bytes) {
        return Err(BusError::Denied(format!(
            "{} is not a PNG, JPEG or WebP image",
            grant.resource
        )));
    }
    Ok(grant.resource.clone())
}
