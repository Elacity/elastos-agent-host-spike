//! The documents model, shared by the Bus v1 core and the Bus v2 guest.
//!
//! Pure logic, no I/O: it checks that bytes are text ([`text`]) and turns a
//! document into typed blocks ([`markdown`]). A block holds text only. There
//! is no HTML, no link target the surface could follow, and no image source:
//! a link keeps its label and shows its target as text, and an image becomes
//! the text `[image: alt]`. The surface draws blocks with `textContent`, so
//! nothing in a document can become markup or a request.

pub mod markdown;

/// Is this text: the capsule kit's check, shared with every guest.
pub use capsule_kit_guest::text;

use serde_json::{json, Value};

/// The most blocks one document may have.
pub const MAX_BLOCKS: usize = 512;
/// The most spans one block (or one list item) may have.
pub const MAX_SPANS: usize = 256;
/// The most items one list may have.
pub const MAX_LIST_ITEMS: usize = 256;
/// The longest title, in characters.
pub const MAX_TITLE_CHARS: usize = 120;

/// How a run of text is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Plain,
    Strong,
    Em,
    Code,
}

impl Style {
    pub fn name(self) -> &'static str {
        match self {
            Style::Plain => "plain",
            Style::Strong => "strong",
            Style::Em => "em",
            Style::Code => "code",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub style: Style,
    pub text: String,
}

impl Span {
    pub fn plain(text: impl Into<String>) -> Span {
        Span {
            style: Style::Plain,
            text: text.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    Heading {
        level: u8,
        spans: Vec<Span>,
    },
    Paragraph {
        spans: Vec<Span>,
    },
    List {
        ordered: bool,
        items: Vec<Vec<Span>>,
    },
    Code {
        text: String,
    },
    Quote {
        spans: Vec<Span>,
    },
    Rule,
}

/// Why a document cannot be shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelError {
    /// More than [`MAX_BLOCKS`] blocks, [`MAX_SPANS`] spans or
    /// [`MAX_LIST_ITEMS`] items.
    TooLong,
}

/// The kind of document, from its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Markdown,
    Text,
}

impl Kind {
    /// `.md` and `.markdown` are markdown, `.txt` is text; anything else is
    /// not a document this viewer shows.
    pub fn from_name(name: &str) -> Option<Kind> {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".md") || lower.ends_with(".markdown") {
            Some(Kind::Markdown)
        } else if lower.ends_with(".txt") {
            Some(Kind::Text)
        } else {
            None
        }
    }

    pub fn mime(self) -> &'static str {
        match self {
            Kind::Markdown => "text/markdown",
            Kind::Text => "text/plain",
        }
    }
}

/// Turns checked text into blocks: markdown is parsed, plain text becomes
/// one paragraph per blank-line-separated run, line breaks kept.
pub fn blocks(kind: Kind, text: &str) -> Result<Vec<Block>, ModelError> {
    match kind {
        Kind::Markdown => markdown::parse(text),
        Kind::Text => plain_blocks(text),
    }
}

fn plain_blocks(text: &str) -> Result<Vec<Block>, ModelError> {
    let mut blocks = Vec::new();
    let mut lines: Vec<&str> = Vec::new();
    let flush = |lines: &mut Vec<&str>, blocks: &mut Vec<Block>| -> Result<(), ModelError> {
        if !lines.is_empty() {
            push(
                blocks,
                Block::Paragraph {
                    spans: vec![Span::plain(lines.join("\n"))],
                },
            )?;
            lines.clear();
        }
        Ok(())
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            flush(&mut lines, &mut blocks)?;
        } else {
            lines.push(line.trim_end());
        }
    }
    flush(&mut lines, &mut blocks)?;
    Ok(blocks)
}

pub(crate) fn push(blocks: &mut Vec<Block>, block: Block) -> Result<(), ModelError> {
    if blocks.len() >= MAX_BLOCKS {
        return Err(ModelError::TooLong);
    }
    blocks.push(block);
    Ok(())
}

/// The title: the first heading, else the first line of text, else `fallback`;
/// at most [`MAX_TITLE_CHARS`] characters.
pub fn title(blocks: &[Block], fallback: &str) -> String {
    let heading = blocks.iter().find_map(|block| match block {
        Block::Heading { spans, .. } => Some(spans_text(spans)),
        _ => None,
    });
    let first = || {
        blocks.iter().find_map(|block| match block {
            Block::Paragraph { spans } | Block::Quote { spans } => {
                spans_text(spans).lines().next().map(str::to_string)
            }
            _ => None,
        })
    };
    let text = heading
        .or_else(first)
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| fallback.to_string());
    cut(&text, MAX_TITLE_CHARS)
}

fn spans_text(spans: &[Span]) -> String {
    spans.iter().map(|span| span.text.as_str()).collect()
}

pub fn cut(text: &str, chars: usize) -> String {
    if text.chars().count() <= chars {
        text.to_string()
    } else {
        let mut cut: String = text.chars().take(chars).collect();
        cut.push('…');
        cut
    }
}

fn spans_json(spans: &[Span]) -> Value {
    Value::Array(
        spans
            .iter()
            .map(|span| json!({ "style": span.style.name(), "text": span.text }))
            .collect(),
    )
}

/// One block as JSON. Keys are sorted (`serde_json` default map).
pub fn block_json(block: &Block) -> Value {
    match block {
        Block::Heading { level, spans } => {
            json!({ "kind": "heading", "level": level, "spans": spans_json(spans) })
        }
        Block::Paragraph { spans } => json!({ "kind": "paragraph", "spans": spans_json(spans) }),
        Block::List { ordered, items } => json!({
            "kind": "list",
            "ordered": ordered,
            "items": items.iter().map(|item| spans_json(item)).collect::<Vec<_>>(),
        }),
        Block::Code { text } => json!({ "kind": "code", "text": text }),
        Block::Quote { spans } => json!({ "kind": "quote", "spans": spans_json(spans) }),
        Block::Rule => json!({ "kind": "rule" }),
    }
}

/// Writes `text` as a JSON string, escaped exactly as `serde_json` does.
pub fn write_str(out: &mut Vec<u8>, text: &str) {
    serde_json::to_writer(&mut *out, text).expect("a string always serializes");
}

fn write_spans(out: &mut Vec<u8>, spans: &[Span]) {
    out.push(b'[');
    for (index, span) in spans.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(br#"{"style":""#);
        out.extend_from_slice(span.style.name().as_bytes());
        out.extend_from_slice(br#"","text":"#);
        write_str(out, &span.text);
        out.push(b'}');
    }
    out.push(b']');
}

/// One block as JSON, straight into `out`: the same bytes as
/// `block_json(block).to_string()`, without building a `Value` per span,
/// which costs too much fuel on Bus v1.
pub fn write_block(out: &mut Vec<u8>, block: &Block) {
    match block {
        Block::Heading { level, spans } => {
            out.extend_from_slice(br#"{"kind":"heading","level":"#);
            out.extend_from_slice(level.to_string().as_bytes());
            out.extend_from_slice(br#","spans":"#);
            write_spans(out, spans);
            out.push(b'}');
        }
        Block::Paragraph { spans } | Block::Quote { spans } => {
            let kind: &[u8] = if matches!(block, Block::Paragraph { .. }) {
                br#"{"kind":"paragraph","spans":"#
            } else {
                br#"{"kind":"quote","spans":"#
            };
            out.extend_from_slice(kind);
            write_spans(out, spans);
            out.push(b'}');
        }
        Block::List { ordered, items } => {
            out.extend_from_slice(br#"{"items":["#);
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_spans(out, item);
            }
            out.extend_from_slice(br#"],"kind":"list","ordered":"#);
            out.extend_from_slice(if *ordered { b"true" } else { b"false" });
            out.push(b'}');
        }
        Block::Code { text } => {
            out.extend_from_slice(br#"{"kind":"code","text":"#);
            write_str(out, text);
            out.push(b'}');
        }
        Block::Rule => out.extend_from_slice(br#"{"kind":"rule"}"#),
    }
}

#[cfg(test)]
mod tests;
