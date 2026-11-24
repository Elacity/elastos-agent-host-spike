//! Typed UI document. The guest sends blocks. The host stores blocks.
//!
//! There is no media type and no document JSON, so there is no key scan and
//! no blocklist. A string is text. An image is a grant id. Script, a URI,
//! and raw bytes are not values of this type.
//!
//! Bounds: 32 blocks, 64 spans, 32 list items, depth 2, 1000 text bytes in
//! one string, 16 KiB of text in one document. Depth 1 is the document. A
//! list item's blocks are depth 2. A list at depth 2 holds spans only.

use serde_json::{json, Value};

pub const MAX_BLOCKS: usize = 32;
pub const MAX_SPANS: usize = 64;
pub const MAX_ITEMS: usize = 32;
pub const MAX_DEPTH: usize = 2;
pub const MAX_TEXT_BYTES: usize = 1000;
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Span {
    Plain(String),
    Strong(String),
    Emphasis(String),
    Code(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Spans(Vec<Span>),
    Blocks(Vec<Block>),
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
    Code {
        text: String,
    },
    Quote {
        paragraphs: Vec<Vec<Span>>,
    },
    List {
        ordered: bool,
        items: Vec<Item>,
    },
    Rule,
    Image {
        grant: String,
        alt: String,
        resource: String,
        empty: bool,
        expires_at_ms: Option<u64>,
    },
}

impl Block {
    pub fn text(text: impl Into<String>) -> Self {
        Block::Paragraph {
            spans: vec![Span::Plain(text.into())],
        }
    }

    pub fn image(grant: impl Into<String>, resource: impl Into<String>) -> Self {
        Block::Image {
            grant: grant.into(),
            alt: String::new(),
            resource: resource.into(),
            empty: false,
            expires_at_ms: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub nodes: Vec<Block>,
}

const MAX_REVOKED_GRANTS: usize = 32;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantBook {
    grants: Vec<HeldGrant>,
    revoked: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HeldGrant {
    id: String,
    resource: String,
    actions: Vec<String>,
    image: bool,
    expires_at_ms: Option<u64>,
}

impl GrantBook {
    pub fn hold(&mut self, id: &str, resource: &str, action: &str) {
        self.hold_until(id, resource, action, None);
    }

    pub fn hold_until(
        &mut self,
        id: &str,
        resource: &str,
        action: &str,
        expires_at_ms: Option<u64>,
    ) {
        self.revoked.retain(|kept| kept != id);
        if let Some(grant) = self.grants.iter_mut().find(|grant| grant.id == id) {
            grant.expires_at_ms = expires_at_ms;
            return;
        }
        self.grants.push(HeldGrant {
            id: id.to_string(),
            resource: resource.to_string(),
            actions: vec![action.to_string()],
            image: false,
            expires_at_ms,
        });
    }

    /// The bytes of a read this guest finished. An image is PNG, JPEG, or WebP.
    pub fn note_bytes(&mut self, id: &str, bytes: &[u8]) {
        if let Some(grant) = self.grants.iter_mut().find(|grant| grant.id == id) {
            grant.image = is_image(bytes);
        }
    }

    pub fn revoke(&mut self, id: &str) {
        let Some(pos) = self.grants.iter().position(|grant| grant.id == id) else {
            return;
        };
        self.grants.remove(pos);
        if self.revoked.iter().any(|kept| kept == id) {
            return;
        }
        if self.revoked.len() == MAX_REVOKED_GRANTS {
            self.revoked.remove(0);
        }
        self.revoked.push(id.to_string());
    }

    pub fn due(&self, now_ms: u64) -> Vec<String> {
        self.grants
            .iter()
            .filter(|grant| grant.expires_at_ms.is_some_and(|at| now_ms >= at))
            .map(|grant| grant.id.clone())
            .collect()
    }

    pub fn clear(&mut self) {
        self.grants.clear();
        self.revoked.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    #[cfg(test)]
    fn grant_slots(&self) -> usize {
        self.grants.len() + self.revoked.len()
    }
}

pub fn is_image(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"\xFF\xD8\xFF")
        || (bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP")
}

#[derive(Debug)]
pub enum PresentError {
    Invalid(String),
    Denied(String),
}

struct Counts {
    blocks: usize,
    spans: usize,
    items: usize,
    text: usize,
}

/// Checks one document and fills each image from a grant this guest holds.
pub fn present_blocks(
    blocks: Vec<Block>,
    book: &GrantBook,
    now_ms: u64,
) -> Result<Frame, PresentError> {
    if blocks.is_empty() || blocks.len() > MAX_BLOCKS {
        return Err(PresentError::Invalid(format!(
            "a document has 1 to {MAX_BLOCKS} blocks"
        )));
    }
    let mut counts = Counts {
        blocks: 0,
        spans: 0,
        items: 0,
        text: 0,
    };
    let mut out = Vec::with_capacity(blocks.len());
    for block in blocks {
        out.push(check_block(block, 1, book, now_ms, &mut counts)?);
    }
    Ok(Frame { nodes: out })
}

fn check_block(
    block: Block,
    depth: usize,
    book: &GrantBook,
    now_ms: u64,
    counts: &mut Counts,
) -> Result<Block, PresentError> {
    if depth > MAX_DEPTH {
        return Err(PresentError::Invalid(format!("depth cap {MAX_DEPTH}")));
    }
    counts.blocks += 1;
    if counts.blocks > MAX_BLOCKS {
        return Err(PresentError::Invalid(format!(
            "a document has at most {MAX_BLOCKS} blocks"
        )));
    }
    match block {
        Block::Heading { level, spans } => {
            if !(1..=6).contains(&level) {
                return Err(PresentError::Invalid("a heading level is 1 to 6".into()));
            }
            Ok(Block::Heading {
                level,
                spans: check_spans(spans, counts)?,
            })
        }
        Block::Paragraph { spans } => Ok(Block::Paragraph {
            spans: check_spans(spans, counts)?,
        }),
        Block::Code { text } => {
            count_text(&text, counts)?;
            Ok(Block::Code { text })
        }
        Block::Quote { paragraphs } => {
            let mut out = Vec::with_capacity(paragraphs.len());
            for paragraph in paragraphs {
                out.push(check_spans(paragraph, counts)?);
            }
            Ok(Block::Quote { paragraphs: out })
        }
        Block::List { ordered, items } => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                counts.items += 1;
                if counts.items > MAX_ITEMS {
                    return Err(PresentError::Invalid(format!(
                        "a document has at most {MAX_ITEMS} list items"
                    )));
                }
                out.push(match item {
                    Item::Spans(spans) => Item::Spans(check_spans(spans, counts)?),
                    Item::Blocks(blocks) => {
                        if depth == MAX_DEPTH {
                            return Err(PresentError::Invalid(format!("depth cap {MAX_DEPTH}")));
                        }
                        let mut nested = Vec::with_capacity(blocks.len());
                        for block in blocks {
                            nested.push(check_block(block, depth + 1, book, now_ms, counts)?);
                        }
                        Item::Blocks(nested)
                    }
                });
            }
            Ok(Block::List {
                ordered,
                items: out,
            })
        }
        Block::Rule => Ok(Block::Rule),
        Block::Image { grant, alt, .. } => {
            count_text(&alt, counts)?;
            let (resource, expires_at_ms) = image_grant(&grant, book, now_ms)?;
            Ok(Block::Image {
                grant,
                alt,
                resource,
                empty: false,
                expires_at_ms,
            })
        }
    }
}

fn check_spans(spans: Vec<Span>, counts: &mut Counts) -> Result<Vec<Span>, PresentError> {
    for span in &spans {
        counts.spans += 1;
        if counts.spans > MAX_SPANS {
            return Err(PresentError::Invalid(format!(
                "a document has at most {MAX_SPANS} spans"
            )));
        }
        count_text(span_text(span), counts)?;
    }
    Ok(spans)
}

fn span_text(span: &Span) -> &str {
    match span {
        Span::Plain(text) | Span::Strong(text) | Span::Emphasis(text) | Span::Code(text) => text,
    }
}

fn count_text(text: &str, counts: &mut Counts) -> Result<(), PresentError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(PresentError::Invalid(format!(
            "a text has at most {MAX_TEXT_BYTES} bytes"
        )));
    }
    counts.text += text.len();
    if counts.text > MAX_DOCUMENT_BYTES {
        return Err(PresentError::Invalid(format!(
            "size cap {MAX_DOCUMENT_BYTES}"
        )));
    }
    Ok(())
}

fn image_grant(
    grant: &str,
    book: &GrantBook,
    now_ms: u64,
) -> Result<(String, Option<u64>), PresentError> {
    if grant.is_empty() {
        return Err(PresentError::Invalid("an image names a grant".into()));
    }
    if book.revoked.iter().any(|id| id == grant) {
        return Err(PresentError::Denied(format!("{grant} was revoked")));
    }
    let Some(held) = book.grants.iter().find(|item| item.id == grant) else {
        if book.revoked.len() == MAX_REVOKED_GRANTS {
            return Err(PresentError::Denied(format!(
                "{grant} is not among the {MAX_REVOKED_GRANTS} revokes still recorded"
            )));
        }
        return Err(PresentError::Denied(format!(
            "{grant} is not a grant this guest holds"
        )));
    };
    if !held.actions.iter().any(|action| action == "read") {
        return Err(PresentError::Denied(format!("{grant} does not allow read")));
    }
    if held.expires_at_ms.is_some_and(|at| now_ms >= at) {
        return Err(PresentError::Denied(format!("{grant} expired")));
    }
    if !held.image {
        return Err(PresentError::Denied(format!(
            "{} is not an image",
            held.resource
        )));
    }
    Ok((held.resource.clone(), held.expires_at_ms))
}

/// The named place stays. The picture is gone.
pub fn blank_grant(frame: &mut Frame, grant: &str) -> bool {
    let mut hit = false;
    blank_nodes(&mut frame.nodes, &mut |image_grant, empty| {
        if image_grant == grant && !*empty {
            *empty = true;
            hit = true;
        }
    });
    hit
}

/// An image whose grant time has passed becomes a named empty place.
pub fn blank_expired(frame: &mut Frame, now_ms: u64) -> Vec<String> {
    let mut due = Vec::new();
    fn walk(nodes: &mut [Block], now_ms: u64, due: &mut Vec<String>) {
        for node in nodes {
            match node {
                Block::List { items, .. } => {
                    for item in items {
                        if let Item::Blocks(nested) = item {
                            walk(nested, now_ms, due);
                        }
                    }
                }
                Block::Image {
                    grant,
                    empty,
                    expires_at_ms,
                    ..
                } if expires_at_ms.is_some_and(|at| now_ms >= at) && !*empty => {
                    *empty = true;
                    due.push(grant.clone());
                }
                _ => {}
            }
        }
    }
    walk(&mut frame.nodes, now_ms, &mut due);
    due
}

fn blank_nodes(nodes: &mut [Block], hit: &mut dyn FnMut(&str, &mut bool)) {
    for node in nodes {
        match node {
            Block::List { items, .. } => {
                for item in items {
                    if let Item::Blocks(nested) = item {
                        blank_nodes(nested, hit);
                    }
                }
            }
            Block::Image { grant, empty, .. } => hit(grant, empty),
            _ => {}
        }
    }
}

pub fn image_grant_ids(frame: &Frame) -> Vec<String> {
    let mut ids = Vec::new();
    fn walk(nodes: &[Block], ids: &mut Vec<String>) {
        for node in nodes {
            match node {
                Block::List { items, .. } => {
                    for item in items {
                        if let Item::Blocks(nested) = item {
                            walk(nested, ids);
                        }
                    }
                }
                Block::Image { grant, empty, .. } if !empty && !grant.is_empty() => {
                    ids.push(grant.clone());
                }
                _ => {}
            }
        }
    }
    walk(&frame.nodes, &mut ids);
    ids
}

/// Home's frame. No grant id and no image bytes.
pub fn encode_frame(nodes: &[Block]) -> Vec<u8> {
    serde_json::to_vec(&json!({ "nodes": nodes.iter().map(encode_block).collect::<Vec<_>>() }))
        .unwrap_or_else(|_| b"{\"nodes\":[]}".to_vec())
}

fn encode_block(block: &Block) -> Value {
    match block {
        Block::Heading { level, spans } => json!({
            "kind": "heading",
            "level": level,
            "spans": encode_spans(spans),
        }),
        Block::Paragraph { spans } => json!({ "kind": "paragraph", "spans": encode_spans(spans) }),
        Block::Code { text } => json!({ "kind": "code", "text": text }),
        Block::Quote { paragraphs } => json!({
            "kind": "quote",
            "paragraphs": paragraphs.iter().map(|spans| encode_spans(spans)).collect::<Vec<_>>(),
        }),
        Block::List { ordered, items } => json!({
            "kind": "list",
            "ordered": ordered,
            "items": items.iter().map(encode_item).collect::<Vec<_>>(),
        }),
        Block::Rule => json!({ "kind": "rule" }),
        Block::Image {
            resource,
            alt,
            empty,
            ..
        } => json!({
            "kind": "image",
            "resource": resource,
            "alt": alt,
            "empty": empty,
        }),
    }
}

fn encode_spans(spans: &[Span]) -> Vec<Value> {
    spans
        .iter()
        .map(|span| {
            let (style, text) = match span {
                Span::Plain(text) => ("plain", text),
                Span::Strong(text) => ("strong", text),
                Span::Emphasis(text) => ("emphasis", text),
                Span::Code(text) => ("code", text),
            };
            json!({ "style": style, "text": text })
        })
        .collect()
}

fn encode_item(item: &Item) -> Value {
    match item {
        Item::Spans(spans) => json!({ "spans": encode_spans(spans) }),
        Item::Blocks(blocks) => {
            json!({ "blocks": blocks.iter().map(encode_block).collect::<Vec<_>>() })
        }
    }
}

/// A Home answer. One bad node refuses the whole answer. Grant ids are not a field.
pub fn accept_frame(bytes: &[u8], max: usize) -> Vec<Value> {
    if bytes.len() > max {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    if object.len() != 1 {
        return Vec::new();
    }
    let Some(nodes) = object.get("nodes").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for node in nodes {
        let Some(clean) = clean_block(node, 1) else {
            return Vec::new();
        };
        out.push(clean);
    }
    out
}

fn clean_block(value: &Value, depth: usize) -> Option<Value> {
    if depth > MAX_DEPTH {
        return None;
    }
    let object = value.as_object()?;
    let kind = object.get("kind")?.as_str()?;
    match kind {
        "heading" if object.len() == 3 => {
            let level = object.get("level")?.as_u64()?;
            if !(1..=6).contains(&level) {
                return None;
            }
            Some(json!({
                "kind": "heading",
                "level": level,
                "spans": clean_spans(object.get("spans")?)?,
            }))
        }
        "paragraph" if object.len() == 2 => Some(json!({
            "kind": "paragraph",
            "spans": clean_spans(object.get("spans")?)?,
        })),
        "code" if object.len() == 2 => Some(json!({
            "kind": "code",
            "text": object.get("text")?.as_str()?,
        })),
        "quote" if object.len() == 2 => {
            let paragraphs = object.get("paragraphs")?.as_array()?;
            let mut clean = Vec::new();
            for paragraph in paragraphs {
                clean.push(clean_spans(paragraph)?);
            }
            Some(json!({ "kind": "quote", "paragraphs": clean }))
        }
        "list" if object.len() == 3 => {
            if !object.get("ordered")?.is_boolean() {
                return None;
            }
            let items = object.get("items")?.as_array()?;
            let mut clean = Vec::new();
            for item in items {
                clean.push(clean_item(item, depth)?);
            }
            Some(json!({
                "kind": "list",
                "ordered": object.get("ordered")?.as_bool()?,
                "items": clean,
            }))
        }
        "rule" if object.len() == 1 => Some(json!({ "kind": "rule" })),
        "image" if object.len() == 4 => {
            if !object.get("empty")?.is_boolean() {
                return None;
            }
            Some(json!({
                "kind": "image",
                "resource": object.get("resource")?.as_str()?,
                "alt": object.get("alt")?.as_str()?,
                "empty": object.get("empty")?.as_bool()?,
            }))
        }
        _ => None,
    }
}

fn clean_spans(value: &Value) -> Option<Vec<Value>> {
    let spans = value.as_array()?;
    let mut out = Vec::new();
    for span in spans {
        let object = span.as_object()?;
        if object.len() != 2 {
            return None;
        }
        let style = object.get("style")?.as_str()?;
        if !matches!(style, "plain" | "strong" | "emphasis" | "code") {
            return None;
        }
        out.push(json!({
            "style": style,
            "text": object.get("text")?.as_str()?,
        }));
    }
    Some(out)
}

fn clean_item(value: &Value, depth: usize) -> Option<Value> {
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    if let Some(spans) = object.get("spans") {
        return Some(json!({ "spans": clean_spans(spans)? }));
    }
    let blocks = object.get("blocks")?.as_array()?;
    let mut nested = Vec::new();
    for block in blocks {
        nested.push(clean_block(block, depth + 1)?);
    }
    Some(json!({ "blocks": nested }))
}

/// Wall time when the test clock is unset. `0` on the provider clock means this.
pub fn host_now(set: u64) -> u64 {
    if set != 0 {
        return set;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn book_with_photo() -> (GrantBook, &'static str) {
        let mut book = GrantBook::default();
        let photo = "localhost://Users/self/Pictures/a.png";
        book.hold("g1", photo, "read");
        book.note_bytes("g1", b"\x89PNG\r\n\x1a\n");
        (book, photo)
    }

    #[test]
    fn a_script_shaped_string_is_text() {
        let (book, _) = book_with_photo();
        let frame =
            present_blocks(vec![Block::text("<script>alert(1)</script>")], &book, 0).unwrap();
        assert_eq!(frame.nodes, vec![Block::text("<script>alert(1)</script>")]);
        let answer = encode_frame(&frame.nodes);
        let accepted = accept_frame(&answer, 48 * 1024);
        assert_eq!(accepted[0]["spans"][0]["text"], "<script>alert(1)</script>");
        let mut with_grant = serde_json::from_slice::<Value>(&answer).unwrap();
        with_grant["nodes"][0]["grant"] = json!("g1");
        assert!(accept_frame(&serde_json::to_vec(&with_grant).unwrap(), 48 * 1024).is_empty());
    }

    #[test]
    fn an_image_needs_a_read_grant_on_an_image() {
        let (mut book, photo) = book_with_photo();
        book.hold("g-write", photo, "write");
        book.hold(
            "g-text",
            "localhost://Users/self/Documents/note.txt",
            "read",
        );
        book.note_bytes("g-text", b"note");
        book.hold_until("g-old", photo, "read", Some(5));
        book.note_bytes("g-old", b"\x89PNG\r\n\x1a\n");
        let now = 10;
        let show = present_blocks(vec![Block::image("g1", "")], &book, now).unwrap();
        assert_eq!(show.nodes, vec![Block::image("g1", photo)]);
        let missing = present_blocks(vec![Block::image("g-missing", "")], &book, now).unwrap_err();
        assert!(
            matches!(missing, PresentError::Denied(ref message) if message.contains("not a grant"))
        );
        book.revoke("g1");
        let revoked = present_blocks(vec![Block::image("g1", "")], &book, now).unwrap_err();
        assert!(
            matches!(revoked, PresentError::Denied(ref message) if message.contains("was revoked"))
        );
        let write = present_blocks(vec![Block::image("g-write", "")], &book, now).unwrap_err();
        assert!(
            matches!(write, PresentError::Denied(ref message) if message.contains("does not allow read"))
        );
        let text = present_blocks(vec![Block::image("g-text", "")], &book, now).unwrap_err();
        assert!(
            matches!(text, PresentError::Denied(ref message) if message.contains("is not an image"))
        );
        let expired = present_blocks(vec![Block::image("g-old", "")], &book, now).unwrap_err();
        assert!(
            matches!(expired, PresentError::Denied(ref message) if message.contains("expired"))
        );
    }

    #[test]
    fn revoke_and_expiry_leave_a_named_empty_place() {
        let mut frame = Frame {
            nodes: vec![
                Block::text("stay"),
                Block::Image {
                    grant: "g1".into(),
                    alt: "a cat".into(),
                    resource: "localhost://Users/self/Pictures/a.png".into(),
                    empty: false,
                    expires_at_ms: Some(10),
                },
            ],
        };
        assert!(blank_grant(&mut frame, "g1"));
        match &frame.nodes[1] {
            Block::Image {
                empty,
                alt,
                resource,
                ..
            } => {
                assert!(*empty);
                assert_eq!(alt, "a cat");
                assert_eq!(resource, "localhost://Users/self/Pictures/a.png");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(frame.nodes[0], Block::text("stay"));
        frame.nodes[1] = Block::Image {
            grant: "g1".into(),
            alt: "a cat".into(),
            resource: "localhost://Users/self/Pictures/a.png".into(),
            empty: false,
            expires_at_ms: Some(10),
        };
        assert_eq!(blank_expired(&mut frame, 10), vec!["g1".to_string()]);
        assert!(matches!(frame.nodes[1], Block::Image { empty: true, .. }));
    }

    #[test]
    fn bounds_refuse_depth_size_and_level() {
        let (book, _) = book_with_photo();
        let deep = Block::List {
            ordered: false,
            items: vec![Item::Blocks(vec![Block::List {
                ordered: false,
                items: vec![Item::Blocks(vec![Block::text("too deep")])],
            }])],
        };
        let err = present_blocks(vec![deep], &book, 0).unwrap_err();
        assert!(matches!(err, PresentError::Invalid(ref message) if message.contains("depth cap")));
        let err = present_blocks(vec![Block::text("x".repeat(MAX_TEXT_BYTES + 1))], &book, 0)
            .unwrap_err();
        assert!(matches!(err, PresentError::Invalid(ref message) if message.contains("1000")));
        let err = present_blocks(
            vec![Block::Heading {
                level: 0,
                spans: vec![Span::Plain("x".into())],
            }],
            &book,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PresentError::Invalid(ref message) if message.contains("1 to 6")));
        let mut book = GrantBook::default();
        for n in 0..40 {
            let id = format!("g{n}");
            book.hold(&id, "localhost://Users/self/Pictures/a.png", "read");
            book.note_bytes(&id, b"\x89PNG\r\n\x1a\n");
            book.revoke(&id);
        }
        assert!(book.grant_slots() <= 32);
        let latest = present_blocks(vec![Block::image("g39", "")], &book, 0).unwrap_err();
        assert!(
            matches!(latest, PresentError::Denied(ref message) if message.contains("was revoked")),
            "{latest:?}"
        );
        let oldest = present_blocks(vec![Block::image("g0", "")], &book, 0).unwrap_err();
        assert!(
            matches!(oldest, PresentError::Denied(ref message) if message.contains("not among the 32")),
            "{oldest:?}"
        );
    }
}
