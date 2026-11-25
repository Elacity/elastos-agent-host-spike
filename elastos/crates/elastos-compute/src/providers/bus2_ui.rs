//! UI document check. One pure function. It does not see a grant or a host.
//!
//! Media type `application/vnd.elastos.ui+json;v=0`. A document is
//! `{"frame":[node, ...]}`. A node is `{"text":"..."}` or
//! `{"image":{"grant":"..."}}`. Script, a handler, a URI, and raw bytes are
//! refused by name. The size cap is checked before JSON, and the depth cap
//! before a key, so those refusals stay the ones named here.

use serde_json::Value;

pub const UI_MEDIA_TYPE: &str = "application/vnd.elastos.ui+json;v=0";
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
pub const MAX_NODES: usize = 32;
pub const MAX_TEXT_CHARS: usize = 1000;
/// A drawn image document is four containers deep. Eight still fits that
/// shape and stops a nested document.
pub const MAX_DEPTH: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Text(String),
    Image { grant: String },
}

/// `None` accepts a known key. Script, a handler, a URI, bytes, and any other
/// key are refused.
fn refused_key(key: &str) -> Option<&'static str> {
    let lower = key.to_ascii_lowercase();
    if lower == "script" || lower.starts_with("on") {
        return Some("scripts and event handlers are not allowed");
    }
    if matches!(
        lower.as_str(),
        "html" | "src" | "url" | "uri" | "href" | "bytes" | "data"
    ) {
        return Some("images are named by a grant, never by a URI or bytes");
    }
    if matches!(lower.as_str(), "frame" | "text" | "image" | "grant") {
        return None;
    }
    Some("unknown key")
}

fn walk(value: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("depth cap {MAX_DEPTH}"));
    }
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                if let Some(why) = refused_key(key) {
                    return Err(format!("key {key:?}: {why}"));
                }
                walk(inner, depth + 1)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                walk(item, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn one_node(value: &Value) -> Result<Node, String> {
    let object = value.as_object().ok_or("a node is an object")?;
    let text = object.contains_key("text");
    let image = object.contains_key("image");
    if text == image || object.len() != 1 {
        return Err("a node is text or an image, with no other keys".to_string());
    }
    if text {
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .ok_or("text is a string")?;
        if text.chars().count() > MAX_TEXT_CHARS {
            return Err(format!(
                "a text node has at most {MAX_TEXT_CHARS} characters"
            ));
        }
        return Ok(Node::Text(text.to_string()));
    }
    let image = object
        .get("image")
        .and_then(Value::as_object)
        .ok_or("an image names a grant")?;
    if image.len() != 1 {
        return Err("an image names a grant, with no other keys".to_string());
    }
    let grant = image
        .get("grant")
        .and_then(Value::as_str)
        .filter(|grant| !grant.is_empty())
        .ok_or("an image names a grant")?;
    Ok(Node::Image {
        grant: grant.to_string(),
    })
}

/// serde_json keeps the last copy of a repeated key. This walk refuses that
/// before the value is built. Keys are compared after string escapes.
/// Guest JSON, bounded before any recursive walk. `read` params use this too.
pub(crate) fn reject_guest_json(bytes: &[u8]) -> Result<(), String> {
    reject_duplicate_keys(bytes)
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), String> {
    let mut i = 0;
    scan_value(bytes, &mut i, 1)?;
    skip_ws(bytes, &mut i);
    if i != bytes.len() {
        return Err("document is not JSON".to_string());
    }
    Ok(())
}

fn skip_ws(bytes: &[u8], i: &mut usize) {
    while bytes.get(*i).is_some_and(|byte| byte.is_ascii_whitespace()) {
        *i += 1;
    }
}

fn scan_value(bytes: &[u8], i: &mut usize, depth: usize) -> Result<(), String> {
    // Checked before any further call. Eight is this checker's own cap.
    if depth > MAX_DEPTH {
        return Err(format!("depth cap {MAX_DEPTH}"));
    }
    skip_ws(bytes, i);
    match bytes.get(*i).copied() {
        Some(b'{') => scan_object(bytes, i, depth),
        Some(b'[') => scan_array(bytes, i, depth),
        Some(b'"') => {
            scan_string(bytes, i)?;
            Ok(())
        }
        Some(b't') => scan_lit(bytes, i, b"true"),
        Some(b'f') => scan_lit(bytes, i, b"false"),
        Some(b'n') => scan_lit(bytes, i, b"null"),
        Some(b'-') | Some(b'0'..=b'9') => scan_number(bytes, i),
        _ => Err("document is not JSON".to_string()),
    }
}

fn scan_object(bytes: &[u8], i: &mut usize, depth: usize) -> Result<(), String> {
    *i += 1;
    let mut keys = Vec::new();
    loop {
        skip_ws(bytes, i);
        if bytes.get(*i) == Some(&b'}') {
            *i += 1;
            return Ok(());
        }
        if !keys.is_empty() {
            if bytes.get(*i) != Some(&b',') {
                return Err("document is not JSON".to_string());
            }
            *i += 1;
            skip_ws(bytes, i);
        }
        let key = scan_string(bytes, i)?;
        if keys.iter().any(|seen| seen == &key) {
            return Err(format!("duplicate key {key:?}"));
        }
        keys.push(key);
        skip_ws(bytes, i);
        if bytes.get(*i) != Some(&b':') {
            return Err("document is not JSON".to_string());
        }
        *i += 1;
        scan_value(bytes, i, depth + 1)?;
    }
}

fn scan_array(bytes: &[u8], i: &mut usize, depth: usize) -> Result<(), String> {
    *i += 1;
    let mut seen = false;
    loop {
        skip_ws(bytes, i);
        if bytes.get(*i) == Some(&b']') {
            *i += 1;
            return Ok(());
        }
        if seen {
            if bytes.get(*i) != Some(&b',') {
                return Err("document is not JSON".to_string());
            }
            *i += 1;
        }
        scan_value(bytes, i, depth + 1)?;
        seen = true;
    }
}

fn scan_string(bytes: &[u8], i: &mut usize) -> Result<String, String> {
    if bytes.get(*i) != Some(&b'"') {
        return Err("document is not JSON".to_string());
    }
    *i += 1;
    let mut raw = Vec::new();
    while let Some(byte) = bytes.get(*i).copied() {
        *i += 1;
        match byte {
            b'"' => {
                return String::from_utf8(raw).map_err(|_| "document is not JSON".to_string());
            }
            b'\\' => {
                let esc = bytes.get(*i).copied().ok_or("document is not JSON")?;
                *i += 1;
                let ch = match esc {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{0008}',
                    b'f' => '\u{000c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => {
                        let hex = bytes.get(*i..*i + 4).ok_or("document is not JSON")?;
                        *i += 4;
                        let text = std::str::from_utf8(hex).map_err(|_| "document is not JSON")?;
                        let code = u32::from_str_radix(text, 16)
                            .map_err(|_| "document is not JSON".to_string())?;
                        char::from_u32(code).ok_or("document is not JSON")?
                    }
                    _ => return Err("document is not JSON".to_string()),
                };
                raw.extend(ch.encode_utf8(&mut [0; 4]).as_bytes());
            }
            byte if byte < 0x20 => return Err("document is not JSON".to_string()),
            byte => raw.push(byte),
        }
    }
    Err("document is not JSON".to_string())
}

fn scan_lit(bytes: &[u8], i: &mut usize, lit: &[u8]) -> Result<(), String> {
    if bytes.get(*i..).is_some_and(|rest| rest.starts_with(lit)) {
        *i += lit.len();
        Ok(())
    } else {
        Err("document is not JSON".to_string())
    }
}

fn scan_number(bytes: &[u8], i: &mut usize) -> Result<(), String> {
    if bytes.get(*i) == Some(&b'-') {
        *i += 1;
    }
    if !take_digits(bytes, i) {
        return Err("document is not JSON".to_string());
    }
    if bytes.get(*i) == Some(&b'.') {
        *i += 1;
        if !take_digits(bytes, i) {
            return Err("document is not JSON".to_string());
        }
    }
    if matches!(bytes.get(*i), Some(b'e' | b'E')) {
        *i += 1;
        if matches!(bytes.get(*i), Some(b'+' | b'-')) {
            *i += 1;
        }
        if !take_digits(bytes, i) {
            return Err("document is not JSON".to_string());
        }
    }
    Ok(())
}

fn take_digits(bytes: &[u8], i: &mut usize) -> bool {
    let start = *i;
    while bytes.get(*i).is_some_and(|byte| byte.is_ascii_digit()) {
        *i += 1;
    }
    *i > start
}

/// Checks one document. The frame it returns names text and grant ids.
pub fn check_document(media_type: &str, document: &[u8]) -> Result<Vec<Node>, String> {
    if media_type != UI_MEDIA_TYPE {
        return Err(format!(
            "media type {media_type:?}; expected {UI_MEDIA_TYPE}"
        ));
    }
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "size cap {MAX_DOCUMENT_BYTES}: document is {} bytes",
            document.len()
        ));
    }
    reject_duplicate_keys(document)?;
    // serde_json::from_slice keeps its own depth limit (128). This crate does
    // not turn that limit off. The scan above already refused anything past 8,
    // so this parse never walks a deeper tree.
    let value: Value =
        serde_json::from_slice(document).map_err(|err| format!("document is not JSON: {err}"))?;
    walk(&value, 1)?;
    let root = value.as_object().ok_or("a document is one frame")?;
    if root.len() != 1 || !root.contains_key("frame") {
        return Err("a document has other keys besides frame".to_string());
    }
    let frame = value
        .get("frame")
        .and_then(Value::as_array)
        .ok_or("a document is one frame")?;
    if frame.is_empty() || frame.len() > MAX_NODES {
        return Err(format!("a frame has 1 to {MAX_NODES} nodes"));
    }
    frame.iter().map(one_node).collect()
}

/// A grant the guest already holds. Present reads this record. It does not
/// ask for a new grant.
/// Revoked ids kept so a later present can still say the grant was revoked.
const MAX_REVOKED_GRANTS: usize = 32;
const MAX_HELD_GRANTS: usize = 32;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantBook {
    grants: Vec<HeldGrant>,
    revoked: Vec<String>,
    /// Ids no longer held: pushed out of `revoked`, or evicted from `grants`.
    dropped: Vec<String>,
    /// Set by [`GrantBook::clear`]. A later read or present stays denied.
    closed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HeldGrant {
    id: String,
    resource: String,
    actions: Vec<String>,
}

impl GrantBook {
    pub fn hold(&mut self, id: &str, resource: &str, action: &str) {
        self.revoked.retain(|kept| kept != id);
        self.dropped.retain(|kept| kept != id);
        if self.grants.iter().any(|grant| grant.id == id) {
            return;
        }
        if self.grants.len() == MAX_HELD_GRANTS {
            let old = self.grants.remove(0);
            if self.dropped.len() == MAX_REVOKED_GRANTS {
                self.dropped.remove(0);
            }
            self.dropped.push(old.id);
        }
        self.grants.push(HeldGrant {
            id: id.to_string(),
            resource: resource.to_string(),
            actions: vec![action.to_string()],
        });
    }

    pub fn revoke(&mut self, id: &str) {
        let held = self.grants.iter().position(|grant| grant.id == id);
        if held.is_none()
            && (self.revoked.iter().any(|kept| kept == id)
                || self.dropped.iter().any(|kept| kept == id))
        {
            return;
        }
        if let Some(pos) = held {
            self.grants.remove(pos);
        }
        if self.revoked.iter().any(|kept| kept == id) {
            return;
        }
        if self.revoked.len() == MAX_REVOKED_GRANTS {
            let old = self.revoked.remove(0);
            if self.dropped.len() == MAX_REVOKED_GRANTS {
                self.dropped.remove(0);
            }
            self.dropped.push(old);
        }
        self.revoked.push(id.to_string());
    }

    /// Drops every grant this guest holds, including the revoked ids. A stop
    /// does this. A revoke of one grant does not.
    pub fn clear(&mut self) {
        self.grants.clear();
        self.revoked.clear();
        self.dropped.clear();
        self.closed = true;
    }

    /// A revoked, forgotten, or closed grant cannot back a read.
    pub fn blocks_read(&self, id: &str) -> bool {
        self.closed
            || self.revoked.iter().any(|kept| kept == id)
            || self.dropped.iter().any(|kept| kept == id)
    }

    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    #[cfg(test)]
    fn grant_slots(&self) -> usize {
        self.grants.len() + self.revoked.len()
    }
}

/// One frame. An image is a grant id and a resource name. It holds no bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub nodes: Vec<FrameNode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameNode {
    Text(String),
    Image { grant: String, resource: String },
}

#[derive(Debug)]
pub enum PresentError {
    Invalid(String),
    Denied(String),
}

/// The slice 10 checker runs first. A grant that is unknown, revoked, or not
/// read is denied and stores nothing.
pub fn present_frame(
    media: &str,
    document: &[u8],
    book: &GrantBook,
) -> Result<Frame, PresentError> {
    if book.closed {
        return Err(PresentError::Denied("the grant book is closed".into()));
    }
    let nodes = check_document(media, document).map_err(PresentError::Invalid)?;
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        out.push(match node {
            Node::Text(text) => FrameNode::Text(text),
            Node::Image { grant } => {
                if book.revoked.iter().any(|id| id == &grant) {
                    return Err(PresentError::Denied(format!("{grant} was revoked")));
                }
                let Some(held) = book.grants.iter().find(|item| item.id == grant) else {
                    if book.dropped.iter().any(|id| id == &grant) {
                        return Err(PresentError::Denied(format!(
                            "{grant} is not among the {MAX_REVOKED_GRANTS}"
                        )));
                    }
                    return Err(PresentError::Denied(format!(
                        "{grant} is not a grant this guest holds"
                    )));
                };
                if !held.actions.iter().any(|action| action == "read") {
                    return Err(PresentError::Denied(format!("{grant} does not allow read")));
                }
                FrameNode::Image {
                    grant,
                    resource: held.resource.clone(),
                }
            }
        });
    }
    Ok(Frame { nodes: out })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_ui_refuses_a_script_key() {
        let err = check_document(
            UI_MEDIA_TYPE,
            br#"{"frame":[{"text":"hi","script":"alert(1)"}]}"#,
        )
        .unwrap_err();
        assert!(
            err.contains("scripts and event handlers are not allowed"),
            "{err}"
        );
        let err = check_document(UI_MEDIA_TYPE, br#"{"frame":[{"text":"hi","onclick":"x"}]}"#)
            .unwrap_err();
        assert!(
            err.contains("scripts and event handlers are not allowed"),
            "{err}"
        );
        let big = vec![b' '; MAX_DOCUMENT_BYTES + 1];
        let err = check_document(UI_MEDIA_TYPE, &big).unwrap_err();
        assert!(err.contains("size cap"), "{err}");
        let deep = br#"{"frame":{"frame":{"frame":{"frame":{"frame":{"frame":{"frame":{"frame":{"frame":{}}}}}}}}}}"#;
        let err = check_document(UI_MEDIA_TYPE, deep).unwrap_err();
        assert!(err.contains("depth cap"), "{err}");
    }

    #[test]
    fn v2_ui_refuses_an_image_uri() {
        let err = check_document(
            UI_MEDIA_TYPE,
            br#"{"frame":[{"image":{"grant":"g1","uri":"https://example.com/a.png"}}]}"#,
        )
        .unwrap_err();
        assert!(err.contains("never by a URI or bytes"), "{err}");
        let nodes = check_document(
            UI_MEDIA_TYPE,
            br#"{"frame":[{"text":"hi"},{"image":{"grant":"g1"}}]}"#,
        )
        .unwrap();
        assert_eq!(
            nodes,
            vec![
                Node::Text("hi".to_string()),
                Node::Image {
                    grant: "g1".to_string()
                }
            ]
        );
    }

    #[test]
    fn v2_ui_refuses_the_wrong_media_type() {
        let good = br#"{"frame":[{"text":"hi"}]}"#;
        for media in ["text/html", "application/vnd.elastos.ui+json;v=1", ""] {
            let err = check_document(media, good).unwrap_err();
            assert!(err.contains("media type"), "{media}: {err}");
        }
    }

    #[test]
    fn v2_ui_refuses_src_html_href_and_bytes() {
        for (key, value) in [
            ("src", "https://example.com/a.png"),
            ("html", "<b>hi</b>"),
            ("href", "https://example.com"),
            ("bytes", "iVBORw0KGgo="),
        ] {
            let document =
                format!(r#"{{"frame":[{{"image":{{"grant":"g1","{key}":"{value}"}}}}]}}"#);
            let err = check_document(UI_MEDIA_TYPE, document.as_bytes()).unwrap_err();
            assert!(err.contains("never by a URI or bytes"), "{key}: {err}");
        }
    }

    #[test]
    fn duplicate_keys_and_stray_keys_are_refused() {
        let err =
            check_document(UI_MEDIA_TYPE, br#"{"frame":[{"text":"a","text":"b"}]}"#).unwrap_err();
        assert!(err.contains("duplicate key"), "{err}");
        let err =
            check_document(UI_MEDIA_TYPE, br#"{"frame":[{"text":"x","grant":"y"}]}"#).unwrap_err();
        assert!(err.contains("other keys"), "{err}");
        let err =
            check_document(UI_MEDIA_TYPE, br#"{"grant":"y","frame":[{"text":"x"}]}"#).unwrap_err();
        assert!(err.contains("other keys"), "{err}");
    }

    #[test]
    fn revoked_ids_stay_bounded_and_still_say_revoked() {
        let mut book = GrantBook::default();
        for n in 0..40 {
            let id = format!("g{n}");
            book.hold(&id, "localhost://Users/self/Pictures/a.png", "read");
            book.revoke(&id);
        }
        assert!(
            book.grant_slots() <= 32,
            "revoked ids stay in a bounded list, have {}",
            book.grant_slots()
        );
        let media = UI_MEDIA_TYPE;
        let latest =
            present_frame(media, br#"{"frame":[{"image":{"grant":"g39"}}]}"#, &book).unwrap_err();
        assert!(
            matches!(latest, PresentError::Denied(ref message) if message.contains("was revoked")),
            "{latest:?}"
        );
        let oldest =
            present_frame(media, br#"{"frame":[{"image":{"grant":"g0"}}]}"#, &book).unwrap_err();
        assert!(
            matches!(oldest, PresentError::Denied(ref message) if message.contains("not among the 32")),
            "{oldest:?}"
        );
        let never =
            present_frame(media, br#"{"frame":[{"image":{"grant":"never"}}]}"#, &book).unwrap_err();
        assert!(
            matches!(never, PresentError::Denied(ref message) if message.contains("not a grant") && !message.contains("not among the 32")),
            "an id that was never revoked must not claim the revoke list, got {never:?}"
        );
    }

    #[test]
    fn an_evicted_grant_blocks_a_read() {
        let mut book = GrantBook::default();
        book.hold("old", "localhost://Users/self/Pictures/a.png", "read");
        for n in 0..MAX_HELD_GRANTS {
            book.hold(
                &format!("g{n}"),
                "localhost://Users/self/Pictures/a.png",
                "read",
            );
        }
        assert!(
            book.blocks_read("old"),
            "evicting a grant must block a later read"
        );
        let err = present_frame(
            UI_MEDIA_TYPE,
            br#"{"frame":[{"image":{"grant":"old"}}]}"#,
            &book,
        )
        .unwrap_err();
        assert!(
            matches!(err, PresentError::Denied(ref message) if message.contains("old")),
            "{err:?}"
        );
    }

    /// 16,384 `[`, the same many `{"a":`, and a 16 KiB string. Each ends
    /// Invalid. The check runs in a child: a stack overflow there fails this
    /// row, and the suite process stays up.
    #[test]
    fn deep_documents_end_invalid_and_the_process_lives() {
        const NAME: &str =
            "providers::bus2_ui::tests::deep_documents_end_invalid_and_the_process_lives";
        if std::env::var("RA2_DEPTH_CHILD").is_err() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .arg(NAME)
                .arg("--exact")
                .arg("--test-threads=1")
                .arg("--nocapture")
                .env("RA2_DEPTH_CHILD", "1");
            let output = child.output().expect("depth child starts");
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "deep document must end Invalid in a live process, status {:?}\n{stdout}\n{stderr}",
                output.status
            );
            assert!(
                stdout.contains("deep document: Invalid")
                    || stderr.contains("deep document: Invalid"),
                "child did not report Invalid\n{stdout}\n{stderr}"
            );
            return;
        }
        for document in deep_documents() {
            let err = check_document(UI_MEDIA_TYPE, &document).expect_err("deep document");
            assert!(!err.is_empty(), "{err}");
            let read =
                super::super::bus2_stream::read_cap(&document).expect_err("deep read params");
            assert!(
                read.contains("depth cap")
                    || read.contains("not JSON")
                    || read.contains("expected"),
                "{read}"
            );
            eprintln!("deep document: Invalid");
        }
        let mut nested = Vec::new();
        for _ in 0..200 {
            nested.extend_from_slice(br#"{"a":"#);
        }
        nested.extend_from_slice(br#"null"#);
        nested.extend(std::iter::repeat_n(b'}', 200));
        let err = serde_json::from_slice::<serde_json::Value>(&nested).expect_err("serde depth");
        assert!(
            err.to_string().contains("recursion"),
            "serde_json keeps its own depth limit, got {err}"
        );
        eprintln!("deep document: Invalid");
    }

    fn deep_documents() -> [Vec<u8>; 3] {
        let brackets = vec![b'['; MAX_DOCUMENT_BYTES];
        let mut objects = Vec::new();
        while objects.len() + 5 <= MAX_DOCUMENT_BYTES {
            objects.extend_from_slice(br#"{"a":"#);
        }
        let mut deep_string = vec![b'"'];
        while deep_string.len() + 7 <= MAX_DOCUMENT_BYTES {
            deep_string.extend_from_slice(br#"\u0041"#);
        }
        deep_string.push(b'"');
        [brackets, objects, deep_string]
    }

    #[test]
    fn v2_ui_refuses_over_32_nodes_and_1000_characters() {
        let mut nodes = (0..MAX_NODES)
            .map(|_| r#"{"text":"ok"}"#)
            .collect::<Vec<_>>();
        let at_limit = format!(r#"{{"frame":[{}]}}"#, nodes.join(","));
        assert_eq!(
            check_document(UI_MEDIA_TYPE, at_limit.as_bytes())
                .unwrap()
                .len(),
            MAX_NODES
        );
        nodes.push(r#"{"text":"over"}"#);
        let over = format!(r#"{{"frame":[{}]}}"#, nodes.join(","));
        let err = check_document(UI_MEDIA_TYPE, over.as_bytes()).unwrap_err();
        assert!(err.contains("32"), "{err}");

        let text = "x".repeat(MAX_TEXT_CHARS);
        let at_chars = format!(r#"{{"frame":[{{"text":"{text}"}}]}}"#);
        assert!(check_document(UI_MEDIA_TYPE, at_chars.as_bytes()).is_ok());
        let text = "x".repeat(MAX_TEXT_CHARS + 1);
        let over_chars = format!(r#"{{"frame":[{{"text":"{text}"}}]}}"#);
        let err = check_document(UI_MEDIA_TYPE, over_chars.as_bytes()).unwrap_err();
        assert!(err.contains("1000"), "{err}");
    }
}
