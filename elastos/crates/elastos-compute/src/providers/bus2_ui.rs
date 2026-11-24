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
    if text == image {
        return Err("a node is text or an image".to_string());
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
    let grant = object
        .get("image")
        .and_then(Value::as_object)
        .and_then(|image| image.get("grant"))
        .and_then(Value::as_str)
        .filter(|grant| !grant.is_empty())
        .ok_or("an image names a grant")?;
    Ok(Node::Image {
        grant: grant.to_string(),
    })
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
    let value: Value =
        serde_json::from_slice(document).map_err(|err| format!("document is not JSON: {err}"))?;
    walk(&value, 1)?;
    let frame = value
        .get("frame")
        .and_then(Value::as_array)
        .ok_or("a document is one frame")?;
    if frame.is_empty() || frame.len() > MAX_NODES {
        return Err(format!("a frame has 1 to {MAX_NODES} nodes"));
    }
    frame.iter().map(one_node).collect()
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
}
