//! `ui.present`: one declarative document draws one frame.
//!
//! The document, media type `application/vnd.elastos.ui+json;v=0` (a stub
//! format for this proof), is `{"frame": [node, ...]}`, where a node is
//! `{"text": "..."}` or `{"image": {"grant": "<grant-id>"}}`. An image is named
//! by a grant this guest holds, with `read`, on an object that is an image.
//! There is no URI, no bytes, no script, no handler and no HTML. A new
//! `present` replaces the frame on screen.

use serde::Deserialize;

use crate::{BusError, HostState, UI_MEDIA_TYPE};

pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
pub const MAX_NODES: usize = 32;
pub const MAX_TEXT_CHARS: usize = 1000;

/// A drawn frame, as the host holds it: images by grant and resource, never
/// by bytes from the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub nodes: Vec<Node>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Text(String),
    Image { grant: String, resource: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    frame: Vec<NodeIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
enum NodeIn {
    Text(String),
    Image(ImageIn),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageIn {
    grant: String,
}

/// Keys that would make the document more than a description.
fn forbidden_key(key: &str) -> Option<&'static str> {
    let lower = key.to_ascii_lowercase();
    if lower == "script" || lower.starts_with("on") {
        return Some("scripts and event handlers are not allowed");
    }
    if ["html", "src", "url", "uri", "href", "bytes", "data"].contains(&lower.as_str()) {
        return Some("images are named by a grant, never by a URI or bytes");
    }
    None
}

fn scan(value: &serde_json::Value) -> Result<(), BusError> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                if let Some(why) = forbidden_key(key) {
                    return Err(BusError::Invalid(format!("key {key:?}: {why}")));
                }
                scan(inner)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => items.iter().try_for_each(scan),
        _ => Ok(()),
    }
}

fn is_image(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"\xFF\xD8\xFF")
        || (bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
}

/// Checks a document and returns the frame it draws, or the refusal.
pub fn check_document(
    state: &HostState,
    media_type: &str,
    document: &[u8],
) -> Result<Frame, BusError> {
    if media_type != UI_MEDIA_TYPE {
        return Err(BusError::Invalid(format!(
            "media type {media_type:?}; expected {UI_MEDIA_TYPE}"
        )));
    }
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(BusError::Invalid(format!(
            "document is {} bytes, over the {MAX_DOCUMENT_BYTES}-byte limit",
            document.len()
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(document)
        .map_err(|err| BusError::Invalid(format!("document is not JSON: {err}")))?;
    scan(&value)?;
    let parsed: Document = serde_json::from_slice(document)
        .map_err(|err| BusError::Invalid(format!("document shape: {err}")))?;
    if parsed.frame.is_empty() || parsed.frame.len() > MAX_NODES {
        return Err(BusError::Invalid(format!(
            "a frame has 1 to {MAX_NODES} nodes"
        )));
    }
    let mut nodes = Vec::new();
    for node in parsed.frame {
        nodes.push(match node {
            NodeIn::Text(text) => {
                if text.chars().count() > MAX_TEXT_CHARS {
                    return Err(BusError::Invalid(format!(
                        "a text node has at most {MAX_TEXT_CHARS} characters"
                    )));
                }
                Node::Text(text)
            }
            NodeIn::Image(ImageIn { grant: id }) => {
                if state.revoked.contains(&id) {
                    return Err(BusError::Denied(format!("{id} was revoked")));
                }
                let grant = state
                    .grants
                    .iter()
                    .find(|grant| grant.id == id)
                    .ok_or_else(|| {
                        BusError::Denied(format!("{id} is not a grant this guest holds"))
                    })?;
                if !grant.actions.iter().any(|action| action == "read") {
                    return Err(BusError::Denied(format!("{id} does not allow read")));
                }
                let object = state
                    .objects
                    .get(&grant.resource)
                    .ok_or_else(|| BusError::NotFound(format!("no object {}", grant.resource)))?;
                if !is_image(&object.bytes) {
                    return Err(BusError::Invalid(format!(
                        "{} is not a PNG, JPEG or WebP image",
                        grant.resource
                    )));
                }
                Node::Image {
                    grant: id,
                    resource: grant.resource.clone(),
                }
            }
        });
    }
    Ok(Frame { nodes })
}
