//! The shelf: the documents the person asked to read.
//!
//! ```json
//! {
//!   "schema": "elastos.docs-viewer.shelf/v1",
//!   "items": [
//!     { "uri": "localhost://Users/self/Documents/notes.md" },
//!     { "uri": "localhost://Users/self/Documents/todo.txt" }
//!   ]
//! }
//! ```
//!
//! Unknown fields are refused, like manifest parsing.

use capsule_kit_guest::uri::check_object_uri;
use serde_json::Value;

use crate::{DOCUMENTS_PREFIX, MAX_SHELF_ITEMS};

pub const SHELF_SCHEMA: &str = "elastos.docs-viewer.shelf/v1";

pub fn parse(bytes: &[u8]) -> Result<Vec<String>, String> {
    let shelf: Value =
        serde_json::from_slice(bytes).map_err(|err| format!("shelf is not JSON: {err}"))?;
    let shelf = shelf
        .as_object()
        .ok_or_else(|| "shelf must be a JSON object".to_string())?;
    if let Some(key) = shelf
        .keys()
        .find(|key| !matches!(key.as_str(), "schema" | "items"))
    {
        return Err(format!("shelf has unknown field {key:?}"));
    }
    if shelf.get("schema").and_then(Value::as_str) != Some(SHELF_SCHEMA) {
        return Err(format!("shelf schema must be {SHELF_SCHEMA}"));
    }
    let items = shelf
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "shelf items must be a list".to_string())?;
    if items.is_empty() {
        return Err("shelf has no items".to_string());
    }
    if items.len() > MAX_SHELF_ITEMS {
        return Err(format!(
            "shelf has {} items, the limit is {MAX_SHELF_ITEMS}",
            items.len()
        ));
    }
    items
        .iter()
        .enumerate()
        .map(|(index, item)| parse_item(item).map_err(|err| format!("shelf item {index}: {err}")))
        .collect()
}

fn parse_item(item: &Value) -> Result<String, String> {
    let item = item
        .as_object()
        .ok_or_else(|| "must be a JSON object".to_string())?;
    if let Some(key) = item.keys().find(|key| key.as_str() != "uri") {
        return Err(format!("unknown field {key:?}"));
    }
    let uri = item
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "uri must be a string".to_string())?;
    check_uri(uri)?;
    Ok(uri.to_string())
}

/// An item names one object under the person's Documents folder.
fn check_uri(uri: &str) -> Result<(), String> {
    check_object_uri(uri, DOCUMENTS_PREFIX)
}
