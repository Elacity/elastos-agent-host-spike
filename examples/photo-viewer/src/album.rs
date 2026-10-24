//! The album the person asks to play.
//!
//! ```json
//! {
//!   "schema": "elastos.photo-viewer.album/v1",
//!   "items": [
//!     { "uri": "localhost://Users/self/Pictures/a.png", "duration_ms": 4000 },
//!     { "uri": "localhost://Users/self/Pictures/b.jpg" }
//!   ]
//! }
//! ```
//!
//! Unknown fields are refused, like manifest parsing.

use capsule_kit_guest::uri::check_object_uri;
use serde_json::Value;

use crate::{
    DEFAULT_DURATION_MS, MAX_ALBUM_ITEMS, MAX_DURATION_MS, MIN_DURATION_MS, PICTURES_PREFIX,
};

pub const ALBUM_SCHEMA: &str = "elastos.photo-viewer.album/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlbumItem {
    pub uri: String,
    pub duration_ms: u64,
}

pub fn parse(bytes: &[u8]) -> Result<Vec<AlbumItem>, String> {
    let album: Value =
        serde_json::from_slice(bytes).map_err(|err| format!("album is not JSON: {err}"))?;
    let album = album
        .as_object()
        .ok_or_else(|| "album must be a JSON object".to_string())?;
    if let Some(key) = album
        .keys()
        .find(|key| !matches!(key.as_str(), "schema" | "items"))
    {
        return Err(format!("album has unknown field {key:?}"));
    }
    if album.get("schema").and_then(Value::as_str) != Some(ALBUM_SCHEMA) {
        return Err(format!("album schema must be {ALBUM_SCHEMA}"));
    }
    let items = album
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "album items must be a list".to_string())?;
    if items.is_empty() {
        return Err("album has no items".to_string());
    }
    if items.len() > MAX_ALBUM_ITEMS {
        return Err(format!(
            "album has {} items, the limit is {MAX_ALBUM_ITEMS}",
            items.len()
        ));
    }
    items
        .iter()
        .enumerate()
        .map(|(index, item)| parse_item(item).map_err(|err| format!("album item {index}: {err}")))
        .collect()
}

fn parse_item(item: &Value) -> Result<AlbumItem, String> {
    let item = item
        .as_object()
        .ok_or_else(|| "must be a JSON object".to_string())?;
    if let Some(key) = item
        .keys()
        .find(|key| !matches!(key.as_str(), "uri" | "duration_ms"))
    {
        return Err(format!("unknown field {key:?}"));
    }
    let uri = item
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "uri must be a string".to_string())?;
    check_uri(uri)?;
    let duration_ms = match item.get("duration_ms") {
        None => DEFAULT_DURATION_MS,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| "duration_ms must be a whole number".to_string())?,
    };
    if !(MIN_DURATION_MS..=MAX_DURATION_MS).contains(&duration_ms) {
        return Err(format!(
            "duration_ms {duration_ms} is outside {MIN_DURATION_MS}..={MAX_DURATION_MS}"
        ));
    }
    Ok(AlbumItem {
        uri: uri.to_string(),
        duration_ms,
    })
}

/// An item names one object under the person's Pictures folder.
fn check_uri(uri: &str) -> Result<(), String> {
    check_object_uri(uri, PICTURES_PREFIX)
}
