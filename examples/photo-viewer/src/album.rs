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
//! Unknown fields are refused, like manifest parsing. The list rules are the
//! kit's (`capsule_kit_guest::list`); this file adds only the album's
//! duration field.

use capsule_kit_guest::list::{self, ListRules};
use serde_json::Value;

use crate::{
    DEFAULT_DURATION_MS, MAX_ALBUM_ITEMS, MAX_DURATION_MS, MIN_DURATION_MS, PICTURES_PREFIX,
};

pub const ALBUM_SCHEMA: &str = "elastos.photo-viewer.album/v1";

/// What the album says about its own list; the kit checks the rest.
const ALBUM_LIST: ListRules = ListRules {
    noun: "album",
    schema: ALBUM_SCHEMA,
    limit: MAX_ALBUM_ITEMS,
    prefix: PICTURES_PREFIX,
    item_fields: &["duration_ms"],
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlbumItem {
    pub uri: String,
    pub duration_ms: u64,
}

pub fn parse(bytes: &[u8]) -> Result<Vec<AlbumItem>, String> {
    list::parse(bytes, &ALBUM_LIST, |item, uri| {
        Ok(AlbumItem {
            uri: uri.to_string(),
            duration_ms: duration_ms(item)?,
        })
    })
}

fn duration_ms(item: &Value) -> Result<u64, String> {
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
    Ok(duration_ms)
}
