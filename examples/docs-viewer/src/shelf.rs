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
//! Unknown fields are refused, like manifest parsing. The list rules are the
//! kit's (`capsule_kit_guest::list`); this file adds no item field of its own.

use capsule_kit_guest::list::{self, ListRules};

use crate::{DOCUMENTS_PREFIX, MAX_SHELF_ITEMS};

pub const SHELF_SCHEMA: &str = "elastos.docs-viewer.shelf/v1";

/// What the shelf says about its own list; the kit checks the rest.
const SHELF_LIST: ListRules = ListRules {
    noun: "shelf",
    schema: SHELF_SCHEMA,
    limit: MAX_SHELF_ITEMS,
    prefix: DOCUMENTS_PREFIX,
    item_fields: &[],
};

pub fn parse(bytes: &[u8]) -> Result<Vec<String>, String> {
    list::parse(bytes, &SHELF_LIST, |_item, uri| Ok(uri.to_string()))
}
