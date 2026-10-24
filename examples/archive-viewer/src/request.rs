//! The request: which archive to open, and which entries to show.
//!
//! ```json
//! {
//!   "schema": "elastos.archive-viewer.open/v1",
//!   "uri": "localhost://Users/self/Documents/trip.zip",
//!   "show": [0, 2]
//! }
//! ```
//!
//! Unknown fields are refused, like manifest parsing. `show` is optional: the
//! indexes of entries to check for a preview, in this order. The Bus v1
//! Component ABI has no input argument, so the request is an object at a fixed
//! path.

use capsule_kit_guest::uri::check_object_uri;
use serde_json::Value;

use crate::{MAX_REQUEST_SHOW, USERS_PREFIX};

pub const REQUEST_SCHEMA: &str = "elastos.archive-viewer.open/v1";
/// The app's data folder, matched as a whole segment in any ASCII case: a
/// Mac filesystem is case-insensitive, so `.appdata` names the same folder.
/// A request for anything here would reach the app's view object or another
/// app's data, so it is refused.
const APP_DATA_SEGMENT: &str = ".appdata";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub uri: String,
    pub show: Vec<usize>,
}

pub fn parse(bytes: &[u8]) -> Result<Request, String> {
    let request: Value =
        serde_json::from_slice(bytes).map_err(|err| format!("request is not JSON: {err}"))?;
    let request = request
        .as_object()
        .ok_or_else(|| "request must be a JSON object".to_string())?;
    if let Some(key) = request
        .keys()
        .find(|key| !matches!(key.as_str(), "schema" | "uri" | "show"))
    {
        return Err(format!("request has unknown field {key:?}"));
    }
    if request.get("schema").and_then(Value::as_str) != Some(REQUEST_SCHEMA) {
        return Err(format!("request schema must be {REQUEST_SCHEMA}"));
    }
    let uri = request
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "uri must be a string".to_string())?;
    check_uri(uri)?;
    let show = match request.get("show") {
        None => Vec::new(),
        Some(value) => {
            let list = value
                .as_array()
                .ok_or_else(|| "show must be a list of entry indexes".to_string())?;
            if list.len() > MAX_REQUEST_SHOW {
                return Err(format!(
                    "show names {} entries, the limit is {MAX_REQUEST_SHOW}",
                    list.len()
                ));
            }
            let mut indexes = Vec::with_capacity(list.len());
            for (position, item) in list.iter().enumerate() {
                let index = item
                    .as_u64()
                    .ok_or_else(|| format!("show item {position} must be a whole number"))?;
                indexes.push(usize::try_from(index).map_err(|_| {
                    format!("show item {position} is {index}, too large for an entry index")
                })?);
            }
            indexes
        }
    };
    Ok(Request {
        uri: uri.to_string(),
        show,
    })
}

/// The archive is one object under the person's folders, and never under any
/// app's data folder, in any ASCII case.
fn check_uri(uri: &str) -> Result<(), String> {
    if is_app_data(uri) {
        return Err("uri must not be under .AppData/".to_string());
    }
    check_object_uri(uri, USERS_PREFIX)
}

fn is_app_data(uri: &str) -> bool {
    let Some(relative) = uri.strip_prefix(USERS_PREFIX) else {
        return false;
    };
    relative
        .split('/')
        .next()
        .is_some_and(|first| first.eq_ignore_ascii_case(APP_DATA_SEGMENT))
}
