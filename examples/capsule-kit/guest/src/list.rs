//! The strict input list: one JSON object with only `schema` and `items`, a
//! fixed schema, a non-empty capped list, and items that are objects naming
//! one object under the app's folder. Moved here from the photo album and the
//! documents shelf, which had a copy each.
//!
//! An app keeps only what is its own: [`ListRules`] names its noun, its
//! schema, its cap, its folder prefix and its extra item fields, and the
//! `item` closure reads those fields.

use serde_json::Value;

use crate::uri::check_object_uri;

/// What an app says about its own list; the kit checks everything else.
#[derive(Clone, Copy)]
pub struct ListRules {
    /// The word its messages use, for example `"album"`.
    pub noun: &'static str,
    /// The one schema the list must name.
    pub schema: &'static str,
    /// The most items it may hold.
    pub limit: usize,
    /// The folder every item's `uri` stays under.
    pub prefix: &'static str,
    /// The item fields beyond `uri`, which the app's closure reads.
    pub item_fields: &'static [&'static str],
}

/// Checks the list and hands each item to `item` with its `uri`, already
/// checked against `rules.prefix`. A refusal starts with the app's noun, and
/// an item's with `<noun> item <index>: `.
pub fn parse<T>(
    bytes: &[u8],
    rules: &ListRules,
    item: impl Fn(&Value, &str) -> Result<T, String>,
) -> Result<Vec<T>, String> {
    let noun = rules.noun;
    let schema = rules.schema;
    let limit = rules.limit;
    let list: Value =
        serde_json::from_slice(bytes).map_err(|err| format!("{noun} is not JSON: {err}"))?;
    let list = list
        .as_object()
        .ok_or_else(|| format!("{noun} must be a JSON object"))?;
    if let Some(key) = list
        .keys()
        .find(|key| !matches!(key.as_str(), "schema" | "items"))
    {
        return Err(format!("{noun} has unknown field {key:?}"));
    }
    if list.get("schema").and_then(Value::as_str) != Some(schema) {
        return Err(format!("{noun} schema must be {schema}"));
    }
    let items = list
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{noun} items must be a list"))?;
    if items.is_empty() {
        return Err(format!("{noun} has no items"));
    }
    if items.len() > limit {
        return Err(format!(
            "{noun} has {} items, the limit is {limit}",
            items.len()
        ));
    }
    items
        .iter()
        .enumerate()
        .map(|(index, value)| {
            parse_item(value, rules, &item).map_err(|err| format!("{noun} item {index}: {err}"))
        })
        .collect()
}

fn parse_item<T>(
    value: &Value,
    rules: &ListRules,
    item: &impl Fn(&Value, &str) -> Result<T, String>,
) -> Result<T, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "must be a JSON object".to_string())?;
    if let Some(key) = object.keys().find(|key| !allowed(key, rules)) {
        return Err(format!("unknown field {key:?}"));
    }
    let uri = value
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "uri must be a string".to_string())?;
    check_object_uri(uri, rules.prefix)?;
    item(value, uri)
}

/// `uri` and the app's own item fields; nothing else.
fn allowed(key: &str, rules: &ListRules) -> bool {
    key == "uri" || rules.item_fields.contains(&key)
}
