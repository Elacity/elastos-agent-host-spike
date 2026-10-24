//! The URI check of an input list: an item names one object under one
//! folder of the person's. Moved here from the photo album and the documents
//! shelf, which had a copy each.

/// `uri` names one object under `prefix`: not the folder itself, no empty,
/// `.` or `..` segment, and no `?`, `#`, `\` or control character.
pub fn check_object_uri(uri: &str, prefix: &str) -> Result<(), String> {
    let Some(relative) = uri.strip_prefix(prefix) else {
        return Err(format!("uri must start with {prefix}"));
    };
    if relative.is_empty() || relative.ends_with('/') {
        return Err("uri must name an object, not a folder".to_string());
    }
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("uri must not contain empty, . or .. segments".to_string());
    }
    if relative.contains(['?', '#', '\\']) || relative.chars().any(char::is_control) {
        return Err("uri must not contain ?, #, \\ or control characters".to_string());
    }
    Ok(())
}
