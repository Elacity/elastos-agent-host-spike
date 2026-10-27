//! The one detector for a path dependency on this crate.

/// True only when the text names `grant-binding` and carries a `path` key.
///
/// A manifest that names the crate without a path dependency is not a link
/// to this crate's source.
#[rustfmt::skip]
pub fn cargo_toml_path_depends_on_grant_binding(cargo_toml: &str) -> bool {
    let cargo_toml = decode_toml_basic_strings(cargo_toml);
    cargo_toml.contains("grant-binding") && cargo_toml.contains("path")
}

/// Decode escapes in TOML basic strings, so an escaped link stays visible.
///
/// Text outside a string, a comment, and every literal string (`'...'` or
/// `'''...'''`), is copied unchanged. Only a basic string (`"..."` or
/// `"""..."""`) decodes `\\`, `\"`, `\b`, `\t`, `\n`, `\f`, `\r`, `\uXXXX`
/// and `\UXXXXXXXX`. An escape that is unknown, short or not a Unicode scalar
/// stays as source. One or two quote characters just inside a multiline
/// closing delimiter are string text, not the start of a new string.
fn decode_toml_basic_strings(cargo_toml: &str) -> String {
    let bytes = cargo_toml.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'#' => {
                let end = bytes[index..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |offset| index + offset);
                decoded.extend_from_slice(&bytes[index..end]);
                index = end;
            }
            b'\'' => index = copy_literal(bytes, index, &mut decoded),
            b'"' => index = copy_basic(bytes, index, &mut decoded),
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).expect("decoder splits only at ASCII bytes, so it stays UTF-8")
}

/// Copy one literal string unchanged and return the index just past it.
fn copy_literal(bytes: &[u8], start: usize, decoded: &mut Vec<u8>) -> usize {
    if bytes[start..].starts_with(b"'''") {
        decoded.extend_from_slice(b"'''");
        copy_multiline(bytes, start + 3, b'\'', false, decoded)
    } else {
        decoded.push(b'\'');
        let end = find_byte(bytes, start + 1, b'\'').map_or(bytes.len(), |end| end + 1);
        decoded.extend_from_slice(&bytes[start + 1..end]);
        end
    }
}

/// Copy one basic string, decoding its escapes, and return the index past it.
fn copy_basic(bytes: &[u8], start: usize, decoded: &mut Vec<u8>) -> usize {
    if bytes[start..].starts_with(b"\"\"\"") {
        decoded.extend_from_slice(b"\"\"\"");
        copy_multiline(bytes, start + 3, b'"', true, decoded)
    } else {
        decoded.push(b'"');
        let mut index = start + 1;
        while index < bytes.len() && bytes[index] != b'"' {
            if bytes[index] == b'\\' {
                index = copy_escape(bytes, index, decoded);
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        if index < bytes.len() {
            decoded.push(b'"');
            index += 1;
        }
        index
    }
}

/// Copy multiline string content up to and including its closing delimiter.
///
/// A run of three or more quote characters ends the string; the last three are
/// the delimiter and any earlier quote of that run is content.
fn copy_multiline(
    bytes: &[u8],
    mut index: usize,
    quote: u8,
    decode: bool,
    decoded: &mut Vec<u8>,
) -> usize {
    while index < bytes.len() {
        if bytes[index] == quote {
            let run = quote_run(bytes, index, quote);
            if run >= 3 {
                decoded.extend_from_slice(&bytes[index..index + run - 3]);
                index += run - 3;
                decoded.extend_from_slice(&bytes[index..index + 3]);
                return index + 3;
            }
            decoded.extend_from_slice(&bytes[index..index + run]);
            index += run;
        } else if decode && bytes[index] == b'\\' {
            index = copy_escape(bytes, index, decoded);
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    index
}

/// Decode one escape at `index`, or copy it as source, and return the next.
fn copy_escape(bytes: &[u8], index: usize, decoded: &mut Vec<u8>) -> usize {
    match decode_escape(bytes, index) {
        Some((scalar, next)) => {
            let mut buffer = [0u8; 4];
            decoded.extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
            next
        }
        None => {
            decoded.push(b'\\');
            index + 1
        }
    }
}

/// The next occurrence of `byte` at or after `from`.
fn find_byte(bytes: &[u8], from: usize, byte: u8) -> Option<usize> {
    bytes
        .get(from..)?
        .iter()
        .position(|found| *found == byte)
        .map(|offset| from + offset)
}

/// How many `quote` bytes start at `index`.
fn quote_run(bytes: &[u8], index: usize, quote: u8) -> usize {
    bytes[index..]
        .iter()
        .take_while(|byte| **byte == quote)
        .count()
}

/// Decode one backslash escape at `index`, with the index just past it.
fn decode_escape(bytes: &[u8], index: usize) -> Option<(char, usize)> {
    let escaped = *bytes.get(index + 1)?;
    let simple = index + 2;
    match escaped {
        b'\\' => Some(('\\', simple)),
        b'"' => Some(('"', simple)),
        b'b' => Some(('\u{08}', simple)),
        b't' => Some(('\t', simple)),
        b'n' => Some(('\n', simple)),
        b'f' => Some(('\u{0c}', simple)),
        b'r' => Some(('\r', simple)),
        b'u' => decode_unicode(bytes, index, 4),
        b'U' => decode_unicode(bytes, index, 8),
        _ => None,
    }
}

/// Decode `\uXXXX` or `\UXXXXXXXX` when the hex is present and a scalar.
fn decode_unicode(bytes: &[u8], index: usize, digits: usize) -> Option<(char, usize)> {
    let start = index + 2;
    let end = start + digits;
    if end > bytes.len() {
        return None;
    }
    let mut value = 0u32;
    for byte in &bytes[start..end] {
        value = value.checked_mul(16)? + hex_value(*byte)?;
    }
    char::from_u32(value).map(|scalar| (scalar, end))
}

/// A hex digit as its value, accepting `0-9`, `a-f` and `A-F`.
fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a') + 10),
        b'A'..=b'F' => Some(u32::from(byte - b'A') + 10),
        _ => None,
    }
}

#[test]
fn model_escaped_unicode_path_is_a_link() {
    let escaped = "\
[package]\n\
name = \"escape-probe\"\n\
version = \"0.0.0\"\n\
edition = \"2021\"\n\
\n\
[dependencies]\n\
gb = { path = \"../grant-bind\\u0069ng\", package = \"grant-bind\\u0069ng\" }\n";
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\u0069"));
    assert!(cargo_toml_path_depends_on_grant_binding(escaped));
    let wide =
        "gb = { path = \"../grant-bind\\U00000069ng\", package = \"grant-bind\\U00000069ng\" }\n";
    assert!(!wide.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(wide));
    let literal = "gb = { path = '../grant-bind\\u0069ng', package = 'grant-bind\\u0069ng' }\n";
    assert!(!literal.contains("grant-binding"));
    assert!(!cargo_toml_path_depends_on_grant_binding(literal));
    let comment = "# don't edit\n[dependencies]\ngb = { path = \"../grant-bind\\u0069ng\", package = \"grant-bind\\u0069ng\" }\n";
    assert!(!comment.contains("grant-binding"));
    assert!(comment.contains("\\u0069"));
    assert!(cargo_toml_path_depends_on_grant_binding(comment));
    let quoted_comment = "# the \"quoted note\ngb = { path = \"../grant-bind\\u0069ng\" }\n";
    assert!(!quoted_comment.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(quoted_comment));
    let quoted_run = "a = \"\"\"x\"\"\"\"\ngb = { path = \"../grant-bind\\u0069ng\" }\n";
    assert!(!quoted_run.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(quoted_run));
    let literal_run = "a = '''x''''\ngb = { path = \"../grant-bind\\u0069ng\" }\n";
    assert!(!literal_run.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(literal_run));
}
