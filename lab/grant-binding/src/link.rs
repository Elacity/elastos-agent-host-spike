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
/// Text outside a string, and every literal string (`'...'` or `'''...'''`),
/// is copied unchanged. Only a basic string (`"..."` or `"""..."""`) decodes
/// `\\`, `\"`, `\b`, `\t`, `\n`, `\f`, `\r`, `\uXXXX` and `\UXXXXXXXX`.
/// An escape that is unknown, short or not a Unicode scalar stays as source.
fn decode_toml_basic_strings(cargo_toml: &str) -> String {
    let bytes = cargo_toml.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                let quote: &[u8] = if bytes[index..].starts_with(b"'''") {
                    b"'''"
                } else {
                    b"'"
                };
                let start = index;
                index += quote.len();
                index = match find_quote(bytes, index, quote) {
                    Some(end) => end + quote.len(),
                    None => bytes.len(),
                };
                decoded.extend_from_slice(&bytes[start..index]);
            }
            b'"' => {
                let quote: &[u8] = if bytes[index..].starts_with(b"\"\"\"") {
                    b"\"\"\""
                } else {
                    b"\""
                };
                index += quote.len();
                decoded.extend_from_slice(quote);
                while index < bytes.len() && !bytes[index..].starts_with(quote) {
                    if bytes[index] == b'\\' {
                        match decode_escape(bytes, index) {
                            Some((scalar, next)) => {
                                let mut buffer = [0u8; 4];
                                decoded
                                    .extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
                                index = next;
                            }
                            None => {
                                decoded.push(b'\\');
                                index += 1;
                            }
                        }
                    } else {
                        decoded.push(bytes[index]);
                        index += 1;
                    }
                }
                if bytes[index..].starts_with(quote) {
                    decoded.extend_from_slice(quote);
                    index += quote.len();
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).unwrap_or_default()
}

/// The next occurrence of `quote` at or after `from`.
fn find_quote(bytes: &[u8], from: usize, quote: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(quote.len())
        .position(|window| window == quote)
        .map(|offset| from + offset)
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
}
