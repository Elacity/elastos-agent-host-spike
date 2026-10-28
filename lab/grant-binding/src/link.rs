//! The one detector for a path, git, or registry dependency on this crate.

/// True when the decoded text is a path, git, registry, table, dotted, or workspace dependency on this crate.
///
/// A manifest that only names the crate, including its own `version` field, is not a link.
#[rustfmt::skip]
pub fn cargo_toml_path_depends_on_grant_binding(cargo_toml: &str) -> bool {
    let cargo_toml = decode_toml_basic_strings(cargo_toml);
    let packed: String = cargo_toml.chars().filter(|ch| !ch.is_whitespace()).collect();
    let unquoted = packed.replace(['"', '\''], "");
    cargo_toml.contains("grant-binding")
        && (cargo_toml.contains("path")
            || packed.split("grant-binding").skip(1).any(|suffix| {
                suffix.trim_start_matches(['"', '\'']).strip_prefix('=')
                    .is_some_and(|value| value.starts_with(['"', '\'']))
            })
            || ((unquoted.contains("grant-binding={")
                || unquoted.contains("grant-binding.git=")
                || unquoted.contains("grant-binding.version=")
                || unquoted.contains("grant-binding.workspace=")
                || unquoted.contains(".grant-binding]")
                || unquoted.contains("package=grant-binding"))
                && (unquoted.contains("git=")
                    || unquoted.contains("version=")
                    || unquoted.contains("workspace="))))
}

/// Decode escapes in TOML basic strings, so an escaped link stays visible.
///
/// Text outside a string and every literal string (`'...'` or `'''...'''`) is
/// copied unchanged. A `#` comment is omitted through the end of its line, so
/// comment text is not a path link. Only a basic string (`"..."` or
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

/// The index just after a TOML line-ending escape at `index`.
///
/// `index` is the backslash. The escape and the whitespace after its newline
/// produce no characters. A letter escape is not this form.
fn line_ending_escape_end(bytes: &[u8], index: usize) -> Option<usize> {
    let mut next = index + 1;
    if bytes.get(next) == Some(&b'\r') {
        next += 1;
    }
    if bytes.get(next) != Some(&b'\n') {
        return None;
    }
    next += 1;
    while matches!(bytes.get(next), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        next += 1;
    }
    Some(next)
}

/// Decode one escape at `index`, or copy it as source, and return the next.
fn copy_escape(bytes: &[u8], index: usize, decoded: &mut Vec<u8>) -> usize {
    if let Some(next) = line_ending_escape_end(bytes, index) {
        return next;
    }
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

#[test]
fn model_multiline_basic_string_escape_is_a_link() {
    let multiline = "gb = { path = \"\"\"../grant-bind\\u0069ng\"\"\", package = \"\"\"grant-bind\\u0069ng\"\"\" }\n";
    assert!(!multiline.contains("grant-binding"));
    assert!(multiline.contains("\\u0069"));
    assert!(multiline.contains("\"\"\""));
    assert!(cargo_toml_path_depends_on_grant_binding(multiline));
}

#[test]
fn model_unknown_hex_escape_is_not_a_link() {
    let hex = "gb = { path = \"../grant-bind\\x69ng\", package = \"grant-bind\\x69ng\" }\n";
    assert!(!hex.contains("grant-binding"));
    assert!(hex.contains("\\x69"));
    assert!(!cargo_toml_path_depends_on_grant_binding(hex));
}

#[test]
fn model_uppercase_hex_escape_is_a_link() {
    let upper = "gb = { path = \"../grant-bindi\\u006Eg\", package = \"grant-bindi\\u006Eg\" }\n";
    assert!(!upper.contains("grant-binding"));
    assert!(upper.contains("\\u006E"));
    assert!(cargo_toml_path_depends_on_grant_binding(upper));
}

#[test]
fn model_lowercase_hex_escape_is_a_link() {
    let lower = "gb = { path = \"../grant-bindi\\u006eg\", package = \"grant-bindi\\u006eg\" }\n";
    assert!(!lower.contains("grant-binding"));
    assert!(lower.contains("\\u006e"));
    assert!(cargo_toml_path_depends_on_grant_binding(lower));
}

#[test]
fn model_newline_escape_is_not_a_link() {
    let escaped = "gb = { path = \"../grant-bindi\\ng\", package = \"grant-bindi\\ng\" }\n";
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\n"));
    assert!(!cargo_toml_path_depends_on_grant_binding(escaped));
}

#[test]
fn model_backspace_escape_is_not_a_link() {
    let escaped = "gb = { path = \"../grant-\\binding\", package = \"grant-\\binding\" }\n";
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\b"));
    assert!(!cargo_toml_path_depends_on_grant_binding(escaped));
}

#[test]
fn model_tab_escape_is_not_a_link() {
    let escaped = "gb = { path = \"../gran\\t-binding\", package = \"gran\\t-binding\" }\n";
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\t"));
    assert!(!cargo_toml_path_depends_on_grant_binding(escaped));
}

#[test]
fn model_carriage_return_escape_is_not_a_link() {
    let escaped = "gb = { path = \"../g\\rant-binding\", package = \"g\\rant-binding\" }\n";
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\r"));
    assert!(!cargo_toml_path_depends_on_grant_binding(escaped));
}

#[test]
fn model_line_ending_escape_is_a_link() {
    let lf = "gb = { path = \"\"\"../grant-bindi\\\nng\"\"\", package = \"\"\"grant-bindi\\\nng\"\"\" }\n";
    assert!(!lf.contains("grant-binding"));
    assert!(lf.contains("\\\n"));
    assert!(cargo_toml_path_depends_on_grant_binding(lf));
    let crlf = "gb = { path = \"\"\"../grant-bindi\\\r\nng\"\"\", package = \"\"\"grant-bindi\\\r\nng\"\"\" }\n";
    assert!(!crlf.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(crlf));
    let spaced = "gb = { path = \"\"\"../grant-bindi\\\n  ng\"\"\", package = \"\"\"grant-bindi\\\n  ng\"\"\" }\n";
    assert!(!spaced.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(spaced));
    let literal = "gb = { path = '''../grant-bindi\\\nng''', package = '''grant-bindi\\\nng''' }\n";
    assert!(!literal.contains("grant-binding"));
    assert!(!cargo_toml_path_depends_on_grant_binding(literal));
}

#[test]
fn model_comment_is_not_a_path_link() {
    let whole_line = "# path = \"../grant-binding\"\nname = \"other\"\n";
    assert!(whole_line.contains("grant-binding"));
    assert!(whole_line.contains("path"));
    assert!(!cargo_toml_path_depends_on_grant_binding(whole_line));
    let trailing = "name = \"grant-binding\" # path = \"lab/grant-binding\"\n";
    assert!(trailing.contains("grant-binding"));
    assert!(trailing.contains("path"));
    assert!(!cargo_toml_path_depends_on_grant_binding(trailing));
    let followed = "# path = \"../grant-binding\"\ngb = { path = \"../grant-binding\" }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(followed));
}

#[test]
fn model_literal_string_path_is_a_link() {
    let single = "gb = { path = '../grant-binding' }\n";
    assert!(single.contains("grant-binding"));
    assert!(single.contains("path"));
    assert!(cargo_toml_path_depends_on_grant_binding(single));
    let multi = "gb = { path = '''../grant-binding''' }\n";
    assert!(multi.contains("grant-binding"));
    assert!(multi.contains("path"));
    assert!(cargo_toml_path_depends_on_grant_binding(multi));
    let escaped = "gb = { path = '../grant-bind\\u0069ng' }\n";
    assert!(!escaped.contains("grant-binding"));
    assert!(!cargo_toml_path_depends_on_grant_binding(escaped));
}

#[test]
fn model_case_different_manifest_is_not_a_link() {
    let renamed = "Grant-Binding = { path = \"lab/Grant-Binding\" }\n";
    assert!(renamed.contains("path"));
    assert!(!renamed.contains("grant-binding"));
    assert!(!cargo_toml_path_depends_on_grant_binding(renamed));
    let key = "grant-binding = { Path = \"lab/grant-binding\" }\n";
    assert!(key.contains("grant-binding"));
    assert!(!key.contains("path"));
    assert!(!cargo_toml_path_depends_on_grant_binding(key));
}

#[test]
fn model_hash_inside_a_string_is_still_a_link() {
    let basic = "note = \"uses # syntax\"; gb = { path = \"../grant-binding\" }\n";
    assert!(basic.contains("grant-binding"));
    assert!(basic.contains("path"));
    assert!(cargo_toml_path_depends_on_grant_binding(basic));
    let literal = "note = 'uses # syntax'; gb = { path = '../grant-binding' }\n";
    assert!(literal.contains("grant-binding"));
    assert!(literal.contains("path"));
    assert!(cargo_toml_path_depends_on_grant_binding(literal));
}

#[test]
fn model_git_or_registry_dependency_is_a_link() {
    let git = "grant-binding = { git = \"https://example.com/gb.git\" }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(git));
    let git_tight = "grant-binding={git=\"https://example.com/gb.git\"}\n";
    assert!(cargo_toml_path_depends_on_grant_binding(git_tight));
    let version = "grant-binding = { version = \"1.2.3\" }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(version));
    let version_tight = "grant-binding={version=\"1.2.3\"}\n";
    assert!(cargo_toml_path_depends_on_grant_binding(version_tight));
    let inline = "grant-binding = \"1.2.3\"\n";
    assert!(cargo_toml_path_depends_on_grant_binding(inline));
    let inline_tight = "grant-binding=\"1.2.3\"\n";
    assert!(cargo_toml_path_depends_on_grant_binding(inline_tight));
    let package = "gb = { package = \"grant-binding\", version = \"1.2.3\" }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(package));
    let package_git =
        "gb = { package = \"grant-binding\", git = \"https://example.com/gb.git\" }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(package_git));
    let version_after_options =
        "[dependencies]\ngrant-binding = { default-features = false, version = \"1.2.3\" }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(
        version_after_options
    ));
    let git_after_options = "[dependencies]\ngrant-binding = { default-features = false, git = \"https://example.com/gb.git\" }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(git_after_options));
    let literal_version = "[dependencies]\ngrant-binding = '1.2.3'\n";
    assert!(cargo_toml_path_depends_on_grant_binding(literal_version));
    let version_table = "[dependencies.grant-binding]\nversion = \"1.2.3\"\n";
    assert!(cargo_toml_path_depends_on_grant_binding(version_table));
    for manifest in [
        "[dependencies.grant-binding]\ndefault-features = false\ngit = 'https://example.com/gb.git'\n",
        "[dependencies]\ngrant-binding = { features = ['fixture'], registry = 'fixture', version = '1.2.3' }\n",
        "[dependencies]\n'grant-binding' = '1.2.3'\n",
        "[dependencies]\n\"grant-binding\" = \"1.2.3\"\n",
        "[dependencies]\n\"grant-b\\u0069nding\" = '1.2.3'\n",
        "[dependencies]\ngrant-binding = '''1.2.3'''\n",
        "[dependencies]\ngrant-binding = \"\"\"1.2.3\"\"\"\n",
        "[dependencies]\n'grant-binding' = { 'default-features' = false, 'version' = '1.2.3' }\n",
        "[dependencies]\n\"grant-binding\" = { \"default-features\" = false, \"git\" = 'https://example.com/gb.git' }\n",
        "['dependencies'.'grant-binding']\n'version' = '1.2.3'\n",
        "[\"dependencies\".\"grant-binding\"]\n\"git\" = 'https://example.com/gb.git'\n",
        "[dependencies]\ngrant-binding.version = '1.2.3'\n",
        "[dependencies]\n'grant-binding'.'git' = 'https://example.com/gb.git'\n",
        "dependencies.grant-binding.version = '1.2.3'\n",
        "dependencies = { grant-binding = { default-features = false, git = 'https://example.com/gb.git' } }\n",
        "[dependencies]\ngb = { default-features = false, package = 'grant-binding', version = '1.2.3' }\n",
        "[dependencies]\ngb = { git = 'https://example.com/gb.git', 'package' = 'grant-binding' }\n",
        "[dependencies]\ngb = { \"version\" = '1.2.3', \"package\" = \"grant-binding\" }\n",
        "[dependencies]\ngb = { version = '1.2.3', package = '''grant-binding''' }\n",
        "[dependencies]\ngb = { git = 'https://example.com/gb.git', package = \"\"\"grant-binding\"\"\" }\n",
        "[dependencies.gb]\nversion = '1.2.3'\npackage = 'grant-binding'\n",
        "[dependencies.gb]\npackage = 'grant-binding'\ngit = 'https://example.com/gb.git'\n",
        "[dependencies]\ngb.package = 'grant-binding'\ngb.version = '1.2.3'\n",
        "[dev-dependencies.grant-binding]\nversion = '1.2.3'\n",
        "[build-dependencies.grant-binding]\ngit = 'https://example.com/gb.git'\n",
        "[target.'cfg(unix)'.dependencies.grant-binding]\nversion = '1.2.3'\n",
        "[workspace.dependencies.grant-binding]\nversion = '1.2.3'\n",
    ] {
        assert!(cargo_toml_path_depends_on_grant_binding(manifest), "{manifest}");
    }
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "name = \"grant-binding\"\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "name = \"grant-binding\"\nversion = \"0.1.0\"\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "package = \"grant-binding\"\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "Grant-Binding = { git = \"https://example.com/gb.git\" }\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "Grant-Binding = { version = \"1.2.3\" }\n"
    ));
    for manifest in [
        "[package]\nname = 'grant-binding'\nversion = '1.2.3'\n",
        "[package]\n\"name\" = \"grant-binding\"\n\"version\" = '1.2.3'\n",
        "[dependencies]\ngb = { package = 'grant-binding' }\n",
        "[dependencies]\n'Grant-Binding' = '1.2.3'\n",
        "[dependencies.Grant-Binding]\nversion = '1.2.3'\n",
        "[dependencies]\ngrant-binding = { Version = '1.2.3' }\n",
        "[dependencies.grant-binding]\nGit = 'https://example.com/gb.git'\n",
        "[dependencies]\n# grant-binding = '1.2.3'\n",
    ] {
        assert!(
            !cargo_toml_path_depends_on_grant_binding(manifest),
            "{manifest}"
        );
    }
}

#[test]
fn model_table_or_dotted_dependency_is_a_link() {
    let branch_first =
        "grant-binding = { branch = \"main\", git = \"https://example.com/gb.git\" }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(branch_first));
    let registry_first = "grant-binding = { registry = \"crates-io\", version = \"1.2.3\" }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(registry_first));
    let workspace = "grant-binding = { workspace = true }\n";
    assert!(cargo_toml_path_depends_on_grant_binding(workspace));
    let table = "[dependencies.grant-binding]\nversion = \"1.2.3\"\n";
    assert!(cargo_toml_path_depends_on_grant_binding(table));
    let dev_table = "[dev-dependencies.grant-binding]\ngit = \"https://example.com/gb.git\"\n";
    assert!(cargo_toml_path_depends_on_grant_binding(dev_table));
    let patch_table = "[patch.crates-io.grant-binding]\ngit = \"https://example.com/gb.git\"\n";
    assert!(cargo_toml_path_depends_on_grant_binding(patch_table));
    let dotted_version = "grant-binding.version = \"1.2.3\"\n";
    assert!(cargo_toml_path_depends_on_grant_binding(dotted_version));
    let dotted_git = "grant-binding.git = \"https://example.com/gb.git\"\n";
    assert!(cargo_toml_path_depends_on_grant_binding(dotted_git));
    let dotted_workspace = "grant-binding.workspace = true\n";
    assert!(cargo_toml_path_depends_on_grant_binding(dotted_workspace));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "name = \"grant-binding\"\nversion = \"0.1.0\"\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "package = \"grant-binding\"\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "serde = { workspace = true }\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "other = { git = \"https://example.com/grant-binding.git\" }\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "[dependencies.grant-binding]\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "Grant-Binding.version = \"1.2.3\"\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "[dependencies.Grant-Binding]\nversion = \"1.2.3\"\n"
    ));
}
