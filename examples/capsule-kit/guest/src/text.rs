//! Is this text? The checks a guest runs on the head of an object before it
//! reads further, and on the whole object after. Moved here from the
//! documents viewer's model (`docs-model` re-exports it).
//!
//! Text here is UTF-8, with an optional UTF-8 byte order mark, and no control
//! character other than tab, line feed and carriage return. A UTF-16 or
//! UTF-32 byte order mark, a NUL, or any other control byte means it is not
//! text.

/// Why bytes are not text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextError {
    /// A UTF-16 or UTF-32 byte order mark.
    OtherEncoding,
    /// Not valid UTF-8.
    NotUtf8,
    /// A NUL or another control character.
    Control,
}

const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

fn other_encoding(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\xFF\xFE")
        || bytes.starts_with(b"\xFE\xFF")
        || bytes.starts_with(b"\x00\x00\xFE\xFF")
}

fn allowed(c: char) -> bool {
    !c.is_control() || matches!(c, '\t' | '\n' | '\r')
}

fn check_chars(text: &str) -> Result<(), TextError> {
    if text.chars().all(allowed) {
        Ok(())
    } else {
        Err(TextError::Control)
    }
}

/// The head of a document: the first bytes, which may end inside a
/// character when `more` says the document goes on.
pub fn check_head(head: &[u8], more: bool) -> Result<(), TextError> {
    if other_encoding(head) {
        return Err(TextError::OtherEncoding);
    }
    let body = head.strip_prefix(UTF8_BOM).unwrap_or(head);
    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        // Only a character cut short at the very end may be incomplete.
        Err(err) if more && err.error_len().is_none() => {
            std::str::from_utf8(&body[..err.valid_up_to()]).map_err(|_| TextError::NotUtf8)?
        }
        Err(_) => return Err(TextError::NotUtf8),
    };
    check_chars(text)
}

/// The whole document as text, without its byte order mark.
pub fn check_whole(bytes: &[u8]) -> Result<&str, TextError> {
    if other_encoding(bytes) {
        return Err(TextError::OtherEncoding);
    }
    let body = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    let text = std::str::from_utf8(body).map_err(|_| TextError::NotUtf8)?;
    check_chars(text)?;
    Ok(text)
}
