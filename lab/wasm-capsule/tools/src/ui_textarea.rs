//! A lab multiline text area node.
//!
//! This is UI state only. An edit resolves to a capability request that the
//! Runtime decides on; nothing here admits, launches or authorises anything
//! (P6). The node keeps three pieces of state consistent at all times: the
//! text, the cursor, and the limits it accepts (P10).
//!
//! Limits, chosen conservatively because the task gives no numbers:
//! * text is at most [`MAX_BYTES`] bytes (64 KiB) as UTF-8 on the wire;
//! * text is at most [`MAX_LINES`] lines (2000), where a trailing newline does
//!   not start an extra line;
//! * line endings are normalised to `\n` on the way in, so `\r\n` and a lone
//!   `\r` both become a single `\n`;
//! * the cursor is a byte offset into the normalised text and is always on a
//!   UTF-8 char boundary and within `0..=len`.
//!
//! Refusals use one error enum and one `code()` table; `Display` renders the
//! code and a short explanation and never a host path.

use std::fmt;

/// The text field accepts at most this many UTF-8 bytes (64 KiB).
pub const MAX_BYTES: usize = 64 * 1024;

/// The text field accepts at most this many lines (2000).
pub const MAX_LINES: usize = 2000;

/// Why a text area edit was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextAreaError {
    /// The normalised text is wider than [`MAX_BYTES`].
    TextTooLong,
    /// The normalised text has more than [`MAX_LINES`] lines.
    TooManyLines,
    /// The cursor offset is not within the text or not on a char boundary.
    InvalidCursor,
}

impl TextAreaError {
    /// The stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            TextAreaError::TextTooLong => "text_too_long",
            TextAreaError::TooManyLines => "too_many_lines",
            TextAreaError::InvalidCursor => "invalid_cursor",
        }
    }
}

impl fmt::Display for TextAreaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            TextAreaError::TextTooLong => "text exceeds the 64 KiB limit",
            TextAreaError::TooManyLines => "text exceeds the 2000 line limit",
            TextAreaError::InvalidCursor => "cursor is not a valid boundary in the text",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for TextAreaError {}

/// Replace every `\r\n` and lone `\r` with a single `\n`.
pub fn normalise_line_endings(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    out
}

/// Count lines in already normalised text: one more than the number of
/// `\n`, except a trailing `\n` does not start a new line. Empty text is one
/// line.
fn count_lines(text: &str) -> usize {
    if text.is_empty() {
        return 1;
    }
    let newlines = text.bytes().filter(|b| *b == b'\n').count();
    if text.ends_with('\n') {
        newlines
    } else {
        newlines + 1
    }
}

/// The largest char boundary at or below `offset` within `text`.
fn floor_boundary(text: &str, offset: usize) -> usize {
    let mut at = offset.min(text.len());
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// A multiline text area node with a bounded text buffer and a valid cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextArea {
    text: String,
    cursor: usize,
}

impl Default for TextArea {
    fn default() -> Self {
        Self::new()
    }
}

impl TextArea {
    /// An empty text area with the cursor at zero.
    pub fn new() -> Self {
        TextArea {
            text: String::new(),
            cursor: 0,
        }
    }

    /// The current text, always normalised to `\n` line endings.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The cursor as a byte offset into [`TextArea::text`], on a char
    /// boundary and within `0..=text().len()`.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Number of lines currently shown (a trailing newline does not start an
    /// extra line; empty text is one line).
    pub fn line_count(&self) -> usize {
        count_lines(&self.text)
    }

    /// Replace the whole text, normalising line endings and checking limits.
    /// The cursor clamps to the end of the new text.
    pub fn set_text(&mut self, input: &str) -> Result<(), TextAreaError> {
        let normalised = normalise_line_endings(input);
        Self::check(&normalised)?;
        self.cursor = normalised.len();
        self.text = normalised;
        Ok(())
    }

    /// Replace the whole text and place the cursor, normalising line endings
    /// and checking limits. The cursor must be a char boundary.
    pub fn replace(
        &mut self,
        input: &str,
        cursor: usize,
    ) -> Result<(), TextAreaError> {
        let normalised = normalise_line_endings(input);
        Self::check(&normalised)?;
        if !normalised.is_char_boundary(cursor) {
            return Err(TextAreaError::InvalidCursor);
        }
        self.cursor = cursor;
        self.text = normalised;
        Ok(())
    }

    /// Insert a string at the cursor, normalising its line endings. The
    /// cursor moves to the end of the inserted text.
    pub fn insert(&mut self, input: &str) -> Result<(), TextAreaError> {
        let addition = normalise_line_endings(input);
        let mut next = String::with_capacity(self.text.len() + addition.len());
        next.push_str(&self.text[..self.cursor]);
        next.push_str(&addition);
        next.push_str(&self.text[self.cursor..]);
        Self::check(&next)?;
        let cursor = self.cursor + addition.len();
        self.text = next;
        self.cursor = floor_boundary(&self.text, cursor);
        Ok(())
    }

    /// Move the cursor to `offset`. The offset must be within the text and on
    /// a char boundary.
    pub fn set_cursor(&mut self, offset: usize) -> Result<(), TextAreaError> {
        if !self.text.is_char_boundary(offset) {
            return Err(TextAreaError::InvalidCursor);
        }
        self.cursor = offset;
        Ok(())
    }

    /// Empty the text and reset the cursor to zero.
    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }

    /// The text and cursor as a wire-ready pair, for a capability request.
    pub fn snapshot(&self) -> (&str, usize) {
        (&self.text, self.cursor)
    }

    /// Reject text that is past a limit. Byte length is measured on the
    /// normalised UTF-8 text (P6).
    fn check(text: &str) -> Result<(), TextAreaError> {
        if text.len() > MAX_BYTES {
            return Err(TextAreaError::TextTooLong);
        }
        if count_lines(text) > MAX_LINES {
            return Err(TextAreaError::TooManyLines);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P6: a resource bound is enforced with its named refusal.
    #[test]
    fn over_64kib_is_refused_with_text_too_long() {
        let mut area = TextArea::new();
        let big = "a".repeat(MAX_BYTES + 1);
        let err = area.set_text(&big).unwrap_err();
        assert_eq!(err.code(), "text_too_long");
        // The refused edit left the node unchanged.
        assert_eq!(area.text(), "");
        assert_eq!(area.cursor(), 0);
    }

    // P6: the boundary value is accepted, one byte over is not.
    #[test]
    fn exactly_64kib_is_accepted() {
        let mut area = TextArea::new();
        let ok = "a".repeat(MAX_BYTES);
        area.set_text(&ok).expect("boundary text is accepted");
        assert_eq!(area.text().len(), MAX_BYTES);
    }

    // P6: the line bound is enforced with its named refusal.
    #[test]
    fn over_2000_lines_is_refused_with_too_many_lines() {
        let mut area = TextArea::new();
        // 2001 lines needs 2000 newlines.
        let many = "x\n".repeat(MAX_LINES) + "x";
        let err = area.set_text(&many).unwrap_err();
        assert_eq!(err.code(), "too_many_lines");
        assert_eq!(area.text(), "");
    }

    // P6: exactly 2000 lines is accepted and counted correctly.
    #[test]
    fn exactly_2000_lines_is_accepted() {
        let mut area = TextArea::new();
        let ok = "x\n".repeat(MAX_LINES - 1) + "x";
        area.set_text(&ok).expect("2000 lines accepted");
        assert_eq!(area.line_count(), MAX_LINES);
    }

    // P10: line endings are normalised so the node has one canonical text.
    #[test]
    fn crlf_and_cr_become_lf() {
        let mut area = TextArea::new();
        area.set_text("a\r\nb\rc\n").expect("finite text");
        assert_eq!(area.text(), "a\nb\nc\n");
        assert!(area.text().bytes().all(|b| b != b'\r'));
    }

    // P10: the cursor stays valid and on a char boundary after edits.
    #[test]
    fn cursor_stays_valid_after_insert_and_replace() {
        let mut area = TextArea::new();
        area.set_text("hello").expect("small text");
        area.set_cursor(5).expect("end is a boundary");
        area.insert("\r\nworld").expect("insert is in limits");
        assert_eq!(area.text(), "hello\nworld");
        assert_eq!(area.cursor(), "hello\nworld".len());
        assert!(area.text().is_char_boundary(area.cursor()));
    }

    // P10: a refused insert does not corrupt text or cursor.
    #[test]
    fn refused_insert_leaves_state_consistent() {
        let mut area = TextArea::new();
        area.set_text("keep").expect("small text");
        area.set_cursor(4).expect("end is a boundary");
        let big = "z".repeat(MAX_BYTES);
        let err = area.insert(&big).unwrap_err();
        assert_eq!(err.code(), "text_too_long");
        assert_eq!(area.text(), "keep");
        assert_eq!(area.cursor(), 4);
    }

    // P10: set_text clamps the cursor into the new shorter text.
    #[test]
    fn set_text_clamps_cursor_to_end() {
        let mut area = TextArea::new();
        area.replace("abcdef", 6).expect("small text");
        area.set_text("ab").expect("small text");
        assert_eq!(area.cursor(), 2);
        assert!(area.text().is_char_boundary(area.cursor()));
    }

    // P10: a non-boundary cursor is refused, not silently split.
    #[test]
    fn non_boundary_cursor_is_refused() {
        let mut area = TextArea::new();
        // "é" is two bytes; offset 1 is inside it.
        let err = area.replace("é", 1).unwrap_err();
        assert_eq!(err.code(), "invalid_cursor");
        let mut area2 = TextArea::new();
        area2.set_text("é").expect("small text");
        let err2 = area2.set_cursor(1).unwrap_err();
        assert_eq!(err2.code(), "invalid_cursor");
    }

    // P6: refusing preserves the previous text, so edits are atomic.
    #[test]
    fn failed_edit_is_atomic() {
        let mut area = TextArea::new();
        area.set_text("safe\r\ntext").expect("small text");
        let many = "\n".repeat(MAX_LINES + 1);
        assert_eq!(area.set_text(&many).unwrap_err().code(), "too_many_lines");
        assert_eq!(area.text(), "safe\ntext");
    }

    // P10: every limit at zero state is still a valid, consistent node.
    #[test]
    fn zero_limits_state_is_consistent() {
        let area = TextArea::new();
        assert_eq!(area.text(), "");
        assert_eq!(area.cursor(), 0);
        assert_eq!(area.line_count(), 1);
        assert_eq!(area.snapshot(), ("", 0));
    }

    // P6: the display form carries the code and a human explanation only.
    #[test]
    fn display_carries_code_and_explanation() {
        let rendered = TextAreaError::TextTooLong.to_string();
        assert!(rendered.starts_with("text_too_long: "));
        let rendered_lines = TextAreaError::TooManyLines.to_string();
        assert!(rendered_lines.starts_with("too_many_lines: "));
    }
}
