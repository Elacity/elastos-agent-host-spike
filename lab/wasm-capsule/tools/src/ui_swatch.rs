//! `ui_swatch`: a colour swatch picker for lab UI screens.
//!
//! A pick is a choice of one of the host palette's token names, never a raw
//! colour value. The host owns the palette; a screen names a token and the
//! Runtime resolves it. This module therefore accepts only token names
//! (see [`SwatchPicker::pick`]) and refuses anything that carries a colour
//! value of its own.
//!
//! Preset bounds chosen for this module (stated here, small and conservative):
//! a picker holds between [`MIN_SWATCHES`] (1) and [`MAX_SWATCHES`] (32)
//! swatches.
//!
//! A pick resolves to a `palette.<token>` capability request string for the
//! Runtime to route; this crate never paints, never parses a colour, and
//! never reaches the network.

use std::fmt;

/// Smallest number of swatches a picker may hold.
pub const MIN_SWATCHES: usize = 1;
/// Largest number of swatches a picker may hold.
pub const MAX_SWATCHES: usize = 32;

/// Refusals of the swatch picker. Each variant has one stable snake_case code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwatchError {
    /// The pick carried a raw colour value such as `#ff0000`.
    RawColourNotAllowed,
    /// The pick named a token that is not in this picker.
    UnknownSwatch,
    /// A picker was built with no swatches or more than [`MAX_SWATCHES`].
    SwatchCountOutOfRange,
}

impl SwatchError {
    /// The stable code of this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            SwatchError::RawColourNotAllowed => "raw_colour_not_allowed",
            SwatchError::UnknownSwatch => "unknown_swatch",
            SwatchError::SwatchCountOutOfRange => "swatch_count_out_of_range",
        }
    }
}

impl fmt::Display for SwatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            SwatchError::RawColourNotAllowed => {
                "a raw colour value is not a palette token, name a host palette token instead"
            }
            SwatchError::UnknownSwatch => "that token is not one of this picker's swatches",
            SwatchError::SwatchCountOutOfRange => {
                "a picker holds one to thirty-two swatches"
            }
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for SwatchError {}

/// A bounded set of host palette token names a screen may choose from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwatchPicker {
    tokens: Vec<String>,
    selected: Option<String>,
}

/// True when `value` is a host palette token name: a non-empty run of
/// `a-z`, `0-9` and `-`, starting with a letter. Anything else, including
/// every form of raw colour, is not a token.
fn is_palette_token(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// True when `value` looks like a raw colour literal rather than a name.
fn is_raw_colour(value: &str) -> bool {
    value.starts_with('#') || value.starts_with("rgb") || value.starts_with("hsl")
}

impl SwatchPicker {
    /// Build a picker holding exactly `tokens`, in order. Each entry must be
    /// a palette token name; the count must be in
    /// [`MIN_SWATCHES`]..=[`MAX_SWATCHES`].
    pub fn new(tokens: &[&str]) -> Result<Self, SwatchError> {
        if tokens.len() < MIN_SWATCHES || tokens.len() > MAX_SWATCHES {
            return Err(SwatchError::SwatchCountOutOfRange);
        }
        let mut owned = Vec::with_capacity(tokens.len());
        for token in tokens {
            // A raw colour is reported as such; any other non-token is unknown.
            if is_raw_colour(token) {
                return Err(SwatchError::RawColourNotAllowed);
            }
            if !is_palette_token(token) {
                return Err(SwatchError::UnknownSwatch);
            }
            owned.push((*token).to_string());
        }
        Ok(SwatchPicker {
            tokens: owned,
            selected: None,
        })
    }

    /// The tokens this picker offers, in order.
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }

    /// The currently selected token, if a pick succeeded.
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Pick a swatch by palette token name. A raw colour value is refused
    /// with [`SwatchError::RawColourNotAllowed`]; a name that is not one of
    /// this picker's tokens is refused with [`SwatchError::UnknownSwatch`].
    pub fn pick(&mut self, pick: &str) -> Result<(), SwatchError> {
        if is_raw_colour(pick) {
            return Err(SwatchError::RawColourNotAllowed);
        }
        if !self.tokens.iter().any(|t| t == pick) {
            return Err(SwatchError::UnknownSwatch);
        }
        self.selected = Some(pick.to_string());
        Ok(())
    }

    /// Resolve the current pick to the Runtime capability request string
    /// `palette.<token>`. Returns `None` while nothing is picked.
    pub fn capability_request(&self) -> Option<String> {
        self.selected
            .as_ref()
            .map(|token| format!("palette.{}", token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P6: a screen may only choose a host palette token, so a raw colour
    // value is refused with its stable code, never painted or stored.
    #[test]
    fn raw_colour_is_refused() {
        let mut picker =
            SwatchPicker::new(&["accent", "surface"]).expect("two tokens fit the bounds");
        let err = picker.pick("#ff0000").unwrap_err();
        assert_eq!(err.code(), "raw_colour_not_allowed");
        let err = picker.pick("rgb(0, 0, 0)").unwrap_err();
        assert_eq!(err.code(), "raw_colour_not_allowed");
        assert_eq!(picker.selected(), None);
    }

    // P6: a picker can only offer tokens that exist; an unknown swatch is
    // refused with its stable code and nothing is selected.
    #[test]
    fn unknown_swatch_is_refused() {
        let mut picker =
            SwatchPicker::new(&["accent", "surface"]).expect("two tokens fit the bounds");
        let err = picker.pick("warning").unwrap_err();
        assert_eq!(err.code(), "unknown_swatch");
        assert_eq!(picker.selected(), None);
    }

    // P6: a known token picks and resolves to a Runtime capability request.
    #[test]
    fn known_token_picks_and_resolves() {
        let mut picker =
            SwatchPicker::new(&["accent", "surface"]).expect("two tokens fit the bounds");
        picker.pick("surface").expect("surface is one of the tokens");
        assert_eq!(picker.selected(), Some("surface"));
        assert_eq!(
            picker.capability_request().as_deref(),
            Some("palette.surface")
        );
    }

    // P6: the bound is one to thirty-two swatches; zero and thirty-three are
    // both refused with the count code. Every limit at its zero or edge.
    #[test]
    fn count_bounds_are_enforced() {
        let empty = SwatchPicker::new(&[]).unwrap_err();
        assert_eq!(empty.code(), "swatch_count_out_of_range");

        let one = ["accent"];
        assert_eq!(SwatchPicker::new(&one).unwrap().tokens().len(), 1);

        let many: Vec<&str> = vec!["accent"; MAX_SWATCHES];
        assert!(SwatchPicker::new(&many).is_ok());

        let too_many: Vec<&str> = vec!["accent"; MAX_SWATCHES + 1];
        let over = SwatchPicker::new(&too_many).unwrap_err();
        assert_eq!(over.code(), "swatch_count_out_of_range");
    }

    // P6: the refusal names its code before any human text, so a UI can key
    // on the code alone. Tests assert code(); Display shape is checked here
    // only for the prefix invariant.
    #[test]
    fn display_starts_with_code() {
        let err = SwatchError::RawColourNotAllowed;
        let rendered = format!("{}", err);
        assert!(rendered.starts_with("raw_colour_not_allowed: "));
        assert!(!rendered.contains("/"));
    }

    // P6: a raw colour in the offered set is refused, so a picker itself
    // cannot smuggle a value the host did not name.
    #[test]
    fn raw_colour_in_token_list_is_refused() {
        let err = SwatchPicker::new(&["accent", "#00ff00"]).unwrap_err();
        assert_eq!(err.code(), "raw_colour_not_allowed");
    }
}
