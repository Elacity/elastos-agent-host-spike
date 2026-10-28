//! KT2 (P6): validation of the capsule icon a manifest may declare.
//!
//! A capsule icon is optional. When the manifest declares none, the host
//! shows its default icon and [`IconCheck::resolve`] returns
//! [`Icon::HostDefault`]. When it declares one, the bytes are checked
//! against small conservative limits and the caller gets either
//! [`Icon::Declared`] or a [`bad_icon`](IconError::BadIcon) refusal that
//! carries a reason code.
//!
//! Preset limits (the task gives no numbers, so these are the stated ones,
//! all conservative):
//! - `max_bytes`: 64 KiB, 65536 bytes.
//! - `min_side`: 32 px, `max_side`: 512 px, and the icon must be square.
//! - Only PNG is accepted, recognised by its 8 byte signature.
//!
//! The check reads only the PNG signature and the IHDR width and height. It
//! does not decode pixels, so a declared icon whose header is sound but
//! whose pixels are corrupt is out of scope for this lab check.
//!
//! Check order is fixed: byte budget, then PNG signature, then header, then
//! squareness, then the side bounds. The byte budget is therefore the only
//! refusal a zero-length budget can produce for a nonempty declaration.
//!
//! This is a lab check and never an admission or launch decision.

use std::fmt;

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
const IHDR_LEN: usize = 8 + 8 + 13;
const U32_BYTES: usize = 4;

/// The conservative limits one icon is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconLimits {
    /// Largest accepted icon, in bytes.
    pub max_bytes: usize,
    /// Smallest accepted side, in pixels.
    pub min_side: u32,
    /// Largest accepted side, in pixels.
    pub max_side: u32,
}

impl IconLimits {
    /// The preset limits documented at the top of this module.
    pub const PRESET: IconLimits = IconLimits {
        max_bytes: 64 * 1024,
        min_side: 32,
        max_side: 512,
    };
}

impl Default for IconLimits {
    fn default() -> Self {
        IconLimits::PRESET
    }
}

/// What the host shows for a capsule once the manifest is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Icon {
    /// The manifest declared no icon; the host default applies.
    HostDefault,
    /// The manifest declared an icon that passed every check. The bytes are
    /// the declared icon, kept for the host to show.
    Declared { bytes: Vec<u8>, side: u32 },
}

/// The one error type of this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IconError {
    /// The declared icon is not a PNG.
    NotPng,
    /// The declared icon is larger than the allowed maximum.
    TooLarge,
    /// The declared icon is not square.
    NotSquare,
    /// The declared icon is smaller than the minimum side.
    TooSmall,
    /// The declared icon is larger than the maximum side.
    TooWide,
    /// The declared icon header cannot be read.
    BadHeader,
}

impl IconError {
    /// The stable snake_case code of this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            IconError::NotPng => "not_png",
            IconError::TooLarge => "too_large",
            IconError::NotSquare => "not_square",
            IconError::TooSmall => "too_small",
            IconError::TooWide => "too_wide",
            IconError::BadHeader => "bad_header",
        }
    }
}

impl fmt::Display for IconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            IconError::NotPng => "declared icon is not a PNG",
            IconError::TooLarge => "declared icon is larger than 64 KiB",
            IconError::NotSquare => "declared icon is not square",
            IconError::TooSmall => "declared icon is under 32 px a side",
            IconError::TooWide => "declared icon is over 512 px a side",
            IconError::BadHeader => "declared icon header cannot be read",
        };
        write!(f, "bad_icon/{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for IconError {}

/// The result of [`IconCheck::check`]: either an icon to show or a refusal.
pub type IconOutcome = Result<Icon, IconError>;

/// One icon check under given limits. [`IconCheck::preset`] is the lab check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconCheck {
    limits: IconLimits,
}

impl IconCheck {
    /// The check under the preset limits.
    pub const fn preset() -> IconCheck {
        IconCheck {
            limits: IconLimits::PRESET,
        }
    }

    /// The check under caller-given limits.
    pub const fn with_limits(limits: IconLimits) -> IconCheck {
        IconCheck { limits }
    }

    /// The limits this check applies.
    pub const fn limits(&self) -> IconLimits {
        self.limits
    }

    /// Resolve a manifest's icon declaration. `None` means the manifest
    /// declared no icon, so the host default applies. `Some(bytes)` is
    /// checked: a sound icon is [`Icon::Declared`], anything else is a
    /// [`bad_icon`](IconError::BadIcon) refusal carrying its reason code.
    pub fn resolve(&self, declared: Option<&[u8]>) -> IconOutcome {
        match declared {
            None => Ok(Icon::HostDefault),
            Some(bytes) => self.check(bytes),
        }
    }

    /// Check one declared icon.
    pub fn check(&self, bytes: &[u8]) -> IconOutcome {
        if bytes.len() > self.limits.max_bytes {
            return Err(IconError::TooLarge);
        }
        if bytes.len() < PNG_SIGNATURE.len() || bytes[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
            return Err(IconError::NotPng);
        }
        let (width, height) = self.header_side(bytes).ok_or(IconError::BadHeader)?;
        if width != height {
            return Err(IconError::NotSquare);
        }
        if width < self.limits.min_side {
            return Err(IconError::TooSmall);
        }
        if width > self.limits.max_side {
            return Err(IconError::TooWide);
        }
        Ok(Icon::Declared {
            bytes: bytes.to_vec(),
            side: width,
        })
    }

    /// Read the IHDR width and height of a PNG that already passed the
    /// signature check.
    fn header_side(&self, bytes: &[u8]) -> Option<(u32, u32)> {
        if bytes.len() < IHDR_LEN {
            return None;
        }
        let ihdr_at = PNG_SIGNATURE.len();
        if bytes[ihdr_at..ihdr_at + U32_BYTES] != [0, 0, 0, 13] {
            return None;
        }
        let ihdr = &bytes[ihdr_at + U32_BYTES..ihdr_at + U32_BYTES + U32_BYTES];
        if ihdr != b"IHDR" {
            return None;
        }
        let width_at = ihdr_at + U32_BYTES + U32_BYTES;
        let width = u32::from_be_bytes(read_u32(bytes, width_at)?);
        let height = u32::from_be_bytes(read_u32(bytes, width_at + U32_BYTES)?);
        Some((width, height))
    }
}

impl Default for IconCheck {
    fn default() -> Self {
        IconCheck::preset()
    }
}

fn read_u32(bytes: &[u8], at: usize) -> Option<[u8; 4]> {
    let slice = bytes.get(at..at + U32_BYTES)?;
    let mut out = [0u8; 4];
    out.copy_from_slice(slice);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PNG-shaped fixture with the given side, padded with zeros to `pad`
    /// bytes. Only the signature and IHDR are real, which is all this module
    /// reads.
    fn png(side: u32, height: u32, pad: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PNG_SIGNATURE);
        out.extend_from_slice(&[0, 0, 0, 13]);
        out.extend_from_slice(b"IHDR");
        out.extend_from_slice(&side.to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&[8, 6, 0, 0, 0]);
        while out.len() < pad {
            out.push(0);
        }
        out
    }

    fn side_of(icon: Icon) -> u32 {
        match icon {
            Icon::HostDefault => 0,
            Icon::Declared { side, .. } => side,
        }
    }

    // P6: a manifest without an icon resolves to the host default, no refusal.
    #[test]
    fn no_icon_resolves_to_host_default() {
        let check = IconCheck::preset();
        assert_eq!(check.resolve(None), Ok(Icon::HostDefault));
    }

    // P6: a sound 64 px square PNG is accepted as the declared icon and its
    // side is reported to the host.
    #[test]
    fn sound_square_png_is_declared() {
        let icon = png(64, 64, IHDR_LEN);
        let got = IconCheck::preset().resolve(Some(&icon));
        assert_eq!(got, Ok(Icon::Declared { bytes: icon, side: 64 }));
    }

    // P6: both preset side bounds are inclusive, so 32 px and 512 px pass
    // while just outside them is refused with the bound's code.
    #[test]
    fn side_bounds_are_inclusive() {
        let check = IconCheck::preset();
        assert_eq!(check.check(&png(32, 32, IHDR_LEN)).map(side_of), Ok(32));
        assert_eq!(check.check(&png(512, 512, IHDR_LEN)).map(side_of), Ok(512));
        assert_eq!(check.check(&png(31, 31, IHDR_LEN)).unwrap_err().code(), "too_small");
        assert_eq!(check.check(&png(513, 513, IHDR_LEN)).unwrap_err().code(), "too_wide");
    }

    // P6: a non-square PNG is refused with not_square, even when both sides
    // are within bounds.
    #[test]
    fn non_square_png_is_refused() {
        let err = IconCheck::preset().check(&png(64, 65, IHDR_LEN)).unwrap_err();
        assert_eq!(err.code(), "not_square");
    }

    // P6: a declared icon that is not a PNG is refused with not_png.
    #[test]
    fn non_png_is_refused() {
        let bytes = b"GIF89a not a png".to_vec();
        let err = IconCheck::preset().check(&bytes).unwrap_err();
        assert_eq!(err.code(), "not_png");
    }

    // P6: an empty declaration is not a PNG and is refused with not_png under
    // the preset budget.
    #[test]
    fn empty_declared_icon_is_refused() {
        let err = IconCheck::preset().check(&[]).unwrap_err();
        assert_eq!(err.code(), "not_png");
    }

    // P6: a declared icon over the 64 KiB preset maximum is refused with
    // too_large before its header is read.
    #[test]
    fn oversized_icon_is_refused() {
        let icon = png(64, 64, 64 * 1024 + 1);
        assert_eq!(icon.len(), 64 * 1024 + 1);
        let err = IconCheck::preset().check(&icon).unwrap_err();
        assert_eq!(err.code(), "too_large");
    }

    // P6: exactly the byte maximum is accepted, so the bound is inclusive.
    #[test]
    fn byte_maximum_is_inclusive() {
        let icon = png(64, 64, 64 * 1024);
        assert_eq!(icon.len(), 64 * 1024);
        assert!(IconCheck::preset().check(&icon).is_ok());
    }

    // P6: a PNG signature with no readable IHDR is refused with bad_header.
    #[test]
    fn truncated_header_is_refused() {
        let mut icon = PNG_SIGNATURE.to_vec();
        icon.extend_from_slice(&[0, 0, 0, 13]);
        let err = IconCheck::preset().check(&icon).unwrap_err();
        assert_eq!(err.code(), "bad_header");
    }

    // P6: Display renders the stable code then the explanation, so a refusal
    // can be logged without depending on its wording.
    #[test]
    fn display_renders_code_then_explanation() {
        let shown = format!("{}", IconError::NotSquare);
        assert!(shown.starts_with("bad_icon/not_square: "), "got {shown}");
    }

    // P6: with every limit at zero, each limit still refuses by its own code
    // and none silently defaults: a nonempty icon is over the byte budget so
    // too_large wins first; with the budget restored and the side bounds at
    // zero, a sound icon is too_wide, and an empty declaration is not_png
    // because zero bytes can never equal the PNG signature.
    #[test]
    fn zero_limits_refuse_every_icon() {
        let zero = IconLimits { max_bytes: 0, min_side: 0, max_side: 0 };
        let check = IconCheck::with_limits(zero);
        assert_eq!(check.limits(), zero);
        assert_eq!(check.check(&png(64, 64, IHDR_LEN)).unwrap_err().code(), "too_large");
        assert_eq!(check.check(&png(32, 32, IHDR_LEN)).unwrap_err().code(), "too_large");
        assert_eq!(check.check(&[]).unwrap_err().code(), "not_png");
        let tight = IconLimits { max_bytes: 64 * 1024, min_side: 0, max_side: 0 };
        let err = IconCheck::with_limits(tight)
            .check(&png(64, 64, IHDR_LEN))
            .unwrap_err();
        assert_eq!(err.code(), "too_wide");
    }

    // P6: resolve refuses a declared icon that fails a check, and the
    // refusal's code is the reason, never the host default.
    #[test]
    fn resolve_refuses_a_bad_declared_icon() {
        let bad = png(10, 10, IHDR_LEN);
        let err = IconCheck::preset().resolve(Some(&bad)).unwrap_err();
        assert_eq!(err.code(), "too_small");
    }
}
