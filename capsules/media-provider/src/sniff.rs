// Built-by: deepseek-v4.1-flash-1017-ultrafast

//! Magic-byte media type detection and declared-type verification.
//!
//! P13: no untyped bytes cross a trust boundary; the provider pins the real
//! container before acting. P2: a signed `declared_type` is a claim, so it is
//! checked against the bytes rather than believed. This module is pure std with
//! no I/O and no external crates, so it is cheap to run on the first bytes of
//! every input and needs no extra dependencies.

/// A media container recognised from its leading magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    /// PNG image, `image/png`.
    Png,
    /// JPEG image, `image/jpeg`.
    Jpeg,
    /// GIF image, `image/gif`.
    Gif,
    /// WebP image, `image/webp`.
    Webp,
}

impl MediaType {
    /// The canonical MIME type for this container.
    pub fn mime_type(self) -> &'static str {
        match self {
            MediaType::Png => "image/png",
            MediaType::Jpeg => "image/jpeg",
            MediaType::Gif => "image/gif",
            MediaType::Webp => "image/webp",
        }
    }
}

/// A refusal from [`sniff`] or [`check_declared`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffError {
    /// The bytes are not PNG, JPEG, GIF or WebP.
    UnknownMediaType,
    /// The declared MIME type is not one this provider supports.
    UnsupportedDeclaredType,
    /// The signed declared type and the sniffed type disagree.
    TypeMismatch,
}

impl SniffError {
    /// The stable refusal reason string carried to the Runtime.
    pub fn reason(self) -> &'static str {
        match self {
            SniffError::UnknownMediaType => "unknown-media-type",
            SniffError::UnsupportedDeclaredType => "unknown-media-type",
            SniffError::TypeMismatch => "type-mismatch",
        }
    }
}

const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const JPEG_SIGNATURE: [u8; 3] = [0xFF, 0xD8, 0xFF];
const GIF87A_SIGNATURE: [u8; 6] = *b"GIF87a";
const GIF89A_SIGNATURE: [u8; 6] = *b"GIF89a";
const WEBP_RIFF_SIGNATURE: [u8; 4] = *b"RIFF";
const WEBP_FORM_TYPE: [u8; 4] = *b"WEBP";

/// Detect the media type from the leading magic bytes.
///
/// Returns `Err(SniffError::UnknownMediaType)` when the bytes match none of the
/// supported containers (including truncated inputs that cannot be proven).
pub fn sniff(bytes: &[u8]) -> Result<MediaType, SniffError> {
    if bytes.starts_with(&PNG_SIGNATURE) {
        return Ok(MediaType::Png);
    }
    if bytes.starts_with(&JPEG_SIGNATURE) {
        return Ok(MediaType::Jpeg);
    }
    if bytes.starts_with(&GIF87A_SIGNATURE) || bytes.starts_with(&GIF89A_SIGNATURE) {
        return Ok(MediaType::Gif);
    }
    if bytes.len() >= 12 && bytes[..4] == WEBP_RIFF_SIGNATURE && bytes[8..12] == WEBP_FORM_TYPE {
        return Ok(MediaType::Webp);
    }
    Err(SniffError::UnknownMediaType)
}

/// Parse a declared MIME type into a supported [`MediaType`].
fn parse_declared(declared_type: &str) -> Option<MediaType> {
    let trimmed = declared_type.split(';').next().unwrap_or("").trim();
    if trimmed.eq_ignore_ascii_case("image/png") {
        Some(MediaType::Png)
    } else if trimmed.eq_ignore_ascii_case("image/jpeg")
        || trimmed.eq_ignore_ascii_case("image/jpg")
    {
        Some(MediaType::Jpeg)
    } else if trimmed.eq_ignore_ascii_case("image/gif") {
        Some(MediaType::Gif)
    } else if trimmed.eq_ignore_ascii_case("image/webp") {
        Some(MediaType::Webp)
    } else {
        None
    }
}

/// Check the signed declared type against the bytes.
///
/// P2: the declaration is verified, never assumed. Refuses with
/// `unknown-media-type` when the signature is not recognised or the declared
/// type is unsupported, and with `type-mismatch` when the two disagree. On
/// success returns the sniffed [`MediaType`] so the caller can sign the type
/// that was actually verified.
pub fn check_declared(bytes: &[u8], declared_type: &str) -> Result<MediaType, SniffError> {
    let sniffed = sniff(bytes)?;
    let declared = parse_declared(declared_type).ok_or(SniffError::UnsupportedDeclaredType)?;
    if sniffed != declared {
        return Err(SniffError::TypeMismatch);
    }
    Ok(sniffed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // P13: each container is recognised from its own magic bytes.
    #[test]
    fn sniff_detects_each_supported_container() {
        assert_eq!(
            sniff(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap(),
            MediaType::Png
        );
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap(), MediaType::Jpeg);
        assert_eq!(sniff(b"GIF87a").unwrap(), MediaType::Gif);
        assert_eq!(sniff(b"GIF89a").unwrap(), MediaType::Gif);
        let mut webp = Vec::from(*b"RIFF");
        webp.extend_from_slice(&[0x24, 0x00, 0x00, 0x00]);
        webp.extend_from_slice(b"WEBPVP8 ");
        assert_eq!(sniff(&webp).unwrap(), MediaType::Webp);
    }

    // P13 falsifier: unrecognised and truncated inputs are refused, not guessed.
    #[test]
    fn sniff_refuses_unknown_media_type() {
        for bad in [
            b"".as_slice(),
            b"\x00\x01\x02\x03".as_slice(),
            b"RIFF\x24\x00\x00\x00XXXX".as_slice(),
            &PNG_SIGNATURE[..7],
        ] {
            assert_eq!(sniff(bad), Err(SniffError::UnknownMediaType));
            assert_eq!(sniff(bad).unwrap_err().reason(), "unknown-media-type");
        }
    }

    // P2: a matching declaration is accepted and the sniffed type returned.
    #[test]
    fn check_declared_accepts_matching_type() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(check_declared(&png, "image/png").unwrap(), MediaType::Png);
        assert_eq!(
            check_declared(&png, "IMAGE/PNG; q=1").unwrap(),
            MediaType::Png
        );
        assert_eq!(
            check_declared(&[0xFF, 0xD8, 0xFF, 0xE0], "image/jpeg").unwrap(),
            MediaType::Jpeg
        );
    }

    // P2 falsifier: a lying declaration (PNG bytes, JPEG claim) is refused with
    // the exact reason string, not silently accepted.
    #[test]
    fn check_declared_refuses_type_mismatch() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let err = check_declared(&png, "image/jpeg").unwrap_err();
        assert_eq!(err, SniffError::TypeMismatch);
        assert_eq!(err.reason(), "type-mismatch");

        let mut webp = Vec::from(*b"RIFF");
        webp.extend_from_slice(&[0x24, 0x00, 0x00, 0x00]);
        webp.extend_from_slice(b"WEBPVP8 ");
        assert_eq!(
            check_declared(&webp, "image/png").unwrap_err().reason(),
            "type-mismatch"
        );
    }

    // P2: an unsupported declared type is refused as unknown, never coerced.
    #[test]
    fn check_declared_refuses_unsupported_or_unknown_declared_type() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(
            check_declared(&png, "video/mp4").unwrap_err().reason(),
            "unknown-media-type"
        );
        assert_eq!(
            check_declared(b"not-an-image", "image/png")
                .unwrap_err()
                .reason(),
            "unknown-media-type"
        );
    }
}

// Built-by: deepseek-v4.1-flash-1017-ultrafast
