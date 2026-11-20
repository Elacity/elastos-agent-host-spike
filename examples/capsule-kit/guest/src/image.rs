//! Magic bytes and frame dimensions for PNG, JPEG and WebP. Moved here from
//! the photo viewer.
//!
//! Only the container headers are read. Nothing here decodes pixels.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Png,
    Jpeg,
    Webp,
}

impl Kind {
    pub fn mime(self) -> &'static str {
        match self {
            Kind::Png => "image/png",
            Kind::Jpeg => "image/jpeg",
            Kind::Webp => "image/webp",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The bytes end before the header that names the type or the size.
    Truncated,
    /// The bytes are not PNG, JPEG or WebP.
    UnknownType,
    /// The type is known but its header is not well formed.
    Malformed,
}

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG_MAGIC: &[u8] = b"\xff\xd8\xff";
const RIFF_MAGIC: &[u8] = b"RIFF";
const WEBP_MAGIC: &[u8] = b"WEBP";

/// Bytes needed to tell the three types apart.
pub const SNIFF_BYTES: usize = 12;

/// Names the type from the first bytes of an object.
pub fn sniff(header: &[u8]) -> Result<Kind, HeaderError> {
    if header.starts_with(PNG_MAGIC) {
        return Ok(Kind::Png);
    }
    if header.starts_with(JPEG_MAGIC) {
        return Ok(Kind::Jpeg);
    }
    if header.len() >= SNIFF_BYTES && header.starts_with(RIFF_MAGIC) && &header[8..12] == WEBP_MAGIC
    {
        return Ok(Kind::Webp);
    }
    if is_prefix_of_magic(header) {
        return Err(HeaderError::Truncated);
    }
    Err(HeaderError::UnknownType)
}

fn is_prefix_of_magic(header: &[u8]) -> bool {
    if header.len() < PNG_MAGIC.len() && PNG_MAGIC.starts_with(header) {
        return true;
    }
    if header.len() < JPEG_MAGIC.len() && JPEG_MAGIC.starts_with(header) {
        return true;
    }
    // A RIFF header shorter than "RIFF" + size + "WEBP".
    if header.len() < SNIFF_BYTES {
        let riff = header.len().min(RIFF_MAGIC.len());
        if header[..riff] == RIFF_MAGIC[..riff] {
            let webp_start = 8;
            if header.len() <= webp_start {
                return true;
            }
            let have = &header[webp_start..];
            return WEBP_MAGIC.starts_with(have);
        }
    }
    false
}

/// Bytes read before the type is known. Enough for the PNG IHDR and the
/// WebP VP8, VP8L and VP8X frame headers.
pub const HEADER_BYTES: u64 = 32;

/// Width and height of a PNG or WebP from its first [`HEADER_BYTES`] bytes.
///
/// JPEG keeps its frame header after a run of marker segments; use
/// [`jpeg_dimensions`] for it.
pub fn header_dimensions(kind: Kind, header: &[u8]) -> Result<(u32, u32), HeaderError> {
    let (width, height) = match kind {
        Kind::Png => png_dimensions(header)?,
        Kind::Webp => webp_dimensions(header)?,
        Kind::Jpeg => return Err(HeaderError::Malformed),
    };
    nonzero(width, height)
}

fn nonzero(width: u32, height: u32) -> Result<(u32, u32), HeaderError> {
    if width == 0 || height == 0 {
        return Err(HeaderError::Malformed);
    }
    Ok((width, height))
}

/// Segments a JPEG may have before its frame header.
pub const MAX_JPEG_SEGMENTS: usize = 32;

/// JPEG: walk the marker segments to the first start-of-frame, reading only
/// each 4-byte marker and length and the 5 bytes of the frame header.
/// Segment payloads (EXIF, ICC, thumbnails) are skipped, not read.
///
/// `read(offset, length)` returns at most `length` bytes; fewer means the
/// object ends there. Its error stops the walk unchanged.
pub fn jpeg_dimensions<E>(
    mut read: impl FnMut(u64, u64) -> Result<Vec<u8>, E>,
) -> Result<Result<(u32, u32), HeaderError>, E> {
    let mut at: u64 = 2;
    for _ in 0..MAX_JPEG_SEGMENTS {
        let marker = read(at, 4)?;
        if marker.len() < 2 {
            return Ok(Err(HeaderError::Truncated));
        }
        if marker[0] != 0xff {
            return Ok(Err(HeaderError::Malformed));
        }
        match marker[1] {
            // Fill byte before a marker.
            0xff => {
                at += 1;
                continue;
            }
            // Markers without a length.
            0x01 | 0xd0..=0xd7 => {
                at += 2;
                continue;
            }
            // Scan data or end of image before any frame header.
            0xd9 | 0xda => return Ok(Err(HeaderError::Malformed)),
            _ => {}
        }
        if marker.len() < 4 {
            return Ok(Err(HeaderError::Truncated));
        }
        let segment = u64::from(be_u16(&marker, 2));
        if segment < 2 {
            return Ok(Err(HeaderError::Malformed));
        }
        let is_frame = matches!(marker[1], 0xc0..=0xcf) && !matches!(marker[1], 0xc4 | 0xc8 | 0xcc);
        if is_frame {
            // Precision (1), height (2), width (2).
            let frame = read(at + 4, 5)?;
            if frame.len() < 5 {
                return Ok(Err(HeaderError::Truncated));
            }
            return Ok(nonzero(be_u16(&frame, 3), be_u16(&frame, 1)));
        }
        at += 2 + segment;
    }
    Ok(Err(HeaderError::Malformed))
}

fn need(bytes: &[u8], len: usize) -> Result<(), HeaderError> {
    if bytes.len() < len {
        return Err(HeaderError::Truncated);
    }
    Ok(())
}

fn be_u16(bytes: &[u8], at: usize) -> u32 {
    u32::from(bytes[at]) << 8 | u32::from(bytes[at + 1])
}

fn be_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn le_u16(bytes: &[u8], at: usize) -> u32 {
    u32::from(bytes[at]) | u32::from(bytes[at + 1]) << 8
}

fn le_u24(bytes: &[u8], at: usize) -> u32 {
    u32::from(bytes[at]) | u32::from(bytes[at + 1]) << 8 | u32::from(bytes[at + 2]) << 16
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// PNG: signature, then the IHDR chunk with big-endian width and height.
fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), HeaderError> {
    need(bytes, 24)?;
    if &bytes[12..16] != b"IHDR" {
        return Err(HeaderError::Malformed);
    }
    Ok((be_u32(bytes, 16), be_u32(bytes, 20)))
}

/// WebP: the first chunk is VP8X (extended), VP8L (lossless) or "VP8 " (lossy).
fn webp_dimensions(bytes: &[u8]) -> Result<(u32, u32), HeaderError> {
    need(bytes, 16)?;
    match &bytes[12..16] {
        b"VP8X" => {
            need(bytes, 30)?;
            Ok((1 + le_u24(bytes, 24), 1 + le_u24(bytes, 27)))
        }
        b"VP8L" => {
            need(bytes, 25)?;
            if bytes[20] != 0x2f {
                return Err(HeaderError::Malformed);
            }
            let bits = le_u32(bytes, 21);
            Ok(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1))
        }
        b"VP8 " => {
            need(bytes, 30)?;
            if bytes[23..26] != [0x9d, 0x01, 0x2a] {
                return Err(HeaderError::Malformed);
            }
            Ok((le_u16(bytes, 26) & 0x3fff, le_u16(bytes, 28) & 0x3fff))
        }
        _ => Err(HeaderError::Malformed),
    }
}
