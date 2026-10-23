//! Photo viewer core guest (slices P1 and P1b).
//!
//! Runtime calls `lifecycle.run`. The guest reads one album object, then the
//! header of each image it names, through `providers.invoke` with a grant it
//! requested for that object. It reads headers only, with the offset/length
//! read window: the magic bytes name the type (PNG, JPEG, WebP), the frame
//! header gives the dimensions, and one byte past the size limit tells an
//! oversize object. Image bodies are never read; Runtime is to name the bytes
//! by CID (roadmap 2.2).
//!
//! An authority failure (no grant, a refused or failed call, an album that
//! cannot be read or parsed) stops the run before anything is written, and
//! `run` returns a `bus-error` that names the resource and the reason. A
//! content failure (wrong type, truncated or malformed header, oversize,
//! frame too large) skips that item; the playlist lists it with its reason.
//!
//! The Component ABI has no input argument and no return value
//! (`elastos/wit/elastos-bus-v1.wit:84-88`), so the album and the playlist are
//! principal-scoped objects at fixed paths. The guest imports only
//! `elastos:bus@v1`. It has no files, sockets, clock or environment.

mod album;

#[cfg(test)]
mod tests;

use capsule_kit_guest::{bus, grant, image, read_at, read_bounded, App};
use serde_json::{json, Value};

pub use album::{AlbumItem, ALBUM_SCHEMA};
pub use capsule_kit_guest::image::{Kind, HEADER_BYTES, MAX_JPEG_SEGMENTS};
pub use capsule_kit_guest::{Bus, BusFailure, CallError, InvokeReply, Refusal, READ_CHUNK_BYTES};

/// The album the person asked to play.
pub const ALBUM_URI: &str = "localhost://Users/self/.AppData/App/photo-viewer/album.json";
/// Where the playlist is written for the render-only surface.
pub const PLAYLIST_URI: &str = "localhost://Users/self/.AppData/App/photo-viewer/playlist.json";
/// Album items must name objects under this folder.
pub const PICTURES_PREFIX: &str = "localhost://Users/self/Pictures/";
pub const PLAYLIST_SCHEMA: &str = "elastos.photo-viewer.playlist/v1";

/// The album is read whole, so it keeps a small cap.
pub const MAX_ALBUM_BYTES: u64 = 16 * 1024;
pub const MAX_ALBUM_ITEMS: usize = 64;
/// Checked with one byte past it; the body is not read.
pub const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SIDE: u32 = 8192;
pub const MAX_PIXELS: u64 = 40_000_000;
pub const DEFAULT_DURATION_MS: u64 = 5_000;
pub const MIN_DURATION_MS: u64 = 1_000;
pub const MAX_DURATION_MS: u64 = 60_000;

/// What the photo viewer's refusals say about it.
pub const APP: App = App {
    name: "photo-viewer",
    input: "album",
    max_input_bytes: MAX_ALBUM_BYTES,
};

/// Why one item is left out of the playlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Skip {
    WrongType,
    Truncated,
    Malformed,
    Oversize,
    Dimensions { width: u32, height: u32 },
}

impl Skip {
    pub fn code(&self) -> &'static str {
        match self {
            Skip::WrongType => "wrong_type",
            Skip::Truncated => "truncated",
            Skip::Malformed => "malformed",
            Skip::Oversize => "oversize",
            Skip::Dimensions { .. } => "dimensions",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Skip::WrongType => "not PNG, JPEG or WebP".to_string(),
            Skip::Truncated => "ends before its image header".to_string(),
            Skip::Malformed => "has a malformed image header".to_string(),
            Skip::Oversize => format!("is larger than {MAX_OBJECT_BYTES} bytes"),
            Skip::Dimensions { width, height } => format!(
                "is {width}x{height}; the limit is {MAX_SIDE} a side and {MAX_PIXELS} pixels"
            ),
        }
    }
}

impl From<image::HeaderError> for Skip {
    fn from(err: image::HeaderError) -> Self {
        match err {
            image::HeaderError::Truncated => Skip::Truncated,
            image::HeaderError::UnknownType => Skip::WrongType,
            image::HeaderError::Malformed => Skip::Malformed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaylistItem {
    pub order: usize,
    pub uri: String,
    pub kind: Kind,
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub order: usize,
    pub uri: String,
    pub reason: Skip,
}

/// Reads the album and its image headers, and writes the playlist.
/// Returns the playlist text that was written.
pub fn run(bus: &mut dyn Bus) -> Result<String, Refusal> {
    let album_grant = grant(bus, ALBUM_URI, "read", "read the album to play")?;
    let album_bytes = read_bounded(bus, ALBUM_URI, &album_grant, Vec::new(), MAX_ALBUM_BYTES)?
        .ok_or(Refusal::InputTooLarge)?;
    let items = album::parse(&album_bytes).map_err(Refusal::Input)?;

    let mut playlist = Vec::with_capacity(items.len());
    let mut skipped = Vec::new();
    for (order, item) in items.iter().enumerate() {
        match check_item(bus, order, item)? {
            Ok(checked) => playlist.push(checked),
            Err(reason) => skipped.push(Skipped {
                order,
                uri: item.uri.clone(),
                reason,
            }),
        }
    }

    let text = playlist_json(&playlist, &skipped);
    let write_grant = grant(bus, PLAYLIST_URI, "write", "write the checked playlist")?;
    bus::write_bytes(bus, PLAYLIST_URI, &write_grant, text.as_bytes()).map_err(|error| {
        Refusal::Call {
            resource: PLAYLIST_URI.to_string(),
            error,
        }
    })?;
    Ok(text)
}

/// The outer error stops the run; the inner one skips the item.
fn check_item(
    bus: &mut dyn Bus,
    order: usize,
    item: &AlbumItem,
) -> Result<Result<PlaylistItem, Skip>, Refusal> {
    let uri = item.uri.as_str();
    let item_grant = grant(bus, uri, "read", "read the header of an image in the album")?;

    // Type first, from the header alone.
    let header = read_at(bus, uri, &item_grant, 0, HEADER_BYTES)?;
    let kind = match image::sniff(&header) {
        Ok(kind) => kind,
        Err(err) => return Ok(Err(err.into())),
    };

    // Size next: one byte past the limit.
    if !read_at(bus, uri, &item_grant, MAX_OBJECT_BYTES, 1)?.is_empty() {
        return Ok(Err(Skip::Oversize));
    }

    let dimensions = match kind {
        Kind::Jpeg => {
            image::jpeg_dimensions(|offset, length| read_at(bus, uri, &item_grant, offset, length))?
        }
        Kind::Png | Kind::Webp => image::header_dimensions(kind, &header),
    };
    let (width, height) = match dimensions {
        Ok(dimensions) => dimensions,
        Err(err) => return Ok(Err(err.into())),
    };
    if width > MAX_SIDE || height > MAX_SIDE || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Ok(Err(Skip::Dimensions { width, height }));
    }

    Ok(Ok(PlaylistItem {
        order,
        uri: uri.to_string(),
        kind,
        width,
        height,
        duration_ms: item.duration_ms,
    }))
}

/// Keys are sorted (`serde_json` default map), so the text is deterministic.
pub fn playlist_json(items: &[PlaylistItem], skipped: &[Skipped]) -> String {
    let items: Vec<Value> = items
        .iter()
        .map(|item| {
            json!({
                "order": item.order,
                "uri": item.uri,
                "mime": item.kind.mime(),
                "width": item.width,
                "height": item.height,
                "duration_ms": item.duration_ms,
            })
        })
        .collect();
    let skipped: Vec<Value> = skipped
        .iter()
        .map(|skip| {
            json!({
                "order": skip.order,
                "uri": skip.uri,
                "reason": skip.reason.code(),
                "message": skip.reason.message(),
            })
        })
        .collect();
    json!({
        "schema": PLAYLIST_SCHEMA,
        "album": ALBUM_URI,
        "items": items,
        "skipped": skipped,
    })
    .to_string()
}

#[cfg(target_arch = "wasm32")]
struct PhotoViewer;

#[cfg(target_arch = "wasm32")]
impl capsule_kit_guest::wit::exports::elastos::bus::lifecycle::Guest for PhotoViewer {
    fn run() -> Result<(), capsule_kit_guest::wit::elastos::bus::types::BusError> {
        capsule_kit_guest::component::lifecycle_run(&APP, |bus| run(bus).map(|_| ()))
    }
}

#[cfg(target_arch = "wasm32")]
capsule_kit_guest::wit::export_lifecycle!(PhotoViewer with_types_in capsule_kit_guest::wit);
