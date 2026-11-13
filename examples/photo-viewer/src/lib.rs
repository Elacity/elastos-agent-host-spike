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

/// A photo set the run was launched with by its CID. The Runtime answers
/// these names itself, for this run only: `not_found` on the first means the
/// run was not launched with content.
pub const LAUNCH_CONTENT: &str = "elastos://launch/content/";
pub const LAUNCH_CONTENT_PATTERN: &str = "elastos://launch/content/*";
/// Where the playlist goes on a content launch: the launch's own output,
/// kept by the Runtime for the launch, not the person's storage.
pub const LAUNCH_OUTPUT_PATTERN: &str = "elastos://launch/output/*";
pub const LAUNCH_PLAYLIST_URI: &str = "elastos://launch/output/playlist.json";
/// The Runtime's listing of the launched content: each file's path and size.
pub const LISTING_SCHEMA: &str = "elastos.launch.content-listing/v1";
/// The core reads at most this much of the set's listing. The listing plays
/// the album's part, so it has the album's cap, and the worst launched set
/// costs the fuel the worst album does. (The Runtime's own cap, 256 KiB, is
/// wider: a set it starts may still be one this core refuses.)
pub const MAX_LISTING_BYTES: u64 = MAX_ALBUM_BYTES;
/// On a content launch the album is the set's files under this folder.
pub const LAUNCH_IMAGES: &str = "images/";

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
///
/// One question decides where everything is: was this run launched with a
/// photo set? It asks for the launch's content first. Granted: the album is
/// the set's pictures and the playlist goes to the launch's output. Answered
/// `not_found`: the album and the playlist are the person's, as they always
/// were. Any other answer ends the run: nothing falls back to the person's
/// storage after a refusal or a failure.
pub fn run(bus: &mut dyn Bus) -> Result<String, Refusal> {
    let launch = match bus.request(
        LAUNCH_CONTENT_PATTERN,
        "read",
        "read the photo set this run opens",
    ) {
        Ok(grant) => Some(grant),
        Err(BusFailure::NotFound(_)) => None,
        Err(failure) => {
            return Err(Refusal::NoGrant {
                resource: LAUNCH_CONTENT_PATTERN.to_string(),
                failure,
            })
        }
    };
    let (items, album) = match &launch {
        Some(content) => (launch_album(bus, content)?, LAUNCH_CONTENT),
        None => {
            let album_grant = grant(bus, ALBUM_URI, "read", "read the album to play")?;
            let album_bytes =
                read_bounded(bus, ALBUM_URI, &album_grant, Vec::new(), MAX_ALBUM_BYTES)?
                    .ok_or(Refusal::InputTooLarge)?;
            (
                album::parse(&album_bytes).map_err(Refusal::Input)?,
                ALBUM_URI,
            )
        }
    };

    let mut playlist = Vec::with_capacity(items.len());
    let mut skipped = Vec::new();
    for (order, item) in items.iter().enumerate() {
        match check_item(bus, order, item, launch.as_deref())? {
            Ok(checked) => playlist.push(checked),
            Err(reason) => skipped.push(Skipped {
                order,
                uri: item.uri.clone(),
                reason,
            }),
        }
    }

    let text = playlist_json(album, &playlist, &skipped);
    let (granted, target) = match launch {
        Some(_) => (LAUNCH_OUTPUT_PATTERN, LAUNCH_PLAYLIST_URI),
        None => (PLAYLIST_URI, PLAYLIST_URI),
    };
    let write_grant = grant(bus, granted, "write", "write the checked playlist")?;
    bus::write_bytes(bus, target, &write_grant, text.as_bytes()).map_err(|error| {
        Refusal::Call {
            resource: target.to_string(),
            error,
        }
    })?;
    Ok(text)
}

/// The album of a content launch: the files of the launched set under
/// `images/`, in the order of their paths, as the Runtime lists them, each
/// read under the one grant the launch gave. A set with none is refused, as
/// an album with none is.
fn launch_album(bus: &mut dyn Bus, content: &str) -> Result<Vec<AlbumItem>, Refusal> {
    let listing = read_bounded(bus, LAUNCH_CONTENT, content, Vec::new(), MAX_LISTING_BYTES)?
        .ok_or_else(|| {
            Refusal::Input(format!(
                "the set's listing is larger than {MAX_LISTING_BYTES} bytes"
            ))
        })?;
    let listing: Value = serde_json::from_slice(&listing)
        .map_err(|err| Refusal::Input(format!("the set's listing does not parse: {err}")))?;
    if listing["schema"] != LISTING_SCHEMA {
        return Err(Refusal::Input(format!(
            "the set's listing is not {LISTING_SCHEMA}"
        )));
    }
    let files = listing["files"]
        .as_array()
        .ok_or_else(|| Refusal::Input("the set's listing has no files".to_string()))?;
    let path = |file: &Value| file["path"].as_str().map(str::to_string);
    let images: Vec<String> = files
        .iter()
        .filter_map(path)
        .filter(|path| path.starts_with(LAUNCH_IMAGES))
        .collect();
    if images.is_empty() || images.len() > MAX_ALBUM_ITEMS {
        return Err(Refusal::Input(format!(
            "the set holds {} files under {LAUNCH_IMAGES}; 1 to {MAX_ALBUM_ITEMS} are played",
            images.len()
        )));
    }
    let item = |path: String| AlbumItem {
        uri: format!("{LAUNCH_CONTENT}{path}"),
        duration_ms: DEFAULT_DURATION_MS,
    };
    Ok(images.into_iter().map(item).collect())
}

/// The outer error stops the run; the inner one skips the item.
fn check_item(
    bus: &mut dyn Bus,
    order: usize,
    item: &AlbumItem,
    launch: Option<&str>,
) -> Result<Result<PlaylistItem, Skip>, Refusal> {
    let uri = item.uri.as_str();
    // On a content launch every picture is read under the launch's one grant;
    // otherwise each is asked for on its own.
    let item_grant = match launch {
        Some(content) => content.to_string(),
        None => grant(bus, uri, "read", "read the header of an image in the album")?,
    };

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
/// `album` names where the album came from.
pub fn playlist_json(album: &str, items: &[PlaylistItem], skipped: &[Skipped]) -> String {
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
        "album": album,
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
