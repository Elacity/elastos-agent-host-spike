//! Photo viewer core guest (slice P1).
//!
//! Runtime calls `lifecycle.run`. The guest reads one album object, then each
//! image it names, through `providers.invoke` with a grant it requested for
//! that object. It checks the magic bytes (PNG, JPEG, WebP), the object size
//! and the frame dimensions, and writes one playlist object. Any refusal
//! stops the run before the playlist is written, and `run` returns a
//! `bus-error` that names the item and the reason.
//!
//! The Component ABI has no input argument and no return value
//! (`elastos/wit/elastos-bus-v1.wit:84-88`), so the album and the playlist are
//! principal-scoped objects at fixed paths. The guest imports only
//! `elastos:bus@v1`. It has no files, sockets, clock or environment.

mod album;
mod bus;
mod image;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub use album::{AlbumItem, ALBUM_SCHEMA};
pub use bus::{Bus, BusFailure, CallError, InvokeReply};
pub use image::Kind;

/// The album the person asked to play.
pub const ALBUM_URI: &str = "localhost://Users/self/.AppData/App/photo-viewer/album.json";
/// Where the playlist is written for the render-only surface.
pub const PLAYLIST_URI: &str = "localhost://Users/self/.AppData/App/photo-viewer/playlist.json";
/// Album items must name objects under this folder.
pub const PICTURES_PREFIX: &str = "localhost://Users/self/Pictures/";
pub const PLAYLIST_SCHEMA: &str = "elastos.photo-viewer.playlist/v1";

pub const MAX_ALBUM_BYTES: u64 = 64 * 1024;
pub const MAX_ALBUM_ITEMS: usize = 64;
pub const MAX_OBJECT_BYTES: u64 = 128 * 1024;
/// Image bytes read and hashed in one run, across the whole album.
///
/// Content crosses the Bus as a JSON array of numbers, and the guest parses
/// and hashes it at about 415 fuel a byte. `ComponentProvider` gives each
/// run a fixed 100,000,000 fuel (`elastos-compute/src/providers/component.rs:28`)
/// and reports an exhausted run without its cause (`component.rs:134`). This
/// budget keeps the worst album under 80% of that fuel, so the guest refuses
/// with a reason instead of trapping. `host-test` gates the number.
pub const MAX_ALBUM_BODY_BYTES: u64 = 128 * 1024;
pub const MAX_SIDE: u32 = 8192;
pub const MAX_PIXELS: u64 = 40_000_000;
pub const DEFAULT_DURATION_MS: u64 = 5_000;
pub const MIN_DURATION_MS: u64 = 1_000;
pub const MAX_DURATION_MS: u64 = 60_000;

/// Bytes per read. Content travels as a JSON array of numbers, up to four
/// characters a byte, so 32 KiB stays well under the 1 MiB bridge frame
/// (`elastos-server/src/resource_bridge.rs:32`).
pub const READ_CHUNK_BYTES: u64 = 32 * 1024;
/// Bytes read before the type is known.
pub const HEADER_BYTES: u64 = 32;

/// Why the run stopped. Each variant names what is missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    NoGrant {
        resource: String,
        failure: BusFailure,
    },
    Call {
        resource: String,
        error: CallError,
    },
    AlbumTooLarge,
    Album(String),
    WrongType {
        index: usize,
        uri: String,
    },
    Truncated {
        index: usize,
        uri: String,
    },
    Malformed {
        index: usize,
        uri: String,
    },
    Oversize {
        index: usize,
        uri: String,
    },
    AlbumBodyBudget {
        index: usize,
        uri: String,
    },
    Dimensions {
        index: usize,
        uri: String,
        width: u32,
        height: u32,
    },
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::NoGrant { resource, failure } => {
                format!("photo-viewer has no grant for {resource}: {}", failure.message())
            }
            Refusal::Call { resource, error } => match error {
                CallError::Bus(failure) => {
                    format!("photo-viewer call on {resource} failed: {}", failure.message())
                }
                CallError::Provider { code, message } => {
                    format!("photo-viewer call on {resource} failed: {code}: {message}")
                }
                CallError::Shape(message) => {
                    format!("photo-viewer call on {resource} had an unexpected answer: {message}")
                }
            },
            Refusal::AlbumTooLarge => {
                format!("photo-viewer album is larger than {MAX_ALBUM_BYTES} bytes")
            }
            Refusal::Album(message) => format!("photo-viewer album refused: {message}"),
            Refusal::WrongType { index, uri } => {
                format!("photo-viewer item {index} ({uri}) is not PNG, JPEG or WebP")
            }
            Refusal::Truncated { index, uri } => {
                format!("photo-viewer item {index} ({uri}) ends before its image header")
            }
            Refusal::Malformed { index, uri } => {
                format!("photo-viewer item {index} ({uri}) has a malformed image header")
            }
            Refusal::Oversize { index, uri } => {
                format!("photo-viewer item {index} ({uri}) is larger than {MAX_OBJECT_BYTES} bytes")
            }
            Refusal::AlbumBodyBudget { index, uri } => format!(
                "photo-viewer item {index} ({uri}) would take the album past {MAX_ALBUM_BODY_BYTES} image bytes, the most one run can check"
            ),
            Refusal::Dimensions {
                index,
                uri,
                width,
                height,
            } => format!(
                "photo-viewer item {index} ({uri}) is {width}x{height}; the limit is {MAX_SIDE} a side and {MAX_PIXELS} pixels"
            ),
        }
    }

    /// The `bus-error` Runtime receives from `lifecycle.run`.
    pub fn to_bus_failure(&self) -> BusFailure {
        let message = self.message();
        match self {
            Refusal::NoGrant { .. } => BusFailure::Denied(message),
            Refusal::Call { error, .. } => match error {
                CallError::Bus(BusFailure::Denied(_)) => BusFailure::Denied(message),
                CallError::Bus(BusFailure::NotFound(_)) => BusFailure::NotFound(message),
                CallError::Bus(BusFailure::Timeout(_)) => BusFailure::Timeout(message),
                CallError::Bus(BusFailure::Unavailable(_)) | CallError::Provider { .. } => {
                    BusFailure::Unavailable(message)
                }
                CallError::Bus(BusFailure::Invalid(_)) => BusFailure::Invalid(message),
                CallError::Bus(BusFailure::Internal(_)) | CallError::Shape(_) => {
                    BusFailure::Internal(message)
                }
            },
            _ => BusFailure::Invalid(message),
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
    pub bytes: u64,
    pub sha256: String,
}

/// Reads the album and its images, checks them, and writes the playlist.
/// Returns the playlist text that was written.
pub fn run(bus: &mut dyn Bus) -> Result<String, Refusal> {
    let album_grant = grant(bus, ALBUM_URI, "read", "read the album to play")?;
    let album_bytes = read_bounded(bus, ALBUM_URI, &album_grant, MAX_ALBUM_BYTES)?
        .ok_or(Refusal::AlbumTooLarge)?;
    let items = album::parse(&album_bytes).map_err(Refusal::Album)?;

    let mut playlist = Vec::with_capacity(items.len());
    let mut body_bytes = 0;
    for (index, item) in items.iter().enumerate() {
        let checked = check_item(bus, index, item, MAX_ALBUM_BODY_BYTES - body_bytes)?;
        body_bytes += checked.bytes;
        playlist.push(checked);
    }

    let text = playlist_json(&playlist);
    let write_grant = grant(bus, PLAYLIST_URI, "write", "write the checked playlist")?;
    bus::write_text(bus, PLAYLIST_URI, &write_grant, &text).map_err(|error| Refusal::Call {
        resource: PLAYLIST_URI.to_string(),
        error,
    })?;
    Ok(text)
}

fn grant(bus: &mut dyn Bus, resource: &str, action: &str, reason: &str) -> Result<String, Refusal> {
    bus.request(resource, action, reason)
        .map_err(|failure| Refusal::NoGrant {
            resource: resource.to_string(),
            failure,
        })
}

fn call<T>(resource: &str, result: Result<T, CallError>) -> Result<T, Refusal> {
    result.map_err(|error| Refusal::Call {
        resource: resource.to_string(),
        error,
    })
}

/// Reads the whole object in chunks. `None` means it is larger than `limit`.
fn read_bounded(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    limit: u64,
) -> Result<Option<Vec<u8>>, Refusal> {
    let mut bytes = Vec::new();
    loop {
        let offset = bytes.len() as u64;
        // Ask for one byte past the limit so an exact fit is told apart from more.
        let ask = READ_CHUNK_BYTES.min(limit + 1 - offset);
        let chunk = call(uri, bus::read_window(bus, uri, grant, offset, ask))?;
        let short = (chunk.len() as u64) < ask;
        bytes.extend_from_slice(&chunk);
        if bytes.len() as u64 > limit {
            return Ok(None);
        }
        if short {
            return Ok(Some(bytes));
        }
    }
}

/// `budget` is what is left of [`MAX_ALBUM_BODY_BYTES`] for this run.
fn check_item(
    bus: &mut dyn Bus,
    index: usize,
    item: &AlbumItem,
    budget: u64,
) -> Result<PlaylistItem, Refusal> {
    let uri = item.uri.as_str();
    let item_grant = grant(bus, uri, "read", "read an image named in the album")?;

    // Type first, from the header alone.
    let header = call(
        uri,
        bus::read_window(bus, uri, &item_grant, 0, HEADER_BYTES),
    )?;
    let kind = image::sniff(&header).map_err(|err| header_refusal(err, index, uri))?;

    // Size next, with one byte past each limit, before reading the body.
    if extends_past(bus, uri, &item_grant, MAX_OBJECT_BYTES)? {
        return Err(oversize(index, uri));
    }
    let limit = MAX_OBJECT_BYTES.min(budget);
    let over_budget = || Refusal::AlbumBodyBudget {
        index,
        uri: uri.to_string(),
    };
    if limit < MAX_OBJECT_BYTES && extends_past(bus, uri, &item_grant, limit)? {
        return Err(over_budget());
    }

    // The bound holds even if the object grows after the size check.
    let bytes = read_bounded(bus, uri, &item_grant, limit)?.ok_or_else(|| {
        if limit < MAX_OBJECT_BYTES {
            over_budget()
        } else {
            oversize(index, uri)
        }
    })?;
    // The type is checked again on the bytes that are hashed.
    if image::sniff(&bytes).map_err(|err| header_refusal(err, index, uri))? != kind {
        return Err(Refusal::Malformed {
            index,
            uri: uri.to_string(),
        });
    }
    let (width, height) =
        image::dimensions(kind, &bytes).map_err(|err| header_refusal(err, index, uri))?;
    if width > MAX_SIDE || height > MAX_SIDE || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(Refusal::Dimensions {
            index,
            uri: uri.to_string(),
            width,
            height,
        });
    }

    Ok(PlaylistItem {
        order: index,
        uri: uri.to_string(),
        kind,
        width,
        height,
        duration_ms: item.duration_ms,
        bytes: bytes.len() as u64,
        sha256: hex(&Sha256::digest(&bytes)),
    })
}

/// True when the object has a byte at `offset`.
fn extends_past(bus: &mut dyn Bus, uri: &str, grant: &str, offset: u64) -> Result<bool, Refusal> {
    let byte = call(uri, bus::read_window(bus, uri, grant, offset, 1))?;
    Ok(!byte.is_empty())
}

fn oversize(index: usize, uri: &str) -> Refusal {
    Refusal::Oversize {
        index,
        uri: uri.to_string(),
    }
}

fn header_refusal(err: image::HeaderError, index: usize, uri: &str) -> Refusal {
    let uri = uri.to_string();
    match err {
        image::HeaderError::Truncated => Refusal::Truncated { index, uri },
        image::HeaderError::UnknownType => Refusal::WrongType { index, uri },
        image::HeaderError::Malformed => Refusal::Malformed { index, uri },
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Keys are sorted (`serde_json` default map), so the text is deterministic.
pub fn playlist_json(items: &[PlaylistItem]) -> String {
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
                "bytes": item.bytes,
                "sha256": item.sha256,
            })
        })
        .collect();
    json!({
        "schema": PLAYLIST_SCHEMA,
        "album": ALBUM_URI,
        "items": items,
    })
    .to_string()
}

#[cfg(target_arch = "wasm32")]
wit_bindgen::generate!({
    path: "../../elastos/wit",
    world: "product-capsule-v1",
});

#[cfg(target_arch = "wasm32")]
const EXPECTED_RUNTIME_ABI: &str = "elastos.component/v1";

#[cfg(target_arch = "wasm32")]
mod component {
    use super::elastos::bus::{capabilities, providers, runtime, types};
    use super::{Bus, BusFailure, InvokeReply};

    pub struct WitBus;

    fn from_wit(err: types::BusError) -> BusFailure {
        match err {
            types::BusError::Denied(message) => BusFailure::Denied(message),
            types::BusError::NotFound(message) => BusFailure::NotFound(message),
            types::BusError::Invalid(message) => BusFailure::Invalid(message),
            types::BusError::Unavailable(message) => BusFailure::Unavailable(message),
            types::BusError::Timeout(message) => BusFailure::Timeout(message),
            types::BusError::Internal(message) => BusFailure::Internal(message),
        }
    }

    pub fn to_wit(failure: BusFailure) -> types::BusError {
        match failure {
            BusFailure::Denied(message) => types::BusError::Denied(message),
            BusFailure::NotFound(message) => types::BusError::NotFound(message),
            BusFailure::Invalid(message) => types::BusError::Invalid(message),
            BusFailure::Unavailable(message) => types::BusError::Unavailable(message),
            BusFailure::Timeout(message) => types::BusError::Timeout(message),
            BusFailure::Internal(message) => types::BusError::Internal(message),
        }
    }

    impl Bus for WitBus {
        fn request(
            &mut self,
            resource: &str,
            action: &str,
            reason: &str,
        ) -> Result<String, BusFailure> {
            capabilities::request(&types::CapabilityRequest {
                resource: resource.to_string(),
                actions: vec![action.to_string()],
                reason: reason.to_string(),
            })
            .map(|grant| grant.id)
            .map_err(from_wit)
        }

        fn invoke(
            &mut self,
            resource: &str,
            operation: &str,
            body: &[u8],
            grant: &str,
        ) -> Result<InvokeReply, BusFailure> {
            providers::invoke(&types::InvokeRequest {
                resource: resource.to_string(),
                operation: operation.to_string(),
                body: body.to_vec(),
                grant: Some(grant.to_string()),
            })
            .map(|reply| InvokeReply {
                status: reply.status,
                body: reply.body,
            })
            .map_err(from_wit)
        }
    }

    pub fn runtime_abi() -> String {
        runtime::info().abi
    }
}

#[cfg(target_arch = "wasm32")]
struct PhotoViewer;

#[cfg(target_arch = "wasm32")]
impl exports::elastos::bus::lifecycle::Guest for PhotoViewer {
    fn run() -> Result<(), elastos::bus::types::BusError> {
        let abi = component::runtime_abi();
        if abi != EXPECTED_RUNTIME_ABI {
            return Err(elastos::bus::types::BusError::Invalid(format!(
                "photo-viewer requires {EXPECTED_RUNTIME_ABI}, received {abi}"
            )));
        }
        run(&mut component::WitBus)
            .map(|_| ())
            .map_err(|refusal| component::to_wit(refusal.to_bus_failure()))
    }
}

#[cfg(target_arch = "wasm32")]
export!(PhotoViewer);
