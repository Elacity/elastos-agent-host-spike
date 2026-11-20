//! GBA viewer core guest (AP4 slice 1b).
//!
//! Runtime starts this core as the one program under the page a content pins.
//! The core reads the launch's file listing, takes its one `.gba` file, refuses
//! it by name when it is missing, empty or larger than 64 MiB, and asks the
//! Runtime for that file's digest. It writes one launch record under
//! `elastos://launch/output/` naming that file's path, size and sha256. The
//! page reads the record and fetches the ROM at the recorded path.
//!
//! The core's sourced duties are the size cap and the record (ruling r2
//! section 3, L2). It reads no GBA header: L2 gives that check no repo source.
//! The cap is the core's rule; the page's own bound is a fetch sanity bound
//! only.
//!
//! The Component ABI has no input argument and no return value, so the launch
//! set and the record are the launch's own names. The guest imports only
//! `elastos:bus@v1`. It has no files, sockets, clock or environment.

#[cfg(test)]
mod tests;

use std::fmt;

use capsule_kit_guest::{bus, Bus, BusFailure, CallError, READ_CHUNK_BYTES};
use serde_json::{json, Value};

/// A game set the run was launched with by its CID. The Runtime answers these
/// names itself, for this run only.
pub const LAUNCH_CONTENT: &str = "elastos://launch/content/";
pub const LAUNCH_CONTENT_PATTERN: &str = "elastos://launch/content/*";
/// The launch's own output: kept by the Runtime for the launch, not the
/// person's storage. The page reads the record from the output route.
pub const LAUNCH_OUTPUT_PATTERN: &str = "elastos://launch/output/*";
pub const LAUNCH_RECORD_URI: &str = "elastos://launch/output/rom.json";
/// The Runtime's listing of the launched content: each file's path and size.
pub const LISTING_SCHEMA: &str = "elastos.launch.content-listing/v1";
/// The listing plays no part in the record, so it keeps a small cap. The
/// Runtime's own cap is wider: a set it starts may still be one this core
/// refuses.
pub const MAX_LISTING_BYTES: u64 = 256 * 1024;
/// A ROM over this many bytes is refused. The core owns this rule.
pub const MAX_ROM_BYTES: u64 = 64 * 1024 * 1024;
/// The launched content's one ROM is the one file with this suffix. No name is
/// guessed: zero or two such files are refused.
pub const ROM_SUFFIX: &str = ".gba";

/// The launched content's ROM, as the Runtime's listing names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rom {
    pub path: String,
    pub size: u64,
}

/// Why the run stopped. Every variant names itself in its `Display`: the
/// Runtime receives the same text as a `bus-error`, and the open fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreError {
    /// The launch does not bind this run.
    NoLaunch { failure: BusFailure },
    /// The launch has no output this run may write.
    NoOutput { failure: BusFailure },
    /// The listing is unreadable, too long, or not the Runtime's listing.
    Listing(String),
    /// No `.gba` file is in the launched content.
    RomMissing,
    /// More than one `.gba` file is in the launched content.
    RomAmbiguous(usize),
    /// The ROM is a file of zero bytes.
    RomEmpty { path: String },
    /// The ROM is larger than [`MAX_ROM_BYTES`].
    RomTooLarge { size: u64 },
    /// The digest's size differs from the listing's.
    DigestSizeMismatch { listing: u64, answer: u64 },
    /// The digest's algorithm is not the one the record names.
    DigestAlgorithm(String),
    /// The digest's sha256 is not exactly 64 lowercase hex characters.
    DigestMalformed,
    /// A read of the launch's content failed.
    Read { resource: String, error: CallError },
    /// The launch record could not be written.
    Write { resource: String, error: CallError },
}

impl CoreError {
    /// The `bus-error` Runtime receives from `lifecycle.run`.
    pub fn to_bus_failure(&self) -> BusFailure {
        match self {
            CoreError::NoLaunch { failure } | CoreError::NoOutput { failure } => failure.clone(),
            CoreError::Read { error, .. } | CoreError::Write { error, .. } => match error {
                CallError::Bus(failure) => failure.clone(),
                CallError::Provider { .. } => BusFailure::Unavailable(self.to_string()),
                CallError::Shape(_) => BusFailure::Internal(self.to_string()),
            },
            CoreError::Listing(_)
            | CoreError::RomMissing
            | CoreError::RomAmbiguous(_)
            | CoreError::RomEmpty { .. }
            | CoreError::RomTooLarge { .. }
            | CoreError::DigestSizeMismatch { .. }
            | CoreError::DigestAlgorithm(_)
            | CoreError::DigestMalformed => BusFailure::Invalid(self.to_string()),
        }
    }
}

fn call_error_message(error: &CallError) -> String {
    match error {
        CallError::Bus(failure) => failure.message().to_string(),
        CallError::Provider { code, message } => format!("{code}: {message}"),
        CallError::Shape(message) => message.clone(),
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::NoLaunch { failure } => {
                write!(formatter, "gba_core_no_launch: {}", failure.message())
            }
            CoreError::NoOutput { failure } => {
                write!(formatter, "gba_core_no_output: {}", failure.message())
            }
            CoreError::Listing(message) => {
                write!(formatter, "gba_core_listing_invalid: {message}")
            }
            CoreError::RomMissing => write!(formatter, "gba_core_rom_missing"),
            CoreError::RomAmbiguous(count) => write!(formatter, "gba_core_rom_ambiguous: {count}"),
            CoreError::RomEmpty { path } => write!(formatter, "gba_core_rom_empty: {path}"),
            CoreError::RomTooLarge { size } => write!(formatter, "gba_core_rom_too_large: {size}"),
            CoreError::DigestSizeMismatch { listing, answer } => {
                write!(
                    formatter,
                    "gba_core_digest_size_mismatch: {listing} != {answer}"
                )
            }
            CoreError::DigestAlgorithm(algorithm) => {
                write!(formatter, "gba_core_digest_algorithm: {algorithm}")
            }
            CoreError::DigestMalformed => write!(formatter, "gba_core_digest_malformed"),
            CoreError::Read { resource, error } => {
                write!(
                    formatter,
                    "gba_core_read_failed: {resource}: {}",
                    call_error_message(error)
                )
            }
            CoreError::Write { resource, error } => {
                write!(
                    formatter,
                    "gba_core_write_failed: {resource}: {}",
                    call_error_message(error)
                )
            }
        }
    }
}

/// The core's whole body, as the Runtime's `lifecycle.run` sees it.
pub fn entry(bus: &mut dyn Bus) -> Result<(), BusFailure> {
    run(bus).map(|_| ()).map_err(|error| error.to_bus_failure())
}

/// Reads the launched content's ROM and writes the launch record. Returns the
/// record text that was written.
pub fn run(bus: &mut dyn Bus) -> Result<String, CoreError> {
    let content = bus
        .request(
            LAUNCH_CONTENT_PATTERN,
            "read",
            "read the game this run opens",
        )
        .map_err(|failure| CoreError::NoLaunch { failure })?;
    let listing = read_listing(bus, &content)?;
    let rom = rom_of(&listing)?;
    // The cap is checked from the listing before any byte of the ROM is read,
    // so an over-cap ROM costs one listing read, not 64 MiB of reads.
    if rom.size > MAX_ROM_BYTES {
        return Err(CoreError::RomTooLarge { size: rom.size });
    }
    if rom.size == 0 {
        return Err(CoreError::RomEmpty { path: rom.path });
    }
    let uri = format!("{LAUNCH_CONTENT}{}", rom.path);
    let digest = bus::digest(bus, &uri, &content).map_err(|error| CoreError::Read {
        resource: uri.clone(),
        error,
    })?;
    if digest.size != rom.size {
        return Err(CoreError::DigestSizeMismatch {
            listing: rom.size,
            answer: digest.size,
        });
    }
    if digest.algorithm != "sha256" {
        return Err(CoreError::DigestAlgorithm(digest.algorithm));
    }
    if !lowercase_hex64(&digest.sha256) {
        return Err(CoreError::DigestMalformed);
    }
    let sha256 = digest.sha256;
    let record = record_json(&rom, &sha256);
    let output = bus
        .request(LAUNCH_OUTPUT_PATTERN, "write", "write the launch record")
        .map_err(|failure| CoreError::NoOutput { failure })?;
    bus::write_bytes(bus, LAUNCH_RECORD_URI, &output, record.as_bytes()).map_err(|error| {
        CoreError::Write {
            resource: LAUNCH_RECORD_URI.to_string(),
            error,
        }
    })?;
    Ok(record)
}

/// One launch record, exactly the three keys `path`, `size` and `sha256`.
pub fn record_json(rom: &Rom, sha256: &str) -> String {
    json!({
        "path": rom.path,
        "size": rom.size,
        "sha256": sha256,
    })
    .to_string()
}

/// The Runtime's listing, read to its end or refused when it passes the cap.
fn read_listing(bus: &mut dyn Bus, grant: &str) -> Result<Vec<u8>, CoreError> {
    let mut bytes = Vec::new();
    loop {
        let offset = bytes.len() as u64;
        // Ask one byte past the cap, so an exact fit is told apart from more.
        let ask = READ_CHUNK_BYTES.min(MAX_LISTING_BYTES + 1 - offset);
        let chunk = bus::read_window(bus, LAUNCH_CONTENT, grant, offset, ask).map_err(|error| {
            CoreError::Read {
                resource: LAUNCH_CONTENT.to_string(),
                error,
            }
        })?;
        let short = (chunk.len() as u64) < ask;
        bytes.extend_from_slice(&chunk);
        if bytes.len() as u64 > MAX_LISTING_BYTES {
            return Err(CoreError::Listing(format!(
                "is larger than {MAX_LISTING_BYTES} bytes"
            )));
        }
        if short {
            return Ok(bytes);
        }
    }
}

/// The launched content's one `.gba` file: zero or two or more are refused.
fn rom_of(listing: &[u8]) -> Result<Rom, CoreError> {
    let listing: Value = serde_json::from_slice(listing)
        .map_err(|error| CoreError::Listing(format!("does not parse: {error}")))?;
    if listing["schema"] != LISTING_SCHEMA {
        return Err(CoreError::Listing(format!(
            "is not the Runtime's {LISTING_SCHEMA}"
        )));
    }
    let files = listing["files"]
        .as_array()
        .ok_or_else(|| CoreError::Listing("has no files".to_string()))?;
    let mut roms = Vec::new();
    for file in files {
        let Some(path) = file["path"].as_str() else {
            return Err(CoreError::Listing("has a file without a path".to_string()));
        };
        if !path.ends_with(ROM_SUFFIX) {
            continue;
        }
        if !plain_relative_path(path) {
            return Err(CoreError::Listing(format!(
                "has an invalid ROM path: {path}"
            )));
        }
        let size = file["size"]
            .as_u64()
            .ok_or_else(|| CoreError::Listing(format!("has no size for {path}")))?;
        roms.push(Rom {
            path: path.to_string(),
            size,
        });
    }
    match roms.len() {
        0 => Err(CoreError::RomMissing),
        1 => Ok(roms.remove(0)),
        count => Err(CoreError::RomAmbiguous(count)),
    }
}

/// A path under the launch's content: relative, with no empty, `.` or `..`
/// component. The Runtime names the files; this core still refuses a name it
/// would not fetch.
fn plain_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

/// Exactly 64 lowercase hex characters: the record's `sha256` shape.
fn lowercase_hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(target_arch = "wasm32")]
struct GbaViewerCore;

#[cfg(target_arch = "wasm32")]
impl capsule_kit_guest::wit::exports::elastos::bus::lifecycle::Guest for GbaViewerCore {
    fn run() -> Result<(), capsule_kit_guest::wit::elastos::bus::types::BusError> {
        use capsule_kit_guest::component;
        let abi = component::runtime_abi();
        if abi != component::EXPECTED_RUNTIME_ABI {
            return Err(component::to_wit(BusFailure::Invalid(format!(
                "gba-viewer-core requires {}, received {abi}",
                component::EXPECTED_RUNTIME_ABI
            ))));
        }
        let mut bus = component::WitBus;
        entry(&mut bus).map_err(component::to_wit)
    }
}

#[cfg(target_arch = "wasm32")]
capsule_kit_guest::wit::export_lifecycle!(GbaViewerCore with_types_in capsule_kit_guest::wit);
