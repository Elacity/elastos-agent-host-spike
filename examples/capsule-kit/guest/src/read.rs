//! The refusals that stop a run, and the reads every guest makes: a grant for
//! one object and one action, a window read, a bounded whole read, and a read
//! counted against a budget before anything else can happen to it.
//!
//! Moved here from the photo and documents viewers, which had a copy each.

use crate::bus::{self, Bus, BusFailure, CallError};

/// Bytes per read. Content travels as a JSON array of numbers, up to four
/// characters a byte, so 8 KiB stays far under the 1 MiB bridge frame
/// (`elastos-server/src/resource_bridge.rs:32`).
pub const READ_CHUNK_BYTES: u64 = 8 * 1024;

/// What a guest's refusals say about it: its name, what its input list is
/// called, and that list's cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct App {
    pub name: &'static str,
    pub input: &'static str,
    pub max_input_bytes: u64,
}

/// Why the run stopped: an authority failure, or an input list that cannot
/// be read. Each variant names what is missing.
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
    /// The input list is larger than `App::max_input_bytes`.
    InputTooLarge,
    /// The input list does not parse.
    Input(String),
}

impl Refusal {
    pub fn message(&self, app: &App) -> String {
        let name = app.name;
        match self {
            Refusal::NoGrant { resource, failure } => {
                format!("{name} has no grant for {resource}: {}", failure.message())
            }
            Refusal::Call { resource, error } => match error {
                CallError::Bus(failure) => {
                    format!("{name} call on {resource} failed: {}", failure.message())
                }
                CallError::Provider { code, message } => {
                    format!("{name} call on {resource} failed: {code}: {message}")
                }
                CallError::Shape(message) => {
                    format!("{name} call on {resource} had an unexpected answer: {message}")
                }
            },
            Refusal::InputTooLarge => format!(
                "{name} {} is larger than {} bytes",
                app.input, app.max_input_bytes
            ),
            Refusal::Input(message) => format!("{name} {} refused: {message}", app.input),
        }
    }

    /// The `bus-error` Runtime receives from `lifecycle.run`.
    pub fn to_bus_failure(&self, app: &App) -> BusFailure {
        let message = self.message(app);
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
            Refusal::InputTooLarge | Refusal::Input(_) => BusFailure::Invalid(message),
        }
    }
}

/// `capabilities.request` for one object and one action.
pub fn grant(
    bus: &mut dyn Bus,
    resource: &str,
    action: &str,
    reason: &str,
) -> Result<String, Refusal> {
    bus.request(resource, action, reason)
        .map_err(|failure| Refusal::NoGrant {
            resource: resource.to_string(),
            failure,
        })
}

/// One window read; a refused or failed call stops the run.
pub fn read_at(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, Refusal> {
    bus::read_window(bus, uri, grant, offset, length).map_err(|error| Refusal::Call {
        resource: uri.to_string(),
        error,
    })
}

/// Reads on from the end of `bytes` in chunks, to the end of the object.
/// `None` means it is larger than `limit`.
pub fn read_bounded(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    mut bytes: Vec<u8>,
    limit: u64,
) -> Result<Option<Vec<u8>>, Refusal> {
    loop {
        let offset = bytes.len() as u64;
        // Ask for one byte past the limit so an exact fit is told apart from more.
        let ask = READ_CHUNK_BYTES.min(limit + 1 - offset);
        let chunk = read_at(bus, uri, grant, offset, ask)?;
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

/// One read, taken off what a run may still read (`left`) the moment it
/// returns, before anything else can happen to it. The read window refuses
/// an answer longer than it asked for, so `length` is the most it can take
/// off; asking for more than is left is a bug in the caller.
pub fn read_counted(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    left: &mut u64,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, Refusal> {
    assert!(length <= *left, "a read past what the run may read");
    let bytes = read_at(bus, uri, grant, offset, length)?;
    *left -= bytes.len() as u64;
    Ok(bytes)
}
