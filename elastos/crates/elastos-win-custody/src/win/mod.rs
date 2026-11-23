//! Owner-only creates and opens. The parent module compiles this on Windows.
#![deny(unsafe_op_in_unsafe_fn)]

mod open;
mod sd;

#[cfg(test)]
mod tests;

use std::io;
use std::path::Path;

pub use open::{create_owner_dir, open_owner_file, Disp};
pub use sd::verify_owner_only;

use crate::CustodyError;

pub(super) fn reparse_at(path: &Path) -> CustodyError {
    CustodyError::ReparsePoint {
        path: path.display().to_string(),
    }
}

pub(super) fn foreign(path: &Path) -> CustodyError {
    CustodyError::ForeignDacl {
        path: path.display().to_string(),
    }
}

pub(super) fn invalid(path: &Path, reason: &str) -> CustodyError {
    io_at(path, io::Error::new(io::ErrorKind::InvalidInput, reason))
}

pub(super) fn io_at(path: &Path, error: io::Error) -> CustodyError {
    CustodyError::Io(io::Error::new(
        error.kind(),
        format!("{}: {error}", path.display()),
    ))
}
