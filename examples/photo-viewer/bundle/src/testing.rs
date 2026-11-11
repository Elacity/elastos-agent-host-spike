//! Helpers for tests of capsules that use this tool (capsule kit item A6):
//! the photo viewer's own tests and the documents viewer's bundle test.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::Refusal;

/// A store is sealed read-only; this opens it again, so a temporary folder
/// that holds one can be removed.
pub fn unseal(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        for child in std::fs::read_dir(path).unwrap() {
            unseal(&child.unwrap().path());
        }
    } else if meta.is_file() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}

/// The code of the refusal `result` must be.
pub fn refused<T: std::fmt::Debug>(result: Result<T, Refusal>) -> &'static str {
    let refusal = result.expect_err("expected a refusal");
    println!("refused: {refusal}");
    refusal.code()
}
