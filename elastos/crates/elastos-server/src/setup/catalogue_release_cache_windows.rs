//! Windows has no installed-release catalogue cache. Refuse before reading the
//! release; nothing is counted as verified.

use std::path::Path;

use crate::sources::TrustedSource;

pub(super) fn verified_components(
    _data: &Path,
    _runtime: &Path,
    _source: &TrustedSource,
) -> anyhow::Result<Vec<u8>> {
    Err(super::windows_unsupported(
        "Installed release catalogue verification",
    ))
}
