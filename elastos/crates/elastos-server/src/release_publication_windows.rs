//! Publisher admission requires an identity-stable, no-follow directory walk.
//! Windows publication waits for an equivalent file custody implementation.

use std::path::Path;

use anyhow::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactDescriptor {
    pub name: String,
    pub cid: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug)]
pub struct UnsupportedOnWindows;

impl std::fmt::Display for UnsupportedOnWindows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "release publication is unsupported on Windows without owner and file identity checks",
        )
    }
}

impl std::error::Error for UnsupportedOnWindows {}

/// Only the Unix admission path can construct a publication.
#[derive(Debug)]
pub struct Publication {
    _private: (),
}

impl Publication {
    pub fn open_flat(_input: &Path, _pinned_did: &str) -> Result<Self> {
        Err(UnsupportedOnWindows.into())
    }

    pub fn open_published(_root: &Path, _pinned_did: &str) -> Result<Self> {
        Err(UnsupportedOnWindows.into())
    }

    pub fn version(&self) -> &str {
        unreachable!("Windows cannot construct a Publication")
    }

    pub fn channel(&self) -> &str {
        unreachable!("Windows cannot construct a Publication")
    }

    pub fn release_cid(&self) -> &str {
        unreachable!("Windows cannot construct a Publication")
    }

    pub fn head_bytes(&self) -> &[u8] {
        unreachable!("Windows cannot construct a Publication")
    }

    pub fn release_bytes(&self) -> &[u8] {
        unreachable!("Windows cannot construct a Publication")
    }

    pub fn installer_bytes(&self) -> &[u8] {
        unreachable!("Windows cannot construct a Publication")
    }

    pub fn artifacts(&self) -> &[ArtifactDescriptor] {
        unreachable!("Windows cannot construct a Publication")
    }

    pub fn unchanged_published(&self) -> Result<()> {
        Err(UnsupportedOnWindows.into())
    }

    pub fn read_verified_artifact(&self, _name: &str) -> Result<Vec<u8>> {
        Err(UnsupportedOnWindows.into())
    }

    pub fn read_verified_artifact_bounded(&self, _name: &str, _max_bytes: u64) -> Result<Vec<u8>> {
        Err(UnsupportedOnWindows.into())
    }

    pub fn snapshot_into(&self, _output: &Path) -> Result<()> {
        Err(UnsupportedOnWindows.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_refuses_publication_before_reading_a_path() {
        let missing = Path::new("publication-does-not-exist");
        assert!(Publication::open_flat(missing, "did:key:test")
            .unwrap_err()
            .downcast_ref::<UnsupportedOnWindows>()
            .is_some());
        assert!(Publication::open_published(missing, "did:key:test")
            .unwrap_err()
            .downcast_ref::<UnsupportedOnWindows>()
            .is_some());
    }
}
