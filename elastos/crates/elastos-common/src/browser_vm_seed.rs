//! Process-verified seed identity carried in the Runtime launch request.

use std::{fs, io, path::Path};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileIdentity {
    pub fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mode: metadata.mode(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserVmSeedIdentity {
    pub link: FileIdentity,
    pub target: FileIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<BrowserVmBootArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd: Option<BrowserVmBootArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserVmBootArtifact {
    pub link: FileIdentity,
    pub target: FileIdentity,
    pub sha256: String,
}

impl BrowserVmBootArtifact {
    /// Byte length of the file admitted at launch. The copy stops at this size.
    pub fn admitted_len(&self) -> u64 {
        self.target.len
    }

    pub fn check(&self, path: &Path) -> Result<(), String> {
        let current = BrowserVmSeedIdentity::read(path)
            .map_err(|error| format!("Browser boot artifact identity: {error}"))?;
        if current.link != self.link || current.target != self.target {
            return Err(
                "Browser boot artifact changed after Runtime admission; retry Browser open".into(),
            );
        }
        Ok(())
    }
}

impl BrowserVmSeedIdentity {
    /// Byte length of the file admitted at launch. The copy stops at this size.
    pub fn admitted_len(&self) -> u64 {
        self.target.len
    }

    pub fn read(path: &Path) -> io::Result<Self> {
        let target = fs::metadata(path)?;
        if !target.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Browser rootfs seed must be a regular file",
            ));
        }
        Ok(Self {
            link: FileIdentity::from_metadata(&fs::symlink_metadata(path)?),
            target: FileIdentity::from_metadata(&target),
            sha256: None,
            kernel: None,
            initrd: None,
        })
    }

    pub fn check(&self, path: &Path) -> Result<(), String> {
        let current =
            Self::read(path).map_err(|error| format!("Browser rootfs seed identity: {error}"))?;
        if current.link != self.link || current.target != self.target {
            return Err(
                "Browser rootfs seed changed after Runtime admission; retry Browser open".into(),
            );
        }
        Ok(())
    }
}
