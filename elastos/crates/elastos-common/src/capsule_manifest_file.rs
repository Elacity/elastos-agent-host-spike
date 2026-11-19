//! Bounded reads of a folder's capsule manifest before its contents are checked.

use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::Path;

/// The bundle walk's existing 64 MiB total-byte budget. The walk uses this
/// value too, so every manifest it can accept also fits a pre-check read.
pub const MAX_CAPSULE_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "capsule.json is not a regular file",
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "capsule.json is not a regular file",
        ));
    }
    if metadata.len() > MAX_CAPSULE_MANIFEST_BYTES {
        return Err(too_large());
    }

    let mut bytes = Vec::new();
    file.take(MAX_CAPSULE_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CAPSULE_MANIFEST_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}

fn too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("capsule.json exceeds {MAX_CAPSULE_MANIFEST_BYTES} bytes"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_manifest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capsule.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_CAPSULE_MANIFEST_BYTES + 1).unwrap();

        let error = read(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds 67108864 bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_manifest_is_refused_without_waiting() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capsule.json");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(read(&path));
        });
        let answer = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        let error = answer.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not a regular file"));
    }

    #[test]
    fn regular_manifest_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capsule.json");
        let source = include_bytes!("../../../../templates/capsules/web-app/capsule.json");
        std::fs::write(&path, source).unwrap();

        let bytes = read(&path).unwrap();
        assert_eq!(bytes, source);
        let manifest: crate::CapsuleManifest = serde_json::from_slice(&bytes).unwrap();
        manifest.validate().unwrap();
    }
}
