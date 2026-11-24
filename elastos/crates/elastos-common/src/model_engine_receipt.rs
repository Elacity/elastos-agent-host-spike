//! The macOS engine receipt. The Runtime maps these results onto its start errors.

use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

pub enum ModelReceiptError {
    Io(std::io::Error),
    Rejected(&'static str),
}

pub fn model_engine_receipt_entries(
    base: &Path,
    engine: &Path,
) -> Result<(PathBuf, Vec<serde_json::Value>), ModelReceiptError> {
    let prefix = base.join("libexec/llama.cpp");
    let relative = engine
        .strip_prefix(&prefix)
        .map_err(|_| ModelReceiptError::Rejected("model engine bundle is unavailable"))?;
    let mut parts = relative.components();
    let (Some(Component::Normal(version)), Some(Component::Normal(platform))) =
        (parts.next(), parts.next())
    else {
        return Err(ModelReceiptError::Rejected(
            "model engine bundle is unavailable",
        ));
    };
    if !parts.all(|part| matches!(part, Component::Normal(_))) {
        return Err(ModelReceiptError::Rejected(
            "model engine bundle is unavailable",
        ));
    }
    let bundle = prefix.join(version).join(platform);
    let receipt = bundle.join(".elastos-engine.json");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&receipt)
        .map_err(ModelReceiptError::Io)?;
    let before = file.metadata().map_err(ModelReceiptError::Io)?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != 0o400
        || before.len() > 256 * 1024
    {
        return Err(ModelReceiptError::Rejected("unsafe model engine receipt"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(ModelReceiptError::Io)?;
    let after = file.metadata().map_err(ModelReceiptError::Io)?;
    if bytes.len() > 256 * 1024
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || std::fs::symlink_metadata(&receipt)
            .map_err(ModelReceiptError::Io)?
            .ino()
            != after.ino()
    {
        return Err(ModelReceiptError::Rejected("changed model engine receipt"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ModelReceiptError::Rejected("invalid model engine receipt"))?;
    if value["schema"] != "elastos.local-model-engine/v2" {
        return Err(ModelReceiptError::Rejected("invalid model engine receipt"));
    }
    let entries = value["entries"]
        .as_array()
        .filter(|entries| entries.len() <= 1024)
        .ok_or(ModelReceiptError::Rejected("invalid model engine receipt"))?;
    let mut seen = std::collections::BTreeSet::new();
    for entry in entries {
        let path = entry["path"]
            .as_str()
            .ok_or(ModelReceiptError::Rejected("invalid model engine receipt"))?;
        if path.is_empty()
            || !Path::new(path)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            || !seen.insert(path)
        {
            return Err(ModelReceiptError::Rejected("invalid model engine receipt"));
        }
    }
    Ok((bundle, entries.clone()))
}

pub fn model_engine_receipt_file_matches(
    path: &Path,
    entry: &serde_json::Value,
) -> Result<bool, ModelReceiptError> {
    use sha2::{Digest as _, Sha256};

    if entry["type"] != "file"
        || !std::fs::symlink_metadata(path)
            .map_err(ModelReceiptError::Io)?
            .is_file()
    {
        return Ok(false);
    }
    let mut file = std::fs::File::open(path).map_err(ModelReceiptError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(ModelReceiptError::Io)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let expected = format!("sha256:{:x}", digest.finalize());
    Ok(entry["sha256"].as_str() == Some(expected.as_str()))
}
