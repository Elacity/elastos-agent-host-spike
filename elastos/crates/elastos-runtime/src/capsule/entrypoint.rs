use std::path::Path;

use elastos_common::{ElastosError, Result};

/// Refuse an on-disk entrypoint unless it is a regular file inside its capsule.
/// An absent entrypoint is left to the launch path's own missing-file error.
pub async fn check_entrypoint_file(capsule_dir: &Path, entrypoint: &str) -> Result<()> {
    let refused =
        |why: &str| ElastosError::InvalidManifest(format!("Entrypoint {entrypoint} {why}"));
    let Ok(file) = tokio::fs::canonicalize(capsule_dir.join(entrypoint)).await else {
        return Ok(());
    };
    let dir = tokio::fs::canonicalize(capsule_dir)
        .await
        .map_err(ElastosError::Io)?;
    if !file.starts_with(&dir) {
        return Err(refused("leads out of the capsule directory"));
    }
    let kind = tokio::fs::metadata(&file).await.map_err(ElastosError::Io)?;
    if !kind.is_file() {
        return Err(refused("is not a regular file"));
    }
    Ok(())
}
