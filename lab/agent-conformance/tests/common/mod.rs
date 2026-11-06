//! One installed component-Home writer, shared by the Runtime tests.

use agent_conformance::build::repository;
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::runtime::localhost_provider_under_test;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub mod operator;
pub mod signed_bundle;

pub fn operator_platform() -> Result<&'static str, &'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("darwin-arm64"),
        ("macos", "x86_64") => Ok("darwin-amd64"),
        _ => Err("operator Home requires darwin-arm64 or darwin-amd64"),
    }
}

/// Prepare a fresh Home only. Exclusive creation refuses existing destinations,
/// including symlinks, before a copy or manifest write can follow them.
pub fn write_operator_home(home: &ThrowawayHome) -> Result<PathBuf, Box<dyn Error>> {
    write_operator_home_with_loader(home, || {
        let provider = localhost_provider_under_test()?;
        Ok(fs::read(provider.verified_path()?)?)
    })
}

// Keep native preparation replaceable in tests while sharing the full writer.
pub(super) fn write_operator_home_with_loader(
    home: &ThrowawayHome,
    load_provider: impl FnOnce() -> Result<Vec<u8>, Box<dyn Error>>,
) -> Result<PathBuf, Box<dyn Error>> {
    home.guard(home.home(), home.data())?;
    let bytes = load_provider()?;
    let installed = home.data().join("bin/localhost-provider");
    write_component_home(
        home,
        "localhost-provider",
        &installed,
        &bytes,
        &format!("{:x}", Sha256::digest(&bytes)),
    )?;
    let config = home.data().join("config.toml");
    File::create_new(&config)
        .map_err(|error| format!("create operator config {}: {error}", config.display()))?
        .write_all(include_bytes!("../../fixtures/operator-config.toml"))
        .map_err(|error| format!("write operator config {}: {error}", config.display()))?;
    Ok(installed)
}

/// Copy one repository entry and stamp the installed bytes and claimed hash.
/// Callers select the destination independently so F-ac1i can move only the copy.
pub fn write_component_home(
    home: &ThrowawayHome,
    component: &str,
    installed: &Path,
    bytes: &[u8],
    checksum: &str,
) -> Result<(), Box<dyn Error>> {
    home.guard(home.home(), home.data())?;
    let platform = operator_platform()?;
    let source_path = repository().join("components.json");
    let source_bytes = fs::read(&source_path)
        .map_err(|error| format!("read component source {}: {error}", source_path.display()))?;
    let source: Value = serde_json::from_slice(&source_bytes)
        .map_err(|error| format!("decode component source {}: {error}", source_path.display()))?;
    let mut entry = source["external"][component].clone();
    let platforms = entry["platforms"]
        .as_object_mut()
        .ok_or_else(|| format!("repository {component} entry requires platforms"))?;
    let info = platforms.entry(platform).or_insert_with(|| json!({}));
    if !info.is_object() {
        return Err(format!("repository {component} platform must be an object").into());
    }

    let bin = home.data().join("bin");
    fs::create_dir(&bin)
        .map_err(|error| format!("create component directory {}: {error}", bin.display()))?;
    let mut copy = File::create_new(installed)
        .map_err(|error| format!("create component file {}: {error}", installed.display()))?;
    copy.write_all(bytes)
        .map_err(|error| format!("write component file {}: {error}", installed.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        copy.set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|error| {
                format!("set component permissions {}: {error}", installed.display())
            })?;
    }
    info["checksum"] = json!(format!("sha256:{checksum}"));
    info["size"] = json!(copy
        .metadata()
        .map_err(|error| format!("read component metadata {}: {error}", installed.display()))?
        .len());
    info["install_path"] = json!(format!("bin/{component}"));
    let manifest = json!({"external": {component: entry}, "profiles": {}});
    let manifest_path = home.data().join("components.json");
    serde_json::to_writer_pretty(
        File::create_new(&manifest_path).map_err(|error| {
            format!(
                "create component manifest {}: {error}",
                manifest_path.display()
            )
        })?,
        &manifest,
    )
    .map_err(|error| {
        format!(
            "write component manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    Ok(())
}
