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
    home.guard(home.home(), home.data())?;
    let provider = localhost_provider_under_test()?;
    let bytes = fs::read(&provider.binary)?;
    let installed = home.data().join("bin/localhost-provider");
    write_component_home(
        home,
        "localhost-provider",
        &installed,
        &bytes,
        &format!("{:x}", Sha256::digest(&bytes)),
    )?;
    File::create_new(home.data().join("config.toml"))?
        .write_all(include_bytes!("../../fixtures/operator-config.toml"))?;
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
    let source: Value = serde_json::from_slice(&fs::read(repository().join("components.json"))?)?;
    let mut entry = source["external"][component].clone();
    let platforms = entry["platforms"]
        .as_object_mut()
        .ok_or_else(|| format!("repository {component} entry requires platforms"))?;
    let info = platforms.entry(platform).or_insert_with(|| json!({}));
    if !info.is_object() {
        return Err(format!("repository {component} platform must be an object").into());
    }

    fs::create_dir(home.data().join("bin"))?;
    let mut copy = File::create_new(installed)?;
    copy.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        copy.set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    info["checksum"] = json!(format!("sha256:{checksum}"));
    info["size"] = json!(copy.metadata()?.len());
    info["install_path"] = json!(format!("bin/{component}"));
    let manifest = json!({"external": {component: entry}, "profiles": {}});
    serde_json::to_writer_pretty(
        File::create_new(home.data().join("components.json"))?,
        &manifest,
    )?;
    Ok(())
}
