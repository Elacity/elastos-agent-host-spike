//! One installed operator-Home fixture, shared by the operator tests.

use agent_conformance::build::repository;
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::runtime::{localhost_provider_under_test, sha256_file};
use serde_json::{json, Value};
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

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
    let platform = operator_platform()?;
    let provider = localhost_provider_under_test()?;
    let source: Value = serde_json::from_slice(&fs::read(repository().join("components.json"))?)?;
    let mut entry = source["external"]["localhost-provider"].clone();
    let platforms = entry["platforms"]
        .as_object_mut()
        .ok_or("repository localhost-provider entry requires platforms")?;
    let info = platforms.entry(platform).or_insert_with(|| json!({}));
    if !info.is_object() {
        return Err("repository localhost-provider platform must be an object".into());
    }

    fs::create_dir(home.data().join("bin"))?;
    let installed = home.data().join("bin/localhost-provider");
    let mut copy = File::create_new(&installed)?;
    std::io::copy(&mut File::open(&provider.binary)?, &mut copy)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        copy.set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    info["checksum"] = json!(format!("sha256:{}", sha256_file(&installed)?));
    info["size"] = json!(copy.metadata()?.len());
    info["install_path"] = json!("bin/localhost-provider");
    let manifest = json!({"external": {"localhost-provider": entry}, "profiles": {}});
    serde_json::to_writer_pretty(
        File::create_new(home.data().join("components.json"))?,
        &manifest,
    )?;
    File::create_new(home.data().join("config.toml"))?
        .write_all(include_bytes!("../../fixtures/operator-config.toml"))?;
    Ok(installed)
}
