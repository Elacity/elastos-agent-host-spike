use agent_conformance::build::repository;
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::runtime::{localhost_provider_under_test, sha256_file};
use serde_json::{json, Value};
use std::error::Error;
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;

/// The shared operator fixture owns only the provider and its local manifest.
/// Runtime owns first-run state. The caller decides the bounded launch mode.
pub fn write_operator_home(home: &ThrowawayHome) -> Result<PathBuf, Box<dyn Error>> {
    home.guard(home.home(), home.data())?;
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-amd64",
        _ => return Err("operator Home fixture requires darwin-arm64 or darwin-amd64".into()),
    };
    let source: Value = serde_json::from_slice(&fs::read(repository().join("components.json"))?)?;
    let mut provider = source
        .pointer("/external/localhost-provider")
        .filter(|entry| entry.is_object())
        .ok_or("repository manifest has no localhost-provider entry")?
        .clone();
    let info = provider
        .get_mut("platforms")
        .and_then(|platforms| platforms.get_mut(platform))
        .and_then(Value::as_object_mut)
        .ok_or("repository localhost-provider entry has no current platform")?;
    let built = localhost_provider_under_test()?;

    // Exclusive creation refuses pre-existing paths, including symlinks.
    fs::create_dir(home.data().join("bin"))?;
    let installed = home.data().join("bin/localhost-provider");
    let mut copy = File::create_new(&installed)?;
    let size = io::copy(&mut File::open(&built.binary)?, &mut copy)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        copy.set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    let checksum = sha256_file(&installed)?;
    if checksum != built.sha256 {
        return Err("installed localhost-provider bytes differ from the built SHA-256".into());
    }
    info.insert("checksum".into(), json!(format!("sha256:{checksum}")));
    info.insert("size".into(), json!(size));
    info.insert("install_path".into(), json!("bin/localhost-provider"));
    let manifest = json!({"external": {"localhost-provider": provider}, "profiles": {}});
    serde_json::to_writer_pretty(
        File::create_new(home.data().join("components.json"))?,
        &manifest,
    )?;
    Ok(installed)
}
