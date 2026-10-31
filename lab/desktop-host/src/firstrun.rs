//! First open from the signed release folder inside the app (ELASTOS-DESKTOP-APP P4).
//!
//! LAB DRAFT: `elastos install --from` exists only on the lab Runtime branch
//! `lab/standalone-install`. The Runtime checks the publisher, signatures, CIDs and
//! SHA-256 of every file exactly as for a download; this app only runs it, and only
//! into `ELASTOS_LAB_HOME`.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

/// `Contents/Resources/release` of this app, when `bundle.sh` packed one.
pub fn payload() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let release = exe.parent()?.parent()?.join("Resources/release");
    release.is_dir().then_some(release)
}

/// Runs the release's own Runtime, a file named by its CID, to install from `release`.
pub fn install(release: &Path, home: &Path) -> io::Result<()> {
    let cid = std::fs::read_to_string(release.with_file_name("runtime-cid"))?;
    std::fs::create_dir_all(home)?;
    let log = std::fs::File::options()
        .create(true)
        .append(true)
        .open(home.join("install.log"))?;
    let status = Command::new(release.join(cid.trim()))
        .arg("install")
        .arg("--from")
        .arg(release)
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "the Runtime installer exited with {status}; see {}",
            home.join("install.log").display()
        )));
    }
    Ok(())
}

/// Appends one timing line to `<lab home>/firstrun-timing.log`.
pub fn note(home: &Path, started: Instant, what: &str) {
    use std::io::Write;
    if let Ok(mut log) = std::fs::File::options()
        .create(true)
        .append(true)
        .open(home.join("firstrun-timing.log"))
    {
        let _ = writeln!(log, "{:>7.2} s  {what}", started.elapsed().as_secs_f64());
    }
}
