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

/// Runs the release's own Runtime, a file named by its CID, to install from
/// `release`. The folder is not trusted to name its own publisher, release or
/// endpoints, or to supply the Runtime that checks them: `bundle.sh` builds all of
/// them into this app, and only the Runtime bytes with the built-in SHA-256 run.
pub fn install(release: &Path, home: &Path) -> io::Result<()> {
    let (Some(head), Some(publisher), Some(runtime), Some(runtime_sha256), Some(sources_sha256)) = (
        option_env!("ELASTOS_RELEASE_HEAD"),
        option_env!("ELASTOS_RELEASE_PUBLISHER"),
        option_env!("ELASTOS_RELEASE_RUNTIME"),
        option_env!("ELASTOS_RELEASE_RUNTIME_SHA256"),
        option_env!("ELASTOS_RELEASE_SOURCES_SHA256"),
    ) else {
        return Err(io::Error::other(
            "this app was built without a release to install",
        ));
    };
    // Ubuntu's umask leaves new folders group-writable; the Runtime's providers
    // refuse data under a group-writable ancestor.
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(home)?;
    }
    let installer = home.join(format!(".elastos-installer-{}", std::process::id()));
    stage_runtime(&release.join(runtime), runtime_sha256, &installer)?;
    let log = std::fs::File::options()
        .create(true)
        .append(true)
        .open(home.join("install.log"))?;
    let status = Command::new(&installer)
        .arg("install")
        .arg("--from")
        .arg(release)
        .args(["--publisher", publisher, "--head", head])
        .args(["--sources-sha256", sources_sha256])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .status();
    let _ = std::fs::remove_file(&installer);
    let status = status?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "the Runtime installer exited with {status}; see {}",
            home.join("install.log").display()
        )));
    }
    Ok(())
}

/// Copies `source` to a new private `staged` file only if its bytes have `sha256`,
/// reading it once without following a link.
fn stage_runtime(source: &Path, sha256: &str, staged: &Path) -> io::Result<()> {
    use sha2::Digest;
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("the app's Runtime is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if format!("{:x}", sha2::Sha256::digest(&bytes)) != sha256 {
        return Err(io::Error::other(
            "the app's Runtime is not the one this app was built with",
        ));
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(staged)?
        .write_all(&bytes)
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
