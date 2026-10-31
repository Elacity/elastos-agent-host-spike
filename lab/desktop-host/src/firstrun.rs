//! First open from the files inside the app (prototype P3 of ELASTOS-DESKTOP-APP).
//!
//! SIMULATED: the Runtime has no command yet that installs from local files. This
//! clones a ready-made alpha.26 install that `bundle.sh` packed into the app and skips
//! the publisher, signature, CID and SHA-256 checks the real Runtime command must run.
//! It only ever writes into `ELASTOS_LAB_HOME`.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// `Contents/Resources/payload` of this app, when `bundle.sh` packed one.
pub fn payload() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let payload = exe.parent()?.parent()?.join("Resources/payload");
    payload.is_dir().then_some(payload)
}

/// `Contents/Resources/sim-bin`: a do-nothing `open`, so alpha.26 `home --browser`
/// starts Home without a browser.
pub fn sim_bin() -> Option<PathBuf> {
    let bin = payload()?.parent()?.join("sim-bin");
    bin.is_dir().then_some(bin)
}

/// Clones the packed install into `home` and points its absolute paths at `home`.
/// APFS clones files on the same volume, so this takes no extra space.
pub fn install(payload: &Path, home: &Path) -> io::Result<()> {
    let seed = std::fs::read_to_string(payload.join(".seed-home"))?;
    let seed = seed.trim();
    let target = home
        .to_str()
        .ok_or_else(|| io::Error::other("the lab home path is not UTF-8"))?;
    std::fs::create_dir_all(home)?;
    for dir in [".local", "Library"] {
        let status = Command::new("/bin/cp")
            .arg("-cRp")
            .arg(payload.join(dir))
            .arg(home)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!("cp {dir} exited with {status}")));
        }
    }
    for file in lines(&payload.join(".path-files"))? {
        let file = home.join(file);
        let text = std::fs::read_to_string(&file)?;
        std::fs::write(&file, text.replace(seed, target))?;
    }
    // Links are listed, not packed: a signed app may not hold links that leave it.
    for line in lines(&payload.join(".path-links"))? {
        let (link, to) = line
            .split_once('\t')
            .ok_or_else(|| io::Error::other("bad .path-links line"))?;
        std::os::unix::fs::symlink(to.replace(seed, target), home.join(link))?;
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

fn lines(list: &Path) -> io::Result<Vec<String>> {
    Ok(std::fs::read_to_string(list)?
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}
