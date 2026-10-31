//! A release folder on this computer as the byte source for install and setup, for a
//! desktop app that carries its release (`elastos install --from <dir>`).
//!
//! The folder holds `release-head.json`, `release.json`, `sources.json`, and every
//! artifact named by its CID. The folder is untrusted: install takes the head CID
//! and publisher DID from its caller. Only where the bytes come from changes: the
//! release signatures, the head-to-release binding, the binary descriptor, each
//! row's checksum and size, and the pinned catalogue and network checks run exactly
//! as they do for bytes that arrive over Carrier.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Context;

static SELECTED: OnceLock<PathBuf> = OnceLock::new();

/// Makes `dir` this process's byte source for setup. Set once, before setup runs.
pub fn select(dir: &Path) -> anyhow::Result<()> {
    let dir = fs::canonicalize(dir)
        .with_context(|| format!("release folder {} is not readable", dir.display()))?;
    anyhow::ensure!(
        dir.is_dir(),
        "release folder {} is not a folder",
        dir.display()
    );
    SELECTED
        .set(dir)
        .map_err(|_| anyhow::anyhow!("a release folder is already selected"))
}

pub(crate) fn selected() -> Option<&'static Path> {
    SELECTED.get().map(PathBuf::as_path)
}

const METADATA_MAX_BYTES: usize = 256 * 1024;
const SOURCES_MAX_BYTES: usize = 64 * 1024;
const RUNTIME_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Opens `<dir>/<name>` once, without following a link or blocking on a pipe, and
/// refuses anything but a regular file.
fn open_entry(dir: &Path, name: &str) -> anyhow::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(name))
        .with_context(|| format!("the release folder has no readable {name}"))?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "{name} in the release folder is not a regular file"
    );
    Ok(file)
}

fn read_entry(dir: &Path, name: &str, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_entry(dir, name)?
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= max_bytes,
        "{name} in the release folder exceeds its {max_bytes}-byte bound"
    );
    Ok(bytes)
}

/// A CID is letters and digits only, so the name cannot leave the folder.
fn ensure_cid_name(cid: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !cid.is_empty() && cid.len() <= 128 && cid.bytes().all(|b| b.is_ascii_alphanumeric()),
        "release folder lookup needs a CID, not {cid:?}"
    );
    Ok(())
}

/// The artifact named `cid`, refused above `max_bytes` as a Carrier reply would be.
pub(crate) fn read(dir: &Path, cid: &str, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    ensure_cid_name(cid)?;
    read_entry(dir, cid, max_bytes)
}

pub(crate) fn open(dir: &Path, cid: &str) -> anyhow::Result<fs::File> {
    ensure_cid_name(cid)?;
    open_entry(dir, cid)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// Installs the folder's Runtime through the same writer `install.sh` uses, then
/// upgrades protected roots as `install.sh` does. Returns the installed binary.
///
/// Trust comes from the caller, never from the folder: `head_cid` names the exact
/// release head, `publisher` is its only accepted signer, as `install.sh` pins its
/// maintainer DID, and `sources_sha256` pins the folder's update endpoints. A
/// computer that already has ElastOS is refused, it updates itself from Home,
/// unless it is this same release whose setup did not finish.
pub fn install(
    from: &Path,
    install_dir: &Path,
    publisher: &str,
    head_cid: &str,
    sources_sha256: &str,
) -> anyhow::Result<PathBuf> {
    let dir = fs::canonicalize(from)
        .with_context(|| format!("release folder {} is not readable", from.display()))?;
    let binary = install_dir.join("elastos");
    let data_dir = crate::sources::default_data_dir();
    if fs::symlink_metadata(&binary).is_ok() {
        let same_release = crate::sources::load_trusted_sources(&data_dir)
            .ok()
            .and_then(|config| config.default_source().cloned())
            .is_some_and(|source| {
                source.head_cid == head_cid
                    && source.publisher_dids == [publisher]
                    && Path::new(&source.install_path) == binary
            });
        anyhow::ensure!(
            same_release,
            "ElastOS is already installed at {}; it updates itself from Home, so this installation was not changed",
            binary.display()
        );
        migrate_principal_roots(&data_dir)?;
        return Ok(binary);
    }

    let head = read_entry(&dir, "release-head.json", METADATA_MAX_BYTES)?;
    crate::update::verify_release_metadata_cid(head_cid, &head)
        .context("release-head.json is not the release this installer was given")?;
    let release = read_entry(&dir, "release.json", METADATA_MAX_BYTES)?;
    let manifest: serde_json::Value = serde_json::from_slice(&release)?;
    let version = manifest["payload"]["version"]
        .as_str()
        .context("the release names no version")?;
    let descriptor =
        &manifest["payload"]["platforms"][crate::update::detect_release_platform()]["binary"];
    let (Some(cid), Some(size), Some(sha256)) = (
        descriptor["cid"].as_str(),
        descriptor["size"].as_u64(),
        descriptor["sha256"].as_str(),
    ) else {
        anyhow::bail!("the release names no Runtime for this computer");
    };
    anyhow::ensure!(
        size <= RUNTIME_MAX_BYTES,
        "the release's Runtime is too large"
    );
    let runtime = read(&dir, cid, size as usize)?;
    anyhow::ensure!(
        runtime.len() as u64 == size && sha256_hex(&runtime) == sha256,
        "the Runtime in the release folder is not the one the release names"
    );

    let sources_bytes = read_entry(&dir, "sources.json", SOURCES_MAX_BYTES)?;
    anyhow::ensure!(
        sha256_hex(&sources_bytes) == sources_sha256,
        "sources.json is not the one this installer was given"
    );
    let mut sources: serde_json::Value = serde_json::from_slice(&sources_bytes)?;
    let install_path = binary
        .to_str()
        .context("the install folder path is not UTF-8")?;
    for source in sources["sources"]
        .as_array_mut()
        .context("the release folder's sources.json lists no source")?
    {
        source["install_path"] = install_path.into();
        source["publisher_dids"] = serde_json::json!([publisher]);
        source["head_cid"] = head_cid.into();
    }
    // The same admission install_release runs, before any of the folder's code runs.
    let config: crate::sources::TrustedSourcesConfig = serde_json::from_value(sources.clone())?;
    crate::installed_release::admit_candidate(
        &binary,
        config
            .default_source()
            .context("the release folder's sources.json has no default source")?,
        &runtime,
        &head,
        &release,
    )?;

    if crate::sources::trusted_sources_path(&data_dir).exists() {
        let current = crate::sources::load_trusted_sources(&data_dir)?;
        anyhow::ensure!(
            current
                .default_source()
                .is_some_and(|source| source.publisher_dids.iter().any(|did| did == publisher)),
            "ElastOS data on this computer trusts a different publisher; this installation was not changed"
        );
    }

    // Admission reads private copies, so the folder cannot change under it.
    let scratch = tempfile::tempdir()?;
    let staged = scratch.path().join("elastos");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&staged)?
            .write_all(&runtime)?;
    }
    let reported = std::process::Command::new(&staged)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output()
        .context("the release's Runtime did not run on this computer")?;
    anyhow::ensure!(
        reported.status.success()
            && reported.stderr.is_empty()
            && String::from_utf8_lossy(&reported.stdout).trim_end_matches('\n')
                == format!("elastos {version}"),
        "the release's Runtime does not report version {version}; this installation was not changed"
    );
    let head_path = scratch.path().join("release-head.json");
    let release_path = scratch.path().join("release.json");
    let sources_path = scratch.path().join("sources.json");
    fs::write(&head_path, &head)?;
    fs::write(&release_path, &release)?;
    fs::write(&sources_path, serde_json::to_vec_pretty(&sources)?)?;

    fs::create_dir_all(install_dir)?;
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&data_dir)?;
    }
    crate::update::install_release(
        &data_dir,
        &binary,
        [
            staged.as_path(),
            sources_path.as_path(),
            head_path.as_path(),
            release_path.as_path(),
        ],
        false,
    )?;
    migrate_principal_roots(&data_dir)?;
    Ok(binary)
}

fn migrate_principal_roots(data_dir: &Path) -> anyhow::Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let backup = data_dir.join("backups").join(format!(
        "principal-root-upgrade-{stamp}-{}",
        std::process::id()
    ));
    crate::api::auth_gateway::migrate_configured_principal_roots_offline(data_dir, &backup)?;
    Ok(())
}
