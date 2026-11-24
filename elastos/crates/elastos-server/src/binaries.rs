use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use elastos_common::{CapsuleManifest, ProviderAuthority};
use elastos_runtime::provider::CheckedExecutable;

use crate::{setup, sources::default_data_dir};

/// The running runtime has been admitted. Call `prepare` immediately before spawn.
#[derive(Debug)]
pub struct AdmittedRuntime {
    path: PathBuf,
    checksum: Option<String>,
}

/// Canonical install path and lowercase sha256. `Ok(None)` with no release.
pub(crate) fn signed_runtime_install(data_dir: &Path) -> anyhow::Result<Option<(PathBuf, String)>> {
    let Some(source) = setup::installed_release_source(data_dir)? else {
        return Ok(None);
    };
    let path = std::fs::canonicalize(&source.install_path)
        .map_err(|error| anyhow::anyhow!("installed release binary: {error}"))?;
    let (release_bytes, _) =
        crate::installed_release::read_signed_release(data_dir, &path, &source, false, true)?;
    let release: serde_json::Value = serde_json::from_slice(&release_bytes)?;
    let sha256 = release["payload"]["platforms"][crate::update::detect_release_platform()]
        ["binary"]["sha256"]
        .as_str()
        .filter(|sha| sha.len() == 64)
        .ok_or_else(|| anyhow::anyhow!("signed runtime digest is malformed"))?
        .to_ascii_lowercase();
    Ok(Some((path, sha256)))
}

impl AdmittedRuntime {
    /// Hold the admitted bytes. A `dev_mode` source Home holds that path unchecked.
    pub fn prepare(&self) -> anyhow::Result<setup::verified_executable::VerifiedExecutable> {
        if self.checksum.is_none() {
            return setup::verified_executable::VerifiedExecutable::unchecked(&self.path);
        }
        setup::verified_executable::VerifiedExecutable::prepare(&self.path, self.signed_checksum()?)
    }

    pub fn signed_checksum(&self) -> anyhow::Result<&str> {
        self.checksum.as_deref().ok_or_else(|| {
            anyhow::anyhow!("no signed release digest (dev_mode start is unchecked)")
        })
    }
}

/// Admit the running Runtime before this process starts it again.
/// An installed Home admits only bytes that match its signed release.
/// A source Home with no release continues only through `dev_mode = true`.
pub fn checked_running_runtime(data_dir: &Path, exe: &Path) -> anyhow::Result<AdmittedRuntime> {
    let Some((install, sha256)) = signed_runtime_install(data_dir)? else {
        if !setup::source_home_dev_mode(data_dir) {
            return Err(setup::missing_trusted_source_error());
        }
        return Ok(AdmittedRuntime {
            path: exe.to_path_buf(),
            checksum: None,
        });
    };
    let running =
        std::fs::canonicalize(exe).map_err(|error| anyhow::anyhow!("running binary: {error}"))?;
    let checksum = format!("sha256:{sha256}");
    // A different path is admitted only when that file's own bytes match.
    if running != install {
        anyhow::ensure!(
            running_file_matches_digest(&running, &checksum)?,
            "running binary is not the installed release"
        );
    }
    Ok(AdmittedRuntime {
        path: install,
        checksum: Some(checksum),
    })
}

fn running_file_matches_digest(path: &Path, checksum: &str) -> anyhow::Result<bool> {
    let expected = checksum
        .strip_prefix("sha256:")
        .filter(|hex_digits| hex_digits.len() == 64)
        .ok_or_else(|| anyhow::anyhow!("signed runtime digest is malformed"))?;
    let (actual, _) = crate::installed_release::file_digest(path)?;
    Ok(actual == expected.to_ascii_lowercase())
}

/// Bind a native provider start to the current publisher-signed release.
/// A failed admission stays a refused executable until the bridge reports it.
pub fn checked_native_provider(path: &Path) -> CheckedExecutable {
    checked_native_provider_with_data_dir(&default_data_dir(), path)
}

/// Admit a native provider against the signed release of the Home at
/// `data_dir`, the Home whose state the provider will serve.
pub fn checked_native_provider_with_data_dir(data_dir: &Path, path: &Path) -> CheckedExecutable {
    // Library tests start isolated fixture executables that live outside the
    // Home they run against; an executable inside the Home is always admitted.
    #[cfg(all(test, unix))]
    if path.is_file() && !path.starts_with(data_dir) {
        return crate::test_support::fixture_executable(path).with_home_data_dir(data_dir);
    }
    let admitted = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("native provider name is invalid"))
        .and_then(|name| setup::verify_installed_component_start(data_dir, name, path))
        // Admission holds the signed bytes; the bridge re-checks the same
        // digest at spawn and runs the bytes it checked (CheckedExecutable).
        .and_then(|verified| {
            let checksum = verified.signed_checksum()?;
            CheckedExecutable::pinned(path, checksum)
                .map(|checked| checked.with_home_data_dir(data_dir))
                .map_err(anyhow::Error::msg)
        });
    admitted.unwrap_or_else(|error| {
        CheckedExecutable::refused(
            path,
            format!("provider signed release admission refused: {error}"),
        )
    })
}

/// Find a provider binary from an operator override or installed runtime paths.
pub fn find_installed_provider_binary(name: &str) -> Option<PathBuf> {
    let data_dir = default_data_dir();
    let env_name = format!(
        "ELASTOS_{}_BIN",
        name.to_ascii_uppercase().replace('-', "_")
    );

    if let Some(path) = std::env::var_os(env_name) {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    if let Some(dir) = std::env::var_os("ELASTOS_CAPSULE_BIN_DIR") {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    let installed_component = data_dir.join("bin").join(name);
    if installed_component.is_file() {
        return Some(installed_component);
    }

    let installed_capsule = data_dir.join("capsules").join(name).join(name);
    if installed_capsule.is_file() {
        return Some(installed_capsule);
    }

    if let Some(global_data_dir) = dirs::data_dir().map(|dir| dir.join("elastos")) {
        let global_component = global_data_dir.join("bin").join(name);
        if global_component.is_file() {
            return Some(global_component);
        }

        let global_capsule = global_data_dir.join("capsules").join(name).join(name);
        if global_capsule.is_file() {
            return Some(global_capsule);
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let from_exe = exe_dir.join("../share/elastos/bin").join(name);
            if from_exe.is_file() {
                return Some(from_exe);
            }
        }
    }

    if let Some(path_dirs) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_dirs) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

pub fn verify_component_binary_with_data_dir(
    data_dir: &Path,
    name: &str,
    path: &Path,
) -> anyhow::Result<()> {
    let checksum = setup::verify_installed_component_binary(data_dir, name, path)?;
    tracing::info!(
        "{} binary verified against installed manifest ({})",
        name,
        checksum
    );
    Ok(())
}

pub fn verify_component_binary(name: &str, path: &Path) -> anyhow::Result<()> {
    let data_dir = default_data_dir();
    verify_component_binary_with_data_dir(&data_dir, name, path)
}

pub fn resolve_verified_provider_binary(
    name: &str,
    missing_guidance: &str,
) -> anyhow::Result<CheckedExecutable> {
    let path = find_installed_provider_binary(name)
        .ok_or_else(|| anyhow::anyhow!("{}", missing_guidance))?;
    verify_component_binary(name, &path)?;
    Ok(checked_native_provider(&path))
}

pub fn resolve_verified_native_provider_binary_with_data_dir(
    data_dir: &Path,
    name: &str,
) -> anyhow::Result<Option<PathBuf>> {
    let bin_dir = std::env::var_os("ELASTOS_CAPSULE_BIN_DIR").map(PathBuf::from);
    resolve_verified_native_provider_binary_with_bin_dir(data_dir, name, bin_dir.as_deref())
}

/// A native provider row that the resolver verified: the executable path, the
/// checksum its row names, and the row itself.
struct VerifiedNativeRow {
    path: PathBuf,
    checksum: String,
    component: setup::Component,
}

fn resolve_verified_native_provider_binary_with_bin_dir(
    data_dir: &Path,
    name: &str,
    bin_dir: Option<&Path>,
) -> anyhow::Result<Option<PathBuf>> {
    Ok(resolve_verified_native_row_with_bin_dir(data_dir, name, bin_dir)?.map(|row| row.path))
}

fn resolve_verified_native_row_with_bin_dir(
    data_dir: &Path,
    name: &str,
    bin_dir: Option<&Path>,
) -> anyhow::Result<Option<VerifiedNativeRow>> {
    let manifest_path = data_dir.join("components.json");
    let manifest_bytes = match std::fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow::anyhow!(
                "cannot resolve native provider '{}': failed to read {}: {}",
                name,
                manifest_path.display(),
                err
            ));
        }
    };
    let manifest: setup::ComponentsManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|err| {
            anyhow::anyhow!(
                "cannot resolve native provider '{}': invalid {}: {}",
                name,
                manifest_path.display(),
                err
            )
        })?;
    let Some(component) = manifest.external.get(name) else {
        return Ok(None);
    };
    setup::validate_provider_runtime(name, component)?;
    let expected_install_path = format!("bin/{name}");
    let install_path = component.install_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "component '{}' is missing install_path for native provider resolution",
            name
        )
    })?;
    if install_path != expected_install_path {
        anyhow::bail!(
            "component '{}' native provider install_path must be '{}'",
            name,
            expected_install_path
        );
    }
    let installed_path = data_dir.join(install_path);
    let path = bin_dir
        .map(|bin_dir| bin_dir.join(name))
        .unwrap_or(installed_path);
    if !path.is_file() {
        return Ok(None);
    }
    let expected_checksum = setup::resolve_platform_info(component, &setup::detect_platform())
        .and_then(|platform| platform.checksum.as_deref())
        .filter(|checksum| !checksum.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "component '{}' is missing the current platform checksum",
                name
            )
        })?;
    let verified_checksum = setup::verify_installed_component_binary(data_dir, name, &path)?;
    if verified_checksum != expected_checksum {
        anyhow::bail!(
            "component '{}' selected binary checksum differs from the resolving manifest",
            name
        );
    }
    tracing::info!(
        "{} binary verified against installed manifest ({})",
        name,
        verified_checksum
    );
    Ok(Some(VerifiedNativeRow {
        path,
        checksum: verified_checksum,
        component: component.clone(),
    }))
}

pub fn resolve_verified_native_provider_binary(
    name: &str,
) -> anyhow::Result<Option<CheckedExecutable>> {
    let data_dir = default_data_dir();
    Ok(
        resolve_verified_native_provider_binary_with_data_dir(&data_dir, name)?
            .map(|path| checked_native_provider_with_data_dir(&data_dir, &path)),
    )
}

/// A native provider whose executable, manifest and authority the resolver
/// verified. The fields are private; only `admit_with_bin_dir` writes them.
pub struct AdmittedProvider {
    key: String,
    path: PathBuf,
    checksum: String,
    signer_did: Option<String>,
    authority: ProviderAuthority,
}

impl AdmittedProvider {
    /// `Ok(None)` when no row resolves for `key` here; `Err` when a resolved
    /// row or the manifest beside it does not verify.
    pub fn admit(data_dir: &Path, key: &str) -> anyhow::Result<Option<Self>> {
        let bin_dir = std::env::var_os("ELASTOS_CAPSULE_BIN_DIR").map(PathBuf::from);
        let signers = setup::installed_release_signers(data_dir)?;
        Self::admit_with_bin_dir(data_dir, key, bin_dir.as_deref(), &signers)
    }

    fn admit_with_bin_dir(
        data_dir: &Path,
        key: &str,
        bin_dir: Option<&Path>,
        signers: &BTreeMap<String, String>,
    ) -> anyhow::Result<Option<Self>> {
        let Some(row) = resolve_verified_native_row_with_bin_dir(data_dir, key, bin_dir)? else {
            return Ok(None);
        };
        let manifest_path = data_dir.join("capsules").join(key).join("capsule.json");
        let invalid = |err: String| anyhow::anyhow!("cannot admit '{}': {}", key, err);
        let bytes = elastos_common::capsule_manifest_file::read(&manifest_path)
            .map_err(|err| invalid(format!("read {}: {err}", manifest_path.display())))?;
        let manifest: CapsuleManifest = serde_json::from_slice(&bytes)
            .map_err(|err| invalid(format!("{}: {err}", manifest_path.display())))?;
        manifest.validate().map_err(invalid)?;
        if manifest.name != key {
            anyhow::bail!("cannot admit '{}': manifest names '{}'", key, manifest.name);
        }
        let runtime = row.component.provider_runtime.as_ref().ok_or_else(|| {
            anyhow::anyhow!("component '{}' is missing provider runtime metadata", key)
        })?;
        if manifest.provides.as_deref() != Some(runtime.provides.as_str()) {
            anyhow::bail!(
                "cannot admit '{}': manifest provides {:?}, the row provides '{}'",
                key,
                manifest.provides,
                runtime.provides
            );
        }
        let authority = manifest
            .authority
            .ok_or_else(|| invalid("declares no authority".to_string()))?;
        Ok(Some(Self {
            key: key.to_owned(),
            path: row.path,
            checksum: row.checksum,
            signer_did: signers.get(key).cloned(),
            authority,
        }))
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The admitted bytes as the bridge's spawn-time check. The exact path is
    /// admitted through the signed release; the signed digest is pinned here
    /// and re-checked when the provider starts. A Home with no signed digest,
    /// including `dev_mode`, is refused.
    pub fn checked_executable(&self, data_dir: &Path) -> Result<CheckedExecutable, String> {
        let verified = setup::verify_installed_component_start(data_dir, &self.key, &self.path)
            .map_err(|error| format!("provider signed release admission refused: {error}"))?;
        let signed = verified
            .signed_checksum()
            .map_err(|error| format!("provider signed release admission refused: {error}"))?;
        if signed != self.checksum {
            return Err(
                "provider signed release admission refused: signed digest differs from the admitted row"
                    .to_string(),
            );
        }
        CheckedExecutable::pinned(&self.path, signed)
            .map(|checked| checked.with_home_data_dir(data_dir))
    }

    #[allow(dead_code)]
    pub(crate) fn checksum(&self) -> &str {
        &self.checksum
    }

    #[allow(dead_code)]
    pub(crate) fn signer_did(&self) -> Option<&str> {
        self.signer_did.as_deref()
    }

    pub fn authority(&self) -> &ProviderAuthority {
        &self.authority
    }
}

/// A file `open_regular` will admit. The running test binary is used when it
/// already has one link and a private mode; otherwise a byte copy is signed.
#[cfg(all(test, unix))]
pub(crate) struct InstallableRuntime {
    _hold: Option<tempfile::TempDir>,
    pub path: PathBuf,
}

#[cfg(all(test, unix))]
impl InstallableRuntime {
    pub(crate) fn of(exe: &Path) -> InstallableRuntime {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::metadata(exe).expect("running binary metadata");
        let installable = meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o7022 == 0;
        if installable {
            return InstallableRuntime {
                _hold: None,
                path: exe.to_path_buf(),
            };
        }
        let hold = tempfile::tempdir().unwrap();
        let path = hold.path().join("runtime");
        std::fs::copy(exe, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        InstallableRuntime {
            _hold: Some(hold),
            path,
        }
    }
}

/// Runs `test_name` in a child when this process is the parallel test gate.
/// The child is the only place a case may set `TMPDIR` or `ELASTOS_*`.
#[cfg(all(test, unix))]
pub(crate) fn run_isolated(test_name: &str) -> bool {
    if std::env::var_os("ELASTOS_TEST_ISOLATED").is_some() {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .arg("--exact")
        .arg(test_name)
        .env("ELASTOS_TEST_ISOLATED", "1")
        .output()
        .expect("isolated test process");
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success() && text.contains("1 passed"),
        "isolated {test_name} failed: {:?}\n{text}",
        output.status
    );
    false
}

#[cfg(all(test, unix))]
pub(crate) struct ReadonlyTemp {
    _root: tempfile::TempDir,
    previous: Option<std::ffi::OsString>,
}

#[cfg(all(test, unix))]
impl ReadonlyTemp {
    pub(crate) fn enter() -> ReadonlyTemp {
        assert!(
            std::env::var_os("ELASTOS_TEST_ISOLATED").is_some(),
            "TMPDIR is process-global; run this case in an isolated child"
        );
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("ro");
        std::fs::create_dir(&dir).unwrap();
        let mut permissions = std::fs::metadata(&dir).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o500);
        std::fs::set_permissions(&dir, permissions).unwrap();
        let previous = std::env::var_os("TMPDIR");
        std::env::set_var("TMPDIR", &dir);
        ReadonlyTemp {
            _root: root,
            previous,
        }
    }
}

#[cfg(all(test, unix))]
struct RuntimePathEnv;

#[cfg(all(test, unix))]
impl RuntimePathEnv {
    fn point_at(path: &std::path::Path) -> RuntimePathEnv {
        assert!(
            std::env::var_os("ELASTOS_TEST_ISOLATED").is_some(),
            "ELASTOS_* is process-global; run this case in an isolated child"
        );
        for key in [
            "ELASTOS_BIN",
            "ELASTOS_RUNTIME_BINARY",
            "ELASTOS_RUNTIME_PATH",
        ] {
            std::env::set_var(key, path);
        }
        RuntimePathEnv
    }
}

#[cfg(all(test, unix))]
impl Drop for RuntimePathEnv {
    fn drop(&mut self) {
        for key in [
            "ELASTOS_BIN",
            "ELASTOS_RUNTIME_BINARY",
            "ELASTOS_RUNTIME_PATH",
        ] {
            std::env::remove_var(key);
        }
    }
}

#[cfg(all(test, unix))]
impl Drop for ReadonlyTemp {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var("TMPDIR", value),
            None => std::env::remove_var("TMPDIR"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn current_platform() -> &'static str {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "linux-amd64",
            ("linux", "aarch64") => "linux-arm64",
            ("macos", "aarch64") => "darwin-arm64",
            (os, arch) => panic!("unsupported test platform {os}-{arch}"),
        }
    }

    fn write_components_manifest(
        data_dir: &Path,
        name: &str,
        checksum: &str,
        runtime: Option<serde_json::Value>,
    ) {
        let mut component = serde_json::json!({
            "install_path": format!("bin/{name}"),
            "platforms": {
                current_platform(): {
                    "checksum": checksum,
                    "install_path": format!("bin/{name}")
                }
            }
        });
        if let Some(runtime) = runtime {
            component["provider_runtime"] = runtime;
        }
        std::fs::write(
            data_dir.join("components.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "external": {
                    name: component
                },
                "capsules": {},
                "profiles": {}
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn native_runtime(provides: &str) -> serde_json::Value {
        serde_json::json!({
            "role": "provider",
            "substrate": "native",
            "runtime_abi": "elastos.provider-stdio/v1",
            "execution": "native-provider",
            "provides": provides
        })
    }
    #[cfg(unix)]
    #[test]
    fn resolve_verified_native_provider_binary_rejects_unstamped_external_binary() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let external_dir = temp.path().join("external-bin");
        std::fs::create_dir_all(&external_dir).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(external_dir.join("did-provider"), b"external-only").unwrap();
        write_components_manifest(
            &data_dir,
            "did-provider",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            Some(native_runtime("elastos://did/*")),
        );

        let result =
            resolve_verified_native_provider_binary_with_data_dir(&data_dir, "did-provider")
                .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn resolve_verified_native_provider_binary_returns_none_when_manifest_is_missing() {
        let temp = tempfile::tempdir().unwrap();

        let result =
            resolve_verified_native_provider_binary_with_data_dir(temp.path(), "did-provider")
                .unwrap();

        assert!(result.is_none());
    }
    #[cfg(unix)]
    #[test]
    fn resolve_verified_native_provider_binary_rejects_missing_runtime_contract() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path();
        let bin_dir = data_dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("did-provider"), b"binary").unwrap();
        write_components_manifest(
            data_dir,
            "did-provider",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            None,
        );

        let error = resolve_verified_native_provider_binary_with_data_dir(data_dir, "did-provider")
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("missing provider runtime metadata"));
    }

    #[test]
    fn resolve_verified_native_provider_binary_rejects_malformed_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path();
        std::fs::write(data_dir.join("components.json"), b"{not-json").unwrap();

        let error = resolve_verified_native_provider_binary_with_data_dir(data_dir, "did-provider")
            .unwrap_err();
        assert!(error.to_string().contains("invalid"));
        assert!(error.to_string().contains("components.json"));
    }
    #[cfg(unix)]
    #[test]
    fn resolve_verified_native_provider_binary_rejects_noncanonical_install_path() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path();
        std::fs::write(
            data_dir.join("components.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "external": {
                    "did-provider": {
                        "install_path": "capsules/did-provider",
                        "provider_runtime": native_runtime("elastos://did/*"),
                        "platforms": {
                            current_platform(): {
                                "checksum": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                                "install_path": "capsules/did-provider"
                            }
                        }
                    }
                },
                "capsules": {},
                "profiles": {}
            }))
            .unwrap(),
        )
        .unwrap();

        let error = resolve_verified_native_provider_binary_with_data_dir(data_dir, "did-provider")
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("native provider install_path must be 'bin/did-provider'"));
    }
    #[cfg(unix)]
    #[test]
    fn resolve_verified_native_provider_binary_rejects_checksum_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path();
        let bin_dir = data_dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("did-provider"), b"binary").unwrap();
        write_components_manifest(
            data_dir,
            "did-provider",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            Some(native_runtime("elastos://did/*")),
        );

        let error = resolve_verified_native_provider_binary_with_data_dir(data_dir, "did-provider")
            .unwrap_err();
        assert!(error.to_string().contains("failed checksum verification"));
    }
    #[cfg(unix)]
    #[test]
    fn resolve_verified_native_provider_binary_accepts_stamped_installed_binary() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path();
        let bin_dir = data_dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let bytes = b"binary";
        let path = bin_dir.join("did-provider");
        std::fs::write(&path, bytes).unwrap();
        let checksum = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
        write_components_manifest(
            data_dir,
            "did-provider",
            &checksum,
            Some(native_runtime("elastos://did/*")),
        );

        let resolved =
            resolve_verified_native_provider_binary_with_data_dir(data_dir, "did-provider")
                .unwrap();
        assert_eq!(resolved.as_deref(), Some(path.as_path()));
    }
    #[cfg(unix)]
    #[test]
    fn subordinate_runtime_accepts_only_verified_provider_from_parent_bin() {
        let temp = tempfile::tempdir().unwrap();
        let parent_data_dir = temp.path().join("parent");
        let child_data_dir = temp.path().join("child");
        let parent_bin_dir = parent_data_dir.join("bin");
        std::fs::create_dir_all(&parent_bin_dir).unwrap();
        std::fs::create_dir_all(&child_data_dir).unwrap();
        let bytes = b"object-provider-binary";
        let path = parent_bin_dir.join("object-provider");
        std::fs::write(&path, bytes).unwrap();
        let checksum = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
        for data_dir in [&parent_data_dir, &child_data_dir] {
            write_components_manifest(
                data_dir,
                "object-provider",
                &checksum,
                Some(native_runtime("elastos://storage/*")),
            );
        }
        let resolved = resolve_verified_native_provider_binary_with_bin_dir(
            &child_data_dir,
            "object-provider",
            Some(&parent_bin_dir),
        )
        .unwrap();
        assert_eq!(resolved.as_deref(), Some(path.as_path()));

        let child_path = child_data_dir.join("bin/object-provider");
        std::fs::create_dir_all(child_path.parent().unwrap()).unwrap();
        std::fs::write(&child_path, bytes).unwrap();
        let empty_parent_bin = temp.path().join("empty-parent/bin");
        std::fs::create_dir_all(&empty_parent_bin).unwrap();
        assert!(resolve_verified_native_provider_binary_with_bin_dir(
            &child_data_dir,
            "object-provider",
            Some(&empty_parent_bin),
        )
        .unwrap()
        .is_none());

        write_components_manifest(
            &child_data_dir,
            "object-provider",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            Some(native_runtime("elastos://storage/*")),
        );
        let error = resolve_verified_native_provider_binary_with_bin_dir(
            &child_data_dir,
            "object-provider",
            Some(&parent_bin_dir),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("selected binary checksum differs"));

        write_components_manifest(&child_data_dir, "object-provider", &checksum, None);
        assert!(resolve_verified_native_provider_binary_with_bin_dir(
            &child_data_dir,
            "object-provider",
            Some(&parent_bin_dir),
        )
        .is_err());

        write_components_manifest(
            &child_data_dir,
            "object-provider",
            &checksum,
            Some(native_runtime("elastos://storage/*")),
        );
        std::fs::write(&path, b"wrong-binary").unwrap();
        assert!(resolve_verified_native_provider_binary_with_bin_dir(
            &child_data_dir,
            "object-provider",
            Some(&parent_bin_dir),
        )
        .is_err());
    }

    /// A Home whose `did-provider` row, binary and manifest all verify.
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let bin_dir = data_dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let bytes = b"did-provider-binary";
        let path = bin_dir.join("did-provider");
        std::fs::write(&path, bytes).unwrap();
        let checksum = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
        write_components_manifest(
            &data_dir,
            "did-provider",
            &checksum,
            Some(native_runtime("elastos://did/*")),
        );
        write_manifest(&data_dir, "did-provider", "did-provider", "elastos://did/*");
        (temp, data_dir, path)
    }

    fn write_manifest(data_dir: &Path, dir_key: &str, name: &str, provides: &str) {
        let text = format!(
            r#"{{"schema":"elastos.capsule/v1","version":"0.2.0","name":"{name}","role":"provider",
"type":"microvm","entrypoint":"rootfs.ext4","provides":"{provides}","authority":{{"reason":"test",
"capabilities":[{{"resource":"{provides}","actions":["read"],"operations":["read"]}}],
"audit_events":["test.read"],"rights":[{{"id":"storage","rules":["(allow file-read* (subpath (param \"STORAGE_ROOT\")))"]}}]}}}}"#
        );
        let dir = data_dir.join("capsules").join(dir_key);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("capsule.json"), text).unwrap();
    }

    fn admit(
        data_dir: &Path,
        signers: &BTreeMap<String, String>,
    ) -> anyhow::Result<Option<AdmittedProvider>> {
        AdmittedProvider::admit_with_bin_dir(data_dir, "did-provider", None, signers)
    }
    #[cfg(unix)]
    /// R1 ADMIT.
    #[test]
    fn admit_returns_the_verified_row_and_the_manifest_authority() {
        let (_temp, data_dir, path) = fixture();
        let admitted = admit(&data_dir, &BTreeMap::new()).unwrap().expect("admits");
        assert_eq!(admitted.key(), "did-provider");
        assert_eq!(admitted.path(), path);
        let expected = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(b"did-provider-binary"))
        );
        assert_eq!(admitted.checksum(), expected);
        assert_eq!(admitted.authority().rights.len(), 1);
        assert_eq!(admitted.authority().rights[0].id, "storage");
    }
    #[cfg(unix)]
    /// R2 ADMIT-MISMATCH.
    #[test]
    fn admit_refuses_a_manifest_that_is_not_the_rows_component() {
        let (_temp, data_dir, _path) = fixture();
        write_manifest(
            &data_dir,
            "did-provider",
            "wallet-provider",
            "elastos://did/*",
        );
        let error = admit(&data_dir, &BTreeMap::new()).err().expect("refused");
        assert!(
            error.to_string().contains("names 'wallet-provider'"),
            "{error}"
        );

        write_manifest(
            &data_dir,
            "did-provider",
            "did-provider",
            "elastos://wallet/meta/status",
        );
        let error = admit(&data_dir, &BTreeMap::new()).err().expect("refused");
        assert!(
            error.to_string().contains("elastos://wallet/meta/status")
                && error.to_string().contains("'elastos://did/*'"),
            "{error}"
        );
    }
    #[cfg(unix)]
    /// R3 ADMIT-NO-MANIFEST: a resolved row without its manifest is a refusal,
    /// not `Ok(None)`.
    #[test]
    fn admit_refuses_a_resolved_row_without_its_manifest() {
        let (_temp, data_dir, _path) = fixture();
        std::fs::remove_file(data_dir.join("capsules/did-provider/capsule.json")).unwrap();
        let error = admit(&data_dir, &BTreeMap::new()).err().expect("refused");
        assert!(error.to_string().contains("capsule.json"), "{error}");
    }
    #[cfg(unix)]
    /// R4 ADMIT-BAD-CHECKSUM stays the resolver's row.
    #[test]
    fn admit_refuses_bytes_that_differ_from_the_row() {
        let (_temp, data_dir, path) = fixture();
        std::fs::write(&path, b"tampered").unwrap();
        let error = admit(&data_dir, &BTreeMap::new()).err().expect("refused");
        assert!(
            error.to_string().contains("failed checksum verification"),
            "{error}"
        );
    }
    #[cfg(unix)]
    /// R5 SIGNER.
    #[test]
    fn admit_reports_the_signer_of_the_rows_record() {
        let (_temp, data_dir, _path) = fixture();
        let mut signers = BTreeMap::new();
        signers.insert("did-provider".to_string(), "did:key:zTest".to_string());
        assert_eq!(
            admit(&data_dir, &signers).unwrap().unwrap().signer_did(),
            Some("did:key:zTest")
        );
        assert_eq!(
            admit(&data_dir, &BTreeMap::new())
                .unwrap()
                .unwrap()
                .signer_did(),
            None
        );
    }

    /// R6 ONLY-MAKER. Needles are built from parts so this file's own text
    /// never matches them; whitespace is removed before matching.
    #[test]
    fn admitted_provider_has_one_maker_in_binaries_and_no_other_route() {
        let squash = |text: &str| text.split_whitespace().collect::<String>();
        let type_open = ["Admitted", "Provider{"].concat();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut sites = BTreeMap::new();
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for path in std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()) {
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let n = squash(&std::fs::read_to_string(&path).unwrap())
                        .matches(&type_open)
                        .count();
                    if n > 0 {
                        sites.insert(path.strip_prefix(root).unwrap().to_owned(), n);
                    }
                }
            }
        }
        // The struct head and the impl head; any other site is a second literal.
        assert_eq!(sites, BTreeMap::from([("src/binaries.rs".into(), 2)]));

        let source = include_str!("binaries.rs").replace("\r\n", "\n");
        let struct_head = ["struct Admitted", "Provider {"].concat();
        let impl_head = ["impl Admitted", "Provider {"].concat();
        assert_eq!(source.matches(&struct_head).count(), 1);
        assert_eq!(source.matches(&impl_head).count(), 1);
        assert!(!source.contains(&["for ", "Admitted", "Provider"].concat()));
        let at = source.find(&struct_head).unwrap();
        // Everything between the previous item's closing brace and the head.
        let header = &source[source[..at].rfind("\n}\n").unwrap() + 3..at];
        let header_code: Vec<_> = header
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("//"))
            .collect();
        assert_eq!(header_code, ["pub"]);
        let body = &source[at..][..source[at..].find("\n}\n").unwrap()];
        assert!(!body.contains("pub"), "{body}");

        let production = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        let code: String = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .map(|line| format!("{line}\n"))
            .collect();
        let type_name = ["Admitted", "Provider"].concat();
        // The two heads; an alias or a free function over the type adds one.
        assert_eq!(code.matches(&type_name).count(), 2);
        let maker_name = ["admit_with", "_bin_dir"].concat();
        // The maker stays private and has one caller, `admit`.
        let maker_line = format!("\n    fn {maker_name}(\n");
        assert_eq!(code.matches(&maker_line).count(), 1);
        assert_eq!(code.matches(&maker_name).count(), 2);
        let admit_at = code.find("fn admit(").unwrap();
        let admit_body = &code[admit_at..][..code[admit_at..].find("\n    }\n").unwrap()];
        assert!(admit_body.contains(&format!("Self::{maker_name}(")));
        // No `mut self`, `&mut self` or `&mut Self`: nothing changes a made value.
        let impl_at = code.find(&impl_head).unwrap();
        let impl_block = &code[impl_at..][..code[impl_at..].find("\n}\n").unwrap()];
        assert!(!impl_block.contains("mut"), "{impl_block}");
        for accessor in ["admit", "key", "path", "authority"] {
            assert!(impl_block.contains(&format!("pub fn {accessor}(")));
        }
        for accessor in ["checksum", "signer_did"] {
            assert!(impl_block.contains(&format!("pub(crate) fn {accessor}(")));
        }

        let self_open = ["Self", "{"].concat();
        let maker = source.find("fn admit_with_bin_dir(").unwrap();
        let end = maker + source[maker..].find("\n    }\n").unwrap();
        assert_eq!(squash(&source[maker..end]).matches(&self_open).count(), 1);
        let outside = squash(&[&source[..maker], &source[end..]].concat());
        assert_eq!(
            outside.matches(&self_open).count(),
            0,
            "a Self literal outside the maker"
        );
    }
    #[cfg(unix)]
    /// R7 VALIDATE: a manifest that `validate()` refuses is not admitted.
    #[test]
    fn admit_refuses_a_manifest_that_does_not_validate() {
        let (_temp, data_dir, _path) = fixture();
        let path = data_dir.join("capsules/did-provider/capsule.json");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"rootfs.ext4\"", "\"../rootfs.ext4\"")).unwrap();
        let error = admit(&data_dir, &BTreeMap::new()).err().expect("refused");
        assert!(error.to_string().contains("path traversal"), "{error}");
    }
    #[cfg(unix)]
    /// R8 SIGNER-READ: a Home whose signed release cannot be read is refused.
    #[test]
    fn admit_refuses_a_home_whose_release_cannot_be_read() {
        let (_temp, data_dir, _path) = fixture();
        std::fs::write(data_dir.join("installation"), b"").unwrap();
        let error = AdmittedProvider::admit(&data_dir, "did-provider")
            .err()
            .expect("refused");
        assert!(
            error.to_string().contains("No trusted source configured"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_home_running_runtime_keeps_the_named_dev_opt_in() {
        if !run_isolated("binaries::tests::source_home_running_runtime_keeps_the_named_dev_opt_in")
        {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let exe = temp.path().join("dev-runtime");
        std::fs::write(&exe, b"source runtime").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let refused = checked_running_runtime(temp.path(), &exe).unwrap_err();
        let message = format!("{refused:#}");
        assert!(
            message.contains("No trusted source configured"),
            "{message}"
        );
        assert!(message.contains("dev_mode = true"), "{message}");
        std::fs::write(temp.path().join("config.toml"), "dev_mode = true\n").unwrap();
        let _readonly = ReadonlyTemp::enter();
        let admitted = checked_running_runtime(temp.path(), &exe).expect("dev admit must not copy");
        drop(_readonly);
        assert!(admitted.signed_checksum().is_err());
        let held = admitted.prepare().unwrap();
        assert_eq!(held.held_content_sha256().len(), 64);
        assert!(held.exec_path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn signed_running_runtime_holds_the_release_bytes() {
        if !run_isolated("binaries::tests::signed_running_runtime_holds_the_release_bytes") {
            return;
        }
        let fixture = crate::installed_release::tests::Fixture::new();
        let binary = fixture.data.join("runtime");
        let digest = hex::encode(sha2::Sha256::digest(b"installed signed runtime"));
        let _readonly = ReadonlyTemp::enter();
        let admitted =
            checked_running_runtime(&fixture.data, &binary).expect("admit must not copy");
        drop(_readonly);
        assert_eq!(
            admitted.signed_checksum().unwrap(),
            format!("sha256:{digest}")
        );
        let held = admitted.prepare().unwrap();
        assert_eq!(held.signed_checksum().unwrap(), format!("sha256:{digest}"));
        assert!(held.exec_path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn same_bytes_at_another_path_are_admitted_without_a_copy() {
        if !run_isolated("binaries::tests::same_bytes_at_another_path_are_admitted_without_a_copy")
        {
            return;
        }
        let fixture = crate::installed_release::tests::Fixture::new();
        let binary = fixture.data.join("runtime");
        let same = fixture.data.join("runtime-copy");
        std::fs::copy(&binary, &same).unwrap();
        std::fs::set_permissions(&same, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _env = RuntimePathEnv::point_at(&binary);
        let _readonly = ReadonlyTemp::enter();
        let admitted = checked_running_runtime(&fixture.data, &same).unwrap();
        drop(_readonly);
        drop(_env);
        std::fs::write(&same, b"tampered caller path").unwrap();
        let held = admitted.prepare().unwrap();
        let digest = hex::encode(sha2::Sha256::digest(b"installed signed runtime"));
        assert_eq!(held.signed_checksum().unwrap(), format!("sha256:{digest}"));
        assert_eq!(held.held_content_sha256(), digest);
    }

    #[cfg(unix)]
    #[test]
    fn different_bytes_are_refused_even_when_environment_names_the_release() {
        if !run_isolated(
            "binaries::tests::different_bytes_are_refused_even_when_environment_names_the_release",
        ) {
            return;
        }
        let fixture = crate::installed_release::tests::Fixture::new();
        let binary = fixture.data.join("runtime");
        let other = fixture.data.join("other-runtime");
        std::fs::write(&other, b"not the signed runtime").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _env = RuntimePathEnv::point_at(&binary);
        let error = checked_running_runtime(&fixture.data, &other).unwrap_err();
        drop(_env);
        assert!(
            error
                .to_string()
                .contains("running binary is not the installed release"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dev_hold_fingerprint_is_the_held_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime");
        std::fs::write(&path, b"held-bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let held = setup::verified_executable::VerifiedExecutable::unchecked(&path).unwrap();
        std::fs::write(&path, b"replaced-path").unwrap();
        let digest = held.held_content_sha256();
        assert_eq!(digest, hex::encode(sha2::Sha256::digest(b"held-bytes")));
    }

    /// Parent admits the test binary, `prepare` makes the macOS private copy,
    /// and the child started from that copy admits its own bytes.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_child_of_private_copy_readmits() {
        if std::env::var_os("ELASTOS_S5A_READMIT").is_some() {
            let data = std::env::var("ELASTOS_S5A_DATA").unwrap();
            let install = std::env::var("ELASTOS_S5A_INSTALL").unwrap();
            let exe = std::env::current_exe().unwrap();
            if exe.as_path() == std::path::Path::new(&install) {
                eprintln!("child current_exe is still the install path");
                std::process::exit(3);
            }
            match checked_running_runtime(std::path::Path::new(&data), &exe) {
                Ok(admitted) => {
                    if admitted.signed_checksum().is_err() {
                        eprintln!("child admission has no signed digest");
                        std::process::exit(4);
                    }
                    std::fs::write(std::env::var("ELASTOS_S5A_MARKER").unwrap(), b"admitted")
                        .unwrap();
                    std::process::exit(0);
                }
                Err(error) => {
                    eprintln!("child readmit refused: {error:#}");
                    std::process::exit(2);
                }
            }
        }
        let exe = std::env::current_exe().unwrap();
        let install = InstallableRuntime::of(&exe);
        let fixture = crate::installed_release::tests::Fixture::bound_to(&install.path);
        let marker = fixture.data.join("child-admitted");
        let admitted = checked_running_runtime(&fixture.data, &exe).unwrap();
        let prepared = admitted.prepare().unwrap();
        let output = std::process::Command::new(prepared.exec_path())
            .arg("--exact")
            .arg("binaries::tests::macos_child_of_private_copy_readmits")
            .env("ELASTOS_S5A_READMIT", "1")
            .env("ELASTOS_S5A_DATA", &fixture.data)
            .env("ELASTOS_S5A_INSTALL", &install.path)
            .env("ELASTOS_S5A_MARKER", &marker)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "status {:?} stdout {} stderr {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&marker).unwrap(), b"admitted");
    }

    /// The parent drops `prepared` while this child is still running. The child
    /// holds the private copy the way `run_serve` does, and the production
    /// supersession watch follows the signed install.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_detached_copy_outlives_prepared_and_yields_when_the_install_changes() {
        const TEST_NAME: &str = "binaries::tests::macos_detached_copy_outlives_prepared_and_yields_when_the_install_changes";
        if std::env::var_os("ELASTOS_S5A_GRANDCHILD").is_some() {
            let data = std::env::var("ELASTOS_S5A_DATA").unwrap();
            let exe = std::env::current_exe().unwrap();
            match checked_running_runtime(std::path::Path::new(&data), &exe) {
                Ok(admitted) => {
                    if admitted.signed_checksum().is_err() {
                        eprintln!("grandchild admission has no signed digest");
                        std::process::exit(4);
                    }
                    std::process::exit(0);
                }
                Err(error) => {
                    eprintln!("grandchild readmit refused: {error:#}");
                    std::process::exit(2);
                }
            }
        }
        if std::env::var_os("ELASTOS_S5A_DETACHED").is_some() {
            macos_detached_serve();
            return;
        }
        let exe = std::env::current_exe().unwrap();
        // `InstallableRuntime::of` can return the running test binary. This test
        // replaces the install, so the signed file is always a separate copy.
        let install_hold = tempfile::tempdir().unwrap();
        let install_path = install_hold.path().join("runtime");
        std::fs::copy(&exe, &install_path).unwrap();
        std::fs::set_permissions(&install_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(
            std::fs::canonicalize(&install_path).unwrap(),
            std::fs::canonicalize(&exe).unwrap(),
            "the signed install must not be the running test binary"
        );
        let fixture = crate::installed_release::tests::Fixture::bound_to(&install_path);
        let ready = fixture.data.join("detached-ready");
        let go = fixture.data.join("detached-go");
        let grand = fixture.data.join("grandchild-admitted");
        let admitted = checked_running_runtime(&fixture.data, &exe).unwrap();
        let mut prepared = admitted.prepare().unwrap();
        let exec_path = prepared.exec_path().to_path_buf();
        assert!(
            exec_path
                .parent()
                .and_then(|dir| dir.file_name())
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("elastos-exec-")),
            "private copy path {}",
            exec_path.display()
        );
        let mut command = std::process::Command::new(&exec_path);
        command
            .arg("--exact")
            .arg(TEST_NAME)
            .env("ELASTOS_S5A_DETACHED", "1")
            .env("ELASTOS_S5A_DATA", &fixture.data)
            .env("ELASTOS_S5A_READY", &ready)
            .env("ELASTOS_S5A_GO", &go)
            .env("ELASTOS_S5A_MARKER", &grand)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().unwrap();
        let _kill = KillProcessGroup(child.id() as i32);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        while !ready.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("detached child exited before ready: {status}");
            }
            assert!(
                std::time::Instant::now() < deadline,
                "detached child did not become ready"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        prepared.persist_private_copy();
        drop(prepared);
        std::thread::sleep(std::time::Duration::from_secs(5));
        assert!(
            child.try_wait().unwrap().is_none(),
            "detached child died after the parent dropped its private copy"
        );
        assert!(
            exec_path.exists(),
            "private copy was removed while the child was running"
        );
        std::fs::write(&go, b"go").unwrap();
        let grand_deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        while !grand.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("detached child exited before its child re-admitted: {status}");
            }
            assert!(
                std::time::Instant::now() < grand_deadline,
                "child of the detached runtime did not re-admit"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(std::fs::read(&grand).unwrap(), b"ok");
        let replacement = install_path.with_extension("next");
        std::fs::write(&replacement, b"a different installed runtime").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&replacement, &install_path).unwrap();
        let exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < exit_deadline,
                "detached child did not exit 75 after the installed binary changed"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        assert_eq!(status.code(), Some(75), "{status}");
        assert!(
            !exec_path.exists(),
            "private copy remained after the stale host exited"
        );
    }

    #[cfg(target_os = "macos")]
    fn macos_detached_serve() {
        let data = std::path::PathBuf::from(std::env::var("ELASTOS_S5A_DATA").unwrap());
        let ready = std::path::PathBuf::from(std::env::var("ELASTOS_S5A_READY").unwrap());
        let go = std::path::PathBuf::from(std::env::var("ELASTOS_S5A_GO").unwrap());
        let grand = std::path::PathBuf::from(std::env::var("ELASTOS_S5A_MARKER").unwrap());
        let held = crate::host_lock::hold_running_exec_copy().unwrap_or_else(|error| {
            eprintln!("adopt failed: {error:#}");
            std::process::exit(2);
        });
        if held.is_none() {
            eprintln!("detached process was not started from a private exec copy");
            std::process::exit(3);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            crate::host_lock::spawn_installed_binary_supersession_watch(&data, "serve");
            std::fs::write(&ready, b"ready").unwrap();
            while !go.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("binaries::tests::macos_detached_copy_outlives_prepared_and_yields_when_the_install_changes")
                .env("ELASTOS_S5A_GRANDCHILD", "1")
                .env("ELASTOS_S5A_DATA", &data)
                .env_remove("ELASTOS_S5A_DETACHED")
                .status()
                .unwrap();
            std::fs::write(
                &grand,
                if status.success() {
                    &b"ok"[..]
                } else {
                    &b"bad"[..]
                },
            )
            .unwrap();
            std::future::pending::<()>().await
        });
    }

    #[cfg(target_os = "macos")]
    struct KillProcessGroup(i32);

    #[cfg(target_os = "macos")]
    impl Drop for KillProcessGroup {
        fn drop(&mut self) {
            unsafe {
                libc::kill(-self.0, libc::SIGKILL);
                libc::waitpid(self.0, std::ptr::null_mut(), 0);
            }
        }
    }
}
