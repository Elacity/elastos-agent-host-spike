use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use elastos_common::{CapsuleManifest, ProviderAuthority};
use elastos_runtime::provider::CheckedExecutable;

use crate::{setup, sources::default_data_dir};

/// Admit the running Runtime binary before this process starts it again.
/// An installed Home admits only its signed release binary and returns those
/// held bytes. A source Home with no release continues only through
/// `verify_installed_component_start`'s `dev_mode = true` opt-in.
pub fn checked_running_runtime(
    data_dir: &Path,
    exe: &Path,
) -> anyhow::Result<setup::verified_executable::VerifiedExecutable> {
    let Some(source) = setup::installed_release_source(data_dir)? else {
        return setup::verify_installed_component_start(data_dir, "elastos", exe);
    };
    let runtime = std::fs::canonicalize(&source.install_path)
        .map_err(|error| anyhow::anyhow!("installed release binary: {error}"))?;
    // The signed descriptor is checked before the path comparison, so a
    // substituted file is refused even when this process is some other binary.
    let (release_bytes, _) =
        crate::installed_release::read_signed_release(data_dir, &runtime, &source, false, true)?;
    let running =
        std::fs::canonicalize(exe).map_err(|error| anyhow::anyhow!("running binary: {error}"))?;
    anyhow::ensure!(
        running == runtime,
        "running binary is not the installed release"
    );
    let release: serde_json::Value = serde_json::from_slice(&release_bytes)?;
    let platform = crate::update::detect_release_platform();
    let sha = release["payload"]["platforms"][platform]["binary"]["sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("signed runtime digest is missing"))?;
    setup::verified_executable::VerifiedExecutable::prepare(&runtime, &format!("sha256:{sha}"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

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
        let temp = tempfile::tempdir().unwrap();
        let exe = std::env::current_exe().unwrap();
        let refused = checked_running_runtime(temp.path(), &exe).unwrap_err();
        assert!(
            refused.to_string().contains("No trusted source configured"),
            "{refused:#}"
        );
        std::fs::write(temp.path().join("config.toml"), "dev_mode = true\n").unwrap();
        let held = checked_running_runtime(temp.path(), &exe).unwrap();
        assert!(
            held.signed_checksum().is_err(),
            "dev_mode start is unchecked"
        );
        assert!(held.exec_path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn signed_running_runtime_holds_the_release_bytes() {
        let fixture = crate::installed_release::tests::Fixture::new();
        let binary = fixture.data.join("runtime");
        let held = checked_running_runtime(&fixture.data, &binary).unwrap();
        let digest = hex::encode(sha2::Sha256::digest(b"installed signed runtime"));
        assert_eq!(held.signed_checksum().unwrap(), format!("sha256:{digest}"));
        assert!(held.exec_path().exists());
    }
}
