//! Operating-system entry for a provider whose rights have passed the grant gate.
//!
//! `start_provider` is that entry. It resolves rights first, then:
//! Linux (x86_64 or aarch64) calls the failure-record launcher;
//! macOS renders the Seatbelt profile and stops, because no `sandbox-exec`
//! spawn exists yet; every other OS refuses before creating a process.
//! The server does not call this. The tests in this module do. The child path
//! between fork and exec stays in `failure_record` and is unchanged here.

// No server caller yet, so the entry is unused outside tests. The rights gate
// is called from here, so rights.rs does not carry this allow.
#![allow(dead_code)]

use super::rights_table::{self, RuntimeProviderId};
use elastos_common::ProviderAuthority;
use std::path::Path;

const UNSUPPORTED_OS: &str = "provider start is refused: this operating system has no confinement, so the provider binary does not start";
const MACOS_NO_SPAWN: &str =
    "provider start on macos is refused: the Seatbelt profile has no spawn path yet";

/// Admit `authority` for `provider`, then hand the process to this OS.
pub(super) fn start_provider(
    provider: RuntimeProviderId,
    authority: &ProviderAuthority,
    executable: &Path,
    storage_root: &Path,
) -> Result<i32, String> {
    let admitted = super::rights::check_rights_against_runtime_templates(
        provider,
        authority,
        rights_table::RIGHTS,
    )?;
    dispatch(provider, &admitted, executable, storage_root)
}

fn require_grant(admitted: &[&rights_table::RightRow]) -> Result<(), String> {
    if admitted.is_empty() {
        return Err("provider start is refused: the Runtime grant has no rights".to_string());
    }
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn dispatch(
    provider: RuntimeProviderId,
    admitted: &[&rights_table::RightRow],
    executable: &Path,
    storage_root: &Path,
) -> Result<i32, String> {
    require_grant(admitted)?;
    // `start` installs this provider's full Runtime plan. The admitted rows
    // are the declaration that passed the grant. Allocation for the gate is
    // finished. `start` forks only after its own buffers exist; this function
    // adds nothing between fork and exec.
    let args: &[&std::ffi::CStr] = &[];
    super::failure_record::start(provider, storage_root, executable, args).map_err(|error| {
        match error {
            super::failure_record::LaunchError::BeforeFork(reason) => reason,
            super::failure_record::LaunchError::ChildFailed { reason, .. } => reason,
        }
    })
}

#[cfg(target_os = "macos")]
fn dispatch(
    provider: RuntimeProviderId,
    admitted: &[&rights_table::RightRow],
    executable: &Path,
    storage_root: &Path,
) -> Result<i32, String> {
    require_grant(admitted)?;
    // The renderer emits this provider's full Seatbelt profile.
    let profile = super::macos_profile::render_macos_profile(provider);
    if !profile.starts_with("(version 1)\n(deny default)\n(deny network*)\n") {
        return Err(
            "provider start on macos is refused: the Seatbelt profile is missing its deny-default head"
                .to_string(),
        );
    }
    let _ = (executable, storage_root);
    Err(MACOS_NO_SPAWN.to_string())
}

#[cfg(any(
    test,
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))
))]
fn refuse_unsupported_os(executable: &Path) -> Result<i32, String> {
    let _ = (executable, "unsupported-os-does-not-spawn");
    Err(UNSUPPORTED_OS.to_string())
}

#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
fn dispatch(
    provider: RuntimeProviderId,
    admitted: &[&rights_table::RightRow],
    executable: &Path,
    storage_root: &Path,
) -> Result<i32, String> {
    require_grant(admitted)?;
    let _ = (provider, storage_root);
    refuse_unsupported_os(executable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn committed_authority(name: &str) -> ProviderAuthority {
        let path = format!(
            "{}/../../../capsules/{name}-provider/capsule.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let json = std::fs::read_to_string(&path).unwrap();
        let manifest: elastos_common::CapsuleManifest = serde_json::from_str(&json).unwrap();
        manifest.authority.unwrap()
    }

    fn marker_program(dir: &Path) -> (PathBuf, PathBuf) {
        let marker = dir.join("ran");
        let program = dir.join("mark.sh");
        std::fs::write(
            &program,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&program).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&program, permissions).unwrap();
        (program, marker)
    }

    #[test]
    fn unsupported_os_refuses_before_the_binary_runs() {
        let dir = tempfile::tempdir().unwrap();
        let (program, marker) = marker_program(dir.path());
        let error = refuse_unsupported_os(&program).unwrap_err();
        assert_eq!(
            error,
            "provider start is refused: this operating system has no confinement, so the provider binary does not start"
        );
        assert!(!marker.exists(), "the provider binary never runs");
    }

    #[test]
    fn widened_rule_is_refused_before_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let (program, marker) = marker_program(dir.path());
        let mut authority = committed_authority("did");
        let template = super::super::rights::approved_right_template("storage").unwrap();
        let storage = authority
            .rights
            .iter_mut()
            .find(|right| right.id == "storage")
            .unwrap();
        storage.rules = vec![
            r#"(allow file-read* file-write* (subpath "/"))"#.to_string(),
            template[1].to_string(),
        ];
        assert_eq!(
            start_provider(RuntimeProviderId::Did, &authority, &program, dir.path()).map(|_| ()),
            Err(
                "provider right \"storage\" rule text differs from the Runtime template"
                    .to_string()
            )
        );
        assert!(!marker.exists(), "the provider binary never runs");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_profile_path_refuses_before_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let (program, marker) = marker_program(dir.path());
        let mut authority = committed_authority("did");
        authority.rights.clear();
        assert_eq!(
            start_provider(RuntimeProviderId::Did, &authority, &program, dir.path()).unwrap_err(),
            "provider start on macos is refused: the Seatbelt profile has no spawn path yet"
        );
        assert!(!marker.exists(), "the provider binary never runs");
    }
}
