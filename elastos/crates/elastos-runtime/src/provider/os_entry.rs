//! Operating-system entry for a provider whose rights have passed the grant gate.
//!
//! `start_provider` is that entry. It resolves rights first. Linux (x86_64 or
//! aarch64) installs the admitted rows through the failure-record launcher.
//! The caller passes the device and inode of the directory it opened. Linux
//! opens the path again and refuses when that directory is different, before
//! the plan and the fork. macOS checks the same directory identity, then starts
//! the provider through `sandbox-exec` with the rendered Seatbelt profile.
//! Every other OS refuses before creating a process. The launcher and the
//! Linux installer are private children of this module. The child path between
//! fork and exec stays in `failure_record` and is unchanged here.

use super::rights::AdmittedRights;
use super::rights_table::{self, RuntimeProviderId};
use elastos_common::ProviderAuthority;
use std::os::fd::OwnedFd;
use std::path::Path;

/// A directory the caller opened, with the device and inode of that open.
#[derive(Clone, Copy)]
pub(super) struct CheckedDirectory<'a> {
    pub path: &'a Path,
    pub dev: u64,
    pub ino: u64,
}

/// The descriptors the caller created for the child's fd 0 and fd 1 (the
/// child ends), plus the parent ends that are returned in `Launched`.
///
/// The caller creates both pipes, passes the child ends to the launcher, and
/// drops them after the call. The parent ends travel through this value so the
/// launched handle carries the only remaining copies.
pub(super) struct ChildStdio {
    pub stdin: i32,
    pub stdout: i32,
    pub to_child: OwnedFd,
    pub from_child: OwnedFd,
}

/// A provider process the OS arm started. `pid` is the launcher's, and the two
/// parent ends are the protocol pipes. The successful pid belongs to the
/// caller, which owns its reap.
#[derive(Debug)]
pub(super) struct Launched {
    pub pid: libc::pid_t,
    pub to_child: OwnedFd,
    pub from_child: OwnedFd,
}

#[cfg(all(
    not(elastos_unsupported_os_check),
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "failure_record.rs"]
mod failure_record;

#[cfg(all(
    not(elastos_unsupported_os_check),
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "preexec_installer.rs"]
mod preexec_installer;

#[cfg(any(
    test,
    elastos_unsupported_os_check,
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))
))]
const UNSUPPORTED_OS: &str = "provider start is refused: this operating system has no confinement, so the provider binary does not start";

/// Admit `authority` for `provider`, then hand the process to this OS.
pub(super) fn start_provider(
    provider: RuntimeProviderId,
    authority: &ProviderAuthority,
    executable: &Path,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    let admitted = super::rights::check_rights_against_runtime_templates(
        provider,
        authority,
        rights_table::RIGHTS,
    )?;
    dispatch(provider, &admitted, executable, checked, stdio)
}

fn require_grant(admitted: &AdmittedRights) -> Result<(), String> {
    if admitted.rows().is_empty() {
        return Err("provider start is refused: the Runtime grant has no rights".to_string());
    }
    Ok(())
}

#[cfg(all(
    not(elastos_unsupported_os_check),
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(dead_code)] // The server does not call this entry yet.
fn dispatch(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    executable: &Path,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    require_grant(admitted)?;
    // `start` compares the reopened path with this directory, builds the plan,
    // then forks. Allocation finishes before the fork. This function adds
    // nothing between fork and exec.
    let args: &[&std::ffi::CStr] = &[];
    let pid = failure_record::start(
        provider,
        admitted,
        checked,
        executable,
        args,
        Some(stdio.stdin),
        Some(stdio.stdout),
    )
    .map_err(|error| match error {
        failure_record::LaunchError::BeforeFork(reason) => reason,
        failure_record::LaunchError::ChildFailed { reason, .. } => reason,
    })?;
    Ok(Launched {
        pid,
        to_child: stdio.to_child,
        from_child: stdio.from_child,
    })
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn dispatch(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    executable: &Path,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    require_grant(admitted)?;
    let profile = super::macos_profile::render_macos_profile(provider, admitted);
    if !profile.starts_with("(version 1)\n(deny default)\n(deny network*)\n") {
        return Err(
            "provider start on macos is refused: the Seatbelt profile is missing its deny-default head"
                .to_string(),
        );
    }
    macos_start(executable, checked, stdio, profile)
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn macos_start(
    executable: &Path,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
    profile: String,
) -> Result<Launched, String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::process::{Command, Stdio};

    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(checked.path)
        .map_err(|error| {
            format!("provider start is refused: cannot reopen storage root: {error}")
        })?;
    let identity = directory
        .metadata()
        .map_err(|error| format!("provider start is refused: cannot stat storage root: {error}"))?;
    if identity.dev() != checked.dev || identity.ino() != checked.ino {
        return Err(
            "provider start is refused: the reopened storage root is not the checked directory"
                .into(),
        );
    }
    let storage = std::fs::canonicalize(checked.path).map_err(|error| {
        format!("provider start is refused: cannot resolve storage root: {error}")
    })?;
    let parent = storage
        .parent()
        .ok_or("provider start is refused: storage root has no parent")?;
    let binary = std::fs::canonicalize(executable).map_err(|error| {
        format!("provider start is refused: cannot resolve provider executable: {error}")
    })?;
    let duplicate = |fd| {
        // Command maps this copy to fd 0 or 1. Keep the original copy closed
        // across exec so the provider receives only the protocol descriptors.
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            Err(format!(
                "provider start is refused: cannot duplicate child pipe: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(copy) })
        }
    };
    let input = duplicate(stdio.stdin)?;
    let output = duplicate(stdio.stdout)?;
    let child = Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(profile)
        .arg("-D")
        .arg(format!("PROVIDER_EXECUTABLE={}", binary.display()))
        .arg("-D")
        .arg(format!("STORAGE_PARENT={}", parent.display()))
        .arg("-D")
        .arg(format!("STORAGE_ROOT={}", storage.display()))
        .arg(&binary)
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| {
            format!("provider start is refused: cannot start sandbox-exec: {error}")
        })?;
    let pid = child.id() as libc::pid_t;
    drop(child); // ForkChild owns waitpid from this point.
    Ok(Launched {
        pid,
        to_child: stdio.to_child,
        from_child: stdio.from_child,
    })
}

/// The unsupported-OS arm. Real `dispatch` on an unsupported target calls this
/// and returns it. Tests call this same function. `elastos_unsupported_os_check`
/// compiles that dispatch on a supported host: a FreeBSD target check cannot,
/// because `ring`'s C build has no FreeBSD headers on this machine.
#[cfg(any(
    test,
    elastos_unsupported_os_check,
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))
))]
#[allow(dead_code)] // A supported host's library build does not compile this arm.
fn refuse_unsupported_os(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    executable: &Path,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    require_grant(admitted)?;
    let _ = (
        provider,
        executable,
        checked.path,
        checked.dev,
        checked.ino,
        stdio,
    );
    Err(UNSUPPORTED_OS.to_string())
}

#[cfg(any(
    elastos_unsupported_os_check,
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))
))]
#[allow(dead_code)] // A supported host's library build does not compile this arm.
fn dispatch(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    executable: &Path,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    refuse_unsupported_os(provider, admitted, executable, checked, stdio)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn pipe_pair() -> (i32, i32) {
        let mut fds = [-1; 2];
        #[cfg(target_os = "linux")]
        let opened = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        #[cfg(not(target_os = "linux"))]
        let opened = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(opened, 0);
        (fds[0], fds[1])
    }

    fn checked_directory(path: &Path) -> CheckedDirectory<'_> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).expect("the storage directory opens");
        CheckedDirectory {
            path,
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }

    fn stdio() -> ChildStdio {
        let (input_read, input_write) = pipe_pair();
        let (output_read, output_write) = pipe_pair();
        unsafe {
            ChildStdio {
                stdin: input_read,
                stdout: output_write,
                to_child: OwnedFd::from_raw_fd(input_write),
                from_child: OwnedFd::from_raw_fd(output_read),
            }
        }
    }

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

    fn production_source() -> String {
        let path = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/provider/os_entry.rs"
        ));
        let source = std::fs::read_to_string(path).unwrap();
        source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn unsupported_os_refuses_before_the_binary_runs() {
        let dir = tempfile::tempdir().unwrap();
        let (program, marker) = marker_program(dir.path());
        let admitted = super::super::rights::admit_runtime_grant(RuntimeProviderId::Did);
        let error = refuse_unsupported_os(
            RuntimeProviderId::Did,
            &admitted,
            &program,
            checked_directory(dir.path()),
            stdio(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            "provider start is refused: this operating system has no confinement, so the provider binary does not start"
        );
        assert!(!marker.exists(), "the provider binary never runs");
    }

    #[test]
    fn unsupported_dispatch_only_calls_the_refusal() {
        let production = production_source();
        let call = "refuse_unsupported_os(provider, admitted, executable, checked, stdio)";
        assert_eq!(production.matches(call).count(), 1);
        let at = production.find(call).unwrap();
        let head = production[..at].rfind("fn dispatch").unwrap();
        let open = production[head..].find('{').unwrap() + head;
        let close = production[open..].find('}').unwrap() + open;
        let body = production[open + 1..close]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(body, call);
    }

    #[test]
    fn only_os_entry_names_the_launcher() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut named = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                if text.contains("failure_record::start")
                    || text.contains("failure_record::LaunchError")
                {
                    named.push(path);
                }
            }
        }
        named.sort();
        let entry = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/provider/os_entry.rs");
        assert_eq!(named, vec![entry]);
        let production = production_source();
        assert!(production.contains("mod failure_record;"));
        assert!(production.contains("failure_record::start("));
        let module =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/provider/mod.rs"))
                .unwrap();
        assert!(
            !module.contains("failure_record"),
            "the launcher stays a child of the OS entry"
        );
    }

    #[test]
    fn installer_is_reached_only_through_the_entry() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut named = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                if text.contains("preexec_installer::prepare")
                    || text.contains("preexec_installer::install")
                {
                    named.push(path);
                }
            }
        }
        named.sort();
        let entry = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/provider/os_entry.rs");
        let launcher =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/provider/failure_record.rs");
        assert_eq!(named, vec![launcher, entry]);
        let module =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/provider/mod.rs"))
                .unwrap();
        assert!(
            !module.contains("preexec_installer"),
            "the installer stays a child of the OS entry"
        );
        let production = production_source();
        assert!(production.contains("mod preexec_installer;"));
    }

    #[test]
    fn os_arms_install_the_admitted_rows() {
        let production = production_source();
        assert!(!production.contains("applied_rows"));
        let normalised: String = production.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalised.contains(
            "failure_record::start( provider, admitted, checked, executable, args, Some(stdio.stdin), Some(stdio.stdout), )"
        ));
        assert!(production.contains("render_macos_profile(provider, admitted)"));
        assert!(
            !production.contains("for_provider"),
            "the arms build from the admitted rows"
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/provider");
        let launcher = std::fs::read_to_string(root.join("failure_record.rs")).unwrap();
        let start = launcher.find("pub(super) fn start(").unwrap();
        let launch = launcher.find("fn launch(").unwrap();
        let start_body: String = launcher[start..launch]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert!(start_body.contains("preexec_installer::prepare(provider,admitted,"));
        assert!(!start_body.contains("for_provider"));
        let installer = std::fs::read_to_string(root.join("preexec_installer.rs")).unwrap();
        let prepare = installer.find("pub(super) fn prepare(").unwrap();
        let install = installer.find("pub(super) unsafe fn install(").unwrap();
        let prepare_body: String = installer[prepare..install]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert!(prepare_body.contains("landlock_plan::build(provider,admitted,"));
        assert!(prepare_body.contains("seccomp_program::program(provider,admitted,"));
        assert!(!prepare_body.contains("for_provider"));
    }

    #[test]
    fn narrower_declaration_produces_a_narrower_plan() {
        let mut authority = committed_authority("did");
        authority
            .rights
            .retain(|right| right.id == "bound-executable");
        let admitted = super::super::rights::check_rights_against_runtime_templates(
            RuntimeProviderId::Did,
            &authority,
            rights_table::RIGHTS,
        )
        .unwrap();
        let full_rights = super::super::rights::check_rights_against_runtime_templates(
            RuntimeProviderId::Did,
            &committed_authority("did"),
            rights_table::RIGHTS,
        )
        .unwrap();
        let bindings = super::super::landlock_plan::Bindings {
            storage_root: PathBuf::from("/provider/did"),
            provider_executable: PathBuf::from("/bin/did"),
            storage_dev: 0,
            storage_ino: 0,
        };
        let narrow =
            super::super::landlock_plan::build(RuntimeProviderId::Did, &admitted, &bindings, 5)
                .unwrap();
        let full =
            super::super::landlock_plan::build(RuntimeProviderId::Did, &full_rights, &bindings, 5)
                .unwrap();
        assert_eq!(
            full.rules.len(),
            narrow.rules.len() + 1,
            "a narrower declaration applies one fewer Landlock rule"
        );
        assert!(narrow
            .rules
            .iter()
            .any(|rule| rule.0 == "PROVIDER_EXECUTABLE"));
        assert!(!narrow.rules.iter().any(|rule| rule.0 == "STORAGE_ROOT"));
        assert!(full.rules.iter().any(|rule| rule.0 == "STORAGE_ROOT"));
        let arch = super::super::seccomp_list::AuditArch::Aarch64;
        let narrow_names =
            super::super::seccomp_list::linux_seccomp_list(RuntimeProviderId::Did, &admitted, arch);
        let full_names = super::super::seccomp_list::linux_seccomp_list(
            RuntimeProviderId::Did,
            &full_rights,
            arch,
        );
        assert!(narrow_names.contains(&"write") && narrow_names.contains(&"writev"));
        assert!(!narrow_names.contains(&"pwrite64"));
        assert!(full_names.contains(&"write") && full_names.contains(&"pwrite64"));
        assert!(narrow_names.len() < full_names.len());
        let narrow_profile =
            super::super::macos_profile::render_macos_profile(RuntimeProviderId::Did, &admitted);
        let full_profile =
            super::super::macos_profile::render_macos_profile(RuntimeProviderId::Did, &full_rights);
        assert!(!narrow_profile.contains("STORAGE_ROOT"));
        assert!(full_profile.contains("STORAGE_ROOT"));
        assert!(narrow_profile.len() < full_profile.len());
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
            start_provider(
                RuntimeProviderId::Did,
                &authority,
                &program,
                checked_directory(dir.path()),
                stdio(),
            )
            .map(|_| ()),
            Err(
                "provider right \"storage\" rule text differs from the Runtime template"
                    .to_string()
            )
        );
        assert!(!marker.exists(), "the provider binary never runs");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_changed_storage_root_refuses_before_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let (program, marker) = marker_program(dir.path());
        let mut authority = committed_authority("did");
        authority.rights.clear();
        let mut checked = checked_directory(dir.path());
        checked.ino += 1;
        assert_eq!(
            start_provider(
                RuntimeProviderId::Did,
                &authority,
                &program,
                checked,
                stdio(),
            )
            .unwrap_err(),
            "provider start is refused: the reopened storage root is not the checked directory"
        );
        assert!(!marker.exists(), "the provider binary never runs");
    }
}
