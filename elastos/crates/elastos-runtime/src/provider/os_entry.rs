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
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    /// The verified copy sandbox-exec runs. The bridge holds it while the
    /// provider lives, so the checked bytes are the bytes that start.
    #[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
    pub prepared: super::checked_executable::PreparedExecutable,
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
    executable: &super::CheckedExecutable,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    // Did, wallet, and model have no helper allow-list. The lookup returns
    // before it opens a directory. A key that renders a plan is refused.
    refuse_single_root_on_helper_allow_list(provider, checked.path, executable.path())?;
    let admitted = super::rights::check_rights_against_runtime_templates(
        provider,
        authority,
        rights_table::RIGHTS,
    )?;
    dispatch(provider, &admitted, executable, checked, stdio)
}

/// Seatbelt text and Landlock plan for localhost, object, or chain.
///
/// Each provider gets its own file roots. The data directory contains
/// `identity/device.key`, so that directory stays out of the allow-list.
/// `spawn_confined` admits did, wallet, and model. `start_provider` calls
/// this to refuse those ids when they also have an allow-list. The call
/// does not install the plan.
pub(crate) fn render_helper_confinement(
    component_key: &str,
    data_dir: &Path,
    executable: &Path,
    landlock_abi: u32,
) -> Result<super::path_allow::HelperConfinement, String> {
    super::path_allow::render(component_key, data_dir, executable, landlock_abi)
}

fn refuse_single_root_on_helper_allow_list(
    provider: RuntimeProviderId,
    data_dir: &Path,
    executable: &Path,
) -> Result<(), String> {
    let component_key = match provider {
        RuntimeProviderId::Did => "did-provider",
        RuntimeProviderId::Wallet => "wallet-provider",
        RuntimeProviderId::Model => "model-provider",
        RuntimeProviderId::Localhost => "localhost-provider",
        RuntimeProviderId::Object => "object-provider",
        RuntimeProviderId::Chain => "chain-provider",
    };
    let absent = format!(
        "provider start is refused: component key \"{component_key}\" has no path allow-list"
    );
    match render_helper_confinement(component_key, data_dir, executable, 0) {
        Err(error) if error == absent => Ok(()),
        Ok(confinement) => {
            let rules = confinement
                .landlock
                .iter()
                .map(|rule| format!("{} {} {:#x}", rule.name, rule.path.display(), rule.mask))
                .collect::<Vec<_>>()
                .join(", ");
            Err(format!(
                "provider start is refused: a single-root provider has a path allow-list (abi {}, handled {:#x}, seatbelt {} bytes, {rules})",
                confinement.landlock_abi,
                confinement.landlock_handled,
                confinement.seatbelt.len(),
            ))
        }
        Err(error) => Err(error),
    }
}

/// Start localhost, object, or chain under that provider's path allow-list.
///
/// The data directory is not a storage root. `identity/device.key` stays
/// outside the Seatbelt parameters and the Landlock rules.
pub(crate) fn start_path_allow(
    component_key: &str,
    executable: &super::CheckedExecutable,
    data_dir: &Path,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    if super::rights_table::RuntimeProviderId::path_allow(component_key).is_none() {
        return Err(format!(
            "provider start is refused: component key \"{component_key}\" has no path allow-list"
        ));
    }
    start_path_allow_os(component_key, executable, data_dir, stdio)
}

#[cfg(all(
    not(elastos_unsupported_os_check),
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn start_path_allow_os(
    component_key: &str,
    executable: &super::CheckedExecutable,
    data_dir: &Path,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    let provider = super::rights_table::RuntimeProviderId::path_allow(component_key)
        .ok_or_else(|| {
            format!(
                "provider start is refused: component key \"{component_key}\" has no path allow-list"
            )
        })?;
    let abi = super::landlock_plan::kernel_abi()?;
    let (_confinement, plan) =
        super::path_allow::render_with_plan(component_key, data_dir, executable.path(), abi)?;
    let prepared = preexec_installer::prepare_path_allow(provider, plan)?;
    let data = data_dir
        .to_str()
        .ok_or("provider start is refused: the data directory path is not Unicode")?;
    let env = std::ffi::CString::new(format!("ELASTOS_DATA_DIR={data}")).map_err(|_| {
        "provider start is refused: the data directory path contains NUL".to_string()
    })?;
    let pid = failure_record::start_prepared(
        &prepared,
        executable,
        Some(stdio.stdin),
        Some(stdio.stdout),
        Some(&env),
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
fn start_path_allow_os(
    component_key: &str,
    executable: &super::CheckedExecutable,
    data_dir: &Path,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    let confinement = super::path_allow::render(component_key, data_dir, executable.path(), 5)?;
    let prepared = executable.verify_at_spawn()?;
    let binary = std::fs::canonicalize(prepared.exec_path()).map_err(|error| {
        format!("provider start is refused: cannot resolve provider executable: {error}")
    })?;
    let mut defines = Vec::new();
    for rule in &confinement.landlock {
        if matches!(
            rule.name,
            "PROVIDER_EXECUTABLE" | "LANDLOCK_LOADER_PATHS" | "READ_ONLY_FILE"
        ) {
            continue;
        }
        defines.push((rule.name.to_string(), rule.path.clone()));
    }
    for (index, path) in confinement.metadata.iter().enumerate() {
        defines.push((format!("META_{index}"), path.clone()));
    }
    defines.push(("PROVIDER_EXECUTABLE".to_string(), binary.clone()));
    let bound: Vec<(&str, &Path)> = defines
        .iter()
        .map(|(name, path)| (name.as_str(), path.as_path()))
        .collect();
    let mut command = macos_sandbox_command(
        Path::new("/usr/bin/sandbox-exec"),
        &confinement.seatbelt,
        &binary,
        &bound,
        Some(data_dir),
    )?;
    // localhost stats the working directory before it reads init. That directory
    // is the data directory, which has a metadata grant. The parent's directory
    // does not.
    command.current_dir(data_dir);
    macos_launch(command, stdio, prepared)
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
fn start_path_allow_os(
    component_key: &str,
    executable: &super::CheckedExecutable,
    data_dir: &Path,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    let _ = (component_key, executable, data_dir, stdio);
    Err(UNSUPPORTED_OS.to_string())
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
fn dispatch(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    executable: &super::CheckedExecutable,
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
    executable: &super::CheckedExecutable,
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
    // Re-check the signed digest now and start the verified copy, never the
    // caller's pathname.
    let prepared = executable.verify_at_spawn()?;
    macos_start(prepared, checked, stdio, profile)
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn macos_start(
    prepared: super::checked_executable::PreparedExecutable,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
    profile: String,
) -> Result<Launched, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;

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
    // Resolve the storage path from the directory we checked, not from a
    // second lookup of the caller's pathname.
    let mut path = [0i8; 1024];
    if unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } != 0 {
        return Err(format!(
            "provider start is refused: cannot resolve held storage root: {}",
            std::io::Error::last_os_error()
        ));
    }
    let storage = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        unsafe { std::ffi::CStr::from_ptr(path.as_ptr()) }.to_bytes(),
    ));
    let resolved = std::fs::metadata(&storage).map_err(|error| {
        format!("provider start is refused: cannot verify held storage root path: {error}")
    })?;
    if resolved.dev() != checked.dev || resolved.ino() != checked.ino {
        return Err("provider start is refused: held storage root path changed".into());
    }
    let parent = storage
        .parent()
        .ok_or("provider start is refused: storage root has no parent")?;
    let binary = std::fs::canonicalize(prepared.exec_path()).map_err(|error| {
        format!("provider start is refused: cannot resolve provider executable: {error}")
    })?;
    let command = macos_command(
        Path::new("/usr/bin/sandbox-exec"),
        &profile,
        &binary,
        parent,
        &storage,
    )?;
    macos_launch(command, stdio, prepared)
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn macos_launch(
    mut command: std::process::Command,
    stdio: ChildStdio,
    prepared: super::checked_executable::PreparedExecutable,
) -> Result<Launched, String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

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
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return Err(format!(
            "provider start is refused: cannot inspect descriptor limit: {}",
            std::io::Error::last_os_error()
        ));
    }
    let max_fd = macos_fd_sweep_limit(
        unsafe { limit.assume_init() }.rlim_cur,
        macos_maxfilesperproc(),
    )?;
    // The child's stdio is already mapped when pre_exec runs. Mark every
    // other open descriptor close-on-exec before sandbox-exec starts.
    unsafe {
        command.pre_exec(move || {
            for fd in 3..max_fd {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 && libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::null())
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
        prepared,
    })
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn macos_maxfilesperproc() -> Result<libc::rlim_t, String> {
    let mut maxfilesperproc: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&maxfilesperproc);
    // SAFETY: kern.maxfilesperproc is an int and `length` is its size.
    let read = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut maxfilesperproc as *mut libc::c_int).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 {
        return Err(format!(
            "provider start is refused: cannot read kern.maxfilesperproc: {}",
            std::io::Error::last_os_error()
        ));
    }
    if length != std::mem::size_of_val(&maxfilesperproc) || maxfilesperproc <= 0 {
        return Err("provider start is refused: kern.maxfilesperproc has an invalid value".into());
    }
    Ok(maxfilesperproc as libc::rlim_t)
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn macos_fd_sweep_limit(
    soft: libc::rlim_t,
    maxfilesperproc: Result<libc::rlim_t, String>,
) -> Result<i32, String> {
    let maxfilesperproc = maxfilesperproc?;
    if maxfilesperproc == 0 || maxfilesperproc > i32::MAX as libc::rlim_t {
        return Err("provider start is refused: kern.maxfilesperproc has an invalid value".into());
    }
    Ok(soft.min(maxfilesperproc) as i32)
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn macos_command(
    launcher: &Path,
    profile: &str,
    binary: &Path,
    parent: &Path,
    storage: &Path,
) -> Result<std::process::Command, String> {
    macos_sandbox_command(
        launcher,
        profile,
        binary,
        &[
            ("STORAGE_ROOT", storage),
            ("STORAGE_PARENT", parent),
            ("PROVIDER_EXECUTABLE", binary),
        ],
        None,
    )
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn macos_sandbox_command(
    launcher: &Path,
    profile: &str,
    binary: &Path,
    defines: &[(&str, &Path)],
    data_dir: Option<&Path>,
) -> Result<std::process::Command, String> {
    use std::os::unix::ffi::OsStrExt;

    let mut command = std::process::Command::new(launcher);
    command.env_clear();
    if let Some(data_dir) = data_dir {
        command.env("ELASTOS_DATA_DIR", data_dir);
    }
    command.arg("-p").arg(profile);
    for (name, path) in defines {
        command.arg("-D").arg(format!("{name}={}", path.display()));
    }
    command.arg(binary);
    let arg_max = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
    if arg_max <= 0 {
        return Err("provider start is refused: cannot inspect argument limit".into());
    }
    // Include the executable, every NUL-terminated argument, and argv pointers.
    // Keep the complete argv below half of ARG_MAX for exec's own overhead.
    let args: Vec<_> = command.get_args().collect();
    let argv_bytes = launcher.as_os_str().as_bytes().len()
        + 1
        + args
            .iter()
            .map(|arg| arg.as_bytes().len() + 1)
            .sum::<usize>()
        + (args.len() + 2) * std::mem::size_of::<*const libc::c_char>();
    if argv_bytes > (arg_max as usize) / 2 {
        return Err(
            "provider start is refused: sandbox-exec arguments exceed argument limit".into(),
        );
    }
    Ok(command)
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
    executable: &super::CheckedExecutable,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    refuse_unsupported_os(provider, admitted, executable.path(), checked, stdio)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
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

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn macos_fd_sweep_limit_clamps_large_finite_and_unlimited() {
        let maxfilesperproc = 184_320 as libc::rlim_t;
        assert_eq!(
            macos_fd_sweep_limit(2_000_000_000, Ok(maxfilesperproc)),
            Ok(maxfilesperproc as i32)
        );
        assert_eq!(
            macos_fd_sweep_limit(libc::RLIM_INFINITY, Ok(maxfilesperproc)),
            Ok(maxfilesperproc as i32)
        );
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn macos_fd_sweep_limit_keeps_small_soft_limit() {
        assert_eq!(macos_fd_sweep_limit(1024, Ok(184_320)), Ok(1024));
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn macos_fd_sweep_limit_refuses_unreadable_maxfilesperproc() {
        let error = "provider start is refused: cannot read kern.maxfilesperproc: fixture failure";
        assert_eq!(
            macos_fd_sweep_limit(1024, Err(error.to_string())),
            Err(error.to_string())
        );
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn macos_launch_binds_every_profile_parameter() {
        use std::collections::BTreeSet;

        let binary = Path::new("/private/fixture/bin/did-provider");
        let parent = Path::new("/private/fixture/data");
        let storage = Path::new("/private/fixture/data/did");
        let profile = super::super::macos_profile::render_macos_profile(
            RuntimeProviderId::Did,
            &super::super::rights::admit_committed(RuntimeProviderId::Did),
        );
        let command = macos_command(
            Path::new("/usr/bin/sandbox-exec"),
            &profile,
            binary,
            parent,
            storage,
        )
        .unwrap();
        assert!(
            command.get_current_dir().is_none(),
            "inherit the caller's working directory"
        );
        assert!(
            command.get_envs().next().is_none(),
            "the helper needs no environment entries"
        );
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "-p");
        assert_eq!(
            args[1], profile,
            "the profile text is an argument, not a path"
        );
        assert!(!args.iter().any(|arg| arg == "-f"));
        assert_eq!(
            &args[2..],
            [
                "-D",
                "STORAGE_ROOT=/private/fixture/data/did",
                "-D",
                "STORAGE_PARENT=/private/fixture/data",
                "-D",
                "PROVIDER_EXECUTABLE=/private/fixture/bin/did-provider",
                "/private/fixture/bin/did-provider",
            ]
        );
        let named: BTreeSet<_> = profile
            .split("(param \"")
            .skip(1)
            .map(|tail| tail.split_once('"').unwrap().0)
            .collect();
        let bound: BTreeSet<_> = args
            .windows(2)
            .filter(|pair| pair[0] == "-D")
            .map(|pair| pair[1].split_once('=').unwrap().0)
            .collect();
        assert_eq!(
            bound, named,
            "every rendered parameter needs one -D binding"
        );
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn macos_profile_has_no_swappable_file() {
        let binary = Path::new("/private/fixture/bin/did-provider");
        let parent = Path::new("/private/fixture/data");
        let storage = Path::new("/private/fixture/data/did");
        let profile = super::super::macos_profile::render_macos_profile(
            RuntimeProviderId::Did,
            &super::super::rights::admit_committed(RuntimeProviderId::Did),
        );
        let command = macos_command(
            Path::new("/usr/bin/sandbox-exec"),
            &profile,
            binary,
            parent,
            storage,
        )
        .unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], profile.as_str());
        assert!(!args.iter().any(|arg| arg == "-f"));

        let arg_max = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
        assert!(arg_max > 0);
        assert!(profile.len() < (arg_max as usize) / 2);
        assert_eq!(
            macos_command(
                Path::new("/usr/bin/sandbox-exec"),
                &"x".repeat(arg_max as usize),
                binary,
                parent,
                storage,
            )
            .unwrap_err(),
            "provider start is refused: sandbox-exec arguments exceed argument limit"
        );
        let long_storage = format!("/{}", "x".repeat(arg_max as usize / 2));
        assert_eq!(
            macos_command(
                Path::new("/usr/bin/sandbox-exec"),
                &profile,
                binary,
                parent,
                Path::new(&long_storage),
            )
            .unwrap_err(),
            "provider start is refused: sandbox-exec arguments exceed argument limit"
        );
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn macos_helper_does_not_see_parent_environment() {
        let temp = tempfile::tempdir().unwrap();
        let launcher = temp.path().join("launcher.sh");
        std::fs::write(&launcher, b"#!/bin/sh\n/usr/bin/env\n").unwrap();
        let mut permissions = std::fs::metadata(&launcher).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&launcher, permissions).unwrap();
        let marker = "ELASTOS_MACOS_PROVIDER_PARENT_ONLY_1750";
        std::env::set_var(marker, "private-parent-value");
        let output = macos_command(
            &launcher,
            "(version 1)\n(deny default)\n",
            Path::new("/private/fixture/bin/did-provider"),
            Path::new("/private/fixture/data"),
            Path::new("/private/fixture/data/did"),
        )
        .unwrap()
        .output()
        .unwrap();
        std::env::remove_var(marker);
        assert!(output.status.success(), "{output:?}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains(marker));
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
    fn single_root_providers_stay_off_the_helper_allow_list() {
        // These paths must stay unread. A single-root id returns before render
        // opens a directory, including when the path is missing.
        let missing = Path::new("/no/such/elastos-helper-root");
        let binary = Path::new("/no/such/elastos-helper-binary");
        for provider in [
            RuntimeProviderId::Did,
            RuntimeProviderId::Wallet,
            RuntimeProviderId::Model,
        ] {
            refuse_single_root_on_helper_allow_list(provider, missing, binary)
                .unwrap_or_else(|err| panic!("{provider:?} touched the helper allow-list: {err}"));
        }
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
        let call = "refuse_unsupported_os(provider, admitted, executable.path(), checked, stdio)";
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
                &super::super::CheckedExecutable::for_test(&program),
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
                &super::super::CheckedExecutable::for_test(&program),
                checked,
                stdio(),
            )
            .unwrap_err(),
            "provider start is refused: the reopened storage root is not the checked directory"
        );
        assert!(!marker.exists(), "the provider binary never runs");
    }

    #[cfg(all(
        not(elastos_unsupported_os_check),
        any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )
    ))]
    #[test]
    fn localhost_object_and_chain_cannot_open_device_key() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let data = temp.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let data = std::fs::canonicalize(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in elastos_common::localhost::FILE_BACKED_ROOTS {
            let root = data.join(name);
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("own.txt"), b"own").unwrap();
        }
        let chain = data.join("chain-provider");
        std::fs::create_dir(&chain).unwrap();
        std::fs::write(chain.join("own.txt"), b"chain").unwrap();
        let identity = data.join("identity");
        std::fs::create_dir(&identity).unwrap();
        let device_key = identity.join("device.key");
        std::fs::write(&device_key, b"secret").unwrap();
        let cases = [
            (
                "localhost-provider",
                data.join("AppCapsules/own.txt"),
                chain.join("own.txt"),
                data.join("AppCapsules/result.txt"),
            ),
            (
                "object-provider",
                data.join("ElastOS/own.txt"),
                data.join("AppCapsules/own.txt"),
                data.join("ElastOS/result.txt"),
            ),
            (
                "chain-provider",
                chain.join("own.txt"),
                data.join("AppCapsules/own.txt"),
                chain.join("result.txt"),
            ),
        ];
        for (key, own, foreign, result) in cases {
            let source = temp.path().join(format!("{key}.rs"));
            let binary = temp.path().join(key);
            let device_lit = format!("{:?}", device_key.display().to_string());
            let own_lit = format!("{:?}", own.display().to_string());
            let foreign_lit = format!("{:?}", foreign.display().to_string());
            let result_lit = format!("{:?}", result.display().to_string());
            let mut probe = String::from(
                "use std::os::unix::fs::PermissionsExt;\nfn main() {\n    let mut report = String::new();\n    let checks: &[(&str, &str)] = &[\n        (\"device\", ",
            );
            probe.push_str(&device_lit);
            probe.push_str("),\n        (\"own\", ");
            probe.push_str(&own_lit);
            probe.push_str("),\n        (\"foreign\", ");
            probe.push_str(&foreign_lit);
            probe.push_str(
                "),\n    ];\n    for (name, path) in checks {\n        let code = match std::fs::File::open(path) {\n            Ok(_) => \"open\".to_string(),\n            Err(err) => err.raw_os_error().unwrap_or(-1).to_string(),\n        };\n        let stat = match std::fs::symlink_metadata(path) {\n            Ok(_) => \"stat\".to_string(),\n            Err(err) => err.raw_os_error().unwrap_or(-1).to_string(),\n        };\n        report.push_str(name);\n        report.push('=');\n        report.push_str(&code);\n        report.push('\\n');\n        report.push_str(name);\n        report.push_str(\"_stat=\");\n        report.push_str(&stat);\n        report.push('\\n');\n        if *name == \"device\" {\n            let chmod = match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {\n                Ok(_) => \"chmod\".to_string(),\n                Err(err) => err.raw_os_error().unwrap_or(-1).to_string(),\n            };\n            report.push_str(\"device_chmod=\");\n            report.push_str(&chmod);\n            report.push('\\n');\n        }\n    }\n    if std::fs::write(",
            );
            probe.push_str(&result_lit);
            probe.push_str(", report).is_err() {\n        std::process::exit(91);\n    }\n}\n");
            std::fs::write(&source, probe).unwrap();
            let compiled = std::process::Command::new("rustc")
                .arg("--edition=2021")
                .arg("-o")
                .arg(&binary)
                .arg(&source)
                .status()
                .unwrap_or_else(|err| panic!("rustc: {err}"));
            assert!(compiled.success(), "{key} probe did not compile");
            let (pipes, child_in, child_out) = probe_stdio();
            let started = start_path_allow(
                key,
                &super::super::CheckedExecutable::for_test(&binary),
                &data,
                pipes,
            );
            unsafe {
                libc::close(child_in);
                libc::close(child_out);
            }
            let launched = started.unwrap_or_else(|err| panic!("{key} did not start: {err}"));
            let status = reap_probe(launched.pid, &launched.from_child);
            drop(launched);
            let report = std::fs::read_to_string(&result).unwrap_or_else(|err| {
                panic!("{key} wrote no report ({}): {err}", wait_text(status))
            });
            let line = |name: &str| {
                report
                    .lines()
                    .find_map(|line| line.strip_prefix(&format!("{name}=")))
                    .unwrap_or_else(|| panic!("{key} report missing {name}: {report}"))
            };
            assert!(
                matches!(line("device"), "1" | "13"),
                "{key} opened identity/device.key or failed another way: {report} ({})",
                wait_text(status)
            );
            // macOS Seatbelt refuses lstat. Linux Landlock does not gate inode
            // metadata, so stat stays allowed and this assertion records that gap.
            #[cfg(target_os = "macos")]
            assert_eq!(
                line("device_stat"),
                "1",
                "{key} stat of identity/device.key: {report}"
            );
            #[cfg(target_os = "linux")]
            assert_eq!(
                line("device_stat"),
                "stat",
                "{key} Landlock does not gate inode metadata; stat of identity/device.key stays allowed: {report}"
            );
            // chmod/fchmodat are not in the object filter. Seccomp returns
            // EACCES (13). Landlock would not have stopped a granted chmod.
            #[cfg(target_os = "linux")]
            if key == "object-provider" {
                assert_eq!(
                    line("device_chmod"),
                    "13",
                    "{key} chmod of identity/device.key was not refused: {report}"
                );
            }
            assert_eq!(
                line("own"),
                "open",
                "{key} could not open its own root: {report}"
            );
            assert!(
                matches!(line("foreign"), "1" | "13"),
                "{key} opened a path outside its roots: {report}"
            );
        }
    }

    /// The real `chain-provider` binary, started by `start_path_allow`.
    ///
    /// A counted run builds that binary with `--locked --offline` into
    /// `target/provider-fence-tests` and runs it. A failed build, or a Linux
    /// kernel that refuses Landlock ABI 5, panics.
    /// Linux-only companions, not this test: `a_root_swapped_for_a_symlink_between_render_and_install_is_refused_by_the_installer`
    /// and `a_clean_path_allow_plan_installs_and_allows_its_root_but_not_the_device_key`.
    #[cfg(all(
        not(elastos_unsupported_os_check),
        any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )
    ))]
    #[test]
    fn chain_provider_binary_answers_inside_its_fence() {
        use sha2::{Digest, Sha256};
        use std::io::{Read, Write};

        #[cfg(target_os = "linux")]
        if let Err(reason) = super::super::landlock_plan::kernel_abi() {
            panic!("chain-provider real-binary proof did not run: {reason}");
        }
        let bin = chain_provider_binary();
        assert!(bin.is_file(), "chain binary {}", bin.display());
        let binary_bytes = std::fs::read(&bin).unwrap();
        eprintln!("chain binary sha256 {:x}", Sha256::digest(&binary_bytes));
        let arch = if cfg!(target_arch = "x86_64") {
            super::super::seccomp_list::AuditArch::X86_64
        } else {
            super::super::seccomp_list::AuditArch::Aarch64
        };
        let admitted = super::super::rights::admit_runtime_grant(
            super::super::rights_table::RuntimeProviderId::Chain,
        );
        let prog = super::super::seccomp_program::program(
            super::super::rights_table::RuntimeProviderId::Chain,
            &admitted,
            arch,
        );
        let mut words = Vec::with_capacity(prog.len() * 16);
        for instruction in &prog {
            for word in instruction {
                words.extend_from_slice(&word.to_le_bytes());
            }
        }
        eprintln!(
            "chain seccomp program sha256 {:x} ({} instructions)",
            Sha256::digest(&words),
            prog.len()
        );
        match super::super::landlock_plan::kernel_abi() {
            Ok(abi) => eprintln!("landlock abi {abi}"),
            Err(_) => eprintln!("macOS, no Landlock"),
        }

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let data = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        let chain_root = data.join("chain-provider");
        std::fs::create_dir(&chain_root).unwrap();
        std::fs::set_permissions(&chain_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity = data.join("identity");
        std::fs::create_dir(&identity).unwrap();
        let device_key = identity.join("device.key");
        std::fs::write(&device_key, b"device-key-sentinel").unwrap();
        let state = chain_root.join("node-lifecycle-state.json");
        std::os::unix::fs::symlink("../identity/device.key", &state).unwrap();

        fn write_line(fd: i32, line: &str) {
            let mut bytes = line.as_bytes().to_vec();
            bytes.push(b'\n');
            let mut sent = 0;
            while sent < bytes.len() {
                let n =
                    unsafe { libc::write(fd, bytes[sent..].as_ptr().cast(), bytes.len() - sent) };
                assert!(
                    n > 0,
                    "write to chain helper: {}",
                    std::io::Error::last_os_error()
                );
                sent += n as usize;
            }
        }
        fn read_line(fd: i32, pending: &mut Vec<u8>, timeout: std::time::Duration) -> String {
            let start = std::time::Instant::now();
            loop {
                if let Some(at) = pending.iter().position(|byte| *byte == b'\n') {
                    let line: Vec<u8> = pending.drain(..=at).collect();
                    return String::from_utf8(line).unwrap();
                }
                if start.elapsed() > timeout {
                    panic!(
                        "chain helper sent no line: {}",
                        String::from_utf8_lossy(pending)
                    );
                }
                let mut pollfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let left = timeout
                    .saturating_sub(start.elapsed())
                    .as_millis()
                    .min(1_000) as i32;
                let ready = unsafe { libc::poll(&mut pollfd, 1, left.max(1)) };
                assert!(ready >= 0, "poll: {}", std::io::Error::last_os_error());
                if ready == 0 {
                    continue;
                }
                let mut chunk = [0u8; 2048];
                let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
                assert!(n >= 0, "read: {}", std::io::Error::last_os_error());
                if n == 0 {
                    panic!(
                        "chain helper closed stdout: {}",
                        String::from_utf8_lossy(pending)
                    );
                }
                pending.extend_from_slice(&chunk[..n as usize]);
            }
        }
        fn ask(
            launched: &Launched,
            pending: &mut Vec<u8>,
            line: &str,
            timeout: std::time::Duration,
        ) -> serde_json::Value {
            write_line(launched.to_child.as_raw_fd(), line);
            let text = read_line(launched.from_child.as_raw_fd(), pending, timeout);
            serde_json::from_str(text.trim()).unwrap_or_else(|err| panic!("{err} in {text}"))
        }
        fn launch(bin: &std::path::Path, data: &std::path::Path) -> Launched {
            let (pipes, child_in, child_out) = probe_stdio();
            let started = start_path_allow(
                "chain-provider",
                &super::super::CheckedExecutable::for_test(bin),
                data,
                pipes,
            );
            unsafe {
                libc::close(child_in);
                libc::close(child_out);
            }
            started.unwrap_or_else(|err| panic!("chain-provider did not start: {err}"))
        }
        let quick = std::time::Duration::from_secs(20);

        let mut pending = Vec::new();
        let launched = launch(&bin, &data);
        let networks = ask(&launched, &mut pending, "{\"op\":\"networks\"}", quick);
        assert_eq!(networks["status"], "ok", "{networks}");
        assert!(networks["data"]["networks"].is_array(), "{networks}");
        let denied = ask(
            &launched,
            &mut pending,
            "{\"op\":\"node_lifecycle\",\"network\":\"esc-mainnet\",\"action\":\"status\"}",
            quick,
        );
        assert_eq!(
            denied["code"], "node_lifecycle_state_unavailable",
            "{denied}"
        );
        let message = denied["message"].as_str().unwrap_or("");
        assert!(
            message.contains("Permission denied") || message.contains("Operation not permitted"),
            "{denied}"
        );
        assert!(!message.contains("device-key-sentinel"), "{denied}");
        let _ = ask(&launched, &mut pending, "{\"op\":\"shutdown\"}", quick);
        let status = reap_probe(launched.pid, &launched.from_child);
        drop(launched);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "poisoned chain helper {}",
            wait_text(status)
        );
        std::fs::remove_file(&state).unwrap();

        let mut pending = Vec::new();
        let launched = launch(&bin, &data);
        let clean = ask(
            &launched,
            &mut pending,
            "{\"op\":\"node_lifecycle\",\"network\":\"esc-mainnet\",\"action\":\"status\"}",
            quick,
        );
        assert_eq!(clean["status"], "ok", "{clean}");
        let saved =
            std::fs::read_to_string(&state).unwrap_or_else(|err| panic!("state file: {err}"));
        let parsed: serde_json::Value = serde_json::from_str(&saved).unwrap();
        assert_eq!(parsed["schema"], "elastos.chain.node_lifecycle_state/v1");
        assert!(parsed["networks"]["esc-mainnet"].is_object(), "{saved}");
        assert!(std::fs::symlink_metadata(&state).unwrap().is_file());

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x10\"}";
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(body);
        });
        let init = serde_json::json!({
            "op": "init",
            "config": { "networks": [{
                "id": "fixture",
                "display_name": "Fixture",
                "kind": "evm_json_rpc",
                "chain_id": 1,
                "native_symbol": "ETH",
                "provider": "test",
                "mainnet": false,
                "explorer_url": null,
                "rpc_url": format!("http://127.0.0.1:{port}")
            }] }
        });
        let inited = ask(&launched, &mut pending, &init.to_string(), quick);
        assert_eq!(inited["status"], "ok", "{inited}");
        let block = ask(
            &launched,
            &mut pending,
            "{\"op\":\"block_number\",\"network\":\"fixture\"}",
            quick,
        );
        assert_eq!(block["status"], "ok", "{block}");
        assert_eq!(block["data"]["block_number_hex"], "0x10", "{block}");

        let https = serde_json::json!({
            "op": "init",
            "config": { "networks": [{
                "id": "public",
                "display_name": "Public",
                "kind": "evm_json_rpc",
                "chain_id": 1,
                "native_symbol": "ETH",
                "provider": "test",
                "mainnet": false,
                "explorer_url": null,
                "rpc_url": "https://example.com/"
            }] }
        });
        let https_init = ask(&launched, &mut pending, &https.to_string(), quick);
        assert_eq!(https_init["status"], "ok", "{https_init}");
        let https_block = ask(
            &launched,
            &mut pending,
            "{\"op\":\"block_number\",\"network\":\"public\"}",
            std::time::Duration::from_secs(25),
        );
        let code = https_block["code"].as_str().unwrap_or("");
        let https_message = https_block["message"].as_str().unwrap_or("");
        if code == "upstream_unreachable" {
            eprintln!("chain HTTPS leg has no egress: {https_message}");
        } else {
            assert!(
                code == "upstream_invalid_json"
                    || (code == "upstream_http_error" && https_message.contains("405")),
                "https://example.com/ {https_block}"
            );
            eprintln!("chain HTTPS leg: {code} {https_message}");
        }
        let _ = ask(&launched, &mut pending, "{\"op\":\"shutdown\"}", quick);
        let status = reap_probe(launched.pid, &launched.from_child);
        drop(launched);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "clean chain helper {}",
            wait_text(status)
        );
    }

    #[cfg(all(
        not(elastos_unsupported_os_check),
        any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )
    ))]
    fn chain_provider_binary() -> PathBuf {
        let repo =
            std::fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."))
                .expect("repo root");
        let target_dir = repo.join("target/provider-fence-tests");
        let binary = target_dir.join("debug/chain-provider");
        let manifest = repo.join("capsules/chain-provider/Cargo.toml");
        let output = std::process::Command::new(env!("CARGO"))
            .args(["build", "--locked", "--offline", "--manifest-path"])
            .arg(&manifest)
            .args(["--bin", "chain-provider", "--target-dir"])
            .arg(&target_dir)
            .current_dir(&repo)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env("CARGO_BUILD_BUILD_DIR", target_dir.join("build"))
            .env("CARGO_PROFILE_DEV_DEBUG", "line-tables-only")
            .env("CARGO_TERM_COLOR", "never")
            .output()
            .unwrap_or_else(|err| panic!("cargo build chain-provider did not start: {err}"));
        if !output.status.success() || !binary.is_file() {
            panic!(
                "cargo build --locked --offline --bin chain-provider failed ({}); binary {}\n{}",
                output.status,
                binary.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        binary
    }

    fn probe_stdio() -> (ChildStdio, i32, i32) {
        let (input_read, input_write) = pipe_pair();
        let (output_read, output_write) = pipe_pair();
        let stdio = unsafe {
            ChildStdio {
                stdin: input_read,
                stdout: output_write,
                to_child: OwnedFd::from_raw_fd(input_write),
                from_child: OwnedFd::from_raw_fd(output_read),
            }
        };
        (stdio, input_read, output_write)
    }

    fn wait_text(status: i32) -> String {
        if libc::WIFEXITED(status) {
            format!("exit {}", libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            format!("signal {}", libc::WTERMSIG(status))
        } else {
            format!("status {status}")
        }
    }

    fn reap_probe(pid: libc::pid_t, from_child: &OwnedFd) -> i32 {
        let fd = from_child.as_raw_fd();
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let start = std::time::Instant::now();
        let mut status = 0;
        loop {
            let mut buf = [0u8; 256];
            unsafe {
                libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
            }
            let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if got == pid {
                return status;
            }
            if got < 0 {
                panic!("waitpid: {}", std::io::Error::last_os_error());
            }
            if start.elapsed() > std::time::Duration::from_secs(20) {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                }
                panic!("path-allow probe {pid} did not exit");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}
