//! Operating-system entry for a provider whose rights have passed the grant gate.
//!
//! `start_provider` is that entry. It resolves rights first. Linux (x86_64 or
//! aarch64) installs the admitted rows through the failure-record launcher.
//! The caller passes the device and inode of the directory it opened. Linux
//! opens the path again and refuses when that directory is different, before
//! the plan and the fork. macOS checks the same directory identity, then starts
//! the provider through `sandbox-exec` with the rendered Seatbelt profile.
//! Unix-like systems other than Linux and macOS refuse before creating a
//! process. Windows fences are P2-11, parked, and are not this refusal. The
//! launcher and the Linux installer are private children of this module. The
//! child path between fork and exec stays in `failure_record` and is unchanged
//! here.

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
    /// Optional libraries the plan left out. The bridge names them when the
    /// helper exits before it answers.
    pub omitted_libraries: Vec<String>,
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
    let admitted = super::rights::check_rights_against_runtime_templates(
        provider,
        authority,
        rights_table::RIGHTS,
    )?;
    dispatch(provider, &admitted, executable, checked, stdio)
}

/// The signed-authority gate for localhost, object, and chain. Both OS arms
/// start from this result. Linux does not admit a second grant.
pub(crate) fn admit_path_allow(
    component_key: &str,
    authority: &ProviderAuthority,
) -> Result<(RuntimeProviderId, AdmittedRights), String> {
    let provider = RuntimeProviderId::path_allow(component_key).ok_or_else(|| {
        format!(
            "provider start is refused: component key \"{component_key}\" has no path allow-list"
        )
    })?;
    let admitted = super::rights::check_rights_against_runtime_templates(
        provider,
        authority,
        rights_table::RIGHTS,
    )?;
    require_grant(&admitted)?;
    Ok((provider, admitted))
}

/// Start localhost, object, or chain under that provider's path allow-list.
///
/// The data directory is not a storage root. `identity/device.key` stays
/// outside the Seatbelt parameters and the Landlock rules. Admission is the
/// same gate `start_provider` uses, and it runs before either OS arm.
pub(crate) fn start_path_allow(
    component_key: &str,
    authority: &ProviderAuthority,
    executable: &super::CheckedExecutable,
    data_dir: &Path,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    let (provider, admitted) = admit_path_allow(component_key, authority)?;
    start_path_allow_os(provider, &admitted, executable, data_dir, stdio)
}

fn start_path_allow_os(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    executable: &super::CheckedExecutable,
    data_dir: &Path,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    #[cfg(all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let verified = executable.verify_at_spawn()?;
        let abi = super::landlock_plan::kernel_abi()?;
        let (_confinement, plan) =
            super::landlock_plan::with_interpreter_fd(verified.fd(), || {
                super::path_allow::render_with_plan(
                    provider,
                    admitted,
                    data_dir,
                    executable.path(),
                    abi,
                )
            })?;
        let omitted_libraries = plan.omitted_libraries.clone();
        let _ = super::landlock_plan::take_omitted_libraries();
        let prepared = preexec_installer::prepare_path_allow(provider, admitted, plan)?;
        let data = data_dir
            .to_str()
            .ok_or("provider start is refused: the data directory path is not Unicode")?;
        let env = std::ffi::CString::new(format!("ELASTOS_DATA_DIR={data}")).map_err(|_| {
            "provider start is refused: the data directory path contains NUL".to_string()
        })?;
        let pid = failure_record::with_launch_fd(verified.fd(), || {
            failure_record::start_prepared(
                &prepared,
                executable,
                Some(stdio.stdin),
                Some(stdio.stdout),
                Some(&env),
            )
        })
        .map_err(|error| match error {
            failure_record::LaunchError::BeforeFork(reason) => reason,
            failure_record::LaunchError::ChildFailed { reason, .. } => reason,
        })?;
        Ok(Launched {
            pid,
            to_child: stdio.to_child,
            from_child: stdio.from_child,
            omitted_libraries,
        })
    }
    #[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
    {
        let (confinement, plan) = super::path_allow::render_with_plan(
            provider,
            admitted,
            data_dir,
            executable.path(),
            5,
        )?;
        launch_macos_path_allow(&confinement, &plan, executable, data_dir, stdio)
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
    {
        let _ = (provider, admitted, executable, data_dir);
        let _ = (stdio.stdin, stdio.stdout, stdio.to_child, stdio.from_child);
        Err(UNSUPPORTED_OS.to_string())
    }
}

/// Re-open every allow-list root and refuse when its device or inode changed.
///
/// A root swapped before this re-check starts nothing. The check opens the
/// path, compares the device and inode recorded at render, and drops the
/// descriptor. `sandbox-exec` then resolves each rule by name. A process of
/// the same user can still replace a root after this check and before the
/// child uses it. A symlink at that path does not grant its target. A real
/// directory swapped onto the path is readable, including a file moved into
/// it. `identity/device.key` is not under any allowed root, so that path
/// stays unread. The three helpers do not compare the device and
/// inode again after the profile is on. sandbox-exec resolved the rules by
/// name, so a same-user swap after that is the helper's own read.
///
/// `plan.root_dev` lines up with the storage roots, which are the first rules.
/// The executable, loader, and resolver paths are not roots. Metadata literals
/// and `current_dir` are not roots either; the launch comment says why a swap
/// of those paths does not widen the profile.
#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn confirm_allow_list_roots(plan: &super::landlock_plan::Plan) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    for (index, rule) in plan.rules.iter().enumerate().take(plan.root_dev.len()) {
        let path = CString::new(rule.1.as_os_str().as_bytes())
            .map_err(|_| format!("provider start is refused: {} contains NUL", rule.0))?;
        super::root_pin::open_pinned_directory(&path, super::root_pin::DIRECTORY_OPEN_FLAGS, plan.root_dev[index], plan.root_ino[index])
            .map_err(|errno| format!("provider start is refused: {} changed between the allow-list check and sandbox-exec: errno {errno}", rule.0))?;
    }
    Ok(())
}

/// Build the Seatbelt command and start it. The root check is the last step
/// before `sandbox-exec`. A root swapped before that check starts nothing.
/// After it, `sandbox-exec` resolves paths by name.
#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn launch_macos_path_allow(
    confinement: &super::path_allow::HelperConfinement,
    plan: &super::landlock_plan::Plan,
    executable: &super::CheckedExecutable,
    data_dir: &Path,
    stdio: ChildStdio,
) -> Result<Launched, String> {
    let prepared = executable.verify_at_spawn()?;
    let binary = std::fs::canonicalize(prepared.exec_path()).map_err(|error| {
        format!("provider start is refused: cannot resolve provider executable: {error}")
    })?;
    let mut defines: Vec<(String, std::path::PathBuf)> = confinement
        .landlock
        .iter()
        .filter(|rule| {
            !matches!(
                rule.0,
                "PROVIDER_EXECUTABLE" | "LANDLOCK_LOADER_PATHS" | "READ_ONLY_FILE"
            )
        })
        .map(|rule| (rule.0.to_string(), rule.1.clone()))
        .collect();
    defines.extend(
        confinement
            .metadata
            .iter()
            .enumerate()
            .map(|(index, path)| (format!("META_{index}"), path.clone())),
    );
    defines.push(("PROVIDER_EXECUTABLE".to_string(), binary.clone()));
    if confinement.seatbelt.contains("(param \"ELASTOS_WALLET\")") {
        // macOS only. Linux Landlock cannot exclude this child of ElastOS.
        // The directory has to exist or sandbox-exec aborts on the subpath.
        defines.push((
            "ELASTOS_WALLET".to_string(),
            super::path_allow::ensure_localhost_wallet_dir(data_dir)?,
        ));
    }
    let bound: Vec<(&str, &Path)> = defines
        .iter()
        .map(|(name, path)| (name.as_str(), path.as_path()))
        .collect();
    let omitted_libraries = plan.omitted_libraries.clone();
    confirm_allow_list_roots(plan)?;
    let mut command = macos_sandbox_command(
        Path::new("/usr/bin/sandbox-exec"),
        &confinement.seatbelt,
        &binary,
        &bound,
        Some(data_dir),
    )?;
    // localhost stats the working directory before it reads init. That directory
    // is the data directory. Localhost and object have a `file-read-metadata`
    // literal for it, not a subpath and not a read of `identity/device.key`.
    // Chain has no metadata literal. `current_dir` adds no Seatbelt rule, and
    // this launch does not re-stat the directory: a same-user swap of it is
    // the root gap above, not a second grant.
    command.current_dir(data_dir);
    macos_launch(command, stdio, prepared, omitted_libraries)
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
        omitted_libraries: super::landlock_plan::take_omitted_libraries(),
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
    macos_launch(command, stdio, prepared, Vec::new())
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn macos_launch(
    mut command: std::process::Command,
    stdio: ChildStdio,
    prepared: super::checked_executable::PreparedExecutable,
    omitted_libraries: Vec<String>,
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
        omitted_libraries,
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

/// Unix-like systems other than Linux and macOS. This arm refuses before a
/// process exists. Real `dispatch` on one of those systems calls this and
/// returns it. Tests call this same function. `elastos_unsupported_os_check`
/// compiles that dispatch on a supported host: a FreeBSD target check cannot,
/// because `ring`'s C build has no FreeBSD headers on this machine. Windows
/// is not this arm. Windows fences are P2-11, parked.
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
    use std::os::fd::AsRawFd;
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
    fn full_grant() -> ProviderAuthority {
        serde_json::from_value(serde_json::json!({
            "reason": "runtime grant",
            "capabilities": [],
            "audit_events": [],
            "rights": []
        }))
        .expect("full grant authority")
    }

    #[test]
    fn single_root_providers_stay_off_the_helper_allow_list() {
        for key in ["did-provider", "wallet-provider", "model-provider"] {
            assert!(
                RuntimeProviderId::path_allow(key).is_none(),
                "{key} has no path allow-list"
            );
            assert!(RuntimeProviderId::from_component_key(key).is_some());
        }
        for key in ["localhost-provider", "object-provider", "chain-provider"] {
            assert!(RuntimeProviderId::from_component_key(key).is_none());
            assert!(RuntimeProviderId::path_allow(key).is_some());
        }
        let production = production_source();
        let start = production
            .split_once("pub(super) fn start_provider(")
            .expect("start_provider")
            .1
            .split_once("pub(crate) fn admit_path_allow(")
            .expect("admit_path_allow")
            .0;
        assert!(!start.contains("render_with_plan"));
        assert!(start.contains("check_rights_against_runtime_templates"));
    }

    #[test]
    fn signed_authority_is_refused_before_either_operating_system_starts() {
        let authority: ProviderAuthority = serde_json::from_value(serde_json::json!({
            "reason": "runtime grant",
            "capabilities": [],
            "audit_events": [],
            "rights": [{
                "id": "storage",
                "rules": ["(allow file-read* file-write* (subpath \"/\"))"]
            }]
        }))
        .expect("bad storage right");
        let missing = Path::new("/no/such/elastos-helper-root");
        let error = start_path_allow(
            "localhost-provider",
            &authority,
            &super::super::CheckedExecutable::for_test(missing),
            missing,
            stdio(),
        )
        .expect_err("a signed right that is not the template is refused");
        assert!(
            error
                .contains("provider right \"storage\" rule text differs from the Runtime template"),
            "{error}"
        );
        assert!(!error.contains("no confinement"));
        assert!(!error.contains("Landlock"));
        assert!(!error.contains("sandbox-exec"));
        let production = production_source();
        assert_eq!(
            production
                .matches("check_rights_against_runtime_templates")
                .count(),
            2,
            "start_provider and admit_path_allow are the only gates"
        );
        let installer = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/provider/preexec_installer.rs"
        ))
        .unwrap();
        let installer = installer.split("#[cfg(test)]").next().unwrap();
        assert!(
            !installer.contains("runtime_grant"),
            "Linux has no second admission door"
        );
    }

    #[test]
    fn an_edited_embedded_helper_manifest_fails_the_template_gate() {
        let manifests = [
            (
                "localhost-provider",
                include_str!("../../../../capsules/localhost-provider/capsule.json"),
            ),
            (
                "object-provider",
                include_str!("../../../../../capsules/object-provider/capsule.json"),
            ),
            (
                "chain-provider",
                include_str!("../../../../../capsules/chain-provider/capsule.json"),
            ),
        ];
        for (key, raw) in manifests {
            let manifest: elastos_common::CapsuleManifest =
                serde_json::from_str(raw).unwrap_or_else(|err| panic!("{key}: {err}"));
            let authority = manifest.authority.expect("authority");
            assert!(
                authority.rights.is_empty(),
                "{key} product manifest declares rights"
            );
            admit_path_allow(key, &authority)
                .unwrap_or_else(|err| panic!("{key} embedded manifest refused: {err}"));
            let mut value = serde_json::to_value(&authority).unwrap();
            value["rights"] = serde_json::json!([{
                "id": "storage",
                "rules": ["(allow file-read* file-write* (subpath \"/\"))"]
            }]);
            let edited: ProviderAuthority = serde_json::from_value(value).unwrap();
            let error = match admit_path_allow(key, &edited) {
                Ok(_) => panic!("an edited embedded manifest was admitted"),
                Err(error) => error,
            };
            assert!(
                error.contains(
                    "provider right \"storage\" rule text differs from the Runtime template"
                ),
                "{key}: {error}"
            );
        }
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
    fn a_signed_right_narrows_the_helper_file_and_exec_grant() {
        fn authority_with(id: &str) -> ProviderAuthority {
            let row = rights_table::RIGHTS
                .iter()
                .find(|row| row.id == id)
                .unwrap_or_else(|| panic!("missing {id}"));
            serde_json::from_value(serde_json::json!({
                "reason": "runtime grant",
                "capabilities": [],
                "audit_events": [],
                "rights": [{ "id": id, "rules": row.rules }]
            }))
            .expect("signed right")
        }
        let executable = Path::new("/opt/elastos/localhost-provider");
        let storage = super::super::rights::check_rights_against_runtime_templates(
            RuntimeProviderId::Localhost,
            &authority_with("storage"),
            rights_table::RIGHTS,
        )
        .unwrap();
        let exec = super::super::rights::check_rights_against_runtime_templates(
            RuntimeProviderId::Localhost,
            &authority_with("bound-executable"),
            rights_table::RIGHTS,
        )
        .unwrap();
        let held = tempfile::tempdir().unwrap();
        for name in elastos_common::localhost::FILE_BACKED_ROOTS {
            std::fs::create_dir(held.path().join(name)).unwrap();
        }
        let (storage_only, storage_plan) = super::super::path_allow::render_with_plan(
            RuntimeProviderId::Localhost,
            &storage,
            held.path(),
            executable,
            5,
        )
        .unwrap();
        assert!(storage_only.seatbelt.contains("subpath"));
        assert!(!storage_only.seatbelt.contains("process-exec"));
        assert!(!storage_plan.root_dev.is_empty());
        assert!(!storage_plan
            .rules
            .iter()
            .any(|rule| rule.0 == "PROVIDER_EXECUTABLE"));
        let (exec_only, exec_plan) = super::super::path_allow::render_with_plan(
            RuntimeProviderId::Localhost,
            &exec,
            Path::new("/data"),
            executable,
            5,
        )
        .unwrap();
        assert!(!exec_only.seatbelt.contains("subpath"));
        assert!(exec_only.seatbelt.contains("process-exec"));
        assert!(exec_plan.root_dev.is_empty());
        assert!(exec_plan
            .rules
            .iter()
            .any(|rule| rule.0 == "PROVIDER_EXECUTABLE"));
        let names = super::super::seccomp_list::linux_seccomp_list(
            RuntimeProviderId::Localhost,
            &storage,
            super::super::seccomp_list::AuditArch::X86_64,
        );
        assert!(names.contains(&"mkdir"));
        assert!(!names.contains(&"execve"));
        let names = super::super::seccomp_list::linux_seccomp_list(
            RuntimeProviderId::Localhost,
            &exec,
            super::super::seccomp_list::AuditArch::X86_64,
        );
        assert!(names.contains(&"execve"));
        assert!(!names.contains(&"mkdir"));
    }

    #[test]
    fn chain_https_leg_says_not_proven_when_there_is_no_egress() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/provider/os_entry.rs"
        ))
        .unwrap();
        let needle = ["if code == \"", "upstream_unreachable\""].concat();
        let at = source.find(&needle).expect("https branch");
        let arm = source[at..].split("} else {").next().unwrap();
        assert!(arm.contains("not proven"), "{arm}");
        assert!(!arm.contains("assert"), "{arm}");
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

    /// `dispatch` says allocation finishes before the fork. The child runs the
    /// launcher's `pid == 0` arm, its record writers, and the installer's
    /// `sequence`, `close_except` and `install`. None of them names a call
    /// that allocates on the heap.
    #[test]
    fn the_child_between_fork_and_exec_does_not_allocate() {
        assert!(production_source().contains("Allocation finishes before the fork."));
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/provider");
        let installer = std::fs::read_to_string(root.join("preexec_installer.rs")).unwrap();
        let launcher = std::fs::read_to_string(root.join("failure_record.rs")).unwrap();
        let between = |text: &str, from: &str, to: &str| -> String {
            let start = text
                .find(from)
                .unwrap_or_else(|| panic!("{from} is missing"));
            let end = start
                + text[start..]
                    .find(to)
                    .unwrap_or_else(|| panic!("{to} is missing"));
            text[start..end].to_string()
        };
        let child = [
            between(
                &installer,
                "pub(super) fn record(&self)",
                "pub(super) fn from_record(",
            ),
            between(&installer, "fn sequence(", "#[repr(C)]"),
            between(
                &installer,
                "fn close_except(",
                "pub(super) fn prepare_path_allow(",
            ),
            between(&launcher, "if pid == 0 {", "drop(stderr_null);"),
            between(&launcher, "fn child_test_hook(hook", "fn decode("),
        ];
        let allocating = [
            "vec!",
            "Vec",
            "Box",
            "String",
            "format!",
            "to_string",
            "to_vec",
            "to_owned",
            ".push(",
            ".collect",
            "CString",
            ".sort",
            ".dedup",
            ".clone()",
            "Arc",
            "Rc::",
        ];
        for body in &child {
            for call in allocating {
                assert!(
                    !body.contains(call),
                    "the child between fork and exec calls {call}:\n{body}"
                );
            }
        }
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
        assert!(prepare_body.contains("assemble(provider,admitted,"));
        assert!(!prepare_body.contains("for_provider"));
        // `assemble` is the production installer. A `#[cfg(test)]` helper now
        // sits above it, so the prefix before the first test attribute is no
        // longer the whole production function. The call still has to pass
        // the admitted rows.
        let assemble = installer.find("fn assemble(").expect("assemble");
        let assemble_end = installer[assemble..]
            .find("pub(super) fn prepare(")
            .expect("prepare follows assemble")
            + assemble;
        let assemble_body: String = installer[assemble..assemble_end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert!(
            assemble_body.contains("seccomp_program::program(provider,admitted,"),
            "assemble installs the admitted filter"
        );
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
        // The renderer is absent when the unsupported-OS check is on.
        #[cfg(not(elastos_unsupported_os_check))]
        {
            let narrow_profile = super::super::macos_profile::render_macos_profile(
                RuntimeProviderId::Did,
                &admitted,
            );
            let full_profile = super::super::macos_profile::render_macos_profile(
                RuntimeProviderId::Did,
                &full_rights,
            );
            assert!(!narrow_profile.contains("STORAGE_ROOT"));
            assert!(full_profile.contains("STORAGE_ROOT"));
            assert!(narrow_profile.len() < full_profile.len());
        }
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
        // Object's own root is ElastOS/System, not ElastOS. The file directly
        // under ElastOS is outside that grant.
        let system = data.join("ElastOS/System");
        std::fs::create_dir(&system).unwrap();
        std::fs::write(system.join("own.txt"), b"own").unwrap();
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
                data.join("ElastOS/System/own.txt"),
                data.join("ElastOS/own.txt"),
                data.join("Users/result.txt"),
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
            let denied = if key == "object-provider" {
                data.join("ElastOS/System/denied.txt")
            } else {
                result.with_file_name("denied.txt")
            };
            let denied_lit = format!("{:?}", denied.display().to_string());
            let mut probe = String::from(
                "use std::os::unix::fs::PermissionsExt;\nfn main() {\n    let mut report = String::new();\n    let checks: &[(&str, &str)] = &[\n        (\"device\", ",
            );
            probe.push_str(&device_lit);
            probe.push_str("),\n        (\"own\", ");
            probe.push_str(&own_lit);
            probe.push_str("),\n        (\"foreign\", ");
            probe.push_str(&foreign_lit);
            probe.push_str(
                "),\n    ];\n    for (name, path) in checks {\n        let code = match std::fs::File::open(path) {\n            Ok(_) => \"open\".to_string(),\n            Err(err) => err.raw_os_error().unwrap_or(-1).to_string(),\n        };\n        let stat = match std::fs::symlink_metadata(path) {\n            Ok(_) => \"stat\".to_string(),\n            Err(err) => err.raw_os_error().unwrap_or(-1).to_string(),\n        };\n        report.push_str(name);\n        report.push('=');\n        report.push_str(&code);\n        report.push('\\n');\n        report.push_str(name);\n        report.push_str(\"_stat=\");\n        report.push_str(&stat);\n        report.push('\\n');\n        if *name == \"device\" {\n            let chmod = match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {\n                Ok(_) => \"chmod\".to_string(),\n                Err(err) => err.raw_os_error().unwrap_or(-1).to_string(),\n            };\n            report.push_str(\"device_chmod=\");\n            report.push_str(&chmod);\n            report.push('\\n');\n        }\n    }\n    let denied_code = match std::fs::write(",
            );
            probe.push_str(&denied_lit);
            probe.push_str(
                ", b\"x\") {\n        Ok(_) => \"ok\".to_string(),\n        Err(err) => err.raw_os_error().unwrap_or(-1).to_string(),\n    };\n    report.push_str(\"denied=\");\n    report.push_str(&denied_code);\n    report.push('\\n');\n    if std::fs::write(",
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
                &full_grant(),
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
            if key == "object-provider" {
                assert!(
                    matches!(line("denied"), "1" | "13"),
                    "{key} wrote under ElastOS/System: {report}"
                );
                assert!(
                    !data.join("ElastOS/System/denied.txt").exists(),
                    "the refused write left a file under ElastOS/System"
                );
            }
        }
    }

    /// The real `chain-provider` binary, started by `start_path_allow`.
    ///
    /// A counted run uses the chain binary `just prepare-providers` built into
    /// `target/provider-fence-tests`. A missing binary, or a Linux kernel that
    /// refuses a kernel below Landlock ABI 3, panics.
    /// Linux-only companions, not this test: `a_root_swapped_for_a_symlink_between_render_and_install_is_refused_by_the_installer`,
    /// `a_different_directory_swapped_in_at_the_same_name_is_refused_with_estale`,
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
                &full_grant(),
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
            eprintln!("chain HTTPS leg is not proven: no egress ({https_message})");
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
        let binary = repo.join("target/provider-fence-tests/debug/chain-provider");
        if !binary.is_file() {
            panic!(
                "chain-provider is not at {}. Run `just prepare-providers` before these tests. That command builds the helper binaries; the tests do not download crates.",
                binary.display()
            );
        }
        binary
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
    fn wait_text(status: i32) -> String {
        if libc::WIFEXITED(status) {
            format!("exit {}", libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            format!("signal {}", libc::WTERMSIG(status))
        } else {
            format!("status {status}")
        }
    }

    /// A root swapped after render and before the re-check is refused.
    /// The swap is in place when `launch_macos_path_allow` calls
    /// `confirm_allow_list_roots`. Removing that call makes this start a
    /// process. A swap after the re-check is the gap the Seatbelt test shows:
    /// `sandbox-exec` resolves the path by name.
    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn a_root_swapped_between_render_and_sandbox_exec_is_refused_and_starts_nothing() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let data = std::fs::canonicalize(temp.path()).unwrap();
        let root = data.join("chain-provider");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = root.join("started");
        let source = temp.path().join("probe.rs");
        std::fs::write(
            &source,
            r#"use std::io::{BufRead, Write};
fn main() {
    let _ = std::fs::write("chain-provider/started", b"started");
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        if line.is_err() { break; }
        if writeln!(out, "{{\"status\":\"ok\"}}").is_err() { break; }
        let _ = out.flush();
    }
}
"#,
        )
        .unwrap();
        let binary = temp.path().join("probe");
        let built = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "probe build failed: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        let admitted = super::super::rights::admit_runtime_grant(
            super::super::rights_table::RuntimeProviderId::Chain,
        );
        let (confinement, plan) = super::super::path_allow::render_with_plan(
            super::super::rights_table::RuntimeProviderId::Chain,
            &admitted,
            &data,
            &binary,
            5,
        )
        .unwrap_or_else(|err| panic!("render before the swap: {err}"));
        let parked = data.join("parked-root");
        std::fs::rename(&root, &parked).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (stdio, child_in, child_out) = probe_stdio();
        let started = super::launch_macos_path_allow(
            &confinement,
            &plan,
            &super::super::CheckedExecutable::for_test(&binary),
            &data,
            stdio,
        );
        unsafe {
            libc::close(child_in);
            libc::close(child_out);
        }
        match started {
            Err(error) => {
                assert!(error.contains("chain-provider"), "{error}");
                assert!(error.contains("changed"), "{error}");
                assert!(
                    !marker.exists(),
                    "a refused start wrote {}",
                    marker.display()
                );
            }
            Ok(launched) => {
                unsafe {
                    libc::kill(launched.pid, libc::SIGKILL);
                    let mut status = 0;
                    libc::waitpid(launched.pid, &mut status, 0);
                }
                panic!("a root swapped before the re-check started a process");
            }
        }
    }

    /// After the re-check, `sandbox-exec` resolves a subpath by name. A symlink
    /// at that path does not grant its target: the textual child and the
    /// target's own path both stay denied. A real directory swapped onto the
    /// same path is readable, including a file placed there. `identity/device.key`
    /// stays denied at its own path, and the rendered plan does not name it.
    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn a_symlink_subpath_resolves_outside_and_the_device_key_stays_unread() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let data = base.join("data");
        let outside = base.join("outside");
        std::fs::create_dir_all(data.join("identity")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let key = data.join("identity/device.key");
        std::fs::write(&key, b"device-key").unwrap();
        std::fs::write(outside.join("secret"), b"outside-secret").unwrap();
        let root = data.join("chain-provider");
        std::fs::create_dir(&root).unwrap();
        let admitted = super::super::rights::admit_runtime_grant(
            super::super::rights_table::RuntimeProviderId::Chain,
        );
        let (confinement, plan) = super::super::path_allow::render_with_plan(
            super::super::rights_table::RuntimeProviderId::Chain,
            &admitted,
            &data,
            Path::new("/opt/elastos/chain-provider"),
            5,
        )
        .unwrap_or_else(|err| panic!("render of the real root: {err}"));
        assert!(
            plan.rules.iter().all(|rule| !key.starts_with(&rule.1)),
            "identity/device.key is under an allowed root: {:?}",
            plan.rules
        );
        assert!(!confinement.seatbelt.contains("device.key"));
        assert!(!confinement.seatbelt.contains("identity"));
        assert!(confinement
            .seatbelt
            .contains("(allow file-read* file-write* (subpath (param \"chain-provider\")))"));
        std::fs::remove_dir(&root).unwrap();
        std::os::unix::fs::symlink(&outside, &root).unwrap();
        assert!(std::fs::symlink_metadata(&root)
            .unwrap()
            .file_type()
            .is_symlink());
        let source = base.join("probe.rs");
        let probe = base.join("probe");
        std::fs::write(
            &source,
            r#"fn main() {
    fn one(path: &str) -> String {
        match std::fs::read(path) {
            Ok(bytes) => format!("READ:{}", String::from_utf8_lossy(&bytes)),
            Err(err) => format!("DENY:{:?}", err.kind()),
        }
    }
    for path in std::env::args().skip(1) {
        println!("{path} {}", one(&path));
    }
}
"#,
        )
        .unwrap();
        let built = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-o"])
            .arg(&probe)
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "probe build failed: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        let probe_text = probe.display().to_string();
        let root_text = root.display().to_string();
        assert!(!probe_text.contains('"') && !root_text.contains('"'));
        // `/usr/lib` lets this probe's dynamic linker start. The product
        // subpath under test is `root_text` only. The device key is neither.
        let profile = format!(
            "(version 1)\n(deny default)\n(deny network*)\n(allow process-exec (literal \"{probe_text}\"))\n(allow file-read* (literal \"{probe_text}\"))\n(allow file-read* (subpath \"/usr/lib\"))\n(allow file-read* (subpath \"/System/Library\"))\n(allow file-read* (literal \"/\"))\n(allow sysctl-read)\n(allow file-read* file-write* (subpath \"{root_text}\"))\n"
        );
        let run = |profile: &str, paths: &[std::path::PathBuf]| {
            let mut command = std::process::Command::new("/usr/bin/sandbox-exec");
            command.arg("-p").arg(profile).arg(&probe);
            for path in paths {
                command.arg(path);
            }
            let output = command.output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                output.status.success(),
                "sandbox-exec probe failed: {stderr} {stdout}"
            );
            (stdout, stderr)
        };
        let textual = root.join("secret");
        let target = outside.join("secret");
        let (symlink_out, symlink_err) =
            run(&profile, &[textual.clone(), target.clone(), key.clone()]);
        assert!(
            symlink_out.contains(&format!("{textual} DENY:", textual = textual.display()))
                && symlink_out.contains(&format!("{target} DENY:", target = target.display()))
                && symlink_out.contains(&format!("{key} DENY:", key = key.display()))
                && !symlink_out.contains("READ:"),
            "a symlink subpath granted a path outside the textual directory: {symlink_out} {symlink_err}"
        );
        std::fs::remove_file(&root).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("secret"), b"replaced-secret").unwrap();
        std::fs::write(root.join("device.key"), b"moved-key").unwrap();
        let (dir_out, dir_err) = run(
            &profile,
            &[root.join("secret"), root.join("device.key"), key.clone()],
        );
        assert!(
            dir_out.contains("READ:replaced-secret") && dir_out.contains("READ:moved-key"),
            "a real directory swapped onto the root was not readable: {dir_out} {dir_err}"
        );
        assert!(
            dir_out.contains(&format!("{key} DENY:", key = key.display()))
                && !dir_out.contains("READ:device-key"),
            "identity/device.key was readable from its own path: {dir_out} {dir_err}"
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
