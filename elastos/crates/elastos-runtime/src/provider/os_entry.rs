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

/// Admit the model grant and build its Linux plan.
///
/// The Landlock report is the caller's. ABI 5 or newer returns the plan the
/// preexec installer attaches. A missing, older, or failed report refuses
/// before a provider is registered.
#[cfg(any(
    test,
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(super) fn model_linux_attachment(
    authority: &ProviderAuthority,
    bindings: &super::landlock_plan::Bindings,
    reported: std::io::Result<u32>,
    arch: super::landlock_plan::ModelArch,
) -> Result<super::landlock_plan::LinuxModelPlan, String> {
    let admitted = super::rights::check_rights_against_runtime_templates(
        RuntimeProviderId::Model,
        authority,
        rights_table::RIGHTS,
    )?;
    require_grant(&admitted)?;
    let abi = super::landlock_plan::require_abi(reported)?;
    let plan = super::landlock_plan::linux_model_plan(&admitted, bindings, arch, abi)?;
    let attached = plan.rules.iter().any(|rule| rule.0 == "STORAGE_ROOT")
        && plan
            .rules
            .iter()
            .any(|rule| rule.0 == "PROVIDER_EXECUTABLE")
        && !plan.program.is_empty();
    if !attached {
        return Err("provider start is refused: the Landlock plan is not attached".to_string());
    }
    Ok(plan)
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
    macos_start(prepared, checked, stdio, profile, &[])
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn macos_start(
    prepared: super::checked_executable::PreparedExecutable,
    checked: CheckedDirectory<'_>,
    stdio: ChildStdio,
    profile: String,
    extra: &[(&str, &Path)],
) -> Result<Launched, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

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
    let mut command = macos_command(
        Path::new("/usr/bin/sandbox-exec"),
        &profile,
        &binary,
        parent,
        &storage,
        extra,
    )?;
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return Err(format!(
            "provider start is refused: cannot inspect descriptor limit: {}",
            std::io::Error::last_os_error()
        ));
    }
    let maxfilesperproc = macos_maxfilesperproc();
    let max_fd = macos_fd_sweep_limit(unsafe { limit.assume_init() }.rlim_cur, maxfilesperproc)?;
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
    extra: &[(&str, &Path)],
) -> Result<std::process::Command, String> {
    use std::os::unix::ffi::OsStrExt;

    let mut command = std::process::Command::new(launcher);
    command.env_clear();
    command.arg("-p").arg(profile);
    for (name, path) in [
        ("STORAGE_ROOT", storage),
        ("STORAGE_PARENT", parent),
        ("PROVIDER_EXECUTABLE", binary),
    ] {
        command.arg("-D").arg(format!("{name}={}", path.display()));
    }
    for (name, path) in extra {
        let value = extra_binding_value(path)?;
        command.arg("-D").arg(format!("{name}={value}"));
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

/// One extra Seatbelt parameter. The value stays a single `-D` argument.
#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn extra_binding_value(path: &Path) -> Result<&str, String> {
    path.to_str()
        .filter(|value| !value.contains(['=', '\n', '"', '\\']))
        .ok_or_else(|| {
            "provider start is refused: a model binding path is not a Seatbelt parameter"
                .to_string()
        })
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
pub(super) struct ModelLaunch<'a> {
    pub engine: &'a Path,
    pub model: &'a Path,
    pub bundle: &'a Path,
    pub hosted: &'a Path,
    pub brokers: &'a [std::path::PathBuf],
    pub engines: &'a [std::path::PathBuf],
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
pub(super) fn admitted_model_profile(admitted: &AdmittedRights) -> String {
    super::macos_profile::render_macos_profile(RuntimeProviderId::Model, admitted)
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn model_file(path: &Path, file: bool) -> Result<std::path::PathBuf, String> {
    let canon = std::fs::canonicalize(path).map_err(|_| "model path".to_string())?;
    if canon != path || file != canon.is_file() {
        return Err("model path".into());
    }
    Ok(canon)
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
fn model_bindings(launch: &ModelLaunch<'_>) -> Result<Vec<(String, std::path::PathBuf)>, String> {
    if launch.brokers.len() != 64 || launch.engines.len() != 64 {
        return Err("model sockets".into());
    }
    let engine = model_file(launch.engine, true)?;
    let model = model_file(launch.model, true)?;
    let bundle = model_file(launch.bundle, false)?;
    if !engine.starts_with(&bundle) {
        return Err("model engine".into());
    }
    let mut ancestors: Vec<_> = model.ancestors().skip(1).map(Path::to_path_buf).collect();
    let root = std::path::PathBuf::from("/");
    if ancestors.len() > 19 || ancestors.last() != Some(&root) {
        return Err("model ancestors".into());
    }
    ancestors.resize(19, root);
    let hosted_parent = launch.hosted.parent().ok_or("model socket")?;
    if std::fs::canonicalize(hosted_parent).ok().as_deref() != Some(hosted_parent) {
        return Err("model socket".into());
    }
    let mut bindings = vec![
        ("MODEL".into(), model),
        ("ENGINE".into(), engine),
        ("ENGINE_BUNDLE".into(), bundle),
        ("HOSTED_SOCKET".into(), launch.hosted.to_path_buf()),
    ];
    for (index, ancestor) in ancestors.into_iter().enumerate() {
        bindings.push((format!("MODEL_ANCESTOR_{index}"), ancestor));
    }
    for (prefix, paths) in [
        ("BROKER_SOCKET", launch.brokers),
        ("ENGINE_SOCKET", launch.engines),
    ] {
        for (index, path) in paths.iter().enumerate() {
            let parent = path.parent().ok_or("model socket")?;
            if std::fs::canonicalize(parent).ok().as_deref() != Some(parent) {
                return Err("model socket".into());
            }
            bindings.push((format!("{prefix}_{index}"), path.clone()));
        }
    }
    Ok(bindings)
}

#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
pub(super) fn model_rights_command(
    authority: &ProviderAuthority,
    binary: &Path,
    storage: &Path,
    parent: &Path,
    launch: &ModelLaunch<'_>,
) -> Result<std::process::Command, String> {
    let admitted = super::rights::check_rights_against_runtime_templates(
        RuntimeProviderId::Model,
        authority,
        rights_table::RIGHTS,
    )?;
    require_grant(&admitted)?;
    let profile = admitted_model_profile(&admitted);
    let head = "(version 1)\n(deny default)\n(deny network*)\n";
    if !profile.starts_with(head) || profile.contains("(allow default)") {
        return Err(
            "provider start is refused: the model profile is not the rendered rights profile"
                .into(),
        );
    }
    let owned =
        model_bindings(launch).map_err(|item| format!("provider start is refused: {item}"))?;
    let extra: Vec<(&str, &Path)> = owned
        .iter()
        .map(|(n, p)| (n.as_str(), p.as_path()))
        .collect();
    let mut bound =
        std::collections::BTreeSet::from(["STORAGE_ROOT", "STORAGE_PARENT", "PROVIDER_EXECUTABLE"]);
    let missing = extra.iter().any(|(name, _)| !bound.insert(*name))
        || profile
            .split("(param \"")
            .skip(1)
            .any(|tail| !bound.contains(tail.split('"').next().unwrap_or("")));
    if missing {
        return Err(
            "provider start is refused: a model profile parameter has no Runtime binding".into(),
        );
    }
    macos_command(
        Path::new("/usr/bin/sandbox-exec"),
        &profile,
        binary,
        parent,
        storage,
        &extra,
    )
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
            &[],
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
            &[],
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
                &[],
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
                &[],
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
            &[],
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

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    fn rule_lines(profile: &str) -> Vec<&str> {
        profile
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with('('))
            .collect()
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn model_start_rights_part_is_the_rendered_profile() {
        let admitted = super::super::rights::admit_committed(RuntimeProviderId::Model);
        let profile = admitted_model_profile(&admitted);
        let rendered =
            super::super::macos_profile::render_macos_profile(RuntimeProviderId::Model, &admitted);
        assert_eq!(profile, rendered, "the model start uses the rendered grant");
        assert!(profile.starts_with("(version 1)\n(deny default)\n(deny network*)\n"));
        assert!(
            !profile.contains("(allow default)"),
            "the hand-written model policy is not the start profile"
        );
        let oracle = include_str!("../../../../../capsules/model-provider/confine.sb");
        assert_eq!(
            rule_lines(&profile),
            rule_lines(oracle),
            "the rendered model profile is the committed oracle"
        );
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn removing_one_model_right_drops_its_rule_from_the_start_profile() {
        let full = admitted_model_profile(&super::super::rights::admit_committed(
            RuntimeProviderId::Model,
        ));
        let mut authority = committed_authority("model");
        let before = authority.rights.len();
        authority.rights.retain(|right| right.id != "model-gpu");
        assert_eq!(authority.rights.len(), before - 1);
        let admitted = super::super::rights::check_rights_against_runtime_templates(
            RuntimeProviderId::Model,
            &authority,
            rights_table::RIGHTS,
        )
        .unwrap();
        let narrow = admitted_model_profile(&admitted);
        assert_ne!(narrow, full);
        assert!(full.contains("com.apple.MTLCompilerService"));
        assert!(!narrow.contains("com.apple.MTLCompilerService"));
        assert!(narrow.starts_with("(version 1)\n(deny default)\n(deny network*)\n"));
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn model_start_binds_every_rendered_parameter() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().canonicalize().unwrap().join("bundle");
        std::fs::create_dir(&bundle).unwrap();
        let engine = bundle.join("llama-server");
        let model = temp.path().canonicalize().unwrap().join("model.gguf");
        std::fs::write(&engine, b"engine").unwrap();
        std::fs::write(&model, b"gguf").unwrap();
        let ipc = temp.path().canonicalize().unwrap().join("ipc");
        std::fs::create_dir(&ipc).unwrap();
        let brokers: Vec<_> = (0..64)
            .map(|index| ipc.join(format!("{index}.sock")))
            .collect();
        let engines: Vec<_> = (0..64)
            .map(|index| ipc.join(format!("{index}.engine.sock")))
            .collect();
        let hosted = ipc.join("hosted.sock");
        let launch = ModelLaunch {
            engine: &engine,
            model: &model,
            bundle: &bundle,
            hosted: &hosted,
            brokers: &brokers,
            engines: &engines,
        };
        let owned = model_bindings(&launch).unwrap();
        let extra: Vec<_> = owned
            .iter()
            .map(|(name, path)| (name.as_str(), path.as_path()))
            .collect();
        let admitted = super::super::rights::admit_committed(RuntimeProviderId::Model);
        let profile = admitted_model_profile(&admitted);
        let command = macos_command(
            Path::new("/usr/bin/sandbox-exec"),
            &profile,
            Path::new("/private/fixture/bin/model-provider"),
            Path::new("/private/fixture/data"),
            Path::new("/private/fixture/data/model"),
            &extra,
        )
        .unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], profile);
        let bound: std::collections::BTreeSet<_> = args
            .windows(2)
            .filter(|pair| pair[0] == "-D")
            .map(|pair| pair[1].split_once('=').unwrap().0.to_string())
            .collect();
        let named: std::collections::BTreeSet<_> = profile
            .split("(param \"")
            .skip(1)
            .map(|tail| tail.split('"').next().unwrap().to_string())
            .collect();
        assert_eq!(bound, named);
        assert!(bound.contains("ENGINE"));
        assert!(bound.contains("MODEL"));
        assert!(bound.contains("BROKER_SOCKET_0"));
        assert!(bound.contains("ENGINE_SOCKET_63"));
        assert!(!args.iter().any(|arg| arg.contains("(allow default)")));
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[test]
    fn extra_binding_refuses_a_quote_or_a_backslash() {
        let profile = "(version 1)\n(deny default)\n(deny network*)\n";
        let binary = Path::new("/private/fixture/bin/model-provider");
        let parent = Path::new("/private/fixture/data");
        let storage = Path::new("/private/fixture/data/model");
        for (label, path) in [
            ("quote", Path::new("/private/fixture/has\"quote")),
            ("backslash", Path::new("/private/fixture/has\\slash")),
            ("equals", Path::new("/private/fixture/has=sign")),
            ("newline", Path::new("/private/fixture/has\nline")),
        ] {
            let error = macos_command(
                Path::new("/usr/bin/sandbox-exec"),
                profile,
                binary,
                parent,
                storage,
                &[("ENGINE", path)],
            )
            .expect_err(label);
            assert!(
                error.contains("a model binding path is not a Seatbelt parameter"),
                "{label}: {error}"
            );
        }
        let command = macos_command(
            Path::new("/usr/bin/sandbox-exec"),
            profile,
            binary,
            parent,
            storage,
            &[("ENGINE", Path::new("/private/fixture/engine"))],
        )
        .expect("a binding without a quote or a backslash is a Seatbelt parameter");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|arg| arg == "-D"));
        assert!(args
            .iter()
            .any(|arg| arg == "ENGINE=/private/fixture/engine"));
    }

    fn linux_model_bindings() -> super::super::landlock_plan::Bindings {
        super::super::landlock_plan::Bindings {
            storage_root: PathBuf::from("/provider/model"),
            provider_executable: PathBuf::from("/bin/model"),
            storage_dev: 7,
            storage_ino: 9,
        }
    }

    #[test]
    fn model_linux_landlock_check_refuses_before_registration() {
        let authority = committed_authority("model");
        let bindings = linux_model_bindings();
        let no_landlock = super::super::landlock_plan::require_abi(Err(std::io::Error::from(
            std::io::ErrorKind::Unsupported,
        )))
        .unwrap_err();
        for reported in [
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported)),
            Err(std::io::Error::other("landlock query failed")),
        ] {
            assert_eq!(
                model_linux_attachment(
                    &authority,
                    &bindings,
                    reported,
                    super::super::landlock_plan::ModelArch::X86_64,
                )
                .unwrap_err(),
                no_landlock,
                "a missing or failed Landlock check refuses before a provider is registered"
            );
        }
        for abi in [0u32, 2, 4] {
            assert_eq!(
                model_linux_attachment(
                    &authority,
                    &bindings,
                    Ok(abi),
                    super::super::landlock_plan::ModelArch::Aarch64,
                )
                .unwrap_err(),
                super::super::landlock_plan::require_abi(Ok(abi)).unwrap_err(),
                "ABI {abi} refuses before a provider is registered"
            );
        }
    }

    #[test]
    fn model_linux_start_attaches_the_admitted_plan() {
        let authority = committed_authority("model");
        let admitted = super::super::rights::admit_committed(RuntimeProviderId::Model);
        let bindings = linux_model_bindings();
        for arch in [
            super::super::landlock_plan::ModelArch::X86_64,
            super::super::landlock_plan::ModelArch::Aarch64,
        ] {
            for abi in [5u32, 6] {
                let plan = model_linux_attachment(&authority, &bindings, Ok(abi), arch)
                    .unwrap_or_else(|error| panic!("{arch:?} ABI {abi}: {error}"));
                let reference =
                    super::super::landlock_plan::linux_model_plan(&admitted, &bindings, arch, abi)
                        .unwrap();
                assert_eq!(plan.rules, reference.rules, "{arch:?} ABI {abi} landlock");
                assert_eq!(
                    plan.program, reference.program,
                    "{arch:?} ABI {abi} seccomp"
                );
                assert!(plan.rules.iter().any(|rule| rule.0 == "STORAGE_ROOT"));
                assert!(plan
                    .rules
                    .iter()
                    .any(|rule| rule.0 == "PROVIDER_EXECUTABLE"));
                assert!(!plan.program.is_empty());
            }
        }
    }
}
