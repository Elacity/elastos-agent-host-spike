//! The guard against this host's real kernel.
//!
//! Positive control: the provider starts and shows it is confined.
//! Refusals: the launcher runs under an inherited seccomp filter that makes one
//! real system call fail, as an old kernel, a container profile or a sysctl
//! would, and must refuse. No fake object sits between the guard and the
//! kernel in these tests.

mod common;

use std::fs;
use std::process::Stdio;

use common::*;
use fail_closed_linux::{
    Fault, Guard, HostKernel, Kernel, LaunchError, ProviderKind, DEFAULT_DENIED_SYSCALLS,
    REQUIRED_LANDLOCK_ABI,
};

fn host_guard(storage: &TempDir) -> Guard<HostKernel> {
    Guard::host(stand_in_policy(storage.path()))
}

fn assert_confined(session: &mut Session) {
    let status = session.ask("status");
    assert_eq!(field(&status, "nnp"), "1", "{status}");
    assert_eq!(field(&status, "seccomp"), "2", "{status}");
    for caps in ["cap_eff", "cap_prm", "cap_inh"] {
        assert_eq!(field(&status, caps), "0", "{status}");
    }
    assert_eq!(field(&status, "cap_bnd"), "0", "{status}");
}

/// The invariant that holds on every Linux host: the provider either runs
/// confined or does not run. It never runs unconfined.
#[test]
fn the_provider_runs_confined_or_is_refused_never_unconfined() {
    for provider in ProviderKind::ALL {
        let storage = TempDir::new("invariant");
        match host_guard(&storage).launch(provider, stand_in_command(storage.path())) {
            Ok(child) => {
                let mut session = Session::new(child);
                assert_confined(&mut session);
                assert!(marker_of(storage.path()).exists());
                session.finish();
            }
            Err(LaunchError::Refused(refusal)) => {
                eprintln!("{refusal}");
                assert!(
                    !marker_of(storage.path()).exists(),
                    "refused, yet the provider ran"
                );
                assert_eq!(storage.entries(), Vec::<String>::new());
            }
            Err(other) => panic!("neither a confined start nor a refusal: {other}"),
        }
    }
}

/// Positive control. A host that cannot confine fails here with the layer it
/// lacks; set `FCL_ALLOW_UNCONFINABLE_HOST=1` to accept a refusal on such a host
/// (the invariant test above still runs).
#[test]
fn a_started_provider_is_confined_by_every_layer() {
    let storage = TempDir::new("confined");
    let outside = TempDir::new("outside");
    let victim = outside.path().join("victim");
    fs::write(&victim, b"keep me").unwrap();

    let guard = host_guard(&storage);
    let child = match guard.launch(ProviderKind::Did, stand_in_command(storage.path())) {
        Ok(child) => child,
        Err(LaunchError::Refused(refusal))
            if std::env::var_os("FCL_ALLOW_UNCONFINABLE_HOST").is_some() =>
        {
            eprintln!("host cannot confine, accepted by request: {refusal}");
            return;
        }
        Err(other) => panic!("this host cannot start the provider confined: {other}"),
    };
    let mut session = Session::new(child);

    assert_confined(&mut session);

    // User namespace: the provider's namespace is not ours, and its ids still
    // map to the owner of the files it may use.
    let ours = fs::read_link("/proc/self/ns/user").unwrap();
    let theirs = fs::read_link(format!("/proc/{}/ns/user", session.pid())).unwrap();
    assert_ne!(ours, theirs, "the provider shares our user namespace");
    let status = session.ask("status");
    assert_eq!(field(&status, "uid"), unsafe { libc::getuid() }.to_string());

    // Landlock: inside the root works; outside is refused for write and truncate.
    let inside = storage.path().join("state");
    assert_eq!(session.ask(&format!("write {}", inside.display())), "ok");
    assert!(inside.exists());
    let outside_file = outside.path().join("planted");
    assert_eq!(
        session.ask(&format!("write {}", outside_file.display())),
        format!("err={}", libc::EACCES)
    );
    assert!(!outside_file.exists());
    assert_eq!(
        session.ask(&format!("truncate {}", victim.display())),
        format!("err={}", libc::EACCES)
    );
    assert_eq!(fs::read(&victim).unwrap(), b"keep me");

    // Seccomp: a socket is refused.
    assert_eq!(session.ask("socket"), format!("err={}", libc::EPERM));

    session.finish();
}

/// Run the launcher CLI with one real system call failing, for each provider.
fn assert_cli_refuses(nr: i64, errno: i32, arg0: Option<u32>, expected: &str) {
    for provider in ProviderKind::ALL {
        let storage = TempDir::new("cli");
        let mut command = launch_cli_under(
            provider.name(),
            storage.path(),
            Some(deny_filter(nr, errno, arg0)),
        );
        let output = command.stdin(Stdio::null()).output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(
            output.status.code(),
            Some(71),
            "{}: {stderr}",
            provider.name()
        );
        assert!(
            stderr.starts_with(&format!("{} not started: {expected}", provider.name())),
            "{}: {stderr:?} does not start with the reason {expected:?}",
            provider.name()
        );
        let cause = std::io::Error::from_raw_os_error(errno).to_string();
        assert!(
            stderr.contains(&cause),
            "the injected cause {cause:?} is missing: {stderr}"
        );
        assert!(output.stdout.is_empty());
        assert!(
            !marker_of(storage.path()).exists(),
            "{}: the provider image ran",
            provider.name()
        );
        assert_eq!(storage.entries(), Vec::<String>::new());
    }
}

#[test]
fn real_refusal_when_user_namespaces_are_off() {
    for errno in [libc::EPERM, libc::ENOSPC] {
        assert_cli_refuses(
            libc::SYS_unshare,
            errno,
            None,
            "linux confinement refused: user namespaces are turned off",
        );
    }
}

#[test]
fn real_refusal_when_the_capability_drop_fails() {
    let expected = "linux confinement refused: the capability set cannot be dropped";
    assert_cli_refuses(libc::SYS_capset, libc::EPERM, None, expected);
    assert_cli_refuses(libc::SYS_capset, libc::ENOMEM, None, expected);
    assert_cli_refuses(
        libc::SYS_prctl,
        libc::EPERM,
        Some(libc::PR_CAPBSET_DROP as u32),
        expected,
    );
}

#[test]
fn real_refusal_when_no_new_privs_cannot_be_set() {
    assert_cli_refuses(
        libc::SYS_prctl,
        libc::EPERM,
        Some(libc::PR_SET_NO_NEW_PRIVS as u32),
        "linux confinement refused: no_new_privs cannot be set",
    );
}

#[test]
fn real_refusal_when_seccomp_cannot_be_installed() {
    for errno in [libc::ENOSYS, libc::EINVAL] {
        assert_cli_refuses(
            libc::SYS_seccomp,
            errno,
            None,
            "linux confinement refused: the seccomp filter cannot be installed",
        );
    }
}

#[test]
fn real_refusal_when_landlock_is_missing() {
    for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
        assert_cli_refuses(
            libc::SYS_landlock_create_ruleset,
            errno,
            None,
            "linux confinement refused: the kernel has no Landlock",
        );
    }
}

#[test]
fn real_refusal_when_the_landlock_ruleset_cannot_be_applied() {
    let expected = "linux confinement refused: the Landlock ruleset cannot be applied";
    assert_cli_refuses(
        libc::SYS_landlock_restrict_self,
        libc::EPERM,
        None,
        expected,
    );
    assert_cli_refuses(libc::SYS_landlock_add_rule, libc::EPERM, None, expected);
}

#[test]
fn real_refusal_when_the_landlock_abi_is_too_old() {
    let host_abi = HostKernel::new()
        .landlock_abi()
        .expect("this host has Landlock");
    assert!(
        host_abi >= REQUIRED_LANDLOCK_ABI,
        "this host reports ABI {host_abi}"
    );

    let storage = TempDir::new("too-old");
    let guard = host_guard(&storage).require_landlock_abi(host_abi + 1);
    match guard.launch(ProviderKind::Model, stand_in_command(storage.path())) {
        Err(LaunchError::Refused(refusal)) => {
            assert_eq!(refusal.fault, Fault::LandlockTooOld { found: host_abi });
            let reason = refusal.reason();
            assert!(
                reason.contains(&format!(
                    "needs ABI {}, this kernel reports ABI {host_abi}",
                    host_abi + 1
                )),
                "{reason}"
            );
        }
        other => panic!("a kernel older than the requirement must be refused: {other:?}"),
    }
    assert!(!marker_of(storage.path()).exists());
    assert_eq!(storage.entries(), Vec::<String>::new());
}

/// Control for the harness: a filter that fails a system call the guard never
/// makes does not stop the provider, so the refusals above are not the
/// harness refusing everything.
#[test]
fn the_launcher_starts_the_provider_when_the_filtered_call_is_not_one_it_makes() {
    let storage = TempDir::new("control");
    let mut command = launch_cli_under(
        ProviderKind::Did.name(),
        storage.path(),
        Some(deny_filter(libc::SYS_acct, libc::EPERM, None)),
    );
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"status\nexit\n")
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("nnp=1 seccomp=2"), "{stdout}");
    assert!(marker_of(storage.path()).exists());
}

#[test]
fn the_launcher_reports_a_missing_program_as_a_start_failure_not_a_refusal() {
    let storage = TempDir::new("missing");
    let output = std::process::Command::new(FCL_LAUNCH)
        .args(["--provider", "wallet-provider", "--storage-root"])
        .arg(storage.path())
        .args(["--", "/nonexistent/provider"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(70),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_baseline_filter_refuses_each_listed_call_and_allows_the_rest() {
    let storage = TempDir::new("filter");
    let policy = stand_in_policy(storage.path());
    let program = policy.seccomp.instructions();
    for nr in DEFAULT_DENIED_SYSCALLS {
        assert_eq!(
            run_filter(program, native_arch(), *nr),
            RET_ERRNO | libc::EPERM as u32,
            "system call {nr}"
        );
    }
    for allowed in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_openat,
        libc::SYS_execve,
        libc::SYS_exit_group,
    ] {
        assert_eq!(
            run_filter(program, native_arch(), allowed as u32),
            RET_ALLOW,
            "system call {allowed}"
        );
    }
}

#[test]
fn the_baseline_filter_kills_a_foreign_architecture() {
    let storage = TempDir::new("arch");
    let policy = stand_in_policy(storage.path());
    let foreign = native_arch() ^ 0x0000_0100;
    assert_eq!(
        run_filter(
            policy.seccomp.instructions(),
            foreign,
            libc::SYS_socket as u32
        ),
        RET_KILL_PROCESS
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn the_baseline_filter_refuses_a_listed_call_reached_by_its_x32_number() {
    let storage = TempDir::new("x32");
    let policy = stand_in_policy(storage.path());
    let x32 = libc::SYS_socket as u32 | 0x4000_0000;
    assert_eq!(
        run_filter(policy.seccomp.instructions(), native_arch(), x32),
        RET_ERRNO | libc::EPERM as u32
    );
}
