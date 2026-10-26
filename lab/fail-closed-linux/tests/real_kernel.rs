//! The guard on the real kernel, through the `fcl-launch` CLI.
//!
//! The positive test starts the static probe for each provider and reads the
//! running probe's /proc/<pid> from outside. Each refusal test makes one real
//! step fail, either through a kernel rule (a parent user namespace limit, an
//! unreadable launcher binary, a Landlock ABI above the host's, the Landlock
//! stacking limit) or through a seccomp filter the launcher inherits that
//! makes one system call fail.

mod common;

use common::{
    assert_refused, host_landlock_abi, launch_command, launcher, output, require_line,
    unconfined_tiocgwinsz, wait_with_timeout, with_test_hooks, Fixture, Inherit, PROVIDERS,
};
use fail_closed_linux::{PID_NAMESPACE_UNAVAILABLE, TEST_FUTURE_FS_ABI, TEST_FUTURE_FS_NAME};
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;

fn status_field(status: &str, field: &str) -> String {
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .unwrap_or_else(|| panic!("no {field} in\n{status}"))
        .trim()
        .to_string()
}

#[test]
fn real_confined_provider_has_every_layer() {
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let own_user_ns = fs::read_link("/proc/self/ns/user").unwrap();
    for provider in PROVIDERS {
        let fixture = Fixture::new("confined", provider);
        let mut command = launch_command(&launcher(), provider, &fixture, &[], Inherit::Nothing);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("cannot start the launcher");
        let stdin = child.stdin.take().unwrap();
        let mut lines = Vec::new();
        let mut pid = None;
        for line in BufReader::new(child.stdout.take().unwrap()).lines() {
            let line = line.unwrap();
            if let Some(rest) = line.strip_prefix(&format!("started {provider} pid=")) {
                pid = Some(rest.parse::<u32>().unwrap());
            }
            lines.push(line);
            if pid.is_some() && lines.iter().any(|line| line == "ready") {
                break;
            }
        }
        let pid = pid.unwrap_or_else(|| panic!("{provider}: no started line in {lines:?}"));
        assert!(
            lines.iter().any(|line| line == "ready"),
            "{provider}: {lines:?}"
        );
        unconfined_tiocgwinsz(&fixture.tty_path).unwrap_or_else(|err| {
            panic!(
                "{provider}: unconfined TIOCGWINSZ on {:?} must succeed: {err}",
                fixture.tty_path
            )
        });

        let proc = format!("/proc/{pid}");
        let status = fs::read_to_string(format!("{proc}/status")).unwrap();
        assert_eq!(status_field(&status, "NoNewPrivs"), "1", "{provider}");
        assert_eq!(status_field(&status, "Seccomp"), "2", "{provider}");
        for set in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            assert_eq!(
                status_field(&status, set),
                "0000000000000000",
                "{provider} {set}"
            );
        }
        let uid_map = fs::read_to_string(format!("{proc}/uid_map")).unwrap();
        let fields: Vec<&str> = uid_map.split_whitespace().collect();
        assert_eq!(
            fields,
            [uid.to_string(), uid.to_string(), "1".to_string()],
            "{provider}"
        );
        let user_ns = fs::read_link(format!("{proc}/ns/user")).unwrap();
        assert_ne!(
            user_ns, own_user_ns,
            "{provider} shares the test's user namespace"
        );

        let nspid_line = require_line(&lines, "nspid=", provider);
        let nspid: i32 = nspid_line
            .rsplit('=')
            .next()
            .and_then(|text| text.parse().ok())
            .unwrap_or_else(|| panic!("NOT RUN: bad {nspid_line}"));
        assert_eq!(
            nspid, 2,
            "{provider}: provider nspid must be 2 under init, got {nspid}"
        );
        let init_nspid = status_field(&status, "NSpid");
        assert_eq!(
            init_nspid.split_whitespace().last(),
            Some("1"),
            "{provider}: returned pid must be PID-namespace init, NSpid={init_nspid:?}"
        );
        let own_pid_ns = fs::read_link("/proc/self/ns/pid").unwrap();
        let init_pid_ns = fs::read_link(format!("{proc}/ns/pid")).unwrap();
        assert_ne!(
            init_pid_ns, own_pid_ns,
            "{provider} returned pid still shares the host PID namespace"
        );
        let launcher_children = children_of(child.id());
        assert_eq!(
            launcher_children,
            [pid],
            "{provider}: a host-namespace helper still sits beside init: {launcher_children:?}"
        );

        for expected in [
            format!("probe-ran provider={provider}"),
            "marker ok".to_string(),
            format!("socket_inet errno={}", libc::EPERM),
            format!("socket_unix errno={}", libc::EPERM),
            format!("read_outside errno={}", libc::EACCES),
            format!("write_outside errno={}", libc::EACCES),
            format!("read_etc_passwd errno={}", libc::EACCES),
            "storage_write ok".to_string(),
            "storage_read ok".to_string(),
            "truncate_storage ok".to_string(),
        ] {
            assert!(
                lines.contains(&expected),
                "{provider}: missing {expected:?} in {lines:?}"
            );
        }
        for denied in ["truncate_outside", "o_trunc_outside"] {
            assert!(
                lines
                    .iter()
                    .any(|line| line.starts_with(&format!("{denied} errno="))),
                "{provider}: missing denied {denied} in {lines:?}"
            );
            assert!(
                !lines.iter().any(|line| line == &format!("{denied} ok")),
                "{provider}: {denied} was allowed in {lines:?}"
            );
        }
        assert!(
            lines.contains(&format!("ioctl_dev errno={}", libc::EACCES)),
            "{provider}: ioctl_dev must be Landlock EACCES ({}), got {lines:?}",
            libc::EACCES
        );

        drop(stdin);
        let done = child.wait_with_output().unwrap();
        assert_eq!(
            done.status.code(),
            Some(0),
            "{provider}: {}",
            String::from_utf8_lossy(&done.stderr)
        );
        assert!(fixture.marker().exists(), "{provider}");
        assert!(
            !fixture.outside_dir.join("written-by-probe").exists(),
            "{provider}"
        );
    }
}

#[test]
fn real_user_namespaces_off_refuses() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("userns-limit", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &[],
            Inherit::UserNamespaceLimit,
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "user-namespace",
            "unshare",
            "(os error 28)",
        );

        let fixture = Fixture::new("userns-eperm", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &[],
            Inherit::Errno {
                nr: libc::SYS_unshare,
                arg0: None,
                errno: libc::EPERM,
            },
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "user-namespace",
            "unshare",
            "(os error 1)",
        );
    }
}

#[test]
fn real_id_map_unwritable_refuses() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("idmap", provider);
        let exec_only = fixture.exec_only_launcher();
        let run = output(launch_command(
            &exec_only,
            provider,
            &fixture,
            &[],
            Inherit::Nothing,
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "user-namespace",
            "uid_map",
            "(os error 13)",
        );
    }
}

#[test]
fn real_capability_drop_failure_refuses() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("capset", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &[],
            Inherit::Errno {
                nr: libc::SYS_capset,
                arg0: None,
                errno: libc::EPERM,
            },
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "capabilities",
            "capset",
            "(os error 1)",
        );

        let fixture = Fixture::new("bounding", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &[],
            Inherit::Errno {
                nr: libc::SYS_prctl,
                arg0: Some(libc::PR_CAPBSET_DROP as u32),
                errno: libc::EPERM,
            },
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "capabilities",
            "bounding_set",
            "(os error 1)",
        );
    }
}

#[test]
fn real_no_new_privs_failure_refuses() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("nnp", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &[],
            Inherit::Errno {
                nr: libc::SYS_prctl,
                arg0: Some(libc::PR_SET_NO_NEW_PRIVS as u32),
                errno: libc::EPERM,
            },
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "no_new_privs",
            "set_no_new_privs",
            "(os error 1)",
        );
    }
}

#[test]
fn real_seccomp_install_failure_refuses() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("seccomp", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &[],
            Inherit::Errno {
                nr: libc::SYS_seccomp,
                arg0: None,
                errno: libc::ENOSYS,
            },
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "seccomp",
            "install_filter",
            "(os error 38)",
        );
    }
}

#[test]
fn real_landlock_missing_refuses() {
    for provider in PROVIDERS {
        for (errno, label) in [(libc::ENOSYS, "enosys"), (libc::EOPNOTSUPP, "eopnotsupp")] {
            let fixture = Fixture::new(&format!("landlock-missing-{label}"), provider);
            let run = output(launch_command(
                &launcher(),
                provider,
                &fixture,
                &[],
                Inherit::Errno {
                    nr: libc::SYS_landlock_create_ruleset,
                    arg0: None,
                    errno,
                },
            ));
            assert_refused(
                &run,
                &fixture,
                provider,
                "landlock",
                "abi_probe",
                &format!(
                    "Landlock is not available: {}",
                    std::io::Error::from_raw_os_error(errno)
                ),
            );
        }
    }
}

#[test]
fn real_landlock_abi_below_required_refuses() {
    let host = host_landlock_abi();
    let required = (host + 1).to_string();
    for provider in PROVIDERS {
        let fixture = Fixture::new("abi-floor", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &["--require-landlock-abi", &required],
            Inherit::Nothing,
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "landlock",
            "abi_floor",
            &format!("Landlock ABI {host} is below the required {required}"),
        );
    }
}

#[test]
fn real_landlock_ruleset_unappliable_refuses() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("landlock-stack", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &[],
            Inherit::LandlockDomains(16),
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "landlock",
            "restrict_self",
            "(os error 7)",
        );

        let fixture = Fixture::new("landlock-restrict-eperm", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &[],
            Inherit::Errno {
                nr: libc::SYS_landlock_restrict_self,
                arg0: None,
                errno: libc::EPERM,
            },
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "landlock",
            "restrict_self",
            "(os error 1)",
        );
    }
}

fn read_until_ready(child: &mut std::process::Child, provider: &str) -> (u32, Vec<String>) {
    let mut lines = Vec::new();
    let mut pid = None;
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        if let Some(rest) = line.strip_prefix(&format!("started {provider} pid=")) {
            pid = Some(rest.parse::<u32>().unwrap());
        }
        lines.push(line);
        if pid.is_some() && lines.iter().any(|line| line == "ready") {
            break;
        }
    }
    let pid = pid.unwrap_or_else(|| panic!("{provider}: no started line in {lines:?}"));
    assert!(
        lines.iter().any(|line| line == "ready"),
        "{provider}: {lines:?}"
    );
    (pid, lines)
}

#[test]
fn real_confined_child_cannot_signal_host() {
    let host_pid = std::process::id();
    assert_ne!(
        host_pid, 1,
        "NOT RUN: this process is pid 1; a host kill target of 1 is the confined init"
    );
    for provider in PROVIDERS {
        let fixture = Fixture::new("signal-host", provider);
        let mut command = launch_command(&launcher(), provider, &fixture, &[], Inherit::Nothing);
        command
            .arg("--kill-host")
            .arg(host_pid.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("cannot start the launcher");
        let stdin = child.stdin.take().unwrap();
        let (_pid, lines) = read_until_ready(&mut child, provider);

        let nspid_line = require_line(&lines, "nspid=", provider);
        let nspid: i32 = nspid_line
            .rsplit('=')
            .next()
            .and_then(|text| text.parse().ok())
            .unwrap_or_else(|| panic!("NOT RUN: bad {nspid_line}"));
        assert_eq!(
            nspid, 2,
            "{provider}: confined nspid must be 2, got {nspid}"
        );

        let host_line = require_line(&lines, "kill_host ", provider);
        let errno = host_line
            .strip_prefix("kill_host errno=")
            .and_then(|text| text.parse::<i32>().ok());
        let errno = errno.unwrap_or_else(|| {
            panic!("{provider}: kill_host must record an errno, got {host_line}")
        });
        assert!(
            errno == libc::ESRCH || errno == libc::EPERM,
            "{provider}: kill_host expected ESRCH ({}) or EPERM ({}), got {errno} ({host_line})",
            libc::ESRCH,
            libc::EPERM
        );
        assert!(
            lines.iter().any(|line| line == "kill_child ok"),
            "{provider}: missing kill_child ok in {lines:?}"
        );

        drop(stdin);
        let done = child.wait_with_output().unwrap();
        assert_eq!(
            done.status.code(),
            Some(0),
            "{provider}: {}",
            String::from_utf8_lossy(&done.stderr)
        );
    }
}

#[test]
fn real_pid_namespace_unavailable_refuses() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("pidns", provider);
        let run = output(launch_command(
            &launcher(),
            provider,
            &fixture,
            &[],
            Inherit::Errno {
                nr: libc::SYS_unshare,
                arg0: Some(libc::CLONE_NEWPID as u32),
                errno: libc::EPERM,
            },
        ));
        assert_refused(
            &run,
            &fixture,
            provider,
            "pid-namespace",
            "unshare_pid",
            PID_NAMESPACE_UNAVAILABLE,
        );
        assert_refused(
            &run,
            &fixture,
            provider,
            "pid-namespace",
            "unshare_pid",
            "(os error 1)",
        );
    }
}

#[test]
fn real_reaper_propagates_exit_status() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("reaper-exit", provider);
        let mut command = launch_command(&launcher(), provider, &fixture, &[], Inherit::Nothing);
        command.arg("--exit").arg("42");
        let run = output(command);
        let stdout = String::from_utf8_lossy(&run.stdout);
        let stderr = String::from_utf8_lossy(&run.stderr);
        let context = format!(
            "status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            run.status
        );
        assert_eq!(run.status.code(), Some(42), "{provider}: {context}");
        assert!(
            stdout.contains("nspid="),
            "NOT RUN: probe did not print nspid\n{context}"
        );
        assert!(
            !stderr.contains("refused to start"),
            "{provider}: guard refused\n{context}"
        );
    }
}

#[test]
fn real_reaper_forwards_signal() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("reaper-signal", provider);
        let mut command = launch_command(&launcher(), provider, &fixture, &[], Inherit::Nothing);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("cannot start the launcher");
        let _stdin = child.stdin.take().unwrap();
        let (pid, lines) = read_until_ready(&mut child, provider);
        require_line(&lines, "nspid=", provider);
        let provider_pid = innermost_child(pid)
            .unwrap_or_else(|| panic!("NOT RUN: no provider pid under helper {pid} ({provider})"));

        let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        assert_eq!(sent, 0, "{provider}: kill({pid}, SIGTERM) failed");

        let status = wait_with_timeout(&mut child, 5).unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{provider}: launcher did not exit after SIGTERM to pid {pid}");
        });
        assert_eq!(
            status
                .code()
                .or_else(|| status.signal().map(|sig| 128 + sig)),
            Some(128 + libc::SIGTERM),
            "{provider}: expected 128+SIGTERM, got {status:?}"
        );
        assert!(
            !std::path::Path::new(&format!("/proc/{provider_pid}")).exists(),
            "{provider}: provider pid {provider_pid} still exists; the reaper did not forward SIGTERM"
        );
    }
}

fn children_of(pid: u32) -> Vec<u32> {
    fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|text| text.parse().ok())
        .collect()
}

fn zombies_with_parent(ppid: u32) -> Vec<u32> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        let is_zombie = status
            .lines()
            .any(|line| line.starts_with("State:\tZ") || line.starts_with("State: Z"));
        let parent = status.lines().find_map(|line| {
            line.strip_prefix("PPid:")
                .and_then(|text| text.trim().parse::<u32>().ok())
        });
        if is_zombie && parent == Some(ppid) {
            found.push(pid);
        }
    }
    found
}

fn innermost_child(pid: u32) -> Option<u32> {
    let mut current = pid;
    let mut last = None;
    for _ in 0..4 {
        match children_of(current).first().copied() {
            Some(child) => {
                last = Some(child);
                current = child;
            }
            None => break,
        }
    }
    last
}

#[test]
fn real_per_right_floor_refuses_on_this_kernel() {
    let host = host_landlock_abi();
    assert!(
        host < TEST_FUTURE_FS_ABI,
        "this row needs a host ABI below {TEST_FUTURE_FS_ABI}, got {host}"
    );
    for provider in PROVIDERS {
        let fixture = Fixture::new("per-right-floor", provider);
        let mut command = launch_command(
            &launcher(),
            provider,
            &fixture,
            &["--test-require-right", TEST_FUTURE_FS_NAME],
            Inherit::Nothing,
        );
        with_test_hooks(&mut command);
        let run = output(command);
        assert_refused(
            &run,
            &fixture,
            provider,
            "landlock",
            "abi_floor",
            &format!(
                "this kernel's Landlock ABI {host} cannot deny {TEST_FUTURE_FS_NAME} (needs ABI {TEST_FUTURE_FS_ABI})"
            ),
        );
    }
}

#[test]
fn real_extra_floor_still_names_the_missing_right() {
    let host = host_landlock_abi();
    let required = (host + 1).to_string();
    for provider in PROVIDERS {
        let fixture = Fixture::new("extra-floor-names-right", provider);
        let mut command = launch_command(
            &launcher(),
            provider,
            &fixture,
            &[
                "--require-landlock-abi",
                &required,
                "--test-require-right",
                TEST_FUTURE_FS_NAME,
            ],
            Inherit::Nothing,
        );
        with_test_hooks(&mut command);
        let run = output(command);
        assert_refused(
            &run,
            &fixture,
            provider,
            "landlock",
            "abi_floor",
            &format!(
                "this kernel's Landlock ABI {host} cannot deny {TEST_FUTURE_FS_NAME} (needs ABI {TEST_FUTURE_FS_ABI})"
            ),
        );
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(
            stderr.contains(&format!(
                "Landlock ABI {host} is below the required {required}"
            )),
            "{provider}: extra floor hidden\n{stderr}"
        );
    }
}

#[test]
fn real_empty_fault_pipe_is_not_a_start() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("empty-pipe", provider);
        let mut command = launch_command(
            &launcher(),
            provider,
            &fixture,
            &["--test-empty-pipe"],
            Inherit::Nothing,
        );
        with_test_hooks(&mut command);
        let run = output(command);
        assert_refused(
            &run,
            &fixture,
            provider,
            "launch",
            "report",
            "the child ended before it wrote a fault or started",
        );
    }
}

#[test]
fn real_sigkill_returned_pid_tears_down_namespace() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("sigkill-init", provider);
        let mut command = launch_command(&launcher(), provider, &fixture, &[], Inherit::Nothing);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("cannot start the launcher");
        let _stdin = child.stdin.take().unwrap();
        let (pid, lines) = read_until_ready(&mut child, provider);
        require_line(&lines, "nspid=", provider);
        let provider_pid = innermost_child(pid)
            .unwrap_or_else(|| panic!("NOT RUN: no provider pid under init {pid} ({provider})"));

        let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        assert_eq!(sent, 0, "{provider}: kill({pid}, SIGKILL) failed");

        let status = wait_with_timeout(&mut child, 5).unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{provider}: launcher did not exit after SIGKILL to pid {pid}");
        });
        assert_eq!(
            status
                .code()
                .or_else(|| status.signal().map(|sig| 128 + sig)),
            Some(128 + libc::SIGKILL),
            "{provider}: expected 128+SIGKILL, got {status:?}"
        );
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "{provider}: init pid {pid} still exists after SIGKILL"
        );
        assert!(
            !std::path::Path::new(&format!("/proc/{provider_pid}")).exists(),
            "{provider}: provider pid {provider_pid} survived SIGKILL of the returned pid"
        );
    }
}

#[test]
fn real_daemonize_keeps_namespace_until_init_dies() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("daemonize", provider);
        let mut command = launch_command(&launcher(), provider, &fixture, &[], Inherit::Nothing);
        command
            .arg("--daemonize")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("cannot start the launcher");
        let _stdin = child.stdin.take().unwrap();
        let (pid, lines) = read_until_ready(&mut child, provider);
        require_line(&lines, "nspid=", provider);

        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            child.try_wait().unwrap().is_none(),
            "{provider}: launcher exited after the provider daemonized"
        );
        let leftover = innermost_child(pid)
            .unwrap_or_else(|| panic!("{provider}: daemonized grandchild gone under init {pid}"));
        assert!(
            std::path::Path::new(&format!("/proc/{leftover}")).exists(),
            "{provider}: daemonized grandchild {leftover} is gone"
        );

        let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        assert_eq!(sent, 0, "{provider}: kill({pid}, SIGKILL) failed");
        let status = wait_with_timeout(&mut child, 5).unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{provider}: launcher did not exit after SIGKILL of init {pid}");
        });
        assert!(
            status.code() == Some(128 + libc::SIGKILL) || status.signal() == Some(libc::SIGKILL),
            "{provider}: expected SIGKILL of init, got {status:?}"
        );
        assert!(
            !std::path::Path::new(&format!("/proc/{leftover}")).exists(),
            "{provider}: daemonized grandchild {leftover} survived SIGKILL of init"
        );
    }
}

#[test]
fn real_init_reaps_orphaned_grandchild() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("orphan-reap", provider);
        let mut command = launch_command(&launcher(), provider, &fixture, &[], Inherit::Nothing);
        command
            .arg("--orphan-exit")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("cannot start the launcher");
        let stdin = child.stdin.take().unwrap();
        let (pid, lines) = read_until_ready(&mut child, provider);
        require_line(&lines, "orphan-forked", provider);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut leftover;
        loop {
            leftover = zombies_with_parent(pid);
            if leftover.is_empty() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            leftover.is_empty(),
            "{provider}: init left grandchild zombies {leftover:?} under {pid}"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "{provider}: launcher exited while the provider is still running"
        );

        drop(stdin);
        let status = wait_with_timeout(&mut child, 5).unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{provider}: launcher did not exit after the provider closed");
        });
        assert_eq!(
            status.code(),
            Some(0),
            "{provider}: expected exit 0, got {status:?}"
        );
    }
}

#[test]
fn real_confine_ready_without_exec_is_not_a_start() {
    for provider in PROVIDERS {
        let fixture = Fixture::new("confine-ready", provider);
        let mut command = launch_command(
            &launcher(),
            provider,
            &fixture,
            &["--test-confine-ready"],
            Inherit::Nothing,
        );
        with_test_hooks(&mut command);
        let run = output(command);
        assert_refused(
            &run,
            &fixture,
            provider,
            "launch",
            "confine_ready",
            "ConfineReady without execve is not a start",
        );
    }
}

#[test]
fn real_lying_rights_probe_refuses() {
    let host = host_landlock_abi();
    for provider in PROVIDERS {
        let fixture = Fixture::new("lie-rights", provider);
        let mut command = launch_command(
            &launcher(),
            provider,
            &fixture,
            &["--test-lie-rights"],
            Inherit::Nothing,
        );
        with_test_hooks(&mut command);
        let run = output(command);
        assert_refused(
            &run,
            &fixture,
            provider,
            "landlock",
            "right_probe",
            &format!("landlock_create_ruleset returned EINVAL (reported ABI {host})"),
        );
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(stderr.contains("truncate"), "{provider}: {stderr}");
        assert!(stderr.contains("ioctl_dev"), "{provider}: {stderr}");
    }
}

#[test]
fn real_production_cli_rejects_test_hooks_without_switch() {
    let fixture = Fixture::new("hooks-off", "did-provider");
    let run = output(launch_command(
        &launcher(),
        "did-provider",
        &fixture,
        &["--test-require-right", TEST_FUTURE_FS_NAME],
        Inherit::Nothing,
    ));
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(64), "{stderr}");
    assert!(
        stderr.contains("unknown argument"),
        "production CLI accepted a test hook:\n{stderr}"
    );
}
