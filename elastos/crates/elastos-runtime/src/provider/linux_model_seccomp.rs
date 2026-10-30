//! Linux model-provider socket boundary. The provider and its descendants may
//! create Unix sockets for the private local engine path, but cannot create
//! Internet sockets. Runtime closes all other inherited descriptors on exec.

use std::io;
use tokio::process::Command;

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000 | libc::EPERM as u32;
const CLOSE_RANGE_CLOEXEC: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn install_on_command(command: &mut Command) -> io::Result<()> {
    let mut code = vec![
        stmt(LD_W_ABS, 4), // seccomp_data.arch
        jump(JEQ_K, AUDIT_ARCH, 1, 0),
        stmt(RET_K, RET_KILL_PROCESS),
        stmt(LD_W_ABS, 0), // seccomp_data.nr
        jump(JGE_K, 0x4000_0000, 0, 1),
        stmt(RET_K, RET_KILL_PROCESS),
    ];
    for syscall in [libc::SYS_socket, libc::SYS_socketpair] {
        code.extend([
            jump(JEQ_K, syscall as u32, 0, 4),
            stmt(LD_W_ABS, 16), // seccomp_data.args[0], low 32 bits
            jump(JEQ_K, libc::AF_UNIX as u32, 1, 0),
            stmt(RET_K, RET_ERRNO),
            stmt(RET_K, RET_ALLOW),
        ]);
    }
    // These syscalls could create sockets or receive an external descriptor
    // without the socket() gate. Ordinary local HTTP uses read/write instead.
    for syscall in [
        libc::SYS_io_uring_setup,
        libc::SYS_pidfd_getfd,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
    ] {
        code.extend([jump(JEQ_K, syscall as u32, 0, 1), stmt(RET_K, RET_ERRNO)]);
    }
    code.push(stmt(RET_K, RET_ALLOW));
    let length =
        u16::try_from(code.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // All allocation occurs in Runtime before fork. The pre-exec closure only
    // makes raw syscalls and returns an errno if confinement cannot attach.
    unsafe {
        use std::os::unix::process::CommandExt as _;
        command.as_std_mut().pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            let program = libc::sock_fprog {
                len: length,
                filter: code.as_mut_ptr(),
            };
            if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn install_on_command(_: &mut Command) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux model socket confinement is unavailable on this architecture",
    ))
}

#[cfg(all(
    test,
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "macos")
))]
mod tests {
    use super::*;

    /// Printed by the filtered probe when its row passes. A child that exits
    /// zero without it exercised nothing and FAILS.
    const PROBE_TOKEN: &str = "elastos-seccomp-row-probe-passed";
    const ROW_VAR: &str = "ELASTOS_LINUX_MODEL_SECCOMP_ROW";
    const PROBE_TEST: &str =
        "provider::linux_model_seccomp::tests::child_and_descendant_have_no_inet_sockets";

    /// Expected result of a row: EPERM, a permitted call, or SIGSYS.
    const EPERM: u8 = 0;
    const PERMITTED: u8 = 1;
    const KILLED: u8 = 2;

    /// A row body is a plain `fn` taking the row's three syscall arguments, so
    /// the table stays a table and no row captures state.
    type Body = fn(libc::c_int, libc::c_int, libc::c_int) -> libc::c_long;

    struct Row {
        name: &'static str,
        body: Body,
        domain: libc::c_int,
        kind: libc::c_int,
        protocol: libc::c_int,
        outcome: u8,
    }

    fn errno() -> libc::c_int {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn sys(nr: libc::c_long, a: [libc::c_ulong; 6]) -> libc::c_long {
        unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]) }
    }

    fn close_all(fds: &[libc::c_int]) {
        for fd in fds {
            unsafe { libc::close(*fd) };
        }
    }

    /// `socket` with the row's own family, type and protocol. Each denied shape
    /// opens on this host without the filter, so only the socket gate can turn
    /// it into EPERM.
    fn socket_body(domain: libc::c_int, kind: libc::c_int, protocol: libc::c_int) -> libc::c_long {
        sys(
            libc::SYS_socket,
            [domain as _, kind as _, protocol as _, 0, 0, 0],
        )
    }

    /// `socketpair` of the row's family, type and protocol. A permitted pair (the
    /// Unix control) is closed again, so the row leaks no descriptor.
    fn socketpair_body(
        domain: libc::c_int,
        kind: libc::c_int,
        protocol: libc::c_int,
    ) -> libc::c_long {
        let mut fds = [-1 as libc::c_int; 2];
        let rc = sys(
            libc::SYS_socketpair,
            [
                domain as _,
                kind as _,
                protocol as _,
                fds.as_mut_ptr() as _,
                0,
                0,
            ],
        );
        if rc >= 0 {
            close_all(&fds);
        }
        rc
    }

    /// `getpid` must stay permitted: the filter denies by number, not by class.
    fn getpid_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        sys(libc::SYS_getpid, [0; 6])
    }

    /// The x32 boundary: `nr >= 0x40000000` must be killed, not mapped onto the
    /// low x86_64 syscall that shares its low 32 bits.
    fn x32_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        sys(0x4000_0000, [0; 6])
    }

    /// Each denied family through `socket`, the Unix controls through both
    /// creators, `getpid` and the x32 boundary. Each entry is its own probe run,
    /// so a removed deny entry turns exactly that row red.
    #[rustfmt::skip]
    fn rows() -> Vec<Row> {
        let row = |name, body, domain, kind, protocol, outcome| Row {
            name, body, domain, kind, protocol, outcome,
        };
        let (tcp, raw) = (libc::SOCK_STREAM, libc::SOCK_RAW);
        vec![
            row("socket+AF_INET", socket_body, libc::AF_INET, tcp, libc::IPPROTO_TCP, EPERM),
            row("socket+AF_INET6", socket_body, libc::AF_INET6, tcp, libc::IPPROTO_TCP, EPERM),
            row("socket+AF_NETLINK", socket_body, libc::AF_NETLINK, raw, 0, EPERM),
            row("socket+AF_UNIX", socket_body, libc::AF_UNIX, tcp, 0, PERMITTED),
            row("socketpair+AF_UNIX", socketpair_body, libc::AF_UNIX, tcp, 0, PERMITTED),
            row("getpid", getpid_body, 0, 0, 0, PERMITTED),
            row("nr==0x40000000", x32_body, 0, 0, 0, KILLED),
        ]
    }

    fn check(name: &str, outcome: u8, rc: libc::c_long) {
        match outcome {
            EPERM => {
                assert_eq!(rc, -1, "row {name}: expected -1, got {rc}");
                assert_eq!(
                    errno(),
                    libc::EPERM,
                    "row {name}: expected EPERM, got errno {}",
                    errno()
                );
            }
            PERMITTED => assert!(
                rc >= 0,
                "row {name}: expected a permitted call, got {rc} (errno {})",
                errno()
            ),
            _ => panic!("row {name}: returned {rc}, expected SIGSYS"),
        }
    }

    /// Runs one named row inside the filtered probe or its descendant.
    fn probe(wanted: &str) {
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
            1
        );
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) },
            2,
            "the model filter was not attached"
        );
        let row = rows()
            .into_iter()
            .find(|row| row.name == wanted)
            .unwrap_or_else(|| panic!("unknown probe row {wanted}"));
        let rc = (row.body)(row.domain, row.kind, row.protocol);
        check(row.name, row.outcome, rc);
        println!("{PROBE_TOKEN} {}", row.name);
    }

    #[tokio::test]
    async fn child_and_descendant_have_no_inet_sockets() {
        let name =
            "provider::linux_model_seccomp::tests::child_and_descendant_have_no_inet_sockets";
        let executable = std::env::current_exe().unwrap();
        // A row probe outranks the legacy stage variable, which the descendant
        // body below leaves in this process's environment for its children.
        if let Ok(row) = std::env::var(ROW_VAR) {
            probe(&row);
            return;
        }
        if let Ok(stage) = std::env::var("ELASTOS_LINUX_MODEL_SECCOMP_PROBE") {
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
                1
            );
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }, 2);
            for domain in [libc::AF_INET, libc::AF_INET6] {
                let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
                assert_eq!(fd, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            }
            let unix = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            assert!(unix >= 0);
            unsafe { libc::close(unix) };
            if stage == "child" {
                let output = std::process::Command::new(&executable)
                    .arg("--exact")
                    .arg(name)
                    .arg("--nocapture")
                    .env("ELASTOS_LINUX_MODEL_SECCOMP_PROBE", "descendant")
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains("descendant-probe-ok"),
                    "{}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
            println!("{stage}-probe-ok");
            return;
        }
        let mut command = Command::new(executable);
        command
            .arg("--exact")
            .arg(name)
            .arg("--nocapture")
            .env("ELASTOS_LINUX_MODEL_SECCOMP_PROBE", "child")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        install_on_command(&mut command).unwrap();
        let output = command.output().await.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("child-probe-ok"),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// Reaps one probe child without blocking the runtime thread and kills it
    /// at `limit`, so a probe stuck in a permitted syscall fails by name. The
    /// child stays owned by the caller, so its stdout pipe survives the wait.
    async fn run_probe(
        child: &mut tokio::process::Child,
        limit: std::time::Duration,
    ) -> Option<std::process::ExitStatus> {
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = child.try_wait().expect("probe wait failed") {
                return Some(status);
            }
            if start.elapsed() > limit {
                let _ = child.start_kill();
                return child.wait().await.ok();
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// Harness half: each row runs in its own filtered child through
    /// `install_on_command`, and one row's failure keeps the others reporting
    /// their own name. A row that exits zero without printing the pass token
    /// fails, so a probe that never exercised its syscall cannot pass.
    #[tokio::test]
    async fn every_denied_syscall_and_domain_has_a_row() {
        let all = rows();
        let total = all.len();
        let mut failures = Vec::new();
        // Control: each EPERM row's call must succeed without the filter, so
        // only the gate under test can refuse it. The SIGSYS row is killed by
        // the arch gate itself and has no unfiltered call to try.
        for row in &all {
            let rc = match row.outcome {
                EPERM => (row.body)(row.domain, row.kind, row.protocol),
                _ => 0,
            };
            assert!(rc >= 0, "row {} is not valid unfiltered", row.name);
        }
        for row in all {
            let name = row.name;
            let mut command = Command::new(std::env::current_exe().expect("test executable path"));
            command
                .arg("--exact")
                .arg(PROBE_TEST)
                .arg("--nocapture")
                .env(ROW_VAR, row.name)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null());
            install_on_command(&mut command).expect("filter attach failed");
            let mut child = command.spawn().expect("probe child did not start");
            let deadline = std::time::Duration::from_secs(20);
            let result: Result<(), String> = match run_probe(&mut child, deadline).await {
                None => Err(format!("row {name}: probe child did not finish")),
                Some(status) if row.outcome == KILLED => {
                    use std::os::unix::process::ExitStatusExt as _;
                    if status.signal() == Some(libc::SIGSYS) {
                        Ok(())
                    } else {
                        Err(format!("row {name}: expected SIGSYS, status {status:?}"))
                    }
                }
                Some(status) if !status.success() => Err(format!("row {name} failed: {status:?}")),
                // The child must also prove it exercised the row.
                Some(_) => {
                    let mut stdout = String::new();
                    if let Some(pipe) = child.stdout.as_mut() {
                        use tokio::io::AsyncReadExt as _;
                        pipe.read_to_string(&mut stdout).await.ok();
                    }
                    if stdout.contains(PROBE_TOKEN) {
                        Ok(())
                    } else {
                        Err(format!("row {name}: no pass token"))
                    }
                }
            };
            if let Err(failure) = result {
                failures.push(failure);
            }
        }
        println!("ROWS: {total} checked, {} failed", failures.len());
        assert!(
            failures.is_empty(),
            "{} of {total} rows failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
