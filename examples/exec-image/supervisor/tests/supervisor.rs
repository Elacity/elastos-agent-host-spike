//! The supervisor on this machine, as root, with real vsock for the exit
//! port and a Unix socket open to everyone for the report (vsock itself
//! cannot connect locally here: no loopback transport). Each test uses its
//! own reserved port. Skips when not root or without vsock.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const SUPERVISOR: &str = env!("CARGO_BIN_EXE_exec-supervisor");

/// One test at a time: each supervisor ends by killing every process of
/// 65534 on the machine, which is right inside the exec VM (one command per
/// boot) but would kill another test's command here.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn can_run() -> bool {
    let root = unsafe { libc::geteuid() } == 0;
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    if !root || fd < 0 {
        eprintln!("skipping: needs root and vsock");
    }
    root && fd >= 0
}

struct Run {
    _dir: tempfile_dir::Dir,
    console: PathBuf,
    socket: PathBuf,
    child: Child,
}

mod tempfile_dir {
    /// A world-traversable temporary directory (the command runs as 65534).
    pub struct Dir(pub std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn start(port: u32, program: &[&str]) -> Run {
    let dir = std::env::temp_dir().join(format!("exec-supervisor-{port}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let console = dir.join("console");
    std::fs::write(&console, b"").unwrap();
    let socket = dir.join("report.sock");
    let child = Command::new(SUPERVISOR)
        .args(["run", "--port", &port.to_string(), "--console"])
        .arg(&console)
        .args(["--host-cid", "1", "--report-unix"])
        .arg(&socket)
        .arg("--")
        .args(program)
        .spawn()
        .unwrap();
    Run {
        _dir: tempfile_dir::Dir(dir),
        console,
        socket,
        child,
    }
}

/// Connect as the host would, retrying until the report is served.
fn read_report(socket: &Path, within: Duration) -> Option<String> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket) {
            let mut text = String::new();
            stream.read_to_string(&mut text).ok()?;
            return Some(text);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn finish(mut run: Run) -> (Option<String>, String, Option<i32>) {
    let report = read_report(&run.socket, Duration::from_secs(30));
    let status = run.child.wait().unwrap().code();
    let console = std::fs::read_to_string(&run.console).unwrap();
    (report, console, status)
}

/// Live (not zombie) processes of 65534 whose command line contains `needle`.
fn live_nobody_processes(needle: &str) -> usize {
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter(|entry| {
            std::fs::read(entry.path().join("cmdline")).is_ok_and(|line| {
                String::from_utf8_lossy(&line)
                    .replace('\0', " ")
                    .contains(needle)
            })
        })
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("status")).ok())
        .filter(|status| {
            status.lines().any(|line| {
                line.strip_prefix("Uid:")
                    .and_then(|ids| ids.split_whitespace().next())
                    == Some("65534")
            }) && !status
                .lines()
                .any(|line| line.starts_with("State:") && line.contains('Z'))
        })
        .count()
}

#[test]
fn a_command_runs_unprivileged_and_its_code_is_reported() {
    let _serial = serial();
    if !can_run() {
        return;
    }
    let run = start(
        1001,
        &[
            "/bin/sh",
            "-c",
            "grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/self/status; exit 7",
        ],
    );
    let (report, console, status) = finish(run);
    assert_eq!(report.as_deref(), Some("7\n"), "{console}");
    assert_eq!(status, Some(0));
    for line in [
        "Uid:\t65534\t65534\t65534\t65534",
        "Gid:\t65534\t65534\t65534\t65534",
        "CapInh:\t0000000000000000",
        "CapPrm:\t0000000000000000",
        "CapEff:\t0000000000000000",
        "CapBnd:\t0000000000000000",
        "CapAmb:\t0000000000000000",
        "NoNewPrivs:\t1",
    ] {
        assert!(console.contains(line), "missing {line:?} in {console}");
    }
    let groups = console
        .lines()
        .find(|line| line.starts_with("Groups:"))
        .unwrap();
    assert_eq!(groups.trim_end(), "Groups:", "{console}");
    assert!(!console.contains("elastos-exec-exit"));
}

#[test]
fn a_command_killed_by_a_signal_is_not_reported_as_zero() {
    let _serial = serial();
    if !can_run() {
        return;
    }
    let run = start(1002, &["/bin/sh", "-c", "kill -9 $$"]);
    let (report, console, _) = finish(run);
    assert_eq!(report.as_deref(), Some("137\n"), "{console}");
}

#[test]
fn the_command_cannot_bind_the_exit_port() {
    let _serial = serial();
    if !can_run() {
        return;
    }
    let run = start(1003, &[SUPERVISOR, "probe", "bind", "--port", "1003"]);
    let (report, console, _) = finish(run);
    assert!(
        console.contains("probe-bind: port 1003: EACCES"),
        "{console}"
    );
    assert!(
        console.contains("exit port 1003 held (a second bind gets EADDRINUSE)"),
        "{console}"
    );
    assert_eq!(report.as_deref(), Some("0\n"), "{console}");
}

#[test]
fn a_forged_report_never_reaches_the_host() {
    let _serial = serial();
    if !can_run() {
        return;
    }
    let dir_socket =
        std::env::temp_dir().join(format!("exec-supervisor-1004-{}", std::process::id()));
    let socket = dir_socket.join("report.sock");
    let run = start(
        1004,
        &[
            SUPERVISOR,
            "probe",
            "report",
            "--port",
            "1004",
            "--report-unix",
            socket.to_str().unwrap(),
        ],
    );
    let (report, console, _) = finish(run);
    assert_eq!(report.as_deref(), Some("3\n"), "{console}");
    assert!(!console.contains("wrote a forged report"), "{console}");
    assert_eq!(
        live_nobody_processes("probe report --port 1004"),
        0,
        "a process of the command was left running"
    );
}

#[test]
fn no_report_is_served_before_the_command_ends() {
    let _serial = serial();
    if !can_run() {
        return;
    }
    let mut run = start(1005, &["/bin/sh", "-c", "sleep 2; exit 0"]);
    assert_eq!(read_report(&run.socket, Duration::from_millis(1_200)), None);
    assert_eq!(
        read_report(&run.socket, Duration::from_secs(30)).as_deref(),
        Some("0\n")
    );
    assert_eq!(run.child.wait().unwrap().code(), Some(0));
}

#[test]
fn a_program_that_cannot_run_reports_127() {
    let _serial = serial();
    if !can_run() {
        return;
    }
    let run = start(1006, &["/no/such/program"]);
    let (report, _, _) = finish(run);
    assert_eq!(report.as_deref(), Some("127\n"));
}

#[test]
fn nothing_runs_unless_the_exit_port_is_held() {
    let _serial = serial();
    if !can_run() {
        return;
    }
    // Someone else holds the port first.
    let holder = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_cid = libc::VMADDR_CID_ANY;
    address.svm_port = 1007;
    let bound = unsafe {
        libc::bind(
            holder,
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    assert_eq!(bound, 0);
    let marker = std::env::temp_dir().join(format!("exec-supervisor-ran-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let mut run = start(
        1007,
        &["/bin/sh", "-c", &format!("touch {}", marker.display())],
    );
    assert_eq!(run.child.wait().unwrap().code(), Some(1));
    assert!(!marker.exists(), "the command ran without the exit port");
    assert_eq!(read_report(&run.socket, Duration::from_millis(300)), None);
    assert!(std::fs::read_to_string(&run.console)
        .unwrap()
        .contains("cannot hold exit port 1007"));
    unsafe { libc::close(holder) };
}
