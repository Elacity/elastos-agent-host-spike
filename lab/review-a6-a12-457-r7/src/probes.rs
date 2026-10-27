//! r7 hunts compiled only inside the #457 worktree for one run. Restored after.

use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::a12;
use crate::a6;

fn hunt(id: &str, verdict: &str, detail: &str) {
    println!("HUNT {id}: {verdict} | {detail}");
}

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn restore_env(key: &str, previous: Option<std::ffi::OsString>) {
    match previous {
        Some(value) => std::env::set_var(key, value),
        None => std::env::remove_var(key),
    }
}

fn leftovers_contain(found: &[PathBuf], path: &Path) -> bool {
    found
        .iter()
        .any(|p| p == path || p.ends_with(path.file_name().unwrap_or_default()))
}

fn unique_under(root: &Path, prefix: &str) -> PathBuf {
    root.join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        stamp()
    ))
}

struct PathCleanup {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl PathCleanup {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            dirs: Vec::new(),
        }
    }
    fn file(&mut self, path: PathBuf) -> PathBuf {
        self.files.push(path.clone());
        path
    }
    fn dir(&mut self, path: PathBuf) -> PathBuf {
        self.dirs.push(path.clone());
        path
    }
}

impl Drop for PathCleanup {
    fn drop(&mut self) {
        for path in self.files.iter().rev() {
            let _ = fs::remove_file(path);
        }
        for path in self.dirs.iter().rev() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn snapshot_or_skip(id: &str) -> Option<a12::FsSnapshot> {
    match a12::snapshot_run_window() {
        Ok(snap) => Some(snap),
        Err(reason) => {
            hunt(id, "INCONCLUSIVE", &reason);
            None
        }
    }
}

fn leftovers_or_skip(id: &str, before: &a12::FsSnapshot) -> Option<Result<Vec<PathBuf>, String>> {
    match a12::leftovers_in_run_window(before) {
        Ok(found) => Some(Ok(found)),
        Err(reason) => Some(Err(reason)),
    }
}

fn host_not_run(part: a12::HostPart, id: &str) {
    match part {
        a12::HostPart::NotRun(reason) => hunt(id, "NOT RUN", &reason),
        a12::HostPart::Pass(line) => hunt(id, "SURVIVED", &format!("HostPart PASS: {line}")),
        a12::HostPart::Fail(line) => hunt(id, "FAIL", &line),
    }
}

// ---------- r6 claim reconfirm ----------

#[test]
fn r7_ra6_ready_journey_still_blocked() {
    match a6::resident_two_instance_token_journey() {
        a6::JourneyStatus::Blocked { ask, reason } => {
            hunt("r7-ra6-current", "BLOCKED", &format!("ask={ask} {reason}"))
        }
        a6::JourneyStatus::Pass(line) => hunt(
            "r7-ra6-current",
            "SURVIVED",
            &format!("PASS without two resident instances: {line}"),
        ),
        a6::JourneyStatus::Fail(line) => hunt("r7-ra6-current", "FAIL", &line),
    }
}

#[test]
fn r7_host_parts_stay_not_run() {
    host_not_run(a12::detached_child_after_return_host_part(), "r7-detached-hostpart");
    host_not_run(a12::bind_mount_host_part(), "r7-bind-hostpart");
    host_not_run(a12::pid_namespace_host_part(), "r7-pidns-hostpart");
    host_not_run(a12::run_user_uid_host_part(), "r7-run-user-hostpart");
    host_not_run(a12::watch_sysctl_host_part(), "r7-watch-sysctl-hostpart");
}

#[test]
fn r7_hardlink_out_dest_is_listed() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let watch = clean.dir(unique_under(Path::new("/var/tmp"), "r7-hl-watch"));
    let out = clean.dir(unique_under(Path::new("/home/ubuntu"), "r7-hl-out"));
    let _ = fs::create_dir_all(&watch);
    let _ = fs::create_dir_all(&out);
    let src = clean.file(watch.join("keep.txt"));
    let dest = clean.file(out.join("keep.txt"));
    if fs::write(&src, b"hardlink leftover\n").is_err() || fs::hard_link(&src, &dest).is_err() {
        hunt("r7-hardlink-out", "INCONCLUSIVE", "write or hard_link failed");
        return;
    }
    let Some(before) = snapshot_or_skip("r7-hardlink-out") else {
        return;
    };
    let _ = fs::remove_file(&src);
    match leftovers_or_skip("r7-hardlink-out", &before) {
        Some(Ok(found)) if leftovers_contain(&found, &dest) => {
            hunt("r7-hardlink-out", "CAUGHT", "outside hardlink dest listed")
        }
        Some(Ok(found)) => hunt(
            "r7-hardlink-out",
            "SURVIVED",
            &format!("dest leftover unseen: {found:?}"),
        ),
        Some(Err(reason)) => hunt("r7-hardlink-out", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_home_cache_while_xdg_set() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let sandbox = clean.dir(unique_under(Path::new("/home/ubuntu"), "r7-home-cache"));
    let xdg = sandbox.join("xdg-cache");
    let home_cache = sandbox.join(".cache");
    fs::create_dir_all(&xdg).unwrap();
    fs::create_dir_all(&home_cache).unwrap();
    let prev_home = std::env::var_os("HOME");
    let prev_cache = std::env::var_os("XDG_CACHE_HOME");
    std::env::set_var("HOME", &sandbox);
    std::env::set_var("XDG_CACHE_HOME", &xdg);
    let leftover = clean.file(home_cache.join("secret.txt"));
    let Some(before) = snapshot_or_skip("r7-home-cache") else {
        restore_env("HOME", prev_home);
        restore_env("XDG_CACHE_HOME", prev_cache);
        return;
    };
    fs::write(&leftover, b"home-cache leftover\n").unwrap();
    let result = leftovers_or_skip("r7-home-cache", &before);
    restore_env("HOME", prev_home);
    restore_env("XDG_CACHE_HOME", prev_cache);
    match result {
        Some(Ok(found)) if leftovers_contain(&found, &leftover) => {
            hunt("r7-home-cache", "CAUGHT", "$HOME/.cache leftover listed with XDG set")
        }
        Some(Ok(found)) => hunt(
            "r7-home-cache",
            "SURVIVED",
            &format!("HOME/.cache leftover unseen: {found:?}"),
        ),
        Some(Err(reason)) => hunt("r7-home-cache", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_subdir_create_then_delete() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let dir = clean.dir(unique_under(Path::new("/var/tmp"), "r7-subwatch"));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("gone.txt");
    let Some(before) = snapshot_or_skip("r7-subdir-ephemeral") else {
        return;
    };
    fs::write(&path, b"existed only in a /var/tmp subdir\n").unwrap();
    fs::remove_file(&path).unwrap();
    match leftovers_or_skip("r7-subdir-ephemeral", &before) {
        Some(Ok(found)) if leftovers_contain(&found, &path) => {
            hunt("r7-subdir-ephemeral", "CAUGHT", "subdir create-then-delete listed")
        }
        Some(Ok(found)) => hunt(
            "r7-subdir-ephemeral",
            "SURVIVED",
            &format!("subdir ghost unseen: {found:?}"),
        ),
        Some(Err(reason)) => hunt("r7-subdir-ephemeral", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_rename_out_dest() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let src = clean.file(unique_under(Path::new("/var/tmp"), "r7-ren-src").with_extension("txt"));
    let dest = clean.file(unique_under(Path::new("/home/ubuntu"), "r7-ren-dest").with_extension("txt"));
    let Some(before) = snapshot_or_skip("r7-rename-out") else {
        return;
    };
    fs::write(&src, b"rename leftover\n").unwrap();
    fs::rename(&src, &dest).unwrap();
    match leftovers_or_skip("r7-rename-out", &before) {
        Some(Ok(found)) if leftovers_contain(&found, &dest) => {
            hunt("r7-rename-out", "CAUGHT", "rename dest leftover listed")
        }
        Some(Ok(found)) => hunt(
            "r7-rename-out",
            "SURVIVED",
            &format!("rename dest unseen: {found:?}"),
        ),
        Some(Err(reason)) => hunt("r7-rename-out", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_otmpfile_unlink_in_subdir() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let dir = clean.dir(unique_under(Path::new("/var/tmp"), "r7-otmp-sub"));
    let _ = fs::create_dir_all(&dir);
    let dest = dir.join("gone.txt");
    let Some(before) = snapshot_or_skip("r7-otmpfile-unlink") else {
        return;
    };
    let parent = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
    let fd = unsafe {
        libc::open(
            parent.as_ptr(),
            libc::O_RDWR | libc::O_TMPFILE | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        hunt(
            "r7-otmpfile-unlink",
            "INCONCLUSIVE",
            &format!("O_TMPFILE: {}", std::io::Error::last_os_error()),
        );
        return;
    }
    let dest_c = std::ffi::CString::new(dest.as_os_str().as_bytes()).unwrap();
    let rc = unsafe {
        libc::linkat(
            fd,
            std::ffi::CString::new("").unwrap().as_ptr(),
            libc::AT_FDCWD,
            dest_c.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    unsafe { libc::close(fd) };
    if rc != 0 {
        hunt(
            "r7-otmpfile-unlink",
            "INCONCLUSIVE",
            &format!("linkat: {}", std::io::Error::last_os_error()),
        );
        return;
    }
    let _ = fs::remove_file(&dest);
    match leftovers_or_skip("r7-otmpfile-unlink", &before) {
        Some(Ok(found)) if leftovers_contain(&found, &dest) => {
            hunt("r7-otmpfile-unlink", "CAUGHT", "O_TMPFILE+unlink ghost listed")
        }
        Some(Ok(found)) => hunt(
            "r7-otmpfile-unlink",
            "SURVIVED",
            &format!("O_TMPFILE unlink unseen: {found:?}"),
        ),
        Some(Err(reason)) => hunt("r7-otmpfile-unlink", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_setsid_write_after_return() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let path = clean.file(unique_under(Path::new("/var/tmp"), "r7-detached").with_extension("txt"));
    let Some(before) = snapshot_or_skip("r7-detached-after-return") else {
        return;
    };
    let leftovers = match leftovers_or_skip("r7-detached-after-return", &before) {
        Some(Ok(found)) => found,
        Some(Err(reason)) => {
            hunt("r7-detached-after-return", "INCONCLUSIVE", &reason);
            return;
        }
        None => return,
    };
    let script = format!(
        "setsid /bin/sh -c 'sleep 0.2; printf detached > \"$1\"' _ '{}'",
        path.display()
    );
    let _ = Command::new("/bin/sh").args(["-c", &script]).status();
    std::thread::sleep(Duration::from_millis(400));
    let wrote = path.is_file();
    let saw = leftovers_contain(&leftovers, &path);
    if !wrote {
        hunt(
            "r7-detached-after-return",
            "INCONCLUSIVE",
            "setsid child did not write",
        );
        return;
    }
    if saw {
        hunt(
            "r7-detached-after-return",
            "CAUGHT",
            "census listed the path before the child wrote",
        );
    } else {
        hunt(
            "r7-detached-after-return",
            "SURVIVED",
            "setsid child wrote under /var/tmp after leftovers_in_run_window returned Ok; HostPart is NOT RUN, not a closed PASS",
        );
    }
}

// ---------- new false-PASS hunts ----------

#[test]
fn r7_memfd_create_anonymous() {
    let _lock = a12::lock_real_root();
    let Some(before) = snapshot_or_skip("r7-memfd") else {
        return;
    };
    let name = std::ffi::CString::new("r7-memfd").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) };
    if fd < 0 {
        hunt(
            "r7-memfd",
            "INCONCLUSIVE",
            &format!("memfd_create: {}", std::io::Error::last_os_error()),
        );
        return;
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd as i32) };
    let _ = file.write_all(b"memfd leftover bytes\n");
    let leftovers = leftovers_or_skip("r7-memfd", &before);
    drop(file);
    match leftovers {
        Some(Ok(found)) => {
            let saw_proc = found.iter().any(|p| {
                p.starts_with("/proc/") && p.to_string_lossy().contains("/fd/")
            });
            if saw_proc {
                hunt("r7-memfd", "CAUGHT", "census listed a /proc fd path for memfd");
            } else {
                hunt(
                    "r7-memfd",
                    "OUT OF SCOPE",
                    "anonymous memfd has no directory entry; A12 watches disk paths. Not a leftover after the process exits.",
                );
            }
        }
        Some(Err(reason)) => hunt("r7-memfd", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_shm_open_in_dev_shm() {
    let _lock = a12::lock_real_root();
    let name = format!("/r7-shm-{}-{}", std::process::id(), stamp());
    let c_name = std::ffi::CString::new(name.as_str()).unwrap();
    let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600) };
    if fd < 0 {
        hunt(
            "r7-shm-open",
            "INCONCLUSIVE",
            &format!("shm_open: {}", std::io::Error::last_os_error()),
        );
        return;
    }
    let path = PathBuf::from("/dev/shm").join(name.trim_start_matches('/'));
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let _ = file.write_all(b"shm leftover\n");
    drop(file);
    let Some(before) = snapshot_or_skip("r7-shm-open") else {
        let _ = unsafe { libc::shm_unlink(c_name.as_ptr()) };
        return;
    };
    // Recreate after snapshot so the object is a run-window leftover.
    let _ = unsafe { libc::shm_unlink(c_name.as_ptr()) };
    let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600) };
    if fd >= 0 {
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let _ = file.write_all(b"shm leftover after snapshot\n");
    }
    let result = leftovers_or_skip("r7-shm-open", &before);
    let _ = unsafe { libc::shm_unlink(c_name.as_ptr()) };
    match result {
        Some(Ok(found)) if leftovers_contain(&found, &path) => {
            hunt("r7-shm-open", "CAUGHT", "/dev/shm shm_open leftover listed")
        }
        Some(Ok(found)) => hunt(
            "r7-shm-open",
            "SURVIVED",
            &format!("shm_open leftover unseen at {}: {found:?}", path.display()),
        ),
        Some(Err(reason)) => hunt("r7-shm-open", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_unix_socket_file() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let path = clean.file(unique_under(Path::new("/var/tmp"), "r7-sock"));
    let Some(before) = snapshot_or_skip("r7-unix-socket") else {
        return;
    };
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(err) => {
            hunt("r7-unix-socket", "INCONCLUSIVE", &format!("bind: {err}"));
            return;
        }
    };
    match leftovers_or_skip("r7-unix-socket", &before) {
        Some(Ok(found)) if leftovers_contain(&found, &path) => {
            hunt("r7-unix-socket", "CAUGHT", "unix socket file listed")
        }
        Some(Ok(found)) => hunt(
            "r7-unix-socket",
            "SURVIVED",
            &format!("unix socket leftover unseen: {found:?}"),
        ),
        Some(Err(reason)) => hunt(
            "r7-unix-socket",
            "FAIL-CLOSED",
            &format!("census refused a socket leftover: {reason}"),
        ),
        None => {}
    }
    drop(listener);
}

#[test]
fn r7_mkfifo() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let path = clean.file(unique_under(Path::new("/var/tmp"), "r7-fifo"));
    let Some(before) = snapshot_or_skip("r7-mkfifo") else {
        return;
    };
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    if rc != 0 {
        hunt(
            "r7-mkfifo",
            "INCONCLUSIVE",
            &format!("mkfifo: {}", std::io::Error::last_os_error()),
        );
        return;
    }
    // Do not call leftovers_in_run_window here. hash_whole_file_sparse uses
    // blocking File::open; that would hang this process and poison LIVE_WATCH.
    let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/a12.rs"));
    let blocking_open = source.contains("let Ok(file) = fs::File::open(path)");
    let open_status = Command::new("timeout")
        .args([
            "2",
            "python3",
            "-I",
            "-c",
            &format!(
                "import os; os.open({path:?}, os.O_RDONLY) if False else open({path:?}, 'rb')"
            ),
        ])
        .status();
    let timed_out = open_status.map(|s| s.code() == Some(124)).unwrap_or(false);
    if blocking_open && timed_out {
        hunt(
            "r7-mkfifo",
            "SURVIVED",
            "python open() on the FIFO timed out; census File::open has no O_NONBLOCK, so a leftover fifo can hang leftovers_in_run_window",
        );
    } else if blocking_open {
        hunt(
            "r7-mkfifo",
            "SURVIVED",
            &format!(
                "source still uses blocking File::open (child timed_out={timed_out}); fifo leftover is unsafe to census in-process"
            ),
        );
    } else {
        hunt(
            "r7-mkfifo",
            "CAUGHT",
            "census open is no longer a blocking File::open",
        );
    }
    let _ = before;
}

#[test]
fn r7_proc_self_fd_write_after_unlink() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let path = clean.file(unique_under(Path::new("/var/tmp"), "r7-procfd").with_extension("txt"));
    let Some(before) = snapshot_or_skip("r7-proc-fd") else {
        return;
    };
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(&path)
        .unwrap();
    let fd = file.as_raw_fd();
    fs::remove_file(&path).unwrap();
    let proc_path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    let mut via = fs::OpenOptions::new().write(true).open(&proc_path).unwrap();
    let _ = via.write_all(b"wrote via /proc/self/fd after unlink\n");
    drop(via);
    drop(file);
    match leftovers_or_skip("r7-proc-fd", &before) {
        Some(Ok(found)) if leftovers_contain(&found, &path) => {
            hunt(
                "r7-proc-fd",
                "CAUGHT",
                "create+unlink then /proc/self/fd write produced a live-watch leftover",
            )
        }
        Some(Ok(found)) => hunt(
            "r7-proc-fd",
            "SURVIVED",
            &format!("unlinked inode written via /proc/self/fd unseen: {found:?}"),
        ),
        Some(Err(reason)) => hunt("r7-proc-fd", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_scm_rights_helper_write() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let path = clean.file(unique_under(Path::new("/var/tmp"), "r7-scm").with_extension("txt"));
    let sock = clean.file(unique_under(Path::new("/var/tmp"), "r7-scm-sock"));
    let Some(before) = snapshot_or_skip("r7-scm-rights") else {
        return;
    };
    fs::write(&path, b"before helper\n").unwrap();
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(err) => {
            hunt("r7-scm-rights", "INCONCLUSIVE", &format!("bind: {err}"));
            return;
        }
    };
    let script = format!(
        r#"
import os, socket, array, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect({sock:?})
fds = array.array('i')
msg, anc, _, _ = s.recvmsg(1, socket.CMSG_SPACE(4))
for cmsg in anc:
    if cmsg[0] == socket.SOL_SOCKET and cmsg[1] == socket.SCM_RIGHTS:
        fds.frombytes(cmsg[2][:4])
if not fds:
    sys.exit(2)
os.write(fds[0], b'helper-via-scm-rights\n')
os.close(fds[0])
"#
    );
    let mut child = Command::new("python3")
        .args(["-I", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("python helper");
    let (stream, _) = listener.accept().unwrap();
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    let fd = file.as_raw_fd();
    send_fd(&stream, fd);
    drop(file);
    let _ = child.wait();
    drop(listener);
    match leftovers_or_skip("r7-scm-rights", &before) {
        Some(Ok(found)) if leftovers_contain(&found, &path) => {
            hunt("r7-scm-rights", "CAUGHT", "SCM_RIGHTS helper write left a named leftover")
        }
        Some(Ok(found)) => hunt(
            "r7-scm-rights",
            "SURVIVED",
            &format!("helper write via SCM_RIGHTS unseen: {found:?}"),
        ),
        Some(Err(reason)) => hunt("r7-scm-rights", "INCONCLUSIVE", &reason),
        None => {}
    }
}

fn send_fd(stream: &UnixStream, fd: i32) {
    let mut hdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut dummy as *mut u8).cast(),
        iov_len: 1,
    };
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];
    hdr.msg_control = cmsg_buf.as_mut_ptr().cast();
    hdr.msg_controllen = cmsg_space;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as _;
        std::ptr::write(libc::CMSG_DATA(cmsg).cast::<i32>(), fd);
        libc::sendmsg(stream.as_raw_fd(), &hdr, 0);
    }
}

#[test]
fn r7_write_after_watch_torn_down() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let path = clean.file(unique_under(Path::new("/var/tmp"), "r7-after-watch").with_extension("txt"));
    let Some(before) = snapshot_or_skip("r7-after-watch") else {
        return;
    };
    let leftovers = match leftovers_or_skip("r7-after-watch", &before) {
        Some(Ok(found)) => found,
        Some(Err(reason)) => {
            hunt("r7-after-watch", "INCONCLUSIVE", &reason);
            return;
        }
        None => return,
    };
    // leftovers_in_run_window drains but does not drop LIVE_WATCH.
    fs::write(&path, b"after census return\n").unwrap();
    let saw = leftovers_contain(&leftovers, &path);
    if saw {
        hunt(
            "r7-after-watch",
            "CAUGHT",
            "write after return was already in the leftover list",
        );
    } else {
        hunt(
            "r7-after-watch",
            "SURVIVED",
            "write after leftovers_in_run_window returned is invisible; LIVE_WATCH is not dropped, but the returned Ok([]) is not a closed window",
        );
    }
}

#[test]
fn r7_xdg_runtime_dir() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let runtime = clean.dir(unique_under(Path::new("/home/ubuntu"), "r7-xdg-runtime"));
    fs::create_dir_all(&runtime).unwrap();
    let prev = std::env::var_os("XDG_RUNTIME_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", &runtime);
    let leftover = clean.file(runtime.join("secret.txt"));
    let roots = a12::writable_temp_roots();
    let listed = roots.iter().any(|r| r == &runtime);
    let Some(before) = snapshot_or_skip("r7-xdg-runtime") else {
        restore_env("XDG_RUNTIME_DIR", prev);
        return;
    };
    fs::write(&leftover, b"xdg-runtime leftover\n").unwrap();
    let result = leftovers_or_skip("r7-xdg-runtime", &before);
    restore_env("XDG_RUNTIME_DIR", prev);
    match result {
        Some(Ok(found)) if leftovers_contain(&found, &leftover) => hunt(
            "r7-xdg-runtime",
            "CAUGHT",
            &format!("XDG_RUNTIME_DIR leftover listed (roots_contain={listed})"),
        ),
        Some(Ok(found)) => hunt(
            "r7-xdg-runtime",
            if listed { "SURVIVED" } else { "SURVIVED" },
            &format!("XDG_RUNTIME_DIR leftover unseen listed={listed}: {found:?}"),
        ),
        Some(Err(reason)) => hunt("r7-xdg-runtime", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_tmpdir_changed_mid_run() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let first = clean.dir(unique_under(Path::new("/home/ubuntu"), "r7-tmpdir-a"));
    let second = clean.dir(unique_under(Path::new("/home/ubuntu"), "r7-tmpdir-b"));
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    let stale = clean.file(second.join("already-there.txt"));
    fs::write(&stale, b"pre-existing in future TMPDIR\n").unwrap();
    let prev = std::env::var_os("TMPDIR");
    std::env::set_var("TMPDIR", &first);
    let Some(before) = snapshot_or_skip("r7-tmpdir-mid") else {
        restore_env("TMPDIR", prev);
        return;
    };
    std::env::set_var("TMPDIR", &second);
    let created = clean.file(second.join("new-after-switch.txt"));
    fs::write(&created, b"created after TMPDIR switch\n").unwrap();
    let result = leftovers_or_skip("r7-tmpdir-mid", &before);
    restore_env("TMPDIR", prev);
    match result {
        Some(Ok(found)) => {
            let saw_new = leftovers_contain(&found, &created);
            let saw_stale = leftovers_contain(&found, &stale);
            if saw_stale {
                hunt(
                    "r7-tmpdir-mid",
                    "FALSE-FAIL",
                    "pre-existing file in the new TMPDIR was treated as a leftover after TMPDIR changed mid-run",
                );
            } else if saw_new {
                hunt(
                    "r7-tmpdir-mid",
                    "CAUGHT",
                    "file created in the new TMPDIR after the switch was listed; pre-existing file was not",
                );
            } else {
                hunt(
                    "r7-tmpdir-mid",
                    "SURVIVED",
                    "TMPDIR switch: new leftover unseen and stale file not listed",
                );
            }
        }
        Some(Err(reason)) => hunt("r7-tmpdir-mid", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_inotify_overflow_under_load() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let dir = clean.dir(unique_under(Path::new("/var/tmp"), "r7-overflow"));
    fs::create_dir_all(&dir).unwrap();
    let Some(before) = snapshot_or_skip("r7-overflow-load") else {
        return;
    };
    // max_queued_events is 16384 on this host. Burst past it.
    for i in 0..20000 {
        let path = dir.join(format!("e{i}"));
        let _ = fs::write(&path, b"x");
        let _ = fs::remove_file(&path);
    }
    match leftovers_or_skip("r7-overflow-load", &before) {
        Some(Err(reason)) if reason.contains("overflow") => hunt(
            "r7-overflow-load",
            "CAUGHT",
            &format!("load overflow fail-closed: {reason}"),
        ),
        Some(Ok(found)) => hunt(
            "r7-overflow-load",
            "SURVIVED",
            &format!("20000 create/delete events returned Ok leftovers={} — overflow did not fail closed", found.len()),
        ),
        Some(Err(reason)) => hunt(
            "r7-overflow-load",
            "FAIL-CLOSED",
            &format!("census refused under load (not overflow text): {reason}"),
        ),
        None => {}
    }
}

#[test]
fn r7_rename_across_mounts() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let src = clean.file(unique_under(Path::new("/var/tmp"), "r7-xdev-src").with_extension("txt"));
    let dest = clean.file(unique_under(Path::new("/dev/shm"), "r7-xdev-dest").with_extension("txt"));
    let Some(before) = snapshot_or_skip("r7-rename-xdev") else {
        return;
    };
    fs::write(&src, b"cross-mount leftover\n").unwrap();
    match fs::rename(&src, &dest) {
        Ok(()) => hunt(
            "r7-rename-xdev",
            "INCONCLUSIVE",
            "/var/tmp and /dev/shm accepted rename (same mount?)",
        ),
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            // Honest cross-mount: copy + unlink, which is what rename(2) cannot do.
            fs::copy(&src, &dest).unwrap();
            fs::remove_file(&src).unwrap();
            match leftovers_or_skip("r7-rename-xdev", &before) {
                Some(Ok(found)) if leftovers_contain(&found, &dest) => hunt(
                    "r7-rename-xdev",
                    "CAUGHT",
                    "copy+unlink across /var/tmp -> /dev/shm listed dest",
                ),
                Some(Ok(found)) => hunt(
                    "r7-rename-xdev",
                    "SURVIVED",
                    &format!("cross-mount dest leftover unseen: {found:?}"),
                ),
                Some(Err(reason)) => hunt("r7-rename-xdev", "INCONCLUSIVE", &reason),
                None => {}
            }
        }
        Err(err) => hunt("r7-rename-xdev", "INCONCLUSIVE", &format!("rename: {err}")),
    }
}

#[test]
fn r7_mount_namespace_escape() {
    let unshare = Command::new("unshare")
        .args(["-m", "--", "true"])
        .output();
    match unshare {
        Ok(out) if out.status.success() => hunt(
            "r7-mount-ns",
            "INCONCLUSIVE",
            "unshare -m succeeded; this runner did not plant a leftover in a new mount ns",
        ),
        Ok(out) => hunt(
            "r7-mount-ns",
            "NOT RUN",
            &format!(
                "unshare -m refused ({}); mount-namespace escape must stay NOT RUN, never PASS",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ),
        Err(err) => hunt("r7-mount-ns", "NOT RUN", &format!("unshare missing: {err}")),
    }
}

#[test]
fn r7_created_then_unlinked_before_snapshot() {
    let _lock = a12::lock_real_root();
    let mut clean = PathCleanup::new();
    let path = clean.file(unique_under(Path::new("/var/tmp"), "r7-before-snap").with_extension("txt"));
    fs::write(&path, b"exists only before snapshot\n").unwrap();
    fs::remove_file(&path).unwrap();
    let Some(before) = snapshot_or_skip("r7-before-snapshot") else {
        return;
    };
    match leftovers_or_skip("r7-before-snapshot", &before) {
        Some(Ok(found)) if leftovers_contain(&found, &path) => hunt(
            "r7-before-snapshot",
            "FALSE-FAIL",
            "a file that was gone before the snapshot was listed as a leftover",
        ),
        Some(Ok(_)) => hunt(
            "r7-before-snapshot",
            "EXPECTED",
            "create+unlink before snapshot is not a run leftover; census stayed clean of that path",
        ),
        Some(Err(reason)) => hunt("r7-before-snapshot", "INCONCLUSIVE", &reason),
        None => {}
    }
}

#[test]
fn r7_system_temp_false_fail() {
    let _lock = a12::lock_real_root();
    let Some(before) = snapshot_or_skip("r7-system-temps") else {
        return;
    };
    // Give systemd-tmpfiles / other host writers a short window.
    let _ = Command::new("systemd-tmpfiles")
        .args(["--create", "--user"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    std::thread::sleep(Duration::from_millis(400));
    match leftovers_or_skip("r7-system-temps", &before) {
        Some(Ok(found)) if !found.is_empty() => {
            let interesting: Vec<_> = found
                .iter()
                .filter(|p| {
                    let s = p.to_string_lossy();
                    s.starts_with("/tmp")
                        || s.starts_with("/var/tmp")
                        || s.starts_with("/dev/shm")
                        || s.contains("systemd")
                })
                .take(12)
                .cloned()
                .collect();
            if interesting.is_empty() {
                hunt(
                    "r7-system-temps",
                    "NOTE",
                    &format!("census listed {} paths; none under system temps", found.len()),
                );
            } else {
                hunt(
                    "r7-system-temps",
                    "FALSE-FAIL",
                    &format!(
                        "clean window listed host paths (systemd-tmpfiles or other writers): {interesting:?}"
                    ),
                );
            }
        }
        Some(Ok(_)) => hunt(
            "r7-system-temps",
            "CLEAN",
            "no leftovers during a quiet window after systemd-tmpfiles --create --user",
        ),
        Some(Err(reason)) => hunt(
            "r7-system-temps",
            "FAIL-CLOSED",
            &format!("quiet window refused: {reason}"),
        ),
        None => {}
    }
}

#[test]
fn r7_source_pins() {
    let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/a12.rs"));
    if source.contains("RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS") {
        hunt("r7-openat2-pin", "CAUGHT", "openat2 flags still in source");
    } else {
        hunt("r7-openat2-pin", "SURVIVED", "openat2 flags missing");
    }
    if source.contains("if ev.mask & libc::IN_Q_OVERFLOW != 0") {
        hunt("r7-overflow-pin", "CAUGHT", "IN_Q_OVERFLOW if still in drain");
    } else {
        hunt("r7-overflow-pin", "SURVIVED", "IN_Q_OVERFLOW if missing");
    }
    if source.contains("let _ = watch.add") {
        hunt(
            "r7-watch-add-pin",
            "SURVIVED",
            "let _ = watch.add is back; add failures are ignored",
        );
    } else {
        hunt("r7-watch-add-pin", "CAUGHT", "watch.add errors propagate");
    }
    if source.contains("hash_whole_file_sparse") && source.contains("fs::File::open(path)") {
        hunt(
            "r7-fifo-open-pin",
            "SURVIVED",
            "hash_whole_file_sparse uses blocking File::open; a FIFO leftover can hang the census",
        );
    } else {
        hunt("r7-fifo-open-pin", "CAUGHT", "census open is non-blocking or skipped for special files");
    }
}
