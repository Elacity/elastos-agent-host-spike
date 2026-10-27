//! r6 hunts compiled only inside the #343 worktree for one run. Restored after.

use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn claimed_pair(pid1: u32, pid2: u32) -> a6::RuntimeResidentEvidence {
    a6::RuntimeResidentEvidence {
        instance_1_id: a6::INSTANCE_1.into(),
        instance_1_pid: pid1,
        instance_1_grant: "grant-1".into(),
        instance_2_id: a6::INSTANCE_2.into(),
        instance_2_pid: pid2,
        instance_2_grant: "grant-2".into(),
    }
}

fn leftovers_contain(found: &[PathBuf], path: &Path) -> bool {
    found.iter().any(|p| p == path || p.ends_with(path.file_name().unwrap_or_default()))
}

// ---------- detached child after first census ----------

#[test]
fn r6_detached_child_writes_after_census_returns() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let path = PathBuf::from("/var/tmp").join(format!("r6-detached-{pid}-{}.txt", stamp()));
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(path.clone());
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            hunt("r6-detached-after-return", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let leftovers = match a12::leftovers_in_run_window(&before) {
        Ok(found) => found,
        Err(reason) => {
            hunt(
                "r6-detached-after-return",
                "INCONCLUSIVE",
                &format!("census failed before child write: {reason}"),
            );
            return;
        }
    };
    let script = format!(
        "setsid /bin/sh -c 'sleep 0.2; printf detached > \"$1\"' _ '{}'",
        path.display()
    );
    let status = Command::new("/bin/sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !status.map(|s| s.success()).unwrap_or(false) {
        hunt(
            "r6-detached-after-return",
            "INCONCLUSIVE",
            "setsid double-fork spawn failed",
        );
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(400));
    let wrote = path.is_file();
    let saw = leftovers_contain(&leftovers, &path);
    if !wrote {
        hunt(
            "r6-detached-after-return",
            "INCONCLUSIVE",
            "detached child did not write after census returned",
        );
        return;
    }
    if saw {
        hunt(
            "r6-detached-after-return",
            "CAUGHT",
            "census already listed the path before the child wrote",
        );
    } else {
        hunt(
            "r6-detached-after-return",
            "SURVIVED",
            "setsid child wrote under /var/tmp after leftovers_in_run_window returned Ok; census PASSed a window it did not close",
        );
    }
}

#[test]
fn r6_detached_child_writes_during_window() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let path = PathBuf::from("/var/tmp").join(format!("r6-detached-live-{pid}-{}.txt", stamp()));
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(path.clone());
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            hunt("r6-detached-during", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let script = format!(
        "setsid /bin/sh -c 'printf detached-live > \"$1\"' _ '{}'",
        path.display()
    );
    let _ = Command::new("/bin/sh")
        .args(["-c", &script])
        .status();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let leftovers = match a12::leftovers_in_run_window(&before) {
        Ok(found) => found,
        Err(reason) => {
            hunt("r6-detached-during", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let wrote = path.is_file();
    let saw = leftovers_contain(&leftovers, &path);
    if !wrote {
        hunt(
            "r6-detached-during",
            "INCONCLUSIVE",
            "detached child did not write during the window",
        );
        return;
    }
    hunt(
        "r6-detached-during",
        if saw { "CAUGHT" } else { "SURVIVED" },
        "setsid child wrote under /var/tmp after the first snapshot and the file still existed at the second census",
    );
}

// ---------- bind mount ----------

#[test]
fn r6_bind_mount_into_watched_tree() {
    let parent = a12::isolated_dir("r6-bind");
    let src = parent.join("src");
    let dest = parent.join("dest");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(src.join("hidden.txt"), b"bind leftover\n").unwrap();
    let mount = Command::new("mount")
        .args(["--bind", &src.to_string_lossy(), &dest.to_string_lossy()])
        .output();
    let unshare = Command::new("unshare")
        .args(["-m", "--", "true"])
        .output();
    let mount_ok = mount
        .as_ref()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let unshare_ok = unshare
        .as_ref()
        .map(|o| o.status.success())
        .unwrap_or(false);
    a12::remove_isolated(&parent);
    if mount_ok || unshare_ok {
        hunt(
            "r6-bind-mount",
            "INCONCLUSIVE",
            "host allowed mount or unshare; bind leftover not exercised in this runner",
        );
        return;
    }
    hunt(
        "r6-bind-mount",
        "NOT RUN",
        "mount --bind and unshare -m are refused; lab must fail closed (NOT RUN), never PASS this class",
    );
}

// ---------- hardlink copied out then deleted ----------

#[test]
fn r6_hardlink_copied_out_then_deleted() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let watch_dir = PathBuf::from("/var/tmp").join(format!("r6-hl-watch-{pid}-{}", stamp()));
    let out_dir = PathBuf::from("/home/ubuntu").join(format!("r6-hl-out-{pid}-{}", stamp()));
    let _ = fs::create_dir_all(&watch_dir);
    let _ = fs::create_dir_all(&out_dir);
    let src = watch_dir.join("keep.txt");
    let dest = out_dir.join("keep.txt");
    struct Cleanup {
        src: PathBuf,
        dest: PathBuf,
        watch: PathBuf,
        out: PathBuf,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.src);
            let _ = fs::remove_file(&self.dest);
            let _ = fs::remove_dir(&self.watch);
            let _ = fs::remove_dir(&self.out);
        }
    }
    let _cleanup = Cleanup {
        src: src.clone(),
        dest: dest.clone(),
        watch: watch_dir.clone(),
        out: out_dir.clone(),
    };
    if fs::write(&src, b"hardlink leftover\n").is_err() {
        hunt("r6-hardlink-out", "INCONCLUSIVE", "could not write watch file");
        return;
    }
    if fs::hard_link(&src, &dest).is_err() {
        hunt(
            "r6-hardlink-out",
            "INCONCLUSIVE",
            "hard_link out of /var/tmp failed",
        );
        return;
    }
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            hunt("r6-hardlink-out", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let _ = fs::remove_file(&src);
    let leftovers = match a12::leftovers_in_run_window(&before) {
        Ok(found) => found,
        Err(reason) => {
            hunt("r6-hardlink-out", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let dest_lives = dest.is_file();
    let saw_dest = leftovers_contain(&leftovers, &dest);
    let saw_src = leftovers_contain(&leftovers, &src);
    if !dest_lives {
        hunt(
            "r6-hardlink-out",
            "INCONCLUSIVE",
            "outside hardlink disappeared",
        );
        return;
    }
    if saw_dest {
        hunt(
            "r6-hardlink-out",
            "CAUGHT",
            "outside hardlink path was listed as a leftover",
        );
    } else {
        hunt(
            "r6-hardlink-out",
            "SURVIVED",
            &format!(
                "inode still linked at {} after watch copy deleted; dest not in leftovers (src_event={saw_src})",
                dest.display()
            ),
        );
    }
}

// ---------- $HOME/.cache while XDG_CACHE_HOME is set ----------

#[test]
fn r6_home_cache_while_xdg_cache_home_set() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let sandbox = a12::isolation_root().join(format!("r6-home-cache-{pid}-{}", stamp()));
    let xdg = sandbox.join("xdg-cache");
    let home_cache = sandbox.join(".cache");
    fs::create_dir_all(&xdg).unwrap();
    fs::create_dir_all(&home_cache).unwrap();
    let prev_home = std::env::var_os("HOME");
    let prev_cache = std::env::var_os("XDG_CACHE_HOME");
    std::env::set_var("HOME", &sandbox);
    std::env::set_var("XDG_CACHE_HOME", &xdg);
    let roots = a12::extra_watch_roots();
    let watches_home_cache = roots.iter().any(|r| r == &home_cache);
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            restore_env("HOME", prev_home);
            restore_env("XDG_CACHE_HOME", prev_cache);
            a12::remove_isolated(&sandbox);
            hunt("r6-home-cache", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let secret = home_cache.join("secret.txt");
    fs::write(&secret, b"home-cache leftover\n").unwrap();
    let leftovers = a12::leftovers_in_run_window(&before).unwrap_or_default();
    let saw = leftovers_contain(&leftovers, &secret);
    restore_env("HOME", prev_home);
    restore_env("XDG_CACHE_HOME", prev_cache);
    a12::remove_isolated(&sandbox);
    if watches_home_cache && saw {
        hunt(
            "r6-home-cache",
            "CAUGHT",
            "extra_watch_roots still listed $HOME/.cache and the leftover was found",
        );
    } else {
        hunt(
            "r6-home-cache",
            "SURVIVED",
            &format!(
                "XDG_CACHE_HOME set; extra_watch_roots watches_home_cache={watches_home_cache} leftover_found={saw}"
            ),
        );
    }
}

// ---------- inotify queue overflow ----------

#[test]
fn r6_inotify_queue_overflow_fail_closed() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let dir = PathBuf::from("/var/tmp").join(format!("r6-overflow-{pid}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            hunt("r6-overflow", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let queued = fs::read_to_string("/proc/sys/fs/inotify/max_queued_events")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(16384);
    let n = queued + 2048;
    for i in 0..n {
        let path = dir.join(format!("e{i}"));
        let _ = fs::write(&path, b"x");
        let _ = fs::remove_file(&path);
    }
    match a12::leftovers_in_run_window(&before) {
        Err(reason) if reason.contains("overflow") || reason.contains("fail closed") => {
            hunt(
                "r6-overflow",
                "CAUGHT",
                &format!("IN_Q_OVERFLOW fail closed after {n} create/delete events: {reason}"),
            );
        }
        Err(reason) => hunt(
            "r6-overflow",
            "INCONCLUSIVE",
            &format!("census erred but not as overflow: {reason}"),
        ),
        Ok(found) => {
            let saw_dir = leftovers_contain(&found, &dir);
            if saw_dir && found.len() >= n {
                hunt(
                    "r6-overflow",
                    "CAUGHT",
                    "every create/delete was recorded; queue did not overflow",
                );
            } else {
                hunt(
                    "r6-overflow",
                    "SURVIVED",
                    &format!(
                        "leftovers_in_run_window returned Ok with {} paths after {n} events; overflow was silent or events dropped",
                        found.len()
                    ),
                );
            }
        }
    }
}

// ---------- watch limit exhausted ----------

#[test]
fn r6_watch_limit_add_failures_are_ignored() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/a12.rs"
    ));
    let ignores = source.matches("let _ = watch.add").count();
    let start = source.find("fn add(").unwrap_or(0);
    let add_body = &source[start..];
    let add_returns_err = add_body.contains("wd < 0");
    let live_open_ignores = source.contains("let _ = watch.add(&root)")
        || source.contains("let _ = watch.add(&path)");
    if live_open_ignores && ignores > 0 && add_returns_err {
        hunt(
            "r6-watch-limit",
            "SURVIVED",
            &format!(
                "LiveWatch::open / add_dir_watches_recursive ignore {ignores} add failures; exhausted max_user_watches would drop events and still PASS"
            ),
        );
    } else if !live_open_ignores {
        hunt(
            "r6-watch-limit",
            "CAUGHT",
            "watch add failures propagate (fail closed)",
        );
    } else {
        hunt(
            "r6-watch-limit",
            "INCONCLUSIVE",
            &format!("ignores={ignores} add_returns_err={add_returns_err}"),
        );
    }

    let max = fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    hunt(
        "r6-watch-limit-host",
        "NOT RUN",
        &format!(
            "max_user_watches={max}; this user cannot write the sysctl; lab must fail closed when add fails rather than PASS"
        ),
    );
}

// ---------- pre-opened fd ----------

#[test]
fn r6_preopened_fd_write_existing_file() {
    let parent = a12::isolated_dir("r6-preopen-exist");
    let path = parent.join("slot.txt");
    fs::write(&path, b"before\n").unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("pre-open");
    let before = a12::snapshot(&parent).expect("before");
    file.write_all(b"after-preopen\n").unwrap();
    drop(file);
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|p| p == &path);
    a12::remove_isolated(&parent);
    hunt(
        "r6-preopen-existing",
        if found { "CAUGHT" } else { "SURVIVED" },
        "write via fd opened before the snapshot on a file that still exists",
    );
}

#[test]
fn r6_preopened_dirfd_create_delete_in_subdir() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let dir = PathBuf::from("/var/tmp").join(format!("r6-preopen-dir-{pid}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    let c_dir = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
    let dirfd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dirfd < 0 {
        let _ = fs::remove_dir_all(&dir);
        hunt(
            "r6-preopen-dirfd",
            "INCONCLUSIVE",
            "could not open dirfd before watch",
        );
        return;
    }
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            unsafe { libc::close(dirfd) };
            let _ = fs::remove_dir_all(&dir);
            hunt("r6-preopen-dirfd", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let name = std::ffi::CString::new("gone.txt").unwrap();
    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd >= 0 {
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let _ = file.write_all(b"existed only via preopened dirfd\n");
        drop(file);
    }
    let _ = unsafe { libc::unlinkat(dirfd, name.as_ptr(), 0) };
    unsafe { libc::close(dirfd) };
    let leftovers = match a12::leftovers_in_run_window(&before) {
        Ok(found) => found,
        Err(reason) => {
            let _ = fs::remove_dir_all(&dir);
            hunt("r6-preopen-dirfd", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let ghost = dir.join("gone.txt");
    let saw = leftovers_contain(&leftovers, &ghost);
    let _ = fs::remove_dir_all(&dir);
    hunt(
        "r6-preopen-dirfd",
        if saw { "CAUGHT" } else { "SURVIVED" },
        "create+delete via dirfd opened before the watch, inside a /var/tmp subdir that is not recursively inotify-watched",
    );
}

// ---------- rename across watched/unwatched ----------

#[test]
fn r6_rename_watched_to_unwatched() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let src = PathBuf::from("/var/tmp").join(format!("r6-ren-src-{pid}-{}.txt", stamp()));
    let dest = PathBuf::from("/home/ubuntu").join(format!("r6-ren-dest-{pid}-{}.txt", stamp()));
    struct Cleanup(PathBuf, PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(&self.1);
        }
    }
    let _cleanup = Cleanup(src.clone(), dest.clone());
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            hunt("r6-rename-out", "INCONCLUSIVE", &reason);
            return;
        }
    };
    fs::write(&src, b"rename leftover\n").unwrap();
    fs::rename(&src, &dest).unwrap();
    let leftovers = match a12::leftovers_in_run_window(&before) {
        Ok(found) => found,
        Err(reason) => {
            hunt("r6-rename-out", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let saw_src = leftovers_contain(&leftovers, &src);
    let saw_dest = leftovers_contain(&leftovers, &dest);
    let dest_lives = dest.is_file();
    if dest_lives && saw_dest {
        hunt(
            "r6-rename-out",
            "CAUGHT",
            "unwatched dest path listed as leftover",
        );
    } else if dest_lives && saw_src {
        hunt(
            "r6-rename-out-event",
            "CAUGHT",
            "IN_MOVED_FROM / source event recorded",
        );
        hunt(
            "r6-rename-out-dest",
            "SURVIVED",
            &format!("leftover still at unwatched {} and dest path was not listed", dest.display()),
        );
    } else if dest_lives {
        hunt(
            "r6-rename-out",
            "SURVIVED",
            &format!(
                "renamed out of watch to {}; no leftover path recorded",
                dest.display()
            ),
        );
    } else {
        hunt("r6-rename-out", "INCONCLUSIVE", "dest missing after rename");
    }
}

#[test]
fn r6_rename_unwatched_to_watched() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let src = PathBuf::from("/home/ubuntu").join(format!("r6-ren-in-src-{pid}-{}.txt", stamp()));
    let dest = PathBuf::from("/var/tmp").join(format!("r6-ren-in-dest-{pid}-{}.txt", stamp()));
    struct Cleanup(PathBuf, PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(&self.1);
        }
    }
    let _cleanup = Cleanup(src.clone(), dest.clone());
    fs::write(&src, b"incoming leftover\n").unwrap();
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            hunt("r6-rename-in", "INCONCLUSIVE", &reason);
            return;
        }
    };
    fs::rename(&src, &dest).unwrap();
    let leftovers = match a12::leftovers_in_run_window(&before) {
        Ok(found) => found,
        Err(reason) => {
            hunt("r6-rename-in", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let saw = leftovers_contain(&leftovers, &dest);
    hunt(
        "r6-rename-in",
        if saw { "CAUGHT" } else { "SURVIVED" },
        "rename from unwatched $HOME into /var/tmp",
    );
}

// ---------- memfd / O_TMPFILE + linkat ----------

#[test]
fn r6_otmpfile_linkat_into_tree() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let dest = PathBuf::from("/var/tmp").join(format!("r6-otmp-{pid}-{}.txt", stamp()));
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(dest.clone());
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            hunt("r6-otmpfile", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let parent = std::ffi::CString::new("/var/tmp").unwrap();
    let fd = unsafe {
        libc::open(
            parent.as_ptr(),
            libc::O_RDWR | libc::O_TMPFILE | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        hunt(
            "r6-otmpfile",
            "INCONCLUSIVE",
            &format!(
                "O_TMPFILE not supported: {}",
                std::io::Error::last_os_error()
            ),
        );
        return;
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let _ = file.write_all(b"otmp leftover\n");
    let dest_c = std::ffi::CString::new(dest.as_os_str().as_bytes()).unwrap();
    let rc = unsafe {
        libc::linkat(
            file.as_raw_fd(),
            std::ffi::CString::new("").unwrap().as_ptr(),
            libc::AT_FDCWD,
            dest_c.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    drop(file);
    if rc != 0 {
        hunt(
            "r6-otmpfile",
            "INCONCLUSIVE",
            &format!("linkat AT_EMPTY_PATH failed: {}", std::io::Error::last_os_error()),
        );
        return;
    }
    let leftovers = match a12::leftovers_in_run_window(&before) {
        Ok(found) => found,
        Err(reason) => {
            hunt("r6-otmpfile", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let saw = leftovers_contain(&leftovers, &dest);
    hunt(
        "r6-otmpfile",
        if saw { "CAUGHT" } else { "SURVIVED" },
        "O_TMPFILE + linkat AT_EMPTY_PATH into /var/tmp; file still present at second census",
    );
}

#[test]
fn r6_otmpfile_linkat_then_unlink_in_subdir() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let dir = PathBuf::from("/var/tmp").join(format!("r6-otmp-sub-{pid}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    let dest = dir.join("gone.txt");
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            hunt("r6-otmpfile-unlink", "INCONCLUSIVE", &reason);
            return;
        }
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
            "r6-otmpfile-unlink",
            "INCONCLUSIVE",
            &format!("O_TMPFILE failed: {}", std::io::Error::last_os_error()),
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
            "r6-otmpfile-unlink",
            "INCONCLUSIVE",
            &format!("linkat failed: {}", std::io::Error::last_os_error()),
        );
        return;
    }
    let _ = fs::remove_file(&dest);
    let leftovers = match a12::leftovers_in_run_window(&before) {
        Ok(found) => found,
        Err(reason) => {
            hunt("r6-otmpfile-unlink", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let saw = leftovers_contain(&leftovers, &dest);
    hunt(
        "r6-otmpfile-unlink",
        if saw { "CAUGHT" } else { "SURVIVED" },
        "O_TMPFILE + linkat into a /var/tmp subdir, then unlink before the second snapshot",
    );
}

// ---------- /run/user/$UID ----------

#[test]
fn r6_run_user_uid_temp() {
    let uid = unsafe { libc::getuid() };
    let run_user = PathBuf::from(format!("/run/user/{uid}"));
    let roots = a12::writable_temp_roots();
    let listed = roots.iter().any(|r| r == &run_user);
    let exists = run_user.is_dir();
    if !exists {
        let created = fs::create_dir_all(&run_user);
        if created.is_err() {
            hunt(
                "r6-run-user",
                "NOT RUN",
                &format!(
                    "/run/user/{uid} is absent and this user cannot create it; writable_temp_roots lists it={listed}. Must fail closed (NOT RUN), never PASS."
                ),
            );
            return;
        }
        let _ = fs::remove_dir(&run_user);
    }
    if listed {
        hunt(
            "r6-run-user",
            "CAUGHT",
            "/run/user/$UID is in writable_temp_roots",
        );
        return;
    }
    hunt(
        "r6-run-user",
        "SURVIVED",
        &format!(
            "/run/user/{uid} exists={exists} but is not in writable_temp_roots (XDG_RUNTIME_DIR has no fallback)"
        ),
    );
}

// ---------- create-then-delete in unwatched subdir of a watched root ----------

#[test]
fn r6_create_delete_in_vartmp_subdir() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let dir = PathBuf::from("/var/tmp").join(format!("r6-subwatch-{pid}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("gone.txt");
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            hunt("r6-subdir-ephemeral", "INCONCLUSIVE", &reason);
            return;
        }
    };
    fs::write(&path, b"existed only in a /var/tmp subdir\n").unwrap();
    fs::remove_file(&path).unwrap();
    let leftovers = match a12::leftovers_in_run_window(&before) {
        Ok(found) => found,
        Err(reason) => {
            hunt("r6-subdir-ephemeral", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let saw = leftovers_contain(&leftovers, &path);
    hunt(
        "r6-subdir-ephemeral",
        if saw { "CAUGHT" } else { "SURVIVED" },
        "create-then-delete inside a /var/tmp subdirectory; live watch is only on the top of writable temps",
    );
}

// ---------- pid reuse via pid namespace ----------

#[test]
fn r6_pid_namespace_reuse() {
    let unshare = Command::new("unshare")
        .args(["-p", "-f", "--mount-proc", "true"])
        .output();
    match unshare {
        Ok(out) if out.status.success() => {
            hunt(
                "r6-pidns",
                "INCONCLUSIVE",
                "unshare -p succeeded; this runner did not recycle a proven pid inside a new ns",
            );
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            hunt(
                "r6-pidns",
                "NOT RUN",
                &format!(
                    "unshare -p refused ({err}); pid-namespace reuse must fail closed (NOT RUN), never PASS"
                ),
            );
        }
        Err(err) => hunt(
            "r6-pidns",
            "NOT RUN",
            &format!("unshare missing: {err}; fail closed, never PASS"),
        ),
    }

    match a6::status_for_claimed_resident_pair(claimed_pair(std::process::id(), 1)) {
        a6::JourneyStatus::Fail(_) => hunt(
            "r6-pidns-self-pid1",
            "CAUGHT",
            "this pid + pid 1 still FAIL",
        ),
        a6::JourneyStatus::Pass(line) => hunt(
            "r6-pidns-self-pid1",
            "SURVIVED",
            &format!("PASS: {line}"),
        ),
        a6::JourneyStatus::Blocked { ask, reason } => hunt(
            "r6-pidns-self-pid1",
            "INCONCLUSIVE",
            &format!("BLOCKED ({ask}): {reason}"),
        ),
    }
}

#[test]
fn r6_ready_journey_still_blocked() {
    match a6::resident_two_instance_token_journey() {
        a6::JourneyStatus::Blocked { ask, reason } => hunt(
            "r6-ra6-current",
            "BLOCKED",
            &format!("ask={ask} reason={reason}"),
        ),
        a6::JourneyStatus::Pass(line) => hunt(
            "r6-ra6-current",
            "SURVIVED",
            &format!("PASS without two resident instances: {line}"),
        ),
        a6::JourneyStatus::Fail(line) => hunt("r6-ra6-current", "FAIL", &line),
    }
}
