//! r5 hunts compiled only inside the #343 worktree for one run. Restored after.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::a12;
use crate::a6;

fn hunt(id: &str, verdict: &str, detail: &str) {
    println!("HUNT {id}: {verdict} | {detail}");
}

fn isolated_watch(label: &str) -> PathBuf {
    a12::isolated_dir(label)
}

fn spawn_sleeper(seconds: &str) -> Option<std::process::Child> {
    Command::new("sleep")
        .arg(seconds)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

fn two_other_live_pids() -> Result<(u32, u32, Vec<std::process::Child>), String> {
    let self_pid = std::process::id();
    let mut kids = Vec::new();
    let mut pids = Vec::new();
    for _ in 0..8 {
        let child = spawn_sleeper("30").ok_or_else(|| "could not spawn sleep".to_string())?;
        let pid = child.id();
        if pid != 0 && pid != 1 && pid != self_pid && Path::new(&format!("/proc/{pid}")).is_dir() {
            pids.push(pid);
            kids.push(child);
        } else {
            let _ = child;
        }
        if pids.len() >= 2 {
            break;
        }
    }
    if pids.len() < 2 {
        return Err(format!("could not collect two other live pids; got {pids:?}"));
    }
    Ok((pids[0], pids[1], kids))
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

// ---------- A6: child pid, threads, prove, pid reuse ----------

#[test]
fn r5_child_pid_of_this_process_is_not_a_capsule() {
    let self_pid = std::process::id();
    let child = match spawn_sleeper("20") {
        Some(child) => child,
        None => {
            hunt("r5-child-pid", "INCONCLUSIVE", "could not spawn sleep");
            return;
        }
    };
    let child_pid = child.id();
    let status = a6::status_for_claimed_resident_pair(claimed_pair(self_pid, child_pid));
    let _ = child;
    match status {
        a6::JourneyStatus::Pass(line) => hunt(
            "r5-child-pid",
            "SURVIVED",
            &format!("PASS with this process plus a sleep child: {line}"),
        ),
        a6::JourneyStatus::Fail(reason) => hunt("r5-child-pid", "CAUGHT", &reason),
        a6::JourneyStatus::Blocked { ask, reason } => hunt(
            "r5-child-pid",
            "INCONCLUSIVE",
            &format!("BLOCKED ({ask}): {reason}"),
        ),
    }
}

#[test]
fn r5_two_threads_share_one_pid() {
    let pid = std::process::id();
    match a6::status_for_claimed_resident_pair(claimed_pair(pid, pid)) {
        a6::JourneyStatus::Pass(line) => hunt(
            "r5-two-threads",
            "SURVIVED",
            &format!("PASS with one pid claimed as two instances: {line}"),
        ),
        a6::JourneyStatus::Fail(reason) => hunt("r5-two-threads", "CAUGHT", &reason),
        a6::JourneyStatus::Blocked { ask, reason } => hunt(
            "r5-two-threads",
            "INCONCLUSIVE",
            &format!("BLOCKED ({ask}): {reason}"),
        ),
    }
}

#[test]
fn r5_two_other_live_pids_claimed() {
    match two_other_live_pids() {
        Ok((pid1, pid2, kids)) => {
            let status = a6::status_for_claimed_resident_pair(claimed_pair(pid1, pid2));
            drop(kids);
            match status {
                a6::JourneyStatus::Pass(line) => hunt(
                    "r5-two-other-pids",
                    "SURVIVED",
                    &format!("PASS with two live non-self pids and no RA-6 host: {line}"),
                ),
                a6::JourneyStatus::Fail(reason) => hunt("r5-two-other-pids", "CAUGHT", &reason),
                a6::JourneyStatus::Blocked { ask, reason } => hunt(
                    "r5-two-other-pids",
                    "INCONCLUSIVE",
                    &format!("BLOCKED ({ask}): {reason}"),
                ),
            }
        }
        Err(reason) => hunt("r5-two-other-pids", "INCONCLUSIVE", &reason),
    }
}

#[test]
fn r5_prove_direct_on_child() {
    let child = match spawn_sleeper("20") {
        Some(child) => child,
        None => {
            hunt(
                "r5-prove-child",
                "INCONCLUSIVE",
                "could not spawn sleep",
            );
            return;
        }
    };
    let pid = child.id();
    let result = a6::prove_resident_capsule_instance(pid, a6::INSTANCE_1);
    let _ = child;
    match result {
        Ok(()) => hunt(
            "r5-prove-child",
            "SURVIVED",
            &format!("prove_resident_capsule_instance accepted sleep pid {pid}"),
        ),
        Err(reason) => hunt("r5-prove-child", "CAUGHT", &reason),
    }
}

#[test]
fn r5_pid_reuse_between_proof_and_use() {
    let first = match spawn_sleeper("0.05") {
        Some(child) => child,
        None => {
            hunt("r5-pid-reuse", "INCONCLUSIVE", "could not spawn first child");
            return;
        }
    };
    let old_pid = first.id();
    let _ = first.wait_with_output();
    let mut reused = None;
    let mut attempts = 0;
    for _ in 0..400 {
        attempts += 1;
        let child = match spawn_sleeper("15") {
            Some(child) => child,
            None => break,
        };
        if child.id() == old_pid {
            reused = Some(child);
            break;
        }
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
    }
    match reused {
        None => hunt(
            "r5-pid-reuse",
            "INCONCLUSIVE",
            &format!("pid {old_pid} was not recycled in {attempts} spawns"),
        ),
        Some(child) => {
            let status = a6::status_for_claimed_resident_pair(claimed_pair(old_pid, 1));
            let _ = child;
            match status {
                a6::JourneyStatus::Pass(line) => hunt(
                    "r5-pid-reuse",
                    "SURVIVED",
                    &format!("PASS after pid {old_pid} was reused by a new sleep: {line}"),
                ),
                a6::JourneyStatus::Fail(reason) => hunt("r5-pid-reuse", "CAUGHT", &reason),
                a6::JourneyStatus::Blocked { ask, reason } => hunt(
                    "r5-pid-reuse",
                    "INCONCLUSIVE",
                    &format!("BLOCKED ({ask}): {reason}"),
                ),
            }
        }
    }
}

// ---------- A12: handle, sparse/growing, parent swap, leftovers ----------

#[test]
fn r5_name_to_handle_at_on_tmpfs() {
    let pid = std::process::id();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = PathBuf::from("/dev/shm").join(format!("r5-handle-{pid}-{stamp}"));
    if fs::create_dir_all(&dir).is_err() {
        hunt(
            "r5-handle-tmpfs",
            "INCONCLUSIVE",
            "could not create /dev/shm watch",
        );
        return;
    }
    let path = dir.join("slot.txt");
    fs::write(&path, b"same-bytes\n").unwrap();
    let before = match a12::snapshot(&dir) {
        Ok(snap) => snap,
        Err(reason) => {
            let _ = fs::remove_dir_all(&dir);
            hunt("r5-handle-tmpfs", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let handle = before
        .ids
        .get(&path)
        .map(|id| id.file_handle.clone())
        .unwrap_or_default();
    if handle.is_empty() {
        hunt(
            "r5-handle-tmpfs",
            "SURVIVED",
            "name_to_handle_at returned empty on tmpfs; FileId handle is silently weaker",
        );
    } else {
        hunt(
            "r5-handle-tmpfs",
            "CAUGHT",
            &format!("tmpfs handle bytes={}", handle.len()),
        );
    }
    let before_ino = fs::symlink_metadata(&path).unwrap().ino();
    fs::remove_file(&path).unwrap();
    let mut reused = false;
    for _ in 0..300 {
        fs::write(&path, b"same-bytes\n").unwrap();
        if fs::symlink_metadata(&path).unwrap().ino() == before_ino {
            reused = true;
            break;
        }
        fs::remove_file(&path).unwrap();
    }
    if !path.exists() {
        fs::write(&path, b"same-bytes\n").unwrap();
    }
    let leftovers = a12::leftovers_created(&before, &dir).expect("created-set");
    let found = leftovers.iter().any(|p| p == &path);
    let _ = fs::remove_dir_all(&dir);
    let verdict = if !reused {
        "INCONCLUSIVE"
    } else if found {
        "CAUGHT"
    } else {
        "SURVIVED"
    };
    hunt(
        "r5-handle-tmpfs-reuse",
        verdict,
        &format!(
            "tmpfs same-bytes inode reuse reused={reused} found={found} handle_empty={}",
            handle.is_empty()
        ),
    );
}

#[test]
fn r5_sparse_file_zero_fill() {
    let parent = isolated_watch("r5-sparse");
    let path = parent.join("sparse.bin");
    let status = Command::new("truncate")
        .args(["-s", "1048576"])
        .arg(&path)
        .status();
    if !status.map(|s| s.success()).unwrap_or(false) {
        a12::remove_isolated(&parent);
        hunt("r5-sparse", "INCONCLUSIVE", "truncate -s 1M failed");
        return;
    }
    let before = a12::snapshot(&parent).expect("before");
    let before_hash = before.ids.get(&path).map(|id| id.content_hash);
    let fill = Command::new("dd")
        .args([
            "if=/dev/zero",
            &format!("of={}", path.display()),
            "bs=1048576",
            "count=1",
            "conv=notrunc",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !fill.map(|s| s.success()).unwrap_or(false) {
        a12::remove_isolated(&parent);
        hunt("r5-sparse", "INCONCLUSIVE", "dd zero-fill failed");
        return;
    }
    let after = a12::snapshot(&parent).expect("after");
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let after_hash = after.ids.get(&path).map(|id| id.content_hash);
    let found = leftovers.iter().any(|p| p == &path);
    let hash_same = before_hash == after_hash;
    a12::remove_isolated(&parent);
    hunt(
        "r5-sparse-hash",
        if hash_same { "SURVIVED" } else { "CAUGHT" },
        &format!("zero-fill of a 1MiB hole; hash_same={hash_same} before={before_hash:?} after={after_hash:?}"),
    );
    hunt(
        "r5-sparse-identity",
        if found { "CAUGHT" } else { "SURVIVED" },
        "FileId still moves (ctime/handle) even when fs::read of holes equals zeros",
    );
}

#[test]
fn r5_growing_file_after_snapshot() {
    let parent = isolated_watch("r5-grow");
    let path = parent.join("grow.bin");
    fs::write(&path, vec![b'A'; 4096]).unwrap();
    let before = a12::snapshot(&parent).expect("before");
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&vec![b'B'; 4096]).unwrap();
    drop(file);
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|p| p == &path);
    a12::remove_isolated(&parent);
    hunt(
        "r5-growing-file",
        if found { "CAUGHT" } else { "SURVIVED" },
        "append after snapshot must move FileId via size+full-content hash",
    );
}

#[test]
fn r5_last_byte_of_large_file() {
    let parent = isolated_watch("r5-last-byte");
    let path = parent.join("big.bin");
    let mut first = vec![b'A'; 65 * 1024];
    let last = first.len() - 1;
    first[last] = b'Y';
    fs::write(&path, &first).unwrap();
    let before = a12::snapshot(&parent).expect("before");
    let mut second = first.clone();
    second[last] = b'Z';
    fs::write(&path, &second).unwrap();
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|p| p == &path);
    a12::remove_isolated(&parent);
    hunt(
        "r5-last-byte",
        if found { "CAUGHT" } else { "SURVIVED" },
        "65 KiB file, only the last byte changed",
    );
}

#[test]
fn r5_parent_dir_swap_above_checked_root() {
    let iso = a12::isolation_root();
    let pid = std::process::id();
    let parent = iso.join(format!("r5-parent-{pid}"));
    let hold = parent.join("checked");
    let _ = fs::remove_dir_all(&parent);
    fs::create_dir_all(&hold).unwrap();
    a12::check_tmp_root(&hold).expect("checked under isolation");
    let fake_live = std::env::temp_dir().join(format!("r5-parent-live-{pid}"));
    let _ = fs::remove_dir_all(&fake_live);
    fs::create_dir_all(fake_live.join(".local/share/elastos")).unwrap();
    fs::create_dir_all(fake_live.join("checked")).unwrap();
    let moved = iso.join(format!("r5-parent-moved-{pid}"));
    let _ = fs::remove_dir_all(&moved);
    fs::rename(&parent, &moved).unwrap();
    symlink(&fake_live, &parent).unwrap();
    let write = a12::create_plain_leftover(&hold, "escaped.txt", b"parent-swap\n");
    let escaped = fake_live.join("checked").join("storage").join("escaped.txt");
    let wrote_outside = escaped.is_file();
    let _ = fs::remove_file(&parent);
    let _ = fs::remove_dir_all(&fake_live);
    let _ = fs::remove_dir_all(&moved);
    if wrote_outside {
        hunt(
            "r5-parent-swap",
            "SURVIVED",
            &format!("write landed outside after parent swap: write={write:?}"),
        );
    } else {
        hunt(
            "r5-parent-swap",
            "CAUGHT",
            &format!("write refused after parent swap: {write:?}"),
        );
    }
}

#[test]
fn r5_var_tmp_and_dev_shm_leftovers() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let sandbox = a12::isolation_root().join(format!("r5-outside-home-{pid}-{stamp}"));
    let xdg_cache = sandbox.join("xdg-cache");
    fs::create_dir_all(&xdg_cache).unwrap();
    let prev_home = std::env::var_os("HOME");
    let prev_cache = std::env::var_os("XDG_CACHE_HOME");
    std::env::set_var("HOME", &sandbox);
    std::env::set_var("XDG_CACHE_HOME", &xdg_cache);
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            restore_env("HOME", prev_home);
            restore_env("XDG_CACHE_HOME", prev_cache);
            a12::remove_isolated(&sandbox);
            hunt("r5-var-tmp", "INCONCLUSIVE", &reason);
            hunt("r5-dev-shm", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let var_tmp = PathBuf::from("/var/tmp").join(format!("r5-var-tmp-{pid}-{stamp}.txt"));
    let shm = PathBuf::from("/dev/shm").join(format!("r5-shm-{pid}-{stamp}.txt"));
    let _ = fs::write(&var_tmp, b"var-tmp leftover\n");
    let _ = fs::write(&shm, b"shm leftover\n");
    let leftovers = a12::leftovers_in_run_window(&before).expect("run-window");
    let saw_var = leftovers.iter().any(|p| p == &var_tmp);
    let saw_shm = leftovers.iter().any(|p| p == &shm);
    let _ = fs::remove_file(&var_tmp);
    let _ = fs::remove_file(&shm);
    restore_env("HOME", prev_home);
    restore_env("XDG_CACHE_HOME", prev_cache);
    a12::remove_isolated(&sandbox);
    hunt(
        "r5-var-tmp",
        if saw_var { "CAUGHT" } else { "SURVIVED" },
        "/var/tmp leftover in leftovers_in_run_window",
    );
    hunt(
        "r5-dev-shm",
        if saw_shm { "CAUGHT" } else { "SURVIVED" },
        "/dev/shm leftover in leftovers_in_run_window",
    );
}

#[test]
fn r5_write_then_delete_between_snapshots() {
    let parent = isolated_watch("r5-ephemeral");
    let before = a12::snapshot(&parent).expect("before");
    let path = parent.join("gone.txt");
    fs::write(&path, b"was-here\n").unwrap();
    fs::remove_file(&path).unwrap();
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|p| p == &path);
    a12::remove_isolated(&parent);
    hunt(
        "r5-write-then-delete",
        if found { "CAUGHT" } else { "SURVIVED" },
        "file created and deleted between the two snapshots",
    );
}

#[test]
fn r5_ready_journey_still_blocked() {
    match a6::resident_two_instance_token_journey() {
        a6::JourneyStatus::Blocked { ask, reason } => hunt(
            "r5-ra6-current",
            "BLOCKED",
            &format!("ask={ask} reason={reason}"),
        ),
        a6::JourneyStatus::Pass(line) => hunt(
            "r5-ra6-current",
            "SURVIVED",
            &format!("PASS without two resident instances: {line}"),
        ),
        a6::JourneyStatus::Fail(line) => hunt("r5-ra6-current", "FAIL", &line),
    }
}

fn restore_env(key: &str, previous: Option<std::ffi::OsString>) {
    match previous {
        Some(value) => std::env::set_var(key, value),
        None => std::env::remove_var(key),
    }
}
