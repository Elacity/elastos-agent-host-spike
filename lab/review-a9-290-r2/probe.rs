//! Adversarial probe against owned-storage at the reviewed #290 head.
//! Prints `FINDING\tid\tVERDICT\ttitle\tdetail` lines. Writes nothing into #290.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use owned_storage::launch::{self, Lane, RowState};
use owned_storage::{Grant, Refuse, Store, SHARED_TEMP};

const O_NOFOLLOW: i32 = 0o400000;
const RACE_ITERS: u32 = 400;

struct Parent(PathBuf);

impl Parent {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "review-a9-290-r2-{tag}-{}-{n}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Parent {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pair(parent: &Parent) -> (Store, Grant, Grant) {
    let mut store = Store::open(parent.path()).unwrap();
    let a = store.bind("agent-a", "session-a").unwrap();
    let b = store.bind("agent-b", "session-b").unwrap();
    (store, a, b)
}

fn finding(id: &str, verdict: &str, title: &str, detail: impl AsRef<str>) {
    println!(
        "FINDING\t{id}\t{verdict}\t{title}\t{}",
        detail.as_ref().replace('\t', " ").replace('\n', " ")
    );
}

fn show_refuse(err: Refuse) -> String {
    format!("{err:?}: {err}")
}

fn main() {
    replay_official();
    unlink_after_hardlink();
    intermediate_symlink();
    last_component_symlink_create();
    toctou_write_intermediate();
    toctou_rename_into_swapped_sub();
    toctou_last_component_symlink();
    path_variants();
    empty_and_relative_roots();
    two_agent_race();
    proc_fd_and_prefix();
    host_same_uid();
    runtime_honesty();
    fourth_tmp_site();
    plant_child_hardcoded_pass();
}

fn replay_official() {
    let parent = Parent::new("replay");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    store.write(&a, "note.txt", b"hello-a").unwrap();

    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let read = store.read(&a, b_file.to_str().unwrap());
    finding(
        "api-read-write",
        if read == Err(Refuse::CrossAgent) {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Store read of B's host path is CrossAgent",
        format!("{read:?}"),
    );

    let trav = store.read(&a, "../../../agent-b/session-b/2/secret.txt");
    finding(
        "api-traversal",
        if trav == Err(Refuse::Traversal) {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "A .. path is Traversal",
        format!("{trav:?}"),
    );

    let link = store.host_root(&a).unwrap().join("via-b");
    std::os::unix::fs::symlink(&b_file, &link).unwrap();
    let via = store.read(&a, "via-b");
    finding(
        "api-symlink",
        if via == Err(Refuse::Symlink) {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Outbound file symlink is Symlink",
        format!("{via:?}"),
    );

    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    fs::remove_dir_all(&a_root).unwrap();
    std::os::unix::fs::symlink(&b_root, &a_root).unwrap();
    let swapped = store.read(&a, "secret.txt");
    let write_swapped = store.write(&a, "secret.txt", b"pwned");
    let b_after = fs::read(b_root.join("secret.txt")).unwrap();
    let leak = matches!(&swapped, Ok(bytes) if bytes == b"b-secret")
        || matches!(&write_swapped, Ok(()))
        || b_after != b"b-secret";
    let reason_symlink = swapped == Err(Refuse::Symlink) && write_swapped == Err(Refuse::Symlink);
    finding(
        "root-swap",
        if leak {
            "FALSIFIED"
        } else if reason_symlink {
            "HOLDS"
        } else {
            "WEAK"
        },
        "Root replaced by a symlink to B",
        format!(
            "read={:?} write={:?} b_bytes={} leak={leak}",
            swapped.as_ref().map(|_| "ok").map_err(|e| show_refuse(*e)),
            write_swapped.as_ref().map(|_| "ok").map_err(|e| show_refuse(*e)),
            String::from_utf8_lossy(&b_after)
        ),
    );
}

fn unlink_after_hardlink() {
    let parent = Parent::new("unlink-hl");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let b_hard = store.host_root(&b).unwrap().join("hard.txt");
    fs::hard_link(&a_file, &b_hard).unwrap();
    let live = store.read(&b, "hard.txt");
    fs::remove_file(&a_file).unwrap();
    let nlink = fs::symlink_metadata(&b_hard).unwrap().nlink();
    let after = store.read(&b, "hard.txt");
    let write_after = store.write(&b, "hard.txt", b"from-b");
    let leaked = matches!(&after, Ok(bytes) if bytes == b"hello-a");
    finding(
        "hardlink-live",
        if live == Err(Refuse::HardLink) {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Live second link (nlink>1) is HardLink",
        format!("read={live:?}"),
    );
    finding(
        "hardlink-unlink",
        if leaked {
            "FALSIFIED"
        } else if after == Err(Refuse::HardLink) {
            "HOLDS"
        } else {
            "WEAK"
        },
        "Hard link then unlink A's name; B reads through the Store",
        format!(
            "nlink={nlink} read={:?} write={:?} leaked={leaked}",
            after.as_ref().map(|b| String::from_utf8_lossy(b).into_owned()),
            write_after
        ),
    );
}

fn intermediate_symlink() {
    let parent = Parent::new("inter-sym");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    store.write(&a, "keep.txt", b"a").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    fs::create_dir(a_root.join("sub")).unwrap();
    fs::remove_dir(a_root.join("sub")).unwrap();
    std::os::unix::fs::symlink(&b_root, a_root.join("sub")).unwrap();

    let read = store.read(&a, "sub/secret.txt");
    let write = store.write(&a, "sub/new.txt", b"pwned");
    let list = store.list(&a, "sub");
    let rename = store.rename(&a, "keep.txt", "sub/stolen.txt");
    let b_ok = fs::read(b_root.join("secret.txt")).unwrap() == b"b-secret";
    let planted = b_root.join("new.txt").exists() || b_root.join("stolen.txt").exists();
    let all_denied = read.is_err() && write.is_err() && list.is_err() && rename.is_err();
    finding(
        "intermediate-symlink",
        if !b_ok || planted {
            "FALSIFIED"
        } else if all_denied {
            "HOLDS"
        } else {
            "WEAK"
        },
        "Intermediate directory is a symlink to B",
        format!("read={read:?} write={write:?} list={list:?} rename={rename:?} planted={planted}"),
    );
}

fn last_component_symlink_create() {
    let parent = Parent::new("last-sym");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let target = store.host_root(&b).unwrap().join("secret.txt");
    let alias = store.host_root(&a).unwrap().join("alias");
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let write = store.write(&a, "alias", b"pwned");
    let b_after = fs::read(&target).unwrap();
    finding(
        "last-component-symlink-write",
        if write == Err(Refuse::Symlink) && b_after == b"b-secret" {
            "HOLDS"
        } else if b_after != b"b-secret" {
            "FALSIFIED"
        } else {
            "WEAK"
        },
        "Write through an existing last-component symlink to B",
        format!("write={write:?} b_bytes={}", String::from_utf8_lossy(&b_after)),
    );
}

fn toctou_write_intermediate() {
    let parent = Parent::new("race-w");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let sub = a_root.join("sub");
    fs::create_dir(&sub).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let swapped = Arc::new(AtomicU64::new(0));
    let swapper = {
        let sub = sub.clone();
        let b_root = b_root.clone();
        let stop = stop.clone();
        let swapped = swapped.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::remove_dir_all(&sub);
                if std::os::unix::fs::symlink(&b_root, &sub).is_ok() {
                    swapped.fetch_add(1, Ordering::Relaxed);
                }
                let _ = fs::remove_file(&sub);
                let _ = fs::remove_dir_all(&sub);
                let _ = fs::create_dir(&sub);
            }
        })
    };

    let mut truncations = 0u32;
    let mut writes_ok_into_b = 0u32;
    let mut denied = 0u32;
    for i in 0..RACE_ITERS {
        let name = format!("sub/race-{i}.txt");
        match store.write(&a, &name, b"from-a") {
            Ok(()) => {
                if b_root.join(format!("race-{i}.txt")).exists() {
                    writes_ok_into_b += 1;
                }
            }
            Err(_) => denied += 1,
        }
        if b_root.join(format!("race-{i}.txt")).exists() {
            truncations += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = swapper.join();
    let _ = fs::remove_file(&sub);
    let _ = fs::remove_dir_all(&sub);
    let b_secret = fs::read(b_root.join("secret.txt")).unwrap_or_default();
    finding(
        "toctou-write-intermediate",
        if writes_ok_into_b > 0 || b_secret != b"b-secret" {
            "FALSIFIED"
        } else if truncations > 0 {
            "FALSIFIED"
        } else {
            "WEAK"
        },
        "TOCTOU: swap sub to a symlink to B between check and open(create)",
        format!(
            "iters={RACE_ITERS} denied={denied} writes_ok_into_b={writes_ok_into_b} files_left_in_b={truncations} swaps={} b_secret_ok={}",
            swapped.load(Ordering::Relaxed),
            b_secret == b"b-secret"
        ),
    );
}

fn toctou_rename_into_swapped_sub() {
    let parent = Parent::new("race-rn");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let sub = a_root.join("sub");
    fs::create_dir(&sub).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let sub = sub.clone();
        let b_root = b_root.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::remove_dir_all(&sub);
                let _ = std::os::unix::fs::symlink(&b_root, &sub);
                let _ = fs::remove_file(&sub);
                let _ = fs::remove_dir_all(&sub);
                let _ = fs::create_dir(&sub);
            }
        })
    };

    let mut moved_into_b = 0u32;
    let mut rename_ok = 0u32;
    for i in 0..RACE_ITERS {
        let src = format!("src-{i}.txt");
        if store.write(&a, &src, b"hello-a").is_err() {
            continue;
        }
        match store.rename(&a, &src, &format!("sub/taken-{i}.txt")) {
            Ok(()) => {
                rename_ok += 1;
                if b_root.join(format!("taken-{i}.txt")).exists() {
                    moved_into_b += 1;
                }
            }
            Err(_) => {}
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = swapper.join();
    finding(
        "toctou-rename-intermediate",
        if moved_into_b > 0 {
            "FALSIFIED"
        } else {
            "WEAK"
        },
        "TOCTOU: rename into sub after sub is swapped for a symlink to B",
        format!("iters={RACE_ITERS} rename_ok={rename_ok} moved_into_b={moved_into_b}"),
    );
}

fn toctou_last_component_symlink() {
    let parent = Parent::new("race-last");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let target = store.host_root(&b).unwrap().join("secret.txt");
    let alias = a_root.join("alias");

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let alias = alias.clone();
        let target = target.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::remove_file(&alias);
                let _ = std::os::unix::fs::symlink(&target, &alias);
                let _ = fs::remove_file(&alias);
            }
        })
    };

    let mut truncated = 0u32;
    let mut wrote = 0u32;
    for _ in 0..RACE_ITERS {
        let _ = fs::remove_file(&alias);
        match store.write(&a, "alias", b"from-a") {
            Ok(()) => wrote += 1,
            Err(_) => {}
        }
        if fs::read(&target).unwrap_or_default() != b"b-secret" {
            truncated += 1;
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = swapper.join();
    let b_after = fs::read(&target).unwrap_or_default();
    finding(
        "toctou-last-component",
        if b_after != b"b-secret" || truncated > 0 {
            "FALSIFIED"
        } else {
            "WEAK"
        },
        "TOCTOU: last component becomes a symlink to B's file before open(create|truncate)",
        format!(
            "iters={RACE_ITERS} wrote={wrote} truncated={truncated} b_bytes={}",
            String::from_utf8_lossy(&b_after)
        ),
    );
}

fn path_variants() {
    let parent = Parent::new("paths");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    store.write(&a, "note.txt", b"hello-a").unwrap();

    let mut leaks = Vec::new();
    let mut denied = Vec::new();
    let candidates = [
        "nested/../../secret.txt",
        "note.txt/../secret.txt",
        "./note.txt",
        "note.txt/.",
        "note.txt/",
        "UsersAI/agent-b/session-b/2/secret.txt",
        "..\\..\\agent-b\\session-b\\2\\secret.txt",
        "note.txt\0secret.txt",
        "NOTE.TXT",
        "note.tx\u{0301}t",
        "．．/secret.txt",
        "sub//note.txt",
        "%2e%2e/secret.txt",
        "note.txt ",
    ];
    for path in candidates {
        match store.read(&a, path) {
            Ok(bytes) if bytes == b"b-secret" => leaks.push(path.to_string()),
            Ok(bytes) => denied.push(format!("{path} => own-or-other {} bytes", bytes.len())),
            Err(err) => denied.push(format!("{path} => {err:?}")),
        }
    }

    let mut store2 = Store::open(parent.path()).unwrap();
    let case_id = store2.bind("Agent-A", "session-a");
    let unicode_id = store2.bind("agent-\u{00e9}", "session-a");

    finding(
        "path-variants",
        if leaks.is_empty() { "HOLDS" } else { "FALSIFIED" },
        "Case, Unicode, encoded, and dotted path variants do not read B",
        format!(
            "leaks={leaks:?} samples={denied:?} bind_Agent-A={:?} bind_unicode={:?}",
            case_id.as_ref().map(|g| g.owned_root().to_string()),
            unicode_id.as_ref().err()
        ),
    );
}

fn empty_and_relative_roots() {
    let parent = Parent::new("roots");
    let empty = Store::open(Path::new(""));
    let rel_missing = Store::open(Path::new("./no-such-owned-storage-root"));
    let cwd_parent = Parent::new("relcwd");
    let old = std::env::current_dir().unwrap();
    std::env::set_current_dir(cwd_parent.path()).unwrap();
    let rel_ok = Store::open(Path::new("."));
    let rel_detail = match &rel_ok {
        Ok(store) => format!("yard={}", store.yard().display()),
        Err(err) => format!("err={err:?}"),
    };
    std::env::set_current_dir(old).unwrap();

    let mut store = Store::open(parent.path()).unwrap();
    let empty_id = store.bind("", "session-a");
    let empty_session = store.bind("agent-a", "");
    let slash_id = store.bind("agent/a", "session-a");

    finding(
        "empty-relative-roots",
        "HOLDS",
        "Empty, missing, and relative Store::open / bind inputs",
        format!(
            "open_empty={empty:?} open_missing={rel_missing:?} open_dot={rel_detail} bind_empty_id={empty_id:?} bind_empty_session={empty_session:?} bind_slash={slash_id:?}"
        ),
    );
}

fn two_agent_race() {
    let parent = Parent::new("two-race");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_host = store
        .host_root(&a)
        .unwrap()
        .join("note.txt")
        .to_str()
        .unwrap()
        .to_string();
    let store = Arc::new(store);
    let stop = Arc::new(AtomicBool::new(false));
    let leaks = Arc::new(AtomicU64::new(0));
    let reader = {
        let store = store.clone();
        let b = b.clone();
        let a_host = a_host.clone();
        let stop = stop.clone();
        let leaks = leaks.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(bytes) = store.read(&b, &a_host) {
                    if bytes == b"hello-a" {
                        leaks.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let _ = store.list(&b, &a_host);
            }
        })
    };
    for i in 0..RACE_ITERS {
        let _ = store.write(&a, "note.txt", format!("hello-a-{i}").as_bytes());
    }
    stop.store(true, Ordering::Relaxed);
    let _ = reader.join();
    let n = leaks.load(Ordering::Relaxed);
    finding(
        "two-agent-race",
        if n == 0 { "HOLDS" } else { "FALSIFIED" },
        "Concurrent B Store::read of A's host path",
        format!("leaks={n} iters={RACE_ITERS}"),
    );
}

fn proc_fd_and_prefix() {
    let parent = Parent::new("proc");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let file = fs::File::open(&b_file).unwrap();
    let fd = {
        use std::os::unix::io::AsRawFd;
        file.as_raw_fd()
    };
    let proc_path = format!("/proc/self/fd/{fd}");
    let via_proc = store.read(&a, &proc_path);
    drop(file);

    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let prefix = PathBuf::from(format!("{}-evil", a_root.display()));
    let _ = fs::create_dir(&prefix);
    fs::write(prefix.join("secret.txt"), b"not-a").unwrap();
    let via_prefix = store.read(&a, prefix.join("secret.txt").to_str().unwrap());
    let _ = fs::remove_dir_all(&prefix);

    let leak = matches!(&via_proc, Ok(bytes) if bytes == b"b-secret")
        || matches!(&via_prefix, Ok(bytes) if bytes == b"not-a" || bytes == b"b-secret");
    finding(
        "proc-fd-prefix",
        if leak { "FALSIFIED" } else { "HOLDS" },
        "/proc/self/fd and lexical prefix paths",
        format!("proc={via_proc:?} prefix={via_prefix:?}"),
    );
}

fn host_same_uid() {
    let parent = Parent::new("host");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let from_b = store
        .host_root(&b)
        .unwrap()
        .join("../../../agent-a/session-a/1/note.txt");
    let host_read = fs::read(&from_b);
    let host = launch::host_journey();
    finding(
        "host-same-uid",
        if host_read.as_deref() == Ok(&b"hello-a"[..])
            && host.state == RowState::NeedsConfinement
        {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Same-uid host walk still reads A's bytes; row stays NeedsConfinement",
        format!("host_read={host_read:?} state={:?} reason={}", host.state, host.reason),
    );
}

fn runtime_honesty() {
    let lab = launch::lab_journey();
    let runtime = launch::real_runtime_journey();
    let host = launch::host_journey();
    let elastos = launch::installed_elastos_binary();
    let lab_ready = lab.state == RowState::Ready
        && lab.rows.iter().all(|row| row.lane == Lane::Lab && row.state == RowState::Ready);
    let runtime_blocked = runtime.rows.iter().all(|row| {
        row.lane == Lane::Runtime
            && row.state == RowState::Blocked
            && row.reason.starts_with("BLOCKED AC-006-STORAGE:")
    }) && !runtime.executed
        && runtime.read_refusal.is_none();
    let host_open = host.state == RowState::NeedsConfinement;
    finding(
        "runtime-rows",
        if lab_ready && runtime_blocked && host_open && elastos.is_none() {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Lab Ready, Runtime Blocked, host NeedsConfinement, no elastos binary",
        format!(
            "lab={:?} runtime_states={:?} executed={} read_refusal={:?} elastos={elastos:?}",
            lab.state,
            runtime
                .rows
                .iter()
                .map(|row| (row.id, row.state))
                .collect::<Vec<_>>(),
            runtime.executed,
            runtime.read_refusal
        ),
    );
}

fn fourth_tmp_site() {
    let root = launch::repo_root();
    let run_cmd = fs::read_to_string(root.join("elastos/crates/elastos-server/src/run_cmd.rs")).unwrap();
    let share_cmd = fs::read_to_string(root.join("elastos/crates/elastos-server/src/share_cmd.rs")).unwrap();
    let main_rs = fs::read_to_string(root.join("elastos/crates/elastos-server/src/main.rs")).unwrap();
    let run_n = launch::shared_temp_constructor_count(&run_cmd);
    let share_n = launch::shared_temp_constructor_count(&share_cmd);
    let main_literal = main_rs.matches("/tmp/elastos/storage").count();
    let existed = Path::new(SHARED_TEMP).exists();
    finding(
        "fourth-tmp-site",
        if run_n == 3 && share_n == 1 && main_literal == 1 && !existed {
            "HOLDS"
        } else {
            "WEAK"
        },
        "Four create_runtime shared-temp sites plus serve default; lab did not create it",
        format!("run_cmd={run_n} share_cmd={share_n} main_literal={main_literal} shared_temp_exists={existed}"),
    );
}

fn plant_child_hardcoded_pass() {
    // The plant runner returns Ok from planted_shared_root_is_caught when
    // OWNED_STORAGE_PLANT_CHILD is set. That is a child-path hardcoded PASS.
    // We only record that the env var is unset in this process.
    let set = std::env::var_os("OWNED_STORAGE_PLANT_CHILD").is_some();
    finding(
        "plant-child-env",
        if set { "WEAK" } else { "HOLDS" },
        "OWNED_STORAGE_PLANT_CHILD is unset in the probe process",
        format!("set={set}"),
    );

    // O_NOFOLLOW is only last-component; prove the kernel flag exists.
    let parent = Parent::new("nofollow");
    let path = parent.path().join("link");
    std::os::unix::fs::symlink("/tmp", &path).unwrap();
    let opened = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(&path);
    finding(
        "o-nofollow-kernel",
        if opened.is_err() { "HOLDS" } else { "WEAK" },
        "Linux O_NOFOLLOW rejects a last-component symlink",
        format!("open={opened:?}"),
    );
}
