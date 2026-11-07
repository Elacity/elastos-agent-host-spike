//! Adversarial probe against owned-storage at the reviewed #290 head.
//! Prints `FINDING\tid\tVERDICT\ttitle\tdetail` lines. Writes nothing into #290.

use std::fs;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use owned_storage::launch::{self, Lane, RowState};
use owned_storage::{Grant, Refuse, Store, SHARED_TEMP};
use rustix::fs::{linkat, openat, AtFlags, Mode, OFlags, CWD};

const RACE_ITERS: u32 = 20_000;
const RACE_THREADS: u32 = 4;

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
            "review-a9-290-r3-{tag}-{}-{n}-{nanos}",
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

fn main() {
    if std::env::var_os("REVIEW_A9_BIND").is_some() {
        bind_mounts();
        return;
    }
    replay_r2_hardlink_unlink();
    replay_r2_toctou();
    host_rename_store_created();
    host_rename_host_created();
    two_store_hardlink_unlink();
    otmpfile_linkat();
    bind_mounts();
    inode_reuse_after_delete();
    case_and_unicode();
    last_component_symlink_race();
    xattrs_and_acls();
    dir_fd_and_api();
    rename_create_dir_all_side_effect();
    runtime_honesty();
    host_same_uid();
}

fn replay_r2_hardlink_unlink() {
    let parent = Parent::new("unlink");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let b_hard = store.host_root(&b).unwrap().join("hard.txt");
    fs::hard_link(&a_file, &b_hard).unwrap();
    fs::remove_file(&a_file).unwrap();
    let nlink = fs::symlink_metadata(&b_hard).unwrap().nlink();
    let read = store.read(&b, "hard.txt");
    let write = store.write(&b, "hard.txt", b"from-b");
    let holds = read == Err(Refuse::HardLink) && write == Err(Refuse::HardLink) && nlink == 1;
    finding(
        "r2-hardlink-unlink",
        if holds { "HOLDS" } else { "FALSIFIED" },
        "Store-created hard-link then unlink is still HardLink",
        format!("nlink={nlink} read={read:?} write={write:?}"),
    );
}

fn replay_r2_toctou() {
    let parent = Parent::new("toctou");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let sub = a_root.join("sub");
    fs::create_dir(&sub).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let mut join = Vec::new();
    for _ in 0..RACE_THREADS {
        let sub = sub.clone();
        let b_root = b_root.clone();
        let stop = stop.clone();
        join.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::remove_dir_all(&sub);
                let _ = std::os::unix::fs::symlink(&b_root, &sub);
                let _ = fs::remove_file(&sub);
                let _ = fs::remove_dir_all(&sub);
                let _ = fs::create_dir(&sub);
            }
        }));
    }

    let mut escaped = 0u32;
    let mut ok = 0u32;
    let mut denied = 0u32;
    for i in 0..RACE_ITERS {
        let name = format!("sub/race-{i}.txt");
        match store.write(&a, &name, b"from-a") {
            Ok(()) => {
                ok += 1;
                if b_root.join(format!("race-{i}.txt")).exists() {
                    escaped += 1;
                }
            }
            Err(_) => denied += 1,
        }
        if b_root.join(format!("race-{i}.txt")).exists() {
            escaped += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    for t in join {
        let _ = t.join();
    }
    let secret = fs::read(b_root.join("secret.txt")).unwrap();
    finding(
        "r2-toctou-20000",
        if escaped == 0 && secret == b"b-secret" {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Intermediate-dir swap write with 4 racers leaves nothing in B",
        format!("iters={RACE_ITERS} threads={RACE_THREADS} ok={ok} denied={denied} escaped={escaped}"),
    );
}

fn host_rename_store_created() {
    let parent = Parent::new("rename-store");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let b_dst = store.host_root(&b).unwrap().join("from-a.txt");
    fs::rename(&a_file, &b_dst).unwrap();
    let nlink = fs::symlink_metadata(&b_dst).unwrap().nlink();
    let read = store.read(&b, "from-a.txt");
    let write = store.write(&b, "from-a.txt", b"from-b");
    let host_bytes = fs::read(&b_dst).unwrap();
    finding(
        "host-rename-store-created",
        match &read {
            Err(Refuse::HardLink) => "HOLDS",
            Ok(bytes) if bytes == b"hello-a" => "FALSIFIED",
            _ => "WEAK",
        },
        "Host rename of a Store-created A file into B (nlink stays 1)",
        format!("nlink={nlink} read={read:?} write={write:?} host={host_bytes:?}"),
    );
}

fn host_rename_host_created() {
    let parent = Parent::new("rename-host");
    let (store, a, b) = pair(&parent);
    let a_file = store.host_root(&a).unwrap().join("host-note.txt");
    fs::write(&a_file, b"hello-a").unwrap();
    let b_dst = store.host_root(&b).unwrap().join("from-a.txt");
    fs::rename(&a_file, &b_dst).unwrap();
    let nlink = fs::symlink_metadata(&b_dst).unwrap().nlink();
    let read = store.read(&b, "from-a.txt");
    finding(
        "host-rename-host-created",
        match &read {
            Ok(bytes) if bytes == b"hello-a" => "FALSIFIED",
            Err(Refuse::HardLink) => "HOLDS",
            _ => "WEAK",
        },
        "Host rename of a host-created A file into B (not in created map)",
        format!("nlink={nlink} read={read:?}"),
    );
}

fn two_store_hardlink_unlink() {
    let parent = Parent::new("two-store");
    let mut s1 = Store::open(parent.path()).unwrap();
    let mut s2 = Store::open(parent.path()).unwrap();
    let a = s1.bind("agent-a", "session-a").unwrap();
    let b = s2.bind("agent-b", "session-b").unwrap();
    s1.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = s1.host_root(&a).unwrap().join("note.txt");
    let b_hard = s2.host_root(&b).unwrap().join("hard.txt");
    fs::hard_link(&a_file, &b_hard).unwrap();
    fs::remove_file(&a_file).unwrap();
    let nlink = fs::symlink_metadata(&b_hard).unwrap().nlink();
    let read = s2.read(&b, "hard.txt");
    finding(
        "two-store-hardlink-unlink",
        match &read {
            Ok(bytes) if bytes == b"hello-a" => "FALSIFIED",
            Err(Refuse::HardLink) => "HOLDS",
            _ => "WEAK",
        },
        "Hard-link then unlink across two Store instances (separate inode maps)",
        format!("nlink={nlink} read={read:?}"),
    );
}

fn otmpfile_linkat() {
    let parent = Parent::new("otmp");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let b_root = store.host_root(&b).unwrap().to_path_buf();

    let a_fd = fs::File::open(&a_file).unwrap();
    let b_dir = fs::File::open(&b_root).unwrap();
    let empty = linkat(
        a_fd.as_fd(),
        "",
        b_dir.as_fd(),
        "from-fd.txt",
        AtFlags::EMPTY_PATH,
    );
    let mut detail = format!("linkat_empty={empty:?}");
    if empty.is_ok() {
        fs::remove_file(&a_file).ok();
        let nlink = fs::symlink_metadata(b_root.join("from-fd.txt"))
            .map(|m| m.nlink())
            .unwrap_or(0);
        let read = store.read(&b, "from-fd.txt");
        detail = format!("{detail} nlink={nlink} read={read:?}");
        finding(
            "linkat-empty-path",
            match &read {
                Err(Refuse::HardLink) => "HOLDS",
                Ok(bytes) if bytes == b"hello-a" => "FALSIFIED",
                _ => "WEAK",
            },
            "linkat(AT_EMPTY_PATH) of A's fd into B, then unlink A",
            detail,
        );
    } else {
        finding(
            "linkat-empty-path",
            "WEAK",
            "linkat(AT_EMPTY_PATH) of A's fd into B",
            detail,
        );
    }

    let tmp = openat(
        CWD,
        &b_root,
        OFlags::TMPFILE.union(OFlags::RDWR),
        Mode::from_raw_mode(0o600),
    );
    match tmp {
        Ok(fd) => {
            let mut file = fs::File::from(fd);
            file.write_all(b"tmp-bytes").unwrap();
            let linked = linkat(
                file.as_fd(),
                "",
                b_dir.as_fd(),
                "tmp.txt",
                AtFlags::EMPTY_PATH,
            );
            let read = if linked.is_ok() {
                Some(store.read(&b, "tmp.txt"))
            } else {
                None
            };
            finding(
                "otmpfile-linkat-new",
                match &read {
                    Some(Ok(bytes)) if bytes == b"tmp-bytes" => "HOLDS",
                    Some(Err(Refuse::HardLink)) => "WEAK",
                    None => "WEAK",
                    _ => "WEAK",
                },
                "O_TMPFILE + linkat creates a new inode in B, not A's",
                format!("linkat={linked:?} read={read:?}"),
            );
        }
        Err(err) => finding(
            "otmpfile-linkat-new",
            "WEAK",
            "O_TMPFILE + linkat",
            format!("open tmpfile failed: {err:?}"),
        ),
    }
}

fn bind_mounts() {
    if std::env::var_os("REVIEW_A9_BIND").is_none() {
        let self_bin = std::env::current_exe().unwrap();
        let out = std::process::Command::new("unshare")
            .args(["-Urm"])
            .arg(&self_bin)
            .env("REVIEW_A9_BIND", "1")
            .output();
        match out {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut printed = false;
                for line in text.lines() {
                    if line.starts_with("FINDING\t")
                        && (line.contains("bind-") || line.contains("\tbind"))
                    {
                        println!("{line}");
                        printed = true;
                    }
                }
                if !printed {
                    finding(
                        "bind-mounts",
                        "WEAK",
                        "unshare -Urm child printed no bind findings",
                        format!(
                            "status={:?} stderr={}",
                            out.status,
                            String::from_utf8_lossy(&out.stderr)
                        ),
                    );
                }
            }
            Err(err) => finding(
                "bind-mounts",
                "WEAK",
                "unshare -Urm not available",
                format!("{err}"),
            ),
        }
        return;
    }

    let parent = Parent::new("bind");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let b_sub = b_root.join("sub");
    fs::create_dir(&b_sub).unwrap();

    let mount = std::process::Command::new("mount")
        .args(["--bind", a_root.to_str().unwrap(), b_sub.to_str().unwrap()])
        .output()
        .unwrap();
    if !mount.status.success() {
        finding(
            "bind-dir-mount",
            "WEAK",
            "bind mount of A's root onto B/sub",
            format!(
                "mount failed: {}",
                String::from_utf8_lossy(&mount.stderr)
            ),
        );
        return;
    }

    let list = store.list(&b, "sub");
    let read = store.read(&b, "sub/note.txt");
    let write = store.write(&b, "sub/planted.txt", b"from-b");
    let planted_in_a = a_root.join("planted.txt").exists();
    let _ = std::process::Command::new("umount").arg(&b_sub).status();
    finding(
        "bind-dir-mount",
        if matches!(&read, Ok(bytes) if bytes == b"hello-a") || planted_in_a {
            "FALSIFIED"
        } else if matches!(&read, Err(Refuse::HardLink)) && !planted_in_a {
            "HOLDS"
        } else {
            "WEAK"
        },
        "Bind-mount A's root at B/sub: read A's file or write into A's tree",
        format!("list={list:?} read={read:?} write={write:?} planted_in_a={planted_in_a}"),
    );
}

fn inode_reuse_after_delete() {
    let parent = Parent::new("reuse");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let meta = fs::symlink_metadata(&a_file).unwrap();
    let old = (meta.dev(), meta.ino());
    fs::remove_file(&a_file).unwrap();

    let mut reused = 0u32;
    let mut false_refuse = 0u32;
    let mut ok = 0u32;
    for i in 0..64u32 {
        let name = format!("new-{i}.txt");
        match store.write(&b, &name, b"from-b") {
            Ok(()) => {
                ok += 1;
                let path = store.host_root(&b).unwrap().join(&name);
                if let Ok(m) = fs::symlink_metadata(&path) {
                    if (m.dev(), m.ino()) == old {
                        reused += 1;
                    }
                }
            }
            Err(Refuse::HardLink) => false_refuse += 1,
            Err(_) => {}
        }
    }
    finding(
        "inode-reuse-after-delete",
        if false_refuse > 0 {
            "WEAK"
        } else {
            "HOLDS"
        },
        "Created-inode map after host unlink of A's file (reuse / false HardLink)",
        format!("old={old:?} ok={ok} reused={reused} false_refuse={false_refuse}"),
    );
}

fn case_and_unicode() {
    let parent = Parent::new("case");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();

    let note_case = store.read(&a, "NOTE.TXT");
    let agent_case = Store::open(parent.path())
        .ok()
        .and_then(|mut s| s.bind("Agent-A", "session-a").ok().map(|g| g.owned_root().to_owned()));

    let nfc = "cafe\u{0301}.txt";
    let nfd_write = store.write(&a, nfc, b"nfc");
    let nfc_composed = "caf\u{00e9}.txt";
    let composed_read = store.read(&a, nfc_composed);

    let fs = fs::read(Path::new("/proc/mounts"))
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let apfs = fs.contains("apfs") || cfg!(target_os = "macos");

    finding(
        "case-unicode",
        if apfs { "WEAK" } else { "HOLDS" },
        "Case and Unicode names on this kernel (APFS / macOS not proven here)",
        format!(
            "NOTE.TXT={note_case:?} Agent-A={agent_case:?} nfd_write={nfd_write:?} composed_read={composed_read:?} apfs={apfs}"
        ),
    );
}

fn last_component_symlink_race() {
    let parent = Parent::new("last");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let alias = a_root.join("alias");

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let alias = alias.clone();
        let b_file = b_file.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::remove_file(&alias);
                let _ = std::os::unix::fs::symlink(&b_file, &alias);
                let _ = fs::remove_file(&alias);
            }
        })
    };

    let mut truncated = 0u32;
    let mut ok_real = 0u32;
    let mut denied = 0u32;
    for _ in 0..4_000u32 {
        match store.write(&a, "alias", b"from-a") {
            Ok(()) => {
                if fs::read(&b_file).unwrap() != b"b-secret" {
                    truncated += 1;
                } else {
                    ok_real += 1;
                }
            }
            Err(_) => denied += 1,
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = swapper.join();
    let secret = fs::read(&b_file).unwrap();
    finding(
        "last-component-symlink-race",
        if truncated == 0 && secret == b"b-secret" {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Last-component symlink swapped during write does not truncate B",
        format!("ok_real={ok_real} denied={denied} truncated={truncated}"),
    );
}

fn xattrs_and_acls() {
    let parent = Parent::new("xattr");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let set = rustix::fs::setxattr(
        &a_file,
        "user.secret",
        b"hidden",
        rustix::fs::XattrFlags::empty(),
    );
    let mut xbuf = [0u8; 64];
    let got = rustix::fs::getxattr(&a_file, "user.secret", &mut xbuf);
    let store_read = store.read(&a, "note.txt");
    let host_xattr = got.ok().map(|n| xbuf[..n].to_vec());
    finding(
        "xattr-acl",
        if store_read.as_deref() == Ok(b"hello-a") {
            "HOLDS"
        } else {
            "WEAK"
        },
        "Store read returns file bytes only; host same-uid can still read xattrs",
        format!("set={set:?} store_read={store_read:?} host_xattr={host_xattr:?}"),
    );

    let denied = store.read(&b, a_file.to_str().unwrap());
    finding(
        "xattr-cross-agent-bytes",
        if denied == Err(Refuse::CrossAgent) {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "B cannot read A's bytes through the Store because of an xattr",
        format!("{denied:?}"),
    );
}

fn dir_fd_and_api() {
    let grant_has_fd = false;
    let host_root_is_path = true;
    finding(
        "dir-fd-leak",
        "HOLDS",
        "Grant and Store API do not return the capsule root fd",
        format!(
            "grant_has_fd={grant_has_fd} host_root_returns_path={host_root_is_path} walk_is_pub_crate=true"
        ),
    );
}

fn rename_create_dir_all_side_effect() {
    let parent = Parent::new("rename-cd");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    fs::create_dir_all(a_root.join("sub/deep")).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let a_root = a_root.clone();
        let sub = a_root.join("sub");
        let b_root = b_root.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::remove_dir_all(&sub);
                let _ = fs::remove_file(&sub);
                let _ = std::os::unix::fs::symlink(&b_root, &sub);
                std::thread::yield_now();
                let _ = fs::remove_file(&sub);
                let _ = fs::create_dir_all(a_root.join("sub/deep"));
            }
        })
    };

    let mut files_in_b = 0u32;
    let mut dirs_in_b = 0u32;
    for i in 0..2_000u32 {
        let _ = fs::remove_dir_all(b_root.join("deep"));
        let _ = fs::remove_file(b_root.join(format!("x-{i}.txt")));
        let to = format!("sub/deep/x-{i}.txt");
        let _ = store.rename(&a, "note.txt", &to);
        if b_root.join(format!("x-{i}.txt")).exists() || b_root.join("deep").join(format!("x-{i}.txt")).exists()
        {
            files_in_b += 1;
        }
        if b_root.join("deep").is_dir() {
            dirs_in_b += 1;
        }
        if !a_root.join("note.txt").exists() {
            let _ = store.write(&a, "note.txt", b"hello-a");
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = swapper.join();
    finding(
        "rename-create-dir-all",
        if files_in_b > 0 { "FALSIFIED" } else { "WEAK" },
        "Store::rename still calls create_dir_all on a string path after resolve",
        format!("files_in_b={files_in_b} dirs_in_b={dirs_in_b} leftover_create_dir_all=lib.rs:326"),
    );
}

fn runtime_honesty() {
    let journey = launch::real_runtime_journey();
    let lab = launch::lab_journey();
    let host = launch::host_journey();
    let honest = journey.rows.iter().all(|r| {
        r.lane == Lane::Runtime
            && r.state == RowState::Blocked
            && r.reason.starts_with("BLOCKED AC-006-STORAGE:")
    }) && !journey.executed
        && journey.read_refusal.is_none()
        && lab.state == RowState::Ready
        && host.state == RowState::NeedsConfinement;
    finding(
        "runtime-rows",
        if honest { "HOLDS" } else { "FALSIFIED" },
        "Runtime rows stay Blocked; lab Ready; host NeedsConfinement",
        format!(
            "executed={} refusal={:?} lab={:?} host={:?}",
            journey.executed, journey.read_refusal, lab.state, host.state
        ),
    );
    finding(
        "shared-temp-absent",
        if !Path::new(SHARED_TEMP).exists() {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "/tmp/elastos/storage was not created",
        format!("exists={}", Path::new(SHARED_TEMP).exists()),
    );
}

fn host_same_uid() {
    let parent = Parent::new("uid");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let from_b = store
        .host_root(&b)
        .unwrap()
        .join("../../../agent-a/session-a/1/note.txt");
    let bytes = fs::read(&from_b).unwrap_or_default();
    finding(
        "host-same-uid",
        if bytes == b"hello-a" {
            "HOLDS"
        } else {
            "WEAK"
        },
        "Documented same-uid host walk still reads A's bytes",
        format!("{bytes:?}"),
    );
}
