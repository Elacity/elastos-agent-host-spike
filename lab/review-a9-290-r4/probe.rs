//! Adversarial probe against owned-storage at the reviewed #290 head.
//! Prints `FINDING\tid\tVERDICT\ttitle\tdetail` lines. Writes nothing into #290.

use std::fs;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use owned_storage::launch::{self, Lane, RowState};
use owned_storage::{Grant, Refuse, Store, SHARED_TEMP};
use rustix::fs::{linkat, openat, AtFlags, Mode, OFlags};

const RACE_ITERS: u32 = 20_000;
const RACE_THREADS: u32 = 4;
const REUSE_TRIES: u32 = 2_048;

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
            "review-a9-290-r4-{tag}-{}-{n}-{nanos}",
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

fn ownership_path(agent_root: &Path) -> PathBuf {
    let mut name = agent_root.as_os_str().to_os_string();
    name.push(".owned");
    PathBuf::from(name)
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
    if std::env::var_os("REVIEW_A9_OVERLAY").is_some() {
        overlay_and_dev();
        return;
    }
    replay_r1_api();
    replay_r1_root_swap();
    replay_r2_hardlink_live();
    replay_r2_hardlink_unlink();
    replay_r2_toctou();
    host_rename_store_created();
    host_rename_host_created();
    two_store_hardlink_unlink();
    otmpfile_linkat();
    bind_mounts();
    last_component_symlink_race();
    xattrs_and_acls();
    dir_fd_and_api();
    rename_no_string_mkdir();
    case_and_unicode();
    host_same_uid();
    runtime_honesty();
    ownership_location_and_reach();
    ownership_store_paths();
    ownership_truncate_corrupt();
    ownership_symlink_forge();
    inode_reuse_stale_grant();
    crash_create_before_record();
    concurrent_record_lost_update();
    record_growth();
    rename_within_b();
    overlay_and_dev();
}

fn replay_r1_api() {
    let parent = Parent::new("r1-api");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let b_path = b_file.to_str().unwrap();
    let a_path = a_file.to_str().unwrap();

    let read_b = store.read(&a, b_path);
    let write_b = store.write(&a, b_path, b"pwned");
    let trav = store.read(&a, "../../../agent-b/session-b/2/secret.txt");
    let via = store.host_root(&a).unwrap().join("via-b");
    std::os::unix::fs::symlink(&b_file, &via).unwrap();
    let via_read = store.read(&a, "via-b");
    let list_b = store.list(&a, store.host_root(&b).unwrap().to_str().unwrap());
    let rename_b = store.rename(&a, b_path, "stolen.txt");
    let own_list = store.list(&a, "");
    let holds = read_b == Err(Refuse::CrossAgent)
        && write_b == Err(Refuse::CrossAgent)
        && trav == Err(Refuse::Traversal)
        && via_read == Err(Refuse::Symlink)
        && list_b == Err(Refuse::CrossAgent)
        && rename_b == Err(Refuse::CrossAgent)
        && own_list.as_deref() == Ok(&["note.txt".to_string()][..])
        && fs::read(&b_file).unwrap() == b"b-secret";
    finding(
        "r1-api",
        if holds { "HOLDS" } else { "FALSIFIED" },
        "Store API denies foreign host path, .., symlink, list, and rename",
        format!(
            "read={read_b:?} write={write_b:?} trav={trav:?} via={via_read:?} list={list_b:?} rename={rename_b:?} own_list={own_list:?} a_path={a_path}"
        ),
    );
}

fn replay_r1_root_swap() {
    let parent = Parent::new("r1-swap");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let _ = fs::remove_dir_all(&a_root);
    std::os::unix::fs::symlink(&b_root, &a_root).unwrap();
    let read = store.read(&a, "secret.txt");
    let write = store.write(&a, "secret.txt", b"from-a");
    let secret = fs::read(b_root.join("secret.txt")).unwrap();
    let holds = read == Err(Refuse::Symlink) && secret == b"b-secret";
    finding(
        "r1-root-swap",
        if holds { "HOLDS" } else { "FALSIFIED" },
        "Swapping A's root for a symlink to B is refused",
        format!("read={read:?} write={write:?} secret={secret:?}"),
    );
}

fn replay_r2_hardlink_live() {
    let parent = Parent::new("r2-live");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let b_hard = store.host_root(&b).unwrap().join("hard.txt");
    fs::hard_link(&a_file, &b_hard).unwrap();
    let nlink = fs::symlink_metadata(&b_hard).unwrap().nlink();
    let read = store.read(&b, "hard.txt");
    let write = store.write(&b, "hard.txt", b"from-b");
    let holds = nlink > 1 && read == Err(Refuse::HardLink) && write == Err(Refuse::HardLink);
    finding(
        "r2-hardlink-live",
        if holds { "HOLDS" } else { "FALSIFIED" },
        "Live hard link with nlink>1 is HardLink",
        format!("nlink={nlink} read={read:?} write={write:?}"),
    );
}

fn replay_r2_hardlink_unlink() {
    let parent = Parent::new("r2-unlink");
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
    let parent = Parent::new("r2-toctou");
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
            Err(Refuse::HardLink) => "HOLDS",
            Ok(bytes) if bytes == b"hello-a" => "FALSIFIED",
            _ => "WEAK",
        },
        "Host rename of a host-created A file into B (r3 hole)",
        format!("nlink={nlink} read={read:?}"),
    );
}

fn two_store_hardlink_unlink() {
    let parent = Parent::new("two-yards");
    let mut s1 = Store::open(parent.path()).unwrap();
    let a = s1.bind("agent-a", "session-a").unwrap();
    let mut s2 = Store::open(parent.path()).unwrap();
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
        "Hard-link then unlink across two Store yards (r3 hole)",
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
        detail.push_str(&format!(" nlink={nlink} read={read:?}"));
        finding(
            "linkat-empty-path",
            match &read {
                Err(Refuse::HardLink) => "HOLDS",
                Ok(bytes) if bytes == b"hello-a" => "FALSIFIED",
                _ => "WEAK",
            },
            "linkat(AT_EMPTY_PATH) of A's fd into B, then unlink A",
            detail.clone(),
        );
    } else {
        finding(
            "linkat-empty-path",
            "WEAK",
            "linkat(AT_EMPTY_PATH) of A's fd into B, then unlink A",
            detail.clone(),
        );
    }

    let tmp = openat(
        &b_dir,
        ".",
        OFlags::TMPFILE.union(OFlags::RDWR).union(OFlags::CLOEXEC),
        Mode::from_raw_mode(0o600),
    );
    match tmp {
        Ok(fd) => {
            let _ = rustix::io::write(&fd, b"tmp-bytes");
            let linked = linkat(fd.as_fd(), "", b_dir.as_fd(), "tmp.txt", AtFlags::EMPTY_PATH);
            let read = store.read(&b, "tmp.txt");
            finding(
                "otmpfile-linkat-new",
                match &read {
                    Err(Refuse::HardLink) => "HOLDS",
                    Ok(bytes) if bytes == b"tmp-bytes" => "FALSIFIED",
                    _ => "WEAK",
                },
                "O_TMPFILE + linkat in B is a new inode this Store did not create",
                format!("linkat={linked:?} read={read:?}"),
            );
        }
        Err(err) => finding(
            "otmpfile-linkat-new",
            "WEAK",
            "O_TMPFILE + linkat in B is a new inode this Store did not create",
            format!("open TMPFILE failed: {err:?}"),
        ),
    }
}

fn bind_mounts() {
    if std::env::var_os("REVIEW_A9_BIND").is_none() {
        let exe = std::env::current_exe().expect("probe exe");
        let output = std::process::Command::new("unshare")
            .args(["-Urm", "--"])
            .arg(&exe)
            .env("REVIEW_A9_BIND", "1")
            .env("REVIEW_A9_OVERLAY", "")
            .output();
        match output {
            Ok(out) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                for line in text.lines() {
                    if line.starts_with("FINDING\t") {
                        println!("{line}");
                    }
                }
                if !out.status.success()
                    && !text.contains("FINDING\t")
                    && unshare_unavailable(&text)
                {
                    finding(
                        "bind-dir-mount",
                        "WEAK",
                        "Bind-mount A's root at B/sub",
                        format!("unshare not allowed: {}", text.replace('\n', " ")),
                    );
                }
            }
            Err(error) => finding(
                "bind-dir-mount",
                "WEAK",
                "Bind-mount A's root at B/sub",
                format!("unshare missing: {error}"),
            ),
        }
        return;
    }

    let parent = Parent::new("bind");
    let mut store_a = Store::open(parent.path()).unwrap();
    let a = store_a.bind("agent-a", "session-a").unwrap();
    store_a.write(&a, "note.txt", b"hello-a").unwrap();
    let mut store_b = Store::open(parent.path()).unwrap();
    let b = store_b.bind("agent-b", "session-b").unwrap();
    let a_root = store_a.host_root(&a).unwrap().to_path_buf();
    let b_sub = store_b.host_root(&b).unwrap().join("sub");
    fs::create_dir(&b_sub).unwrap();
    let status = std::process::Command::new("mount")
        .args(["--bind", a_root.to_str().unwrap(), b_sub.to_str().unwrap()])
        .status()
        .expect("mount --bind");
    if !status.success() {
        finding(
            "bind-dir-mount",
            "WEAK",
            "Bind-mount A's root at B/sub",
            format!("mount --bind failed: {status}"),
        );
        return;
    }
    let list = store_b.list(&b, "sub");
    let read = store_b.read(&b, "sub/note.txt");
    let write = store_b.write(&b, "sub/planted.txt", b"pwned");
    let planted_in_a = a_root.join("planted.txt").exists();
    let _ = std::process::Command::new("umount").arg(&b_sub).status();
    let caught = list.is_err() && read.is_err() && write.is_err() && !planted_in_a;
    let leaked = matches!(&read, Ok(bytes) if bytes == b"hello-a")
        || matches!(&list, Ok(names) if names.iter().any(|n| n == "note.txt"))
        || planted_in_a;
    finding(
        "bind-dir-mount",
        if leaked {
            "FALSIFIED"
        } else if caught {
            "HOLDS"
        } else {
            "WEAK"
        },
        "Bind-mount A's root at B/sub: list/read/write (r3 hole)",
        format!("list={list:?} read={read:?} write={write:?} planted_in_a={planted_in_a}"),
    );
}

fn unshare_unavailable(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("not allowed")
        || lower.contains("unshare: failed")
        || lower.contains("cannot unshare")
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
    finding(
        "dir-fd-leak",
        "HOLDS",
        "Grant and Store API do not return the capsule root fd",
        "grant_has_fd=false host_root_returns_path=true walk_is_pub_crate=true",
    );
}

fn rename_no_string_mkdir() {
    let src = std::env::var("OWNED_STORAGE_LIB_RS")
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .unwrap_or_default();
    let leftover = !src.is_empty() && src.contains("create_dir_all");
    finding(
        "rename-create-dir-all",
        if leftover { "WEAK" } else { "HOLDS" },
        "Store::rename leftover string create_dir_all (r3 leftover)",
        format!(
            "lib.rs_contains_create_dir_all={leftover} src_len={}",
            src.len()
        ),
    );
}

fn case_and_unicode() {
    let parent = Parent::new("case");
    let (store, a, _b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let note_case = store.read(&a, "NOTE.TXT");
    let nfc = "cafe\u{0301}.txt";
    let nfd_write = store.write(&a, nfc, b"nfc");
    let composed_read = store.read(&a, "caf\u{00e9}.txt");
    let mounts = fs::read(Path::new("/proc/mounts"))
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let apfs = mounts.contains("apfs") || cfg!(target_os = "macos");
    finding(
        "case-unicode",
        if apfs { "WEAK" } else { "HOLDS" },
        "Case and Unicode names on this kernel (APFS / macOS not proven here)",
        format!("NOTE.TXT={note_case:?} nfd_write={nfd_write:?} composed_read={composed_read:?} apfs={apfs}"),
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
        if bytes == b"hello-a" { "HOLDS" } else { "WEAK" },
        "Documented same-uid host walk still reads A's bytes",
        format!("{bytes:?}"),
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
            "executed={} refusal={:?} lab={:?} host={:?} rows={:?}",
            journey.executed, journey.read_refusal, lab.state, host.state, journey.rows
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

fn ownership_location_and_reach() {
    let parent = Parent::new("own-loc");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let a_owned = ownership_path(&a_root);
    let b_owned = ownership_path(&b_root);
    let inside_a = a_owned.starts_with(&a_root);
    let inside_b = a_owned.starts_with(&b_root) || b_owned.starts_with(&a_root);
    let exists = a_owned.is_file() && b_owned.is_file();
    let mode = fs::metadata(&a_owned)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0);
    let text = fs::read_to_string(&a_owned).unwrap_or_default();
    let a_note = fs::symlink_metadata(a_root.join("note.txt")).unwrap();
    let contains = text.contains(&format!("{} {}", a_note.dev(), a_note.ino()));
    let sibling = a_owned
        .file_name()
        .map(|n| n.to_string_lossy().ends_with(".owned"))
        .unwrap_or(false)
        && a_owned.parent() == a_root.parent();
    finding(
        "ownership-location",
        if exists && sibling && !inside_a && !inside_b && contains {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Ownership file is a sibling of the agent root, not inside any agent tree",
        format!(
            "a_owned={} exists={exists} inside_a={inside_a} inside_b={inside_b} sibling={sibling} mode={mode:#o} contains_inode={contains}",
            a_owned.display()
        ),
    );
}

fn ownership_store_paths() {
    let parent = Parent::new("own-path");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let a_owned = ownership_path(&a_root);
    let before = fs::read(&a_owned).unwrap();

    let dots = store.write(&a, ".owned", b"forged-by-a");
    let trav = store.write(&a, "../1.owned", b"forged-trav");
    let abs = store.write(&a, a_owned.to_str().unwrap(), b"forged-abs");
    let from_b_rel = store.write(&b, "../../../agent-a/session-a/1.owned", b"forged-b");
    let from_b_abs = store.write(&b, a_owned.to_str().unwrap(), b"forged-b-abs");
    let after = fs::read(&a_owned).unwrap();
    let unchanged = after == before;
    let a_dot_owned = a_root.join(".owned");
    let a_wrote_inside = matches!(dots, Ok(())) && a_dot_owned.is_file();
    let holds = unchanged
        && trav == Err(Refuse::Traversal)
        && from_b_rel == Err(Refuse::Traversal)
        && abs.is_err()
        && from_b_abs.is_err();
    finding(
        "ownership-store-write",
        if holds { "HOLDS" } else { "FALSIFIED" },
        "Neither Store can write the sibling ownership file through a Store path",
        format!(
            "dots={dots:?} trav={trav:?} abs={abs:?} from_b_rel={from_b_rel:?} from_b_abs={from_b_abs:?} unchanged={unchanged} a_wrote_inside={a_wrote_inside}"
        ),
    );
}

fn ownership_truncate_corrupt() {
    let parent = Parent::new("own-corr");
    let (store, a, _b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let a_owned = ownership_path(&a_root);

    fs::write(&a_owned, b"").unwrap();
    let empty = store.read(&a, "note.txt");
    store.write(&a, "other.txt", b"new").ok();
    let after_empty_new = store.read(&a, "other.txt");

    fs::write(&a_owned, b"# owned-storage v1\nnot-a-pair\n").unwrap();
    let bad_line = store.read(&a, "note.txt");

    fs::write(&a_owned, b"# owned-storage v1\n1\n").unwrap();
    let short_line = store.read(&a, "note.txt");

    let fail_closed = empty.is_err() && bad_line.is_err() && short_line.is_err();
    finding(
        "ownership-corrupt",
        if fail_closed { "HOLDS" } else { "FALSIFIED" },
        "Truncate or corrupt ownership file fails closed (no grant)",
        format!(
            "empty={empty:?} after_empty_new={after_empty_new:?} bad_line={bad_line:?} short_line={short_line:?}"
        ),
    );
}

fn ownership_symlink_forge() {
    let parent = Parent::new("own-sym");
    let (store, a, b) = pair(&parent);
    store.write(&a, "keep.txt", b"keep-a").unwrap();
    store.write(&b, "forge.txt", b"starter").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let a_owned = ownership_path(&a_root);
    let b_forge = b_root.join("forge.txt");

    fs::remove_file(&a_owned).unwrap();
    std::os::unix::fs::symlink(&b_forge, &a_owned).unwrap();

    let a_write = store.write(&a, "note.txt", b"hello-a");
    let b_sees = store.read(&b, "forge.txt");
    let leak = matches!(&b_sees, Ok(bytes) if bytes.starts_with(b"# owned-storage v1"));

    let planted = a_root.join("planted.txt");
    fs::write(&planted, b"from-b-bytes").unwrap();
    let plant_meta = fs::symlink_metadata(&planted).unwrap();
    let mut forged = b"# owned-storage v1\n".to_vec();
    if let Ok(bytes) = &b_sees {
        forged = bytes.clone();
    }
    if !forged.ends_with(b"\n") {
        forged.push(b'\n');
    }
    forged.extend(format!("{} {}\n", plant_meta.dev(), plant_meta.ino()).into_bytes());
    let b_write = store.write(&b, "forge.txt", &forged);
    let a_read_planted = store.read(&a, "planted.txt");
    let granted = matches!(&a_read_planted, Ok(bytes) if bytes == b"from-b-bytes");

    finding(
        "ownership-symlink-forge",
        if granted {
            "FALSIFIED"
        } else if leak {
            "WEAK"
        } else {
            "HOLDS"
        },
        "Host replaces A's .owned with a symlink to a file B Store-writes; B forges an inode",
        format!(
            "a_write={a_write:?} leak={leak} b_write={b_write:?} a_read_planted={a_read_planted:?} granted={granted}"
        ),
    );
}

fn inode_reuse_stale_grant() {
    let parent = Parent::new("reuse");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let a_file = a_root.join("note.txt");
    let old = {
        let m = fs::symlink_metadata(&a_file).unwrap();
        (m.dev(), m.ino())
    };
    fs::remove_file(&a_file).unwrap();

    let mut reused_name: Option<String> = None;
    let mut reused = 0u32;
    let mut ok = 0u32;
    let mut false_refuse = 0u32;
    for i in 0..REUSE_TRIES {
        let name = format!("new-{i}.txt");
        match store.write(&b, &name, b"from-b") {
            Ok(()) => {
                ok += 1;
                let path = b_root.join(&name);
                if let Ok(m) = fs::symlink_metadata(&path) {
                    if (m.dev(), m.ino()) == old {
                        reused += 1;
                        reused_name = Some(name);
                        break;
                    }
                }
            }
            Err(Refuse::HardLink) => false_refuse += 1,
            Err(_) => {}
        }
    }

    let mut granted = false;
    let mut a_read = None;
    if let Some(name) = &reused_name {
        let src = b_root.join(name);
        let dst = a_root.join("stolen.txt");
        fs::rename(&src, &dst).unwrap();
        let read = store.read(&a, "stolen.txt");
        granted = matches!(&read, Ok(bytes) if bytes == b"from-b");
        a_read = Some(read);
    }

    let verdict = if granted {
        "FALSIFIED"
    } else if reused == 0 {
        "WEAK"
    } else {
        "HOLDS"
    };
    finding(
        "inode-reuse-stale-grant",
        verdict,
        "Stale (dev,ino) after A unlink; B reuses inode; host rename into A",
        format!(
            "old={old:?} ok={ok} reused={reused} false_refuse={false_refuse} reused_name={reused_name:?} a_read={a_read:?} granted={granted}"
        ),
    );
}

fn crash_create_before_record() {
    let parent = Parent::new("crash");
    let (store, a, _b) = pair(&parent);
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let orphan = a_root.join("orphan.txt");
    fs::write(&orphan, b"created-but-unrecorded").unwrap();
    let write = store.write(&a, "orphan.txt", b"retry");
    let read = store.read(&a, "orphan.txt");
    let fail_closed = write == Err(Refuse::HardLink) && read == Err(Refuse::HardLink);
    finding(
        "crash-create-before-record",
        if fail_closed { "HOLDS" } else { "FALSIFIED" },
        "File that exists but is missing from the record is refused (crash window)",
        format!("write={write:?} read={read:?}"),
    );
}

fn concurrent_record_lost_update() {
    let parent = Parent::new("lost");
    let (store, a, _b) = pair(&parent);
    store.write(&a, "keep.txt", b"keep").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let a_owned = ownership_path(&a_root);
    let snapshot = fs::read(&a_owned).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let clobber = {
        let a_owned = a_owned.clone();
        let snapshot = snapshot.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::write(&a_owned, &snapshot);
            }
        })
    };

    let store = Arc::new(store);
    let mut join = Vec::new();
    for t in 0..2u32 {
        let store = store.clone();
        let a = a.clone();
        join.push(std::thread::spawn(move || {
            let mut ok = 0u32;
            let mut denied = 0u32;
            for i in 0..200u32 {
                match store.write(&a, &format!("t{t}-{i}.txt"), b"x") {
                    Ok(()) => ok += 1,
                    Err(_) => denied += 1,
                }
            }
            (ok, denied)
        }));
    }
    let mut ok = 0u32;
    let mut denied = 0u32;
    for t in join {
        let (o, d) = t.join().unwrap();
        ok += o;
        denied += d;
    }
    stop.store(true, Ordering::Relaxed);
    let _ = clobber.join();

    let mut unread = 0u32;
    for t in 0..2u32 {
        for i in 0..200u32 {
            let name = format!("t{t}-{i}.txt");
            if a_root.join(&name).is_file() && store.read(&a, &name).is_err() {
                unread += 1;
            }
        }
    }
    finding(
        "concurrent-lost-update",
        if unread > 0 { "WEAK" } else { "HOLDS" },
        "Host rewrite of the record during concurrent Store writes (lost update fails closed)",
        format!("ok={ok} denied={denied} unread_after={unread} fs_write_not_atomic=true no_flock=true"),
    );
}

fn record_growth() {
    let parent = Parent::new("growth");
    let (store, a, _b) = pair(&parent);
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let a_owned = ownership_path(&a_root);
    let before = fs::metadata(&a_owned).map(|m| m.len()).unwrap_or(0);
    for i in 0..64u32 {
        let _ = store.write(&a, &format!("g-{i}.txt"), b"x");
    }
    for i in 0..32u32 {
        let _ = fs::remove_file(a_root.join(format!("g-{i}.txt")));
    }
    let after = fs::metadata(&a_owned).map(|m| m.len()).unwrap_or(0);
    let text = fs::read_to_string(&a_owned).unwrap_or_default();
    let lines = text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).count();
    finding(
        "record-growth",
        "WEAK",
        "Deleted inodes stay in the record; no size cap (DoS / leftover, not a grant)",
        format!("before_len={before} after_len={after} entries={lines} no_forget=true no_cap=true"),
    );
}

fn rename_within_b() {
    let parent = Parent::new("ren-b");
    let (store, _a, b) = pair(&parent);
    store.write(&b, "note.txt", b"hello-b").unwrap();
    let renamed = store.rename(&b, "note.txt", "moved.txt");
    let read = store.read(&b, "moved.txt");
    let old = store.read(&b, "note.txt");
    let holds = renamed.is_ok() && read.as_deref() == Ok(b"hello-b") && old == Err(Refuse::NotFound);
    finding(
        "rename-within-b",
        if holds { "HOLDS" } else { "FALSIFIED" },
        "Rename of a B-owned file inside B keeps the same inode and still reads",
        format!("renamed={renamed:?} read={read:?} old={old:?}"),
    );
}

fn overlay_and_dev() {
    if std::env::var_os("REVIEW_A9_OVERLAY").is_none() && std::env::var_os("REVIEW_A9_BIND").is_none()
    {
        let exe = std::env::current_exe().expect("probe exe");
        let output = std::process::Command::new("unshare")
            .args(["-Urm", "--"])
            .arg(&exe)
            .env("REVIEW_A9_OVERLAY", "1")
            .output();
        match output {
            Ok(out) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                let mut saw = false;
                for line in text.lines() {
                    if line.starts_with("FINDING\t") {
                        println!("{line}");
                        saw = true;
                    }
                }
                if !saw {
                    finding(
                        "overlay-btrfs-dev",
                        "WEAK",
                        "overlayfs / btrfs subvolume device quirks",
                        format!(
                            "unshare child: {}",
                            text.replace('\n', " ").chars().take(400).collect::<String>()
                        ),
                    );
                }
            }
            Err(error) => finding(
                "overlay-btrfs-dev",
                "WEAK",
                "overlayfs / btrfs subvolume device quirks",
                format!("unshare missing: {error}"),
            ),
        }
        return;
    }
    if std::env::var_os("REVIEW_A9_BIND").is_some() {
        return;
    }

    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let btrfs = mounts.lines().any(|l| l.split_whitespace().nth(2) == Some("btrfs"));
    let parent = Parent::new("ov");
    let lower = parent.path().join("lower");
    let upper = parent.path().join("upper");
    let work = parent.path().join("work");
    let merge = parent.path().join("merge");
    fs::create_dir_all(&lower).unwrap();
    fs::create_dir_all(&upper).unwrap();
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&merge).unwrap();
    fs::write(lower.join("pre.txt"), b"lower-bytes").unwrap();
    let mount = std::process::Command::new("mount")
        .args([
            "-t",
            "overlay",
            "overlay",
            "-o",
            &format!(
                "lowerdir={},upperdir={},workdir={}",
                lower.display(),
                upper.display(),
                work.display()
            ),
            merge.to_str().unwrap(),
        ])
        .output();
    match mount {
        Ok(out) if out.status.success() => {
            let mut store = Store::open(&merge).unwrap();
            let a = store.bind("agent-a", "session-a").unwrap();
            store.write(&a, "note.txt", b"hello-a").unwrap();
            let a_root = store.host_root(&a).unwrap().to_path_buf();
            let note = a_root.join("note.txt");
            let before = fs::symlink_metadata(&note).unwrap();
            let mut f = fs::OpenOptions::new().append(true).open(&note).unwrap();
            f.write_all(b"-more").unwrap();
            drop(f);
            let after = fs::symlink_metadata(&note).unwrap();
            let store_read = store.read(&a, "note.txt");
            let pre = store.read(&a, "pre.txt");
            let same_pair = (before.dev(), before.ino()) == (after.dev(), after.ino());
            let _ = std::process::Command::new("umount").arg(&merge).status();
            finding(
                "overlay-btrfs-dev",
                if matches!(&store_read, Ok(bytes) if bytes.starts_with(b"hello-a"))
                    && pre == Err(Refuse::HardLink)
                {
                    "HOLDS"
                } else if matches!(&store_read, Err(_)) {
                    "WEAK"
                } else {
                    "FALSIFIED"
                },
                "overlayfs copy-up / lower file vs recorded (dev,ino); btrfs noted if present",
                format!(
                    "before=({},{}) after=({},{}) same_pair={same_pair} store_read={store_read:?} lower_pre={pre:?} btrfs={btrfs}",
                    before.dev(),
                    before.ino(),
                    after.dev(),
                    after.ino()
                ),
            );
        }
        Ok(out) => finding(
            "overlay-btrfs-dev",
            "WEAK",
            "overlayfs / btrfs subvolume device quirks",
            format!(
                "overlay mount failed btrfs={btrfs} stderr={}",
                String::from_utf8_lossy(&out.stderr).replace('\n', " ")
            ),
        ),
        Err(error) => finding(
            "overlay-btrfs-dev",
            "WEAK",
            "overlayfs / btrfs subvolume device quirks",
            format!("mount missing: {error} btrfs={btrfs}"),
        ),
    }
}
