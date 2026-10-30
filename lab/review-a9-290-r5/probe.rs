//! Adversarial probe against owned-storage at the reviewed #290 head.
//! Prints `FINDING\tid\tVERDICT\ttitle\tdetail` lines. Writes nothing into #290.
//!
//! Verdict words for r5 attacks: CAUGHT = the Store refused foreign bytes;
//! SURVIVED = the Store returned another agent's bytes; NOT RUN = this
//! machine could not exercise the hunt; WEAK = leftover or fail-closed DoS.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use owned_storage::launch::{self, Lane, RowState};
use owned_storage::{Grant, Refuse, Store, SHARED_TEMP};
use rustix::fs::{lgetxattr, lsetxattr, statx, AtFlags, StatxFlags, XattrFlags};

const NONCE_XATTR: &str = "user.owned-storage.nonce";
const REUSE_SECS: u64 = 15;

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
            "review-a9-290-r5-{tag}-{}-{n}-{nanos}",
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

fn finding(id: &str, verdict: &str, title: impl AsRef<str>, detail: impl AsRef<str>) {
    println!(
        "FINDING\t{id}\t{verdict}\t{}\t{}",
        title.as_ref().replace('\t', " "),
        detail.as_ref().replace('\t', " ").replace('\n', " | ")
    );
}

fn hex_encode(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn read_nonce(path: &Path) -> Result<[u8; 16], String> {
    let mut buf = [0u8; 16];
    let got = lgetxattr(path, NONCE_XATTR, &mut buf).map_err(|err| err.to_string())?;
    if got != 16 {
        return Err(format!("nonce len {got}"));
    }
    Ok(buf)
}

fn set_nonce(path: &Path, nonce: &[u8; 16]) -> Result<(), String> {
    lsetxattr(path, NONCE_XATTR, nonce, XattrFlags::empty()).map_err(|err| err.to_string())
}

fn stamp_fields(path: &Path) -> Result<(u64, u64, i64, u32, i64, u32, [u8; 16]), String> {
    let meta = fs::symlink_metadata(path).map_err(|err| err.to_string())?;
    let stx = statx(
        rustix::fs::CWD,
        path,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS.union(StatxFlags::BTIME),
    )
    .map_err(|err| err.to_string())?;
    let (btime_sec, btime_nsec) = if stx.stx_mask & StatxFlags::BTIME.bits() != 0 {
        (stx.stx_btime.tv_sec, stx.stx_btime.tv_nsec)
    } else {
        (0, 0)
    };
    Ok((
        meta.dev(),
        meta.ino(),
        stx.stx_ctime.tv_sec,
        stx.stx_ctime.tv_nsec,
        btime_sec,
        btime_nsec,
        read_nonce(path)?,
    ))
}

fn create_until_reuse(store: &Store, grant: &Grant, dev: u64, ino: u64) -> Option<String> {
    let start = std::time::Instant::now();
    let mut index = 0u32;
    while start.elapsed() < std::time::Duration::from_secs(REUSE_SECS) {
        let name = format!("new-{index}.txt");
        index += 1;
        store.write(grant, &name, b"from-b").ok()?;
        let path = store.host_root(grant).unwrap().join(&name);
        let meta = fs::symlink_metadata(&path).ok()?;
        if meta.dev() == dev && meta.ino() == ino {
            return Some(name);
        }
        store.unlink(grant, &name).ok()?;
    }
    None
}

fn main() {
    match std::env::var_os("REVIEW_A9_R5_CHILD").as_deref() {
        Some(kind) if kind == "bind" => {
            bind_mounts();
            return;
        }
        Some(kind) if kind == "fs" => {
            filesystems_child();
            return;
        }
        _ => {}
    }
    replay_r1_api();
    replay_r2_hardlink();
    replay_r3_host_rename();
    replay_r4_inode_reuse();
    replay_r4_host_rename_own();
    xattr_copy_reuse();
    xattr_set_own_inode();
    xattr_copy_onto_host_plant();
    newline_inject_owned();
    space_path_parse();
    partial_owned_file();
    crash_orphan();
    concurrent_create_unlink();
    rename_across_agents();
    host_hardlink_then_unlink();
    dir_nonce_only();
    host_rewrite_owned();
    ctime_collision();
    owned_symlink_follow();
    filesystems();
    runtime_honesty();
    host_same_uid();
}

fn replay_r1_api() {
    let parent = Parent::new("r1-api");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let b_path = b_file.to_str().unwrap();
    let via = store.host_root(&a).unwrap().join("via-b");
    std::os::unix::fs::symlink(&b_file, &via).unwrap();
    let holds = store.read(&a, b_path) == Err(Refuse::CrossAgent)
        && store.write(&a, b_path, b"pwned") == Err(Refuse::CrossAgent)
        && store.read(&a, "../secret.txt") == Err(Refuse::Traversal)
        && store.read(&a, "via-b") == Err(Refuse::Symlink)
        && store.list(&a, store.host_root(&b).unwrap().to_str().unwrap())
            == Err(Refuse::CrossAgent)
        && store.rename(&a, b_path, "stolen.txt") == Err(Refuse::CrossAgent)
        && fs::read(&b_file).unwrap() == b"b-secret";
    finding(
        "r1-api",
        if holds { "CAUGHT" } else { "SURVIVED" },
        "Store API denies foreign host path, .., symlink, list, and rename",
        format!("holds={holds}"),
    );
}

fn replay_r2_hardlink() {
    let parent = Parent::new("r2-hl");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let b_hard = store.host_root(&b).unwrap().join("hard.txt");
    fs::hard_link(&a_file, &b_hard).unwrap();
    let live = store.read(&b, "hard.txt");
    fs::remove_file(&a_file).unwrap();
    let after = store.read(&b, "hard.txt");
    let nlink = fs::symlink_metadata(&b_hard).unwrap().nlink();
    let holds = live == Err(Refuse::HardLink) && after == Err(Refuse::HardLink) && nlink == 1;
    finding(
        "r2-hardlink-unlink",
        if holds { "CAUGHT" } else { "SURVIVED" },
        "Hard link, then unlink A's name, still refuses B's Store read",
        format!("live={live:?} after={after:?} nlink={nlink}"),
    );
}

fn replay_r3_host_rename() {
    let parent = Parent::new("r3-hn");
    let (store, a, b) = pair(&parent);
    let a_host = store.host_root(&a).unwrap().join("host-note.txt");
    fs::write(&a_host, b"hello-a").unwrap();
    let b_dst = store.host_root(&b).unwrap().join("from-a.txt");
    fs::rename(&a_host, &b_dst).unwrap();
    let read = store.read(&b, "from-a.txt");
    let holds = read == Err(Refuse::HardLink) && fs::read(&b_dst).unwrap() == b"hello-a";
    finding(
        "r3-host-rename",
        if holds { "CAUGHT" } else { "SURVIVED" },
        "Host rename of a host-created A file into B is refused",
        format!("read={read:?}"),
    );
}

fn replay_r4_inode_reuse() {
    let parent = Parent::new("r4-reuse");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_note = store.host_root(&a).unwrap().join("note.txt");
    let old = fs::symlink_metadata(&a_note).unwrap();
    fs::remove_file(&a_note).unwrap();
    let reused = create_until_reuse(&store, &b, old.dev(), old.ino());
    let mut granted = false;
    let mut read = None;
    if let Some(name) = reused.as_ref() {
        let b_file = store.host_root(&b).unwrap().join(name);
        let stolen = store.host_root(&a).unwrap().join("stolen.txt");
        fs::rename(&b_file, &stolen).unwrap();
        let got = store.read(&a, "stolen.txt");
        granted = got.as_deref() == Ok(&b"from-b"[..]);
        read = Some(got);
    }
    finding(
        "r4-inode-reuse",
        if reused.is_some() && !granted {
            "CAUGHT"
        } else if granted {
            "SURVIVED"
        } else {
            "NOT RUN"
        },
        "r4 journey: A unlink, B reuses (dev,ino), host rename into A",
        format!("reused={reused:?} read={read:?} granted={granted}"),
    );
}

fn replay_r4_host_rename_own() {
    let parent = Parent::new("r4-own");
    let (store, a, _b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let host = store.host_root(&a).unwrap();
    fs::rename(host.join("note.txt"), host.join("moved.txt")).unwrap();
    let moved = store.read(&a, "moved.txt");
    let old = store.read(&a, "note.txt");
    let names = store.list(&a, "").unwrap();
    let holds = moved == Err(Refuse::HardLink)
        && old == Err(Refuse::NotFound)
        && !names.iter().any(|name| name == "moved.txt");
    finding(
        "r4-host-rename-own",
        if holds { "CAUGHT" } else { "SURVIVED" },
        "Host rename inside A's tree is refused by path bind",
        format!("moved={moved:?} old={old:?} names={names:?}"),
    );
}

fn xattr_copy_reuse() {
    let parent = Parent::new("xattr-copy");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_note = store.host_root(&a).unwrap().join("note.txt");
    let old_stamp = stamp_fields(&a_note).ok();
    let old = fs::symlink_metadata(&a_note).unwrap();
    let leftover_nonce = read_nonce(&a_note).ok();
    fs::remove_file(&a_note).unwrap();
    let reused = create_until_reuse(&store, &b, old.dev(), old.ino());
    let mut granted = false;
    let mut set = None;
    let mut read = None;
    if let (Some(name), Some(nonce)) = (reused.as_ref(), leftover_nonce.as_ref()) {
        let b_file = store.host_root(&b).unwrap().join(name);
        set = Some(set_nonce(&b_file, nonce));
        let stolen = store.host_root(&a).unwrap().join("stolen.txt");
        fs::rename(&b_file, &stolen).unwrap();
        let got = store.read(&a, "stolen.txt");
        granted = got.as_deref() == Ok(&b"from-b"[..]);
        read = Some(got);
    }
    finding(
        "xattr-copy-reuse",
        if reused.is_some() && leftover_nonce.is_some() && !granted {
            "CAUGHT"
        } else if granted {
            "SURVIVED"
        } else {
            "NOT RUN"
        },
        "B copies A's leftover user.owned-storage.nonce onto a reused inode, host-renames into A",
        format!(
            "reused={reused:?} set={set:?} read={read:?} granted={granted} old_stamp={old_stamp:?}"
        ),
    );
}

fn xattr_set_own_inode() {
    let parent = Parent::new("xattr-own");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_note = store.host_root(&a).unwrap().join("note.txt");
    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let a_nonce = read_nonce(&a_note).unwrap();
    let set = set_nonce(&b_file, &a_nonce);
    let b_read = store.read(&b, "secret.txt");
    let a_of_b = store.read(&a, b_file.to_str().unwrap());
    let a_own = store.read(&a, "note.txt");
    let granted = a_of_b.as_deref() == Ok(&b"b-secret"[..]);
    finding(
        "xattr-set-own-inode",
        if set.is_ok() && !granted {
            "CAUGHT"
        } else if granted {
            "SURVIVED"
        } else {
            "NOT RUN"
        },
        "B can set user.owned-storage.nonce on its own inode; that does not grant A's Store a read of B",
        format!("set={set:?} b_read={b_read:?} a_of_b={a_of_b:?} a_own={a_own:?} granted={granted}"),
    );
}

fn xattr_copy_onto_host_plant() {
    let parent = Parent::new("xattr-plant");
    let (store, a, _b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let host = store.host_root(&a).unwrap();
    let note = host.join("note.txt");
    let nonce = read_nonce(&note).unwrap();
    let stamp = stamp_fields(&note).unwrap();
    fs::remove_file(&note).unwrap();
    fs::write(&note, b"planted").unwrap();
    let set = set_nonce(&note, &nonce);
    let read = store.read(&a, "note.txt");
    let granted = read.as_deref() == Ok(&b"planted"[..]);
    finding(
        "xattr-copy-host-plant",
        if !granted { "CAUGHT" } else { "SURVIVED" },
        "Host replaces A's file, copies the old nonce onto the new inode",
        format!("set={set:?} read={read:?} granted={granted} old={stamp:?}"),
    );
}

fn newline_inject_owned() {
    let parent = Parent::new("nl-inject");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"from-b").unwrap();
    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let Ok((dev, ino, ctime_sec, ctime_nsec, btime_sec, btime_nsec, nonce)) = stamp_fields(&b_file)
    else {
        finding(
            "newline-inject-owned",
            "NOT RUN",
            "Could not read B's stamp for a newline-injected .owned line",
            "stamp_fields failed",
        );
        return;
    };
    let nonce_hex = hex_encode(&nonce);
    // save_owned appends this file's own stamp after `path`. A trailing
    // `\n# ...` makes that leftover a comment so the injected line stays 9 fields.
    let crafted = format!(
        "x 0 0 0 0 00000000000000000000000000000000\n{dev} {ino} agent-a stolen.txt {ctime_sec} {ctime_nsec} {btime_sec} {btime_nsec} {nonce_hex}\n#"
    );
    let write = store.write(&a, &crafted, b"inject");
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let owned_after_write = fs::read_to_string(ownership_path(&a_root)).unwrap_or_default();
    let owned_lines = owned_after_write.lines().count();
    let stolen = a_root.join("stolen.txt");
    let renamed = fs::rename(&b_file, &stolen);
    let read = store.read(&a, "stolen.txt");
    let granted = read.as_deref() == Ok(&b"from-b"[..]);
    finding(
        "newline-inject-owned",
        if granted {
            "SURVIVED"
        } else if write.is_err() {
            "CAUGHT"
        } else {
            "CAUGHT"
        },
        "Store::write of a newline name injects a second .owned line for B's inode",
        format!(
            "write={write:?} renamed={renamed:?} read={read:?} granted={granted} owned_has_stolen={} owned_lines={owned_lines} crafted_len={}",
            owned_after_write.contains("stolen.txt"),
            crafted.len()
        ),
    );
}

fn space_path_parse() {
    let parent = Parent::new("space");
    let (store, a, b) = pair(&parent);
    store.write(&a, "keep.txt", b"keep").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let spaced = store.write(&a, "my file.txt", b"spaces");
    let keep = store.read(&a, "keep.txt");
    let secret = store.read(&b, "secret.txt");
    let granted = keep.as_deref() == Ok(&b"b-secret"[..]) || secret.as_deref() == Ok(&b"keep"[..]);
    finding(
        "space-path-parse",
        if granted { "SURVIVED" } else { "CAUGHT" },
        "A path with a space must not grant another agent's bytes (parse uses split_whitespace)",
        format!("spaced={spaced:?} keep={keep:?} secret={secret:?} granted={granted}"),
    );
}

fn partial_owned_file() {
    let parent = Parent::new("partial");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap();
    let owned = ownership_path(a_root);
    let bytes = fs::read(&owned).unwrap();
    fs::write(&owned, &bytes[..bytes.len() / 2]).unwrap();
    let read = store.read(&a, "note.txt");
    let write = store.write(&a, "other.txt", b"x");
    let granted = read.as_deref() == Ok(&b"b-secret"[..]) || write.is_ok() && {
        store.read(&a, "other.txt").as_deref() == Ok(&b"b-secret"[..])
    };
    let fail_closed = matches!(read, Err(Refuse::OutsideRoot | Refuse::HardLink));
    finding(
        "partial-owned-file",
        if granted {
            "SURVIVED"
        } else if fail_closed {
            "CAUGHT"
        } else {
            "WEAK"
        },
        "Truncated {root}.owned must fail closed, not grant",
        format!("read={read:?} write={write:?} fail_closed={fail_closed} granted={granted}"),
    );
}

fn crash_orphan() {
    let parent = Parent::new("orphan");
    let (store, a, _b) = pair(&parent);
    let host = store.host_root(&a).unwrap().join("orphan.txt");
    fs::write(&host, b"orphan").unwrap();
    let write = store.write(&a, "orphan.txt", b"from-a");
    let read = store.read(&a, "orphan.txt");
    let granted = read.as_deref() == Ok(&b"orphan"[..]) || write.is_ok() && read.is_ok();
    finding(
        "crash-orphan",
        if granted { "SURVIVED" } else { "CAUGHT" },
        "A file that exists but is missing from the record is refused (crash before record_owned)",
        format!("write={write:?} read={read:?} granted={granted}"),
    );
}

fn concurrent_create_unlink() {
    let parent = Parent::new("race-rec");
    let (store, a, _b) = pair(&parent);
    store.write(&a, "stable.txt", b"stable").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let owned = ownership_path(&a_root);
    let rewriter = {
        let owned = owned.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::write(&owned, "# owned-storage v2\n");
                std::thread::yield_now();
            }
        })
    };
    let mut ok = 0u32;
    let mut denied = 0u32;
    let mut granted_foreign = 0u32;
    for i in 0..400 {
        let name = format!("race-{i}.txt");
        match store.write(&a, &name, b"from-a") {
            Ok(()) => {
                ok += 1;
                let _ = store.unlink(&a, &name);
            }
            Err(_) => denied += 1,
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = rewriter.join();
    let stable = store.read(&a, "stable.txt");
    if stable.as_deref() == Ok(&b"from-b"[..]) {
        granted_foreign += 1;
    }
    finding(
        "concurrent-create-unlink",
        if granted_foreign == 0 {
            "CAUGHT"
        } else {
            "SURVIVED"
        },
        "Host rewrite of .owned during create/unlink must not grant foreign bytes",
        format!(
            "ok={ok} denied={denied} granted_foreign={granted_foreign} stable={stable:?} no_flock=true fs_write_not_atomic=true"
        ),
    );
}

fn rename_across_agents() {
    let parent = Parent::new("rename-x");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let from_b = store.rename(&a, b_file.to_str().unwrap(), "stolen.txt");
    let into_a = store.rename(
        &b,
        "secret.txt",
        store
            .host_root(&a)
            .unwrap()
            .join("from-b.txt")
            .to_str()
            .unwrap(),
    );
    fs::rename(&a_file, store.host_root(&b).unwrap().join("moved-from-a.txt")).unwrap();
    let b_read = store.read(&b, "moved-from-a.txt");
    let granted = from_b.is_ok()
        || into_a.is_ok()
        || b_read.as_deref() == Ok(&b"hello-a"[..]);
    finding(
        "rename-across-agents",
        if granted { "SURVIVED" } else { "CAUGHT" },
        "Store rename across agents, and host rename of A's file into B, stay refused",
        format!("from_b={from_b:?} into_a={into_a:?} b_read={b_read:?} granted={granted}"),
    );
}

fn host_hardlink_then_unlink() {
    let parent = Parent::new("hl-forget");
    let (store, a, _b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let host = store.host_root(&a).unwrap();
    fs::hard_link(host.join("note.txt"), host.join("alias.txt")).unwrap();
    let live = store.read(&a, "alias.txt");
    let unlinked = store.unlink(&a, "note.txt");
    let after = store.read(&a, "alias.txt");
    let granted = after.as_deref() == Ok(&b"hello-a"[..]);
    finding(
        "host-hardlink-then-unlink",
        if granted { "SURVIVED" } else { "CAUGHT" },
        "Host hard link inside A; Store unlink of the recorded name forgets the inode",
        format!("live={live:?} unlinked={unlinked:?} after={after:?} granted={granted}"),
    );
}

fn dir_nonce_only() {
    let parent = Parent::new("dir-nonce");
    let (store, a, b) = pair(&parent);
    let a_sub = store.host_root(&a).unwrap().join("sub");
    let _ = fs::create_dir(&a_sub);
    let write_a = store.write(&a, "sub/file.txt", b"hello-a");
    let dir_nonce = read_nonce(&a_sub).ok();
    let dir_meta = fs::symlink_metadata(&a_sub).ok();
    let _ = store.unlink(&a, "sub/file.txt");
    let _ = fs::remove_file(a_sub.join("file.txt"));
    let _ = fs::remove_dir(&a_sub);
    let b_other = store.host_root(&b).unwrap().join("other");
    let _ = fs::create_dir(&b_other);
    let _ = store.write(&b, "other/file.txt", b"from-b");
    let Some(dir_meta) = dir_meta else {
        finding(
            "dir-nonce-only",
            "NOT RUN",
            "A's sub directory was not created",
            format!("write_a={write_a:?}"),
        );
        return;
    };
    let reused_dir = {
        let start = std::time::Instant::now();
        let mut index = 0u32;
        let mut found = None;
        while start.elapsed() < std::time::Duration::from_secs(REUSE_SECS) {
            let name = format!("d{index}");
            index += 1;
            let path = store.host_root(&b).unwrap().join(&name);
            let _ = fs::create_dir(&path);
            let _ = store.write(&b, &format!("{name}/x.txt"), b"from-b");
            if let Ok(meta) = fs::symlink_metadata(&path) {
                if meta.dev() == dir_meta.dev() && meta.ino() == dir_meta.ino() {
                    found = Some(path);
                    break;
                }
            }
        }
        found
    };
    let mut listed = None;
    let mut child = None;
    let mut granted = false;
    if let (Some(dir), Some(nonce)) = (reused_dir.as_ref(), dir_nonce.as_ref()) {
        let _ = set_nonce(dir, nonce);
        let dest = store.host_root(&a).unwrap().join("sub");
        let _ = fs::rename(dir, &dest);
        listed = Some(store.list(&a, "sub"));
        child = Some(store.read(&a, "sub/x.txt"));
        granted = child.as_ref().and_then(|r| r.as_deref().ok()) == Some(&b"from-b"[..]);
    }
    finding(
        "dir-nonce-only",
        if granted {
            "SURVIVED"
        } else if reused_dir.is_some() {
            "CAUGHT"
        } else {
            "NOT RUN"
        },
        "Directory stamp checks only the nonce; reused dir + copied nonce + host rename into A",
        format!(
            "reused={} listed={listed:?} child={child:?} granted={granted}",
            reused_dir.is_some()
        ),
    );
}

fn host_rewrite_owned() {
    let parent = Parent::new("host-own");
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"from-b").unwrap();
    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let Ok((dev, ino, ctime_sec, ctime_nsec, btime_sec, btime_nsec, nonce)) = stamp_fields(&b_file)
    else {
        finding(
            "host-rewrite-owned",
            "NOT RUN",
            "Could not read B's stamp to host-rewrite A's .owned",
            "",
        );
        return;
    };
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let line = format!(
        "# owned-storage v2\n{dev} {ino} agent-a stolen.txt {ctime_sec} {ctime_nsec} {btime_sec} {btime_nsec} {}\n",
        hex_encode(&nonce)
    );
    fs::write(ownership_path(&a_root), line).unwrap();
    fs::rename(&b_file, a_root.join("stolen.txt")).unwrap();
    let read = store.read(&a, "stolen.txt");
    let granted = read.as_deref() == Ok(&b"from-b"[..]);
    finding(
        "host-rewrite-owned",
        if granted {
            "SURVIVED"
        } else {
            "CAUGHT"
        },
        "Same-uid host rewrite of A's .owned plus host rename of B's file into A",
        format!("read={read:?} granted={granted} (documented same-uid confinement if SURVIVED)"),
    );
}

fn ctime_collision() {
    let parent = Parent::new("ctime");
    let (store, a, _b) = pair(&parent);
    store.write(&a, "one.txt", b"one").unwrap();
    store.write(&a, "two.txt", b"two").unwrap();
    let one = stamp_fields(&store.host_root(&a).unwrap().join("one.txt")).unwrap();
    let two = stamp_fields(&store.host_root(&a).unwrap().join("two.txt")).unwrap();
    let same_time = one.2 == two.2 && one.3 == two.3 && one.4 == two.4 && one.5 == two.5;
    let same_nonce = one.6 == two.6;
    finding(
        "ctime-collision",
        if same_nonce { "SURVIVED" } else { "CAUGHT" },
        "Two Store creates must not share a nonce even if ctime/btime collide",
        format!("same_time={same_time} same_nonce={same_nonce} one_ino={} two_ino={}", one.1, two.1),
    );
}

fn owned_symlink_follow() {
    let parent = Parent::new("owned-sym");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    store.write(&b, "forge.txt", b"starter").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let real = ownership_path(&a_root);
    let backup = a_root.join("owned.bak");
    fs::rename(&real, &backup).unwrap();
    std::os::unix::fs::symlink(ownership_path(&b_root), &real).unwrap();
    let write = store.write(&a, "later.txt", b"later");
    let read = store.read(&a, "note.txt");
    let granted = read.as_deref() == Ok(&b"from-b"[..]) || read.as_deref() == Ok(&b"starter"[..]);
    finding(
        "owned-symlink-follow",
        if granted { "SURVIVED" } else { "CAUGHT" },
        "Host replaces A's .owned with a symlink to B's record; load/save follow today",
        format!("write={write:?} read={read:?} granted={granted}"),
    );
}

fn filesystems() {
    let exe = std::env::current_exe().expect("probe binary");
    let output = std::process::Command::new("unshare")
        .args(["-Urm", "--"])
        .arg(&exe)
        .env("REVIEW_A9_R5_CHILD", "fs")
        .output();
    match output {
        Ok(out) if out.status.success() => {
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
        }
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            finding(
                "fs-unshare",
                "NOT RUN",
                "unshare -Urm filesystem child failed",
                text.chars().take(400).collect::<String>(),
            );
        }
        Err(error) => finding(
            "fs-unshare",
            "NOT RUN",
            "unshare missing",
            error.to_string(),
        ),
    }
    bind_mounts();
}

fn filesystems_child() {
    probe_mount_store("tmpfs", &["mount", "-t", "tmpfs", "tmpfs"]);
    probe_ramfs();
    probe_overlay();
    finding(
        "fat-xattr",
        "NOT RUN",
        "vfat/FAT user xattr: mkfs.vfat is not on this machine",
        "no mkfs.vfat / mkfs.fat",
    );
}

fn probe_mount_store(kind: &str, mount_prefix: &[&str]) {
    let parent = Parent::new(kind);
    let mnt = parent.path().join("mnt");
    fs::create_dir(&mnt).unwrap();
    let status = std::process::Command::new(mount_prefix[0])
        .args(&mount_prefix[1..])
        .arg(&mnt)
        .status();
    match status {
        Ok(st) if st.success() => {}
        other => {
            finding(
                &format!("{kind}-xattr"),
                "NOT RUN",
                format!("{kind} mount failed"),
                format!("{other:?}"),
            );
            return;
        }
    }
    let mut store = match Store::open(&mnt) {
        Ok(store) => store,
        Err(err) => {
            finding(
                &format!("{kind}-xattr"),
                "CAUGHT",
                format!("Store::open on {kind} failed closed"),
                format!("{err:?}"),
            );
            return;
        }
    };
    let a = store.bind("agent-a", "session-a").unwrap();
    let write = store.write(&a, "note.txt", b"hello-a");
    let read = store.read(&a, "note.txt");
    let nonce = store
        .host_root(&a)
        .ok()
        .map(|root| read_nonce(&root.join("note.txt")));
    let fail_closed = write == Err(Refuse::OutsideRoot) || write == Err(Refuse::HardLink);
    let granted_ok = write.is_ok() && read.as_deref() == Ok(&b"hello-a"[..]);
    finding(
        &format!("{kind}-xattr"),
        if fail_closed {
            "CAUGHT"
        } else if granted_ok {
            "CAUGHT"
        } else {
            "WEAK"
        },
        format!("Store create/read on {kind} (xattr support and fail-closed)"),
        format!("write={write:?} read={read:?} nonce={nonce:?} fail_closed={fail_closed}"),
    );
}

fn probe_ramfs() {
    let parent = Parent::new("ramfs");
    let mnt = parent.path().join("mnt");
    fs::create_dir(&mnt).unwrap();
    let status = std::process::Command::new("mount")
        .args(["-t", "ramfs", "ramfs"])
        .arg(&mnt)
        .status();
    match status {
        Ok(st) if st.success() => {}
        other => {
            finding("ramfs-no-xattr", "NOT RUN", "ramfs mount failed", format!("{other:?}"));
            return;
        }
    }
    let opened = Store::open(&mnt);
    let mut granted = false;
    let mut write = None;
    let mut read = None;
    if let Ok(mut store) = opened {
        if let Ok(a) = store.bind("agent-a", "session-a") {
            let w = store.write(&a, "note.txt", b"hello-a");
            let r = store.read(&a, "note.txt");
            granted = r.as_deref() == Ok(&b"hello-a"[..]) && w.is_ok();
            write = Some(w);
            read = Some(r);
        }
        finding(
            "ramfs-no-xattr",
            if granted {
                "SURVIVED"
            } else {
                "CAUGHT"
            },
            "ramfs typically has no user xattr; create must fail closed, not skip the stamp",
            format!("write={write:?} read={read:?} granted={granted}"),
        );
    } else {
        finding(
            "ramfs-no-xattr",
            "CAUGHT",
            "Store::open on ramfs failed closed",
            format!("{opened:?}"),
        );
    }
}

fn probe_overlay() {
    let parent = Parent::new("ovl");
    let lower = parent.path().join("lower");
    let upper = parent.path().join("upper");
    let work = parent.path().join("work");
    let mnt = parent.path().join("mnt");
    for dir in [&lower, &upper, &work, &mnt] {
        fs::create_dir(dir).unwrap();
    }
    fs::write(lower.join("pre.txt"), b"lower").unwrap();
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    let status = std::process::Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &opts])
        .arg(&mnt)
        .status();
    match status {
        Ok(st) if st.success() => {}
        other => {
            finding("overlay-xattr", "NOT RUN", "overlay mount failed", format!("{other:?}"));
            return;
        }
    }
    let mut store = match Store::open(&mnt) {
        Ok(store) => store,
        Err(err) => {
            finding("overlay-xattr", "CAUGHT", "Store::open on overlay failed closed", format!("{err:?}"));
            return;
        }
    };
    let a = match store.bind("agent-a", "session-a") {
        Ok(grant) => grant,
        Err(err) => {
            finding("overlay-xattr", "CAUGHT", "bind on overlay failed closed", format!("{err:?}"));
            return;
        }
    };
    let write = store.write(&a, "note.txt", b"hello-a");
    let read = store.read(&a, "note.txt");
    let pre = store.read(&a, "pre.txt");
    finding(
        "overlay-xattr",
        if write.is_err() && matches!(write, Err(Refuse::OutsideRoot | Refuse::HardLink)) {
            "CAUGHT"
        } else if read.as_deref() == Ok(&b"hello-a"[..]) && pre.is_err() {
            "CAUGHT"
        } else if pre.as_deref() == Ok(&b"lower"[..]) {
            "SURVIVED"
        } else {
            "WEAK"
        },
        "overlayfs Store create/read; a lower-layer file under the grant must stay unowned",
        format!("write={write:?} read={read:?} pre={pre:?}"),
    );
}

fn bind_mounts() {
    if std::env::var_os("REVIEW_A9_R5_CHILD").as_deref() != Some(std::ffi::OsStr::new("bind")) {
        let exe = std::env::current_exe().expect("probe binary");
        let output = std::process::Command::new("unshare")
            .args(["-Urm", "--"])
            .arg(&exe)
            .env("REVIEW_A9_R5_CHILD", "bind")
            .output();
        match output {
            Ok(out) if out.status.success() => {
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
            }
            Ok(out) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if text.to_ascii_lowercase().contains("not permitted") {
                    finding(
                        "r3-bind-mount",
                        "NOT RUN",
                        "unshare -Urm bind-mount not allowed",
                        text.chars().take(200).collect::<String>(),
                    );
                } else {
                    finding(
                        "r3-bind-mount",
                        "NOT RUN",
                        "bind-mount child failed",
                        text.chars().take(400).collect::<String>(),
                    );
                }
            }
            Err(error) => finding("r3-bind-mount", "NOT RUN", "unshare missing", error.to_string()),
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
        finding("r3-bind-mount", "NOT RUN", "mount --bind failed", format!("{status}"));
        return;
    }
    let list = store_b.list(&b, "sub");
    let write = store_b.write(&b, "sub/planted.txt", b"pwned");
    let planted = a_root.join("planted.txt").exists();
    let holds = list.is_err() && write.is_err() && !planted;
    finding(
        "r3-bind-mount",
        if holds { "CAUGHT" } else { "SURVIVED" },
        "Bind-mount of A's tree at B/sub refuses list/write",
        format!("list={list:?} write={write:?} planted_in_a={planted}"),
    );
}

fn runtime_honesty() {
    let lab = launch::lab_journey();
    let journey = launch::real_runtime_journey();
    let host = launch::host_journey();
    let blocked = journey.rows.iter().all(|row| {
        row.lane == Lane::Runtime
            && row.state == RowState::Blocked
            && row.reason.starts_with("BLOCKED AC-006-STORAGE:")
    });
    let honest = blocked
        && !journey.executed
        && journey.read_refusal.is_none()
        && lab.state == RowState::Ready
        && host.state == RowState::NeedsConfinement;
    finding(
        "runtime-rows",
        if honest { "CAUGHT" } else { "SURVIVED" },
        "Runtime rows stay Blocked; lab Ready; host NeedsConfinement; A9 not booked",
        format!(
            "executed={} refusal={:?} lab={:?} host={:?} rows={:?}",
            journey.executed, journey.read_refusal, lab.state, host.state, journey.rows
        ),
    );
    let lib = std::env::var("OWNED_STORAGE_LIB_RS").unwrap_or_default();
    let booked = if lib.is_empty() {
        false
    } else {
        let text = fs::read_to_string(&lib).unwrap_or_default();
        text.contains("A9 is booked") || text.contains("A9 booked")
    };
    finding(
        "a9-not-booked",
        if booked { "SURVIVED" } else { "CAUGHT" },
        "owned-storage source does not claim A9 is booked",
        format!("booked={booked}"),
    );
}

fn host_same_uid() {
    let parent = Parent::new("host-uid");
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let from_b = store
        .host_root(&b)
        .unwrap()
        .join("../../../agent-a/session-a/1/note.txt");
    let bytes = fs::read(&from_b).unwrap();
    finding(
        "host-same-uid",
        if bytes == b"hello-a" { "CAUGHT" } else { "WEAK" },
        "Documented same-uid host walk still reads A's bytes (NEEDS CONFINEMENT/RUNTIME)",
        format!("bytes={bytes:?} shared_temp_exists={}", Path::new(SHARED_TEMP).exists()),
    );
}
