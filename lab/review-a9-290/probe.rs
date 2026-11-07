//! Adversarial probes against PR #290's lab store.
//!
//! Compiled against the reviewed `owned-storage` crate via a scratch
//! manifest. This file lives only in `lab/review-a9-290`. It does not
//! edit #290.

use owned_storage::launch::{
    self, shared_temp_constructor_count, storage_provider_is_unused_for_reads, RowState,
    SHARED_TEMP_CONSTRUCTOR,
};
use owned_storage::{Refuse, Store, SHARED_TEMP};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct Parent {
    path: PathBuf,
}

impl Parent {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "review-a9-290-{}-{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Parent {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn pair(parent: &Parent) -> (Store, owned_storage::Grant, owned_storage::Grant) {
    let mut store = Store::open(parent.path()).unwrap();
    let a = store.bind("agent-a", "session-a").unwrap();
    let b = store.bind("agent-b", "session-b").unwrap();
    (store, a, b)
}

fn finding(id: &str, verdict: &str, title: &str, detail: &str) {
    let detail = detail.replace('\t', " ").replace('\n', " | ");
    println!("FINDING\t{id}\t{verdict}\t{title}\t{detail}");
}

fn main() {
    api_read_write();
    api_list_rename_absent();
    host_list_read_write();
    host_rename_into();
    host_hardlink();
    host_symlink_follow();
    root_replaced_with_symlink();
    denial_reasons();
    shared_temp_lab_and_runtime();
    runtime_rows_and_skips();
    grant_shape_vs_a5();
    host_root_leak();
}

fn api_read_write() {
    let parent = Parent::new();
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let b_file = store.host_root(&b).unwrap().join("secret.txt");
    let path = b_file.to_str().unwrap();

    let read = store.read(&a, path);
    let write = store.write(&a, path, b"overwrite");
    let after = fs::read(&b_file).unwrap();
    let holds = read.as_ref().err() == Some(&Refuse::CrossAgent)
        && write.as_ref().err() == Some(&Refuse::CrossAgent)
        && after == b"b-secret";
    finding(
        "api-read-write",
        if holds { "HOLDS" } else { "FALSIFIED" },
        "Store API denies A's read and write of B's host path",
        &format!("read={read:?} write={write:?} after={}", String::from_utf8_lossy(&after)),
    );

    let trav = store.read(&a, "../../../agent-b/session-b/2/secret.txt");
    finding(
        "api-traversal",
        if trav.as_ref().err() == Some(&Refuse::Traversal) {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Store API denies a .. path toward B",
        &format!("read={trav:?}"),
    );
}

fn api_list_rename_absent() {
    finding(
        "api-list-absent",
        "WEAK",
        "Store has no list operation, so it cannot deny a listing",
        "owned-storage public API is open, bind, read, write, host_root, cleanup, yard. No list.",
    );
    finding(
        "api-rename-absent",
        "WEAK",
        "Store has no rename operation, so it cannot deny a rename-into",
        "owned-storage public API has no rename, link, or symlink method.",
    );
}

fn host_list_read_write() {
    let parent = Parent::new();
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    let via_b = b_root
        .join("..")
        .join("..")
        .join("..")
        .join("agent-a")
        .join("session-a")
        .join("1");
    let listed = fs::read_dir(&via_b)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let leaked = fs::read(via_b.join("note.txt")).unwrap_or_default();
    fs::write(via_b.join("planted-by-b.txt"), b"from-b").unwrap();
    let planted = store.read(&a, "planted-by-b.txt");
    finding(
        "host-list",
        if listed.iter().any(|name| name == "note.txt") {
            "FALSIFIED"
        } else {
            "HOLDS"
        },
        "From B's host root, a sibling walk lists A's files",
        &format!("via_b={} names={listed:?}", via_b.display()),
    );
    finding(
        "host-read",
        if leaked == b"hello-a" {
            "FALSIFIED"
        } else {
            "HOLDS"
        },
        "From B's host root, a sibling walk reads A's bytes",
        &format!("leaked={}", String::from_utf8_lossy(&leaked)),
    );
    finding(
        "host-write",
        if planted.as_deref() == Ok(&b"from-b"[..]) {
            "FALSIFIED"
        } else {
            "HOLDS"
        },
        "From B's host root, a sibling walk writes into A's root",
        &format!("store_read={planted:?} a_root={}", a_root.display()),
    );
}

fn host_rename_into() {
    let parent = Parent::new();
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let src = store.host_root(&a).unwrap().join("note.txt");
    let dest = store.host_root(&b).unwrap().join("from-a.txt");
    let renamed = fs::rename(&src, &dest);
    let in_b = store.read(&b, "from-a.txt");
    let gone = store.read(&a, "note.txt");
    finding(
        "host-rename-into",
        if renamed.is_ok() && in_b.as_deref() == Ok(&b"hello-a"[..]) {
            "FALSIFIED"
        } else {
            "WEAK"
        },
        "Host rename moves A's file into B's root; Store then serves it to B",
        &format!("rename={renamed:?} b_read={in_b:?} a_read={gone:?}"),
    );
}

fn host_hardlink() {
    let parent = Parent::new();
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let src = store.host_root(&a).unwrap().join("note.txt");
    let dest = store.host_root(&b).unwrap().join("hard.txt");
    match fs::hard_link(&src, &dest) {
        Ok(()) => {
            let via_store = store.read(&b, "hard.txt");
            let via_host = fs::read(&dest).unwrap_or_default();
            fs::write(&src, b"changed-by-a").unwrap();
            let after = store.read(&b, "hard.txt");
            finding(
                "host-hardlink",
                if via_store.as_deref() == Ok(&b"hello-a"[..]) {
                    "FALSIFIED"
                } else {
                    "HOLDS"
                },
                "A host hard link in B's root is a Store read of A's inode",
                &format!(
                    "store_read={via_store:?} host={} after_a_write={after:?}",
                    String::from_utf8_lossy(&via_host)
                ),
            );
        }
        Err(error) => finding(
            "host-hardlink",
            "WEAK",
            "Host hard link was not created on this filesystem",
            &format!("hard_link error={error}"),
        ),
    }
}

fn host_symlink_follow() {
    let parent = Parent::new();
    let (store, a, b) = pair(&parent);
    store.write(&a, "note.txt", b"hello-a").unwrap();
    let a_file = store.host_root(&a).unwrap().join("note.txt");
    let link = store.host_root(&b).unwrap().join("via-a");
    std::os::unix::fs::symlink(&a_file, &link).unwrap();
    let denied = store.read(&b, "via-a");
    let host_bytes = fs::read(&link).unwrap_or_default();
    finding(
        "api-symlink",
        if denied.as_ref().err() == Some(&Refuse::Symlink) {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Store API refuses a symlink that leaves B's root",
        &format!("store_read={denied:?}"),
    );
    finding(
        "host-symlink",
        if host_bytes == b"hello-a" {
            "FALSIFIED"
        } else {
            "HOLDS"
        },
        "The same symlink is readable on the host",
        &format!("host={}", String::from_utf8_lossy(&host_bytes)),
    );
}

fn root_replaced_with_symlink() {
    let parent = Parent::new();
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let a_root = store.host_root(&a).unwrap().to_path_buf();
    let b_root = store.host_root(&b).unwrap().to_path_buf();
    fs::remove_dir_all(&a_root).unwrap();
    std::os::unix::fs::symlink(&b_root, &a_root).unwrap();
    let leaked = store.read(&a, "secret.txt");
    let wrote = store.write(&a, "pwned.txt", b"from-a");
    let in_b = store.read(&b, "pwned.txt");
    finding(
        "root-symlink-swap",
        if leaked.as_deref() == Ok(&b"b-secret"[..]) || in_b.as_deref() == Ok(&b"from-a"[..]) {
            "FALSIFIED"
        } else {
            "HOLDS"
        },
        "Replacing A's host root with a symlink to B's root bypasses Store checks",
        &format!("read={leaked:?} write={wrote:?} b_read={in_b:?}"),
    );
}

fn denial_reasons() {
    let parent = Parent::new();
    let (store, a, b) = pair(&parent);
    store.write(&b, "secret.txt", b"b-secret").unwrap();
    let path = store
        .host_root(&b)
        .unwrap()
        .join("secret.txt")
        .to_str()
        .unwrap()
        .to_owned();
    let cross = store.read(&a, &path).unwrap_err();
    let trav = store.read(&a, "../x").unwrap_err();
    let shared = Store::open(Path::new(SHARED_TEMP)).unwrap_err();
    let specific = cross.to_string() == "cross-agent storage is refused"
        && trav.to_string() == "path traversal is refused"
        && shared.to_string() == "shared temp directory is not agent storage"
        && !cross.to_string().contains("error")
        && cross != trav
        && trav != shared;
    finding(
        "specific-reason",
        if specific { "HOLDS" } else { "FALSIFIED" },
        "Lab refusals carry a distinct reason string per class",
        &format!("cross={cross} trav={trav} shared={shared}"),
    );
}

fn shared_temp_lab_and_runtime() {
    let existed = Path::new(SHARED_TEMP).exists();
    let denied = Store::open(Path::new(SHARED_TEMP));
    let created = Path::new(SHARED_TEMP).exists();
    finding(
        "lab-shared-temp",
        if denied.as_ref().err() == Some(&Refuse::SharedTemp) && existed == created {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "Lab Store::open refuses /tmp/elastos/storage and does not create it",
        &format!("denied={denied:?} existed={existed} created={created}"),
    );

    let run_cmd = launch::read_repo_file("elastos/crates/elastos-server/src/run_cmd.rs");
    let share_cmd = launch::read_repo_file("elastos/crates/elastos-server/src/share_cmd.rs");
    let runtime_rs = launch::read_repo_file("elastos/crates/elastos-server/src/runtime.rs");
    let run_count = shared_temp_constructor_count(&run_cmd);
    let share_count = share_cmd.matches(SHARED_TEMP_CONSTRUCTOR).count();
    let unused = storage_provider_is_unused_for_reads(&runtime_rs);
    finding(
        "runtime-shared-temp",
        if run_count == 3 && share_count == 1 {
            "FALSIFIED"
        } else if run_count == 0 && share_count == 0 {
            "HOLDS"
        } else {
            "WEAK"
        },
        "Runtime still constructs /tmp/elastos/storage (run_cmd plus share_cmd)",
        &format!("run_cmd={run_count} share_cmd={share_count} unused_for_reads={unused}"),
    );
}

fn runtime_rows_and_skips() {
    let journey = launch::real_runtime_journey();
    finding(
        "runtime-enforced",
        if journey.state == RowState::Blocked && !journey.executed && journey.read_refusal.is_none()
        {
            "FALSIFIED"
        } else {
            "HOLDS"
        },
        "Denial is not enforced by the Runtime; both real-Runtime rows stay BLOCKED",
        &format!(
            "state={:?} executed={} refusal={:?}",
            journey.state, journey.executed, journey.read_refusal
        ),
    );
    finding(
        "blocked-not-skip-pass",
        if journey.state == RowState::Blocked {
            "HOLDS"
        } else {
            "FALSIFIED"
        },
        "#290's Runtime rows are BLOCKED, not cargo-ignored ok",
        "real_runtime_rows_match_the_launcher passes only while state is Blocked and three run_cmd literals remain.",
    );
}

fn grant_shape_vs_a5() {
    let parent = Parent::new();
    let mut store = Store::open(parent.path()).unwrap();
    let a = store.bind("agent-a", "session-a").unwrap();
    let shape = a.owned_root() == "UsersAI/agent-a/session-a/1";
    finding(
        "grant-shape-a5",
        if shape { "WEAK" } else { "FALSIFIED" },
        "A9 owned_root is UsersAI/<id>/<session>/<instance>; A5 Decision uses UsersAI/<agent>/<rest>",
        &format!(
            "grant owned_root={} identity={} session={} instance={}",
            a.owned_root(),
            a.identity(),
            a.session(),
            a.instance()
        ),
    );
}

fn host_root_leak() {
    let parent = Parent::new();
    let (store, a, _b) = pair(&parent);
    let host = store.host_root(&a).unwrap();
    finding(
        "host-root-api",
        "WEAK",
        "host_root() hands the caller a live host directory under the same uid",
        &format!(
            "owned_root={} host={} mode={:o}",
            a.owned_root(),
            host.display(),
            fs::metadata(host).map(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o777
            }).unwrap_or(0)
        ),
    );
}
