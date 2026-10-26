#![forbid(unsafe_code)]

//! Per-agent owned storage for M1 check A9.
//!
//! The component launcher still builds one shared directory at
//! `/tmp/elastos/storage` (`elastos/crates/elastos-server/src/run_cmd.rs`).
//! `LocalMutableStorage` confines a path only inside the base directory the
//! caller gives it (`elastos/crates/elastos-storage/src/mutable/local.rs`).
//! This crate is the lab stand-in that gives each agent instance its own
//! base directory.
//!
//! Grant binding stays in `lab/grant-binding` and the cx-agent-conformance
//! lane. Their `Decision` already carries `identity`, `session`, and
//! `owned_root`. This store does not register instances or read a forged
//! handle. It keeps the root that binding named and refuses every path that
//! leaves it.
//!
//! Lab stand-in, not the Runtime. `elastos run` still has no per-instance
//! root. The real-Runtime rows stay BLOCKED. The exact change is in
//! `PROPOSED-LAUNCHER-CHANGE.md`.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod launch;

#[cfg(test)]
mod plant;

/// The shared directory the component launcher uses today.
pub const SHARED_TEMP: &str = "/tmp/elastos/storage";

/// The grant names this root. The host path stays on the store.
///
/// `identity`, `session`, and `owned_root` match `grant_binding::Decision`.
/// `instance` matches the instance that decision is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    identity: String,
    session: String,
    instance: u64,
    owned_root: String,
}

impl Grant {
    /// The agent principal this root is bound to.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The session this root is bound to.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// The instance that owns this root.
    pub fn instance(&self) -> u64 {
        self.instance
    }

    /// The resource name on the grant. This is not a host path.
    pub fn owned_root(&self) -> &str {
        &self.owned_root
    }
}

/// Why a storage operation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refuse {
    /// The path is `/tmp/elastos/storage` or a child of it.
    SharedTemp,
    /// The path resolves inside another agent's root.
    CrossAgent,
    /// The path contains `..`.
    Traversal,
    /// A symlink resolves outside the caller's root.
    Symlink,
    /// The path leaves the caller's root some other way.
    OutsideRoot,
    /// The name is empty, absolute, or not a plain segment.
    HostPath,
    /// Cleanup removed the yard.
    Removed,
    /// Cleanup could not remove the yard and made it unreadable.
    Sealed,
    /// The grant does not name a live root in this store.
    UnknownGrant,
    /// The path is inside the root and names nothing.
    NotFound,
}

impl std::fmt::Display for Refuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Refuse::SharedTemp => "shared temp directory is not agent storage",
            Refuse::CrossAgent => "cross-agent storage is refused",
            Refuse::Traversal => "path traversal is refused",
            Refuse::Symlink => "symlink leaves the owned root",
            Refuse::OutsideRoot => "path leaves the owned root",
            Refuse::HostPath => "storage name is a host path",
            Refuse::Removed => "storage was removed",
            Refuse::Sealed => "storage is sealed",
            Refuse::UnknownGrant => "grant does not name an owned root",
            Refuse::NotFound => "path is not in the owned root",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Life {
    Open,
    Removed,
    Sealed,
}

#[derive(Debug)]
struct OpenAgent {
    identity: String,
    session: String,
    instance: u64,
    owned_root: String,
    path: PathBuf,
}

/// One yard of per-agent directories. Cleanup removes the yard.
#[derive(Debug)]
pub struct Store {
    yard: PathBuf,
    agents: Vec<OpenAgent>,
    next_instance: u64,
    life: Life,
}

impl Store {
    /// Creates a private yard under `parent`.
    ///
    /// `parent` must already exist. The shared temp directory, a child of it,
    /// and a symlink are refused before this function creates anything.
    pub fn open(parent: &Path) -> Result<Self, Refuse> {
        if is_shared_temp(parent) {
            return Err(Refuse::SharedTemp);
        }
        let meta = fs::symlink_metadata(parent).map_err(|_| Refuse::OutsideRoot)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(Refuse::HostPath);
        }
        let parent_canon = parent.canonicalize().map_err(|_| Refuse::OutsideRoot)?;
        if is_shared_temp(&parent_canon) {
            return Err(Refuse::SharedTemp);
        }
        let yard = fresh_yard(&parent_canon)?;
        Ok(Self {
            yard,
            agents: Vec::new(),
            next_instance: 0,
            life: Life::Open,
        })
    }

    /// The private yard. Agent grants do not carry this path.
    pub fn yard(&self) -> &Path {
        &self.yard
    }

    /// Opens one instance root bound to `identity` and `session`.
    ///
    /// The grant's owned root is `UsersAI/<identity>/<session>/<instance>`.
    pub fn bind(&mut self, identity: &str, session: &str) -> Result<Grant, Refuse> {
        self.require_open()?;
        plain_segment(identity)?;
        plain_segment(session)?;
        self.next_instance += 1;
        let instance = self.next_instance;
        let path = agent_directory(&self.yard, identity, session, instance);
        if is_shared_temp(&path) {
            return Err(Refuse::SharedTemp);
        }
        fs::create_dir_all(&path).map_err(|_| Refuse::OutsideRoot)?;
        let canon = path.canonicalize().map_err(|_| Refuse::OutsideRoot)?;
        let yard = self.yard.canonicalize().map_err(|_| Refuse::OutsideRoot)?;
        if is_shared_temp(&canon) {
            return Err(Refuse::SharedTemp);
        }
        if !contained(&yard, &canon) {
            return Err(Refuse::OutsideRoot);
        }
        let owned_root = format!("UsersAI/{identity}/{session}/{instance}");
        self.agents.push(OpenAgent {
            identity: identity.to_owned(),
            session: session.to_owned(),
            instance,
            owned_root: owned_root.clone(),
            path: canon,
        });
        Ok(Grant {
            identity: identity.to_owned(),
            session: session.to_owned(),
            instance,
            owned_root,
        })
    }

    /// The host directory for this grant. Callers use it to attempt a direct
    /// cross-agent path. The grant itself names `owned_root`, not this path.
    pub fn host_root(&self, grant: &Grant) -> Result<&Path, Refuse> {
        Ok(&self.agent(grant)?.path)
    }

    /// Reads one file inside the grant's root.
    pub fn read(&self, grant: &Grant, path: &str) -> Result<Vec<u8>, Refuse> {
        let full = self.resolve(grant, path)?;
        match fs::symlink_metadata(&full) {
            Ok(meta) if meta.file_type().is_symlink() => Err(Refuse::Symlink),
            Ok(meta) if meta.is_file() => fs::read(&full).map_err(|_| Refuse::OutsideRoot),
            Ok(_) => Err(Refuse::OutsideRoot),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(Refuse::NotFound),
            Err(_) => Err(Refuse::OutsideRoot),
        }
    }

    /// Writes one file inside the grant's root.
    pub fn write(&self, grant: &Grant, path: &str, bytes: &[u8]) -> Result<(), Refuse> {
        let full = self.resolve(grant, path)?;
        if let Ok(meta) = fs::symlink_metadata(&full) {
            if meta.file_type().is_symlink() {
                return Err(Refuse::Symlink);
            }
            if !meta.is_file() {
                return Err(Refuse::OutsideRoot);
            }
        }
        if let Some(parent) = full.parent() {
            let root = &self.agent(grant)?.path;
            if !contained(root, parent) && parent != root {
                return Err(Refuse::OutsideRoot);
            }
            if parent != root {
                fs::create_dir_all(parent).map_err(|_| Refuse::OutsideRoot)?;
            }
        }
        fs::write(&full, bytes).map_err(|_| Refuse::OutsideRoot)
    }

    /// Removes the yard. A later read or write is refused.
    ///
    /// When removal fails, the yard is sealed unreadable and this returns
    /// [`Refuse::Sealed`].
    pub fn cleanup(&mut self) -> Result<(), Refuse> {
        match self.life {
            Life::Removed | Life::Sealed => return Ok(()),
            Life::Open => {}
        }
        if self.yard.exists() && fs::remove_dir_all(&self.yard).is_err() {
            seal_tree(&self.yard);
            self.life = Life::Sealed;
            self.agents.clear();
            return Err(Refuse::Sealed);
        }
        self.life = Life::Removed;
        self.agents.clear();
        Ok(())
    }

    fn require_open(&self) -> Result<(), Refuse> {
        match self.life {
            Life::Open => Ok(()),
            Life::Removed => Err(Refuse::Removed),
            Life::Sealed => Err(Refuse::Sealed),
        }
    }

    fn agent(&self, grant: &Grant) -> Result<&OpenAgent, Refuse> {
        self.require_open()?;
        self.agents
            .iter()
            .find(|agent| {
                agent.identity == grant.identity
                    && agent.session == grant.session
                    && agent.instance == grant.instance
                    && agent.owned_root == grant.owned_root
            })
            .ok_or(Refuse::UnknownGrant)
    }

    fn resolve(&self, grant: &Grant, path: &str) -> Result<PathBuf, Refuse> {
        let root = self.agent(grant)?.path.clone();
        if path.is_empty() || path.contains('\0') || path.contains('\\') {
            return Err(Refuse::HostPath);
        }
        if path.split(['/', '\\']).any(|segment| segment == "..") {
            return Err(Refuse::Traversal);
        }
        if path.split(['/', '\\']).any(|segment| segment == ".") {
            return Err(Refuse::HostPath);
        }
        let raw = Path::new(path);
        if is_shared_temp(raw) {
            return Err(Refuse::SharedTemp);
        }
        if raw.is_absolute() {
            return self.resolve_absolute(&root, raw);
        }
        self.resolve_relative(&root, raw)
    }

    fn resolve_absolute(&self, root: &Path, path: &Path) -> Result<PathBuf, Refuse> {
        if is_shared_temp(path) {
            return Err(Refuse::SharedTemp);
        }
        let check = if path.exists() {
            path.canonicalize().map_err(|_| Refuse::OutsideRoot)?
        } else if let Some(parent) = path.parent() {
            if is_shared_temp(parent) {
                return Err(Refuse::SharedTemp);
            }
            if parent.exists() {
                let parent = parent.canonicalize().map_err(|_| Refuse::OutsideRoot)?;
                let name = path.file_name().ok_or(Refuse::HostPath)?;
                parent.join(name)
            } else {
                lexical_normalize(path)
            }
        } else {
            lexical_normalize(path)
        };
        if is_shared_temp(&check) {
            return Err(Refuse::SharedTemp);
        }
        if contained(root, &check) {
            return Ok(check);
        }
        if self.agents.iter().any(|agent| {
            agent.path != root && (check == agent.path || contained(&agent.path, &check))
        }) {
            return Err(Refuse::CrossAgent);
        }
        Err(Refuse::OutsideRoot)
    }

    fn resolve_relative(&self, root: &Path, path: &Path) -> Result<PathBuf, Refuse> {
        let mut acc = root.to_path_buf();
        let components: Vec<Component<'_>> = path.components().collect();
        if components.is_empty() {
            return Err(Refuse::HostPath);
        }
        for (index, component) in components.iter().enumerate() {
            match component {
                Component::Normal(name) => {
                    acc.push(name);
                    match fs::symlink_metadata(&acc) {
                        Ok(meta) if meta.file_type().is_symlink() => {
                            acc = resolve_link(root, &acc)?;
                            if index + 1 != components.len() && !acc.is_dir() {
                                return Err(Refuse::Symlink);
                            }
                        }
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            if index + 1 != components.len() {
                                return Err(Refuse::NotFound);
                            }
                        }
                        Err(_) => return Err(Refuse::OutsideRoot),
                    }
                }
                Component::ParentDir => return Err(Refuse::Traversal),
                Component::CurDir => return Err(Refuse::HostPath),
                _ => return Err(Refuse::HostPath),
            }
            if is_shared_temp(&acc) {
                return Err(Refuse::SharedTemp);
            }
            if !contained(root, &acc) && acc != root {
                return Err(Refuse::OutsideRoot);
            }
        }
        if !contained(root, &acc) {
            return Err(Refuse::OutsideRoot);
        }
        Ok(acc)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        if self.life == Life::Open {
            let _ = self.cleanup();
        }
    }
}

/// One directory per instance. A shared return value is the A9 hole.
fn agent_directory(yard: &Path, identity: &str, session: &str, instance: u64) -> PathBuf {
    yard.join(identity).join(session).join(instance.to_string())
}

fn fresh_yard(parent: &Path) -> Result<PathBuf, Refuse> {
    static YARD_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = YARD_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Refuse::OutsideRoot)?
        .as_nanos();
    let yard = parent.join(format!("yard-{}-{seq}-{nanos}", std::process::id()));
    if is_shared_temp(&yard) {
        return Err(Refuse::SharedTemp);
    }
    fs::create_dir(&yard).map_err(|_| Refuse::OutsideRoot)?;
    yard.canonicalize().map_err(|_| Refuse::OutsideRoot)
}

fn plain_segment(value: &str) -> Result<(), Refuse> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(Refuse::HostPath);
    }
    Ok(())
}

fn is_shared_temp(path: &Path) -> bool {
    let shared = Path::new(SHARED_TEMP);
    path == shared || path.starts_with(shared)
}

fn contained(root: &Path, path: &Path) -> bool {
    path.starts_with(root) && path != root
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn resolve_link(root: &Path, link: &Path) -> Result<PathBuf, Refuse> {
    let target = fs::read_link(link).map_err(|_| Refuse::Symlink)?;
    if is_shared_temp(&target) {
        return Err(Refuse::SharedTemp);
    }
    let joined = if target.is_absolute() {
        target
    } else {
        link.parent().unwrap_or(root).join(target)
    };
    let normalized = lexical_normalize(&joined);
    if is_shared_temp(&normalized) {
        return Err(Refuse::SharedTemp);
    }
    let check = if normalized.exists() {
        normalized.canonicalize().map_err(|_| Refuse::Symlink)?
    } else {
        normalized
    };
    if is_shared_temp(&check) {
        return Err(Refuse::SharedTemp);
    }
    if contained(root, &check) {
        Ok(check)
    } else {
        Err(Refuse::Symlink)
    }
}

fn seal_tree(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() && !meta.file_type().is_symlink() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                seal_tree(&entry.path());
            }
        }
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o000));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Parent(PathBuf);

    impl Parent {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "owned-storage-test-{}-{n}-{nanos}",
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

    #[test]
    fn agent_a_reads_and_writes_its_own_storage() {
        let parent = Parent::new();
        let mut store = Store::open(parent.path()).unwrap();
        let a = store.bind("agent-a", "session-a").unwrap();
        assert_eq!(a.identity(), "agent-a");
        assert_eq!(a.session(), "session-a");
        assert_eq!(a.instance(), 1);
        assert_eq!(a.owned_root(), "UsersAI/agent-a/session-a/1");
        let host = store.host_root(&a).unwrap().to_path_buf();
        assert_ne!(a.owned_root(), host.to_str().unwrap());
        assert!(host.starts_with(store.yard()));
        assert!(!is_shared_temp(&host));

        store.write(&a, "note.txt", b"hello-a").unwrap();
        assert_eq!(store.read(&a, "note.txt").unwrap(), b"hello-a");
        assert_eq!(fs::read(host.join("note.txt")).unwrap(), b"hello-a");

        std::os::unix::fs::symlink("note.txt", host.join("alias")).unwrap();
        assert_eq!(store.read(&a, "alias").unwrap(), b"hello-a");

        let again = store.bind("agent-a", "session-a").unwrap();
        assert_eq!(again.owned_root(), "UsersAI/agent-a/session-a/2");
        assert_ne!(
            store.host_root(&a).unwrap(),
            store.host_root(&again).unwrap()
        );
        let note = store.host_root(&a).unwrap().join("note.txt");
        let denied = store
            .read(&again, note.to_str().unwrap())
            .expect_err("another instance");
        assert_eq!(denied, Refuse::CrossAgent);
        assert_eq!(denied.to_string(), "cross-agent storage is refused");

        let other_session = store.bind("agent-a", "session-b").unwrap();
        assert_eq!(other_session.session(), "session-b");
        assert!(other_session.owned_root().contains("/session-b/"));
        let denied = store
            .read(&other_session, note.to_str().unwrap())
            .expect_err("other session");
        assert_eq!(denied, Refuse::CrossAgent);
    }

    #[test]
    fn agent_a_is_denied_b_directly() {
        let parent = Parent::new();
        let (store, a, b) = pair(&parent);
        store.write(&b, "secret.txt", b"b-secret").unwrap();
        let b_file = store.host_root(&b).unwrap().join("secret.txt");
        assert_ne!(a.owned_root(), b.owned_root());
        let path = b_file.to_str().unwrap();

        let denied = store.read(&a, path).expect_err("direct read");
        assert_eq!(denied, Refuse::CrossAgent);
        assert_eq!(denied.to_string(), "cross-agent storage is refused");

        let denied = store
            .write(&a, path, b"overwrite")
            .expect_err("direct write");
        assert_eq!(denied, Refuse::CrossAgent);
        assert_eq!(fs::read(&b_file).unwrap(), b"b-secret");
        assert_ne!(
            store.host_root(&a).unwrap().canonicalize().unwrap(),
            store.host_root(&b).unwrap().canonicalize().unwrap(),
            "agents share a storage root"
        );
    }

    #[test]
    fn agent_a_is_denied_b_through_a_parent_path() {
        let parent = Parent::new();
        let (store, a, b) = pair(&parent);
        store.write(&b, "secret.txt", b"b-secret").unwrap();
        let b_file = store.host_root(&b).unwrap().join("secret.txt");
        let yard = store.yard().to_path_buf();
        for path in [
            "../secret.txt",
            "../../secret.txt",
            "../../../agent-b/session-b/2/secret.txt",
            "nested/../../secret.txt",
        ] {
            let denied = store.read(&a, path).expect_err(path);
            assert_eq!(denied, Refuse::Traversal, "{path}");
            assert_eq!(denied.to_string(), "path traversal is refused");
            let denied = store.write(&a, path, b"no").expect_err(path);
            assert_eq!(denied, Refuse::Traversal, "{path}");
        }
        assert_eq!(fs::read(&b_file).unwrap(), b"b-secret");
        assert!(!yard.join("secret.txt").exists());
        let denied = store
            .write(&a, "../escaped.txt", b"no")
            .expect_err("escape write");
        assert_eq!(denied, Refuse::Traversal);
        assert!(!yard.join("escaped.txt").exists());
        assert_ne!(
            store.host_root(&a).unwrap().canonicalize().unwrap(),
            store.host_root(&b).unwrap().canonicalize().unwrap(),
            "agents share a storage root"
        );
    }

    #[test]
    fn agent_a_is_denied_b_through_a_symlink() {
        let parent = Parent::new();
        let (store, a, b) = pair(&parent);
        store.write(&b, "secret.txt", b"b-secret").unwrap();
        let b_file = store.host_root(&b).unwrap().join("secret.txt");
        let link = store.host_root(&a).unwrap().join("via-b");
        std::os::unix::fs::symlink(&b_file, &link).unwrap();

        let denied = store.read(&a, "via-b").expect_err("symlink read");
        assert_eq!(denied, Refuse::Symlink);
        assert_eq!(denied.to_string(), "symlink leaves the owned root");

        let denied = store
            .write(&a, "via-b", b"pwned")
            .expect_err("symlink write");
        assert_eq!(denied, Refuse::Symlink);
        assert_eq!(fs::read(&b_file).unwrap(), b"b-secret");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_ne!(
            store.host_root(&a).unwrap().canonicalize().unwrap(),
            store.host_root(&b).unwrap().canonicalize().unwrap(),
            "agents share a storage root"
        );
    }

    #[test]
    fn shared_temp_directory_is_refused() {
        assert_eq!(SHARED_TEMP, "/tmp/elastos/storage");
        let shared = Path::new(SHARED_TEMP);
        let existed = shared.symlink_metadata().is_ok();
        let marker = shared.join("owned-storage-marker");
        let marker_existed = marker.symlink_metadata().is_ok();

        let denied = Store::open(shared).expect_err("shared temp");
        assert_eq!(denied, Refuse::SharedTemp);
        assert_eq!(
            denied.to_string(),
            "shared temp directory is not agent storage"
        );
        let nested = shared.join("agent-a");
        assert_eq!(
            Store::open(&nested).expect_err("child of shared temp"),
            Refuse::SharedTemp
        );
        if !existed {
            assert!(
                !shared.exists(),
                "open must not create the shared temp directory"
            );
        }
        if !marker_existed {
            assert!(!marker.exists());
        }

        let parent = Parent::new();
        let mut store = Store::open(parent.path()).unwrap();
        let a = store.bind("agent-a", "session-a").unwrap();
        let link = store.host_root(&a).unwrap().join("temp-link");
        std::os::unix::fs::symlink(shared.join("secret"), &link).unwrap();
        let denied = store.read(&a, "temp-link").expect_err("temp symlink read");
        assert_eq!(denied, Refuse::SharedTemp);
        let denied = store
            .write(&a, "temp-link", b"no")
            .expect_err("temp symlink write");
        assert_eq!(denied, Refuse::SharedTemp);
        if !existed {
            assert!(!shared.exists());
        }
        if !marker_existed {
            assert!(!marker.exists());
        }
    }

    #[test]
    fn cleanup_leaves_nothing_behind() {
        let parent = Parent::new();
        let mut store = Store::open(parent.path()).unwrap();
        let a = store.bind("agent-a", "session-a").unwrap();
        let b = store.bind("agent-b", "session-b").unwrap();
        store.write(&a, "note.txt", b"a-bytes").unwrap();
        store.write(&b, "secret.txt", b"b-secret").unwrap();
        let yard = store.yard().to_path_buf();
        let a_file = store.host_root(&a).unwrap().join("note.txt");
        let b_file = store.host_root(&b).unwrap().join("secret.txt");
        assert!(a_file.is_file());
        assert!(b_file.is_file());

        store.cleanup().unwrap();
        assert!(!a_file.exists());
        assert!(!b_file.exists());
        assert!(!yard.exists());
        assert_eq!(
            fs::read_dir(parent.path()).unwrap().count(),
            0,
            "the yard left a directory behind"
        );
        let denied = store.read(&a, "note.txt").expect_err("after cleanup");
        assert_eq!(denied, Refuse::Removed);
        assert_eq!(denied.to_string(), "storage was removed");
        store.cleanup().unwrap();
        assert!(!yard.exists());

        let yard_on_drop;
        {
            let mut dropped = Store::open(parent.path()).unwrap();
            let agent = dropped.bind("agent-a", "session-a").unwrap();
            dropped.write(&agent, "note.txt", b"gone").unwrap();
            yard_on_drop = dropped.yard().to_path_buf();
            assert!(yard_on_drop.join("agent-a").is_dir());
        }
        assert!(
            !yard_on_drop.exists(),
            "dropping the store left the yard behind"
        );
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn planted_shared_root_is_caught() {
        plant::run_all();
    }
}
