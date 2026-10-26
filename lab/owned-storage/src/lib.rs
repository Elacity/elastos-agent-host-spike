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
//! `owned_root` uses the A5 shape `UsersAI/<agent>/<rest>`. This store does
//! not call `lab/grant-binding`; the grant is unbound. Grant binding stays
//! in that crate and the cx-agent-conformance lane. This store keeps the
//! host directory it created and refuses every path that leaves it.
//!
//! Lab stand-in, not the Runtime. `elastos run` still has no per-instance
//! root. The real-Runtime rows stay BLOCKED. The exact change is in
//! `PROPOSED-LAUNCHER-CHANGE.md`.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

mod walk;

pub mod launch;

#[cfg(test)]
mod plant;

/// The shared directory the component launcher uses today.
pub const SHARED_TEMP: &str = "/tmp/elastos/storage";

/// The grant names this root. The host path stays on the store.
///
/// `owned_root` is the A5 resource `UsersAI/<agent>/<rest>`. This crate does
/// not call `lab/grant-binding` and does not treat these fields as a
/// `Decision`.
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
    /// The file is hard-linked, or this agent did not create its inode.
    HardLink,
    /// The path crosses a mount point, including a bind-mount of another tree.
    CrossMount,
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
            Refuse::HardLink => "hard-linked inode is refused",
            Refuse::CrossMount => "path crosses a mount point",
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
    root: fs::File,
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
        let owned_root = a5_owned_root(identity, &format!("{session}/{instance}"))?;
        let root = walk::open_root(&canon)?;
        let root_meta = fs::symlink_metadata(&canon).map_err(|_| Refuse::OutsideRoot)?;
        record_owned(&canon, &root_meta)?;
        self.agents.push(OpenAgent {
            identity: identity.to_owned(),
            session: session.to_owned(),
            instance,
            owned_root: owned_root.clone(),
            path: canon,
            root,
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
        let root = self.live_root_for(grant)?;
        let parts = io_components(path, root, &full)?;
        let mut file = walk::open_existing_file(&self.agent(grant)?.root, &parts)?;
        let meta = file.metadata().map_err(|_| Refuse::OutsideRoot)?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(Refuse::OutsideRoot);
        }
        require_owned(root, &meta)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| Refuse::OutsideRoot)?;
        Ok(bytes)
    }

    /// Writes one file inside the grant's root.
    pub fn write(&self, grant: &Grant, path: &str, bytes: &[u8]) -> Result<(), Refuse> {
        let full = self.resolve(grant, path)?;
        let root = self.live_root_for(grant)?;
        let parts = io_components(path, root, &full)?;
        if let Ok(meta) = fs::symlink_metadata(&full) {
            if meta.file_type().is_symlink() {
                return Err(Refuse::Symlink);
            }
            if !meta.is_file() {
                return Err(Refuse::OutsideRoot);
            }
            require_owned(root, &meta)?;
        }
        let opened = walk::open_or_create_file(&self.agent(grant)?.root, &parts)?;
        let created = matches!(opened, walk::OpenedFile::Created(_));
        let mut file = opened.file();
        let meta = file.metadata().map_err(|_| Refuse::OutsideRoot)?;
        if meta.file_type().is_symlink() {
            return Err(Refuse::Symlink);
        }
        if !meta.is_file() {
            return Err(Refuse::OutsideRoot);
        }
        if created {
            refuse_hard_link(&meta)?;
            record_owned(root, &meta)?;
            record_path_components(root, &parts)?;
        } else {
            require_owned(root, &meta)?;
        }
        file.set_len(0).map_err(|_| Refuse::OutsideRoot)?;
        file.write_all(bytes).map_err(|_| Refuse::OutsideRoot)
    }

    /// Lists names inside a directory in the grant's root.
    ///
    /// An empty path lists the root. A path into another agent is
    /// [`Refuse::CrossAgent`]. The Store does not confine the host process.
    pub fn list(&self, grant: &Grant, path: &str) -> Result<Vec<String>, Refuse> {
        let root = self.live_root_for(grant)?.to_path_buf();
        let dir = if path.is_empty() {
            root.clone()
        } else {
            self.resolve(grant, path)?
        };
        let confirmed = confirm_resolved(&root, &dir)?;
        let meta = match fs::symlink_metadata(&confirmed) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Refuse::NotFound);
            }
            Err(_) => return Err(Refuse::OutsideRoot),
        };
        if meta.file_type().is_symlink() {
            return Err(Refuse::Symlink);
        }
        if !meta.is_dir() {
            return Err(Refuse::OutsideRoot);
        }
        require_owned(&root, &meta)?;
        let parts = if path.is_empty() {
            Vec::new()
        } else {
            io_components(path, &root, &confirmed)?
        };
        let names = walk::list_names(&walk::open_dir(&self.agent(grant)?.root, &parts)?)?;
        let mut owned_names = Vec::new();
        for name in names {
            let child = confirmed.join(&name);
            let child_meta = match fs::symlink_metadata(&child) {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if require_in_agent_record(&root, &child_meta).is_ok() {
                owned_names.push(name);
            }
        }
        Ok(owned_names)
    }

    /// Renames one name to another inside the grant's root.
    pub fn rename(&self, grant: &Grant, from: &str, to: &str) -> Result<(), Refuse> {
        let root = self.live_root_for(grant)?.to_path_buf();
        let src = confirm_resolved(&root, &self.resolve(grant, from)?)?;
        let dst = self.resolve(grant, to)?;
        let src_meta = fs::symlink_metadata(&src).map_err(|_| Refuse::NotFound)?;
        require_owned(&root, &src_meta)?;
        if let Some(parent) = dst.parent() {
            if parent != root.as_path() && !contained(&root, parent) {
                return Err(Refuse::OutsideRoot);
            }
            confirm_resolved(&root, parent)?;
        }
        confirm_resolved(&root, &dst)?;
        if let Ok(dst_meta) = fs::symlink_metadata(&dst) {
            require_owned(&root, &dst_meta)?;
        }
        let from_parts = io_components(from, &root, &src)?;
        let to_parts = io_components(to, &root, &dst)?;
        walk::rename_rel(&self.agent(grant)?.root, &from_parts, &to_parts)?;
        assert_root_is_real_dir(&root)?;
        Ok(())
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
        self.agents.clear();
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

    fn live_root_for(&self, grant: &Grant) -> Result<&Path, Refuse> {
        let agent = self.agent(grant)?;
        assert_root_is_real_dir(&agent.path)?;
        Ok(&agent.path)
    }

    fn resolve(&self, grant: &Grant, path: &str) -> Result<PathBuf, Refuse> {
        let root = self.live_root_for(grant)?.to_path_buf();
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
            return confirm_resolved(root, &check);
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
        confirm_resolved(root, &acc)
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

fn a5_owned_root(agent: &str, rest: &str) -> Result<String, Refuse> {
    plain_segment(agent)?;
    let name = format!("UsersAI/{agent}/{rest}");
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() < 3 || parts[0] != "UsersAI" || parts[1] != agent {
        return Err(Refuse::HostPath);
    }
    for part in &parts[2..] {
        plain_segment(part)?;
    }
    Ok(name)
}

fn refuse_swapped_root() -> bool {
    true
}

fn assert_root_is_real_dir(root: &Path) -> Result<(), Refuse> {
    if !refuse_swapped_root() {
        return Ok(());
    }
    let meta = fs::symlink_metadata(root).map_err(|_| Refuse::Symlink)?;
    if meta.file_type().is_symlink() {
        return Err(Refuse::Symlink);
    }
    if !meta.is_dir() {
        return Err(Refuse::OutsideRoot);
    }
    let canon = root.canonicalize().map_err(|_| Refuse::Symlink)?;
    if canon != *root {
        return Err(Refuse::Symlink);
    }
    Ok(())
}

fn confirm_resolved(root: &Path, full: &Path) -> Result<PathBuf, Refuse> {
    assert_root_is_real_dir(root)?;
    if !full.exists() {
        if let Some(parent) = full.parent() {
            if parent.exists() {
                let parent_canon = parent.canonicalize().map_err(|_| Refuse::OutsideRoot)?;
                if refuse_swapped_root() && parent_canon != *root && !contained(root, &parent_canon)
                {
                    return Err(Refuse::Symlink);
                }
            }
        }
        return Ok(full.to_path_buf());
    }
    let canon = full.canonicalize().map_err(|_| Refuse::OutsideRoot)?;
    if contained(root, &canon) || canon == *root {
        Ok(canon)
    } else if refuse_swapped_root() {
        Err(Refuse::Symlink)
    } else {
        Ok(full.to_path_buf())
    }
}

fn refuse_hard_link(meta: &fs::Metadata) -> Result<(), Refuse> {
    if meta.is_file() && meta.nlink() > 1 {
        return Err(Refuse::HardLink);
    }
    Ok(())
}

/// Sibling of the agent root. Two Store handles share this file.
fn ownership_path(agent_root: &Path) -> PathBuf {
    let mut name = agent_root.as_os_str().to_os_string();
    name.push(".owned");
    PathBuf::from(name)
}

fn ownership_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn load_owned(agent_root: &Path) -> Result<HashSet<(u64, u64)>, Refuse> {
    let _guard = ownership_lock();
    load_owned_locked(agent_root)
}

fn load_owned_locked(agent_root: &Path) -> Result<HashSet<(u64, u64)>, Refuse> {
    let path = ownership_path(agent_root);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(_) => return Err(Refuse::OutsideRoot),
    };
    let mut set = HashSet::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(dev) = parts.next().and_then(|part| part.parse().ok()) else {
            return Err(Refuse::OutsideRoot);
        };
        let Some(ino) = parts.next().and_then(|part| part.parse().ok()) else {
            return Err(Refuse::OutsideRoot);
        };
        set.insert((dev, ino));
    }
    Ok(set)
}

fn save_owned_locked(agent_root: &Path, set: &HashSet<(u64, u64)>) -> Result<(), Refuse> {
    let path = ownership_path(agent_root);
    let mut out = String::from("# owned-storage v1\n");
    let mut keys: Vec<(u64, u64)> = set.iter().copied().collect();
    keys.sort_unstable();
    for (dev, ino) in keys {
        out.push_str(&format!("{dev} {ino}\n"));
    }
    fs::write(&path, out).map_err(|_| Refuse::OutsideRoot)
}

fn record_owned(agent_root: &Path, meta: &fs::Metadata) -> Result<(), Refuse> {
    let _guard = ownership_lock();
    let mut set = load_owned_locked(agent_root)?;
    set.insert((meta.dev(), meta.ino()));
    save_owned_locked(agent_root, &set)
}

fn record_path_components(agent_root: &Path, parts: &[OsString]) -> Result<(), Refuse> {
    let mut acc = agent_root.to_path_buf();
    for part in parts {
        acc.push(part);
        let meta = fs::symlink_metadata(&acc).map_err(|_| Refuse::OutsideRoot)?;
        record_owned(agent_root, &meta)?;
    }
    Ok(())
}

fn require_positive_ownership() -> bool {
    true
}

fn must_be_in_own_record(agent_root: &Path, meta: &fs::Metadata) -> Result<(), Refuse> {
    if !require_positive_ownership() {
        return Ok(());
    }
    let set = load_owned(agent_root)?;
    if set.contains(&(meta.dev(), meta.ino())) {
        Ok(())
    } else {
        Err(Refuse::HardLink)
    }
}

fn require_in_agent_record(agent_root: &Path, meta: &fs::Metadata) -> Result<(), Refuse> {
    must_be_in_own_record(agent_root, meta)
}

fn require_owned(agent_root: &Path, meta: &fs::Metadata) -> Result<(), Refuse> {
    refuse_hard_link(meta)?;
    require_in_agent_record(agent_root, meta)
}

fn io_components(path: &str, root: &Path, full: &Path) -> Result<Vec<OsString>, Refuse> {
    let raw = Path::new(path);
    let rel: &Path = if raw.is_absolute() {
        full.strip_prefix(root).map_err(|_| Refuse::OutsideRoot)?
    } else {
        raw
    };
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(name) => parts.push(name.to_os_string()),
            Component::ParentDir => return Err(Refuse::Traversal),
            _ => return Err(Refuse::HostPath),
        }
    }
    if parts.is_empty() {
        return Err(Refuse::HostPath);
    }
    Ok(parts)
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
        assert_eq!(
            store
                .read(&a, "alias")
                .expect_err("store does not follow a symlink"),
            Refuse::Symlink
        );

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
    fn agent_a_is_denied_b_when_root_is_swapped_for_a_symlink() {
        let parent = Parent::new();
        let (store, a, b) = pair(&parent);
        store.write(&b, "secret.txt", b"b-secret").unwrap();
        store.write(&a, "note.txt", b"hello-a").unwrap();
        let a_root = store.host_root(&a).unwrap().to_path_buf();
        let b_root = store.host_root(&b).unwrap().to_path_buf();
        fs::remove_dir_all(&a_root).unwrap();
        std::os::unix::fs::symlink(&b_root, &a_root).unwrap();

        let denied = store.read(&a, "secret.txt").expect_err("root swap read");
        assert_eq!(denied, Refuse::Symlink);
        assert_eq!(denied.to_string(), "symlink leaves the owned root");
        let denied = store
            .write(&a, "secret.txt", b"pwned")
            .expect_err("root swap write");
        assert_eq!(denied, Refuse::Symlink);
        assert_eq!(fs::read(b_root.join("secret.txt")).unwrap(), b"b-secret");
    }

    #[test]
    fn agent_b_is_denied_a_hard_linked_inode() {
        let parent = Parent::new();
        let (store, a, b) = pair(&parent);
        store.write(&a, "note.txt", b"hello-a").unwrap();
        let a_file = store.host_root(&a).unwrap().join("note.txt");
        let b_hard = store.host_root(&b).unwrap().join("hard.txt");
        fs::hard_link(&a_file, &b_hard).unwrap();
        let live_meta = fs::symlink_metadata(&b_hard).unwrap();
        assert!(live_meta.nlink() > 1);
        assert_eq!(
            refuse_hard_link(&live_meta).expect_err("nlink"),
            Refuse::HardLink
        );

        let denied = store.read(&b, "hard.txt").expect_err("hard link read");
        assert_eq!(denied, Refuse::HardLink);
        assert_eq!(denied.to_string(), "hard-linked inode is refused");
        let denied = store
            .write(&b, "hard.txt", b"from-b")
            .expect_err("hard link write");
        assert_eq!(denied, Refuse::HardLink);
        assert_eq!(fs::read(&a_file).unwrap(), b"hello-a");

        let outside = parent.path().join("foreign.txt");
        fs::write(&outside, b"foreign").unwrap();
        let a_root = store.host_root(&a).unwrap();
        let foreign_meta = fs::symlink_metadata(&outside).unwrap();
        assert_eq!(
            require_owned(a_root, &foreign_meta).expect_err("foreign inode"),
            Refuse::HardLink
        );
    }

    #[test]
    fn agent_b_is_denied_a_hard_linked_inode_after_a_unlinks() {
        let parent = Parent::new();
        let (store, a, b) = pair(&parent);
        store.write(&a, "note.txt", b"hello-a").unwrap();
        let a_file = store.host_root(&a).unwrap().join("note.txt");
        let b_hard = store.host_root(&b).unwrap().join("hard.txt");
        fs::hard_link(&a_file, &b_hard).unwrap();
        fs::remove_file(&a_file).unwrap();
        assert_eq!(fs::symlink_metadata(&b_hard).unwrap().nlink(), 1);
        assert_eq!(fs::read(&b_hard).unwrap(), b"hello-a");

        let denied = store
            .read(&b, "hard.txt")
            .expect_err("unlinked hard link read");
        assert_eq!(denied, Refuse::HardLink);
        assert_eq!(denied.to_string(), "hard-linked inode is refused");
        let denied = store
            .write(&b, "hard.txt", b"from-b")
            .expect_err("unlinked hard link write");
        assert_eq!(denied, Refuse::HardLink);
        assert_eq!(fs::read(&b_hard).unwrap(), b"hello-a");
    }

    #[test]
    fn last_component_nofollow_is_required() {
        let parent = Parent::new();
        let (store, a, _b) = pair(&parent);
        store.write(&a, "note.txt", b"hello-a").unwrap();
        let host = store.host_root(&a).unwrap().to_path_buf();
        let target = parent.path().join("outside-secret");
        fs::write(&target, b"secret").unwrap();
        fs::remove_file(host.join("note.txt")).unwrap();
        std::os::unix::fs::symlink(&target, host.join("note.txt")).unwrap();
        let denied = store.read(&a, "note.txt").expect_err("must not follow");
        assert_eq!(denied, Refuse::Symlink);
        let denied = store
            .write(&a, "note.txt", b"pwned")
            .expect_err("must not create through a link");
        assert_eq!(denied, Refuse::Symlink);
        assert_eq!(fs::read(&target).unwrap(), b"secret");
    }

    #[test]
    fn live_walk_flags_are_pinned() {
        assert!(
            walk::nofollow_flag().contains(rustix::fs::OFlags::NOFOLLOW),
            "live walk dropped O_NOFOLLOW"
        );
        let flags = walk::resolve_flags();
        assert!(
            flags.contains(rustix::fs::ResolveFlags::NO_SYMLINKS),
            "live walk dropped RESOLVE_NO_SYMLINKS"
        );
        assert!(
            flags.contains(rustix::fs::ResolveFlags::NO_XDEV),
            "live walk dropped RESOLVE_NO_XDEV"
        );
        assert!(walk::openat2_first(), "live walk forced plain openat");
        assert!(walk::resolve_no_xdev(), "live walk dropped NO_XDEV hook");
    }

    #[test]
    fn intermediate_dir_swap_write_leaves_nothing_in_b() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        const ITERS: u32 = 5000;
        let parent = Parent::new();
        let mut store_a = Store::open(parent.path()).unwrap();
        let a = store_a.bind("agent-a", "session-a").unwrap();
        let mut store_b = Store::open(parent.path()).unwrap();
        let b = store_b.bind("agent-b", "session-b").unwrap();
        store_b.write(&b, "secret.txt", b"b-secret").unwrap();
        let a_root = store_a.host_root(&a).unwrap().to_path_buf();
        let b_root = store_b.host_root(&b).unwrap().to_path_buf();
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

        let mut escaped = 0u32;
        let mut denied = 0u32;
        for i in 0..ITERS {
            let name = format!("sub/race-{i}.txt");
            match store_a.write(&a, &name, b"from-a") {
                Ok(()) => {
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
        let _ = swapper.join();
        eprintln!("race two-store iters={ITERS} denied={denied} escaped={escaped}");
        assert_eq!(
            escaped, 0,
            "write landed in B's tree; denied={denied} iters={ITERS}"
        );
        assert_eq!(fs::read(b_root.join("secret.txt")).unwrap(), b"b-secret");
    }

    #[test]
    fn agent_a_lists_and_renames_its_own_storage() {
        let parent = Parent::new();
        let (store, a, _b) = pair(&parent);
        store.write(&a, "note.txt", b"hello-a").unwrap();
        store.write(&a, "keep.txt", b"keep").unwrap();
        let names = store.list(&a, "").unwrap();
        assert_eq!(names, vec!["keep.txt".to_string(), "note.txt".to_string()]);
        store.rename(&a, "note.txt", "renamed.txt").unwrap();
        assert_eq!(store.read(&a, "renamed.txt").unwrap(), b"hello-a");
        assert_eq!(
            store.read(&a, "note.txt").expect_err("old name"),
            Refuse::NotFound
        );
        let names = store.list(&a, "").unwrap();
        assert_eq!(
            names,
            vec!["keep.txt".to_string(), "renamed.txt".to_string()]
        );
    }

    #[test]
    fn agent_a_is_denied_b_list_and_rename() {
        let parent = Parent::new();
        let (store, a, b) = pair(&parent);
        store.write(&b, "secret.txt", b"b-secret").unwrap();
        store.write(&a, "note.txt", b"hello-a").unwrap();
        let b_root = store.host_root(&b).unwrap().to_path_buf();
        let b_file = b_root.join("secret.txt");
        let b_path = b_file.to_str().unwrap();
        let b_dir = b_root.to_str().unwrap();

        let denied = store.list(&a, b_dir).expect_err("list b");
        assert_eq!(denied, Refuse::CrossAgent);
        assert_eq!(denied.to_string(), "cross-agent storage is refused");

        let denied = store
            .rename(&a, b_path, "stolen.txt")
            .expect_err("rename from b");
        assert_eq!(denied, Refuse::CrossAgent);
        let denied = store
            .rename(
                &b,
                "secret.txt",
                store
                    .host_root(&a)
                    .unwrap()
                    .join("from-b.txt")
                    .to_str()
                    .unwrap(),
            )
            .expect_err("rename into a");
        assert_eq!(denied, Refuse::CrossAgent);
        assert_eq!(fs::read(&b_file).unwrap(), b"b-secret");
        assert_eq!(store.read(&b, "secret.txt").unwrap(), b"b-secret");
        assert!(!store.host_root(&a).unwrap().join("stolen.txt").exists());
    }

    #[test]
    fn owned_root_uses_a5_usersai_agent_rest_shape() {
        let parent = Parent::new();
        let mut store = Store::open(parent.path()).unwrap();
        let a = store.bind("agent-a", "session-a").unwrap();
        assert_eq!(a.owned_root(), "UsersAI/agent-a/session-a/1");
        let parts: Vec<&str> = a.owned_root().split('/').collect();
        assert!(parts.len() >= 3, "A5 needs UsersAI/<agent>/<rest>");
        assert_eq!(parts[0], "UsersAI");
        assert_eq!(parts[1], a.identity());
        assert!(!parts[2].is_empty());
        assert_eq!(
            a5_owned_root("agent-1", "notes").unwrap(),
            "UsersAI/agent-1/notes"
        );
        let readme = include_str!("../README.md");
        assert!(readme.contains("UsersAI/<agent>/<rest>"));
        assert!(readme.contains("does not call `lab/grant-binding`"));
        assert!(
            !readme.contains("match `grant_binding::Decision`"),
            "drop the Decision field-match claim"
        );
    }

    #[test]
    fn host_same_uid_walk_needs_confinement_or_runtime() {
        let parent = Parent::new();
        let (store, a, b) = pair(&parent);
        store.write(&a, "note.txt", b"hello-a").unwrap();
        let a_file = store.host_root(&a).unwrap().join("note.txt");
        let from_b = store
            .host_root(&b)
            .unwrap()
            .join("../../../agent-a/session-a/1/note.txt");
        assert_eq!(fs::read(&from_b).unwrap(), b"hello-a");
        fs::write(
            store.host_root(&a).unwrap().join("planted-by-b.txt"),
            b"from-b",
        )
        .unwrap();
        assert_eq!(
            store
                .read(&a, "planted-by-b.txt")
                .expect_err("host-created file is not owned"),
            Refuse::HardLink
        );
        assert_eq!(
            fs::read(store.host_root(&a).unwrap().join("planted-by-b.txt")).unwrap(),
            b"from-b"
        );
        let denied = store
            .read(&b, a_file.to_str().unwrap())
            .expect_err("store still refuses");
        assert_eq!(denied, Refuse::CrossAgent);
        let readme = include_str!("../README.md");
        assert!(readme.contains("NEEDS CONFINEMENT/RUNTIME"));
        let host = crate::launch::host_journey();
        assert_eq!(host.state, crate::launch::RowState::NeedsConfinement);
        assert!(host.reason.contains("NEEDS CONFINEMENT/RUNTIME"));
        assert_eq!(
            crate::launch::lab_journey().state,
            crate::launch::RowState::Ready
        );
        for row in crate::launch::real_runtime_journey().rows {
            assert_eq!(row.state, crate::launch::RowState::Blocked, "{}", row.id);
        }
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
    fn host_rename_into_b_is_refused() {
        let parent = Parent::new();
        let (store, a, b) = pair(&parent);
        let a_host = store.host_root(&a).unwrap().join("host-note.txt");
        fs::write(&a_host, b"hello-a").unwrap();
        let b_dst = store.host_root(&b).unwrap().join("from-a.txt");
        fs::rename(&a_host, &b_dst).unwrap();
        assert_eq!(fs::symlink_metadata(&b_dst).unwrap().nlink(), 1);
        assert_eq!(
            store.read(&b, "from-a.txt").expect_err("host rename read"),
            Refuse::HardLink
        );
        assert_eq!(
            store
                .write(&b, "from-a.txt", b"from-b")
                .expect_err("host rename write"),
            Refuse::HardLink
        );
        assert_eq!(fs::read(&b_dst).unwrap(), b"hello-a");

        store.write(&a, "note.txt", b"store-a").unwrap();
        let a_note = store.host_root(&a).unwrap().join("note.txt");
        let b_note = store.host_root(&b).unwrap().join("from-store-a.txt");
        fs::rename(&a_note, &b_note).unwrap();
        assert_eq!(
            store
                .read(&b, "from-store-a.txt")
                .expect_err("store-created rename"),
            Refuse::HardLink
        );
    }

    #[test]
    fn two_yards_link_unlink_is_refused() {
        let parent = Parent::new();
        let mut store_a = Store::open(parent.path()).unwrap();
        let a = store_a.bind("agent-a", "session-a").unwrap();
        let mut store_b = Store::open(parent.path()).unwrap();
        let b = store_b.bind("agent-b", "session-b").unwrap();
        store_a.write(&a, "note.txt", b"hello-a").unwrap();
        let a_file = store_a.host_root(&a).unwrap().join("note.txt");
        let b_hard = store_b.host_root(&b).unwrap().join("hard.txt");
        fs::hard_link(&a_file, &b_hard).unwrap();
        fs::remove_file(&a_file).unwrap();
        assert_eq!(fs::symlink_metadata(&b_hard).unwrap().nlink(), 1);
        assert_eq!(fs::read(&b_hard).unwrap(), b"hello-a");
        assert_eq!(
            store_b
                .read(&b, "hard.txt")
                .expect_err("two-yard unlink read"),
            Refuse::HardLink
        );
        assert_eq!(
            store_b
                .write(&b, "hard.txt", b"from-b")
                .expect_err("two-yard unlink write"),
            Refuse::HardLink
        );
        assert_eq!(fs::read(&b_hard).unwrap(), b"hello-a");
    }

    #[test]
    fn ownership_record_is_on_disk_and_shared() {
        let parent = Parent::new();
        let mut store = Store::open(parent.path()).unwrap();
        let a = store.bind("agent-a", "session-a").unwrap();
        store.write(&a, "note.txt", b"hello-a").unwrap();
        let host = store.host_root(&a).unwrap().to_path_buf();
        let file_meta = fs::symlink_metadata(host.join("note.txt")).unwrap();
        let disk = fs::read_to_string(ownership_path(&host)).unwrap();
        assert!(disk.contains(&format!("{} {}", file_meta.dev(), file_meta.ino())));

        let yard = store.yard().to_path_buf();
        let grant = Grant {
            identity: a.identity().to_owned(),
            session: a.session().to_owned(),
            instance: a.instance(),
            owned_root: a.owned_root().to_owned(),
        };
        store.life = Life::Removed;
        store.agents.clear();
        drop(store);

        let mut again = Store {
            yard,
            agents: Vec::new(),
            next_instance: 1,
            life: Life::Open,
        };
        let root = walk::open_root(&host).unwrap();
        again.agents.push(OpenAgent {
            identity: grant.identity.clone(),
            session: grant.session.clone(),
            instance: grant.instance,
            owned_root: grant.owned_root.clone(),
            path: host,
            root,
        });
        assert_eq!(again.read(&grant, "note.txt").unwrap(), b"hello-a");
        again.cleanup().unwrap();
    }

    #[test]
    fn bind_mount_of_another_agent_tree_is_refused() {
        if std::env::var_os("OWNED_STORAGE_BIND_CHILD").is_some() {
            run_bind_mount_journey();
            return;
        }
        let exe = std::env::current_exe().expect("test binary");
        let output = std::process::Command::new("unshare")
            .args(["-Urm", "--"])
            .arg(&exe)
            .arg("tests::bind_mount_of_another_agent_tree_is_refused")
            .arg("--exact")
            .arg("--nocapture")
            .env("OWNED_STORAGE_BIND_CHILD", "1")
            .env("OWNED_STORAGE_PLANT_CHILD", "1")
            .output();
        match output {
            Ok(out) if out.status.success() => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(
                    text.contains("bind-mount journey CAUGHT"),
                    "unshare child did not report the journey:\n{text}"
                );
                eprintln!("bind-mount unshare child: CAUGHT");
            }
            Ok(out) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if unshare_unavailable(&text) {
                    eprintln!("NOT RUN: unshare -Urm bind-mount not allowed on this kernel");
                    return;
                }
                panic!("bind-mount child failed:\n{text}");
            }
            Err(error) => {
                eprintln!("NOT RUN: unshare missing ({error})");
            }
        }
    }

    fn run_bind_mount_journey() {
        let parent = Parent::new();
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
        assert!(status.success(), "mount --bind failed: {status}");
        let list = store_b.list(&b, "sub");
        assert!(list.is_err(), "list through bind-mount: {list:?}");
        let write = store_b.write(&b, "sub/planted.txt", b"pwned");
        assert!(write.is_err(), "write through bind-mount: {write:?}");
        assert!(
            !a_root.join("planted.txt").exists(),
            "bind-mount write landed in A"
        );
        println!("bind-mount journey CAUGHT");
    }

    fn unshare_unavailable(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        lower.contains("operation not permitted")
            || lower.contains("permission denied")
            || lower.contains("not allowed")
            || lower.contains("unshare: failed")
            || lower.contains("cannot unshare")
    }

    #[test]
    fn apfs_case_and_unicode_not_run_off_macos() {
        if cfg!(target_os = "macos") {
            let parent = Parent::new();
            let (store, a, _b) = pair(&parent);
            store.write(&a, "NOTE.TXT", b"upper").unwrap();
            let _ = store.read(&a, "note.txt");
        } else {
            eprintln!("NOT RUN: APFS case/Unicode (not a Mac)");
        }
    }

    #[test]
    fn planted_shared_root_is_caught() {
        plant::run_all();
    }
}
