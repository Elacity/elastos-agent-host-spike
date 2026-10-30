#![forbid(unsafe_code)]

//! The grant-binding reference model.
//!
//! One verifier stand-in owns the instance registry, the grant store and the
//! ledger. The host registers an instance with its identity and session, binds
//! an owned `UsersAI/<agent>/...` root to an opaque handle, and gives the guest
//! only that handle. The guest's claims are not read: the stored binding and
//! the registry record for the call's instance decide every use.

pub mod ledger;
pub mod link;
mod ops;
// Placed here as this slice requires; rustfmt would sort it before `ledger`.
#[rustfmt::skip]
mod ask;

#[cfg(test)]
mod plant;

use std::collections::HashMap;

/// An opaque grant handle. The guest holds only this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(u64);

/// An instance registered by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceId(u64);

/// A host call, bound to one instance when the host opens it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    instance: InstanceId,
}

/// The rights stored with a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights {
    pub append: bool,
    pub overwrite: bool,
    pub child_journal: bool,
}

/// What the guest presents.
///
/// Only `handle` is read. The remaining fields are the guest's claims and have
/// no effect on the decision.
#[derive(Debug, Clone)]
pub struct GuestRequest {
    pub handle: Handle,
    pub forged_identity: Option<String>,
    pub forged_session: Option<String>,
    pub forged_instance: Option<InstanceId>,
    pub reported_usage: u64,
    pub forged_ceiling: u64,
    pub forged_append: bool,
    pub forged_overwrite: bool,
    pub forged_child_journal: bool,
}

/// The stored binding that decides a use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantRecord {
    identity: String,
    session: String,
    instance: InstanceId,
    owned_root: String,
    rights: Rights,
    once: bool,
    expiry: Option<u64>,
    effect_limit: Option<u64>,
    effects: u64,
}

/// The binding copied out after a successful check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub identity: String,
    pub session: String,
    pub instance: InstanceId,
    pub owned_root: String,
    pub rights: Rights,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asker {
    Home,
    App,
}

/// A refusal with one clear reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refuse {
    Identity,
    Session,
    Instance,
    UnknownInstance,
    UnknownHandle,
    HostPath,
    OutsidePrincipal,
    SymlinkShaped,
    OutsideRoot,
    PublicRead,
    HomeMint,
    Expired,
    EffectLimit,
}

impl std::fmt::Display for Refuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Refuse::Identity => "identity does not match the grant",
            Refuse::Session => "session does not match the grant",
            Refuse::Instance => "instance does not match the grant",
            Refuse::UnknownInstance => "unknown instance",
            Refuse::UnknownHandle => "unknown handle",
            Refuse::HostPath => "owned root is a host path",
            Refuse::OutsidePrincipal => "owned root is outside the agent principal",
            Refuse::SymlinkShaped => "use path has a symlink-shaped segment",
            Refuse::OutsideRoot => "use path leaves the owned root",
            Refuse::PublicRead => "public storage read does not bind",
            Refuse::HomeMint => "home does not mint an app capability",
            Refuse::Expired => "grant has expired",
            Refuse::EffectLimit => "effect limit is reached",
        })
    }
}

#[derive(Debug)]
struct InstanceRecord {
    identity: String,
    session: String,
}

/// The one verifier stand-in: registry, grant store and ledger.
#[derive(Debug)]
pub struct Verifier {
    registry: HashMap<InstanceId, InstanceRecord>,
    grants: HashMap<Handle, GrantRecord>,
    next_instance: u64,
    next_handle: u64,
    #[allow(dead_code)] // later slices fill the ledger
    ledger: std::sync::Mutex<ledger::Ledger>,
    pending_once: bool,
    pending_expiry: Option<u64>,
    verifier_now: u64,
}

impl Verifier {
    /// An empty verifier with no instances and no grants.
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
            grants: HashMap::new(),
            next_instance: 0,
            next_handle: 0,
            ledger: std::sync::Mutex::new(ledger::Ledger::new()),
            pending_once: false,
            pending_expiry: None,
            verifier_now: 0,
        }
    }

    /// Registers an instance and returns its registry id.
    pub fn register_instance(&mut self, identity: &str, session: &str) -> InstanceId {
        self.next_instance += 1;
        let instance = InstanceId(self.next_instance);
        self.registry.insert(
            instance,
            InstanceRecord {
                identity: identity.to_owned(),
                session: session.to_owned(),
            },
        );
        instance
    }

    /// Opens a host call for one instance.
    pub fn open_call(&self, instance: InstanceId) -> Call {
        Call { instance }
    }

    /// Binds the instance's identity and session, the owned root and the rights
    /// to a fresh handle.
    pub fn bind_grant(
        &mut self,
        instance: InstanceId,
        resource: &str,
        rights: Rights,
    ) -> Result<Handle, Refuse> {
        let once = self.pending_once;
        let expiry = self.pending_expiry.take();
        self.pending_once = false;
        let record = self
            .registry
            .get(&instance)
            .ok_or(Refuse::UnknownInstance)?;
        if record.identity == "home" {
            return Err(Refuse::HomeMint);
        }
        let owned_root = resource_name(&record.identity, resource, None)?;
        self.next_handle += 1;
        let handle = Handle(self.next_handle);
        self.grants.insert(
            handle,
            GrantRecord {
                identity: record.identity.clone(),
                session: record.session.clone(),
                instance,
                owned_root,
                rights,
                once,
                expiry,
                effect_limit: None,
                effects: 0,
            },
        );
        Ok(handle)
    }

    #[cfg(test)]
    pub fn ask_capability(
        &mut self,
        instance: InstanceId,
        resource: &str,
        rights: Rights,
        claimed: Asker,
    ) -> Result<Handle, Refuse> {
        let _claimed = claimed;
        self.bind_grant(instance, resource, rights)
    }

    pub fn bind_once(
        &mut self,
        instance: InstanceId,
        resource: &str,
        rights: Rights,
    ) -> Result<Handle, Refuse> {
        self.pending_once = true;
        self.bind_grant(instance, resource, rights)
    }

    pub fn bind_until(
        &mut self,
        instance: InstanceId,
        resource: &str,
        rights: Rights,
        expiry: u64,
    ) -> Result<Handle, Refuse> {
        self.pending_expiry = Some(expiry);
        self.bind_grant(instance, resource, rights)
    }

    /// Changes the registry identity for a live instance.
    pub fn host_set_identity(
        &mut self,
        instance: InstanceId,
        identity: &str,
    ) -> Result<(), Refuse> {
        self.registry
            .get_mut(&instance)
            .ok_or(Refuse::UnknownInstance)?
            .identity = identity.to_owned();
        Ok(())
    }

    /// Changes the registry session for a live instance.
    pub fn host_set_session(&mut self, instance: InstanceId, session: &str) -> Result<(), Refuse> {
        self.registry
            .get_mut(&instance)
            .ok_or(Refuse::UnknownInstance)?
            .session = session.to_owned();
        Ok(())
    }

    /// Stores the verifier clock. A grant expires when this instant is at or
    /// after the expiry stored on that grant.
    pub fn set_verifier_now(&mut self, now: u64) {
        self.verifier_now = now;
    }

    pub fn set_effect_limit(&mut self, handle: Handle, limit: u64) -> Result<(), Refuse> {
        let grant = self.grants.get_mut(&handle).ok_or(Refuse::UnknownHandle)?;
        grant.effect_limit = Some(limit);
        Ok(())
    }

    fn note_effect(&mut self, handle: Handle) -> Result<(), Refuse> {
        let grant = self.grants.get_mut(&handle).ok_or(Refuse::UnknownHandle)?;
        grant.effects += 1;
        Ok(())
    }

    /// The one handle check: resolves a handle and compares the stored grant
    /// with the registry record of the call's instance, in order.
    pub(crate) fn resolve(&self, call: Call, handle: Handle) -> Result<GrantRecord, Refuse> {
        let grant = self
            .grants
            .get(&handle)
            .cloned()
            .ok_or(Refuse::UnknownHandle)?;
        let live = self
            .registry
            .get(&call.instance)
            .ok_or(Refuse::UnknownInstance)?;
        if live.identity != grant.identity {
            return Err(Refuse::Identity);
        }
        if live.session != grant.session {
            return Err(Refuse::Session);
        }
        if call.instance != grant.instance {
            return Err(Refuse::Instance);
        }
        if let Some(expiry) = grant.expiry {
            if self.verifier_now >= expiry {
                return Err(Refuse::Expired);
            }
        }
        Ok(grant)
    }

    /// Uses a grant for one path. The path must be the stored owned root or a
    /// child under it. The guest's claims are not read.
    pub fn use_path(&self, call: &Call, request: &GuestRequest, path: &str) -> Result<(), Refuse> {
        let record = self.resolve(*call, request.handle)?;
        resource_name(&record.identity, path, Some(&record.owned_root))?;
        Ok(())
    }

    /// Uses a grant. The guest's claims are not read.
    pub fn use_grant(&self, call: Call, request: &GuestRequest) -> Result<Decision, Refuse> {
        let record = self.resolve(call, request.handle)?;
        Ok(Decision {
            identity: record.identity,
            session: record.session,
            instance: record.instance,
            owned_root: record.owned_root,
            rights: record.rights,
        })
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// The one name check. At bind the name is the owned root; a use path also
/// carries the owned root it must stay inside. The walk order is host-shaped,
/// public read, outside principal, symlink-shaped, outside root.
fn resource_name(agent: &str, name: &str, owned_root: Option<&str>) -> Result<String, Refuse> {
    if name.contains('\\') || name.starts_with('/') {
        return Err(Refuse::HostPath);
    }
    let parts: Vec<&str> = name.split('/').collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(Refuse::HostPath);
    }
    if parts.first() == Some(&"Public") {
        return Err(Refuse::PublicRead);
    }
    if parts.len() < 3 || parts[0] != "UsersAI" || parts[1] != agent {
        return Err(Refuse::OutsidePrincipal);
    }
    if !parts.iter().skip(2).all(|part| {
        part.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    }) {
        return Err(Refuse::SymlinkShaped);
    }
    if let Some(root) = owned_root {
        let inside = name
            .strip_prefix(root)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
        if !inside {
            return Err(Refuse::OutsideRoot);
        }
    }
    Ok(name.to_owned())
}

#[cfg(test)]
fn rights() -> Rights {
    Rights {
        append: true,
        overwrite: false,
        child_journal: true,
    }
}

#[cfg(test)]
fn guest(handle: Handle) -> GuestRequest {
    GuestRequest {
        handle,
        forged_identity: None,
        forged_session: None,
        forged_instance: None,
        reported_usage: 0,
        forged_ceiling: 0,
        forged_append: false,
        forged_overwrite: false,
        forged_child_journal: false,
    }
}

/// Serialises source reads against the plant runner, which mutates a source
/// file while it runs.
#[cfg(test)]
fn source_reads() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
fn repo_root() -> std::path::PathBuf {
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("PRINCIPLES.md").is_file() {
            return dir;
        }
        dir = dir
            .parent()
            .unwrap_or_else(|| panic!("no PRINCIPLES.md above {}", env!("CARGO_MANIFEST_DIR")))
            .to_path_buf();
    }
}

#[cfg(test)]
fn walk_manifests(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
    let metadata = std::fs::symlink_metadata(dir)
        .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", dir.display()));
    if metadata.file_type().is_symlink() {
        return;
    }
    for entry in std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("cannot read an entry: {error}"));
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", path.display()));
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            if path.file_name().and_then(|name| name.to_str()) == Some("target") {
                continue;
            }
            walk_manifests(&path, found);
        } else if path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml") {
            found.push(path);
        }
    }
}

#[cfg(test)]
fn manifests_that_link_this_crate(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let own = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let mut manifests = Vec::new();
    walk_manifests(root, &mut manifests);
    let mut linked = Vec::new();
    for path in manifests {
        if path == own {
            continue;
        }
        if link::manifest_depends_on_grant_binding(&path) {
            linked.push(path);
        }
    }
    linked
}

#[test]
fn model_forged_identity_session_and_instance_have_no_effect() {
    let mut verifier = Verifier::new();
    let agent = verifier.register_instance("agent-1", "session-a");
    let other = verifier.register_instance("agent-2", "session-b");
    let handle = verifier
        .bind_grant(agent, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = GuestRequest {
        handle,
        forged_identity: Some("intruder".to_owned()),
        forged_session: Some("intruder-session".to_owned()),
        forged_instance: Some(other),
        reported_usage: 9_999,
        forged_ceiling: 1,
        forged_append: false,
        forged_overwrite: true,
        forged_child_journal: false,
    };
    let decision = verifier
        .use_grant(verifier.open_call(agent), &request)
        .expect("grant");
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
    assert_eq!(decision.instance, agent);
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
    assert_eq!(decision.rights, rights());
    assert_ne!(
        request.forged_identity.as_deref(),
        Some(decision.identity.as_str())
    );
    assert_ne!(
        request.forged_session.as_deref(),
        Some(decision.session.as_str())
    );
    assert_ne!(request.forged_instance, Some(decision.instance));
    assert!(request.reported_usage > 0);
    assert!(request.forged_ceiling > 0);
    let forged_rights = Rights {
        append: request.forged_append,
        overwrite: request.forged_overwrite,
        child_journal: request.forged_child_journal,
    };
    assert_ne!(forged_rights, decision.rights);
}

#[test]
fn model_different_identity_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier
        .host_set_identity(instance, "agent-2")
        .expect("set identity");
    let refusal = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect_err("different identity");
    assert_eq!(refusal, Refuse::Identity);
    assert_eq!(refusal.to_string(), "identity does not match the grant");
}

#[test]
fn model_extended_identity_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier
        .host_set_identity(instance, "agent-10")
        .expect("set identity");
    let refusal = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect_err("extended identity");
    assert_eq!(refusal, Refuse::Identity);
    assert_eq!(refusal.to_string(), "identity does not match the grant");
    verifier
        .host_set_identity(instance, "agent-1")
        .expect("restore identity");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect("the stored identity still matches");
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_case_different_identity_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier
        .host_set_identity(instance, "Agent-1")
        .expect("set identity");
    let refusal = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect_err("case-different identity");
    assert_eq!(refusal, Refuse::Identity);
    assert_eq!(refusal.to_string(), "identity does not match the grant");
    verifier
        .host_set_identity(instance, "agent-1")
        .expect("restore identity");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect("the stored identity still matches");
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_extended_session_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier
        .host_set_session(instance, "session-a2")
        .expect("set session");
    let refusal = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect_err("extended session");
    assert_eq!(refusal, Refuse::Session);
    assert_eq!(refusal.to_string(), "session does not match the grant");
    verifier
        .host_set_session(instance, "session-a")
        .expect("restore session");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect("the stored session still matches");
    assert_eq!(decision.session, "session-a");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_case_different_session_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier
        .host_set_session(instance, "Session-A")
        .expect("set session");
    let refusal = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect_err("case-different session");
    assert_eq!(refusal, Refuse::Session);
    assert_eq!(refusal.to_string(), "session does not match the grant");
    verifier
        .host_set_session(instance, "session-a")
        .expect("restore session");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect("the stored session still matches");
    assert_eq!(decision.session, "session-a");
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_new_session_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier
        .host_set_session(instance, "session-b")
        .expect("set session");
    let refusal = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect_err("new session");
    assert_eq!(refusal, Refuse::Session);
    assert_eq!(refusal.to_string(), "session does not match the grant");
}

#[test]
fn model_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let mut request = guest(handle);
    request.forged_instance = Some(first);
    let refusal = verifier
        .use_grant(verifier.open_call(sibling), &request)
        .expect_err("sibling instance");
    assert_eq!(refusal, Refuse::Instance);
    assert_eq!(refusal.to_string(), "instance does not match the grant");
}

#[test]
fn model_unknown_handle_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind first grant");
    let mut other = Verifier::new();
    let other_instance = other.register_instance("agent-1", "session-a");
    other
        .bind_grant(other_instance, "UsersAI/agent-1/notes", rights())
        .expect("bind elsewhere");
    // This verifier mints its own handles from one; a handle minted by the
    // other verifier is unknown here even when both count from one.
    let unknown = other
        .bind_grant(other_instance, "UsersAI/agent-1/notes", rights())
        .expect("bind elsewhere again");
    let refusal = verifier
        .use_grant(verifier.open_call(instance), &guest(unknown))
        .expect_err("unknown handle");
    assert_eq!(refusal, Refuse::UnknownHandle);
    assert_eq!(refusal.to_string(), "unknown handle");
}

#[test]
fn model_unknown_instance_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    assert_ne!(instance, InstanceId(0));
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = GuestRequest {
        forged_instance: Some(instance),
        ..guest(handle)
    };
    let refusal = verifier
        .use_grant(verifier.open_call(InstanceId(0)), &request)
        .expect_err("unknown instance");
    assert_eq!(refusal, Refuse::UnknownInstance);
    assert_eq!(refusal.to_string(), "unknown instance");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &request)
        .expect("the registered instance still uses the grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_bind_unknown_instance_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    assert_ne!(instance, InstanceId(0));
    let refusal = verifier
        .bind_grant(InstanceId(0), "UsersAI/agent-1/notes", rights())
        .expect_err("unknown instance");
    assert_eq!(refusal, Refuse::UnknownInstance);
    assert_eq!(refusal.to_string(), "unknown instance");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("a registered instance still binds");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect("grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_owned_root_under_the_agent_is_stored() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect("grant");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_host_path_root_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/agent-1/file\\name", rights())
        .expect_err("host path");
    assert_eq!(refusal, Refuse::HostPath);
    assert_eq!(refusal.to_string(), "owned root is a host path");
}

#[test]
fn model_empty_segment_in_the_owned_root_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/agent-1//notes", rights())
        .expect_err("empty segment");
    assert_eq!(refusal, Refuse::HostPath);
    assert_eq!(refusal.to_string(), "owned root is a host path");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("a plain root still binds");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect("grant");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_dotdot_in_the_owned_root_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/agent-1/../notes", rights())
        .expect_err("dotdot");
    assert_eq!(refusal, Refuse::HostPath);
    assert_eq!(refusal.to_string(), "owned root is a host path");
}

#[test]
fn model_owned_root_must_sit_under_the_agent() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/other/notes", rights())
        .expect_err("outside principal");
    assert_eq!(refusal, Refuse::OutsidePrincipal);
    assert_eq!(
        refusal.to_string(),
        "owned root is outside the agent principal"
    );
}

#[test]
fn model_extended_agent_segment_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/agent-10/notes", rights())
        .expect_err("extended agent segment");
    assert_eq!(refusal, Refuse::OutsidePrincipal);
    assert_eq!(
        refusal.to_string(),
        "owned root is outside the agent principal"
    );
}

#[test]
fn model_case_different_agent_segment_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/Agent-1/notes", rights())
        .expect_err("case-different agent segment");
    assert_eq!(refusal, Refuse::OutsidePrincipal);
    assert_eq!(
        refusal.to_string(),
        "owned root is outside the agent principal"
    );
}

#[test]
fn model_public_storage_read_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "Public/notes", rights())
        .expect_err("public storage read");
    assert_eq!(refusal, Refuse::PublicRead);
    assert_eq!(refusal.to_string(), "public storage read does not bind");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    let call = verifier.open_call(instance);
    for path in ["Public/notes", "Public/notes/page.md"] {
        let refusal = verifier
            .use_path(&call, &request, path)
            .expect_err("public storage read");
        assert_eq!(refusal, Refuse::PublicRead);
        assert_eq!(refusal.to_string(), "public storage read does not bind");
    }
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/Public")
        .expect("a later Public segment is a normal child path");
}

#[test]
fn model_public_prefix_is_not_a_public_read() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "Publicity/notes", rights())
        .expect_err("public prefix");
    assert_eq!(refusal, Refuse::OutsidePrincipal);
    assert_eq!(
        refusal.to_string(),
        "owned root is outside the agent principal"
    );
}

#[test]
fn model_case_different_public_segment_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "public/notes", rights())
        .expect_err("case-different Public segment");
    assert_eq!(refusal, Refuse::OutsidePrincipal);
    assert_eq!(
        refusal.to_string(),
        "owned root is outside the agent principal"
    );
}

#[test]
fn model_extended_usersai_segment_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "UsersAIextra/agent-1/notes", rights())
        .expect_err("extended UsersAI segment");
    assert_eq!(refusal, Refuse::OutsidePrincipal);
    assert_eq!(
        refusal.to_string(),
        "owned root is outside the agent principal"
    );
}

#[test]
fn model_case_different_usersai_segment_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "usersai/agent-1/notes", rights())
        .expect_err("case-different UsersAI segment");
    assert_eq!(refusal, Refuse::OutsidePrincipal);
    assert_eq!(
        refusal.to_string(),
        "owned root is outside the agent principal"
    );
}

#[test]
fn model_use_path_under_the_owned_root_is_allowed() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    let call = verifier.open_call(instance);
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes")
        .expect("the owned root");
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("a child of the owned root");
}

#[test]
fn model_forged_identity_does_not_move_the_use_path() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("forged identity does not move the use path");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_forged_session_does_not_move_the_use_path() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("forged session does not move the use path");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_forged_instance_does_not_move_the_use_path() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("forged instance does not move the use path");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_reported_usage_does_not_widen_the_use_path() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    let refusal = verifier
        .use_path(&call, &request, "UsersAI/agent-1/other")
        .expect_err("reported usage does not widen the use path");
    assert_eq!(refusal, Refuse::OutsideRoot);
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_forged_ceiling_does_not_widen_the_use_path() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_ceiling: 1,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 0);
    let refusal = verifier
        .use_path(&call, &request, "UsersAI/agent-1/other")
        .expect_err("forged ceiling does not widen the use path");
    assert_eq!(refusal, Refuse::OutsideRoot);
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_forged_append_does_not_widen_the_use_path() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let refusal = verifier
        .use_path(&call, &request, "UsersAI/agent-1/other")
        .expect_err("forged append does not widen the use path");
    assert_eq!(refusal, Refuse::OutsideRoot);
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_forged_overwrite_does_not_widen_the_use_path() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    let refusal = verifier
        .use_path(&call, &request, "UsersAI/agent-1/other")
        .expect_err("forged overwrite does not widen the use path");
    assert_eq!(refusal, Refuse::OutsideRoot);
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_forged_child_journal_does_not_widen_the_use_path() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let refusal = verifier
        .use_path(&call, &request, "UsersAI/agent-1/other")
        .expect_err("forged child journal does not widen the use path");
    assert_eq!(refusal, Refuse::OutsideRoot);
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_forged_append_does_not_move_the_use_call() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("forged append does not move the use call");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.instance, instance);
}

#[test]
fn model_forged_overwrite_does_not_move_the_use_call() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("forged overwrite does not move the use call");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.instance, instance);
}

#[test]
fn model_forged_child_journal_does_not_move_the_use_call() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("forged child journal does not move the use call");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.instance, instance);
}

#[test]
fn model_forged_identity_does_not_move_the_use_call() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("forged identity does not move the use call");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.identity, "agent-1");
}

#[test]
fn model_forged_session_does_not_move_the_use_call() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("forged session does not move the use call");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.session, "session-a");
}

#[test]
fn model_forged_ceiling_does_not_move_the_use_call() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_ceiling: 1,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 0);
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("forged ceiling does not move the use call");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.instance, instance);
}

#[test]
fn model_reported_usage_does_not_move_the_use_call() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("reported usage does not move the use call");
    let decision = verifier.use_grant(call, &guest(handle)).expect("grant");
    assert_eq!(decision.instance, instance);
}

#[test]
fn model_forged_append_does_not_move_the_use_grant() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let decision = verifier
        .use_grant(call, &request)
        .expect("forged append does not move the use grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
}

#[test]
fn model_forged_child_journal_does_not_move_the_use_grant() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let decision = verifier
        .use_grant(call, &request)
        .expect("forged child journal does not move the use grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
}

#[test]
fn model_forged_overwrite_does_not_move_the_use_grant() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    let decision = verifier
        .use_grant(call, &request)
        .expect("forged overwrite does not move the use grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
}

#[test]
fn model_forged_identity_does_not_move_the_use_grant() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let decision = verifier
        .use_grant(call, &request)
        .expect("forged identity does not move the use grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
}

#[test]
fn model_forged_session_does_not_move_the_use_grant() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let decision = verifier
        .use_grant(call, &request)
        .expect("forged session does not move the use grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
}

#[test]
fn model_forged_ceiling_does_not_move_the_use_grant() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_ceiling: 1,
        ..guest(handle)
    };
    assert!(request.forged_ceiling > 0);
    let decision = verifier
        .use_grant(call, &request)
        .expect("forged ceiling does not move the use grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
}

#[test]
fn model_reported_usage_does_not_move_the_use_grant() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..guest(handle)
    };
    assert!(request.reported_usage > 0);
    let decision = verifier
        .use_grant(call, &request)
        .expect("reported usage does not move the use grant");
    assert_eq!(decision.instance, instance);
    assert_eq!(decision.identity, "agent-1");
    assert_eq!(decision.session, "session-a");
}

#[test]
fn model_use_path_dotdot_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let refusal = verifier
        .use_path(
            &verifier.open_call(instance),
            &guest(handle),
            "UsersAI/agent-1/notes/../other",
        )
        .expect_err("dotdot use path");
    assert_eq!(refusal, Refuse::HostPath);
    assert_eq!(refusal.to_string(), "owned root is a host path");
}

#[test]
fn model_dotdot_prefix_segment_is_a_plain_name() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier
        .use_path(
            &verifier.open_call(instance),
            &guest(handle),
            "UsersAI/agent-1/notes/..hidden",
        )
        .expect("a segment that only starts with dotdot stays inside the root");
}

#[test]
fn model_dot_prefix_segment_is_a_plain_name() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier
        .use_path(
            &verifier.open_call(instance),
            &guest(handle),
            "UsersAI/agent-1/notes/.hidden",
        )
        .expect("a segment that only starts with one dot stays inside the root");
}

#[test]
fn model_underscore_segment_is_a_plain_name() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    verifier
        .use_path(
            &verifier.open_call(instance),
            &guest(handle),
            "UsersAI/agent-1/notes/my_page",
        )
        .expect("a segment with an underscore stays inside the root");
}

#[test]
fn model_use_path_outside_the_owned_root_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    let call = verifier.open_call(instance);
    for path in ["UsersAI/agent-1/other", "UsersAI/agent-1/notes-extra"] {
        let refusal = verifier
            .use_path(&call, &request, path)
            .expect_err("outside the owned root");
        assert_eq!(refusal, Refuse::OutsideRoot);
        assert_eq!(refusal.to_string(), "use path leaves the owned root");
    }
}

#[test]
fn model_case_different_use_path_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let refusal = verifier
        .use_path(
            &verifier.open_call(instance),
            &guest(handle),
            "UsersAI/agent-1/Notes/page.md",
        )
        .expect_err("case-different use path");
    assert_eq!(refusal, Refuse::OutsideRoot);
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_symlink_shaped_use_path_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    let call = verifier.open_call(instance);
    let refusal = verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/link->out")
        .expect_err("symlink-shaped segment");
    assert_eq!(refusal, Refuse::SymlinkShaped);
    assert_eq!(refusal.to_string(), "use path has a symlink-shaped segment");
    for path in ["UsersAI/agent-1/notes/.", "UsersAI/agent-1/notes/.."] {
        let refusal = verifier
            .use_path(&call, &request, path)
            .expect_err("host-shaped segment");
        assert_eq!(refusal, Refuse::HostPath);
        assert_eq!(refusal.to_string(), "owned root is a host path");
    }
}

#[test]
fn model_symlink_shaped_owned_root_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/agent-1/link->out", rights())
        .expect_err("symlink-shaped owned root");
    assert_eq!(refusal, Refuse::SymlinkShaped);
    assert_eq!(refusal.to_string(), "use path has a symlink-shaped segment");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("a plain root still binds");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect("grant");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_use_path_on_a_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let refusal = verifier
        .use_path(
            &verifier.open_call(sibling),
            &guest(handle),
            "UsersAI/agent-1/notes",
        )
        .expect_err("sibling instance");
    assert_eq!(refusal, Refuse::Instance);
    assert_eq!(refusal.to_string(), "instance does not match the grant");
}

#[test]
fn model_grant_keeps_bound_rights() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let bound = Rights {
        append: true,
        overwrite: false,
        child_journal: true,
    };
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", bound)
        .expect("bind");
    let request = GuestRequest {
        forged_append: false,
        forged_overwrite: true,
        forged_child_journal: false,
        ..guest(handle)
    };
    let decision = verifier
        .use_grant(verifier.open_call(instance), &request)
        .expect("grant");
    assert_eq!(decision.rights, bound);
}

#[test]
fn model_forged_append_does_not_widen_the_returned_grant() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let bound = Rights {
        append: false,
        overwrite: true,
        child_journal: false,
    };
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", bound)
        .expect("bind");
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let decision = verifier
        .use_grant(verifier.open_call(instance), &request)
        .expect("forged append does not widen the returned grant");
    assert_eq!(decision.rights, bound);
    assert!(!decision.rights.append);
}

#[test]
fn model_forged_child_journal_does_not_widen_the_returned_grant() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let bound = Rights {
        append: true,
        overwrite: false,
        child_journal: false,
    };
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", bound)
        .expect("bind");
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let decision = verifier
        .use_grant(verifier.open_call(instance), &request)
        .expect("forged child journal does not widen the returned grant");
    assert_eq!(decision.rights, bound);
    assert!(!decision.rights.child_journal);
}

#[test]
fn model_forged_append_does_not_replace_the_returned_root() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let decision = verifier
        .use_grant(verifier.open_call(instance), &request)
        .expect("forged append does not replace the returned root");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_forged_child_journal_does_not_replace_the_returned_root() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    let decision = verifier
        .use_grant(verifier.open_call(instance), &request)
        .expect("forged child journal does not replace the returned root");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}

#[test]
fn model_readme_states_the_reference_model_boundary() {
    let readme = include_str!("../README.md");
    assert!(readme.contains(
        "reference model, not the Runtime; counts toward no M1 check; the Runtime half is Anders's (#464, #463, #181)"
    ));
}

#[test]
fn model_detects_a_path_dependency_on_this_crate() {
    assert!(link::cargo_toml_path_depends_on_grant_binding(
        "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\ngrant-binding = { path = \"missing-gb\" }\n"
    ));
    assert!(!link::cargo_toml_path_depends_on_grant_binding(
        "[package]\nname = \"grant-binding\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
    ));
}

#[test]
fn model_no_other_cargo_toml_path_depends_on_this_crate() {
    let _guard = source_reads();
    let root = repo_root();
    let mut manifests = Vec::new();
    walk_manifests(&root, &mut manifests);
    assert!(
        manifests.len() > 1,
        "walk saw {} Cargo.toml files",
        manifests.len()
    );
    let linked = manifests_that_link_this_crate(&root);
    assert!(linked.is_empty(), "{linked:?}");
}

#[test]
fn model_crate_has_no_dependencies_and_forbids_unsafe() {
    let _guard = source_reads();
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read Cargo.toml");
    assert!(!manifest.contains("[dependencies]"));
    assert!(!manifest.contains("[dev-dependencies]"));
    assert!(!manifest.contains("elastos"));
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read src/lib.rs");
    assert!(
        lib.starts_with("#![forbid(unsafe_code)]"),
        "src/lib.rs must begin with forbid(unsafe_code)"
    );
}

#[test]
fn model_planted_bugs_are_caught() {
    let _guard = source_reads();
    plant::run_all();
}

#[test]
fn model_workspace_dependency_is_a_link_in_place() {
    let _guard = source_reads();
    let root = std::env::temp_dir().join(format!("gb-walk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("app/src")).unwrap();
    std::fs::create_dir_all(root.join("vendor/grant-binding/src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n\n[workspace.dependencies]\ngrant-binding = { path = \"vendor/grant-binding\" }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("app/Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\ngrant-binding = { workspace = true }\n",
    )
    .unwrap();
    std::fs::write(root.join("app/src/lib.rs"), "").unwrap();
    std::fs::write(
        root.join("vendor/grant-binding/Cargo.toml"),
        "[package]\nname = \"grant-binding\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(root.join("vendor/grant-binding/src/lib.rs"), "").unwrap();
    let app = root.join("app/Cargo.toml");
    let vendor = root.join("vendor/grant-binding/Cargo.toml");
    let linked = manifests_that_link_this_crate(&root);
    let same = |left: &std::path::Path, right: &std::path::Path| {
        std::fs::canonicalize(left).ok() == std::fs::canonicalize(right).ok()
    };
    assert!(
        link::manifest_depends_on_grant_binding(&app),
        "detector sees the workspace dependency"
    );
    assert!(
        linked.iter().any(|path| same(path, &app)),
        "walk sees the workspace dependency"
    );
    assert!(
        !link::manifest_depends_on_grant_binding(&vendor),
        "own manifest"
    );
    assert!(
        !linked.iter().any(|path| same(path, &vendor)),
        "walk skips the crate manifest"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn model_registered_home_ask_is_refused() {
    let mut verifier = Verifier::new();
    let home = verifier.register_instance("home", "session-a");
    let photo = verifier.register_instance("photo", "session-a");
    let handle = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("photo ask");
    let call = verifier.open_call(photo);
    let decision = verifier
        .use_grant(call, &guest(handle))
        .expect("photo effect");
    assert_eq!(decision.identity, "photo");
    assert_eq!(decision.owned_root, "UsersAI/photo/library");
    let refusal = verifier
        .bind_grant(home, "UsersAI/home/desk", rights())
        .expect_err("home ask");
    assert_eq!(refusal, Refuse::HomeMint);
    assert_eq!(refusal.to_string(), "home does not mint an app capability");
    let again = verifier
        .use_grant(call, &guest(handle))
        .expect("photo effect remains");
    assert_eq!(again.owned_root, "UsersAI/photo/library");
    let for_home = verifier
        .bind_grant(photo, "UsersAI/home/desk", rights())
        .expect_err("photo ask for a home root");
    assert_eq!(for_home, Refuse::OutsidePrincipal);
    assert_eq!(
        for_home.to_string(),
        "owned root is outside the agent principal"
    );
}

#[test]
fn model_home_direct_mint_is_refused() {
    let mut verifier = Verifier::new();
    let home = verifier.register_instance("home", "session-a");
    let photo = verifier.register_instance("photo", "session-a");
    let direct = verifier
        .bind_grant(home, "UsersAI/home/desk", rights())
        .expect_err("home calls the mint");
    assert_eq!(direct, Refuse::HomeMint);
    assert_eq!(direct.to_string(), "home does not mint an app capability");
    let handle = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("app mint");
    let decision = verifier
        .use_grant(verifier.open_call(photo), &guest(handle))
        .expect("photo effect");
    assert_eq!(decision.identity, "photo");
}

#[test]
fn model_expired_grant_is_refused() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_until(photo, "UsersAI/photo/library", rights(), 5)
        .expect("library ask");
    verifier.set_verifier_now(4);
    verifier
        .use_grant(verifier.open_call(photo), &guest(library))
        .expect("before the expiry");
    verifier.set_verifier_now(5);
    let due = verifier
        .use_grant(verifier.open_call(photo), &guest(library))
        .expect_err("the grant has expired");
    assert_eq!(due, Refuse::Expired);
    assert_eq!(due.to_string(), "grant has expired");
    verifier.set_verifier_now(6);
    let later = verifier
        .use_grant(verifier.open_call(photo), &guest(library))
        .expect_err("past the expiry is still due");
    assert_eq!(later, Refuse::Expired);
}

#[test]
fn model_unset_expiry_is_not_expired() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let leaked = verifier
        .bind_until(photo, "Public/photo/desk", rights(), 0)
        .expect_err("public storage does not bind");
    assert_eq!(leaked, Refuse::PublicRead);
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library ask");
    verifier.set_verifier_now(u64::MAX);
    let decision = verifier
        .use_grant(verifier.open_call(photo), &guest(library))
        .expect("unset expiry is not due");
    assert_eq!(decision.owned_root, "UsersAI/photo/library");
    let frames = verifier
        .bind_until(photo, "UsersAI/photo/frames", rights(), 0)
        .expect("zero expiry");
    verifier.set_verifier_now(0);
    let refusal = verifier
        .use_grant(verifier.open_call(photo), &guest(frames))
        .expect_err("a set expiry of 0 is due at 0");
    assert_eq!(refusal, Refuse::Expired);
    assert_eq!(refusal.to_string(), "grant has expired");
}
