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
        let record = self
            .registry
            .get(&instance)
            .ok_or(Refuse::UnknownInstance)?;
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
            },
        );
        Ok(handle)
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
fn model_readme_states_the_reference_model_boundary() {
    let readme = include_str!("../README.md");
    assert!(readme.contains(
        "reference model, not the Runtime; counts toward no M1 check; the Runtime half is Anders's (#464, #463, #181)"
    ));
}

#[test]
fn model_detects_a_path_dependency_on_this_crate() {
    assert!(link::cargo_toml_path_depends_on_grant_binding(
        r#"grant-binding = { path = "lab/grant-binding" }"#
    ));
    assert!(!link::cargo_toml_path_depends_on_grant_binding(
        r#"name = "grant-binding""#
    ));
}

#[test]
fn model_no_other_cargo_toml_path_depends_on_this_crate() {
    let _guard = source_reads();
    let own = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let mut manifests = Vec::new();
    walk_manifests(&repo_root(), &mut manifests);
    let mut checked = 0;
    for path in manifests {
        if path == own {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        assert!(
            !link::cargo_toml_path_depends_on_grant_binding(&text),
            "{} has a path dependency on grant-binding",
            path.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "no other Cargo.toml was read");
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
