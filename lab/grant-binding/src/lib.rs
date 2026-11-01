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
pub use ask::{AdmitRefuse, BudgetAsk};

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

/// The grant store's entry for one handle: the binding and the end mark that
/// refuses every later use (M1 check A7, condition c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndedGrant {
    pub(crate) record: GrantRecord,
    pub(crate) ended: bool,
}

/// One ended binding a hold still keeps until its last hold clears.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldGrant {
    pub(crate) record: GrantRecord,
}

/// The record `resolve` compares once the handle is known to be live.
fn live_record(grant: EndedGrant) -> GrantRecord {
    grant.record
}

/// The stored binding that decides a use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantRecord {
    identity: String,
    session: String,
    instance: InstanceId,
    owned_root: String,
    rights: Rights,
    parent: Option<Handle>,
    once: bool,
    expiry: Option<u64>,
    effect_limit: Option<u64>,
    effects: u64,
    rate: Option<u64>,
    window: u64,
    window_start: u64,
    window_effects: u64,
    session_bound: bool,
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
    HomeMint,
    Expired,
    EffectLimit,
    IssuingLimit,
    Rate,
    IssuingRate,
    JournalHeld,
    HandleSpace,
    InstanceSpace,
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
            Refuse::IssuingLimit => "effect limit stays on the issuing grant",
            Refuse::Rate => "rate limit is reached",
            Refuse::IssuingRate => "rate stays on the issuing grant",
            Refuse::JournalHeld => "a live journal holds that path",
            Refuse::HandleSpace => "handle id does not fit",
            Refuse::InstanceSpace => "instance id does not fit",
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
    grants: HashMap<Handle, EndedGrant>,
    next_instance: u64,
    next_handle: u64,
    pending_parent: Option<Handle>,
    #[allow(dead_code)] // later slices fill the ledger
    ledger: std::sync::Mutex<ledger::Ledger>,
    pending_once: bool,
    pending_session: bool,
    pending_expiry: Option<u64>,
    verifier_now: u64,
    window_due: bool,
}

impl Verifier {
    /// An empty verifier with no instances and no grants.
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
            grants: HashMap::new(),
            next_instance: 0,
            next_handle: 0,
            pending_parent: None,
            ledger: std::sync::Mutex::new(ledger::Ledger::new()),
            pending_once: false,
            pending_session: false,
            pending_expiry: None,
            verifier_now: 0,
            window_due: false,
        }
    }

    /// Registers an instance and returns its registry id.
    pub fn register_instance(
        &mut self,
        identity: &str,
        session: &str,
    ) -> Result<InstanceId, Refuse> {
        #[rustfmt::skip]
        let next_instance = self.next_instance.checked_add(1).ok_or(Refuse::InstanceSpace)?;
        self.next_instance = next_instance;
        let instance = InstanceId(self.next_instance);
        self.registry.insert(
            instance,
            InstanceRecord {
                identity: identity.to_owned(),
                session: session.to_owned(),
            },
        );
        Ok(instance)
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
        let parent = self.pending_parent.take();
        let once = self.pending_once;
        let expiry = self.pending_expiry.take();
        self.pending_once = false;
        let session_bound = self.pending_session;
        self.pending_session = false;
        let record = self
            .registry
            .get(&instance)
            .ok_or(Refuse::UnknownInstance)?;
        if record.identity == "home" {
            return Err(Refuse::HomeMint);
        }
        let owned_root = resource_name(&record.identity, resource, None)?;
        let next_handle = self.next_handle.checked_add(1).ok_or(Refuse::HandleSpace)?;
        self.next_handle = next_handle;
        let handle = Handle(self.next_handle);
        self.grants.insert(
            handle,
            EndedGrant {
                record: GrantRecord {
                    identity: record.identity.clone(),
                    session: record.session.clone(),
                    instance,
                    owned_root,
                    rights,
                    parent,
                    once,
                    expiry,
                    effect_limit: None,
                    effects: 0,
                    rate: None,
                    window: 0,
                    window_start: 0,
                    window_effects: 0,
                    session_bound: session_bound,
                },
                ended: false,
            },
        );
        Ok(handle)
    }

    /// Ends one grant through the one `end_grant`.
    pub fn revoke_grant(&mut self, handle: Handle) -> Result<(), Refuse> {
        #[rustfmt::skip]
        self.end_grant(handle);
        Ok(())
    }

    #[rustfmt::skip]
    fn end_derived_grants(&mut self, handle: Handle) {
        let children: Vec<Handle> = self
            .grants
            .iter()
            .filter(|(_, grant)| grant.record.parent == Some(handle) && !grant.ended)
            .map(|(child, _)| *child)
            .collect();
        for child in children {
            self.end_grant(child);
        }
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
        let same = {
            let record = self
                .registry
                .get_mut(&instance)
                .ok_or(Refuse::UnknownInstance)?;
            let same = record.session == session;
            if !same {
                record.session = session.to_owned();
            }
            same
        };
        #[rustfmt::skip]
        if same {
            return Ok(());
        };
        #[rustfmt::skip]
        let ended: Vec<Handle> = self
            .grants
            .iter()
            .filter(|(_, grant)| grant.record.instance == instance && grant.record.session_bound)
            .map(|(handle, _)| *handle)
            .collect();
        #[rustfmt::skip]
        for handle in ended {
            self.revoke_grant(handle)?;
        };
        Ok(())
    }

    /// Sets the verifier clock that decides an expiry.
    pub fn set_verifier_now(&mut self, now: u64) {
        self.verifier_now = now;
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

    pub fn bind_for_session(
        &mut self,
        instance: InstanceId,
        resource: &str,
        rights: Rights,
    ) -> Result<Handle, Refuse> {
        self.pending_session = true;
        self.bind_grant(instance, resource, rights)
    }

    #[rustfmt::skip]
    fn limit_expiry(&self, handle: Handle) -> Result<Option<u64>, Refuse> {
        let grant = self.grants.get(&handle).ok_or(Refuse::UnknownHandle)?;
        if grant.ended {
            return Err(Refuse::UnknownHandle);
        }
        if grant.record.parent.is_some() {
            return Err(Refuse::IssuingLimit);
        }
        Ok(grant.record.expiry)
    }

    #[rustfmt::skip]
    pub fn set_effect_limit(&mut self, handle: Handle, limit: u64) -> Result<(), Refuse> {
        let expiry = self.limit_expiry(handle)?;
        self.refuse_if_due(expiry)?;
        let grant = self.grants.get_mut(&handle).ok_or(Refuse::UnknownHandle)?;
        grant.record.effect_limit = Some(limit);
        Ok(())
    }

    #[rustfmt::skip]
    fn rate_expiry(&self, handle: Handle) -> Result<Option<u64>, Refuse> {
        let grant = self.grants.get(&handle).ok_or(Refuse::UnknownHandle)?;
        if grant.record.parent.is_some() {
            return Err(Refuse::IssuingRate);
        }
        if grant.ended {
            return Err(Refuse::UnknownHandle);
        }
        Ok(grant.record.expiry)
    }

    #[rustfmt::skip]
    pub fn set_rate(&mut self, handle: Handle, limit: u64, window: u64) -> Result<(), Refuse> {
        let expiry = self.rate_expiry(handle)?;
        self.refuse_if_due(expiry)?;
        let grant = self.grants.get_mut(&handle).ok_or(Refuse::UnknownHandle)?;
        let starting = grant.record.rate.is_none();
        grant.record.rate = Some(limit);
        grant.record.window = window;
        if starting {
            grant.record.window_start = self.verifier_now;
            grant.record.window_effects = 0;
        }
        Ok(())
    }

    #[rustfmt::skip]
    fn note_effect(&mut self, handle: Handle) -> Result<(), Refuse> {
        let grant = self.grants.get_mut(&handle).ok_or(Refuse::UnknownHandle)?;
        if grant.record.effect_limit.is_some() {
            grant.record.effects += 1;
        }
        if grant.record.rate.is_some() {
            grant.record.window_effects += 1;
        }
        Ok(())
    }

    #[rustfmt::skip]
    fn open_rate_window(&mut self, handle: Handle) -> Result<(), Refuse> {
        self.window_due = false;
        let now = self.verifier_now;
        let grant = self.grants.get(&handle).ok_or(Refuse::UnknownHandle)?;
        let Some(rate) = grant.record.rate else {
            return Ok(());
        };
        let _ = rate;
        self.window_due = match grant.record.window_start.checked_add(grant.record.window) {
            Some(end) => now >= end,
            None => false,
        };
        Ok(())
    }

    /// The live-handle prefix `resolve` runs before the expiry walk: the handle
    /// must be known and not ended, and the call must match the stored binding.
    /// It does not read the expiry, so an expired grant is still live here.
    fn resolve_live(&self, call: Call, handle: Handle) -> Result<GrantRecord, Refuse> {
        let grant = self
            .grants
            .get(&handle)
            .cloned()
            .ok_or(Refuse::UnknownHandle)?;
        if grant.ended {
            return Err(Refuse::UnknownHandle);
        }
        let bound = live_record(grant);
        self.check_call(call, &bound)?;
        Ok(bound)
    }

    /// The one expiry comparison: a set expiry is due when `verifier_now` is at
    /// or after it. `resolve` and both bound writes call it, so one place
    /// decides when a grant has expired.
    #[rustfmt::skip]
    fn refuse_if_due(&self, expiry: Option<u64>) -> Result<(), Refuse> {
        if let Some(expiry) = expiry {
            if self.verifier_now >= expiry {
                return Err(Refuse::Expired);
            }
        }
        Ok(())
    }

    /// The one handle check: resolves a handle and compares the stored grant
    /// with the registry record of the call's instance, in order.
    pub(crate) fn resolve(&self, call: Call, handle: Handle) -> Result<GrantRecord, Refuse> {
        let bound = self.resolve_live(call, handle)?;
        #[rustfmt::skip]
        let _ = {
            let mut expiry = bound.expiry;
            let mut parent = bound.parent;
            while let Some(handle) = parent {
                let ancestor = self.grants.get(&handle).ok_or(Refuse::UnknownHandle)?;
                expiry = ancestor.record.expiry;
                parent = ancestor.record.parent;
            }
            self.refuse_if_due(expiry)?;
        };
        Ok(bound)
    }

    /// The compares every resolved binding shares: the call's instance must be
    /// registered, and the registry record must match the binding's identity,
    /// session and instance, in that order. `resolve` and `resolve_kept` both
    /// call it, so one place decides what a call may reach.
    fn check_call(&self, call: Call, record: &GrantRecord) -> Result<(), Refuse> {
        let live = self
            .registry
            .get(&call.instance)
            .ok_or(Refuse::UnknownInstance)?;
        if live.identity != record.identity {
            return Err(Refuse::Identity);
        }
        if live.session != record.session {
            return Err(Refuse::Session);
        }
        if call.instance != record.instance {
            return Err(Refuse::Instance);
        }
        Ok(())
    }

    /// The one handle check for a hold that outlived its grant's end: resolves
    /// the ledger's kept ended binding and compares it with the registry
    /// record of the call's instance, the same way `resolve` does. A handle
    /// that did not end has no binding here, so `settle`, `release` and
    /// `timeout_hold` fall back to `resolve`.
    pub(crate) fn resolve_kept(&self, call: Call, handle: Handle) -> Result<GrantRecord, Refuse> {
        let mut held = {
            let ledger = self.ledger.lock().expect("ledger lock");
            ledger.ended.get(&handle).cloned()
        }
        .ok_or(Refuse::UnknownHandle)?;
        if let Some(live) = self.registry.get(&call.instance) {
            held.record.session = live.session.clone();
            held.record.identity = live.identity.clone();
        }
        self.check_call(call, &held.record)?;
        Ok(held.record)
    }

    /// Resolves a hold's handle: the live binding first, then the ledger's kept
    /// ended binding only when the handle is unknown, which is what `resolve`
    /// returns for an ended handle. `settle`, `release` and `timeout_hold` use
    /// it so a hold opened before its grant's end still closes. `reserve` and
    /// `admit_ask` call `resolve` and open nothing new on an ended grant.
    fn resolve_for_hold(&self, call: Call, handle: Handle) -> Result<GrantRecord, Refuse> {
        #[rustfmt::skip]
        let resolved = {
            self.resolve_live(call, handle).or_else(|refusal| match refusal {
                Refuse::UnknownHandle => self.resolve_kept(call, handle),
                refusal => Err(refusal),
            })
        };
        resolved
    }

    #[rustfmt::skip]
    fn live_journal_holds(
        &self,
        issuing: Handle,
        identity: &str,
        path: &str,
        owned_root: &str,
    ) -> bool {
        self.grants.values().any(|stored| {
            stored.record.parent == Some(issuing)
                && !stored.ended
                && (resource_name(identity, path, Some(&stored.record.owned_root)).is_ok()
                    || (path != owned_root
                        && resource_name(identity, &stored.record.owned_root, Some(path))
                            .is_ok())
                )
        })
    }

    /// Uses a grant for one path. The path must be the stored owned root or a
    /// child under it. A path a live journal minted from this grant holds, or
    /// a path that contains that journal, is refused. The issuing root stays
    /// allowed. The guest's claims are not read.
    pub fn use_path(&self, call: &Call, request: &GuestRequest, path: &str) -> Result<(), Refuse> {
        let record = self.resolve(*call, request.handle)?;
        resource_name(&record.identity, path, Some(&record.owned_root))?;
        #[rustfmt::skip]
        if self.live_journal_holds(request.handle, &record.identity, path, &record.owned_root) {
            return Err(Refuse::JournalHeld);
        };
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
        if links_this_crate(root, &own, &path) {
            linked.push(path);
        }
    }
    linked
}

#[test]
fn model_forged_identity_session_and_instance_have_no_effect() {
    let mut verifier = Verifier::new();
    let agent = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let other = verifier
        .register_instance("agent-2", "session-b")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let first = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind first grant");
    let mut other = Verifier::new();
    let other_instance = other
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/agent-1/file\\name", rights())
        .expect_err("host path");
    assert_eq!(refusal, Refuse::HostPath);
    assert_eq!(refusal.to_string(), "owned root is a host path");
}

#[test]
fn model_empty_segment_in_the_owned_root_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/agent-1/../notes", rights())
        .expect_err("dotdot");
    assert_eq!(refusal, Refuse::HostPath);
    assert_eq!(refusal.to_string(), "owned root is a host path");
}

#[test]
fn model_owned_root_must_sit_under_the_agent() {
    let mut verifier = Verifier::new();
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let first = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let sibling = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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
    let instance = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
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

/// The one manifest this crate's path dependency may name: the lab
/// stand-in's crate (M1 check A7).
#[cfg(test)]
const ALLOWED_LINK: &str = "lab/agent-conformance";

/// Whether `manifest` is a link outside this crate itself. One named path,
/// `lab/agent-conformance`, is the allowed link, and the crate's own manifest
/// is not a link.
#[cfg(test)]
fn links_this_crate(
    root: &std::path::Path,
    own: &std::path::Path,
    manifest: &std::path::Path,
) -> bool {
    if manifest == own {
        return false;
    }
    let allowed = std::fs::canonicalize(root.join(ALLOWED_LINK).join("Cargo.toml")).ok();
    let links = std::fs::canonicalize(manifest).ok();
    if allowed.is_some() && allowed == links {
        return false;
    }
    link::manifest_depends_on_grant_binding(manifest)
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
    let home = verifier
        .register_instance("home", "session-a")
        .expect("instance");
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
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
    let home = verifier
        .register_instance("home", "session-a")
        .expect("instance");
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
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
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
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
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
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

#[test]
fn model_revoke_one_app_stops_only_that_app() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let notes = verifier
        .register_instance("notes", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("photo ask");
    let pad = verifier
        .bind_grant(notes, "UsersAI/notes/pad", rights())
        .expect("notes ask");
    assert_ne!(library, pad);
    let photo_call = verifier.open_call(photo);
    let notes_call = verifier.open_call(notes);
    verifier
        .use_grant(photo_call, &guest(library))
        .expect("photo effect");
    verifier.revoke_grant(library).expect("revoke photo");
    let stopped = verifier
        .use_grant(photo_call, &guest(library))
        .expect_err("ended photo effect");
    assert_eq!(stopped, Refuse::UnknownHandle);
    assert_eq!(stopped.to_string(), "unknown handle");
    let kept = verifier
        .use_grant(notes_call, &guest(pad))
        .expect("notes grant stays");
    assert_eq!(kept.identity, "notes");
    assert_eq!(kept.owned_root, "UsersAI/notes/pad");
}

#[test]
fn model_revoke_stops_derived_child_journals() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let notes = verifier
        .register_instance("notes", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library ask");
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("album ask");
    let notes_handle = verifier
        .bind_grant(notes, "UsersAI/notes/pad", rights())
        .expect("notes ask");
    let photo_call = verifier.open_call(photo);
    let notes_call = verifier.open_call(notes);
    let roll = verifier
        .create_child_journal(&photo_call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    assert_eq!(
        verifier
            .use_grant(photo_call, &guest(roll))
            .expect("child effect")
            .owned_root,
        "UsersAI/photo/library/roll"
    );
    verifier.revoke_grant(library).expect("revoke library");
    let stopped = verifier
        .use_grant(photo_call, &guest(library))
        .expect_err("ended library");
    assert_eq!(stopped, Refuse::UnknownHandle);
    let child_stopped = verifier
        .use_grant(photo_call, &guest(roll))
        .expect_err("ended child journal");
    assert_eq!(child_stopped, Refuse::UnknownHandle);
    assert_eq!(child_stopped.to_string(), "unknown handle");
    let album_kept = verifier
        .use_grant(photo_call, &guest(album))
        .expect("album grant stays");
    assert_eq!(album_kept.owned_root, "UsersAI/photo/album");
    let notes_kept = verifier
        .use_grant(notes_call, &guest(notes_handle))
        .expect("notes grant stays");
    assert_eq!(notes_kept.identity, "notes");
    assert_eq!(notes_kept.owned_root, "UsersAI/notes/pad");
}

#[test]
fn model_revoke_child_journal_leaves_its_parent() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library ask");
    let photo_call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&photo_call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    let other = verifier
        .create_child_journal(&photo_call, &guest(library), "UsersAI/photo/library/other")
        .expect("sibling journal");
    assert_ne!(roll, other);
    verifier.revoke_grant(roll).expect("revoke one journal");
    let child_stopped = verifier
        .use_grant(photo_call, &guest(roll))
        .expect_err("ended journal");
    assert_eq!(child_stopped, Refuse::UnknownHandle);
    assert_eq!(child_stopped.to_string(), "unknown handle");
    let parent_kept = verifier
        .use_grant(photo_call, &guest(library))
        .expect("issuing grant stays");
    assert_eq!(parent_kept.owned_root, "UsersAI/photo/library");
    let sibling_kept = verifier
        .use_grant(photo_call, &guest(other))
        .expect("sibling journal stays");
    assert_eq!(sibling_kept.owned_root, "UsersAI/photo/library/other");
}

#[test]
fn model_failed_child_keeps_next_ask_independent() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library ask");
    let photo_call = verifier.open_call(photo);
    let refusal = verifier
        .create_child_journal(&photo_call, &guest(library), "UsersAI/photo/other")
        .expect_err("child outside the library");
    assert_eq!(refusal, ops::OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("album ask");
    verifier.revoke_grant(library).expect("revoke library");
    let stopped = verifier
        .use_grant(photo_call, &guest(library))
        .expect_err("ended library");
    assert_eq!(stopped, Refuse::UnknownHandle);
    let album_kept = verifier
        .use_grant(photo_call, &guest(album))
        .expect("independent album stays");
    assert_eq!(album_kept.owned_root, "UsersAI/photo/album");
}

#[test]
fn model_successful_child_keeps_next_ask_independent() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library ask");
    let photo_call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&photo_call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("album ask");
    verifier.revoke_grant(library).expect("revoke library");
    let child_stopped = verifier
        .use_grant(photo_call, &guest(roll))
        .expect_err("ended child journal");
    assert_eq!(child_stopped, Refuse::UnknownHandle);
    let album_kept = verifier
        .use_grant(photo_call, &guest(album))
        .expect("independent album stays");
    assert_eq!(album_kept.owned_root, "UsersAI/photo/album");
}

#[test]
fn model_end_grant_ends_derived_child_journals() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let notes = verifier
        .register_instance("notes", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library ask");
    assert_eq!(library, Handle(1));
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("album ask");
    assert_eq!(album, Handle(2));
    let notes_handle = verifier
        .bind_grant(notes, "UsersAI/notes/pad", rights())
        .expect("notes ask");
    assert_eq!(notes_handle, Handle(3));
    let photo_call = verifier.open_call(photo);
    let notes_call = verifier.open_call(notes);
    let roll = verifier
        .create_child_journal(&photo_call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    assert_eq!(roll, Handle(4));
    let other = verifier
        .create_child_journal(&photo_call, &guest(library), "UsersAI/photo/library/other")
        .expect("sibling journal");
    assert_eq!(other, Handle(5));
    verifier.end_grant(roll);
    let one_child = verifier
        .use_grant(photo_call, &guest(roll))
        .expect_err("the ended journal stays ended");
    assert_eq!(one_child, Refuse::UnknownHandle);
    assert_eq!(one_child.to_string(), "unknown handle");
    verifier
        .use_grant(photo_call, &guest(library))
        .expect("ending one journal leaves the issuing grant");
    verifier
        .use_grant(photo_call, &guest(other))
        .expect("ending one journal leaves its sibling");
    verifier.end_grant(library);
    let parent_stopped = verifier
        .use_grant(photo_call, &guest(library))
        .expect_err("the issuing grant has ended");
    assert_eq!(parent_stopped, Refuse::UnknownHandle);
    assert_eq!(parent_stopped.to_string(), "unknown handle");
    let sibling_stopped = verifier
        .use_grant(photo_call, &guest(other))
        .expect_err("end_grant ends the journal minted from that grant");
    assert_eq!(sibling_stopped, Refuse::UnknownHandle);
    assert_eq!(sibling_stopped.to_string(), "unknown handle");
    let album_kept = verifier
        .use_grant(photo_call, &guest(album))
        .expect("another grant stays");
    assert_eq!(album_kept.owned_root, "UsersAI/photo/album");
    let notes_kept = verifier
        .use_grant(notes_call, &guest(notes_handle))
        .expect("another app stays");
    assert_eq!(notes_kept.identity, "notes");
    assert_eq!(notes_kept.owned_root, "UsersAI/notes/pad");
}

#[test]
fn model_session_grant_ends_when_the_session_changes() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let home = verifier
        .register_instance("home", "session-a")
        .expect("instance");
    let home_mint = verifier
        .bind_for_session(home, "UsersAI/home/desk", rights())
        .expect_err("home does not mint");
    assert_eq!(home_mint, Refuse::HomeMint);
    let library = verifier
        .bind_for_session(photo, "UsersAI/photo/library", rights())
        .expect("session grant");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("standing album");
    verifier
        .use_grant(call, &guest(library))
        .expect("first use");
    verifier
        .use_grant(call, &guest(library))
        .expect("a session grant allows a second use");
    verifier
        .host_set_session(photo, "session-b")
        .expect("session changes");
    let stopped = verifier
        .use_grant(call, &guest(library))
        .expect_err("session grant has ended");
    assert_eq!(stopped, Refuse::UnknownHandle);
    assert_eq!(stopped.to_string(), "unknown handle");
    let child_stopped = verifier
        .use_grant(call, &guest(roll))
        .expect_err("child journal ended with the session grant");
    assert_eq!(child_stopped, Refuse::UnknownHandle);
    let album_while = verifier
        .use_grant(call, &guest(album))
        .expect_err("standing grant waits for the old session");
    assert_eq!(album_while, Refuse::Session);
    verifier
        .host_set_session(photo, "session-a")
        .expect("restore session");
    let still = verifier
        .use_grant(call, &guest(library))
        .expect_err("restore does not revive the session grant");
    assert_eq!(still, Refuse::UnknownHandle);
    let album_kept = verifier
        .use_grant(call, &guest(album))
        .expect("standing grant revives");
    assert_eq!(album_kept.owned_root, "UsersAI/photo/album");
}

#[test]
fn model_same_session_keeps_the_session_grant() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_for_session(photo, "UsersAI/photo/library", rights())
        .expect("session grant");
    verifier
        .host_set_session(photo, "session-a")
        .expect("same session");
    let kept = verifier
        .use_grant(verifier.open_call(photo), &guest(library))
        .expect("the same session does not end the grant");
    assert_eq!(kept.owned_root, "UsersAI/photo/library");
}

#[test]
fn model_session_change_leaves_the_other_instance() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let notes = verifier
        .register_instance("notes", "session-a")
        .expect("instance");
    let library = verifier
        .bind_for_session(photo, "UsersAI/photo/library", rights())
        .expect("photo session grant");
    let pad = verifier
        .bind_for_session(notes, "UsersAI/notes/pad", rights())
        .expect("notes session grant");
    let photo_call = verifier.open_call(photo);
    let notes_call = verifier.open_call(notes);
    verifier
        .use_grant(photo_call, &guest(library))
        .expect("photo session grant works before the change");
    let page = verifier
        .create_child_journal(&notes_call, &guest(pad), "UsersAI/notes/pad/page")
        .expect("notes child journal");
    verifier
        .host_set_session(photo, "session-b")
        .expect("photo session changes");
    let notes_kept = verifier
        .use_grant(notes_call, &guest(pad))
        .expect("the other instance's session grant stays");
    assert_eq!(notes_kept.owned_root, "UsersAI/notes/pad");
    let page_kept = verifier
        .use_grant(notes_call, &guest(page))
        .expect("the other instance's child journal stays");
    assert_eq!(page_kept.owned_root, "UsersAI/notes/pad/page");
}

#[test]
fn model_child_use_follows_the_issuing_expiry() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_until(photo, "UsersAI/photo/library", rights(), 5)
        .expect("issuing expiry");
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("standing album");
    let call = verifier.open_call(photo);
    verifier.set_verifier_now(4);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    let other = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/other")
        .expect("sibling journal");
    let page = verifier
        .create_child_journal(&call, &guest(album), "UsersAI/photo/album/page")
        .expect("standing child");
    verifier
        .use_grant(call, &guest(roll))
        .expect("before the issuing expiry");
    verifier.set_verifier_now(5);
    let due = verifier
        .use_grant(call, &guest(library))
        .expect_err("the issuing grant has expired");
    assert_eq!(due, Refuse::Expired);
    let child_due = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the child journal follows the issuing expiry");
    assert_eq!(child_due, Refuse::Expired);
    let sibling = verifier
        .use_grant(call, &guest(other))
        .expect_err("the sibling follows the same issuing expiry");
    assert_eq!(sibling, Refuse::Expired);
    assert_eq!(sibling.to_string(), "grant has expired");
    verifier.set_verifier_now(6);
    let later = verifier
        .use_grant(call, &guest(roll))
        .expect_err("past the issuing expiry is still due");
    assert_eq!(later, Refuse::Expired);
    let album_kept = verifier
        .use_grant(call, &guest(album))
        .expect("a standing grant has no expiry");
    assert_eq!(album_kept.owned_root, "UsersAI/photo/album");
    let page_kept = verifier
        .use_grant(call, &guest(page))
        .expect("a standing child has no issuing expiry");
    assert_eq!(page_kept.owned_root, "UsersAI/photo/album/page");
}

#[test]
fn model_unset_issuing_expiry_does_not_expire_the_child() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("no expiry");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    verifier.set_verifier_now(u64::MAX);
    let decision = verifier
        .use_grant(call, &guest(roll))
        .expect("unset issuing expiry is not due");
    assert_eq!(decision.owned_root, "UsersAI/photo/library/roll");
}

#[test]
fn model_child_path_follows_the_issuing_expiry() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_until(photo, "UsersAI/photo/library", rights(), 10)
        .expect("issuing expiry");
    let call = verifier.open_call(photo);
    verifier.set_verifier_now(9);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    verifier
        .use_grant(call, &guest(roll))
        .expect("before the issuing expiry");
    verifier
        .use_path(&call, &guest(roll), "UsersAI/photo/library/roll")
        .expect("the child path is inside before the expiry");
    verifier.set_verifier_now(10);
    let due = verifier
        .use_grant(call, &guest(library))
        .expect_err("the issuing grant has expired");
    assert_eq!(due, Refuse::Expired);
    assert_eq!(due.to_string(), "grant has expired");
    let child_due = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the child journal follows the issuing expiry");
    assert_eq!(child_due, Refuse::Expired);
    assert_eq!(child_due.to_string(), "grant has expired");
    let path_due = verifier
        .use_path(&call, &guest(roll), "UsersAI/photo/library/roll")
        .expect_err("the child path follows the issuing expiry");
    assert_eq!(path_due, Refuse::Expired);
    assert_eq!(path_due.to_string(), "grant has expired");
}

#[test]
fn model_issuing_use_path_inside_a_live_journal_is_refused() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let parent = verifier
        .bind_grant(photo, "UsersAI/agent-1/journal", rights())
        .expect("issuing grant");
    assert_eq!(parent, Handle(1));
    let call = verifier.open_call(photo);
    let page = verifier
        .create_child_journal(&call, &guest(parent), "UsersAI/agent-1/journal/page.md")
        .expect("the journal mints");
    assert_eq!(page, Handle(2));
    let inside = verifier
        .use_path(
            &call,
            &guest(parent),
            "UsersAI/agent-1/journal/page.md/line",
        )
        .expect_err("the issuing grant does not use a path inside a live journal");
    assert_eq!(inside, Refuse::JournalHeld);
    assert_eq!(inside.to_string(), "a live journal holds that path");
    let on_journal = verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal/page.md")
        .expect_err("the issuing grant does not use the journal path");
    assert_eq!(on_journal, Refuse::JournalHeld);
    assert_eq!(on_journal.to_string(), "a live journal holds that path");
    let other = verifier
        .bind_grant(photo, "UsersAI/agent-1/journal", rights())
        .expect("another issuing grant");
    assert_eq!(other, Handle(3));
    verifier
        .use_path(&call, &guest(other), "UsersAI/agent-1/journal/page.md/line")
        .expect("another issuing grant still uses that path");
    verifier
        .use_path(&call, &guest(page), "UsersAI/agent-1/journal/page.md/line")
        .expect("the journal's own use stays allowed");
    verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal")
        .expect("a use of the issuing root stays allowed");
    verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal/page")
        .expect("a string prefix is not the journal path");
    verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal/other.md")
        .expect("a path beside a live journal stays allowed");
    verifier.revoke_grant(page).expect("end the journal");
    verifier
        .use_path(
            &call,
            &guest(parent),
            "UsersAI/agent-1/journal/page.md/line",
        )
        .expect("an ended journal frees that path");
    let ended = verifier
        .use_grant(call, &guest(page))
        .expect_err("the ended journal stays ended");
    assert_eq!(ended, Refuse::UnknownHandle);
    assert_eq!(ended.to_string(), "unknown handle");
    verifier
        .use_grant(call, &guest(parent))
        .expect("the issuing grant stays");
    verifier
        .use_grant(call, &guest(other))
        .expect("the other issuing grant stays");
    let once = verifier
        .bind_once(photo, "UsersAI/agent-1/album", rights())
        .expect("allow once");
    assert_eq!(once, Handle(4));
    let shot = verifier
        .create_child_journal(&call, &guest(once), "UsersAI/agent-1/album/shot")
        .expect("the allow-once journal mints");
    assert_eq!(shot, Handle(5));
    let held_once = verifier
        .use_path(&call, &guest(once), "UsersAI/agent-1/album/shot")
        .expect_err("a refused use does not end the allow-once grant");
    assert_eq!(held_once, Refuse::JournalHeld);
    verifier
        .use_grant(call, &guest(once))
        .expect("the allow-once grant stays");
    verifier
        .use_grant(call, &guest(shot))
        .expect("the allow-once journal stays");
}

#[test]
fn model_issuing_use_path_over_a_live_journal_is_refused() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("agent-1", "session-a")
        .expect("instance");
    let parent = verifier
        .bind_grant(photo, "UsersAI/agent-1/journal", rights())
        .expect("issuing grant");
    assert_eq!(parent, Handle(1));
    let call = verifier.open_call(photo);
    let page = verifier
        .create_child_journal(
            &call,
            &guest(parent),
            "UsersAI/agent-1/journal/album/page.md",
        )
        .expect("the journal mints");
    assert_eq!(page, Handle(2));
    let over = verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal/album")
        .expect_err("the issuing grant does not use a path over a live journal");
    assert_eq!(over, Refuse::JournalHeld);
    assert_eq!(over.to_string(), "a live journal holds that path");
    let other = verifier
        .bind_grant(photo, "UsersAI/agent-1/journal", rights())
        .expect("another issuing grant");
    assert_eq!(other, Handle(3));
    verifier
        .use_path(&call, &guest(other), "UsersAI/agent-1/journal/album")
        .expect("another issuing grant still uses that path");
    verifier
        .use_path(
            &call,
            &guest(page),
            "UsersAI/agent-1/journal/album/page.md/line",
        )
        .expect("the journal's own use stays allowed");
    verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal")
        .expect("a use of the issuing root stays allowed");
    verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal/album/page")
        .expect("a string prefix of the journal path is not a cover");
    verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal/albu")
        .expect("a string prefix of the containing path is not a cover");
    verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal/other.md")
        .expect("a path beside a live journal stays allowed");
    verifier.revoke_grant(page).expect("end the journal");
    verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal/album")
        .expect("an ended journal frees that path");
    let ended = verifier
        .use_grant(call, &guest(page))
        .expect_err("the ended journal stays ended");
    assert_eq!(ended, Refuse::UnknownHandle);
    assert_eq!(ended.to_string(), "unknown handle");
    verifier
        .use_grant(call, &guest(parent))
        .expect("the issuing grant stays");
    verifier
        .use_grant(call, &guest(other))
        .expect("the other issuing grant stays");
    let once = verifier
        .bind_once(photo, "UsersAI/agent-1/album", rights())
        .expect("allow once");
    assert_eq!(once, Handle(4));
    let shot = verifier
        .create_child_journal(&call, &guest(once), "UsersAI/agent-1/album/roll/shot")
        .expect("the allow-once journal mints");
    assert_eq!(shot, Handle(5));
    let held_once = verifier
        .use_path(&call, &guest(once), "UsersAI/agent-1/album/roll")
        .expect_err("a refused use does not end the allow-once grant");
    assert_eq!(held_once, Refuse::JournalHeld);
    verifier
        .use_grant(call, &guest(once))
        .expect("the allow-once grant stays");
    verifier
        .use_grant(call, &guest(shot))
        .expect("the allow-once journal stays");
}

#[test]
fn model_handle_id_that_does_not_fit_is_refused() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library");
    assert_eq!(library, Handle(1));
    verifier.next_handle = u64::MAX - 1;
    let frames = verifier
        .bind_grant(photo, "UsersAI/photo/frames", rights())
        .expect("the last handle");
    assert_eq!(frames, Handle(u64::MAX));
    let call = verifier.open_call(photo);
    let refusal = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect_err("the next handle does not fit");
    assert_eq!(refusal, Refuse::HandleSpace);
    assert_eq!(refusal.to_string(), "handle id does not fit");
    assert_eq!(verifier.next_handle, u64::MAX);
    let missing = verifier
        .use_grant(call, &guest(Handle(2)))
        .expect_err("no grant was stored at the next low handle");
    assert_eq!(missing, Refuse::UnknownHandle);
    let wrapped = verifier
        .use_grant(call, &guest(Handle(0)))
        .expect_err("the counter did not wrap");
    assert_eq!(wrapped, Refuse::UnknownHandle);
    let home = verifier
        .register_instance("home", "session-a")
        .expect("instance");
    let home_refusal = verifier
        .bind_grant(home, "UsersAI/home/desk", rights())
        .expect_err("home still does not mint");
    assert_eq!(home_refusal, Refuse::HomeMint);
    assert_eq!(
        home_refusal.to_string(),
        "home does not mint an app capability"
    );
    assert_eq!(verifier.next_handle, u64::MAX);
    let host_path = verifier
        .bind_grant(photo, "UsersAI/photo/../secret", rights())
        .expect_err("a host-shaped name is still refused");
    assert_eq!(host_path, Refuse::HostPath);
    assert_eq!(host_path.to_string(), "owned root is a host path");
    assert_eq!(verifier.next_handle, u64::MAX);
    let child = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect_err("a journal needs a handle");
    assert_eq!(child, ops::OperateRefuse::Binding(Refuse::HandleSpace));
    assert_eq!(child.to_string(), "handle id does not fit");
    assert_eq!(verifier.next_handle, u64::MAX);
    verifier.next_handle = 1;
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("the next ask is an issuing grant");
    assert_eq!(album, Handle(2));
    verifier
        .set_rate(album, 1, 10)
        .expect("an issuing grant stores a rate");
    let library_kept = verifier
        .use_grant(call, &guest(library))
        .expect("the library grant stays");
    assert_eq!(library_kept.owned_root, "UsersAI/photo/library");
    let frames_kept = verifier
        .use_grant(call, &guest(frames))
        .expect("the last handle stays");
    assert_eq!(frames_kept.owned_root, "UsersAI/photo/frames");
    let album_kept = verifier
        .use_grant(call, &guest(album))
        .expect("the album grant stays");
    assert_eq!(album_kept.owned_root, "UsersAI/photo/album");
}

#[test]
fn model_instance_id_that_does_not_fit_is_refused() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    assert_eq!(photo, InstanceId(1));
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library");
    verifier.next_instance = u64::MAX - 1;
    let frames = verifier
        .register_instance("frames", "session-a")
        .expect("instance");
    assert_eq!(frames, InstanceId(u64::MAX));
    let refusal = verifier
        .register_instance("album", "session-a")
        .expect_err("the next instance does not fit");
    assert_eq!(refusal, Refuse::InstanceSpace);
    assert_eq!(refusal.to_string(), "instance id does not fit");
    assert_eq!(verifier.next_instance, u64::MAX);
    let call = verifier.open_call(photo);
    let kept = verifier
        .use_grant(call, &guest(library))
        .expect("the first instance stays");
    assert_eq!(kept.identity, "photo");
    assert_eq!(kept.owned_root, "UsersAI/photo/library");
    let frames_grant = verifier
        .bind_grant(frames, "UsersAI/frames/roll", rights())
        .expect("the last instance still binds");
    let frames_call = verifier.open_call(frames);
    let frames_kept = verifier
        .use_grant(frames_call, &guest(frames_grant))
        .expect("the last instance stays");
    assert_eq!(frames_kept.identity, "frames");
    let wrapped = verifier
        .bind_grant(InstanceId(0), "UsersAI/photo/album", rights())
        .expect_err("the counter did not wrap");
    assert_eq!(wrapped, Refuse::UnknownInstance);
    assert_eq!(wrapped.to_string(), "unknown instance");
    assert_eq!(verifier.next_instance, u64::MAX);
    verifier.next_instance = 1;
    let album = verifier
        .register_instance("album", "session-a")
        .expect("instance");
    assert_eq!(album, InstanceId(2));
    let desk = verifier
        .bind_grant(album, "UsersAI/album/desk", rights())
        .expect("the next register is a new instance");
    let album_call = verifier.open_call(album);
    let album_kept = verifier
        .use_grant(album_call, &guest(desk))
        .expect("the new instance stays");
    assert_eq!(album_kept.identity, "album");
}

#[test]
fn model_later_grant_stores_the_new_session() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_for_session(photo, "UsersAI/photo/library", rights())
        .expect("session grant");
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("standing album");
    let call = verifier.open_call(photo);
    verifier
        .host_set_session(photo, "session-b")
        .expect("session changes");
    let ended = verifier
        .use_grant(call, &guest(library))
        .expect_err("the session grant has ended");
    assert_eq!(ended, Refuse::UnknownHandle);
    assert_eq!(ended.to_string(), "unknown handle");
    let waiting = verifier
        .use_grant(call, &guest(album))
        .expect_err("the standing grant waits for session-a");
    assert_eq!(waiting, Refuse::Session);
    assert_eq!(waiting.to_string(), "session does not match the grant");
    let frames = verifier
        .bind_for_session(photo, "UsersAI/photo/frames", rights())
        .expect("grant on the new session");
    let roll = verifier
        .create_child_journal(&call, &guest(frames), "UsersAI/photo/frames/roll")
        .expect("journal on the new session");
    let frames_use = verifier
        .use_grant(call, &guest(frames))
        .expect("the new session grant matches the live session");
    assert_eq!(frames_use.session, "session-b");
    assert_eq!(frames_use.owned_root, "UsersAI/photo/frames");
    let roll_use = verifier
        .use_grant(call, &guest(roll))
        .expect("the journal stores the new session");
    assert_eq!(roll_use.session, "session-b");
    assert_eq!(roll_use.owned_root, "UsersAI/photo/frames/roll");
    let still = verifier
        .use_grant(call, &guest(library))
        .expect_err("the ended grant stays ended");
    assert_eq!(still, Refuse::UnknownHandle);
    verifier
        .host_set_session(photo, "session-c")
        .expect("session changes again");
    let frames_ended = verifier
        .use_grant(call, &guest(frames))
        .expect_err("the new session grant ends with the next change");
    assert_eq!(frames_ended, Refuse::UnknownHandle);
    let roll_ended = verifier
        .use_grant(call, &guest(roll))
        .expect_err("its journal ends with it");
    assert_eq!(roll_ended, Refuse::UnknownHandle);
    let album_still = verifier
        .use_grant(call, &guest(album))
        .expect_err("the first standing grant still waits for session-a");
    assert_eq!(album_still, Refuse::Session);
    let desk = verifier
        .bind_grant(photo, "UsersAI/photo/desk", rights())
        .expect("standing grant on session-c");
    let desk_use = verifier
        .use_grant(call, &guest(desk))
        .expect("a standing grant stores the live session");
    assert_eq!(desk_use.session, "session-c");
    verifier
        .host_set_session(photo, "session-a")
        .expect("restore session-a");
    verifier
        .use_grant(call, &guest(album))
        .expect("the first standing grant revives");
    let desk_waits = verifier
        .use_grant(call, &guest(desk))
        .expect_err("the session-c grant waits for session-c");
    assert_eq!(desk_waits, Refuse::Session);
    let frames_still = verifier
        .use_grant(call, &guest(frames))
        .expect_err("restore does not revive the ended session grant");
    assert_eq!(frames_still, Refuse::UnknownHandle);
}

#[test]
fn model_later_grant_stores_the_new_identity() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library");
    let call = verifier.open_call(photo);
    verifier
        .host_set_identity(photo, "frames")
        .expect("identity changes");
    let old = verifier
        .use_grant(call, &guest(library))
        .expect_err("the earlier grant keeps photo");
    assert_eq!(old, Refuse::Identity);
    assert_eq!(old.to_string(), "identity does not match the grant");
    let roll = verifier
        .bind_grant(photo, "UsersAI/frames/roll", rights())
        .expect("grant on the new identity");
    let page = verifier
        .create_child_journal(&call, &guest(roll), "UsersAI/frames/roll/page")
        .expect("journal on the new identity");
    let roll_use = verifier
        .use_grant(call, &guest(roll))
        .expect("the new grant matches the live identity");
    assert_eq!(roll_use.identity, "frames");
    assert_eq!(roll_use.owned_root, "UsersAI/frames/roll");
    let page_use = verifier
        .use_grant(call, &guest(page))
        .expect("the journal stores the new identity");
    assert_eq!(page_use.identity, "frames");
    assert_eq!(page_use.owned_root, "UsersAI/frames/roll/page");
    let still = verifier
        .use_grant(call, &guest(library))
        .expect_err("the earlier grant stays on photo");
    assert_eq!(still, Refuse::Identity);
    verifier
        .host_set_identity(photo, "photo")
        .expect("restore photo");
    verifier
        .use_grant(call, &guest(library))
        .expect("the earlier grant revives");
    let roll_waits = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the frames grant waits for frames");
    assert_eq!(roll_waits, Refuse::Identity);
    let page_waits = verifier
        .use_grant(call, &guest(page))
        .expect_err("the journal waits for frames");
    assert_eq!(page_waits, Refuse::Identity);
}

#[test]
fn model_identity_change_leaves_the_session_grant() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_for_session(photo, "UsersAI/photo/library", rights())
        .expect("session grant");
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("standing album");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    verifier
        .use_grant(call, &guest(library))
        .expect("the session grant works");
    verifier
        .host_set_identity(photo, "frames")
        .expect("identity changes");
    let waiting = verifier
        .use_grant(call, &guest(library))
        .expect_err("the session grant waits for photo");
    assert_eq!(waiting, Refuse::Identity);
    assert_eq!(waiting.to_string(), "identity does not match the grant");
    let child_waiting = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the journal waits for photo");
    assert_eq!(child_waiting, Refuse::Identity);
    let album_waiting = verifier
        .use_grant(call, &guest(album))
        .expect_err("the standing grant waits for photo");
    assert_eq!(album_waiting, Refuse::Identity);
    verifier
        .host_set_identity(photo, "photo")
        .expect("restore photo");
    verifier
        .use_grant(call, &guest(library))
        .expect("the session grant revives");
    verifier
        .use_grant(call, &guest(roll))
        .expect("the journal revives");
    let album_kept = verifier
        .use_grant(call, &guest(album))
        .expect("the standing grant revives");
    assert_eq!(album_kept.owned_root, "UsersAI/photo/album");
    verifier
        .host_set_session(photo, "session-b")
        .expect("session changes");
    let ended = verifier
        .use_grant(call, &guest(library))
        .expect_err("a later session change still ends the session grant");
    assert_eq!(ended, Refuse::UnknownHandle);
    assert_eq!(ended.to_string(), "unknown handle");
    let child_ended = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the journal ends with the session grant");
    assert_eq!(child_ended, Refuse::UnknownHandle);
    let album_waits = verifier
        .use_grant(call, &guest(album))
        .expect_err("the standing grant waits for session-a");
    assert_eq!(album_waits, Refuse::Session);
    assert_eq!(album_waits.to_string(), "session does not match the grant");
    verifier
        .host_set_session(photo, "session-a")
        .expect("restore session-a");
    verifier
        .use_grant(call, &guest(album))
        .expect("the standing grant revives");
    let still = verifier
        .use_grant(call, &guest(library))
        .expect_err("restore does not revive the session grant");
    assert_eq!(still, Refuse::UnknownHandle);
}

#[test]
fn model_session_change_ends_under_a_different_identity() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_for_session(photo, "UsersAI/photo/library", rights())
        .expect("session grant");
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("standing album");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    verifier
        .host_set_identity(photo, "frames")
        .expect("identity changes");
    let waiting = verifier
        .use_grant(call, &guest(library))
        .expect_err("the session grant is still live");
    assert_eq!(waiting, Refuse::Identity);
    assert_eq!(waiting.to_string(), "identity does not match the grant");
    verifier
        .host_set_session(photo, "session-b")
        .expect("session changes");
    let ended = verifier
        .use_grant(call, &guest(library))
        .expect_err("the session change ends the grant");
    assert_eq!(ended, Refuse::UnknownHandle);
    assert_eq!(ended.to_string(), "unknown handle");
    let child_ended = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the journal ends with the session grant");
    assert_eq!(child_ended, Refuse::UnknownHandle);
    let album_waits = verifier
        .use_grant(call, &guest(album))
        .expect_err("the standing grant waits for photo");
    assert_eq!(album_waits, Refuse::Identity);
    verifier
        .host_set_identity(photo, "photo")
        .expect("restore photo");
    let still = verifier
        .use_grant(call, &guest(library))
        .expect_err("restore does not revive the session grant");
    assert_eq!(still, Refuse::UnknownHandle);
    let album_still = verifier
        .use_grant(call, &guest(album))
        .expect_err("the standing grant still waits for session-a");
    assert_eq!(album_still, Refuse::Session);
    verifier
        .host_set_session(photo, "session-a")
        .expect("restore session-a");
    verifier
        .use_grant(call, &guest(album))
        .expect("the standing grant revives");
    let gone = verifier
        .use_grant(call, &guest(library))
        .expect_err("the session grant stays ended");
    assert_eq!(gone, Refuse::UnknownHandle);
}

#[test]
fn model_session_and_identity_keep_the_spent_rate() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library");
    let frames = verifier
        .bind_grant(photo, "UsersAI/photo/frames", rights())
        .expect("frames has no rate");
    verifier
        .set_rate(library, 1, 10)
        .expect("one effect in the window");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not spend the rate");
    verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("one effect inside the window");
    let spent = verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the rate is spent");
    assert_eq!(spent, crate::ops::OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(spent.to_string(), "rate limit is reached");
    verifier
        .host_set_session(photo, "session-b")
        .expect("session changes");
    let waiting = verifier
        .use_grant(call, &guest(library))
        .expect_err("the standing grant waits for session-a");
    assert_eq!(waiting, Refuse::Session);
    assert_eq!(waiting.to_string(), "session does not match the grant");
    let child_waiting = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the journal waits for session-a");
    assert_eq!(child_waiting, Refuse::Session);
    verifier
        .host_set_session(photo, "session-a")
        .expect("restore session-a");
    let kept = verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the session change kept the spent rate");
    assert_eq!(kept, crate::ops::OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(kept.to_string(), "rate limit is reached");
    let child_kept = verifier
        .operate(
            &call,
            &guest(roll),
            crate::ops::Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect_err("the journal keeps the same rate");
    assert_eq!(child_kept, crate::ops::OperateRefuse::Binding(Refuse::Rate));
    verifier
        .operate(
            &call,
            &guest(frames),
            crate::ops::Operation::Append,
            "UsersAI/photo/frames",
        )
        .expect("a grant with no rate still appends");
    verifier
        .host_set_identity(photo, "frames")
        .expect("identity changes");
    let identity_wait = verifier
        .use_grant(call, &guest(library))
        .expect_err("the standing grant waits for photo");
    assert_eq!(identity_wait, Refuse::Identity);
    assert_eq!(
        identity_wait.to_string(),
        "identity does not match the grant"
    );
    verifier
        .host_set_identity(photo, "photo")
        .expect("restore photo");
    let still = verifier
        .operate(
            &call,
            &guest(roll),
            crate::ops::Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect_err("the identity change kept the spent rate");
    assert_eq!(still, crate::ops::OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(still.to_string(), "rate limit is reached");
    verifier
        .use_grant(call, &guest(library))
        .expect("the grant stays in the store");
    verifier
        .use_grant(call, &guest(roll))
        .expect("the journal stays in the store");
}

#[test]
fn model_session_and_identity_keep_the_effect_count() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library");
    let frames = verifier
        .bind_grant(photo, "UsersAI/photo/frames", rights())
        .expect("frames has no effect count limit");
    verifier.set_effect_limit(library, 1).expect("one effect");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not spend the count");
    verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("one effect");
    let spent = verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the effect count is spent");
    assert_eq!(
        spent,
        crate::ops::OperateRefuse::Binding(Refuse::EffectLimit)
    );
    assert_eq!(spent.to_string(), "effect limit is reached");
    verifier
        .host_set_session(photo, "session-b")
        .expect("session changes");
    let waiting = verifier
        .use_grant(call, &guest(library))
        .expect_err("the standing grant waits for session-a");
    assert_eq!(waiting, Refuse::Session);
    verifier
        .host_set_session(photo, "session-a")
        .expect("restore session-a");
    let kept = verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the session change kept the spent count");
    assert_eq!(
        kept,
        crate::ops::OperateRefuse::Binding(Refuse::EffectLimit)
    );
    assert_eq!(kept.to_string(), "effect limit is reached");
    let child_kept = verifier
        .operate(
            &call,
            &guest(roll),
            crate::ops::Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect_err("the journal keeps the same count");
    assert_eq!(
        child_kept,
        crate::ops::OperateRefuse::Binding(Refuse::EffectLimit)
    );
    verifier
        .operate(
            &call,
            &guest(frames),
            crate::ops::Operation::Append,
            "UsersAI/photo/frames",
        )
        .expect("a grant with no effect count limit still appends");
    verifier
        .host_set_identity(photo, "frames")
        .expect("identity changes");
    let identity_wait = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the journal waits for photo");
    assert_eq!(identity_wait, Refuse::Identity);
    verifier
        .host_set_identity(photo, "photo")
        .expect("restore photo");
    let still = verifier
        .operate(
            &call,
            &guest(roll),
            crate::ops::Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect_err("the identity change kept the spent count");
    assert_eq!(
        still,
        crate::ops::OperateRefuse::Binding(Refuse::EffectLimit)
    );
    assert_eq!(still.to_string(), "effect limit is reached");
    verifier
        .use_grant(call, &guest(library))
        .expect("the grant stays in the store");
    verifier
        .use_grant(call, &guest(roll))
        .expect("the journal stays in the store");
}

#[test]
fn model_first_rate_keeps_the_effect_count() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library");
    let frames = verifier
        .bind_grant(photo, "UsersAI/photo/frames", rights())
        .expect("frames has no effect count limit");
    verifier.set_effect_limit(library, 2).expect("two effects");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not spend the count");
    verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("one effect before the rate");
    verifier
        .set_rate(library, 10, 10)
        .expect("the first rate does not start the effect count over");
    verifier
        .set_rate(frames, 10, 10)
        .expect("frames has a rate and no effect count limit");
    verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("the second effect reaches the limit");
    let kept = verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the first rate kept the spent count");
    assert_eq!(
        kept,
        crate::ops::OperateRefuse::Binding(Refuse::EffectLimit)
    );
    assert_eq!(kept.to_string(), "effect limit is reached");
    let child_kept = verifier
        .operate(
            &call,
            &guest(roll),
            crate::ops::Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect_err("the journal keeps the same count");
    assert_eq!(
        child_kept,
        crate::ops::OperateRefuse::Binding(Refuse::EffectLimit)
    );
    assert_eq!(child_kept.to_string(), "effect limit is reached");
    verifier
        .operate(
            &call,
            &guest(frames),
            crate::ops::Operation::Append,
            "UsersAI/photo/frames",
        )
        .expect("a grant with no effect count limit still appends");
    verifier
        .use_grant(call, &guest(library))
        .expect("the grant stays in the store");
    verifier
        .use_grant(call, &guest(roll))
        .expect("the journal stays in the store");
}

#[test]
fn model_session_and_identity_keep_the_rate_window() {
    let mut verifier = Verifier::new();
    let photo = verifier
        .register_instance("photo", "session-a")
        .expect("instance");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("library");
    let frames = verifier
        .bind_grant(photo, "UsersAI/photo/frames", rights())
        .expect("frames has no rate");
    verifier.set_verifier_now(10);
    verifier
        .set_rate(library, 1, 10)
        .expect("window starts at 10");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not spend the rate");
    verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("one effect inside the window");
    let spent = verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the rate is spent");
    assert_eq!(spent, crate::ops::OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(spent.to_string(), "rate limit is reached");
    verifier.set_verifier_now(15);
    verifier
        .host_set_session(photo, "session-b")
        .expect("session changes");
    let waiting = verifier
        .use_grant(call, &guest(library))
        .expect_err("the standing grant waits for session-a");
    assert_eq!(waiting, Refuse::Session);
    assert_eq!(waiting.to_string(), "session does not match the grant");
    verifier
        .host_set_session(photo, "session-a")
        .expect("restore session-a");
    verifier
        .host_set_identity(photo, "frames")
        .expect("identity changes");
    let identity_wait = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the journal waits for photo");
    assert_eq!(identity_wait, Refuse::Identity);
    assert_eq!(
        identity_wait.to_string(),
        "identity does not match the grant"
    );
    verifier
        .host_set_identity(photo, "photo")
        .expect("restore photo");
    verifier
        .operate(
            &call,
            &guest(frames),
            crate::ops::Operation::Append,
            "UsersAI/photo/frames",
        )
        .expect("a grant with no rate still appends");
    verifier.set_verifier_now(19);
    let early = verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the window that started at 10 has not ended");
    assert_eq!(early, crate::ops::OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(early.to_string(), "rate limit is reached");
    let child_early = verifier
        .operate(
            &call,
            &guest(roll),
            crate::ops::Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect_err("the journal keeps the same window");
    assert_eq!(
        child_early,
        crate::ops::OperateRefuse::Binding(Refuse::Rate)
    );
    verifier.set_verifier_now(20);
    verifier
        .operate(
            &call,
            &guest(roll),
            crate::ops::Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect("the window that started at 10 ends at 20");
    let next = verifier
        .operate(
            &call,
            &guest(library),
            crate::ops::Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("that effect started the next window");
    assert_eq!(next, crate::ops::OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(next.to_string(), "rate limit is reached");
    verifier
        .use_grant(call, &guest(library))
        .expect("the grant stays in the store");
    verifier
        .use_grant(call, &guest(roll))
        .expect("the journal stays in the store");
}
