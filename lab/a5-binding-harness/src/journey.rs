//! The nine A5 journeys, written once against [`BindingRuntime`].
//!
//! These functions prove the harness. They count toward no M1 check until
//! [`crate::acceptance`] runs them against a live operator. The four positive
//! rows are different journeys: identity reads A's bytes, session reads the
//! host session id, instance launches two activations, storage walks child /
//! `..` / sibling / prefix.

use crate::contract::{
    owned_resource, reject_public_as_binding, require_any_runtime_refusal, require_grant_id,
    require_runtime_allow, require_runtime_refusal, BindingRuntime, Fixture, Grant, Handle,
    HostBinding, Instance, A_SEED, CLEANUP_REASON, HOST_PATH_REFUSAL, IDENTITY_REFUSAL,
    INSTANCE_REFUSAL, OWNED_NOTES, OWNED_ROOT_REFUSAL, PREFIX_REFUSAL, PUBLIC_REASON,
    PUBLIC_RESOURCE, SESSION_REFUSAL, SYMLINK_REFUSAL,
};

pub type Outcome = Result<String, String>;

struct Walk<'a, R: BindingRuntime> {
    runtime: &'a mut R,
    launched: Vec<String>,
}

impl<'a, R: BindingRuntime> Walk<'a, R> {
    fn start(runtime: &'a mut R) -> Result<Self, String> {
        runtime.health()?;
        Ok(Self {
            runtime,
            launched: Vec::new(),
        })
    }

    fn launch(&mut self, identity: &str) -> Result<(Instance, HostBinding), String> {
        let instance = self.runtime.launch(identity, Fixture::BindOwned)?;
        if instance.id.is_empty() {
            return Err(format!("launch of {identity} named no instance"));
        }
        let record = self.runtime.host_record(&instance.handle)?;
        if record.identity.is_empty() || record.session.is_empty() || record.instance.is_empty() {
            return Err(format!(
                "host record for {} named no identity, session or instance",
                instance.handle.as_str()
            ));
        }
        if record.owned_root.is_empty() {
            return Err(format!(
                "host record for {} named no owned root",
                instance.handle.as_str()
            ));
        }
        self.launched.push(instance.id.clone());
        Ok((instance, record))
    }

    fn mint(&mut self, handle: &Handle, record: &HostBinding) -> Result<Grant, String> {
        let resource = owned_resource(&record.identity, &record.session, &record.instance);
        reject_public_as_binding(&resource)?;
        crate::walk::walk_owned(&record.identity, &resource, Some(&record.owned_root))
            .map_err(|refuse| refuse.reason().to_owned())?;
        let grant = self.runtime.mint_grant(handle, &resource)?;
        require_grant_id(&grant.id)?;
        if grant.handle != *handle {
            return Err(format!(
                "minted grant {} bound to handle {}, not {}",
                grant.id,
                grant.handle.as_str(),
                handle.as_str()
            ));
        }
        reject_public_as_binding(&grant.resource)?;
        Ok(grant)
    }

    fn assert_live_binding(&mut self, grant: &Grant, record: &HostBinding) -> Result<(), String> {
        require_grant_id(&grant.id)?;
        let grants = self.runtime.live_grants()?;
        let found = grants.iter().find(|live| live.request_id == grant.id);
        let Some(live) = found else {
            return Err(format!(
                "live-grant view missing grant {}; seen {:?}",
                grant.id,
                grants
                    .iter()
                    .map(|g| g.request_id.as_str())
                    .collect::<Vec<_>>()
            ));
        };
        require_grant_id(&live.request_id)?;
        if live.identity != record.identity
            || live.session != record.session
            || live.instance != record.instance
            || live.owned_root != record.owned_root
        {
            return Err(format!(
                "live grant {} bound to {}/{}/{} {}, expected {}/{}/{} {}",
                live.request_id,
                live.identity,
                live.session,
                live.instance,
                live.owned_root,
                record.identity,
                record.session,
                record.instance,
                record.owned_root
            ));
        }
        reject_public_as_binding(&live.resource)?;
        Ok(())
    }

    fn use_ok(
        &mut self,
        handle: &Handle,
        grant: &Grant,
        record: &HostBinding,
        path: &str,
    ) -> Result<(), String> {
        reject_public_as_binding(path)?;
        crate::walk::walk_owned(&record.identity, path, Some(&record.owned_root))
            .map_err(|refuse| refuse.reason().to_owned())?;
        let outcome = self.runtime.use_grant(handle, grant, path)?;
        require_runtime_allow(outcome)?;
        Ok(())
    }

    fn use_refused(
        &mut self,
        handle: &Handle,
        grant: &Grant,
        path: &str,
        expected: crate::contract::Refusal,
    ) -> Result<(), String> {
        let outcome = self.runtime.use_grant(handle, grant, path)?;
        require_runtime_refusal(outcome, expected)?;
        Ok(())
    }

    fn finish(self, evidence: String) -> Outcome {
        for id in self.launched.iter().rev() {
            let _ = self.runtime.stop(id, CLEANUP_REASON);
        }
        Ok(evidence)
    }

    fn fail(self, reason: String) -> Outcome {
        for id in self.launched.iter().rev() {
            let _ = self.runtime.stop(id, CLEANUP_REASON);
        }
        Err(reason)
    }
}

fn run<R: BindingRuntime>(
    runtime: &mut R,
    body: impl FnOnce(&mut Walk<'_, R>) -> Outcome,
) -> Outcome {
    let mut walk = Walk::start(runtime)?;
    match body(&mut walk) {
        Ok(evidence) => walk.finish(evidence),
        Err(reason) => walk.fail(reason),
    }
}

/// Identity journey: two principals, A's seed bytes come back through the
/// operator, B does not observe them.
pub fn identity_use<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let (a, a_host) = j.launch("agent-a")?;
        let (b, b_host) = j.launch("agent-b")?;
        if a_host.identity == b_host.identity
            || a_host.session == b_host.session
            || a_host.instance == b_host.instance
            || a.handle == b.handle
        {
            return Err(
                "identity journey needs two principals, two sessions and two instances".to_owned(),
            );
        }
        j.runtime.seed(&a.handle, OWNED_NOTES, A_SEED)?;
        let grant = j.mint(&a.handle, &a_host)?;
        j.assert_live_binding(&grant, &a_host)?;
        let path = owned_resource(&a_host.identity, &a_host.session, &a_host.instance);
        j.use_ok(&a.handle, &grant, &a_host, &path)?;
        let got = j.runtime.read_bytes(&a.handle, OWNED_NOTES)?;
        if got != A_SEED {
            return Err(format!(
                "identity journey expected A's seed bytes, got {} bytes",
                got.len()
            ));
        }
        let other = j.runtime.read_bytes(&b.handle, OWNED_NOTES)?;
        if other == A_SEED {
            return Err("identity journey: B observed A's owned bytes".to_owned());
        }
        Ok(format!(
            "A5-ID-POS: grant {} used by {} on {}; bytes from A's root",
            grant.id, a_host.identity, a_host.owned_root
        ))
    })
}

pub fn identity_replay<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let (a, a_host) = j.launch("agent-a")?;
        let (b, b_host) = j.launch("agent-b")?;
        let grant = j.mint(&a.handle, &a_host)?;
        j.assert_live_binding(&grant, &a_host)?;
        let path = owned_resource(&a_host.identity, &a_host.session, &a_host.instance);
        j.use_refused(&b.handle, &grant, &path, IDENTITY_REFUSAL)?;
        j.assert_live_binding(&grant, &a_host)?;
        Ok(format!(
            "A5-ID-REPLAY: grant {} of {} refused for {}",
            grant.id, a_host.identity, b_host.identity
        ))
    })
}

/// Session journey: the host record names the session; that session uses the
/// grant. One principal, unlike the identity row.
pub fn session_use<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let (a, a_host) = j.launch("agent-a")?;
        if a_host.session.is_empty() {
            return Err("session journey needs a session id on the host record".to_owned());
        }
        let grant = j.mint(&a.handle, &a_host)?;
        j.assert_live_binding(&grant, &a_host)?;
        if a_host.session != grant_session_from_live(j, &grant)? {
            return Err(format!(
                "session journey: live grant session is not host record {}",
                a_host.session
            ));
        }
        let path = owned_resource(&a_host.identity, &a_host.session, &a_host.instance);
        j.use_ok(&a.handle, &grant, &a_host, &path)?;
        Ok(format!(
            "A5-SESS-POS: grant {} used in host session {}",
            grant.id, a_host.session
        ))
    })
}

fn grant_session_from_live<R: BindingRuntime>(
    walk: &mut Walk<'_, R>,
    grant: &Grant,
) -> Result<String, String> {
    let grants = walk.runtime.live_grants()?;
    grants
        .into_iter()
        .find(|live| live.request_id == grant.id)
        .map(|live| live.session)
        .ok_or_else(|| format!("live-grant view missing grant {}", grant.id))
}

pub fn session_ended<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let (a, a_host) = j.launch("agent-a")?;
        let grant = j.mint(&a.handle, &a_host)?;
        j.assert_live_binding(&grant, &a_host)?;
        j.runtime.end_session(&a.handle)?;
        let record = j.runtime.request_record(&grant.id)?;
        if record.settled_by.as_deref() != Some("runtime") {
            return Err(format!(
                "A5-SESS-END requires settled_by=runtime, got {:?}",
                record.settled_by
            ));
        }
        let path = owned_resource(&a_host.identity, &a_host.session, &a_host.instance);
        j.use_refused(&a.handle, &grant, &path, SESSION_REFUSAL)?;
        let leftover = j
            .runtime
            .live_grants()?
            .into_iter()
            .any(|live| live.request_id == grant.id);
        if leftover {
            return Err(format!(
                "live-grant view still lists {} after session {} ended",
                grant.id, a_host.session
            ));
        }
        Ok(format!(
            "A5-SESS-END: grant {} settled_by=runtime after session {} ended",
            grant.id, a_host.session
        ))
    })
}

/// Instance journey: two activations of one capsule; the bound instance uses
/// the grant.
pub fn instance_use<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let (x, x_host) = j.launch("agent-a")?;
        let (y, y_host) = j.launch("agent-a")?;
        if x_host.identity != y_host.identity {
            return Err("instance journey needs two activations of one identity".to_owned());
        }
        if x_host.instance == y_host.instance || x.handle == y.handle {
            return Err("instance journey needs two activations with different ids".to_owned());
        }
        let grant = j.mint(&x.handle, &x_host)?;
        j.assert_live_binding(&grant, &x_host)?;
        let path = owned_resource(&x_host.identity, &x_host.session, &x_host.instance);
        j.use_ok(&x.handle, &grant, &x_host, &path)?;
        Ok(format!(
            "A5-INST-POS: grant {} used by instance {} (sibling activation {})",
            grant.id, x_host.instance, y_host.instance
        ))
    })
}

pub fn instance_sibling<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let (x, x_host) = j.launch("agent-a")?;
        let (y, y_host) = j.launch("agent-a")?;
        if x_host.identity != y_host.identity {
            return Err("sibling instances must share one agent identity".to_owned());
        }
        if x_host.instance == y_host.instance || x_host.session == y_host.session {
            return Err("sibling instances must have different id and session".to_owned());
        }
        let grant = j.mint(&x.handle, &x_host)?;
        j.assert_live_binding(&grant, &x_host)?;
        let path = owned_resource(&x_host.identity, &x_host.session, &x_host.instance);
        j.use_refused(&y.handle, &grant, &path, INSTANCE_REFUSAL)?;
        let prefix = format!("{}-evil/notes", x_host.owned_root);
        let prefix_outcome = j.runtime.use_grant(&x.handle, &grant, &prefix)?;
        require_any_runtime_refusal(prefix_outcome, &[PREFIX_REFUSAL, OWNED_ROOT_REFUSAL])?;
        j.assert_live_binding(&grant, &x_host)?;
        Ok(format!(
            "A5-INST-SIB: grant {} of {} refused for sibling {} and prefix {}",
            grant.id, x_host.instance, y_host.instance, prefix
        ))
    })
}

/// Storage journey: child allowed; `..`, symlink-shaped, and prefix collision
/// refused; A's object unchanged.
pub fn storage_use<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let (a, a_host) = j.launch("agent-a")?;
        j.runtime.seed(&a.handle, OWNED_NOTES, A_SEED)?;
        let grant = j.mint(&a.handle, &a_host)?;
        j.assert_live_binding(&grant, &a_host)?;
        let child = owned_resource(&a_host.identity, &a_host.session, &a_host.instance);
        j.use_ok(&a.handle, &grant, &a_host, &child)?;
        let dotdot = format!("{}/../notes", a_host.owned_root);
        j.use_refused(&a.handle, &grant, &dotdot, HOST_PATH_REFUSAL)?;
        let symlink = format!("{}/notes/link@x", a_host.owned_root);
        j.use_refused(&a.handle, &grant, &symlink, SYMLINK_REFUSAL)?;
        let prefix = format!("{}-evil/notes", a_host.owned_root);
        j.use_refused(&a.handle, &grant, &prefix, PREFIX_REFUSAL)?;
        let got = j.runtime.read_bytes(&a.handle, OWNED_NOTES)?;
        if got != A_SEED {
            return Err("storage journey: A's object changed after the refused walks".to_owned());
        }
        Ok(format!(
            "A5-STOR-POS: grant {} child ok; .. / symlink / prefix refused on {}",
            grant.id, a_host.owned_root
        ))
    })
}

pub fn storage_other_root<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let (a, a_host) = j.launch("agent-a")?;
        let (_b, b_host) = j.launch("agent-a")?;
        j.runtime.seed(&a.handle, OWNED_NOTES, A_SEED)?;
        let grant = j.mint(&a.handle, &a_host)?;
        j.assert_live_binding(&grant, &a_host)?;
        let other = owned_resource(&b_host.identity, &b_host.session, &b_host.instance);
        j.use_refused(&a.handle, &grant, &other, OWNED_ROOT_REFUSAL)?;
        let got = j.runtime.read_bytes(&a.handle, OWNED_NOTES)?;
        if got != A_SEED {
            return Err("storage other-root: A's object changed".to_owned());
        }
        Ok(format!(
            "A5-STOR-OTHER: grant {} of {} refused for {}; A's object unchanged",
            grant.id, a_host.owned_root, other
        ))
    })
}

/// Public row: actually read Public. Do not forge a public-claim grant. A
/// Public mint, if attempted, is not binding.
pub fn public_not_binding<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let read = j.runtime.public_read(PUBLIC_RESOURCE)?;
        if !crate::contract::is_public_resource(&read.resource) {
            return Err(format!(
                "public row observed {}, which is not a Public path",
                read.resource
            ));
        }
        if read.bound {
            return Err("public storage read counted as binding".to_owned());
        }
        if read.bytes.is_empty() {
            return Err("public row did not read Public bytes from the operator".to_owned());
        }
        let (a, _a_host) = j.launch("agent-a")?;
        match j.runtime.mint_grant(&a.handle, PUBLIC_RESOURCE) {
            Ok(grant) => {
                return Err(format!(
                    "Public mint {} must not count as a bound grant",
                    grant.id
                ));
            }
            Err(reason) => {
                if reason != PUBLIC_REASON {
                    return Err(format!(
                        "Public mint must be refused as {}; got {reason}",
                        PUBLIC_REASON
                    ));
                }
            }
        }
        Ok(format!(
            "A5-PUB: Public read of {} is not binding; mint refused",
            read.resource
        ))
    })
}
