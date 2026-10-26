//! The nine A5 journeys, written once against [`BindingRuntime`].
//!
//! These functions prove the harness. They count toward no M1 check until
//! [`crate::acceptance`] runs them against a live operator.

use crate::contract::{
    owned_resource, reject_public_as_binding, require_runtime_allow, require_runtime_refusal,
    BindingRuntime, Caller, Fixture, Grant, Instance, CLEANUP_REASON, IDENTITY_REASON,
    INSTANCE_REASON, PUBLIC_REASON, PUBLIC_RESOURCE, ROOT_REASON, SESSION_REASON,
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

    fn launch(&mut self, identity: &str) -> Result<Instance, String> {
        let instance = self.runtime.launch(identity, Fixture::BindOwned)?;
        if instance.identity != identity {
            return Err(format!(
                "launch of {identity} returned identity {}",
                instance.identity
            ));
        }
        if instance.session.is_empty() || instance.id.is_empty() {
            return Err(format!("launch of {identity} named no session or instance"));
        }
        self.launched.push(instance.id.clone());
        Ok(instance)
    }

    fn mint(&mut self, instance: &Instance) -> Result<Grant, String> {
        let resource = owned_resource(&instance.identity, &instance.session, &instance.id);
        reject_public_as_binding(&resource)?;
        let grant = self.runtime.mint_grant(instance, &resource)?;
        if grant.identity != instance.identity
            || grant.session != instance.session
            || grant.instance != instance.id
        {
            return Err(format!(
                "minted grant {} bound to {}/{}/{}, not {}/{}/{}",
                grant.id,
                grant.identity,
                grant.session,
                grant.instance,
                instance.identity,
                instance.session,
                instance.id
            ));
        }
        reject_public_as_binding(&grant.resource)?;
        reject_public_as_binding(&grant.owned_root)?;
        Ok(grant)
    }

    fn assert_live_binding(&mut self, grant: &Grant) -> Result<(), String> {
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
        if live.identity != grant.identity
            || live.session != grant.session
            || live.instance != grant.instance
            || live.owned_root != grant.owned_root
        {
            return Err(format!(
                "live grant {} bound to {}/{}/{} {}, expected {}/{}/{} {}",
                live.request_id,
                live.identity,
                live.session,
                live.instance,
                live.owned_root,
                grant.identity,
                grant.session,
                grant.instance,
                grant.owned_root
            ));
        }
        reject_public_as_binding(&live.resource)?;
        Ok(())
    }

    fn use_ok(&mut self, instance: &Instance, grant: &Grant, path: &str) -> Result<(), String> {
        reject_public_as_binding(path)?;
        let outcome = self
            .runtime
            .use_grant(&Caller::from_instance(instance), grant, path)?;
        require_runtime_allow(outcome)?;
        Ok(())
    }

    fn use_refused(
        &mut self,
        caller: &Instance,
        grant: &Grant,
        path: &str,
        expected: &str,
    ) -> Result<(), String> {
        let outcome = self
            .runtime
            .use_grant(&Caller::from_instance(caller), grant, path)?;
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

pub fn identity_use<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let a = j.launch("agent-a")?;
        let b = j.launch("agent-b")?;
        if a.identity == b.identity || a.session == b.session || a.id == b.id {
            return Err(
                "identity journey needs two principals, two sessions and two instances".to_owned(),
            );
        }
        let grant = j.mint(&a)?;
        j.assert_live_binding(&grant)?;
        let path = owned_resource(&a.identity, &a.session, &a.id);
        j.use_ok(&a, &grant, &path)?;
        Ok(format!(
            "A5-ID-POS: grant {} used by {} on {}",
            grant.id, a.identity, grant.owned_root
        ))
    })
}

pub fn identity_replay<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let a = j.launch("agent-a")?;
        let b = j.launch("agent-b")?;
        let grant = j.mint(&a)?;
        j.assert_live_binding(&grant)?;
        let path = owned_resource(&a.identity, &a.session, &a.id);
        j.use_refused(&b, &grant, &path, IDENTITY_REASON)?;
        j.assert_live_binding(&grant)?;
        Ok(format!(
            "A5-ID-REPLAY: grant {} of {} refused for {}",
            grant.id, a.identity, b.identity
        ))
    })
}

pub fn session_use<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let a = j.launch("agent-a")?;
        let grant = j.mint(&a)?;
        j.assert_live_binding(&grant)?;
        let path = owned_resource(&a.identity, &a.session, &a.id);
        j.use_ok(&a, &grant, &path)?;
        Ok(format!(
            "A5-SESS-POS: grant {} used in session {}",
            grant.id, a.session
        ))
    })
}

pub fn session_ended<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let a = j.launch("agent-a")?;
        let grant = j.mint(&a)?;
        j.assert_live_binding(&grant)?;
        j.runtime.end_session(&a.session)?;
        let path = owned_resource(&a.identity, &a.session, &a.id);
        j.use_refused(&a, &grant, &path, SESSION_REASON)?;
        let leftover = j
            .runtime
            .live_grants()?
            .into_iter()
            .any(|live| live.request_id == grant.id);
        if leftover {
            return Err(format!(
                "live-grant view still lists {} after session {} ended",
                grant.id, a.session
            ));
        }
        Ok(format!(
            "A5-SESS-END: grant {} refused after session {} ended",
            grant.id, a.session
        ))
    })
}

pub fn instance_use<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let a = j.launch("agent-a")?;
        let grant = j.mint(&a)?;
        j.assert_live_binding(&grant)?;
        let path = owned_resource(&a.identity, &a.session, &a.id);
        j.use_ok(&a, &grant, &path)?;
        Ok(format!(
            "A5-INST-POS: grant {} used by instance {}",
            grant.id, a.id
        ))
    })
}

pub fn instance_sibling<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let x = j.launch("agent-a")?;
        let y = j.launch("agent-a")?;
        if x.identity != y.identity {
            return Err("sibling instances must share one agent identity".to_owned());
        }
        if x.id == y.id || x.session == y.session {
            return Err("sibling instances must have different id and session".to_owned());
        }
        let grant = j.mint(&x)?;
        j.assert_live_binding(&grant)?;
        let path = owned_resource(&x.identity, &x.session, &x.id);
        j.use_refused(&y, &grant, &path, INSTANCE_REASON)?;
        j.assert_live_binding(&grant)?;
        Ok(format!(
            "A5-INST-SIB: grant {} of {} refused for sibling {}",
            grant.id, x.id, y.id
        ))
    })
}

pub fn storage_use<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let a = j.launch("agent-a")?;
        let grant = j.mint(&a)?;
        j.assert_live_binding(&grant)?;
        let path = owned_resource(&a.identity, &a.session, &a.id);
        j.use_ok(&a, &grant, &path)?;
        Ok(format!(
            "A5-STOR-POS: grant {} used on {}",
            grant.id, grant.owned_root
        ))
    })
}

pub fn storage_other_root<R: BindingRuntime>(runtime: &mut R) -> Outcome {
    run(runtime, |j| {
        let a = j.launch("agent-a")?;
        let b = j.launch("agent-a")?;
        let grant = j.mint(&a)?;
        j.assert_live_binding(&grant)?;
        let other = owned_resource(&b.identity, &b.session, &b.id);
        j.use_refused(&a, &grant, &other, ROOT_REASON)?;
        Ok(format!(
            "A5-STOR-OTHER: grant {} of {} refused for {}",
            grant.id, grant.owned_root, other
        ))
    })
}

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
        let a = j.launch("agent-a")?;
        let claim = Grant {
            id: "public-claim".to_owned(),
            identity: a.identity.clone(),
            session: a.session.clone(),
            instance: a.id.clone(),
            owned_root: "Public/a5-binding".to_owned(),
            resource: PUBLIC_RESOURCE.to_owned(),
        };
        j.use_refused(&a, &claim, PUBLIC_RESOURCE, PUBLIC_REASON)?;
        Ok(format!(
            "A5-PUB: Public bind refused; public read of {} is not binding",
            read.resource
        ))
    })
}
