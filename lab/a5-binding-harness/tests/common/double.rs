//! Reference double used only for the harness's own tests. The honest double
//! passes every journey. It is not the Runtime and counts toward no M1 check.

use std::collections::HashMap;

use a5_binding_harness::contract::{
    owned_resource, owned_root, Actor, BindingRuntime, Caller, EvidenceKind, Fixture, Grant,
    Instance, LiveGrant, PublicRead, RuntimeEvidence, UseOutcome, PUBLIC_REASON, PUBLIC_RESOURCE,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct Faults {
    pub fake_refusal: bool,
    pub public_as_binding: bool,
    pub identity_replay_allowed: bool,
    pub session_survives_end: bool,
    pub sibling_allowed: bool,
    pub other_root_allowed: bool,
    pub shared_session: bool,
    pub blind_grant_view: bool,
}

#[derive(Clone)]
struct Rec {
    instance: Instance,
    session_live: bool,
}

pub struct Double {
    faults: Faults,
    next: u64,
    agents: HashMap<String, Rec>,
    grants: HashMap<String, Grant>,
}

impl Double {
    pub fn new(faults: Faults) -> Self {
        Self {
            faults,
            next: 0,
            agents: HashMap::new(),
            grants: HashMap::new(),
        }
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.next += 1;
        format!("{prefix}-{}", self.next)
    }

    fn runtime_evidence(
        &self,
        kind: EvidenceKind,
        reason: &str,
        resource: &str,
        refused_by: Actor,
        status: Option<u16>,
        request_id: Option<String>,
    ) -> RuntimeEvidence {
        RuntimeEvidence::from_double(
            kind,
            status,
            request_id,
            reason.to_owned(),
            refused_by,
            resource.to_owned(),
        )
    }
}

impl BindingRuntime for Double {
    fn health(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn launch(&mut self, identity: &str, _fixture: Fixture) -> Result<Instance, String> {
        let id = self.next_id("inst");
        let session = if self.faults.shared_session && !self.agents.is_empty() {
            self.agents.values().next().unwrap().instance.session.clone()
        } else {
            self.next_id("sess")
        };
        let instance = Instance {
            id: id.clone(),
            identity: identity.to_owned(),
            session,
        };
        self.agents.insert(
            id,
            Rec {
                instance: instance.clone(),
                session_live: true,
            },
        );
        Ok(instance)
    }

    fn stop(&mut self, id: &str, _reason: &str) -> Result<(), String> {
        self.agents.remove(id);
        Ok(())
    }

    fn end_session(&mut self, session: &str) -> Result<(), String> {
        for rec in self.agents.values_mut() {
            if rec.instance.session == session {
                rec.session_live = false;
            }
        }
        if !self.faults.session_survives_end {
            self.grants.retain(|_, grant| grant.session != session);
        }
        Ok(())
    }

    fn mint_grant(&mut self, instance: &Instance, resource: &str) -> Result<Grant, String> {
        let id = self.next_id("grant");
        let grant = Grant {
            id: id.clone(),
            identity: instance.identity.clone(),
            session: instance.session.clone(),
            instance: instance.id.clone(),
            owned_root: owned_root(&instance.identity, &instance.session, &instance.id),
            resource: resource.to_owned(),
        };
        self.grants.insert(id, grant.clone());
        Ok(grant)
    }

    fn use_grant(
        &mut self,
        caller: &Caller,
        grant: &Grant,
        path: &str,
    ) -> Result<UseOutcome, String> {
        if self.faults.fake_refusal {
            return Ok(UseOutcome::Refused {
                evidence: self.runtime_evidence(
                    EvidenceKind::Refused,
                    "denied",
                    path,
                    Actor::Fixture,
                    None,
                    None,
                ),
            });
        }
        if path.starts_with("localhost://Public/") || path.starts_with("Public/") {
            if self.faults.public_as_binding {
                return Ok(UseOutcome::Allowed {
                    evidence: self.runtime_evidence(
                        EvidenceKind::Allowed,
                        "ok",
                        path,
                        Actor::Runtime,
                        Some(200),
                        Some(grant.id.clone()),
                    ),
                });
            }
            return Ok(UseOutcome::Refused {
                evidence: self.runtime_evidence(
                    EvidenceKind::Refused,
                    PUBLIC_REASON,
                    path,
                    Actor::Runtime,
                    Some(403),
                    Some(grant.id.clone()),
                ),
            });
        }
        let stored = self.grants.get(&grant.id).cloned();
        let live = self.agents.get(&caller.instance).cloned();
        if stored.as_ref().map(|g| g.identity.as_str()) != Some(caller.identity.as_str())
            && !self.faults.identity_replay_allowed
        {
            return Ok(UseOutcome::Refused {
                evidence: self.runtime_evidence(
                    EvidenceKind::Refused,
                    "identity does not match the grant",
                    path,
                    Actor::Runtime,
                    Some(403),
                    Some(grant.id.clone()),
                ),
            });
        }
        if stored.as_ref().map(|g| g.instance.as_str()) != Some(caller.instance.as_str())
            && !self.faults.sibling_allowed
        {
            return Ok(UseOutcome::Refused {
                evidence: self.runtime_evidence(
                    EvidenceKind::Refused,
                    "instance does not match the grant",
                    path,
                    Actor::Runtime,
                    Some(403),
                    Some(grant.id.clone()),
                ),
            });
        }
        let session_live = live.as_ref().is_some_and(|rec| rec.session_live);
        if (!session_live
            || stored.as_ref().map(|g| g.session.as_str()) != Some(caller.session.as_str()))
            && !self.faults.session_survives_end
        {
            return Ok(UseOutcome::Refused {
                evidence: self.runtime_evidence(
                    EvidenceKind::Refused,
                    "session does not match the grant",
                    path,
                    Actor::Runtime,
                    Some(403),
                    Some(grant.id.clone()),
                ),
            });
        }
        if let Some(stored) = &stored {
            let expected = owned_resource(&stored.identity, &stored.session, &stored.instance);
            if path != expected && !self.faults.other_root_allowed {
                return Ok(UseOutcome::Refused {
                    evidence: self.runtime_evidence(
                        EvidenceKind::Refused,
                        "use path leaves the owned root",
                        path,
                        Actor::Runtime,
                        Some(403),
                        Some(grant.id.clone()),
                    ),
                });
            }
        }
        Ok(UseOutcome::Allowed {
            evidence: self.runtime_evidence(
                EvidenceKind::Allowed,
                "ok",
                path,
                Actor::Runtime,
                Some(200),
                Some(grant.id.clone()),
            ),
        })
    }

    fn live_grants(&mut self) -> Result<Vec<LiveGrant>, String> {
        if self.faults.blind_grant_view {
            return Ok(Vec::new());
        }
        Ok(self
            .grants
            .values()
            .map(|grant| LiveGrant {
                request_id: grant.id.clone(),
                identity: grant.identity.clone(),
                session: grant.session.clone(),
                instance: grant.instance.clone(),
                resource: grant.resource.clone(),
                owned_root: grant.owned_root.clone(),
            })
            .collect())
    }

    fn public_read(&mut self, path: &str) -> Result<PublicRead, String> {
        let resource = if path.is_empty() {
            PUBLIC_RESOURCE.to_owned()
        } else {
            path.to_owned()
        };
        Ok(PublicRead {
            resource,
            bytes: b"a5-binding public fixture bytes\n".to_vec(),
            bound: self.faults.public_as_binding,
        })
    }
}
