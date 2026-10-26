//! Reference double used only for the harness's own tests. The honest double
//! passes every journey. It is not the Runtime and counts toward no M1 check.

use std::collections::HashMap;

use a5_binding_harness::contract::{
    owned_root, Actor, BindingRuntime, EvidenceKind, Fixture, Grant, Handle, HostBinding, Instance,
    LiveGrant, PublicRead, RequestRecord, RuntimeEvidence, UseOutcome, A_SEED, PUBLIC_REASON,
    PUBLIC_RESOURCE,
};
use a5_binding_harness::walk::{walk_owned, WalkRefuse};

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
    pub empty_grant_id: bool,
    pub omit_settled_by: bool,
}

#[derive(Clone)]
struct Rec {
    identity: String,
    session: String,
    instance: String,
    owned_root: String,
    session_live: bool,
}

#[derive(Clone)]
struct StoredGrant {
    grant: Grant,
    identity: String,
    session: String,
    instance: String,
    owned_root: String,
    settled_by: Option<String>,
}

pub struct Double {
    faults: Faults,
    next: u64,
    instances: u64,
    agents: HashMap<String, Rec>,
    grants: HashMap<String, StoredGrant>,
    objects: HashMap<(String, String), Vec<u8>>,
    public_bytes: Vec<u8>,
}

impl Double {
    pub fn new(faults: Faults) -> Self {
        Self {
            faults,
            next: 0,
            instances: 0,
            agents: HashMap::new(),
            grants: HashMap::new(),
            objects: HashMap::new(),
            public_bytes: Vec::new(),
        }
    }

    fn next_id(&mut self, prefix: &str) -> String {
        if prefix == "inst" {
            self.instances += 1;
            return match self.instances {
                1 => "instance-1".to_owned(),
                2 => "instance-1-evil".to_owned(),
                n => format!("instance-{n}"),
            };
        }
        self.next += 1;
        format!("{prefix}-{}", self.next)
    }

    #[allow(clippy::too_many_arguments)]
    fn runtime_evidence(
        &self,
        kind: EvidenceKind,
        reason: &str,
        code: Option<&str>,
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
            code.map(str::to_owned),
            refused_by,
            resource.to_owned(),
        )
    }

    fn rec(&self, handle: &Handle) -> Result<&Rec, String> {
        self.agents
            .get(handle.as_str())
            .ok_or_else(|| format!("unknown handle {}", handle.as_str()))
    }
}

impl BindingRuntime for Double {
    fn health(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn launch(&mut self, identity: &str, _fixture: Fixture) -> Result<Instance, String> {
        let instance_id = self.next_id("inst");
        let handle_id = self.next_id("handle");
        let session = if self.faults.shared_session && !self.agents.is_empty() {
            self.agents.values().next().unwrap().session.clone()
        } else {
            self.next_id("sess")
        };
        let owned = owned_root(identity, &session, &instance_id);
        let handle = Handle::new(handle_id.clone())?;
        self.agents.insert(
            handle_id,
            Rec {
                identity: identity.to_owned(),
                session,
                instance: instance_id.clone(),
                owned_root: owned,
                session_live: true,
            },
        );
        Ok(Instance {
            id: instance_id,
            handle,
        })
    }

    fn host_record(&mut self, handle: &Handle) -> Result<HostBinding, String> {
        let rec = self.rec(handle)?;
        Ok(HostBinding {
            identity: rec.identity.clone(),
            session: rec.session.clone(),
            instance: rec.instance.clone(),
            owned_root: rec.owned_root.clone(),
        })
    }

    fn stop(&mut self, id: &str, _reason: &str) -> Result<(), String> {
        self.agents.retain(|_, rec| rec.instance != id);
        Ok(())
    }

    fn end_session(&mut self, handle: &Handle) -> Result<(), String> {
        let session = self.rec(handle)?.session.clone();
        for rec in self.agents.values_mut() {
            if rec.session == session {
                rec.session_live = false;
            }
        }
        if !self.faults.omit_settled_by {
            for stored in self.grants.values_mut() {
                if stored.session == session {
                    stored.settled_by = Some("runtime".to_owned());
                }
            }
        }
        Ok(())
    }

    fn mint_grant(&mut self, handle: &Handle, resource: &str) -> Result<Grant, String> {
        if resource == PUBLIC_RESOURCE
            || resource.starts_with("localhost://Public/")
            || resource.starts_with("Public/")
        {
            return Err(PUBLIC_REASON.to_owned());
        }
        let rec = self.rec(handle)?.clone();
        let id = if self.faults.empty_grant_id {
            String::new()
        } else {
            self.next_id("grant")
        };
        if !id.is_empty() {
            a5_binding_harness::contract::require_grant_id(&id)?;
        }
        let grant = Grant {
            id: id.clone(),
            handle: handle.clone(),
            resource: resource.to_owned(),
        };
        self.grants.insert(
            id,
            StoredGrant {
                grant: grant.clone(),
                identity: rec.identity,
                session: rec.session,
                instance: rec.instance,
                owned_root: rec.owned_root,
                settled_by: None,
            },
        );
        Ok(grant)
    }

    fn use_grant(
        &mut self,
        handle: &Handle,
        grant: &Grant,
        path: &str,
    ) -> Result<UseOutcome, String> {
        if self.faults.fake_refusal {
            return Ok(UseOutcome::Refused {
                evidence: self.runtime_evidence(
                    EvidenceKind::Refused,
                    "denied",
                    None,
                    path,
                    Actor::Fixture,
                    None,
                    None,
                ),
            });
        }
        let caller = self.rec(handle)?.clone();
        let stored = self.grants.get(&grant.id).cloned();
        if let Some(stored) = &stored {
            if let Err(refuse) = walk_owned(&stored.identity, path, Some(&stored.owned_root)) {
                if refuse == WalkRefuse::PublicRead && self.faults.public_as_binding {
                    return Ok(UseOutcome::Allowed {
                        evidence: self.runtime_evidence(
                            EvidenceKind::Allowed,
                            "ok",
                            None,
                            path,
                            Actor::Runtime,
                            Some(200),
                            Some(grant.id.clone()),
                        ),
                    });
                }
                if refuse == WalkRefuse::OutsideRoot && self.faults.other_root_allowed {
                    // fall through to allow
                } else {
                    return Ok(UseOutcome::Refused {
                        evidence: self.runtime_evidence(
                            EvidenceKind::Refused,
                            refuse.reason(),
                            Some(refuse.code()),
                            path,
                            Actor::Runtime,
                            Some(403),
                            Some(grant.id.clone()),
                        ),
                    });
                }
            }
        } else if path.starts_with("localhost://Public/") || path.starts_with("Public/") {
            return Ok(UseOutcome::Refused {
                evidence: self.runtime_evidence(
                    EvidenceKind::Refused,
                    PUBLIC_REASON,
                    Some("public"),
                    path,
                    Actor::Runtime,
                    Some(403),
                    Some(grant.id.clone()),
                ),
            });
        }
        if stored.as_ref().map(|g| g.identity.as_str()) != Some(caller.identity.as_str())
            && !self.faults.identity_replay_allowed
        {
            return Ok(UseOutcome::Refused {
                evidence: self.runtime_evidence(
                    EvidenceKind::Refused,
                    "identity does not match the grant",
                    Some("identity"),
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
                    Some("instance"),
                    path,
                    Actor::Runtime,
                    Some(403),
                    Some(grant.id.clone()),
                ),
            });
        }
        let session_live = caller.session_live;
        if (!session_live
            || stored.as_ref().map(|g| g.session.as_str()) != Some(caller.session.as_str()))
            && !self.faults.session_survives_end
        {
            return Ok(UseOutcome::Refused {
                evidence: self.runtime_evidence(
                    EvidenceKind::Refused,
                    "session does not match the grant",
                    Some("session"),
                    path,
                    Actor::Runtime,
                    Some(403),
                    Some(grant.id.clone()),
                ),
            });
        }
        Ok(UseOutcome::Allowed {
            evidence: self.runtime_evidence(
                EvidenceKind::Allowed,
                "ok",
                None,
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
            .filter(|stored| {
                self.faults.session_survives_end
                    || self
                        .agents
                        .values()
                        .any(|rec| rec.session == stored.session && rec.session_live)
            })
            .map(|stored| LiveGrant {
                request_id: stored.grant.id.clone(),
                identity: stored.identity.clone(),
                session: stored.session.clone(),
                instance: stored.instance.clone(),
                resource: stored.grant.resource.clone(),
                owned_root: stored.owned_root.clone(),
            })
            .collect())
    }

    fn request_record(&mut self, request_id: &str) -> Result<RequestRecord, String> {
        a5_binding_harness::contract::require_grant_id(request_id)?;
        let stored = self
            .grants
            .get(request_id)
            .ok_or_else(|| format!("unknown request {request_id}"))?;
        Ok(RequestRecord {
            request_id: request_id.to_owned(),
            status: if stored.settled_by.is_some() {
                "denied".to_owned()
            } else {
                "granted".to_owned()
            },
            settled_by: stored.settled_by.clone(),
        })
    }

    fn public_read(&mut self, path: &str) -> Result<PublicRead, String> {
        let resource = if path.is_empty() {
            PUBLIC_RESOURCE.to_owned()
        } else {
            path.to_owned()
        };
        if self.public_bytes.is_empty() {
            self.public_bytes = b"a5-binding public fixture bytes\n".to_vec();
        }
        Ok(PublicRead {
            resource,
            bytes: self.public_bytes.clone(),
            bound: self.faults.public_as_binding,
        })
    }

    fn seed(&mut self, handle: &Handle, rel: &str, bytes: &[u8]) -> Result<(), String> {
        self.rec(handle)?;
        self.objects
            .insert((handle.as_str().to_owned(), rel.to_owned()), bytes.to_vec());
        Ok(())
    }

    fn read_bytes(&mut self, handle: &Handle, rel: &str) -> Result<Vec<u8>, String> {
        self.rec(handle)?;
        Ok(self
            .objects
            .get(&(handle.as_str().to_owned(), rel.to_owned()))
            .cloned()
            .unwrap_or_default())
    }
}

#[allow(dead_code)]
pub fn seed_bytes() -> &'static [u8] {
    A_SEED
}
