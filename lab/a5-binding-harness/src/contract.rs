//! The Runtime interface the journeys need, as SPEC.md states it.
//!
//! Refusal and allow both go through the checkers in this file. A fixture
//! that fakes a refusal, and a Public-storage read presented as binding, fail
//! here before any grade is built.

/// Owned notes file under the instance root named in SPEC.md section 4.
pub const OWNED_NOTES: &str = "notes";
/// Public path that must never count as A5 binding evidence.
pub const PUBLIC_RESOURCE: &str = "localhost://Public/a5-binding/notes";
pub const PUBLIC_REASON: &str = "public storage read does not bind";
pub const IDENTITY_REASON: &str = "identity";
pub const SESSION_REASON: &str = "session";
pub const INSTANCE_REASON: &str = "instance";
pub const ROOT_REASON: &str = "owned root";
pub const CLEANUP_REASON: &str = "harness cleanup: journey finished";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixture {
    BindOwned,
}

impl Fixture {
    pub fn name(self) -> &'static str {
        "bind-owned"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub id: String,
    pub identity: String,
    pub session: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    pub identity: String,
    pub session: String,
    pub instance: String,
}

impl Caller {
    pub fn from_instance(instance: &Instance) -> Caller {
        Caller {
            identity: instance.identity.clone(),
            session: instance.session.clone(),
            instance: instance.id.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub identity: String,
    pub session: String,
    pub instance: String,
    pub owned_root: String,
    pub resource: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveGrant {
    pub request_id: String,
    pub identity: String,
    pub session: String,
    pub instance: String,
    pub resource: String,
    pub owned_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRead {
    pub resource: String,
    pub bytes: Vec<u8>,
    /// True only if the speaker claims this read is A5 binding. The honest
    /// double and the operator adapter leave this false.
    pub bound: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    Runtime,
    Shell,
    Fixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceSource {
    LiveOperator,
    HarnessDouble,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Allowed,
    Refused,
}

/// Evidence of one use. `LiveOperator` is set only by [`crate::http`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeEvidence {
    source: EvidenceSource,
    pub kind: EvidenceKind,
    pub http_status: Option<u16>,
    pub request_id: Option<String>,
    pub reason: String,
    pub refused_by: Actor,
    pub resource: String,
    pub identity: Option<String>,
    pub session: Option<String>,
    pub instance: Option<String>,
}

impl RuntimeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_operator(
        kind: EvidenceKind,
        http_status: u16,
        request_id: Option<String>,
        reason: String,
        refused_by: Actor,
        resource: String,
        identity: Option<String>,
        session: Option<String>,
        instance: Option<String>,
    ) -> Self {
        Self {
            source: EvidenceSource::LiveOperator,
            kind,
            http_status: Some(http_status),
            request_id,
            reason,
            refused_by,
            resource,
            identity,
            session,
            instance,
        }
    }

    /// Harness-test evidence. `acceptance` never turns this into PASS.
    pub fn from_double(
        kind: EvidenceKind,
        http_status: Option<u16>,
        request_id: Option<String>,
        reason: String,
        refused_by: Actor,
        resource: String,
    ) -> Self {
        Self {
            source: EvidenceSource::HarnessDouble,
            kind,
            http_status,
            request_id,
            reason,
            refused_by,
            resource,
            identity: None,
            session: None,
            instance: None,
        }
    }

    pub fn is_live_operator(&self) -> bool {
        matches!(self.source, EvidenceSource::LiveOperator)
    }

    pub fn is_public_resource(&self) -> bool {
        is_public_resource(&self.resource)
    }

    pub fn claims_public_binding(&self) -> bool {
        self.is_public_resource() && self.kind == EvidenceKind::Allowed
    }

    pub fn summary(&self) -> String {
        format!(
            "{:?} {} by {:?} status={:?} request={:?}",
            self.kind, self.reason, self.refused_by, self.http_status, self.request_id
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UseOutcome {
    Allowed { evidence: RuntimeEvidence },
    Refused { evidence: RuntimeEvidence },
}

pub fn is_public_resource(resource: &str) -> bool {
    let rest = resource.strip_prefix("localhost://").unwrap_or(resource);
    rest == "Public" || rest.starts_with("Public/")
}

/// A Public path is never A5 binding evidence.
pub fn reject_public_as_binding(resource: &str) -> Result<(), String> {
    if is_public_resource(resource) {
        return Err(PUBLIC_REASON.to_owned());
    }
    Ok(())
}

pub fn owned_root(identity: &str, session: &str, instance: &str) -> String {
    format!("UsersAI/{identity}/{session}/{instance}")
}

pub fn owned_resource(identity: &str, session: &str, instance: &str) -> String {
    format!(
        "localhost://{}/{}",
        owned_root(identity, session, instance),
        OWNED_NOTES
    )
}

fn require_runtime_speaker(evidence: &RuntimeEvidence) -> Result<(), String> {
    if evidence.refused_by != Actor::Runtime {
        return Err("fixture refusal is not Runtime evidence".to_owned());
    }
    Ok(())
}

pub fn require_runtime_allow(outcome: UseOutcome) -> Result<RuntimeEvidence, String> {
    match outcome {
        UseOutcome::Allowed { evidence } => {
            reject_public_as_binding(&evidence.resource)?;
            if evidence.http_status.is_none() && evidence.request_id.is_none() {
                return Err("Runtime allow needs an operator HTTP status or request id".to_owned());
            }
            Ok(evidence)
        }
        UseOutcome::Refused { evidence } => {
            require_runtime_speaker(&evidence)?;
            Err(format!(
                "expected Runtime allow, got refusal: {}",
                evidence.reason
            ))
        }
    }
}

/// A refusal counts only when the Runtime spoke: `refused_by` is Runtime and
/// the operator (or the honest double standing in for it) left a status or
/// a request id. A fixture-local "denied" fails here.
pub fn require_runtime_refusal(
    outcome: UseOutcome,
    expected: &str,
) -> Result<RuntimeEvidence, String> {
    match outcome {
        UseOutcome::Refused { evidence } => {
            require_runtime_speaker(&evidence)?;
            if evidence.http_status.is_none() && evidence.request_id.is_none() {
                return Err(
                    "Runtime refusal needs an operator HTTP status or request id".to_owned(),
                );
            }
            if !evidence.reason.contains(expected) {
                return Err(format!(
                    "Runtime refusal reason {:?} does not contain {expected:?}",
                    evidence.reason
                ));
            }
            Ok(evidence)
        }
        UseOutcome::Allowed { evidence } => {
            if evidence.is_public_resource() {
                return Err(PUBLIC_REASON.to_owned());
            }
            Err(format!(
                "expected Runtime refusal containing {expected:?}, got allow of {}",
                evidence.resource
            ))
        }
    }
}

/// PASS is live-operator evidence that does not claim a Public read as binding.
pub fn grade_pass(evidence: RuntimeEvidence) -> Result<crate::Grade, String> {
    if !evidence.is_live_operator() {
        return Err("PASS requires live operator evidence".to_owned());
    }
    if evidence.claims_public_binding() {
        return Err(PUBLIC_REASON.to_owned());
    }
    Ok(crate::Grade::Pass(evidence.summary()))
}

/// Every call is made by the harness as the shell. Errors are reasons.
pub trait BindingRuntime {
    fn health(&mut self) -> Result<(), String>;
    fn launch(&mut self, identity: &str, fixture: Fixture) -> Result<Instance, String>;
    fn stop(&mut self, id: &str, reason: &str) -> Result<(), String>;
    fn end_session(&mut self, session: &str) -> Result<(), String>;
    fn mint_grant(&mut self, instance: &Instance, resource: &str) -> Result<Grant, String>;
    fn use_grant(
        &mut self,
        caller: &Caller,
        grant: &Grant,
        path: &str,
    ) -> Result<UseOutcome, String>;
    fn live_grants(&mut self) -> Result<Vec<LiveGrant>, String>;
    fn public_read(&mut self, path: &str) -> Result<PublicRead, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_paths_are_detected() {
        assert!(is_public_resource(PUBLIC_RESOURCE));
        assert!(is_public_resource("Public/notes"));
        assert!(!is_public_resource("UsersAI/agent-a/s/i/notes"));
        assert!(!is_public_resource(
            "localhost://UsersAI/agent-a/s/i/Public"
        ));
    }

    #[test]
    fn reject_public_as_binding_names_the_rule() {
        assert_eq!(
            reject_public_as_binding(PUBLIC_RESOURCE).unwrap_err(),
            PUBLIC_REASON
        );
        reject_public_as_binding("localhost://UsersAI/a/s/i/notes").unwrap();
    }

    #[test]
    fn fixture_refusal_is_not_runtime_evidence() {
        let outcome = UseOutcome::Refused {
            evidence: RuntimeEvidence::from_double(
                EvidenceKind::Refused,
                None,
                None,
                "denied".to_owned(),
                Actor::Fixture,
                owned_resource("a", "s", "i"),
            ),
        };
        assert_eq!(
            require_runtime_refusal(outcome, IDENTITY_REASON).unwrap_err(),
            "fixture refusal is not Runtime evidence"
        );
    }

    #[test]
    fn public_allow_is_not_binding() {
        let outcome = UseOutcome::Allowed {
            evidence: RuntimeEvidence::from_double(
                EvidenceKind::Allowed,
                Some(200),
                Some("r1".to_owned()),
                "ok".to_owned(),
                Actor::Runtime,
                PUBLIC_RESOURCE.to_owned(),
            ),
        };
        assert_eq!(require_runtime_allow(outcome).unwrap_err(), PUBLIC_REASON);
    }

    #[test]
    fn grade_pass_rejects_double_and_public() {
        let double = RuntimeEvidence::from_double(
            EvidenceKind::Allowed,
            Some(200),
            Some("r1".to_owned()),
            "ok".to_owned(),
            Actor::Runtime,
            owned_resource("a", "s", "i"),
        );
        assert_eq!(
            grade_pass(double).unwrap_err(),
            "PASS requires live operator evidence"
        );
        let public = RuntimeEvidence::from_operator(
            EvidenceKind::Allowed,
            200,
            Some("r1".to_owned()),
            "ok".to_owned(),
            Actor::Runtime,
            PUBLIC_RESOURCE.to_owned(),
            None,
            None,
            None,
        );
        assert_eq!(grade_pass(public).unwrap_err(), PUBLIC_REASON);
    }
}
