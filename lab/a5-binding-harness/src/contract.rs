//! The Runtime interface the journeys need, as SPEC.md states it.
//!
//! The guest presents a handle. Identity, session and instance come from the
//! host record of that handle. Refusal matching uses a structured code or the
//! exact reason string, never a substring.

use crate::walk::{walk_owned, WalkRefuse};

/// Owned notes file under the instance root named in SPEC.md section 4.
pub const OWNED_NOTES: &str = "notes";
/// Public path that must never count as A5 binding evidence.
pub const PUBLIC_RESOURCE: &str = "localhost://Public/a5-binding/notes";
pub const CLEANUP_REASON: &str = "harness cleanup: journey finished";
pub const A_SEED: &[u8] = b"a5-identity-agent-a-seed\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub reason: &'static str,
}

pub const IDENTITY_REFUSAL: Refusal = Refusal {
    code: "identity",
    reason: "identity does not match the grant",
};
pub const SESSION_REFUSAL: Refusal = Refusal {
    code: "session",
    reason: "session does not match the grant",
};
pub const INSTANCE_REFUSAL: Refusal = Refusal {
    code: "instance",
    reason: "instance does not match the grant",
};
pub const OWNED_ROOT_REFUSAL: Refusal = Refusal {
    code: "owned_root",
    reason: "use path leaves the owned root",
};
pub const HOST_PATH_REFUSAL: Refusal = Refusal {
    code: "host_path",
    reason: "owned root is a host path",
};
pub const SYMLINK_REFUSAL: Refusal = Refusal {
    code: "symlink",
    reason: "use path has a symlink-shaped segment",
};
pub const PREFIX_REFUSAL: Refusal = Refusal {
    code: "prefix",
    reason: "use path is a prefix collision",
};
pub const PUBLIC_REFUSAL: Refusal = Refusal {
    code: "public",
    reason: "public storage read does not bind",
};

pub const PUBLIC_REASON: &str = PUBLIC_REFUSAL.reason;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixture {
    BindOwned,
}

impl Fixture {
    pub fn name(self) -> &'static str {
        "bind-owned"
    }
}

/// Opaque handle the guest presents. The host record decides the rest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Handle(String);

impl Handle {
    pub fn new(id: impl Into<String>) -> Result<Self, String> {
        let id = id.into();
        if id.is_empty() {
            return Err("empty handle is refused".to_owned());
        }
        Ok(Handle(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub id: String,
    pub handle: Handle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostBinding {
    pub identity: String,
    pub session: String,
    pub instance: String,
    pub owned_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub handle: Handle,
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
pub struct RequestRecord {
    pub request_id: String,
    pub status: String,
    pub settled_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRead {
    pub resource: String,
    pub bytes: Vec<u8>,
    /// Derived from the operator body. True only when that body claims grant
    /// binding fields. Never a hardcoded false.
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
    pub code: Option<String>,
    pub refused_by: Actor,
    pub resource: String,
    pub guest_handle: Option<String>,
}

impl RuntimeEvidence {
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn from_operator(
        kind: EvidenceKind,
        http_status: u16,
        request_id: Option<String>,
        reason: String,
        code: Option<String>,
        refused_by: Actor,
        resource: String,
        guest_handle: Option<String>,
    ) -> Self {
        Self {
            source: EvidenceSource::LiveOperator,
            kind,
            http_status: Some(http_status),
            request_id,
            reason,
            code,
            refused_by,
            resource,
            guest_handle,
        }
    }

    /// Harness-test evidence. `acceptance` never turns this into PASS.
    pub fn from_double(
        kind: EvidenceKind,
        http_status: Option<u16>,
        request_id: Option<String>,
        reason: String,
        code: Option<String>,
        refused_by: Actor,
        resource: String,
    ) -> Self {
        Self {
            source: EvidenceSource::HarnessDouble,
            kind,
            http_status,
            request_id,
            reason,
            code,
            refused_by,
            resource,
            guest_handle: None,
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
            "{:?} {} by {:?} status={:?} request={:?} handle={:?}",
            self.kind,
            self.reason,
            self.refused_by,
            self.http_status,
            self.request_id,
            self.guest_handle
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

pub fn require_grant_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("empty grant id is refused".to_owned());
    }
    Ok(())
}

/// Structured code wins. Otherwise the reason must be the exact string.
/// `contains()` is not a match. "no identity check" is not `identity`.
pub fn refusal_matches(evidence: &RuntimeEvidence, expected: Refusal) -> bool {
    match evidence.code.as_deref() {
        Some(code) => code == expected.code,
        None => evidence.reason == expected.reason,
    }
}

pub fn walk_or_refuse(agent: &str, path: &str, owned_root: Option<&str>) -> Result<(), WalkRefuse> {
    walk_owned(agent, path, owned_root)
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

/// A refusal counts only when the Runtime spoke and the code or the exact
/// reason string matches. A substring is not a match.
pub fn require_runtime_refusal(
    outcome: UseOutcome,
    expected: Refusal,
) -> Result<RuntimeEvidence, String> {
    match outcome {
        UseOutcome::Refused { evidence } => {
            require_runtime_speaker(&evidence)?;
            if evidence.http_status.is_none() && evidence.request_id.is_none() {
                return Err(
                    "Runtime refusal needs an operator HTTP status or request id".to_owned(),
                );
            }
            if !refusal_matches(&evidence, expected) {
                return Err(format!(
                    "Runtime refusal code={:?} reason={:?} is not {} / {:?}",
                    evidence.code, evidence.reason, expected.code, expected.reason
                ));
            }
            Ok(evidence)
        }
        UseOutcome::Allowed { evidence } => {
            if evidence.is_public_resource() {
                return Err(PUBLIC_REASON.to_owned());
            }
            Err(format!(
                "expected Runtime refusal {} / {:?}, got allow of {}",
                expected.code, expected.reason, evidence.resource
            ))
        }
    }
}

pub fn require_any_runtime_refusal(
    outcome: UseOutcome,
    expected: &[Refusal],
) -> Result<RuntimeEvidence, String> {
    match outcome {
        UseOutcome::Refused { evidence } => {
            require_runtime_speaker(&evidence)?;
            if evidence.http_status.is_none() && evidence.request_id.is_none() {
                return Err(
                    "Runtime refusal needs an operator HTTP status or request id".to_owned(),
                );
            }
            if expected
                .iter()
                .any(|item| refusal_matches(&evidence, *item))
            {
                return Ok(evidence);
            }
            Err(format!(
                "Runtime refusal code={:?} reason={:?} is not one of {:?}",
                evidence.code,
                evidence.reason,
                expected.iter().map(|item| item.code).collect::<Vec<_>>()
            ))
        }
        UseOutcome::Allowed { evidence } => {
            if evidence.is_public_resource() {
                return Err(PUBLIC_REASON.to_owned());
            }
            Err(format!(
                "expected Runtime refusal {:?}, got allow of {}",
                expected.iter().map(|item| item.code).collect::<Vec<_>>(),
                evidence.resource
            ))
        }
    }
}

/// PASS is live-operator evidence from a guest handle, not a Public bind.
pub fn grade_pass(evidence: RuntimeEvidence) -> Result<crate::Grade, String> {
    if !evidence.is_live_operator() {
        return Err("PASS requires live operator evidence".to_owned());
    }
    if evidence.claims_public_binding() {
        return Err(PUBLIC_REASON.to_owned());
    }
    if evidence
        .guest_handle
        .as_deref()
        .map(str::is_empty)
        .unwrap_or(true)
    {
        return Err("PASS requires a guest handle presented by the guest".to_owned());
    }
    Ok(crate::Grade::Pass(evidence.summary()))
}

/// Every call is made by the harness as the shell. The guest presents a
/// handle. Errors are reasons.
pub trait BindingRuntime {
    fn health(&mut self) -> Result<(), String>;
    fn launch(&mut self, identity: &str, fixture: Fixture) -> Result<Instance, String>;
    fn host_record(&mut self, handle: &Handle) -> Result<HostBinding, String>;
    fn stop(&mut self, id: &str, reason: &str) -> Result<(), String>;
    fn end_session(&mut self, handle: &Handle) -> Result<(), String>;
    fn mint_grant(&mut self, handle: &Handle, resource: &str) -> Result<Grant, String>;
    fn use_grant(
        &mut self,
        handle: &Handle,
        grant: &Grant,
        path: &str,
    ) -> Result<UseOutcome, String>;
    fn live_grants(&mut self) -> Result<Vec<LiveGrant>, String>;
    fn request_record(&mut self, request_id: &str) -> Result<RequestRecord, String>;
    fn public_read(&mut self, path: &str) -> Result<PublicRead, String>;
    fn seed(&mut self, handle: &Handle, rel: &str, bytes: &[u8]) -> Result<(), String>;
    fn read_bytes(&mut self, handle: &Handle, rel: &str) -> Result<Vec<u8>, String>;
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
                None,
                Actor::Fixture,
                owned_resource("a", "s", "i"),
            ),
        };
        assert_eq!(
            require_runtime_refusal(outcome, IDENTITY_REFUSAL).unwrap_err(),
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
                None,
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
            None,
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
            None,
            Actor::Runtime,
            PUBLIC_RESOURCE.to_owned(),
            Some("handle-1".to_owned()),
        );
        assert_eq!(grade_pass(public).unwrap_err(), PUBLIC_REASON);
    }

    #[test]
    fn theatre_without_guest_handle_is_not_accepted() {
        let evidence = RuntimeEvidence::from_operator(
            EvidenceKind::Allowed,
            200,
            Some("r1".to_owned()),
            "ok".to_owned(),
            None,
            Actor::Runtime,
            owned_resource("a", "s", "i"),
            None,
        );
        assert_eq!(
            grade_pass(evidence).unwrap_err(),
            "PASS requires a guest handle presented by the guest"
        );
        let empty = RuntimeEvidence::from_operator(
            EvidenceKind::Allowed,
            200,
            Some("r1".to_owned()),
            "ok".to_owned(),
            None,
            Actor::Runtime,
            owned_resource("a", "s", "i"),
            Some(String::new()),
        );
        assert_eq!(
            grade_pass(empty).unwrap_err(),
            "PASS requires a guest handle presented by the guest"
        );
    }

    #[test]
    fn empty_grant_id_is_rejected() {
        assert_eq!(
            require_grant_id("").unwrap_err(),
            "empty grant id is refused"
        );
        require_grant_id("grant-1").unwrap();
    }

    #[test]
    fn reason_substring_is_not_a_match() {
        let sub = RuntimeEvidence::from_double(
            EvidenceKind::Refused,
            Some(403),
            Some("r1".to_owned()),
            "no identity check".to_owned(),
            None,
            Actor::Runtime,
            owned_resource("a", "s", "i"),
        );
        assert!(
            !refusal_matches(&sub, IDENTITY_REFUSAL),
            "substring 'identity' in 'no identity check' must not match"
        );
        let evil = RuntimeEvidence::from_double(
            EvidenceKind::Refused,
            Some(403),
            Some("r1".to_owned()),
            "instance-1-evil accepted".to_owned(),
            None,
            Actor::Runtime,
            owned_resource("a", "s", "i"),
        );
        assert!(!refusal_matches(&evil, INSTANCE_REFUSAL));
        let via = RuntimeEvidence::from_double(
            EvidenceKind::Refused,
            Some(403),
            Some("r1".to_owned()),
            "owned root via ..".to_owned(),
            None,
            Actor::Runtime,
            owned_resource("a", "s", "i"),
        );
        assert!(!refusal_matches(&via, OWNED_ROOT_REFUSAL));
        let exact = RuntimeEvidence::from_double(
            EvidenceKind::Refused,
            Some(403),
            Some("r1".to_owned()),
            IDENTITY_REFUSAL.reason.to_owned(),
            None,
            Actor::Runtime,
            owned_resource("a", "s", "i"),
        );
        assert!(refusal_matches(&exact, IDENTITY_REFUSAL));
        let coded = RuntimeEvidence::from_double(
            EvidenceKind::Refused,
            Some(403),
            Some("r1".to_owned()),
            "no identity check".to_owned(),
            Some("identity".to_owned()),
            Actor::Runtime,
            owned_resource("a", "s", "i"),
        );
        assert!(refusal_matches(&coded, IDENTITY_REFUSAL));
    }

    #[test]
    fn empty_handle_is_refused() {
        assert_eq!(Handle::new("").unwrap_err(), "empty handle is refused");
        assert_eq!(Handle::new("h1").unwrap().as_str(), "h1");
    }
}
