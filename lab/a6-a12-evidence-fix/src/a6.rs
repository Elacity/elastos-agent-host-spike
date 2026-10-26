//! A6: a session token stays with the capsule the Runtime granted it to.
//!
//! This crate mints a token with [`CapabilityManager::grant`] and presents it
//! to [`CapabilityManager::validate`]. That is the Runtime session/grant path.
//! It is not two resident capsule instances inside one running Home.
//!
//! Two resident instances in one Runtime is RA-6. The ready journey reports
//! BLOCKED while hosting is absent. PASS requires evidence a real Runtime
//! host produced: two independent resident capsule instances inside one
//! Runtime, each positively proven (not merely a live `/proc` pid), each
//! holding its own grant, sibling refused by the Runtime. Two live pids
//! such as this process and pid 1 are FAIL. An `Ok` from a stub with an
//! empty [`ResidentPair`] is FAIL. Without RA-6 the honest result is
//! BLOCKED, never PASS.

use std::path::Path;
use std::sync::Arc;

use elastos_runtime::capability::manager::{CapabilityManager, ValidationError};
use elastos_runtime::capability::token::{Action, CapabilityToken, ResourceId, TokenConstraints};
use elastos_runtime::capability::CapabilityStore;
use elastos_runtime::primitives::metrics::MetricsManager;
use elastos_runtime::primitives::time::SecureTimestamp;
use elastos_runtime::primitives::AuditLog;

pub const INSTANCE_1: &str = "instance-1";
pub const INSTANCE_2: &str = "instance-2";
const INSTANCE_1_EVIL: &str = "instance-1-evil";
pub const RESOURCE: &str = "localhost://Users/self/Documents/a6-lab/file.txt";
pub const RESOURCE_OTHER: &str = "localhost://Users/self/Documents/a6-lab/other.txt";
pub const RA_6: &str = "RA-6";

pub struct Session {
    manager: CapabilityManager,
    pub token: CapabilityToken,
    resource: ResourceId,
}

impl Session {
    pub fn mint(
        capsule: &str,
        resource: &str,
        action: Action,
        expiry: Option<SecureTimestamp>,
    ) -> Self {
        let manager = CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            Arc::new(AuditLog::new()),
            Arc::new(MetricsManager::new()),
        );
        let resource = ResourceId::new(resource);
        let token = manager.grant(
            capsule,
            resource.clone(),
            action,
            TokenConstraints::default(),
            expiry,
        );
        Self {
            manager,
            token,
            resource,
        }
    }

    /// Mint instance-1's token through the Runtime grant path.
    pub fn mint_instance1() -> Self {
        Self::mint(INSTANCE_1, RESOURCE, Action::Read, None)
    }

    pub fn encoded_token(&self) -> Result<String, String> {
        self.token.to_base64()
    }

    pub fn token_from_wire(&self) -> Result<CapabilityToken, String> {
        CapabilityToken::from_base64(&self.encoded_token()?)
    }

    pub fn validate_as(&self, caller: &str) -> Result<(), ValidationError> {
        self.validate_with(caller, Action::Read, RESOURCE)
    }

    pub fn validate_with(
        &self,
        caller: &str,
        action: Action,
        resource: &str,
    ) -> Result<(), ValidationError> {
        let token = self
            .token_from_wire()
            .expect("granted token must round-trip through from_base64");
        block_on(
            self.manager
                .validate(&token, caller, action, &ResourceId::new(resource), None),
        )
    }

    pub fn revoke(&self, reason: &str) {
        block_on(self.manager.revoke(*self.token.id(), reason));
    }
}

pub fn mint_empty_capsule_token() -> Session {
    Session::mint("", RESOURCE, Action::Read, None)
}

pub fn owner_may_use_own_token() -> Result<String, String> {
    let session = Session::mint_instance1();
    match session.validate_as(INSTANCE_1) {
        Ok(()) => Ok(format!(
            "A6 journey: {INSTANCE_1} may use its Runtime session token (capsule={})",
            session.token.capsule()
        )),
        Err(error) => Err(format!("A6 owner use refused: {error:?}")),
    }
}

pub fn sibling_presenting_owner_token_is_refused() -> Result<String, String> {
    let session = Session::mint_instance1();
    match session.validate_as(INSTANCE_2) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == INSTANCE_2 =>
        {
            Ok(format!(
                "A6 refusal: WrongCapsule {{ expected:{expected} got:{got} }}"
            ))
        }
        other => Err(format!(
            "A6 expected WrongCapsule {{ expected:{INSTANCE_1} got:{INSTANCE_2} }}, got {other:?}"
        )),
    }
}

pub fn prefix_capsule_id_is_refused() -> Result<String, String> {
    let session = Session::mint_instance1();
    match session.validate_as(INSTANCE_1_EVIL) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == INSTANCE_1_EVIL =>
        {
            Ok(format!(
                "A6 prefix refusal: WrongCapsule {{ expected:{expected} got:{got} }}"
            ))
        }
        other => Err(format!(
            "A6 expected exact-match WrongCapsule {{ expected:{INSTANCE_1} got:{INSTANCE_1_EVIL} }}, got {other:?}"
        )),
    }
}

pub fn empty_token_capsule_is_refused() -> Result<String, String> {
    if CapabilityToken::from_base64("").is_ok() {
        return Err("A6 empty token string decoded; from_base64 must refuse it".into());
    }
    let session = mint_empty_capsule_token();
    match session.validate_as(INSTANCE_2) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected.is_empty() && got == INSTANCE_2 =>
        {
            Ok(format!(
                "A6 empty-token refusal: WrongCapsule {{ expected:{expected:?} got:{got} }}"
            ))
        }
        other => Err(format!(
            "A6 expected WrongCapsule {{ expected:\"\" got:{INSTANCE_2} }}, got {other:?}"
        )),
    }
}

pub fn sibling_other_resource_token_is_wrong_capsule() -> Result<String, String> {
    let session = Session::mint(INSTANCE_1, RESOURCE_OTHER, Action::Read, None);
    match session.validate_with(INSTANCE_2, Action::Read, RESOURCE) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == INSTANCE_2 =>
        {
            Ok(format!(
                "A6 other-resource sibling: WrongCapsule {{ expected:{expected} got:{got} }}"
            ))
        }
        other => Err(format!(
            "A6 expected WrongCapsule before WrongResource, got {other:?}"
        )),
    }
}

pub fn sibling_other_action_token_is_wrong_capsule() -> Result<String, String> {
    let session = Session::mint(INSTANCE_1, RESOURCE, Action::Write, None);
    match session.validate_with(INSTANCE_2, Action::Read, RESOURCE) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == INSTANCE_2 =>
        {
            Ok(format!(
                "A6 other-action sibling: WrongCapsule {{ expected:{expected} got:{got} }}"
            ))
        }
        other => Err(format!(
            "A6 expected WrongCapsule before WrongAction, got {other:?}"
        )),
    }
}

pub fn owner_other_resource_is_wrong_resource() -> Result<String, String> {
    let session = Session::mint_instance1();
    match session.validate_with(INSTANCE_1, Action::Read, RESOURCE_OTHER) {
        Err(ValidationError::WrongResource { .. }) => {
            Ok("A6 owner other-resource: WrongResource".into())
        }
        other => Err(format!("A6 expected WrongResource, got {other:?}")),
    }
}

pub fn expired_token_is_refused() -> Result<String, String> {
    let session = Session::mint(
        INSTANCE_1,
        RESOURCE,
        Action::Read,
        Some(SecureTimestamp::at(1)),
    );
    match session.validate_as(INSTANCE_1) {
        Err(ValidationError::TokenExpired) => Ok("A6 expired token: TokenExpired".into()),
        other => Err(format!("A6 expected TokenExpired, got {other:?}")),
    }
}

pub fn revoked_token_is_refused() -> Result<String, String> {
    let session = Session::mint_instance1();
    session.revoke("a6 pack");
    match session.validate_as(INSTANCE_1) {
        Err(ValidationError::TokenRevoked) => Ok("A6 revoked token: TokenRevoked".into()),
        other => Err(format!("A6 expected TokenRevoked, got {other:?}")),
    }
}

pub fn tampered_base64_is_refused() -> Result<String, String> {
    let session = Session::mint_instance1();
    let encoded = session.encoded_token()?;
    if encoded.len() <= 8 {
        return Err(format!("A6 token too short to tamper: {encoded}"));
    }
    let mid = encoded.len() / 2;
    let ch = encoded.as_bytes()[mid];
    let replacement = if ch == b'A' { 'B' } else { 'A' };
    let mut tampered = encoded.clone();
    tampered.replace_range(mid..mid + 1, &replacement.to_string());
    if tampered == encoded {
        return Err("A6 tamper did not change the wire token".into());
    }
    match CapabilityToken::from_base64(&tampered) {
        Err(reason) => Ok(format!(
            "A6 tampered base64: from_base64 refused ({reason})"
        )),
        Ok(decoded) => {
            let result = block_on(session.manager.validate(
                &decoded,
                INSTANCE_1,
                Action::Read,
                &session.resource,
                None,
            ));
            if result.is_ok() {
                return Err(format!(
                    "A6 tampered token decoded and validated as owner: {result:?}"
                ));
            }
            Ok(format!(
                "A6 tampered base64: decoded then validate refused {result:?}"
            ))
        }
    }
}

pub fn case_variant_capsule_id_is_refused() -> Result<String, String> {
    let session = Session::mint_instance1();
    match session.validate_as("INSTANCE-1") {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == "INSTANCE-1" =>
        {
            Ok(format!(
                "A6 case variant: WrongCapsule {{ expected:{expected} got:{got} }}"
            ))
        }
        other => Err(format!(
            "A6 expected exact-case WrongCapsule, got {other:?}"
        )),
    }
}

pub fn zero_width_capsule_id_is_refused() -> Result<String, String> {
    let session = Session::mint_instance1();
    let sneaky = format!("instance-1{}", '\u{200b}');
    match session.validate_as(&sneaky) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == sneaky =>
        {
            Ok(format!(
                "A6 unicode zwsp: WrongCapsule got_len={}",
                got.len()
            ))
        }
        other => Err(format!(
            "A6 expected WrongCapsule for zero-width sibling, got {other:?}"
        )),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum JourneyStatus {
    Pass(String),
    Fail(String),
    Blocked { ask: &'static str, reason: String },
}

/// Empty pair a hosting stub can return. PASS never treats this as evidence.
/// The journey reads live instance ids/pids from the Runtime.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResidentPair;

/// Instance ids, pids, and grants a real Runtime host must report.
#[derive(Debug, PartialEq, Eq)]
pub struct RuntimeResidentEvidence {
    pub instance_1_id: String,
    pub instance_1_pid: u32,
    pub instance_1_grant: String,
    pub instance_2_id: String,
    pub instance_2_pid: u32,
    pub instance_2_grant: String,
}

fn try_host_two_resident_instances() -> Result<ResidentPair, String> {
    Err(format!(
        "{RA_6}: Runtime does not host two resident capsule instances in one process. \
         Bus v2 / RT4 still owns resident lifecycle. Owner A6 rows use fixture deny \
         across Homes, not validate step 4. See lab/a6-a12-evidence-fix/RA-6.md."
    ))
}

/// Independent of the stub return. Empty until the Runtime reports a pair.
pub fn query_runtime_resident_instances() -> Result<RuntimeResidentEvidence, String> {
    Err(
        "Runtime does not report two distinct live resident instance ids/pids, \
         each holding its own grant"
            .into(),
    )
}

fn pid_is_live(pid: u32) -> bool {
    pid != 0 && Path::new(&format!("/proc/{pid}")).is_dir()
}

/// A live `/proc` directory is not proof the pid is a resident capsule.
/// This lab process and pid 1 never count. RA-6 fills the host inspect.
pub fn prove_resident_capsule_instance(pid: u32, instance_id: &str) -> Result<(), String> {
    if instance_id.is_empty() {
        return Err("resident instance id is empty".into());
    }
    if !pid_is_live(pid) {
        return Err(format!("pid {pid} is not a live process"));
    }
    if pid == 1 {
        return Err("pid 1 is not a resident capsule instance hosted by this Runtime".into());
    }
    if pid == std::process::id() {
        return Err(format!(
            "pid {pid} is this lab process, not a resident capsule instance hosted by this Runtime"
        ));
    }
    match inspect_runtime_hosted_resident(pid, instance_id) {
        Some(()) => Ok(()),
        None => Err(format!(
            "pid {pid} is not positively proven a resident capsule instance \
             hosted by this Runtime (instance {instance_id})"
        )),
    }
}

/// Positive inspect of the Runtime this process loaded. Absent until RA-6.
fn inspect_runtime_hosted_resident(_pid: u32, _instance_id: &str) -> Option<()> {
    None
}

fn evidence_is_live_runtime_pair(ev: &RuntimeResidentEvidence) -> Result<(), String> {
    if ev.instance_1_id.is_empty()
        || ev.instance_2_id.is_empty()
        || ev.instance_1_id == ev.instance_2_id
    {
        return Err("Runtime instance ids must be two distinct non-empty ids".into());
    }
    if ev.instance_1_pid == 0 || ev.instance_2_pid == 0 || ev.instance_1_pid == ev.instance_2_pid {
        return Err("Runtime instance pids must be two distinct live pids".into());
    }
    if !pid_is_live(ev.instance_1_pid) || !pid_is_live(ev.instance_2_pid) {
        return Err("Runtime-reported pid is not a live process".into());
    }
    prove_resident_capsule_instance(ev.instance_1_pid, &ev.instance_1_id)?;
    prove_resident_capsule_instance(ev.instance_2_pid, &ev.instance_2_id)?;
    if ev.instance_1_grant.is_empty()
        || ev.instance_2_grant.is_empty()
        || ev.instance_1_grant == ev.instance_2_grant
    {
        return Err("each resident instance must hold its own grant".into());
    }
    Ok(())
}

/// Evaluate claimed Runtime evidence. This process plus pid 1 is FAIL.
pub fn status_for_claimed_resident_pair(evidence: RuntimeResidentEvidence) -> JourneyStatus {
    let session = Session::mint_instance1();
    finish_claimed_evidence(&session, evidence)
}

fn finish_claimed_evidence(session: &Session, evidence: RuntimeResidentEvidence) -> JourneyStatus {
    match evidence_is_live_runtime_pair(&evidence) {
        Err(reason) => JourneyStatus::Fail(reason),
        Ok(()) => match session.validate_as(INSTANCE_2) {
            Err(ValidationError::WrongCapsule { expected, got })
                if expected == INSTANCE_1 && got == INSTANCE_2 =>
            {
                JourneyStatus::Pass(format!(
                    "A6 resident: Runtime hosted {} pid {} and {} pid {}; \
                     sibling refused WrongCapsule {{ expected:{expected} got:{got} }}",
                    evidence.instance_1_id,
                    evidence.instance_1_pid,
                    evidence.instance_2_id,
                    evidence.instance_2_pid
                ))
            }
            other => JourneyStatus::Fail(format!(
                "resident instance-2 presenting instance-1 token: {other:?}"
            )),
        },
    }
}

/// Evaluate an `Ok(ResidentPair)` from the host. An empty stub pair is FAIL.
pub fn status_after_host_ok(pair: ResidentPair) -> JourneyStatus {
    let session = Session::mint_instance1();
    finish_hosted_pair(&session, pair)
}

fn finish_hosted_pair(session: &Session, pair: ResidentPair) -> JourneyStatus {
    let _ = pair;
    match query_runtime_resident_instances() {
        Err(reason) => JourneyStatus::Fail(format!(
            "Ok from stub with empty ResidentPair: FAIL ({reason})"
        )),
        Ok(evidence) => finish_claimed_evidence(session, evidence),
    }
}

/// Ready journey: mint instance-1's real token and present it as a second
/// *resident* instance. Until the Runtime hosts that pair, the status is
/// BLOCKED. An `Ok` from a stub with an empty [`ResidentPair`] is FAIL.
/// Two live `/proc` pids that are not proven resident capsules (this
/// process plus pid 1) are FAIL, never PASS. PASS requires two independent
/// resident capsule instances inside one Runtime, each holding its own
/// grant, sibling refused by the Runtime. Removing validate step 4 from
/// the Runtime this process loaded makes the readiness check FAIL
/// (sibling accepted).
pub fn resident_two_instance_token_journey() -> JourneyStatus {
    let session = Session::mint_instance1();
    match session.validate_as(INSTANCE_2) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == INSTANCE_2 => {}
        other => {
            return JourneyStatus::Fail(format!(
                "ready journey: instance-2 presenting instance-1 token must be WrongCapsule; got {other:?}"
            ));
        }
    }
    match try_host_two_resident_instances() {
        Err(reason) => JourneyStatus::Blocked { ask: RA_6, reason },
        Ok(pair) => finish_hosted_pair(&session, pair),
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}
