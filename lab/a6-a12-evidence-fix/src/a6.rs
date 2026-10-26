//! A6: a session token stays with the capsule the Runtime granted it to.
//!
//! This crate mints a token with [`CapabilityManager::grant`] and presents it
//! to [`CapabilityManager::validate`]. That is the Runtime session/grant path.
//! It is not two resident capsule instances inside one running Home.
//!
//! Two resident instances in one Runtime is RA-6. The ready journey reports
//! BLOCKED, never PASS, until the Runtime hosts that pair.

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

/// Two resident capsule handles inside one Runtime. The Runtime does not
/// expose this yet (RA-6).
pub struct ResidentPair;

fn try_host_two_resident_instances() -> Result<ResidentPair, String> {
    Err(format!(
        "{RA_6}: Runtime does not host two resident capsule instances in one process. \
         Bus v2 / RT4 still owns resident lifecycle. Owner A6 rows use fixture deny \
         across Homes, not validate step 4. See lab/a6-a12-evidence-fix/RA-6.md."
    ))
}

/// Ready journey: mint instance-1's real token and present it as a second
/// *resident* instance. Until the Runtime hosts that pair, the status is
/// BLOCKED. Removing validate step 4 from the Runtime this process loaded
/// makes the readiness check FAIL (sibling accepted). The journey never
/// returns PASS while RA-6 is open.
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
        Err(reason) => JourneyStatus::Blocked {
            ask: RA_6,
            reason,
        },
        Ok(_pair) => {
            match session.validate_as(INSTANCE_2) {
                Err(ValidationError::WrongCapsule { expected, got })
                    if expected == INSTANCE_1 && got == INSTANCE_2 =>
                {
                    JourneyStatus::Pass(format!(
                        "A6 resident: instance-2 presenting instance-1 token refused WrongCapsule {{ expected:{expected} got:{got} }}"
                    ))
                }
                other => JourneyStatus::Fail(format!(
                    "resident instance-2 presenting instance-1 token: {other:?}"
                )),
            }
        }
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}
