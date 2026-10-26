//! A6: a session token stays with the capsule the Runtime granted it to.
//!
//! This crate mints a token with [`CapabilityManager::grant`] and presents it
//! to [`CapabilityManager::validate`]. That is the Runtime session/grant path.
//! It is not two resident capsule instances inside one running Home.

use std::sync::Arc;

use elastos_runtime::capability::manager::{CapabilityManager, ValidationError};
use elastos_runtime::capability::token::{Action, CapabilityToken, ResourceId, TokenConstraints};
use elastos_runtime::capability::CapabilityStore;
use elastos_runtime::primitives::metrics::MetricsManager;
use elastos_runtime::primitives::AuditLog;

const INSTANCE_1: &str = "instance-1";
const INSTANCE_2: &str = "instance-2";
const INSTANCE_1_EVIL: &str = "instance-1-evil";
const RESOURCE: &str = "localhost://Users/self/Documents/a6-lab/file.txt";

pub struct Session {
    manager: CapabilityManager,
    token: CapabilityToken,
    resource: ResourceId,
}

impl Session {
    /// Mint instance-1's token through the Runtime grant path.
    pub fn mint_instance1() -> Self {
        let manager = CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            Arc::new(AuditLog::new()),
            Arc::new(MetricsManager::new()),
        );
        let resource = ResourceId::new(RESOURCE);
        let token = manager.grant(
            INSTANCE_1,
            resource.clone(),
            Action::Read,
            TokenConstraints::default(),
            None,
        );
        Self {
            manager,
            token,
            resource,
        }
    }

    pub fn encoded_token(&self) -> Result<String, String> {
        self.token.to_base64()
    }

    pub fn token_from_wire(&self) -> Result<CapabilityToken, String> {
        CapabilityToken::from_base64(&self.encoded_token()?)
    }

    pub fn validate_as(&self, caller: &str) -> Result<(), ValidationError> {
        let token = self
            .token_from_wire()
            .expect("granted token must round-trip through from_base64");
        block_on(
            self.manager
                .validate(&token, caller, Action::Read, &self.resource, None),
        )
    }
}

pub fn mint_empty_capsule_token() -> Session {
    let manager = CapabilityManager::new(
        Arc::new(CapabilityStore::new()),
        Arc::new(AuditLog::new()),
        Arc::new(MetricsManager::new()),
    );
    let resource = ResourceId::new(RESOURCE);
    let token = manager.grant(
        "",
        resource.clone(),
        Action::Read,
        TokenConstraints::default(),
        None,
    );
    Session {
        manager,
        token,
        resource,
    }
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

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}
