//! The Bus v1 WIT glue: `WitBus` implements `Bus` over the generated
//! `elastos:bus@v1` imports, and `lifecycle_run` is the body of every guest's
//! `lifecycle.run`.

use crate::wit::elastos::bus::{capabilities, providers, runtime, types};
use crate::{App, Bus, BusFailure, InvokeReply, Refusal};

/// The Component ABI every Bus v1 guest here is built for.
pub const EXPECTED_RUNTIME_ABI: &str = "elastos.component/v1";

pub struct WitBus;

fn from_wit(err: types::BusError) -> BusFailure {
    match err {
        types::BusError::Denied(message) => BusFailure::Denied(message),
        types::BusError::NotFound(message) => BusFailure::NotFound(message),
        types::BusError::Invalid(message) => BusFailure::Invalid(message),
        types::BusError::Unavailable(message) => BusFailure::Unavailable(message),
        types::BusError::Timeout(message) => BusFailure::Timeout(message),
        types::BusError::Internal(message) => BusFailure::Internal(message),
    }
}

pub fn to_wit(failure: BusFailure) -> types::BusError {
    match failure {
        BusFailure::Denied(message) => types::BusError::Denied(message),
        BusFailure::NotFound(message) => types::BusError::NotFound(message),
        BusFailure::Invalid(message) => types::BusError::Invalid(message),
        BusFailure::Unavailable(message) => types::BusError::Unavailable(message),
        BusFailure::Timeout(message) => types::BusError::Timeout(message),
        BusFailure::Internal(message) => types::BusError::Internal(message),
    }
}

impl Bus for WitBus {
    fn request(
        &mut self,
        resource: &str,
        action: &str,
        reason: &str,
    ) -> Result<String, BusFailure> {
        capabilities::request(&types::CapabilityRequest {
            resource: resource.to_string(),
            actions: vec![action.to_string()],
            reason: reason.to_string(),
        })
        .map(|grant| grant.id)
        .map_err(from_wit)
    }

    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<InvokeReply, BusFailure> {
        providers::invoke(&types::InvokeRequest {
            resource: resource.to_string(),
            operation: operation.to_string(),
            body: body.to_vec(),
            grant: Some(grant.to_string()),
        })
        .map(|reply| InvokeReply {
            status: reply.status,
            body: reply.body,
        })
        .map_err(from_wit)
    }
}

pub fn runtime_abi() -> String {
    runtime::info().abi
}

/// `lifecycle.run`: checks the Runtime's ABI, runs `run` over the real Bus,
/// and turns a refusal into the `bus-error` Runtime receives.
pub fn lifecycle_run(
    app: &App,
    run: impl FnOnce(&mut dyn Bus) -> Result<(), Refusal>,
) -> Result<(), types::BusError> {
    let abi = runtime_abi();
    if abi != EXPECTED_RUNTIME_ABI {
        return Err(types::BusError::Invalid(format!(
            "{} requires {EXPECTED_RUNTIME_ABI}, received {abi}",
            app.name
        )));
    }
    run(&mut WitBus).map_err(|refusal| to_wit(refusal.to_bus_failure(app)))
}
