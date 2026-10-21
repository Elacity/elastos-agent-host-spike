//! The stub host's side of each imported interface.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wasmtime::component::{Accessor, FutureReader, HasSelf, StreamReader};

use crate::elastos::bus::{
    capabilities, clock, credentials, identity, providers, random, runtime, types, ui,
};
use crate::{BusError, Credential, Grant, HostState, UI_MEDIA_TYPE};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

impl types::Host for HostState {}

impl runtime::Host for HostState {
    fn info(&mut self) -> runtime::RuntimeInfo {
        runtime::RuntimeInfo {
            abi: "elastos:bus@2.0.0".into(),
            runtime_version: "bus2-proof-stub".into(),
            capsule_cid: None,
        }
    }
}

impl identity::Host for HostState {
    fn context(&mut self) -> identity::IdentityContext {
        identity::IdentityContext {
            principal: None,
            capsule: "bus2-proof-guest".into(),
            session: "stub".into(),
            device: None,
        }
    }
}

impl clock::Host for HostState {
    fn now_ms(&mut self) -> u64 {
        now_ms()
    }
}

impl<T: Send + 'static> clock::HostWithStore<T> for HasSelf<HostState> {
    async fn sleep_until_ms(_accessor: &Accessor<T, Self>, deadline: u64) {
        let wait = deadline.saturating_sub(now_ms());
        match Duration::from_millis(wait) {
            // A deadline too far away to schedule is one that never comes.
            wait if wait > Duration::from_secs(24 * 60 * 60) => std::future::pending().await,
            wait => tokio::time::sleep(wait).await,
        }
    }
}

impl random::Host for HostState {
    fn fill(&mut self, len: u32) -> Vec<u8> {
        // Not a source of secrets: the proof needs no randomness.
        vec![0; len.min(4096) as usize]
    }
}

impl credentials::Host for HostState {
    fn presented(&mut self) -> Vec<Credential> {
        self.credentials.clone()
    }
}

impl capabilities::Host for HostState {}

impl<T: Send + 'static> capabilities::HostWithStore<T> for HasSelf<HostState> {
    async fn request(
        _accessor: &Accessor<T, Self>,
        resource: String,
        _actions: Vec<String>,
        _reason: String,
    ) -> Result<Grant, BusError> {
        Err(BusError::Denied(format!(
            "no grant for {resource} (step 3)"
        )))
    }
}

impl providers::Host for HostState {}

impl<T: Send + 'static> providers::HostWithStore<T> for HasSelf<HostState> {
    async fn invoke(
        _accessor: &Accessor<T, Self>,
        request: types::InvokeRequest,
        _body: Option<StreamReader<u8>>,
    ) -> Result<
        (
            types::InvokeStatus,
            StreamReader<u8>,
            FutureReader<Result<(), BusError>>,
        ),
        BusError,
    > {
        Err(BusError::Unavailable(format!(
            "no provider for {} (step 3)",
            request.resource
        )))
    }
}

impl ui::Host for HostState {}

impl<T: Send + 'static> ui::HostWithStore<T> for HasSelf<HostState> {
    async fn present(
        accessor: &Accessor<T, Self>,
        media_type: String,
        document: Vec<u8>,
    ) -> Result<(), BusError> {
        if media_type != UI_MEDIA_TYPE {
            return Err(BusError::Invalid(format!(
                "media type {media_type:?}; expected {UI_MEDIA_TYPE}"
            )));
        }
        accessor.with(|mut access| access.get().frames.push(document));
        Ok(())
    }
}
