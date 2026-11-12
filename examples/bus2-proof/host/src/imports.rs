//! The stub host's side of each imported interface.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::oneshot;
use wasmtime::component::{Accessor, FutureReader, HasSelf, StreamReader};

use crate::elastos::bus::{
    capabilities, clock, credentials, identity, providers, random, runtime, types, ui,
};
use crate::{objects, BusError, Credential, Grant, HostState};

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

impl clock::HostWithStore<HostState> for HasSelf<HostState> {
    async fn sleep_until_ms(_accessor: &Accessor<HostState, Self>, deadline: u64) {
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

impl capabilities::HostWithStore<HostState> for HasSelf<HostState> {
    async fn request(
        accessor: &Accessor<HostState, Self>,
        resource: String,
        actions: Vec<String>,
        _reason: String,
    ) -> Result<Grant, BusError> {
        accessor.with(|mut access| objects::request_grant(access.get(), resource, actions))
    }
}

impl providers::Host for HostState {}

impl providers::HostWithStore<HostState> for HasSelf<HostState> {
    async fn invoke(
        accessor: &Accessor<HostState, Self>,
        request: types::InvokeRequest,
        body: Option<StreamReader<u8>>,
    ) -> Result<
        (
            types::InvokeStatus,
            StreamReader<u8>,
            FutureReader<Result<(), BusError>>,
        ),
        BusError,
    > {
        let has_body = body.is_some();
        if let Some(mut body) = body {
            // Nothing here takes a body; close it so it is not left open.
            let _ = accessor.with(|mut access| body.close(&mut access));
        }
        let read =
            accessor.with(|mut access| objects::start_read(access.get(), request, has_body))?;
        let audit = read.audit.clone();
        let (done, result) = oneshot::channel();
        accessor
            .with(|mut access| {
                let stream =
                    StreamReader::new(&mut access, objects::ObjectStream::new(read, done))?;
                let trailer = FutureReader::new(&mut access, async move {
                    Ok::<_, wasmtime::Error>(result.await.unwrap_or_else(|_| {
                        Err(BusError::Internal(
                            "the provider ended without a result".into(),
                        ))
                    }))
                })?;
                Ok::<_, wasmtime::Error>((stream, trailer))
            })
            .map(|(stream, trailer)| {
                let status = types::InvokeStatus {
                    status: "ok".into(),
                    audit: Some(audit),
                };
                (status, stream, trailer)
            })
            .map_err(|err| BusError::Internal(format!("could not open the read: {err}")))
    }
}

impl ui::Host for HostState {}

impl ui::HostWithStore<HostState> for HasSelf<HostState> {
    async fn present(
        accessor: &Accessor<HostState, Self>,
        media_type: String,
        document: Vec<u8>,
    ) -> Result<(), BusError> {
        accessor.with(|mut access| {
            let state = access.get();
            let frame = crate::ui::check_document(state, &media_type, &document)?;
            state.frames.push(frame);
            Ok(())
        })
    }
}
