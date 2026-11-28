//! Records every [`BindingRuntime`] call a journey makes. Used to derive
//! the asks `needs()` must list. Not Runtime evidence.

use a5_binding_harness::capability::RuntimeCall;
use a5_binding_harness::contract::{
    BindingRuntime, Fixture, Grant, Handle, HostBinding, Instance, LiveGrant, PublicRead,
    RequestRecord, UseOutcome,
};

pub struct Recording<R> {
    inner: R,
    calls: Vec<RuntimeCall>,
}

impl<R: BindingRuntime> Recording<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            calls: Vec::new(),
        }
    }

    pub fn calls(&self) -> &[RuntimeCall] {
        &self.calls
    }

    fn note(&mut self, call: RuntimeCall) {
        self.calls.push(call);
    }
}

impl<R: BindingRuntime> BindingRuntime for Recording<R> {
    fn health(&mut self) -> Result<(), String> {
        self.note(RuntimeCall::Health);
        self.inner.health()
    }

    fn launch(&mut self, identity: &str, fixture: Fixture) -> Result<Instance, String> {
        self.note(RuntimeCall::Launch);
        self.inner.launch(identity, fixture)
    }

    fn host_record(&mut self, handle: &Handle) -> Result<HostBinding, String> {
        self.note(RuntimeCall::HostRecord);
        self.inner.host_record(handle)
    }

    fn stop(&mut self, id: &str, reason: &str) -> Result<(), String> {
        self.note(RuntimeCall::Stop);
        self.inner.stop(id, reason)
    }

    fn end_session(&mut self, handle: &Handle) -> Result<(), String> {
        self.note(RuntimeCall::EndSession);
        self.inner.end_session(handle)
    }

    fn mint_grant(&mut self, handle: &Handle, resource: &str) -> Result<Grant, String> {
        self.note(RuntimeCall::MintGrant);
        self.inner.mint_grant(handle, resource)
    }

    fn use_grant(
        &mut self,
        handle: &Handle,
        grant: &Grant,
        path: &str,
    ) -> Result<UseOutcome, String> {
        self.note(RuntimeCall::UseGrant);
        self.inner.use_grant(handle, grant, path)
    }

    fn live_grants(&mut self) -> Result<Vec<LiveGrant>, String> {
        self.note(RuntimeCall::LiveGrants);
        self.inner.live_grants()
    }

    fn request_record(&mut self, request_id: &str) -> Result<RequestRecord, String> {
        self.note(RuntimeCall::RequestRecord);
        self.inner.request_record(request_id)
    }

    fn public_read(&mut self, path: &str) -> Result<PublicRead, String> {
        self.note(RuntimeCall::PublicRead);
        self.inner.public_read(path)
    }

    fn seed(&mut self, handle: &Handle, rel: &str, bytes: &[u8]) -> Result<(), String> {
        self.note(RuntimeCall::Seed);
        self.inner.seed(handle, rel, bytes)
    }

    fn read_bytes(&mut self, handle: &Handle, rel: &str) -> Result<Vec<u8>, String> {
        self.note(RuntimeCall::ReadBytes);
        self.inner.read_bytes(handle, rel)
    }
}
