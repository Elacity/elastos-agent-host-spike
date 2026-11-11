//! Grants and the one way to read an object: `providers.invoke` with
//! operation `read` and a grant for that object.
//!
//! A read is capped by the smaller of the guest's own cap (in `params`) and
//! the host's hard cap. An object over the cap is refused before any byte is
//! sent. An object that grows past the cap while it is read ends with an error
//! on the trailing future; the stream is never ended short with `ok`.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::sync::oneshot;
use wasmtime::component::{Destination, StreamProducer, StreamResult, VecBuffer};
use wasmtime::{Result, StoreContextMut};

use crate::elastos::bus::types::InvokeRequest;
use crate::{BusError, Grant, HostState};

/// Bytes per chunk the stub provider writes.
pub const READ_CHUNK: usize = 64 * 1024;
/// The host's own cap on one read, whatever the guest asks for.
pub const HOST_MAX_READ_BYTES: usize = 16 * 1024 * 1024;

/// An object in the stub's store.
#[derive(Clone, Debug, Default)]
pub struct StubObject {
    pub bytes: Vec<u8>,
    /// Bytes that appear while the object is being read (a file still being
    /// written), so the provider only finds out its real size as it reads.
    pub grows_by: usize,
}

impl StubObject {
    pub fn new(bytes: Vec<u8>) -> StubObject {
        StubObject { bytes, grows_by: 0 }
    }
}

/// What the provider sent for one read, as the host saw it.
#[derive(Clone, Debug, PartialEq)]
pub struct ReadRecord {
    pub resource: String,
    pub chunks: usize,
    pub bytes: usize,
    pub result: Result<(), BusError>,
}

/// `capabilities.request`: a grant only if the test policy allows every
/// requested action on exactly this resource.
pub fn request_grant(
    state: &mut HostState,
    resource: String,
    actions: Vec<String>,
) -> Result<Grant, BusError> {
    let allowed = state
        .policy
        .iter()
        .any(|(allowed_resource, allowed_actions)| {
            *allowed_resource == resource
                && actions
                    .iter()
                    .all(|action| allowed_actions.contains(action))
        });
    if !allowed || actions.is_empty() {
        return Err(BusError::Denied(format!(
            "no policy allows {actions:?} on {resource}"
        )));
    }
    state.next_id += 1;
    let grant = Grant {
        id: format!("grant:{}", state.next_id),
        resource,
        actions,
        expires_at_ms: None,
    };
    state.grants.push(grant.clone());
    Ok(grant)
}

/// The guest's `params` for a read: `{"max_bytes": N}`, nothing else.
fn guest_cap(params: &[u8]) -> Result<usize, BusError> {
    let bad =
        |why: &str| BusError::Invalid(format!("read params {why}; expected {{\"max_bytes\": N}}"));
    let value: serde_json::Value =
        serde_json::from_slice(params).map_err(|_| bad("are not JSON"))?;
    let object = value.as_object().ok_or_else(|| bad("are not an object"))?;
    if object.len() != 1 {
        return Err(bad("have other keys"));
    }
    let cap = object
        .get("max_bytes")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| bad("have no whole max_bytes"))?;
    if cap == 0 {
        return Err(bad("ask for 0 bytes"));
    }
    Ok(usize::try_from(cap).unwrap_or(usize::MAX))
}

/// A read that passed every check, ready to stream.
pub struct Read {
    pub resource: String,
    pub object: StubObject,
    pub cap: usize,
    pub audit: String,
}

/// Checks a `read` and returns what to stream, or the refusal.
pub fn start_read(
    state: &mut HostState,
    request: InvokeRequest,
    has_body: bool,
) -> Result<Read, BusError> {
    if request.operation != "read" {
        return Err(BusError::Invalid(format!(
            "operation {:?}; this provider only reads",
            request.operation
        )));
    }
    if has_body {
        return Err(BusError::Invalid("a read takes no body".into()));
    }
    let grant_id = request
        .grant
        .ok_or_else(|| BusError::Denied(format!("reading {} needs a grant", request.resource)))?;
    let grant = state
        .grants
        .iter()
        .find(|grant| grant.id == grant_id)
        .ok_or_else(|| BusError::Denied(format!("{grant_id} is not a grant this guest holds")))?;
    if grant.resource != request.resource {
        return Err(BusError::Denied(format!(
            "{grant_id} is for {}, not {}",
            grant.resource, request.resource
        )));
    }
    if !grant.actions.iter().any(|action| action == "read") {
        return Err(BusError::Denied(format!("{grant_id} does not allow read")));
    }
    let guest_cap = guest_cap(&request.params)?;
    let cap = if state.ignore_guest_cap {
        state.max_read_bytes
    } else {
        guest_cap.min(state.max_read_bytes)
    };
    let object = state
        .objects
        .get(&request.resource)
        .cloned()
        .ok_or_else(|| BusError::NotFound(format!("no object {}", request.resource)))?;
    if object.bytes.len() > cap {
        return Err(BusError::Invalid(format!(
            "object is {} bytes, over the cap of {cap}",
            object.bytes.len()
        )));
    }
    state.next_id += 1;
    Ok(Read {
        resource: request.resource,
        object,
        cap,
        audit: format!("read:{}", state.next_id),
    })
}

/// Streams a read in chunks, then resolves the trailing future.
pub struct ObjectStream {
    read: Read,
    sent: usize,
    chunks: usize,
    done: Option<oneshot::Sender<Result<(), BusError>>>,
}

impl ObjectStream {
    pub fn new(read: Read, done: oneshot::Sender<Result<(), BusError>>) -> ObjectStream {
        ObjectStream {
            read,
            sent: 0,
            chunks: 0,
            done: Some(done),
        }
    }

    fn finish(&mut self, state: &mut HostState, result: Result<(), BusError>) {
        state.reads.push(ReadRecord {
            resource: self.read.resource.clone(),
            chunks: self.chunks,
            bytes: self.sent,
            result: result.clone(),
        });
        if let Some(done) = self.done.take() {
            let _ = done.send(result);
        }
    }
}

impl StreamProducer<HostState> for ObjectStream {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut store: StoreContextMut<'a, HostState>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        _finish: bool,
    ) -> Poll<Result<StreamResult>> {
        let this = &mut *self;
        let total = this.read.object.bytes.len() + this.read.object.grows_by;
        if this.sent >= total {
            this.finish(store.data_mut(), Ok(()));
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        let want = READ_CHUNK.min(total - this.sent).min(
            destination
                .remaining(&mut store)
                .unwrap_or(READ_CHUNK)
                .max(1),
        );
        if this.sent + want > this.read.cap {
            // Never end short with ok: stop here, and say why.
            let cap = this.read.cap;
            this.finish(
                store.data_mut(),
                Err(BusError::Invalid(format!(
                    "object grew past the cap of {cap} bytes while it was read"
                ))),
            );
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        let bytes = this.read.object.bytes.as_slice();
        let chunk: Vec<u8> = (this.sent..this.sent + want)
            .map(|at| bytes.get(at).copied().unwrap_or(0xA5))
            .collect();
        this.sent += want;
        this.chunks += 1;
        destination.set_buffer(VecBuffer::from(chunk));
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

impl Drop for ObjectStream {
    fn drop(&mut self) {
        // The guest dropped the stream before the end: the read did not
        // complete, and the trailing future says so.
        if let Some(done) = self.done.take() {
            let _ = done.send(Err(BusError::Unavailable(
                "the read was not completed".into(),
            )));
        }
    }
}
