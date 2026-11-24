//! Guest-visible streaming of a windowed read.
//!
//! The sync bridge returns bytes it has already buffered. This module reads
//! those bytes in windows and can show them to a guest as a stream. It does
//! not stream a provider that has not buffered the object. The trailer is the
//! only success. An object over the cap never opens a chunk.

use std::pin::Pin;
use std::task::{Context, Poll};

use wasmtime::component::{Destination, StreamProducer, StreamResult, VecBuffer};
use wasmtime::StoreContextMut;

/// Bytes one bridge window, and later one guest chunk, may hold.
pub(crate) const READ_CHUNK: usize = 64 * 1024;
/// The host cap on one read, whatever the guest asks for.
pub(crate) const HOST_MAX_READ_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct PreparedRead {
    pub bytes: Vec<u8>,
    pub audit: Option<String>,
}

pub(crate) enum CapFail<E> {
    Over { len: usize, cap: usize },
    Window(E),
}

/// The guest's `params`: `{"max_bytes": N}` and nothing else, then the host cap.
pub(crate) fn read_cap(params: &[u8]) -> Result<usize, String> {
    let bad = |why: &str| format!("read params {why}; expected {{\"max_bytes\": N}}");
    let value: serde_json::Value =
        serde_json::from_slice(params).map_err(|_| bad("are not JSON"))?;
    let object = value.as_object().ok_or_else(|| bad("are not an object"))?;
    if object.len() != 1 {
        return Err(bad("have other keys"));
    }
    let cap = object
        .get("max_bytes")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| bad("have no whole max_bytes"))?;
    if cap == 0 {
        return Err(bad("ask for 0 bytes"));
    }
    Ok(usize::try_from(cap)
        .unwrap_or(usize::MAX)
        .min(HOST_MAX_READ_BYTES))
}

/// Read windows until the object ends. One size check: over the cap, no bytes
/// are returned, so the caller opens no chunk.
pub(crate) fn collect_under_cap<E>(
    cap: usize,
    mut read_window: impl FnMut(u64, u64) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, CapFail<E>> {
    let mut got = Vec::new();
    loop {
        let room = cap.saturating_add(1).saturating_sub(got.len());
        if room == 0 {
            break;
        }
        let ask = READ_CHUNK.min(room);
        let window = read_window(got.len() as u64, ask as u64).map_err(CapFail::Window)?;
        if window.is_empty() || window.len() < ask {
            got.extend_from_slice(&window);
            break;
        }
        got.extend_from_slice(&window);
    }
    if got.len() > cap {
        Err(CapFail::Over {
            len: got.len(),
            cap,
        })
    } else {
        Ok(got)
    }
}

pub(crate) struct WindowRead {
    bytes: Vec<u8>,
    sent: usize,
    done: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

impl WindowRead {
    pub(crate) fn new(
        bytes: Vec<u8>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) -> Self {
        Self {
            bytes,
            sent: 0,
            done: Some(done),
        }
    }

    /// The next guest-visible chunk. `None` ends the stream and resolves the trailer.
    pub(crate) fn pull(&mut self, limit: usize) -> Option<Vec<u8>> {
        if self.sent >= self.bytes.len() {
            self.end_trailer();
            return None;
        }
        let want = chunk_len(self.bytes.len() - self.sent, limit);
        let end = self.sent + want;
        let chunk = self.bytes[self.sent..end].to_vec();
        self.sent = end;
        Some(chunk)
    }

    fn end_trailer(&mut self) {
        let result = if self.sent != self.bytes.len() {
            Err(format!(
                "read ended after {} of {} bytes; the trailer is not ok",
                self.sent,
                self.bytes.len()
            ))
        } else {
            Ok(())
        };
        if let Some(done) = self.done.take() {
            let _ = done.send(result);
        }
    }
}

/// How many buffered bytes the next guest-visible chunk may carry.
fn chunk_len(left: usize, limit: usize) -> usize {
    left.min(limit.max(1)).min(READ_CHUNK)
}

impl Drop for WindowRead {
    fn drop(&mut self) {
        if self.done.is_some() {
            self.end_trailer();
        }
    }
}

impl<D> StreamProducer<D> for WindowRead {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        mut store: StoreContextMut<'a, D>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        _: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let limit = destination.remaining(&mut store).unwrap_or(usize::MAX);
        match self.get_mut().pull(limit) {
            Some(chunk) => {
                destination.set_buffer(VecBuffer::from(chunk));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            None => Poll::Ready(Ok(StreamResult::Dropped)),
        }
    }
}
