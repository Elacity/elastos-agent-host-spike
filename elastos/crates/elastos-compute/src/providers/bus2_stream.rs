//! Guest-visible streaming of one bounded read.
//!
//! The sync bridge returns bytes it has already buffered. This module asks
//! for that object once, up to the host cap, and can show the bytes to a
//! guest as a stream. The trailer is the only success. An object over the
//! cap never opens a chunk.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use wasmtime::component::{Destination, StreamProducer, StreamResult, VecBuffer};
use wasmtime::StoreContextMut;

/// Bytes one guest chunk may hold. The bridge call itself asks once.
pub(crate) const READ_CHUNK: usize = 64 * 1024;
/// The host cap on one read, and on every read in this process together.
pub(crate) const HOST_MAX_READ_BYTES: usize = 16 * 1024 * 1024;

static HOST_READ_HELD: AtomicUsize = AtomicUsize::new(0);

/// Bytes this process is keeping for reads that are still open.
#[derive(Debug)]
pub(crate) struct ReadHold {
    bytes: usize,
}

impl ReadHold {
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self { bytes: 0 }
    }

    /// Reserves `bytes` against the host cap. `None` means the cap is already
    /// in use, so the caller makes no bridge call.
    pub(crate) fn try_reserve(bytes: usize) -> Option<Self> {
        let mut held = HOST_READ_HELD.load(Ordering::Acquire);
        loop {
            let next = held.checked_add(bytes)?;
            if next > HOST_MAX_READ_BYTES {
                return None;
            }
            match HOST_READ_HELD.compare_exchange_weak(
                held,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self { bytes }),
                Err(current) => held = current,
            }
        }
    }

    /// Keeps `bytes` and releases the rest, so a short object leaves room.
    pub(crate) fn shrink(&mut self, bytes: usize) {
        if bytes >= self.bytes {
            return;
        }
        let release = self.bytes - bytes;
        HOST_READ_HELD.fetch_sub(release, Ordering::AcqRel);
        self.bytes = bytes;
    }
}

impl Drop for ReadHold {
    fn drop(&mut self) {
        if self.bytes > 0 {
            HOST_READ_HELD.fetch_sub(self.bytes, Ordering::AcqRel);
            self.bytes = 0;
        }
    }
}

#[derive(Debug)]
pub(crate) struct PreparedRead {
    pub bytes: Vec<u8>,
    pub audit: Option<String>,
    pub hold: ReadHold,
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

pub(crate) struct WindowRead {
    bytes: Vec<u8>,
    sent: usize,
    done: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    _hold: ReadHold,
}

impl WindowRead {
    pub(crate) fn new(
        bytes: Vec<u8>,
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
        hold: ReadHold,
    ) -> Self {
        Self {
            bytes,
            sent: 0,
            done: Some(done),
            _hold: hold,
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
