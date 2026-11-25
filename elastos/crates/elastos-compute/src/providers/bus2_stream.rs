//! Guest-visible streaming of one bounded read.
//!
//! The sync bridge returns bytes it has already buffered. This module asks
//! for that object once, up to the host cap, and can show the bytes to a
//! guest as a stream. The trailer is the only success. An object over the
//! cap never opens a chunk.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use wasmtime::component::{Destination, StreamProducer, StreamResult, VecBuffer};
use wasmtime::StoreContextMut;

/// Bytes one guest chunk may hold. The bridge call itself asks once.
pub(crate) const READ_CHUNK: usize = 64 * 1024;
/// The host cap on one read, and on every read one provider holds together.
pub(crate) const HOST_MAX_READ_BYTES: usize = 16 * 1024 * 1024;
/// How many reads one provider may hold open. Each hold is its own allocation,
/// so a count is capped as well as the bytes.
const MAX_OPEN_HOLDS: usize = 256;

#[derive(Debug)]
struct Slot {
    bytes: AtomicUsize,
    released: AtomicBool,
}

#[derive(Debug)]
struct Ledger {
    held: usize,
    open: Vec<Weak<Slot>>,
}

/// One provider's read budget. A new provider starts empty, so two providers
/// do not refuse each other's guests.
#[derive(Debug)]
pub(crate) struct ReadBudget {
    inner: Mutex<Ledger>,
}

impl ReadBudget {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Ledger {
                held: 0,
                open: Vec::new(),
            }),
        })
    }
}

fn release(ledger: &mut Ledger, slot: &Slot) {
    if slot.released.swap(true, Ordering::Relaxed) {
        return;
    }
    let bytes = slot.bytes.swap(0, Ordering::Relaxed);
    ledger.held = ledger.held.saturating_sub(bytes);
}

/// Bytes this provider is keeping for reads that are still open.
#[derive(Debug)]
pub(crate) struct ReadHold {
    slot: Arc<Slot>,
    budget: Arc<ReadBudget>,
}

impl ReadHold {
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            slot: Arc::new(Slot {
                bytes: AtomicUsize::new(0),
                released: AtomicBool::new(true),
            }),
            budget: ReadBudget::new(),
        }
    }

    /// Reserves `bytes` against this provider's cap. `None` means that cap is
    /// already in use, so the caller makes no bridge call. The bytes stay
    /// counted until this hold is dropped.
    pub(crate) fn try_reserve(budget: &Arc<ReadBudget>, bytes: usize) -> Option<Self> {
        let mut ledger = budget.inner.lock().expect("read ledger");
        ledger.open.retain(|weak| weak.strong_count() > 0);
        if ledger.open.len() >= MAX_OPEN_HOLDS {
            return None;
        }
        let next = ledger.held.checked_add(bytes)?;
        if next > HOST_MAX_READ_BYTES {
            return None;
        }
        ledger.held = next;
        let slot = Arc::new(Slot {
            bytes: AtomicUsize::new(bytes),
            released: AtomicBool::new(false),
        });
        ledger.open.push(Arc::downgrade(&slot));
        Some(Self {
            slot,
            budget: budget.clone(),
        })
    }

    /// Keeps `bytes` and releases the rest, so a short object leaves room.
    pub(crate) fn shrink(&mut self, bytes: usize) {
        let mut ledger = self.budget.inner.lock().expect("read ledger");
        if self.slot.released.load(Ordering::Relaxed) {
            return;
        }
        let current = self.slot.bytes.load(Ordering::Relaxed);
        if bytes >= current {
            return;
        }
        self.slot.bytes.store(bytes, Ordering::Relaxed);
        ledger.held = ledger.held.saturating_sub(current - bytes);
    }
}

impl Drop for ReadHold {
    fn drop(&mut self) {
        let mut ledger = self.budget.inner.lock().expect("read ledger");
        release(&mut ledger, &self.slot);
    }
}

#[derive(Debug)]
pub(crate) struct PreparedRead {
    pub bytes: Vec<u8>,
    pub audit: Option<String>,
    pub hold: ReadHold,
}

/// The guest's `params`: `{"max_bytes": N}` and nothing else, then the host cap.
/// Params are a few bytes. A larger document is refused before the scan.
pub(crate) const READ_PARAMS_MAX: usize = 256;

pub(crate) fn read_cap(params: &[u8]) -> Result<usize, String> {
    let bad = |why: &str| format!("read params {why}; expected {{\"max_bytes\": N}}");
    if params.len() > READ_PARAMS_MAX {
        return Err(bad("are over 256 bytes"));
    }
    // Same depth cap as a UI document, before serde_json parses.
    // Every scan error is a refusal, including a duplicate or a broken key.
    if let Err(err) = super::bus2_ui::reject_guest_json(params) {
        return Err(bad(&err));
    }
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
    /// Checked before each further chunk. A revoke or a stop ends the stream
    /// and the trailer is an error, because the guest did not receive `bytes`.
    stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
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
            stop: None,
        }
    }

    pub(crate) fn stop_when(mut self, stop: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.stop = Some(stop);
        self
    }

    fn stopped(&self) -> bool {
        self.stop.as_ref().is_some_and(|stop| stop())
    }

    /// The next guest-visible chunk. `None` ends the stream and resolves the trailer.
    pub(crate) fn pull(&mut self, limit: usize) -> Option<Vec<u8>> {
        if self.sent >= self.bytes.len() {
            self.end_trailer();
            return None;
        }
        if self.stopped() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_hundred_fifty_seventh_one_byte_hold_is_refused() {
        let budget = Arc::new(ReadBudget::new());
        let mut holds = Vec::new();
        for _ in 0..MAX_OPEN_HOLDS {
            holds.push(ReadHold::try_reserve(&budget, 1).expect("a hold inside the cap"));
        }
        assert!(
            ReadHold::try_reserve(&budget, 1).is_none(),
            "one more hold was accepted"
        );
        holds.pop();
        assert!(ReadHold::try_reserve(&budget, 1).is_some());
    }

    #[test]
    fn a_revoked_grant_stops_the_next_chunk_of_a_16mib_read() {
        let budget = Arc::new(ReadBudget::new());
        let hold = ReadHold::try_reserve(&budget, HOST_MAX_READ_BYTES).expect("the 16 MiB hold");
        let grants = Arc::new(Mutex::new(super::super::bus2_ui::GrantBook::default()));
        assert!(grants
            .lock()
            .expect("grant book")
            .hold("g", "localhost://note", "read"));
        let grants_for_stop = grants.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut stream = WindowRead::new(vec![7u8; HOST_MAX_READ_BYTES], tx, hold).stop_when(
            Arc::new(move || grants_for_stop.lock().expect("grant book").blocks_read("g")),
        );
        let first = stream.pull(READ_CHUNK).expect("the first chunk");
        assert_eq!(first.len(), READ_CHUNK);
        grants.lock().expect("grant book").revoke("g");
        assert!(
            stream.pull(READ_CHUNK).is_none(),
            "a revoked grant gives no more bytes"
        );
        let trailer = rx.blocking_recv().expect("trailer");
        assert!(trailer.is_err(), "the trailer is not ok: {trailer:?}");
        drop(stream);

        let hold = ReadHold::try_reserve(&budget, 8).expect("a small hold");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut stream = WindowRead::new(vec![1u8; 8], tx, hold)
            .stop_when(Arc::new(move || flag.load(Ordering::Acquire)));
        assert!(stream.pull(4).is_some());
        stop.store(true, Ordering::Release);
        assert!(stream.pull(4).is_none(), "a stop gives no more bytes");
        assert!(rx.blocking_recv().expect("trailer").is_err());
    }
}
