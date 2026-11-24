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
use std::time::{Duration, Instant};

use wasmtime::component::{Destination, StreamProducer, StreamResult, VecBuffer};
use wasmtime::StoreContextMut;

/// Bytes one guest chunk may hold. The bridge call itself asks once.
pub(crate) const READ_CHUNK: usize = 64 * 1024;
/// The host cap on one read, and on every read one provider holds together.
pub(crate) const HOST_MAX_READ_BYTES: usize = 16 * 1024 * 1024;

/// How long one open read may keep its reservation. A guest that never pulls
/// still loses it, so the next guest can read. Dropping the stream releases
/// sooner. Tests use a short bound; a running Home uses 30s.
#[cfg(test)]
pub(crate) const READ_HOLD_LIMIT: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const READ_HOLD_LIMIT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct Slot {
    bytes: AtomicUsize,
    /// When the guest received the bytes. The fetch itself does not spend this.
    started: Mutex<Instant>,
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

fn reap(ledger: &mut Ledger) {
    let mut expired = Vec::new();
    ledger.open.retain(|weak| {
        let Some(slot) = weak.upgrade() else {
            return false;
        };
        let age = slot.started.lock().expect("hold start").elapsed();
        if slot.released.load(Ordering::Relaxed) || age >= READ_HOLD_LIMIT {
            expired.push(slot);
            return false;
        }
        true
    });
    for slot in expired {
        release(ledger, &slot);
    }
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
                started: Mutex::new(Instant::now()),
                released: AtomicBool::new(true),
            }),
            budget: ReadBudget::new(),
        }
    }

    /// Reserves `bytes` against this provider's cap. `None` means that cap is
    /// already in use, so the caller makes no bridge call. A reservation older
    /// than [`READ_HOLD_LIMIT`] is released here first.
    pub(crate) fn try_reserve(budget: &Arc<ReadBudget>, bytes: usize) -> Option<Self> {
        let mut ledger = budget.inner.lock().expect("read ledger");
        reap(&mut ledger);
        let next = ledger.held.checked_add(bytes)?;
        if next > HOST_MAX_READ_BYTES {
            return None;
        }
        ledger.held = next;
        let slot = Arc::new(Slot {
            bytes: AtomicUsize::new(bytes),
            started: Mutex::new(Instant::now()),
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

    /// The guest has the bytes. The hold bound runs from here, not from the fetch.
    pub(crate) fn arm(&mut self) {
        let _ledger = self.budget.inner.lock().expect("read ledger");
        *self.slot.started.lock().expect("hold start") = Instant::now();
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
pub(crate) fn read_cap(params: &[u8]) -> Result<usize, String> {
    let bad = |why: &str| format!("read params {why}; expected {{\"max_bytes\": N}}");
    // Same depth cap as a UI document, before serde_json parses.
    if let Err(err) = super::bus2_ui::reject_guest_json(params) {
        if err.contains("depth cap") {
            return Err(bad("are nested past the depth cap"));
        }
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
