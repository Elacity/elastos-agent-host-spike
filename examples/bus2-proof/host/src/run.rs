//! Running a resident guest, and how a run ends.
//!
//! The host asks a guest to stop in one way: it closes the events stream.
//! If the guest has not returned within the grace period, the host cancels
//! the call (it stops driving it and drops the store). A guest that keeps
//! executing is ended by the epoch deadline. Every run records one `Ending`.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use wasmtime::component::{Component, Destination, StreamProducer, StreamReader, StreamResult};
use wasmtime::{Engine, Result, Store, StoreContextMut, UpdateDeadline};

use crate::{linker, BusError, Event, HostState, ProductCapsuleV2};

/// Time and fuel a run may use.
#[derive(Clone, Debug)]
pub struct Limits {
    /// How long a guest has to return after its events close.
    pub grace: Duration,
    /// The longest a run may last, in epoch ticks (the `Ticker`'s period).
    pub max_ticks: u64,
    /// Fuel a guest may use between two epoch ticks. The epoch callback
    /// refills the store to this amount at every tick; using more than this
    /// before the next tick ends the run (`fuel-exhausted`).
    pub fuel_per_tick: u64,
    /// A running guest yields to the executor after every `fuel_slice` units
    /// of fuel, and takes its next slice from what is left of `fuel_per_tick`.
    pub fuel_slice: u64,
    /// Whether a running guest also yields to the executor at every tick.
    pub yield_each_tick: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            grace: Duration::from_millis(300),
            max_ticks: 500,
            fuel_per_tick: 10_000_000_000,
            fuel_slice: 10_000_000,
            yield_each_tick: true,
        }
    }
}

/// How a run ended. One per run.
#[derive(Debug, Clone, PartialEq)]
pub enum Ending {
    /// Returned `ok` after its events were closed.
    Stopped,
    /// Returned `ok` before its events were closed.
    Returned,
    /// Returned `err(bus-error)`.
    ReturnedError(BusError),
    /// Had not returned when the grace period after the close ran out; the
    /// host cancelled the call.
    CancelledAfterGrace,
    /// Was still executing at the epoch deadline.
    EpochDeadline,
    /// Used up its fuel inside one slice.
    FuelExhausted,
    /// Any other trap.
    Trapped(String),
}

impl Ending {
    pub fn reason(&self) -> &'static str {
        match self {
            Ending::Stopped => "stopped",
            Ending::Returned => "returned",
            Ending::ReturnedError(_) => "returned-error",
            Ending::CancelledAfterGrace => "cancelled-after-grace",
            Ending::EpochDeadline => "epoch-deadline",
            Ending::FuelExhausted => "fuel-exhausted",
            Ending::Trapped(_) => "trapped",
        }
    }
}

/// The result of a run: how it ended, and what the host saw.
pub struct Outcome {
    pub ending: Ending,
    pub state: HostState,
}

/// The host's write end of a guest's events. Dropping it closes the stream,
/// which is how the host asks the guest to stop.
pub struct Events(UnboundedSender<Event>);

impl Events {
    pub fn send(&self, event: Event) {
        let _ = self.0.send(event);
    }
}

/// Feeds events to a guest; the end of the channel closes the stream.
struct EventFeed(UnboundedReceiver<Event>);

impl<D> StreamProducer<D> for EventFeed {
    type Item = Event;
    type Buffer = Option<Event>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _store: StoreContextMut<'a, D>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<Result<StreamResult>> {
        match self.0.poll_recv(cx) {
            Poll::Ready(Some(event)) => {
                destination.set_buffer(Some(event));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Ready(None) => Poll::Ready(Ok(StreamResult::Dropped)),
            Poll::Pending if finish => Poll::Ready(Ok(StreamResult::Cancelled)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The epoch deadline was reached.
#[derive(Debug)]
struct DeadlineReached;

impl std::fmt::Display for DeadlineReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the run reached its epoch deadline")
    }
}

impl std::error::Error for DeadlineReached {}

fn ending_of_trap(error: wasmtime::Error) -> Ending {
    if error.downcast_ref::<DeadlineReached>().is_some() {
        return Ending::EpochDeadline;
    }
    if let Some(wasmtime::Trap::OutOfFuel) = error.downcast_ref::<wasmtime::Trap>() {
        return Ending::FuelExhausted;
    }
    Ending::Trapped(format!("{error:#}"))
}

/// Runs `lifecycle.run` with a fresh events stream, while `drive` sends
/// events. When `drive` returns, the events are closed and the grace period
/// starts. The `Ticker` must be running on `engine`.
pub async fn run_resident(
    engine: &Engine,
    component: &Component,
    state: HostState,
    limits: Limits,
    drive: impl AsyncFnOnce(Events),
) -> Result<Outcome> {
    let linker = linker(engine)?;
    let mut store = Store::new(engine, state);
    // Fuel set from the epoch callback does not reach code that is already
    // running (Wasmtime 48 keeps the running count in the compiled code), so
    // a slice ends by fuel: the guest yields, and takes its next slice from
    // the store's reserve, which the epoch callback refills.
    store.set_fuel(limits.fuel_per_tick)?;
    store.fuel_async_yield_interval(Some(limits.fuel_slice))?;
    store.set_epoch_deadline(1);
    let (max_ticks, fuel, yield_each_tick) = (
        limits.max_ticks,
        limits.fuel_per_tick,
        limits.yield_each_tick,
    );
    let mut ticks = 0u64;
    store.epoch_deadline_callback(move |mut context| {
        ticks += 1;
        if ticks > max_ticks {
            return Err(wasmtime::Error::new(DeadlineReached));
        }
        context.set_fuel(fuel)?;
        Ok(if yield_each_tick {
            UpdateDeadline::Yield(1)
        } else {
            UpdateDeadline::Continue(1)
        })
    });

    let world = ProductCapsuleV2::instantiate_async(&mut store, component, &linker).await?;
    let (sender, receiver) = unbounded_channel();
    let events = StreamReader::new(&mut store, EventFeed(receiver))?;
    let grace = limits.grace;

    // The driver and the grace timer sit outside `run_concurrent`: while a
    // guest always has work ready, Wasmtime 48 does not poll the host closure
    // inside `run_concurrent`, so a timer there would never fire.
    let ending = {
        let run = store.run_concurrent(async move |accessor| {
            world
                .elastos_bus_lifecycle()
                .call_run(accessor, events)
                .await
        });
        tokio::pin!(run);
        let drive = drive(Events(sender));
        tokio::pin!(drive);
        let mut closed = false;
        loop {
            tokio::select! {
                ran = &mut run => {
                    break match ran.and_then(|returned| returned) {
                        Ok(Ok(())) if closed => Ending::Stopped,
                        Ok(Ok(())) => Ending::Returned,
                        Ok(Err(error)) => Ending::ReturnedError(error),
                        Err(error) => ending_of_trap(error),
                    };
                }
                () = &mut drive, if !closed => {
                    // `drive` dropped its `Events`: the stream is closed.
                    closed = true;
                }
                () = tokio::time::sleep(grace), if closed => {
                    // Cancel: stop driving the call. It is dropped below.
                    break Ending::CancelledAfterGrace;
                }
            }
        }
    };
    // A cancelled call leaves work in the store; the store is dropped here
    // and only its data is kept.
    Ok(Outcome {
        ending,
        state: store.into_data(),
    })
}
