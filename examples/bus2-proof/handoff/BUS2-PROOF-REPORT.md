# Bus v2 guest-side proof: report (in progress)

Written as each step lands. Steps 1 to 3 are in; the measurements, the remaining proofs and the final
recommendations come in step 7.

## Findings so far

### Wasmtime 48 and wit-bindgen 0.60

1. **They fit, pinned to the same wasm-tools line.**
   - wit-bindgen `=0.60.0` and Wasmtime `=48.0.7` both build on wasm-tools `0.254`.
   - The draft WIT compiled on both sides with no change.
   - The guest's `async fn run(StreamReader<Event>)` and the host's `Accessor`-based imports matched on the
     first try.
2. **Host imports for `async func` must take the store** (`&Accessor<T, Self>`, in a `HostWithStore<T>`
   trait), even when they only touch the guest's own state. A plain `&mut self` is not offered for them.
3. **Fuel cannot be refilled into running code from the epoch callback.**
   - While a guest runs, Wasmtime 48 keeps the fuel count inside the compiled code.
   - `set_fuel` in the callback updates the store, but the running loop does not see it: the store still
     read exactly what the callback had set at the previous tick.
   - **What works:** `fuel_async_yield_interval`. The guest yields after each fuel slice and takes the next
     slice from the store's reserve, which the epoch callback does refill.
   - The test `a_busy_guest_that_yields_each_slice_can_still_be_cancelled` and its falsifier pin this.
4. **The host's own code inside `run_concurrent` is not polled while a guest always has work ready.**
   - A grace timer placed inside the `run_concurrent` closure never fired against a busy guest.
   - Tasks outside the store did run on time (fuel yields do reach the executor).
   - So the stop logic (driver and grace timer) sits outside `run_concurrent`.
5. **There is no host-side cancel that the guest sees.**
   - "Cancel" here means the host stops driving the `run` call and drops the store.
   - The guest gets no signal and no reason.

### The draft interface, from the guest side

1. **Two ways to stop: `event.stop-requested` and closing the events stream.**
   - The close already covers stopping, and only the close is enforced: a guest that ignores
     `stop-requested`, or ignores both, is still ended by the grace cancel or the epoch deadline.
   - `stop_requested_adds_nothing_the_close_cannot_do` shows this.
   - **Recommendation: drop `stop-requested`, so there is one way to stop.**

## Proofs done

| Proof | Tests | Falsifiers |
|---|---|---|
| 5. Admission-like import check | 7 (`tests/admission.rs`) | 7 |
| 1. Resident guest, stop by close, named endings | 8 (`tests/lifecycle.rs`) | 9 |

Endings recorded: `stopped`, `returned`, `returned-error`, `cancelled-after-grace`, `epoch-deadline`,
`fuel-exhausted`, `trapped`.
