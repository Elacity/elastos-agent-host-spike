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
5. **Start-up fuel differs by platform, so it has its own budget.**
   - The same guest source compiles to different bytes on the Mac and on Linux; this is known.
   - Instantiation used 1 unit of fuel here, and more than 10,000 on the Mac.
   - A per-tick budget that started before instantiation made a test pass here and fail there.
   - Now:
     - instantiation runs on its own budget (`instantiate_fuel`), and the run's budget starts just before
       `lifecycle.run`;
     - a trap during instantiation is a named ending (`fuel-exhausted`, or `trapped` with its cause), with
       `started: false`, never a bare error.
   - Found by Cursor's Mac run of `938b8e0f`.
6. **There is no host-side cancel that the guest sees.**
   - "Cancel" here means the host stops driving the `run` call and drops the store.
   - The guest gets no signal and no reason.

### The draft interface, from the guest side

1. **Two ways to stop: `event.stop-requested` and closing the events stream.**
   - The close already covers stopping, and only the close is enforced: a guest that ignores
     `stop-requested`, or ignores both, is still ended by the grace cancel or the epoch deadline.
   - `stop_requested_adds_nothing_the_close_cannot_do` shows this.
   - **Recommendation: drop `stop-requested`, so there is one way to stop.**
2. **`providers.invoke` has three places a read can fail, and the guest must watch all three.**
   - The outer `result`: refused before any byte (no grant, over the cap, not found).
   - The trailing `future<result>`: failed while streaming, for example an object that grew past the cap.
   - The `invoke-status.status` string, which says nothing the other two do not. The guest ignores it.
   - Because only the trailing future says whether the bytes are the object, the guest must hold the whole
     read (up to its cap) before it can use any of it. A streaming consumer, such as a decoder, cannot start
     safely.
3. **No size before the stream.** `invoke-status` has no length. A guest cannot refuse a too-large object
   itself before bytes arrive. It relies on the host refusing up front, and counts what arrives as a second
   check (`a_guest_refuses_more_bytes_than_it_asked_for_even_if_they_arrive`).
4. **`params: list<u8>` is untyped.** The cap travels as JSON (`{"max_bytes": N}`) by an agreement between
   this guest and this stub. Nothing in the interface says so, so every provider and guest pair must agree
   out of band.
5. **The grant id and the resource travel separately.** `invoke-request` carries both `resource` and
   `grant`. The host must check that they match (it does, and a falsifier pins that check). A grant id alone
   would name the resource already.
6. **`body: option<stream<u8>>` on a read** is unused, and must be refused if present.
7. **`ui.present` takes opaque bytes and a media-type string.**
   - To know which grants a frame uses, the host must parse the document.
   - To keep it declarative, the host must also scan it for keys that would make it more than a description
     (`script`, `on*`, `html`, `src`, `uri`).
   - The host here does both, with a strict typed parse and duplicate keys refused.
   - Every host would need the same parser and the same blocklist, and a blocklist is the weak form of
     "no script".
   - A typed document in WIT (`variant node { text(string), image(grant-id) }`) would make script, URIs and
     bytes impossible to express, rather than refused.
8. **`credential.signer` carries no trust** (review change 3).
   - The guest verifies with the key pinned in its manifest, never with a key the credential names.
   - It compares `signer` with the pinned did:key only as a label. A credential with the right signer string
     and a signature by another key is refused, and so is one with another signer string and a signature by
     the pinned key.
   - **Recommendation:** make `signer` a key id that picks one of the keys pinned in the manifest, so a
     manifest can pin the current key and the next one and a publisher can rotate without a guest trusting
     anything new. If only one key may ever be pinned, drop the field instead.
9. **The signed message is not part of the interface.**
   - The guest checks `"elastos:bus2-proof:credential:v1\n" + kind + "\n" + subject-sha256`
     (review change 1).
   - That format is an agreement between this guest and its publisher. The draft names `body: list<u8>`
     and says nothing about what it signs.
   - Every guest would invent its own message, and a signature made for one purpose could be offered for
     another. Tests show that a signature by the pinned key over the same hash, with another kind, another
     tag or no kind, is refused.
   - **Recommendation:** define the signed message (domain tag, kind, subject) and the signature scheme in
     the interface, and type `body` as that signature.
10. **`subject-sha256: string`** leaves the encoding open (hex, which case). 32 bytes (`list<u8>`, or a
    fixed-size type) would leave nothing to agree on.
11. **A frame on screen can name a grant that is later revoked.** The draft has `event.grant-revoked`, but
   nothing says what happens to a frame already drawn with that grant. The stub refuses a new frame that
   names a revoked grant. Whether the host must also clear the old frame is unstated.

## Proofs done

| Proof | Tests | Falsifiers |
|---|---|---|
| 5. Admission-like import check | 7 (`tests/admission.rs`) | 7 |
| 1. Resident guest, stop by close, named endings | 10 (`tests/lifecycle.rs`) | 11 |
| 2. Streaming read under a cap, refused not truncated | 7 (`tests/streaming.rs`) | 8 |
| 3. `ui.present` draws one declarative frame, images by grant | 6 (`tests/ui.rs`) | 7 |
| 4. Credential pinned in the guest's manifest; refuse only; no frame before the check | 7 (`tests/credentials.rs`) | 8 |

The read path:
- the guest asks for a grant on exactly the photo's URI;
- the stub issues it only if the test policy allows it;
- `read` checks the grant: it is held, it is for this resource, and it allows `read`;
- the cap is the smaller of the guest's (from its manifest, sent in `params`) and the host's own;
- the object is streamed in 64 KiB chunks.

Endings recorded: `stopped`, `returned`, `returned-error`, `cancelled-after-grace`, `epoch-deadline`,
`fuel-exhausted`, `trapped`.
