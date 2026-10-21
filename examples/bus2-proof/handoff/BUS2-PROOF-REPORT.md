# Bus v2 guest-side proof: report

What this is:
- a test of the **draft** Bus v2 interface (`wit/bus2.wit`, "DRAFT sketch for review, not a frozen ABI")
  from the guest side;
- three small guests, built for `wasm32-unknown-unknown`, run in a stub host inside this folder's tests;
- not a second Bus, and not the Runtime. Nothing outside `examples/bus2-proof` changed.

How to check it:
- `./verify.sh` builds the guests, runs fmt and clippy, all 38 tests and all 42 falsifiers (each falsifier
  breaks one check and requires its test to fail);
- `cargo run --locked --release -p bus2-host --example measure` prints the measurements below.

## Summary

- **All six proofs hold** on the draft WIT, with Wasmtime `=48.0.7` and wit-bindgen `=0.60.0`, with no change
  to the WIT.
- **The draft works, but some operations have more than one path** (two ways to stop, three ways a read can
  fail), and it leaves several formats unstated (`params`, the UI document, the signed credential message).
  The changes I recommend are in [For Anders](#for-anders).
- **Wasmtime 48 needed three workarounds**, all in the host and none in the guest: fuel slices instead of a
  fuel top-up, the stop logic outside `run_concurrent`, and a separate start-up fuel budget.
- **Sizes are small; compiling is the cost.** The photo guest is about 100 KB as a component. Compiling it
  takes about 140 ms here. Loading already-compiled code takes about 0.3 ms.

## Proofs

| Proof | Tests | Falsifiers |
|---|---|---|
| 1. Resident guest: stop by close, grace cancel, epoch backstop, named endings | 10 (`tests/lifecycle.rs`) | 11 |
| 2. `providers.invoke` streams the photo in chunks under a cap; refused, never truncated | 7 (`tests/streaming.rs`) | 8 |
| 3. `ui.present` draws one declarative frame; images by granted handle; no script | 6 (`tests/ui.rs`) | 7 |
| 4. Credential checked against the key pinned in the manifest; the guest only refuses; no frame before the check | 7 (`tests/credentials.rs`) | 8 |
| 5. Admission refuses imports outside `elastos:bus/*@2.0.0`, and v1 and v2 mixed | 7 (`tests/admission.rs`) | 7 |
| 6. Fuel slices plus async yield: a busy guest does not starve a second guest | 1 (`tests/fairness.rs`) | 1, and 1 shared with proof 1 |

Endings the host records, each by name: `stopped`, `returned`, `returned-error`, `cancelled-after-grace`,
`epoch-deadline`, `fuel-exhausted`, `trapped`. An ending also says whether the guest got past start-up.

The read path (proof 2):
- the guest asks for a grant on exactly the photo's URI;
- the stub issues it only if the test policy allows it;
- `read` checks the grant: it is held, it is for this resource, and it allows `read`;
- the cap is the smaller of the guest's (from its manifest, sent in `params`) and the host's own;
- an object over the cap is refused before any byte is sent;
- the object is streamed in 64 KiB chunks;
- an object that grows past the cap while it is read ends with an error on the trailing future, never with a
  short `ok`. The guest also counts what arrives and refuses more than it asked for.

The credential path (proof 4):
- the guest's `capsule.json` pins one publisher key (a did:key) and one credential kind;
- the signature covers `"elastos:bus2-proof:credential:v1\n" + kind + "\n" + subject-sha256`;
- the guest reads the photo, hashes it, and checks the credential **before** it draws. A failed check gives no
  frame;
- a good credential grants nothing: the host gives the same grants with or without it.

Fairness (proof 6), measured in this container:
- a busy guest (a loop that never awaits) and the photo guest share one engine and one single-threaded
  executor;
- the photo guest started 50 ms after the busy one. It read its photo, checked the credential, drew its frame
  and stopped about 55 ms after the start;
- the busy guest ran on, on refilled fuel slices, until its epoch deadline at about 1.02 s.

Each way of yielding is enough on its own for fairness:
- with only the epoch yield, the photo guest still finished in about 68 ms. But the busy guest ran out of fuel
  at about 0.4 s, because the epoch callback's refill does not reach running code (Wasmtime behaviour 1);
- with only the fuel slices, the photo guest finished in about 55 ms.

The falsifier removes both kinds of yield, and then the photo guest waits for the busy one to end. Removing the
refill makes the busy guest end by fuel instead of by its deadline, which the fairness test also catches.

## For Anders

### Wasmtime 48 behaviours found

1. **Fuel cannot be topped up in running code.**
   - `set_fuel` from the epoch callback updates the store, but a guest that is already running does not see
     it. Wasmtime 48 keeps the running count inside the compiled code.
   - What works: `fuel_async_yield_interval`. The guest yields after each fuel slice and takes its next slice
     from the store's reserve, and the epoch callback refills that reserve.
2. **Host code inside `run_concurrent` is starved by a busy guest.**
   - While a guest always has work ready, the closure passed to `run_concurrent` is not polled. A grace timer
     placed there never fired.
   - Tasks outside the store still ran on time, because the fuel yields do reach the executor.
   - So the driver and the grace timer must sit outside `run_concurrent`.
3. **Instantiation cost differs by build machine.**
   - Instantiating the same guest source used 1 unit of fuel here and more than 10,000 on the Mac. The guest
     bytes or the compiled code differ between the two machines; I did not find out which.
   - A budget shared by start-up and running passed here and failed there (found by Cursor's Mac run).
   - So start-up has its own fuel budget, and a trap during start-up is a named ending, never a bare error.
4. **There is no cancel that the guest sees.** To cancel, the host stops driving the `run` call and drops the
   store. The guest gets no signal and no reason. The host records the reason in its ending, which is enough.
5. **Async host imports must take the store.** An `async func` import gets `&Accessor<T, Self>` in a
   `HostWithStore<T>` trait, even when it only touches the guest's own state.
6. **Compiled code is worth caching.** A warm start (load compiled code, then instantiate) took about 0.3 ms;
   a cold start (compile, then instantiate) took 44 to 140 ms here. Loading compiled code trusts its input,
   so such a cache must be one that only the Runtime writes.

### Interface changes I recommend

1. **Drop `event.stop-requested`.** Closing the events stream already means stop, and only the close can be
   enforced. A guest that ignores `stop-requested` is still ended by the grace cancel or the epoch deadline
   (`stop_requested_adds_nothing_the_close_cannot_do`). One way to stop.
2. **Give `providers.invoke` one place to fail after the call starts.** Keep the outer `result` (refused before
   any byte) and the trailing `future<result>` (failed while streaming). Drop the free-form
   `invoke-status.status` string, which says nothing the other two do not.
3. **Put the size in `invoke-status`.** Then a guest can refuse an object that is too large before any byte
   arrives, and a streaming consumer knows when it has everything.
4. **Type `params`.** Today it is `list<u8>`, and the cap travels as JSON by agreement between this guest and
   this stub. A typed record per operation (for `read`: `max-bytes: u64`) needs no agreement.
5. **Let the grant name the resource.** `invoke-request` carries both `resource` and `grant`, so the host must
   check that they match. A grant id alone is enough, and leaves nothing to mismatch.
6. **Drop `body` from a read.** `body: option<stream<u8>>` is unused for `read` and must be refused if present.
   Per-operation requests (point 4) would remove it.
7. **Make the UI document a WIT type.** Today `ui.present` takes opaque bytes and a media-type string. The host
   must parse the bytes and scan them for keys such as `script`, `on*`, `html`, `src` and `uri`, and a
   blocklist is the weak form of "no script". A type such as `variant node { text(string), image(grant-id) }`
   makes script, URIs and bytes impossible to express.
8. **Make `credential.signer` a key id among the pinned keys, or drop it.** It carries no trust: the guest
   verifies with the key pinned in its manifest, never with a key the credential names. A key id lets a
   manifest pin the current key and the next one, so a publisher can rotate keys without a guest trusting
   anything new. If only one key may ever be pinned, drop the field.
9. **Define the signed message in the interface.** That is the domain tag, the kind and the subject, and the
   signature scheme, with `body` typed as that signature. Otherwise every guest invents its own message, and a
   signature made for one purpose can be offered for another. Tests show that a signature by the pinned key
   over the same hash, with another kind, another tag or no kind, is refused here.
10. **Make `subject-sha256` 32 bytes**, not a string. A string leaves the encoding open (hex, and which case).
11. **Say what happens to a frame on screen when its grant is revoked.** The stub refuses a new frame that
    names a revoked grant. Whether the host must also clear the frame already drawn is unstated.

## Measurements

This container: Linux, 4 vCPUs (Intel Xeon), release build of the host. Median of 9 runs. The Mac numbers
will differ, and so may the compiled sizes (Wasmtime behaviour 3).

| Guest | Core module | Component | Compiled code | Cold start | Warm start | Instantiate only |
|---|---|---|---|---|---|---|
| photo | 97,700 B | 102,707 B | 405,096 B | 141.6 ms | 0.31 ms | 0.03 ms |
| resident | 44,305 B | 46,679 B | 202,632 B | 69.3 ms | 0.19 ms | 0.03 ms |
| busy | 28,664 B | 29,942 B | 132,008 B | 44.2 ms | 0.16 ms | 0.03 ms |

- **Core module:** the guest as built by `cargo build --release --target wasm32-unknown-unknown`, with
  `opt-level = "s"`, LTO, one codegen unit, stripped, `panic = "abort"`.
- **Component:** the core module wrapped by `wit-component`, as the host loads it.
- **Compiled code:** Wasmtime's native code for the component (`Component::serialize`).
- **Cold start:** compile the component (`Component::new`), then instantiate it.
- **Warm start:** load the compiled code (`Component::deserialize`), then instantiate it.
- **Instantiate only:** the component already loaded.

The design note asked for cold start "to the first event read". Instantiating takes about 0.03 ms, so cold
start is almost all compile time. A whole job is measured as well: the photo guest, already compiled, is
instantiated, reads a 1 MiB photo in 16 chunks, hashes it, checks its licence, draws a frame and stops, in
**8.6 ms**.

How much of the photo guest is the credential check, measured once in a scratch build with the check removed:
- without the check: 63,097 B;
- with only SHA-256 kept: 68,083 B, so SHA-256 and its hex encoding are about 5 KB;
- the full guest: 97,700 B, so Ed25519 verification is about 30 KB.

The credential check is about a third of the photo guest, and every guest that checks a credential carries
its own copy. A host-side verify import, with the key still chosen from the guest's own manifest, would save
that size, but it is one more import to trust. I would keep the check in the guest for now.

## Versions

- **Pins:** Rust `1.95.0` (in this folder's `rust-toolchain.toml`), Wasmtime `=48.0.7`, wit-bindgen `=0.60.0`,
  wit-component and wasmparser `=0.254.2`, wat `=1.254.2`. `Cargo.lock` is committed and every build uses
  `--locked`.
- **Wasmtime 48.0.7 needs Rust 1.95**, so the toolchain pin follows the Wasmtime pin.
- **wit-bindgen must be on the same wasm-tools line as Wasmtime.** wit-bindgen 0.60 and Wasmtime 48 are both on
  wasm-tools 0.254. wit-bindgen 0.61 moves to 0.258, which would put two wasm-tools lines in one build. I kept
  to one.
- **Wasmtime 48 has its own error type.** Host code that uses `anyhow` needs Wasmtime's `anyhow` feature, and
  host imports return `wasmtime::Result`.
- **The generated types have no `PartialEq`** unless `bindgen!` is asked for it (`additional_derives`).
- **No `wasm-tools` command line is needed.** The host wraps the guest's core module into a component with the
  `wit-component` crate.
- **Wasmtime 50** is the latest release. As agreed in review, this proof stays on 48, the long-term-support
  release. I have not tried 50, so whether behaviours 1 and 2 above differ there is open.

## Other findings

1. **The draft WIT compiled on both sides with no change**, and the guest's `async fn run(StreamReader<Event>)`
   matched the host's import on the first try.
2. **The guest must hold the whole read (up to its cap) before it uses any of it,** because only the trailing
   future says whether the bytes are the whole object. A streaming consumer, such as an image decoder, cannot
   start safely. Recommendations 2 and 3 make this simpler, but a stream that can still fail at the end always
   means "do not commit to the bytes until the end".
3. **The guest still counts what arrives**, even with the host's cap, and refuses more than it asked for
   (`a_guest_refuses_more_bytes_than_it_asked_for_even_if_they_arrive`). The guest does not need to trust the
   host's counting.

## Rules held

- **No new authority:**
  - grants come only from the test policy;
  - a credential only lets the guest refuse, and the host grants nothing on it (a test and a falsifier);
  - the UI document holds grant handles, never bytes or URIs.
- **One path per operation:** an object is read only through `providers.invoke` with a grant; a guest is asked
  to stop only by closing its events stream.
- **Fail closed:** every refusal has a named reason, a test and a falsifier.
- **Only `examples/bus2-proof` changed.** No Runtime change, nothing under `elastos/`, nothing in
  `examples/photo-viewer`.
