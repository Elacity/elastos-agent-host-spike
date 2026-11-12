# Bus v2 guest-side proof: report

What this is:
- a test of the **draft** Bus v2 interface (`wit/bus2.wit`, "DRAFT sketch for review, not a frozen ABI")
  from the guest side;
- four small guests, built for `wasm32-unknown-unknown`, run in a stub host inside this folder's tests;
- not a second Bus, and not the Runtime. Nothing outside `examples/bus2-proof` changed.

How to check it:
- `./verify.sh` builds the guests, runs fmt and clippy, all 41 tests and all 46 falsifiers (each falsifier
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
- **Start-up runs guest code, and is under the same controls as the run.** Codex found that instantiation ran
  before fuel slicing and yield were on, and before the stop driver was polled. A guest whose start-up loops
  could hold up every other guest until its start-up trapped, and could not be stopped. Now start-up is sliced
  and yields like a running guest, on its own fuel budget. It is driven in the same `select` as the stop
  driver and the grace timer, so a stop during start-up ends the run as `cancelled-during-start-up`.
- **Sizes are small; compiling is the cost.** These are measurements on two machines, not guarantees. The photo
  guest is about 100 KB as a component. Compiling it
  takes about 140 ms in this container and about 70 ms on the Mac. Loading already-compiled code takes about
  0.3 ms here and 0.14 ms on the Mac.

## Proofs

| Proof | Tests | Falsifiers |
|---|---|---|
| 1. Resident guest: stop by close, grace cancel, epoch backstop, named endings, during start-up too | 12 (`tests/lifecycle.rs`) | 14 |
| 2. `providers.invoke` streams the photo in chunks under a cap; refused, never truncated | 7 (`tests/streaming.rs`) | 8 |
| 3. `ui.present` draws one declarative frame; images by granted handle; no script | 6 (`tests/ui.rs`) | 7 |
| 4. Credential checked against the key pinned in the manifest; the guest only refuses; no frame before the check | 7 (`tests/credentials.rs`) | 8 |
| 5. Admission refuses imports outside `elastos:bus/*@2.0.0`, and v1 and v2 mixed | 7 (`tests/admission.rs`) | 7 |
| 6. Fuel slices plus async yield: a busy guest, running or still starting up, does not starve a second guest | 2 (`tests/fairness.rs`) | 2, and 1 shared with proof 1 |

Endings the host records, each by name: `stopped`, `returned`, `returned-error`, `cancelled-after-grace`,
`cancelled-during-start-up`, `epoch-deadline`, `fuel-exhausted`, `trapped`. An ending also says whether the
guest got past start-up.

Start-up (proofs 1 and 6):
- start-up is instantiation, and it runs guest code: a core start function, which `wit-component` makes from
  an exported `_initialize`. The `start-loop` guest's `_initialize` never ends;
- from before instantiation, a guest yields after every fuel slice and at every epoch tick, as when it runs;
- start-up has its own fuel budget, which is not refilled. The run's budget starts just before
  `lifecycle.run`, and is refilled at every tick;
- one epoch deadline covers start-up and the run together;
- start-up and the run are one job, in the same `select` as the stop driver and the grace timer. The grace
  period starts at the close, whether the guest is still starting up or already running. A guest still in
  start-up when it runs out is ended as `cancelled-during-start-up`, and `lifecycle.run` is never called.

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

The fairness claim covers start-up too. Measured in this container:
- a guest stuck in start-up and the photo guest share one engine and one executor. The photo guest was due to
  start at 50 ms;
- the photo guest finished at about 53 ms, so about 3 ms after it was due. It takes about 2 ms alone, so it
  was held up by about 1 ms, less than one 10 ms tick. The test allows it to be up to 100 ms late;
- the stuck guest stayed in start-up until its epoch deadline at about 1.02 s, and never got past start-up;
- before the fix, the photo guest could not start until the stuck guest's start-up trapped, at about 1.06 s.
  The falsifier puts that order back (slicing and yield turned on only after instantiation), and the test
  fails.

A stop during start-up: the drive closed the events after 50 ms with a 200 ms grace period, and the run ended
as `cancelled-during-start-up` after about 255 ms. Before the fix it ran on for 10 s, until the epoch
deadline. Start-up that never ends, with a budget that lasts about 0.1 s, is ended by its own fuel
(`fuel-exhausted`), so the slicing does not refill it.

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
   - Instantiating the same guest source used 1 unit of fuel here and more than 10,000 on the Mac.
   - The guest bytes differ: the photo component is 102,719 B on the Mac and 102,707 B here, and every core
     module differs by 12 to 132 B (see [Measurements](#measurements)).
   - So a guest "named by hash" needs one pinned build environment, or the same source gives a different hash
     on each machine.
   - A budget shared by start-up and running passed here and failed there (found by Cursor's Mac run).
   - So start-up has its own fuel budget, and a trap during start-up is a named ending, never a bare error.
4. **There is no cancel that the guest sees.** To cancel, the host stops driving the `run` call and drops the
   store. The guest gets no signal and no reason. The host records the reason in its ending, which is enough.
5. **Async host imports must take the store.** An `async func` import gets `&Accessor<T, Self>` in a
   `HostWithStore<T>` trait, even when it only touches the guest's own state.
6. **Instantiation runs guest code, outside the run's controls unless the host puts it inside them.**
   - A core start function (from an exported `_initialize`) runs inside `instantiate_async`, before
     `lifecycle.run` can be called.
   - If slicing and yield are turned on only after instantiation, and instantiation is awaited before the stop
     logic starts, such a guest holds up every other guest, and a stop cannot reach it.
   - Turning `fuel_async_yield_interval` and the epoch yield on before instantiation does work in Wasmtime 48:
     start-up then yields like a running guest.
   - Found by Codex's review.
7. **Compiled code is worth caching.**
   - A warm start (load compiled code, then instantiate) took 0.08 to 0.31 ms.
   - A cold start (compile, then instantiate) took 44 to 140 ms in the container and 21 to 70 ms on the Mac.
   - Loading compiled code trusts its input, so such a cache must be one that only the Runtime writes.

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

These are measurements on two machines, not guarantees. Other machines, loads and builds will give other
numbers. Two machines, each with a release build of the host and the median of 9 runs:
- **container:** this Linux container, 4 vCPUs (Intel Xeon);
- **Mac:** Cursor's Mac run of `bfafc3ed`.

Sizes:

| Guest | Core module (container) | Core module (Mac) | Component (container) | Component (Mac) | Compiled code (container) | Compiled code (Mac) |
|---|---|---|---|---|---|---|
| photo | 97,700 B | 97,712 B | 102,707 B | 102,719 B | 405,096 B | 388,552 B |
| resident | 44,305 B | 44,437 B | 46,679 B | 46,811 B | 202,632 B | 231,320 B |
| busy | 28,664 B | 28,780 B | 29,942 B | 30,058 B | 132,008 B | 160,696 B |

The guests are built from the same source and the same `Cargo.lock`, yet every core module differs between
the two machines, by 12 to 132 B. Compiled code is native code for each machine, so it is expected to differ.

Start-up times:

| Guest | Cold start (container) | Cold start (Mac) | Warm start (container) | Warm start (Mac) | Instantiate only (container) | Instantiate only (Mac) |
|---|---|---|---|---|---|---|
| photo | 141.6 ms | 69.52 ms | 0.31 ms | 0.14 ms | 0.03 ms | 0.03 ms |
| resident | 69.3 ms | 34.07 ms | 0.19 ms | 0.11 ms | 0.03 ms | 0.03 ms |
| busy | 44.2 ms | 21.32 ms | 0.16 ms | 0.08 ms | 0.03 ms | 0.03 ms |

The Mac compiles about twice as fast. On both machines, warm start is hundreds of times faster than cold start.

- **Core module:** the guest as built by `cargo build --release --target wasm32-unknown-unknown`, with
  `opt-level = "s"`, LTO, one codegen unit, stripped, `panic = "abort"`.
- **Component:** the core module wrapped by `wit-component`, as the host loads it.
- **Compiled code:** Wasmtime's native code for the component (`Component::serialize`).
- **Cold start:** compile the component (`Component::new`), then instantiate it.
- **Warm start:** load the compiled code (`Component::deserialize`), then instantiate it.
- **Instantiate only:** the component already loaded. The measurement tool instantiates through Wasmtime
  directly, without the run's slicing and yield.

The design note asked for cold start "to the first event read". Instantiating takes about 0.03 ms, so cold
start is almost all compile time. A whole job is measured as well: the photo guest, already compiled, is
instantiated, reads a 1 MiB photo in 16 chunks, hashes it, checks its licence, draws a frame and stops, in
**8.6 ms** in the container and **5.07 ms** on the Mac.

How much of the photo guest is the credential check, measured once in the container, in a scratch build with
the check removed:
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
