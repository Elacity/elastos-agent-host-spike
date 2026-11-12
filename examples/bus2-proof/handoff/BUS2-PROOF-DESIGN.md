# Bus v2 guest-side proof: design note

Evidence for Anders before the Bus v2 interface is frozen (Phase 2, input to milestone 2.3).

**What this is:** one real guest, built against the draft `elastos:bus@2.0.0` world, run by a small
stub host inside a test process. The guest shows what the draft is like to write against.

**What it is not:**
- not a second Bus;
- not a Runtime change. Nothing under `elastos/` and nothing in `examples/photo-viewer/` changes;
- not a grant of anything to anyone.

Branch `claude/bus2-proof`, from `spike/photo-viewer` at `9d449d95`. One draft PR. This note comes first,
before any code.

## 0. Review changes (Cursor, on `7f300800`): approved with these

1. **The credential signature covers a domain-separated message**, not the bare hash:
   `"elastos:bus2-proof:credential:v1\n" + kind + "\n" + subject-sha256 (hex)`.
   - Falsifier: a valid signature by the pinned key, over the same hash, with another kind or another tag,
     is refused.
2. **No frame before the credential check passes.** The check runs after the read completes and before
   `ui.present`. Test: a mismatch draws zero frames.
3. **The guest ignores `signer`.** The report says whether it should become a key id that picks among pinned
   keys, or be dropped.
4. **`stop-requested` is tested as planned.** If closing the stream covers it, the report recommends dropping
   it, so there is one way to stop.
5. **`Cargo.lock` is committed**, and `verify.sh` runs every test and falsifier in one command (for the Mac).
6. **Stay on Wasmtime 48**, the long-term-support release. Wasmtime 50 is mentioned in the report only.

Sections 4.3 and 4.4 below are read with these changes.

## 1. Versions, pinned for this folder only

| Piece | Pin | Why |
|---|---|---|
| Rust | `1.95.0`, in `examples/bus2-proof/rust-toolchain.toml` with the `wasm32-unknown-unknown` target | Wasmtime 48.0.7 needs `rust-version = 1.95.0`. Checked: rustup installs `rustc 1.95.0 (59807616e 2026-04-14)` here |
| Wasmtime | `=48.0.7`, features `component-model`, `component-model-async`, `async`, `cranelift` | The requested line (48.0.4 or later). The latest is 50.0.0; I stay on 48 as asked |
| wit-bindgen (guest) | `=0.60.0` | It is the release built on `wit-parser 0.254`. Wasmtime 48.0.7 is built on `wasmparser`, `wasm-encoder` and `wit-parser` `0.254.1`, so both read the same async ABI. 0.61 moves to 0.258, which is too new |
| wit-component (componentize the guest) | `=0.254.2` (same line) | It turns the guest's core module into a component, in the test harness, with no extra CLI to install |
| wat (test fixtures) | `=1.254.2` (same line) | Hand-written components for the admission tests |

The folder is its own Cargo workspace (`[workspace]`), outside the ElastOS workspace and outside CI, like
`examples/hello`.

## 2. Layout

```
examples/bus2-proof/
  rust-toolchain.toml        Rust 1.95.0 + wasm32-unknown-unknown, this folder only
  Cargo.toml                 its own workspace: host, guests/*
  wit/bus2.wit               the DRAFT, copied unchanged with a header comment
  host/                      stub host library (Wasmtime 48) + the proof tests
  guests/photo/              the resident guest (proofs 1 to 4)
  guests/busy/               a guest that never yields (proof 6)
  fixtures/*.wat             components with bad imports (proof 5)
  falsify.py                 breaks each check once and requires its test to fail
  handoff/BUS2-PROOF-DESIGN.md  this note
  handoff/BUS2-PROOF-REPORT.md  the findings, at the end
```

The test harness builds each guest for `wasm32-unknown-unknown` and componentizes it, like the photo
spike's harness. The stub host is a library used only by the tests. It has no network, no files outside a
temp dir, and no keys of its own beyond test keys.

## 3. The stub host

- **Engine:** one per test run, with:
  - Component Model async on;
  - fuel on;
  - epoch interruption on.
- **Stores:** one per guest. Each store holds:
  - a **grant table**, set by the test. `capabilities.request` returns a grant only if the test's policy
    allows exactly that resource and those actions; otherwise `denied`;
  - an **object table**: object URIs to bytes, standing in for the Library;
  - the **credentials** to present;
  - a **frame log**: what `ui.present` drew;
  - an **ending log**: one named reason per run.
- **One path per operation:**
  - objects are read only through `providers.invoke` with operation `read` and a grant id;
  - images are drawn only by grant handle inside the `ui.present` document;
  - stopping happens only by closing the events stream (see the note on `stop-requested` in section 6).
- **Fail closed:** every refusal is a `bus-error` whose string names what was expected. Each test checks
  the variant and the text.

## 4. The six proofs

Each proof has one or more tests and at least one falsifier: an exact one-place change to the host or the
guest that must make its test fail.

### 4.1 A resident guest that stops when asked, or is ended

- **Flow:** the host calls `lifecycle.run(events)` and keeps the write end of `events`. The guest loops:
  read an event, handle it, read again.
- **The host asks it to stop by closing the stream.** The guest sees the end of the stream and returns
  `ok`.
- **Endings, each recorded with a named reason:**

  | Reason | When |
  |---|---|
  | `stopped` | the guest returned `ok` after the stream closed |
  | `returned-error` | the guest returned `err(bus-error)`; the error is kept |
  | `cancelled-after-grace` | the guest did not return within the grace period; the host cancels the call |
  | `epoch-deadline` | backstop: a guest that never yields (so cannot be cancelled cooperatively) is trapped at the epoch deadline |
  | `trapped` | any other trap; the message is kept |

- **Tests:**
  - a well-behaved guest gives `stopped`;
  - a guest that ignores the close but still awaits gives `cancelled-after-grace`;
  - a guest stuck in a loop gives `epoch-deadline`.
- **Falsifiers:** do not close the stream; no grace cancel; no epoch deadline. Each must change the
  recorded reason or hang the watchdog.

### 4.2 Streaming an object read with a size cap

- **The guest:**
  - first gets a grant for one photo with `capabilities.request(uri, ["read"], reason)`;
  - then calls `providers.invoke({resource: uri, operation: "read", grant: id, params})`, where `params`
    carries its cap as JSON `{"max_bytes": N}`;
  - reads the returned `stream<u8>` in chunks, counting bytes.
- **The bytes count only once the trailing future resolves `ok`.** Any `err` means the guest drops
  everything read so far.
- **The host refuses rather than truncates:**
  - an object known to be larger than the cap: `invoke` itself returns
    `invalid("object is N bytes, over the cap of M")`, and no stream is opened;
  - an object that grows past the cap while streaming: the host stops writing and resolves the future
    `err(invalid(...))`. The guest refuses the partial bytes;
  - the host also has its own hard cap, whatever the guest asks for.
- **The guest checks too.** If more bytes arrive than its cap, it stops and refuses. That is a second
  check, not the only one.
- **Tests:**
  - an exact-cap object is read whole, in more than one chunk;
  - a cap + 1 object is refused before streaming;
  - a growing object is refused at the end, and nothing partial is used;
  - no grant, or a grant for another URI, is `denied`.
- **Falsifiers:** host skips the up-front check; host ends the stream early with `ok` (truncation); guest
  uses bytes before the future resolves; host skips the grant check.

### 4.3 `ui.present` draws one frame

- **The document:** the guest presents one declarative document, media type
  `application/vnd.elastos.ui+json;v=0` (a stub format for this proof):
  `{"frame": [{"text": "..."}, {"image": {"grant": "<grant-id>"}}]}`.
- **The host checks it strictly** and records one frame:
  - the media type must be exact;
  - the JSON keys must be known;
  - nodes may only be `text` and `image`;
  - an image must name a grant this guest holds, with `read`, on an object of an image type;
  - no URI, no bytes, no script, no `on*` keys, no HTML.
- **A new `present` replaces the frame.** There is never more than one.
- **Tests:**
  - a good document draws one frame that holds the grant id, not the bytes;
  - each of these is refused with its reason: a script node, an `onload` key, an image by URI, an image
    by a grant not held, a revoked grant, the wrong media type, and an unknown key.
- **Falsifiers:** accept unknown keys; accept an image by URI; skip the held-grant check.

### 4.4 `credentials.presented`: the guest can refuse, never grant

- **The pin:** the guest's own manifest (`guests/photo/capsule.json`) pins one publisher key as a did:key
  and the credential kind it needs. The manifest is compiled into the guest, so the pin is part of what
  the guest is.
- **At start, the guest calls `credentials.presented()` and needs a credential where:**
  - `kind` is the pinned kind;
  - `signer` is the pinned did:key;
  - `body` is an Ed25519 signature by the **pinned** key (not by whatever `signer` says) over
    `"elastos:bus2-proof:credential:v1\n" + kind + "\n" + subject-sha256` (review change 1);
  - `subject-sha256` equals the SHA-256 of the photo bytes it streamed (proof 4.2), so the credential is
    for this content.
- **On any mismatch the guest returns `err(denied("..."))`** before it presents a frame.
- **It never grants:** the guest has no call that adds authority, and the stub host ignores credentials
  when it decides grants.
- **Tests:**
  - a good credential lets it run;
  - each of these is refused: the wrong signer, the right signer string with a signature by another key,
    the wrong SHA-256, the wrong kind, no credential;
  - with a good credential, a grant the policy refuses is still refused.
- **Falsifiers:** guest skips the signature check; guest trusts `signer` instead of the pinned key; guest
  skips the SHA-256 match.

### 4.5 Admission-like import check

- **Before instantiating anything, the stub reads the component's imports and refuses:**
  - any import outside `elastos:bus/*@2.0.0`, which covers any `wasi:*` and any other package;
  - a component that imports both `elastos:bus/...@1.x` and `@2.0.0`;
  - a core module given where a component is expected;
  - an import of a v2 interface that is not in the world.
- **Fixtures:** small `.wat` components, plus the real photo guest, which must pass.
- **Falsifiers:** allow `wasi:*`; allow mixing v1 and v2; skip the check for core modules.

### 4.6 Fairness: one busy guest cannot starve another

- **Setup:** two stores on one engine, run on one single-threaded executor.
  - Guest A (`guests/busy`) loops forever without awaiting.
  - Guest B (the photo guest) does a short, real job.
- **Fuel is refilled per time slice:**
  - each slice gives a store a fixed amount of fuel;
  - an epoch tick ends the slice, with a callback that refills the fuel and yields to the executor;
  - fuel also yields at a fixed interval, so a guest that burns its slice early still lets others run;
  - running out of fuel inside one slice is a trap, recorded as `fuel-exhausted`.
- **Test:** B finishes while A is still running. A is then ended by the epoch backstop and records its
  reason.
- **A watchdog thread fails the test if the executor stops making progress.** A starved executor cannot
  time itself out.
- **Falsifiers:** no fuel yield and no epoch yield (B must not finish before A is ended); no fuel refill.

## 5. Measurements for the report

- **Size:** the photo guest component, release, `opt-level = "s"`, stripped: total bytes, and how much is
  Ed25519 and SHA-256.
- **Cold start:** `Component::new` from bytes (compile), then instantiate, to the first event read.
- **Warm start:** a component serialized once, then deserialized and instantiated (a cached compile).

Median of several runs, on this container and named as such. The Mac numbers will differ.

## 6. What I expect to find awkward (to confirm or drop in the report)

Hypotheses, not findings yet:

1. **Two ways to stop.** `event.stop-requested` and closing the stream both mean stop. That is two paths for
   one operation. I will use only the close, and test that `stop-requested` adds nothing the close cannot
   do.
2. **Three error paths on `invoke`.** The outer `result`, the free-form `invoke-status.status` string, and
   the trailing `future<result>`. The guest must handle all three and must buffer until the future
   resolves.
3. **Untyped `params: list<u8>`.** Every guest and provider must agree on an encoding out of band.
4. **No size before reading.** `invoke-status` has no length, so a guest cannot refuse a too-large object
   before the stream starts. It has to rely on the host refusing up front.
5. **`ui.present` names grants only inside an opaque document.** The host must parse the document to find
   which grants it uses.
6. **No reason on cancel.** When the host cancels `run`, the guest learns nothing about why.

## 7. Rules held

- **No new authority:**
  - grants come only from the test policy;
  - credentials only let the guest refuse;
  - the UI document holds grant handles, never bytes or URIs.
- **One path per operation** (section 3).
- **Fail closed:** every refusal has a named reason, a test and a falsifier.
- **No private security details** in the report.
- **Commits** end with `Co-authored-by: Claude <noreply@anthropic.com>`. **Not merged by me.**

## 8. Steps, each a commit on this branch

1. Toolchain pin, workspace, stub host skeleton, and admission (4.5).
2. Lifecycle and endings (4.1).
3. Streaming read with caps (4.2).
4. `ui.present` (4.3).
5. Credentials (4.4).
6. Fairness (4.6).
7. Measurements, falsifier run, and `BUS2-PROOF-REPORT.md`.

I will report at the end of each step, or stop sooner if Sasha wants to review a step first.
