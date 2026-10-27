# A1 and A8 hardening

This lane adds real-Runtime proof for two M1 checks that already count, so a
review cannot take them back for want of evidence:

- **A1**: agent logic is a WASM component that imports only `elastos:bus` and is
  admitted by the Runtime allowlist. The row needs a cited WASI-import refusal.
- **A8**: host secrets are denied. The existing proof (PR #179, F-ac8a) uses
  the agent-conformance probe. This lane repeats the refusal with the
  agent-host component itself.

The Runtime owns admission and grants. These tests build, stage and launch,
then read the Runtime's host-side receipts. The guest cannot write those
receipts. A small Runtime change appends each `request_capability` to
`runtime/capability-requests.jsonl` under the Home data dir.

## Rows

| Row | Test | Result on this lane's run |
| --- | --- | --- |
| A1 | `wasi_import_is_refused_at_admission` | PASS |
| A8 | `agent_host_host_key_read_is_refused` | NEEDS RUNTIME (receipt omits session id and guest module hash; Runtime also does not print the assigned component id) |
| A8 | `shipped_wasm_bus_prints_internal_sentence` | NEEDS RUNTIME |
| A8 | `shipped_agent_host_bytes_read_host_key` | BLOCKED (AC-002-ARGS) |

[LOG.md](LOG.md) has the commands, hashes and output of each run.

## The Runtime path

`src/lib.rs` is the one harness. It follows the agent-conformance lane:

1. Build `elastos` (package `elastos-server`) and `localhost-provider` from this
   checkout with `cargo build --locked --offline` into `target/runtime`.
2. Build each component with the repository's
   `scripts/build-component-capsule.sh`, from a copy of its inputs under
   `target/build-inputs`, so the source tree is never written.
3. Make a throwaway Home with `mktemp -d`: its own `HOME`, data dir and
   `TMPDIR`, a cleared environment, and `localhost-provider` installed with its
   SHA-256 in `components.json`.
4. Start `elastos serve` on a loopback port with the agent-conformance operator
   config, and wait for `runtime-coords.json` and `GET /api/health` 200.
5. Launch `elastos run <capsule dir>`, capture stdout and stderr, and stop
   every process group at the end.

The agent-conformance harness runs only on macOS. This harness uses the same
steps with the data-dir rule of each OS: `~/Library/Application Support/elastos`
on macOS and `~/.local/share/elastos` on Linux. It ran on Linux x86_64 here.

## A1: a WASI import is refused at admission

`wasi-guest/` is one small component source with two builds:

- the default build has the agent-host's world, `product-capsule-v1`, and
  imports only `elastos:bus/types@1.0.0`;
- the `wasi-env` build includes the same world and adds one import,
  `wasi:cli/environment@0.2.0`, which it calls so the import stays.

Both builds use the same manifest. The test checks each build's import list
with `wasmparser`, then runs both against one operator. The WASI build must
exit nonzero with this exact stderr line, and must not start:

```text
Error: Component capsule failed: Invalid manifest: component import "wasi:cli/environment@0.2.0" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0
```

The reason comes from `validate_component_imports` in
`elastos/crates/elastos-server/src/component.rs`, which `run_local` calls
before it loads the component. The control build must be admitted and print
`[run] Component capsule 'a1-wasi-guest' exited` with exit 0.

## A8: the agent-host asks for a fake host key and is refused

The test builds the agent-host twice from a copy of `examples/agent-host`:

- the shipped source, unchanged;
- the same source with the guest's own grant-path guards failed for that
  one resource: `host_path` returns false only for the fake key (other
  `..` and `/` checks stay), `request_journal_grants` no longer returns empty
  when the resource is outside `JOURNAL_ROOT`, and `journal_resource` names
  `localhost://Public/../../../../.ssh/id_ed25519`. The copy then asks
  through the shipped `WasmBus` only. There is no extra `capabilities::request?`.

The test requires the injected build to keep the shipped import list (all five
`elastos:bus` interfaces) and to run with the shipped manifest bytes. The
injected guest bytes must name the fake key and must omit the Runtime refusal
sentence and the old early-return marker (`agent-host read the host key`).
The shipped guest bytes must omit the fake key path. It puts a fake key with
an obvious marker at `<home>/.ssh/id_ed25519`. With `Public` at
`<data dir>/Public` (the layout the agent-conformance lane records), four
parent segments name that file on both Linux and macOS; the test checks this
depth lexically and never resolves the path.

Authorship is a host-side receipt. The Runtime appends one JSON line per
bus call to `runtime/capability-requests.jsonl`, with the structured
code `manifest_capability_denied` and the action plus resource. Each run
uses a fresh `mktemp` Home. The test fails if that file exists at any
point from the snapshot through spawn, records size and inode at launch,
locks the first inode seen during `elastos run`, and reads only that
file. It binds those lines to the component id the Runtime printed for
this launch (a `[run]` line or API, never the guest or the jsonl
itself). A missing assigned id is not a match: NEEDS RUNTIME, never
PASS. A foreign `capsule_id` is a FAIL. Session id must equal this
launch, must be an unguessable 128-bit hex minted host-side, and must
not alias `capsule_id` or `identity::context().session`. `session-1`
is refused. `module_hash` is the only hash field and must be of the
staged bytes that will be executed. `guest_function` must be
`request_journal_grants`. Receipts carry a strictly increasing `seq`.
Duplicate JSON keys and a `capsule_id` with whitespace FAIL. The lock
records the real receipt size; a same-inode shrink or a rewrite after
`run_until` FAIL. The cargo test itself refuses PASS while any of
those fields is missing.

The Runtime today writes `capsule_id` as `component-<uuid>` and leaves
`principal_id` null. It does not print that id, and it does not record
session id, module hash, or guest function. The test process shares the
Runtime's uid, so it can write the same file; making the file unwritable
also blocks the Runtime. Those gaps are the Runtime ask in
[RUNTIME-ASK.md](RUNTIME-ASK.md). The pass row is NEEDS RUNTIME until
the Runtime binds this guest, this session, this hash, and this function.

The guest still cannot name a path that maps to the jsonl. The test
requires write and then read for that one fake key. The honest sequence
is judged only from host receipts and the Runtime / bus host log, never
from guest stderr. A guest that skips `request_journal_grants` and
prints `Invalid("the journal append did not follow its grants")` fails.
A guest that only prints the Internal sentence, that asks once after
`identity::context()`, or whose lines the test process wrote before
launch or after the snapshot, fails. `host_path` still treats every
other `..` or `/` path as a host path.

The run must exit nonzero. The fake key bytes must be unchanged and the
marker must be absent from every operator and client capture. A timeout
(`exit:timeout` / `exit:None`) is not a catch.

`WasmBus` still maps `BusError::Internal` to `BusFailure::Other`, so the
path-specific Internal sentence is not the pass criterion. That claim is
the NEEDS RUNTIME row. `elastos:bus@v1` gives a component no launch
arguments, so the unmodified bytes still cannot ask for a host key. The
BLOCKED row records that case.

[fixtures/agent-host-injection.txt](fixtures/agent-host-injection.txt) and
[fixtures/forged-runtime-sentence.txt](fixtures/forged-runtime-sentence.txt)
are the two #316 plants. [fixtures/piece-forge.txt](fixtures/piece-forge.txt)
and [fixtures/direct-request.txt](fixtures/direct-request.txt) are the #356
plants.

## Run it

From the repository root, with the pinned toolchain, its
`wasm32-unknown-unknown` target and cached crates:

```sh
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
```

`run.sh` prints the evidence lines and one result per row. A cold Runtime build
takes several minutes. To run one row:

```sh
CARGO_NET_OFFLINE=true \
CARGO_TARGET_DIR="$PWD/lab/a1-a8-hardening/target/host" \
CARGO_BUILD_BUILD_DIR="$PWD/lab/a1-a8-hardening/target/host-build" \
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 \
cargo test --locked --manifest-path lab/a1-a8-hardening/Cargo.toml \
  --test a1_wasi_import -- --nocapture
```

A passing test removes its `mktemp` Home. A failing test keeps it and
prints its path.

## Falsifiers

[falsifiers.json](falsifiers.json) lists them. Run one with
`python3 lab/a1-a8-hardening/falsify.py <ID>`. It applies the exact edits, runs
the named tests, restores the bytes with a SHA-256 check, and says CAUGHT only
when each test fails at its refusal assertion.

| ID | What it breaks | Test | Result |
| --- | --- | --- | --- |
| F-A1a | stages the control build where the WASI build belongs | `wasi_import_is_refused_at_admission` | CAUGHT |
| F-A1-runtime | turns off the Runtime's component-import allowlist check | `wasi_import_is_refused_at_admission` | CAUGHT |
| F-A8a | declares the fake key in the staged manifest, so the manifest no longer denies it | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-runtime | removes the Runtime's manifest-authority refusal | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-forge | guest returns the Runtime sentence itself and only mentions the bus under `black_box` | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-early | restores the early-return injection at the start of `run()` | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-skip-guards | A-skip-guards: drop the host_path special-case and the JOURNAL_ROOT guard deletion | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-piece-forge | B-piece-forge: guest builds the Internal sentence from split strings | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-wasm-bus-only | C-wasm-bus-only: claim the shipped WasmBus prints the Internal sentence | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-direct-request | D-direct-request: guest asks `capabilities::request` after identity | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-test-writes-lines | test writes the two expected jsonl lines and launches a no-bus guest | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-skip-journal-grants | guest asks write then read, skips `request_journal_grants`, ignores the refusal | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-guest-follow-sentence | guest asks write then read, skips `request_journal_grants`, prints the Invalid sentence | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-race-after-snapshot | test writes the two lines after the inode snapshot, foreign `capsule_id`, no-bus guest | `agent_host_host_key_read_is_refused` | CAUGHT |
| F-A8-session-alias | accept `session_id == capsule_id` / `identity.session` | `session_id_must_not_alias_capsule_id` | CAUGHT |
| F-A8-session-1 | accept predictable `session-1` | `predictable_session_1_is_refused` | CAUGHT |
| F-A8-toctou-hash | hash the in-memory copy, ignore staged bytes | `executed_hash_is_of_staged_bytes` | CAUGHT |
| F-A8-seq-ignored | ignore `seq` gaps, repeats and reordering | `receipt_seq_must_be_strictly_increasing` | CAUGHT |
| F-A8-shrink-dead | record receipt size 0 at lock | `same_inode_shrink_fails` | CAUGHT |
| F-A8-rewrite-after-run | accept a same-inode rewrite after `run_until` | `rewrite_after_seal_fails` | CAUGHT |
| F-A8-dup-keys | last-wins duplicate JSON keys | `duplicate_json_keys_fail` | CAUGHT |
| F-A8-capsule-trim | trim `capsule_id` whitespace | `capsule_id_whitespace_fails` | CAUGHT |

Under F-A1-runtime the Runtime still refused the WASI build, through its
core-module import check, with a different reason; the exact-reason assertion
caught the change. Under F-A8a and F-A8-runtime the request leaves the
manifest bound; the host record is `pending` and the test fails on that
record, without waiting out the client bound. A timeout is NOT CAUGHT.
F-A8-forge fails before the operator starts, because the guest bytes hold
the Runtime sentence. F-A8-early fails the same way on the early-return
marker. The four #356 plants fail on the host-side write-then-read
receipt, except F-A8-wasm-bus-only, which fails when it requires the
Internal sentence on stderr. F-A8-test-writes-lines fails because the
jsonl already exists before launch. F-A8-skip-journal-grants and
F-A8-guest-follow-sentence fail the host-side sequence (guest function
`request_journal_grants`). F-A8-race-after-snapshot fails because the
jsonl exists at spawn. [LOG.md](LOG.md) has the exact lines.
`mutants/binding.py` kills one mutant per new assert.

`runtime-local` entries edit Runtime source on the test machine for one run.
They are restored byte-identical and never committed.

## Limits

- A1 covers one WASI interface, `wasi:cli/environment@0.2.0`, on the
  `elastos run` path. Other WASI interfaces and the Home launch path have no
  row here.
- A8 covers one route (a Bus read) to one fake file outside the Home roots,
  with the grant-path guards failed in a build copy. The unmodified
  agent-host bytes are BLOCKED.
- The shipped `WasmBus` still maps `BusError::Internal` to `BusFailure::Other`.
  That visible-sentence claim is NEEDS RUNTIME and stays out of the pass
  column.
- A8 does not query the operator's pending list. The host-side
  `manifest_capability_denied` record shows the bridge refused before it
  sent the request on. Session id and guest module hash are a Runtime
  ask; see [RUNTIME-ASK.md](RUNTIME-ASK.md).
- `elastos run` for a component also opens `/tmp/elastos/storage` (known as
  AC-006-STORAGE in the agent-conformance lane). This harness does not clean it.
- Linux x86_64 only on this run. The macOS data-dir rule is written. macOS,
  aarch64 and Jetson are NOT RUN.
