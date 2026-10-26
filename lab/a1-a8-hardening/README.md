# A1 and A8 hardening

This lane adds real-Runtime proof for two M1 checks that already count, so a
review cannot take them back for want of evidence:

- **A1**: agent logic is a WASM component that imports only `elastos:bus` and is
  admitted by the Runtime allowlist. The row needs a cited WASI-import refusal.
- **A8**: host secrets are denied. The existing proof (PR #179, F-ac8a) uses
  the agent-conformance probe. This lane repeats the refusal with the
  agent-host component itself.

The Runtime owns admission and grants. These tests only build, stage and
launch, then read what the Runtime prints. Nothing here changes Runtime code.

## Rows

| Row | Test | Result on this lane's run |
| --- | --- | --- |
| A1 | `wasi_import_is_refused_at_admission` | PASS |
| A8 | `agent_host_host_key_read_is_refused` | PASS |
| A8 | `shipped_agent_host_bytes_read_host_key` | BLOCKED (AC-002-ARGS) |

[LOG.md](LOG.md) has the commands, hashes and output of each run.

## The Runtime path

`src/lib.rs` is the one harness. It follows the agent-conformance lane:

1. Build `elastos` (package `elastos-server`) and `localhost-provider` from this
   checkout with `cargo build --locked --offline` into `target/runtime`.
2. Build each component with the repository's
   `scripts/build-component-capsule.sh`, from a copy of its inputs under
   `target/build-inputs`, so the source tree is never written.
3. Make a throwaway Home under `target/homes`: its own `HOME`, data dir and
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
- the same source with one injected statement
  ([fixtures/agent-host-injection.txt](fixtures/agent-host-injection.txt)),
  placed right after `run()` reads its identity. It skips the guest's own
  guards, asks `elastos:bus/capabilities` for `read` on
  `localhost://Public/../../../../.ssh/id_ed25519`, and returns any refusal as
  its lifecycle error.

The test requires the injected build to keep the shipped import list (all five
`elastos:bus` interfaces) and to run with the shipped manifest bytes. It puts a
fake key with an obvious marker at `<home>/.ssh/id_ed25519`. With `Public` at
`<data dir>/Public` (the layout the agent-conformance lane records), four
parent segments name that file on both Linux and macOS; the test checks this
depth lexically and never resolves the path. The run must exit nonzero with
this exact line:

```text
Error: Component capsule failed: Compute error: Component capsule denied: BusError::Internal("capsule manifest does not declare authority for localhost://Public/../../../../.ssh/id_ed25519")
```

The fake key bytes must be unchanged and the marker must be absent from every
operator and client capture. The refusal is the manifest bound in
`elastos/crates/elastos-server/src/resource_bridge.rs` (`request_capability`),
the same reason the probe proof cites.

Why one injected statement: the shipped agent-host asks only for its own journal
(`localhost://Users/self/.AppData/Agents/agent-host/tasks/demo/journal`),
refuses `..` itself (`host_path`), and drops Bus error text. `elastos:bus@v1`
gives a component no launch arguments, so nothing outside the bytes can point
it at another resource. The injection models an agent-host whose own guards
fail; the Runtime must still refuse. The BLOCKED row records the unmodified
bytes case.

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

A passing test removes its Home. A failing test keeps it under `target/homes`
and prints its path.

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

Under F-A1-runtime the Runtime still refused the WASI build, through its
core-module import check, with a different reason; the exact-reason assertion
caught the change. Under both A8 falsifiers the request went on to the
operator and stayed pending until the client gave up after 30 seconds.
[LOG.md](LOG.md) has the exact lines.

`runtime-local` entries edit Runtime source on the test machine for one run.
They are restored byte-identical and never committed.

## Limits

- A1 covers one WASI interface, `wasi:cli/environment@0.2.0`, on the
  `elastos run` path. Other WASI interfaces and the Home launch path have no
  row here.
- A8 covers one route (a Bus read) to one fake file outside the Home roots,
  with an injected request. The unmodified agent-host bytes are BLOCKED.
- A8 does not query the operator's pending list. The exact manifest-bound
  reason shows the bridge refused before it sent the request on.
- `elastos run` for a component also opens `/tmp/elastos/storage` (known as
  AC-006-STORAGE in the agent-conformance lane). This harness does not clean it.
- Linux x86_64 only on this run. The macOS data-dir rule is written but was not
  run here.
