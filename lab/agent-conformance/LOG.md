# Probe contract

- The probe reserves one selector (`read:<path>`, `net:<resource>`, `model:<resource>` or `address:<instance>`) for one Bus attempt per activation; the current lifecycle entry returns `probe launch arguments are unavailable in elastos:bus@v1` until Runtime supplies the selector and result channel described in [GAPS.md](GAPS.md).

## 006 — launch, data directory and grant discovery

Runtime owns launch and grants; the fixture controller approves, the capsule
requests an effect, and the provider performs it. [GAPS.md](GAPS.md) is the single
blocker record and holds the detailed fixture recipe. This page records source
evidence only; live confirmation belongs to 003 after 007 supplies isolation.

**Launch.** `elastos run <component-directory>` and `elastos run --cid <bundle-CID>`
are non-interactive (`elastos/crates/elastos-server/src/main.rs:90-113`). The
component branch uses the operator Runtime, awaits activation and returns
(`elastos/crates/elastos-server/src/run_cmd.rs:51-60,225-269`). Start a fixture
operator first with `elastos serve --addr 127.0.0.1:<port> --storage-path <fixture-storage>`;
`run` requires its coordinates (`run_cmd.rs:165-170`). `--with` is native-provider
hosting (`run_cmd.rs:24-29`). The directory locates the candidate; the computed
hash identifies it, while launch by bundle CID still needs content preparation.

**Data directory.** `default_data_dir` is `dirs::data_dir()/elastos`
(`elastos/crates/elastos-server/src/sources.rs:12-17`). On this Mac, set child
`HOME` to the temporary fixture Home to obtain
`$HOME/Library/Application Support/elastos`; `XDG_DATA_HOME` applies to other
platforms. Task 007 verifies that resolved path and clears inherited
`ELASTOS_RUNTIME_COORDS_FILE` (`elastos/crates/elastos-server/src/runtime_control.rs:446-450`).
AC-006-STORAGE remains open: even the component branch constructs storage at
`/tmp/elastos/storage` (`run_cmd.rs:236`). Runtime must derive that path from the
selected Home before the fixture can claim complete temporary-root isolation.

**Grant decision.** seam exists (shell-authenticated operator HTTP API) —
fixture/command recipe 003 uses: obtain a fixture shell session through
`POST /api/auth/attach`, run a fixed-effect probe, match its exact request in
`GET /api/capability/pending`, then `POST /api/capability/grant` with its
`request_id` and `duration: "once"`. The API requires shell authority
(`elastos/crates/elastos-server/src/api/server.rs:258-277`); approval grants to
the requesting session (`elastos/crates/elastos-server/src/api/handlers/capability.rs:308-353`).
The guest bridge polls for the result for up to 30 seconds
(`elastos/crates/elastos-server/src/resource_bridge.rs:1386-1454`). Credentials
stay inside the future isolated fixture. `dev_mode` configures admission only
(`elastos/crates/elastos-server/src/runtime.rs:188-227`); for a pre-seeded home-file
grant seam: **none found**. Direct manager/store access in server tests is
test-internal (`runtime.rs:508,1026-1043`). 003 has a grant route to exercise once
007 and AC-006-STORAGE are resolved; each effect still needs its own proof.

**Effect channel.** AC-002-ARGS stays open: Bus v1 carries no launch selector or
success payload (`elastos/wit/elastos-bus-v1.wit:87`,
`elastos/crates/elastos-compute/src/providers/component.rs:133,183`). A typed
WIT selector/result plus ComponentProvider and CLI forwarding would close it.
One build-time-fixed effect can use the existing capability/provider imports
(`elastos-bus-v1.wit:72-95`). Propagated refusal reaches exit/stderr with the
source format `Component capsule denied: {err:?}` (`component.rs:135`). The
current probe returns only its unavailable reason. Live refusal, Mac path
resolution and real-Home byte identity: **to confirm in 003**. Zero Runtime
launches were made; the full Runtime build was skipped pending storage isolation.

Principles check (documentation scope; no behavior grade added):

| Question | Answer and evidence |
| --- | --- |
| 1. New name/URL in place of code/content hash? | No. CID launch stays canonical; `run_cmd.rs:127-138`. |
| 2. New ambient or UI authority? | No. The existing shell approval and Bus grant path stay separate; `api/server.rs:258-277`, `component.rs:398-409`. |
| 3. Second operation path or rule copy? | No. The existing CLI/API path is documented; this summary points to the single GAPS record. `run_cmd.rs:58`, `api/server.rs:261`. |
| 4. Does the trusted core grow? | No. Only this LOG and GAPS change; the proposed core work stays blocked. `component.rs:133`, `run_cmd.rs:236`. |
| 5. Clear fail-closed refusal? | Yes for the unchanged probe refusal; `lab/agent-conformance/probe/src/lib.rs:14-25`. Live effect grading remains with 003. |
| 6. Capsule logic stays inside and traps down? | Yes. The available effect interfaces are typed Bus imports; `elastos/wit/elastos-bus-v1.wit:72-95`. |
| 7. New rules have tests and caught falsifiers? | Yes within this docs-only scope: zero new executable rules, tests or falsifiers. Existing `probe_refuses_without_a_launch_argument_channel` at `probe/src/lib.rs:34-40` and F-ac2a in `README.md:43`; effect tests and their falsifiers belong to 003. |

Checks: lane `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`
and `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` passed
offline with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0` under the shared build
lease: 6 tests, 0 failures, 0 ignored. The basic repo gate also passed
(`git diff --check`, product-data check and its 99 tests, Runtime and
chain-provider formatting). Falsifiers were unchanged and were not rerun.
Only GAPS and LOG are tracked edits; clean status awaits the supervisor's
commit because this builder has no git-mutation authority.

- 006: Extended GAPS and this LOG with the source-traced launch, Mac Home rule, HTTP grant recipe, fixed-effect refusal channel and AC-006-STORAGE isolation blocker; probe and harness code stay unchanged.
