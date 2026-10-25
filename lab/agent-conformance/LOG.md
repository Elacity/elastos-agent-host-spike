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

## 008 — throwaway Home and bounded launch

- 008: Added `ThrowawayHome::{new,create_at,guard,launch,finish}`, the single Mac `data_dir` rule, three harness tests, the Cargo result table and its test, RUNBOOK, and the lane's one falsifier list; Runtime and probe sources stay unchanged.

The harness owns a fresh root under `target/`. It checks the selected Home and
data path before using either, clears the child environment, sets HOME/TMPDIR
and the fixed system PATH, and bounds each child. The primitive is exercised
with `/usr/bin/env`, `/bin/sh` and `/bin/sleep`; task 009 owns Runtime launch
acceptance. Successful tests remove their roots. The three deliberate harness
failures below retain their roots for supervisor review, with removal after
that review. The private local lifecycle inventory records those roots.

`falsifiers.json` is the one list. F-probe-a through F-probe-f carry the six
002 mutations formerly named F-ac2a through F-ac2f. Their exact anchors were
checked against the unchanged source, and all six existing tests passed.
The provider lane owns `falsify.py`; lab falsifiers run by hand until it adds
a `lab` arm. The four new entries were each applied once, run, restored from
the original bytes, and rerun. F-report-a covers the new table rule.

Commands below ran from the repository root under the existing shared
heavy-build lease. The local invocation used Python `subprocess.run` with the
following complete environment; HOME supplies only its path value, and the
extra inherited variables contain synthetic fixture values. Thus F-ac1d's
captured environment contains fixture data only. Each `edits` replacement
from `falsifiers.json` was applied with `original.replace(old, new, 1)` after
asserting one match, and restored with `path.write_bytes(original)` in `finally`.
There was no Git mutation or shared-runner change.

```python
lane = pathlib.Path('lab/agent-conformance')
tmp = lane / 'target/falsifier-tmp'
env = dict(
    HOME=os.environ['HOME'], PATH=os.environ['PATH'],
    CARGO_NET_OFFLINE='true',
    CARGO_TARGET_DIR=str((lane / 'target/host').absolute()),
    CARGO_BUILD_BUILD_DIR=str((lane / 'target/host-build').absolute()),
    TMPDIR=str(tmp.absolute()), RUST_TEST_THREADS='2', CARGO_INCREMENTAL='0',
    ELASTOS_RUNTIME_COORDS_FILE=str((tmp / 'absent-coords').absolute()),
    ELASTOS_FIXTURE_ONLY='fixture', XDG_DATA_HOME=str(tmp.absolute()),
    XDG_CONFIG_HOME=str(tmp.absolute()), SPARKS_MODEL_URL='fixture.invalid',
)
```

Each following Cargo command ran once with the mutation (exit 101) and once
after restoration (exit 0). The blocks preserve the captured output. The
failures are test assertions on returned results; every named test ran.

**F-ac1c: take HOME from the parent instead of the fresh root.**

```sh
cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness home_is_throwaway -- --exact --nocapture
```

Planted (exit 101):

```text
running 1 test
retained throwaway root: lab/agent-conformance/target/home-94791-1792940814407772000-0

thread 'home_is_throwaway' (21046616) panicked at tests/harness.rs:8:38:
harness must start with the committed fixture: "home is outside the fresh throwaway root"
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
home_is_throwaway --- FAILED

failures:

failures:
    home_is_throwaway

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p agent-conformance --test harness`
```

Restored (exit 0):

```text
running 1 test
.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
```

**F-ac1d: pass inherited variables to the child.**

```sh
cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness launch_env_is_only_the_throwaway_home -- --exact --nocapture
```

Planted (exit 101):

```text
running 1 test

thread 'launch_env_is_only_the_throwaway_home' (21048189) panicked at tests/harness.rs:93:5:
child environment must have exactly three entries
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
retained throwaway root: lab/agent-conformance/target/home-95244-1792940840079050000-0
launch_env_is_only_the_throwaway_home --- FAILED

failures:

failures:
    launch_env_is_only_the_throwaway_home

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s

error: test failed, to rerun pass `-p agent-conformance --test harness`
```

Restored (exit 0):

```text
running 1 test
.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.03s
```

**F-ac1e: let a child run past its time bound.**

```sh
cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness launch_stops_a_child_past_its_bound -- --exact --nocapture
```

Planted (exit 101):

```text
running 1 test

thread 'launch_stops_a_child_past_its_bound' (21049676) panicked at tests/harness.rs:128:5:
assertion `left == right` failed
  left: None
 right: Some("child exceeded its time bound")
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
retained throwaway root: lab/agent-conformance/target/home-95774-1792940857836508000-0
launch_stops_a_child_past_its_bound --- FAILED

failures:

failures:
    launch_stops_a_child_past_its_bound

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 3.01s

error: test failed, to rerun pass `-p agent-conformance --test harness`
```

Restored (exit 0):

```text
running 1 test
.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 1.00s
```

**F-report-a: grade any result other than ok as PASS.**

```sh
cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test report run_table_requires_cargo_results -- --exact --nocapture
```

Planted (exit 101):

```text
running 1 test

thread 'run_table_requires_cargo_results' (21051270) panicked at tests/report.rs:7:5:
assertion `left == right` failed
  left: ("test | PASS/FAIL/BLOCKED (id)\nblocked | PASS\nworks | FAIL\n", false)
 right: ("test | PASS/FAIL/BLOCKED (id)\nblocked | BLOCKED (RT3)\nworks | PASS\n", true)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
run_table_requires_cargo_results --- FAILED

failures:

failures:
    run_table_requires_cargo_results

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p agent-conformance --test report`
```

Restored (exit 0):

```text
running 1 test
.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Final checks: lane formatting and `run.sh` passed offline with
`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. The script ran
`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -- --list`
and the same test command with `--no-fail-fast -- --format pretty --color never`.
The complete suite has 10 passed, 0 failed and 0 ignored tests. Its exact table:

```text
test | PASS/FAIL/BLOCKED (id)
foreign_and_wrong_version_imports_are_refused | PASS
home_is_throwaway | PASS
launch_env_is_only_the_throwaway_home | PASS
launch_stops_a_child_past_its_bound | PASS
non_component_and_invalid_component_are_refused | PASS
probe_hash_is_stable | PASS
probe_imports_only_the_bus | PASS
probe_manifest_names_the_current_bus_world | PASS
run_table_requires_cargo_results | PASS
tests::probe_refuses_without_a_launch_argument_channel | PASS
```

`git diff --check`, `bash -n lab/agent-conformance/run.sh`, the product-data
check (42 capsules, 2 profiles, 28 method contracts), its 99 tests, and Runtime
and chain-provider formatting also passed. All 10 falsifier IDs are unique,
all commands are `lab`, and every exact edit anchor matches the restored source.
The full run left both source hashes and `git status --porcelain` unchanged;
its generated files are ignored. The builder leaves the source edits for the
supervisor's commit, so an empty Git status follows that commit. The local
branch is 0 ahead / 0 behind its cached `spike/spike/agent-host` upstream;
network restrictions leave remote freshness unverified. GAPS, Cargo manifests,
the lockfile, artifact tests, and probe source have zero changes. PR creation
and independent review belong to the supervisor; the commands and output above
are ready for its PR evidence.

Principles check (paths below are relative to this lane):

| Question | Answer and evidence |
| --- | --- |
| 1. New name or URL where a code/content hash belongs? | No. The unchanged artifact check still compares SHA-256 values; `tests/artifact.rs:144`. System-tool paths locate the test tools. |
| 2. New ambient or UI authority? | No. `src/harness.rs:192` runs the guard and `src/harness.rs:204` clears the child environment before setting its three entries. |
| 3. A second operation path or rule copy? | No. `src/harness.rs:14` owns the Mac data rule and `src/harness.rs:191` owns the only Runtime process primitive; `src/report.rs:19` owns result grading. |
| 4. Does the trusted core grow? | No. The additions are lane modules in `src/lib.rs:3`; the Runtime and provider trees have zero changes. |
| 5. Does refusal fail closed with a reason? | Yes. `src/harness.rs:165` returns distinct guard reasons; `tests/harness.rs:7` asserts them, and `tests/harness.rs:128` asserts the timeout reason. |
| 6. Does capsule logic stay inside and trap down? | Yes. The probe stays unchanged with typed Bus bindings at `probe/src/lib.rs:8` and its internal refusal at `probe/src/lib.rs:14`. |
| 7. Do new rules have tests and caught falsifiers? | Yes. `tests/harness.rs:7`, `tests/harness.rs:82`, `tests/harness.rs:124` and `tests/report.rs:4` passed, failed under their listed mutations, and passed after restoration; exact results are above. |
