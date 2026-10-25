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

## 009 — Runtime identity and contained refusal

- 009: Added the cached `runtime_under_test` build, shared `offline_build` setup, two Runtime refusal tests, the hash above the existing table, F-ac1f/F-ac1g, and the measured Home-path evidence in GAPS and RUNBOOK.

`src/build.rs:offline_build` owns the offline environment shared by the probe
and Runtime builds. `src/runtime.rs:runtime_under_test` caches either the build
result or its Cargo failure once per test process. The Runtime build uses the
normal toolchain environment, development debug info disabled and the one
`target/runtime` directory, including its `build/` and `tmp/` children. Its
absolute binary path and computed SHA-256 identify the bytes exercised. The
Mac's existing `/usr/bin/shasum -a 256` hashes the binary through stdin; Cargo
manifests, dependencies and lockfiles stay unchanged. Like the probe hash,
this identity is specific to the machine and toolchain.

The initial cold check held the existing shared heavy-build lease, opened
read-only and locked with `fcntl.flock(lease, LOCK_EX | LOCK_NB)`. Before the
build, `df -k .` reported 49,298,252 KiB available, enough for the 8 GiB build
budget plus 2 GiB free. The Cargo command run by the helper was:

```sh
cargo build --locked --offline --manifest-path elastos/Cargo.toml -p elastos-server --bin elastos
```

It ran from `elastos/` with an absolute manifest path. The cold Runtime build
and SHA-256 computation took **118.46 seconds**, measured by the helper's
`Instant`; this elapsed value includes hashing. The cold full test command was
`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -- --show-output`.
It passed all 12 tests, with 0 failed and 0 ignored. Both Runtime tests shared
that one build. The source Runtime and providers have zero edits.

`du -sk lab/agent-conformance/target/runtime` reported **2,102,056 KiB**
(2.005 GiB allocated) after verification. The warmed build files
remain for supervisor verification; the local lifecycle inventory sets removal
after that check. They are rebuildable output, rather than an installed Runtime.

Both new tests use `ThrowawayHome::launch`. Their relative probe argument is
computed from the guarded Home to the lane, so Runtime's own log carries no
operator-local checkout path. The first test requires the nonzero exit and
operator refusal reason. The second creates a coordinates decoy at
`home.data()/runtime-coords.json`, checks it exists, launches through the same
primitive, then requires its removal and the same refusal reason. The fixture
uses only dummy values and a documentation address, which Runtime rejects
before a network client is created. Every launch exited within its ten-second
bound. Passing tests removed their Homes.

Exact stderr from the restored refusal test follows as a JSON string, including
ANSI escapes and newlines. JSON decoding reproduces the captured bytes:

```json
"\u001b[2m2026-10-25T15:33:00.593653Z\u001b[0m \u001b[32m INFO\u001b[0m \u001b[2melastos::run_cmd\u001b[0m\u001b[2m:\u001b[0m Running capsule from: ../../../probe\nError: This command requires a running runtime.\n\n  elastos serve\n\nThen run this command again.\n"
```

### Falsifier commands and observed results

These runs held the same shared build lease and used this environment in
addition to the normal developer toolchain environment:

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/check-tmp"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
```

For each ID, the manual Python invocation selected its one entry from
`falsifiers.json`, loaded the original bytes, asserted exactly one `old` match,
and wrote `original.replace(old, new, 1)`. It ran the command below with
`subprocess.run(command, env=env, stdout=PIPE, stderr=STDOUT, text=True)` and
restored `path.write_bytes(original)` in `finally`. It then ran the identical
command after restoration. Every named test ran. Each planted run returned
101 at the intended assertion; each restored run returned 0. The shared runner
and Git state were unchanged.

The output blocks below preserve captured stdout/stderr, with each ESC byte
rendered as the literal `\u001b` for readable Markdown. Other bytes are unchanged.

**F-ac1f.** The single data-dir rule used by the guard and decoy was changed to
`<home>/.local/share/elastos`. The Runtime refused as before, but the decoy
survived, so its named test failed at the removal assertion.

```sh
cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime runtime_data_dir_is_under_throwaway_home -- --exact --nocapture --color never
```

Planted (exit 101):

```text

running 1 test
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
Runtime build and hash: 0.57s
Runtime refusal stderr:
\u001b[2m2026-10-25T15:32:55.074899Z\u001b[0m \u001b[32m INFO\u001b[0m \u001b[2melastos::run_cmd\u001b[0m\u001b[2m:\u001b[0m Running capsule from: ../../../probe
Error: This command requires a running runtime.

  elastos serve

Then run this command again.


thread 'runtime_data_dir_is_under_throwaway_home' (21435793) panicked at tests/runtime.rs:58:5:
Runtime must remove the decoy from the guarded data directory
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
retained throwaway root: lab/agent-conformance/target/home-4271-1792942373411904000-0
runtime_data_dir_is_under_throwaway_home --- FAILED

failures:

failures:
    runtime_data_dir_is_under_throwaway_home

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.68s

error: test failed, to rerun pass `-p agent-conformance --test runtime`
```

Restored (exit 0):

```text

running 1 test
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
Runtime build and hash: 0.56s
Runtime refusal stderr:
\u001b[2m2026-10-25T15:32:57.158222Z\u001b[0m \u001b[32m INFO\u001b[0m \u001b[2melastos::run_cmd\u001b[0m\u001b[2m:\u001b[0m Running capsule from: ../../../probe
Error: This command requires a running runtime.

  elastos serve

Then run this command again.

.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.68s

```

**F-ac1g.** Only the probe manifest ABI was changed to `wasi-preview1`. Runtime
returned the invalid-manifest reason shown below, so its named test failed at
the reason assertion. This checkout validates the manifest before the ABI
branch in `run_cmd.rs`; the observed error comes from that validation.

```sh
cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime run_without_operator_is_refused_with_reason -- --exact --nocapture --color never
```

Planted (exit 101):

```text

running 1 test
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
Runtime build and hash: 0.55s

thread 'run_without_operator_is_refused_with_reason' (21436165) panicked at tests/runtime.rs:31:5:
Runtime must give the operator refusal reason; stderr:
\u001b[2m2026-10-25T15:32:58.878854Z\u001b[0m \u001b[32m INFO\u001b[0m \u001b[2melastos::run_cmd\u001b[0m\u001b[2m:\u001b[0m Running capsule from: ../../../probe
Error: Invalid manifest: WASI Preview 1 is not a supported product capsule ABI; use elastos.component/v1 or elastos.runtime-projection/v1

note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
retained throwaway root: lab/agent-conformance/target/home-4325-1792942377236483000-0
run_without_operator_is_refused_with_reason --- FAILED

failures:

failures:
    run_without_operator_is_refused_with_reason

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.66s

error: test failed, to rerun pass `-p agent-conformance --test runtime`
```

Restored (exit 0):

```text

running 1 test
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
Runtime build and hash: 0.54s
Runtime refusal stderr:
\u001b[2m2026-10-25T15:33:00.593653Z\u001b[0m \u001b[32m INFO\u001b[0m \u001b[2melastos::run_cmd\u001b[0m\u001b[2m:\u001b[0m Running capsule from: ../../../probe
Error: This command requires a running runtime.

  elastos serve

Then run this command again.

.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.65s

```

The two failed Homes retain only fixture data and captured output. Their
private local lifecycle entries keep them for supervisor review and set removal
after that review. The unchanged task 008 failed roots keep their existing
retention decisions. All 12 falsifier IDs are unique, and all exact edit anchors
match the restored source. The earlier falsifiers were unchanged and were
checked for matching anchors; this task ran F-ac1f and F-ac1g.

### Final checks

With `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`, the lane formatting check and
full `run.sh` passed. The script lists Cargo's tests, runs the full locked suite
with `--no-fail-fast -- --format pretty --color never --show-output`, then
prints the computed Runtime identity above its existing table:

```text
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
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
run_without_operator_is_refused_with_reason | PASS
runtime_data_dir_is_under_throwaway_home | PASS
tests::probe_refuses_without_a_launch_argument_channel | PASS
```

The warmed full run took **33.67 seconds**, exit 0.

`git diff --check`, `bash -n lab/agent-conformance/run.sh`, the product-data
check (42 capsules, 2 profiles, 28 method contracts), its 99 tests, and Runtime
and chain-provider formatting also passed. A before/after comparison of source
SHA-256 values and `git status --porcelain` showed the full run changed neither.
Generated files are ignored. Source edits remain for the supervisor's commit;
the task forbids builder Git mutations, so the final worktree is intentionally
dirty only under this lane. Its cached upstream divergence is 0 ahead / 0 behind;
remote freshness is unverified because this task runs offline. The supervisor
owns the PR and independent review; these commands and results supply its PR
evidence. Every GAPS blocker remains open.

Principles check (file references are relative to this lane):

| Question | Answer and evidence |
| --- | --- |
| 1. New name or URL where a code/content hash belongs? | No. `src/runtime.rs:52` hashes the built bytes; `src/runtime.rs:70` prints that identity. Paths locate local build inputs, and the decoy URL is test data. |
| 2. New ambient or UI authority? | No. `tests/runtime.rs:20` uses the guarded launch primitive, whose environment is cleared at `src/harness.rs:204`. The probe and UI stay unchanged. |
| 3. A second operation path or rule copy? | No. `src/build.rs:10` owns shared build setup; `tests/artifact.rs:23` and `src/runtime.rs:30` call it. `tests/runtime.rs:48` uses the existing data-dir rule through `home.data()`. |
| 4. Does the trusted core grow? | No. `src/lib.rs:3` exposes lane modules only; the Runtime and provider trees have zero edits. |
| 5. Does refusal fail closed with a reason? | Yes. `tests/runtime.rs:27` requires a failed exit, and `tests/runtime.rs:31` requires Runtime's operator reason. |
| 6. Does capsule logic stay inside and trap down? | Yes. `probe/src/lib.rs:8` keeps its typed Bus bindings and internal logic; this task changes neither the probe nor its imports. |
| 7. Do new rules have tests and caught falsifiers? | Yes. `tests/runtime.rs:39` and `tests/runtime.rs:46` passed, failed under their named mutations, and passed after restoration, as recorded above. The Runtime hash is identification evidence. |
